import subprocess
import contextlib
import logging
import tarfile
import docker
import json
import os
import io

l = logging.getLogger("archr.target.docker_target")

from . import Target

class DockerImageTarget(Target):
    """
    Describes a target in the form of a Docker image.
    """

    def __init__(
        self, image_name,
        pull=False,
        **kwargs
                 #target_port=None,
                 #target_arch=None,
    ):
        super(DockerImageTarget, self).__init__(**kwargs)

        self._client = docker.client.from_env()
        self.image_id = image_name

        if pull:
            self._client.images.pull(self.image_id)

        self.image = None
        self.container = None
        self._local_path = None

    #
    # Lifecycle
    #

    def build(self, *args, **kwargs):
        self.image = self._client.images.get(self.image_id)
        self.target_args = (
            self.target_args or
            (self.image.attrs['Config']['Entrypoint'] or [ ]) + (self.image.attrs['Config']['Cmd'] or [ ])
        )
        self.target_env = self.target_env or self.image.attrs['Config']['Env']
        self.target_path = self.target_path or self.target_args[0]
        return self

    def start(self):
        self.container = self._client.containers.run(
            self.image,
            entrypoint=['/bin/sh'], command=[], environment=self.target_env,
            detach=True, auto_remove=True,
            stdin_open=True, stdout=True, stderr=True,
            privileged=True, security_opt=["seccomp=unconfined"], #for now, hopefully...
            #network_mode='bridge', ports={11111:11111, self.target_port:self.target_port}
        )
        return self

    def restart(self):
        self.container.restart()

    def stop(self):
        if self.container:
            self.container.kill()
        if self._local_path:
            os.system("sudo umount %s" % self.local_path)
            os.rmdir(self.local_path)
        return self

    def remove(self):
        if self.container:
            self.container.remove(force=True)

    #
    # File access
    #

    @property
    def _merged_path(self):
        return self.container.attrs['GraphDriver']['Data']['MergedDir']

    @property
    def local_path(self):
        if self._local_path is None:
            raise ArchrError("target.mount_local() must be run before target.local_path can be accessed.")
        return self._local_path

    def resolve_local_path(self, path):
        if not path.startswith(self.local_path):
            path = os.path.join(self.local_path, path.lstrip("/"))
        realpath = os.path.realpath(path)
        if not realpath.startswith(self.local_path):
            realpath = os.path.join(self.local_path, realpath.lstrip("/"))
        return realpath

    def mount_local(self, where=None):
        if self._local_path:
            return self

        self._local_path = where or "/tmp/archr_mounts/%s" % self.container.id
        with contextlib.suppress(OSError):
            os.makedirs(self.local_path)
        os.system("sudo mount -o bind %s %s" % (self._merged_path, self.local_path))
        return self

    def inject_contents(self, files, modes=None):
        f = io.BytesIO()
        t = tarfile.open(fileobj=f, mode='w')
        for dst,content in files.items():
            i = tarfile.TarInfo(name=dst)
            i.size = len(content)
            i.mode = 0o777
            if modes and dst in modes:
                i.mode = modes[dst]
            t.addfile(i, fileobj=io.BytesIO(content))
        t.close()
        f.seek(0)
        b = f.read()
        self.container.put_archive("/", b)


    def inject_paths(self, files):
        f = io.BytesIO()
        t = tarfile.open(fileobj=f, mode='w')
        for dst,src in files.items():
            t.add(src, arcname=dst)
        t.close()
        f.seek(0)
        b = f.read()
        self.container.put_archive("/", b)

    def inject_tarball(self, tarball_path, target_path):
        with open(tarball_path, "rb") as t:
            b = t.read()
        assert self.run_command(["mkdir", "-p", target_path]).wait() == 0
        self.container.put_archive(target_path, b)

    def retrieve_tarball(self, target_path):
        stream, _ = self.container.get_archive(target_path)
        return b''.join(stream)

    def resolve_glob(self, target_glob):
        """
        WARNING: THIS IS INSECURE OUT OF LAZINESS AND WILL FAIL WITH SPACES IN FILES OR MULTIPLE FILES
        """
        stdout,_ = self.run_command(["/bin/sh", "-c", "ls -d "+target_glob]).communicate()
        paths = stdout.split()
        return paths

    #
    # Info access
    #

    @property
    def ipv4_address(self):
        if self.container is None:
            return None
        return json.loads(
            subprocess.Popen(["docker", "inspect", self.container.id], stdout=subprocess.PIPE).communicate()[0].decode()
        )[0]['NetworkSettings']['IPAddress']

    @property
    def tcp_ports(self):
        try:
            return [ int(k.split('/')[0]) for k in self.image.attrs['ContainerConfig']['ExposedPorts'].keys() if 'tcp' in k ]
        except KeyError:
            return [ ]

    @property
    def udp_ports(self):
        try:
            return [ int(k.split('/')[0]) for k in self.image.attrs['ContainerConfig']['ExposedPorts'].keys() if 'udp' in k ]
        except KeyError:
            return [ ]

    #
    # Execution
    #

    def run_command(
        self, args=None, args_prefix=None, args_suffix=None, aslr=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ): #pylint:disable=arguments-differ
        assert self.container is not None

        command_args = args or self.target_args
        if args_prefix:
            command_args = args_prefix + command_args
        if args_suffix:
            command_args = command_args + args_suffix
        if not aslr:
            command_args = ['setarch', 'x86_64', '-R'] + command_args

        docker_args = [ "docker", "exec", "-i" ]
        for e in self.target_env:
            docker_args += [ "-e", e ]
        docker_args.append(self.container.id)

        return subprocess.Popen(
            docker_args + command_args,
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0
        )

from ..errors import ArchrError
