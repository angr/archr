import subprocess
import contextlib
import logging
import docker
import shlex
import json
import os

l = logging.getLogger("archr.target.docker_target")

from . import Target

_super_mount_cmd = "docker run --rm --privileged --mount type=bind,src=/tmp/archr_mounts/,target=/tmp/archr_mounts,bind-propagation=rshared --mount type=bind,src=/var/lib/docker,target=/var/lib/docker,bind-propagation=rshared ubuntu "
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

    #
    # Lifecycle
    #

    def build(self):
        self.image = self._client.images.get(self.image_id)
        self.target_args = (
            self.target_args or
            (self.image.attrs['Config']['Entrypoint'] or [ ]) + (self.image.attrs['Config']['Cmd'] or [ ])
        )

        # let's assume that we're not analyzing either setarch nor /bin/sh
        if self.target_args[:2] == [ "/bin/sh", "-c" ]:
            self.target_args = shlex.split(self.target_args[-1])
        if self.target_args[:3] == [ "setarch", "x86_64", "-R" ]:
            self.target_args = self.target_args[3:]

        self.target_env = self.target_env or self.image.attrs['Config']['Env']
        self.target_path = self.target_path or self.target_args[0]
        self.target_cwd = self.target_cwd or self.image.attrs['Config']['WorkingDir'] or "/"

        super().build()
        return self

    def start(self, user=None): #pylint:disable=arguments-differ
        self.container = self._client.containers.run(
            self.image,
            entrypoint=['/bin/sh'], command=[], environment=self.target_env,
            user=user,
            detach=True, auto_remove=True,
            stdin_open=True, stdout=True, stderr=True,
            privileged=True, security_opt=["seccomp=unconfined"], #for now, hopefully...
            #network_mode='bridge', ports={11111:11111, self.target_port:self.target_port}
        )
        return self

    def restart(self):
        self.container.restart()
        return self

    def stop(self):
        if self.container:
            self.container.kill()
        if self._local_path:
            os.system(_super_mount_cmd + "umount -l %s" % self.local_path)
            os.system(_super_mount_cmd + "rmdir %s" % self.local_path)
        return self

    def remove(self):
        if self.container:
            self.container.remove(force=True)
        return self

    #
    # File access
    #

    @property
    def _merged_path(self):
        return self.container.attrs['GraphDriver']['Data']['MergedDir']

    def mount_local(self, where=None):
        if self._local_path:
            return self

        self._local_path = where or "/tmp/archr_mounts/%s" % self.container.id
        os.system(_super_mount_cmd + "mkdir -p %s" % (self.local_path))
        os.system(_super_mount_cmd + "mount -o bind %s %s" % (self._merged_path, self.local_path))
        return self

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        if tarball_contents is None:
            with open(tarball_path, "rb") as t:
                tarball_contents = t.read()
        p = self.run_command(["mkdir", "-p", target_path])
        if p.wait() != 0:
            raise ArchrError("Unexpected error when making target_path in container: " + p.stdout.read() + " " + p.stderr.read())
        self.container.put_archive(target_path, tarball_contents)

    def retrieve_tarball(self, target_path):
        stream, _ = self.container.get_archive(target_path)
        return b''.join(stream)

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

    def _run_command(
        self, args, env,
        user=None, aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ): #pylint:disable=arguments-differ
        if self.container is None:
            raise ArchrError("target.start() must be called before target.run_command()")

        if not aslr:
            args = ['setarch', 'x86_64', '-R'] + args

        docker_args = [ "docker", "exec", "-i" ]
        for e in env:
            docker_args += [ "-e", e ]
        if user:
            docker_args += [ "-u", user ]
        docker_args.append(self.container.id)

        return subprocess.Popen(
            docker_args + args,
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0
        )

from ..errors import ArchrError
