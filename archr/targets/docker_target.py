import subprocess
import logging
import docker
import json
import os

l = logging.getLogger("archr.target.docker_target")

from . import Target

class DockerImageTarget(Target):
    """
    Describes a target in the form of a Docker image.
    """

    def __init__(
        self, image_name,
        pull=False, target_args=None, target_path=None, target_env=None,
        **kwargs
                 #target_port=None,
                 #target_arch=None,
    ):
        super(DockerImageTarget, self).__init__(**kwargs)

        self._client = docker.client.from_env()
        self.image_id = image_name

        if pull:
            self._client.images.pull(self.image_id)

        self.target_args = target_args
        self.target_path = target_path
        self.target_env = target_env
        self.image = None
        self.container = None
        self.subprocess = None

    def build(self, *args, **kwargs):
        self.image = self._client.images.get(self.image_id)
        self.target_args = (
            self.target_args or
            (self.image.attrs['Config']['Entrypoint'] or [ ]) + (self.image.attrs['Config']['Cmd'] or [ ])
        )
        self.target_env = self.target_env or self.image.attrs['Config']['Env']
        self.target_path = self.target_path or self.target_args[0]
        return self

    def inject_file(self, from_path, to_path, perms=None):
        pass

    def remove(self):
        if self.container:
            self.container.remove(force=True)

    def start(self):
        self.container = self._client.containers.run(
            self.image,
            entrypoint=['/bin/sh'], command=[], environment=self.target_env,
            detach=True, auto_remove=True,
            stdin_open=True, stdout=True, stderr=True,
            privileged=True, security_opt=["seccomp=unconfined"], #for now, hopefully...
            #network_mode='bridge', ports={11111:11111, self.target_port:self.target_port}
        )
        try: os.makedirs(self.mounted_path)
        except OSError: pass
        os.system("sudo mount -o bind %s %s" % (self.merged_path, self.mounted_path))
        return self

    def stop(self):
        if self.container:
            self.container.kill()
        os.system("sudo umount %s" % self.mounted_path)
        os.rmdir(self.mounted_path)

    def run_command(
        self, args=None, args_prefix=None, args_suffix=None, aslr=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ): #pylint:disable=arguments-differ
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

    @property
    def ipv4_address(self):
        if self.container is None:
            return None
        return json.loads(
            subprocess.Popen(["docker", "inspect", self.container.id], stdout=subprocess.PIPE).communicate()[0].decode()
        )[0]['NetworkSettings']['IPAddress']

    @property
    def tcp_ports(self):
        return [ int(k.split('/')[0]) for k in self.image.attrs['ContainerConfig']['ExposedPorts'].keys() if 'tcp' in k ]

    @property
    def udp_ports(self):
        return [ int(k.split('/')[0]) for k in self.image.attrs['ContainerConfig']['ExposedPorts'].keys() if 'udp' in k ]

    @property
    def merged_path(self):
        return self.container.attrs['GraphDriver']['Data']['MergedDir']

    @property
    def mounted_path(self):
        return "/tmp/archr_mounts/%s" % self.container.id

    #
    # The things below will eventually be arrows?
    #

    #def rr_trace(self):
    #   binargs = ['../rr/bin/rr', 'record', '-n'] + binargs
    #   self.container.exec_run('pkill rr')
    #   return self.container.exec_run('../rr/bin/rr dump -d /home/victim/.local/share/rr/latest-trace').output

    def fire_ldd(self):
        assert self.container is not None
        mem_map_str,_ = self.run_command([ "ldd", self.target_path ], aslr=False).communicate()
        entries = [l.strip() for l in mem_map_str.decode('utf-8').splitlines()]
        parsed = { }
        for entry in entries:
            if '=>' in entry:
                libname, paren_addr = entry.split('=>')[1].split()
            else:
                libname, paren_addr = entry.split()
            libaddr = int(paren_addr.strip("()"), 16)
            parsed[libname] = libaddr
        return parsed

    #def angr_project(self):
    #   if self.project:
    #       return self.project
    #   fsdir = self._get_fs()
    #   lib_paths = [os.path.join(fsdir, 'usr/lib'),
    #                os.path.join(fsdir, 'lib'),
    #                os.path.join(fsdir, 'lib/i386-linux-gnu')]
    #   lib_opts = { lib : {'base_addr' : libaddr} for lib, libaddr in self.get_memory_map() }
    #   the_binary = os.path.join(fsdir, self.target_path.lstrip("/"))
    #   p = angr.Project(the_binary, load_options={'ld_path':lib_paths, 'lib_opts':lib_opts})
    #   self.project = p
    #   return p

    #def angr_full_init_state(self, crashing_input):
    #   args = None
    #   if not self.extracted_fs:
    #       self._get_fs()
    #   if not self.project:
    #       self.angr_project()
    #   if crashing_input:
    #       if crashing_input.type == 'args':
    #           args = crashing_input.input_args
    #   s = self.project.factory.full_init_state(concrete_fs=True, chroot=self.extracted_fs, args=None)
    #   # TODO: Preconstrain input based on the crash other than args
    #   return s

    #def _get_fs(self):
    #   if self.extracted_fs:
    #       return self.extracted_fs
    #   fsdir = tempfile.mkdtemp()
    #   tarstuff = self.save()
    #   cmdline = 'tar -C %s -x --exclude="/dev" -f %s' % (fsdir, tarstuff)
    #   os.system(cmdline)
    #   self.extracted_fs = fsdir
    #   return fsdir
