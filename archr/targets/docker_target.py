import subprocess
import sys
import tempfile
import logging
import shlex
import os
import re

from . import Target


docker = None

l = logging.getLogger("archr.target.docker_target")

_super_mount_cmd = "docker run --rm --privileged " \
                   "--mount type=bind,src=/tmp/archr_mounts/,target=/tmp/archr_mounts,bind-propagation=rshared " \
                   "--mount type=bind,src=/var/lib/docker,target=/var/lib/docker,bind-propagation=rshared " \
                   "ubuntu "


def import_docker():
    global docker  # pylint:disable=global-statement
    import docker  # pylint:disable=import-outside-toplevel


class DockerImageTarget(Target):
    """
    Describes a target in the form of a Docker image.
    """

    def __init__(
        self, image_name,
        pull=False,
        rm=True,
        bind_tmp=False,
        network_mode='bridge',
        network=None,
        use_init=False,
        companion=False,
        hostname="archr-target",
        **kwargs
        ):
        super().__init__(**kwargs)

        if sys.platform == "win32":
            raise RuntimeError("DockerImageTarget has not been tested on Windows.")

        os.makedirs(os.path.join("/", "tmp", "archr_mounts"), exist_ok=True)
        import_docker()

        if bind_tmp:
            self.tmp_bind = tempfile.mkdtemp(dir="/tmp/archr_mounts", prefix="tmp_")
        else:
            self.tmp_bind = None

        self.image_id = image_name
        self.network = None
        self.network_mode = None
        self.image = None
        self.container = None
        self.volumes = { }
        self.rm = rm
        self._client = None
        self.use_init = use_init
        self.companion = companion
        self.companion_container = None

        self._client = docker.client.from_env()

        if pull:
            self._pull()

        # If we're running in docker-by-docker, default the network to the same network
        if check_in_docker() and not check_dockerd_running() and network is None:
            try:
                with open("/proc/self/cgroup") as f:
                    cgroups = dict(e.split(':', 2)[1:] for e in f.read().strip().split('\n'))
                container_id = re.search("/([0-9a-f]{64})", cgroups["pids"]).group(1)
                container_inspect = self._client.api.inspect_container(container_id)
                network_dict = container_inspect["NetworkSettings"]["Networks"]
                # Grab "first" network
                network = list(network_dict.keys())[0]
                if network == "host":
                    # Don't implicitly start the target with host network
                    network = None
            except (KeyError, IndexError, AttributeError, docker.errors.APIError):
                l.warning("Detected archr is being run from a docker container, but couldn't retrieve network information")

        self.network = network
        self.network_mode = network_mode if not network else None
        self.hostname = hostname

    #
    # Lifecycle
    #

    def build(self, pull=False):# pylint:disable=arguments-differ
        if pull and not self._client.images.list(self.image_id):
            self._pull()
        self.image = self._client.images.get(self.image_id)
        self.target_args = (
            self.target_args or
            (self.image.attrs['Config']['Entrypoint'] or [ ]) + (self.image.attrs['Config']['Cmd'] or [ ])
        )

        # let's assume that we're not analyzing setarch, /bin/sh, or any variant of qemu
        if self.target_args[:2] == [ "/bin/sh", "-c" ]:
            self.target_args = shlex.split(self.target_args[-1])
        if self.target_args[:3] == ['tmux', 'new-session', '-d;']:
            self.target_args = self.target_args[3:]
        if self.target_args[:3] == [ "setarch", "x86_64", "-R" ]:
            self.target_args = self.target_args[3:]
        if "qemu-" in self.target_args[0]:
            self.target_args_prefix = self.target_args[:1]
            self.target_args = self.target_args[1:]
            self.target_arch = re.search(r"qemu-(\w+)(-\w+)?", self.target_args_prefix[0]).group(1)

        if re.match(r"ld[0-9A-Za-z\-]*\.so.*", os.path.basename(self.target_args[0])) is not None:
            self.target_args = self.target_args[1:]
            if self.target_args[0] == "--library-path":
                self.target_args = self.target_args[2:]

        self.target_env = self.target_env or self.image.attrs['Config']['Env']
        self.target_cwd = self.target_cwd or self.image.attrs['Config']['WorkingDir'] or "/"
        specified_path = self.target_path or self.target_args[0]
        self.target_path = specified_path if os.path.isabs(specified_path) else \
            os.path.realpath(os.path.join(self.target_cwd, specified_path))

        super().build()
        return self

    def start(self, user=None, name=None, working_dir=None, labels=None, entry_point=None, timeout=None):  #pylint:disable=arguments-differ
        if labels is None:
            labels = []
        if entry_point is None:
            entry_point = ["/bin/sh"]
        if self.tmp_bind:
            self.volumes[self.tmp_bind] = {'bind': '/tmp/', 'mode': 'rw'}
        if timeout is not None:
            if not isinstance(timeout, int):
                raise TypeError("Timeout must be an int.")
            use_init = True
        else:
            use_init = self.use_init

        self.container = self._client.containers.run(
            self.image,
            name=name,
            entrypoint=entry_point, command=[], environment=self.target_env,
            user=user, labels=labels,
            hostname=self.hostname,
            detach=True, auto_remove=self.rm, working_dir=working_dir,
            stdin_open=True, stdout=True, stderr=True,
            privileged=True, security_opt=["seccomp=unconfined"], volumes=self.volumes,
            network_mode=self.network_mode,
            network=self.network,
            init=use_init
            #network_mode='bridge', ports={11111:11111, self.target_port:self.target_port}
        )
        self.container.reload()  # update self.container.attrs

        if timeout is not None:
            # it will kill the init process since use_init is True when timeout is set
            command = ["/bin/sh", "-c", f"sleep {timeout}; kill 1"]
            self.run_command(command)

        if self.companion:
            self.companion_container = self._client.containers.run(
                "angr/archr-companion",
                name=f"{self.container.name}_companion",
                entrypoint=["/bin/sh"],
                detach=True, auto_remove=self.rm,
                stdin_open=True, stdout=True, stderr=True,
                privileged=True, security_opt=["seccomp=unconfined"], volumes=self.volumes,
                network_mode=f"container:{self.container.id}",
                pid_mode=f"container:{self.container.id}",
                init=use_init
            )
            if timeout is not None:
                # it will kill the init process since use_init is True when timeout is set
                command = ["/bin/sh", "-c", f"sleep {timeout}; kill 1"]
                self.run_companion_command(command)
            self.companion_container.reload()

        return self

    def save(self, repository=None, tag=None, **kwargs):
        return self.container.commit(repository, tag, **kwargs)

    def restart(self):
        self.container.restart()
        return self

    def stop(self):
        if self.container:
            try:
                self.container.kill()
            except docker.errors.APIError:
                # the container is stopped before we attempt to kill it
                pass
            self.container = None
        if self.tmp_bind:
            os.system(_super_mount_cmd + "rm -rf %s" % self.tmp_bind)
        super().stop()
        return self

    def remove(self):
        if self.container:
            l.debug("Force removing container %r. If this is not intended, please ensure variable %r "
                    "is still alive and in scope.", self.container, self)
            try:
                self.container.remove(force=True)
            except docker.errors.NotFound:
                # the container is already gone before we attempt to remove it
                pass
        if self._client:
            self._client.close()
        super().remove()
        return self

    #
    # File access
    #

    @property
    def _merged_path(self):
        return self.container.attrs['GraphDriver']['Data']['MergedDir']

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        if tarball_contents is None:
            with open(tarball_path, "rb") as t:
                tarball_contents = t.read()
        p = self.run_command(["mkdir", "-p", target_path])
        if p.wait() != 0:
            raise ArchrError("Unexpected error when making target_path in container: " + p.stdout.read().decode() +
                             " " + p.stderr.read().decode())
        p.stdin.close()
        p.stdout.close()
        if p.stderr:
            p.stderr.close()
        self.container.put_archive(target_path, tarball_contents)
        if self.user != 'root':
            # TODO: this is probably important, but as implemented (path resolves to /), it is way to slow.
            # TODO: If someone wants this, implement it correctly.
            p = self.run_command(["chown", "-R", f"{self.user}:{self.user}", '/tmp'], user="root",
                                 stderr=subprocess.DEVNULL)
            p.wait()
            p.stdin.close()
            p.stdout.close()
            if p.stderr:
                p.stderr.close()

    def retrieve_tarball(self, target_path, dereference=False):
        stream, _ = self.container.get_archive(target_path)
        return b''.join(stream)

    def realpath(self, target_path):
        l.warning("docker target realpath is not implemented. things may break.")
        return target_path

    def add_volume(self, src_path, dst_path, mode="rw"):
        new_vol = {'bind': dst_path, 'mode': mode}
        self.volumes[src_path] = new_vol

    def resolve_local_path(self, target_path):
        local_path = self.local_workdir + "/" + target_path # os.path.join fucks up with absolute paths
        if not os.path.exists(local_path):
            self.retrieve_into(target_path, os.path.dirname(local_path))
        return local_path


    #
    # Info access
    #

    @property
    def ipv4_address(self):
        if self.container is None:
            return None
        if self.network == "host":
            return "127.0.0.1"
        settings = self.container.attrs['NetworkSettings']
        if self.network:
            settings = settings['Networks'][self.network]
        return settings['IPAddress']

    @property
    def ipv6_address(self):
        if self.container is None:
            return None
        if self.network == "host":
            return "::1"
        settings = self.container.attrs['NetworkSettings']
        if self.network:
            settings = settings['Networks'][self.network]
        return settings['GlobalIPv6Address']

    @property
    def tcp_ports(self):
        ports = []
        try:
            ports.extend([int(k.split('/')[0])
                          for k in self.image.attrs['Config']['ExposedPorts'].keys() if 'tcp' in k])
        except KeyError:
            pass
        try:
            if self.image.attrs['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self.image.attrs['Config']['Env'] if k.startswith('TCP_PORT')])
        except ValueError:
            l.warning('An enviroment variable for %s starts with "TCP_PORT", but the value is not an integer.',
                      self.image_id)
        except KeyError:
            pass
        return ports

    @property
    def udp_ports(self):
        ports = []
        try:
            ports.extend([int(k.split('/')[0])
                          for k in self.image.attrs['Config']['ExposedPorts'].keys() if 'udp' in k])
        except KeyError:
            pass
        try:
            if self.image.attrs['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self.image.attrs['Config']['Env'] if k.startswith('UDP_PORT')])
        except ValueError:
            l.warning('An enviroment variable for %s starts with "UDP_PORT", but the value is not an integer.',
                      self.image_id)
        except KeyError:
            pass
        return ports

    @property
    def tmpwd(self):
        return "/tmp/"

    @property
    def user(self):
        if 'User' in self.image.attrs['Config']:
            return self.image.attrs['Config']['User']
        else:
            return 'root'

    def get_proc_pid(self, proc):
        if not self.container:
            return None

        # get host_pid
        ps_info = self.container.top()
        titles = ps_info['Titles']
        procs = ps_info['Processes']
        pid_idx = titles.index('PID')
        cmd_idx = titles.index('CMD')
        host_pid = None
        for p in procs:
            if p[cmd_idx].split()[0] == proc:
                host_pid = int(p[pid_idx])
        if not host_pid:
            return None

        # For now lets just return the guest pid
        # get guest_pid
        p = self._run_command(args="ps -A -o comm,pid".split(), env=[])
        output = p.stdout.read().decode('utf-8')
        regex = r"{}\s+(\d+)".format(proc)
        matches = re.findall(regex, output)
        if not matches:
            return None

        guest_pid = int(matches[0])
        return guest_pid

    #
    # Execution
    #

    def _run_command(
        self, args, env,
        user=None, aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, use_qemu=False,
        privileged=False
        ): #pylint:disable=arguments-differ
        if self.container is None:
            raise ArchrError("target.start() must be called before target.run_command()")

        if use_qemu:
            from ..analyzers.qemu_tracer import QEMUTracerAnalyzer  # pylint:disable=import-outside-toplevel
            qemu_variant = QEMUTracerAnalyzer.qemu_variant(self.target_os, self.target_arch, False)
            qemu_path = os.path.join(self.tmpwd, "shellphish_qemu", qemu_variant)
            fire_path = os.path.join(self.tmpwd, "shellphish_qemu", "fire")
            args = [fire_path, qemu_path] + args
        else:
            if not aslr and self.target_arch in ['x86_64', 'i386']:
                # use setarch to disable ASLR
                args = ['setarch', 'x86_64', '-R'] + args

        docker_args = [ "docker", "exec", "-i" ]

        if privileged:
            docker_args.append("--privileged")

        for e in env:
            docker_args += [ "-e", e ]
        if user:
            docker_args += [ "-u", user ]
        docker_args.append(self.container.id)

        l.debug("running command: %s", docker_args + args)

        return subprocess.Popen(docker_args + args,
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0) #pylint:disable=consider-using-with

    def run_companion_command(
            self, args, env=None,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ):

        if not self.companion:
            raise ArchrError("The target must be created with `companion=True`")

        if self.companion_container is None:
            raise ArchrError("target.start() must be called before target.run_companion_command()")

        env = env or {}

        docker_args = [ "docker", "exec", "-i" ]
        for e in env:
            docker_args += [ "-e", e ]
        docker_args.append(self.companion_container.id)

        return subprocess.Popen(docker_args + args,
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0) #pylint:disable=consider-using-with


    #
    # Docker wrappers
    #
    def _pull(self):
        try:
            self._client.images.pull(self.image_id)
        except docker.errors.ImageNotFound as err:
            l.info("Unable to pull image %s, got error %s, ignoring and continuing on", self.image_id, err)

    #
    # Serialization
    #

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_client"] = None
        if state["image"] is not None:
            state["image"] = state["image"].id
        if state["container"] is not None:
            state["container"] = state["container"].id
        return state

    def __setstate__(self, state):
        client = docker.client.from_env()
        state["_client"] = client
        if state["image"] is not None:
            state["image"] = client.images.get(state["image"])
        if state["container"] is not None:
            state["container"] = client.containers.get(state["container"])
        for name, value in state.items():
            setattr(self, name, value)


def check_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def check_dockerd_running() -> bool:
    ps = subprocess.run(["ps", "-aux"], stdout=subprocess.PIPE, check=True)
    return b"dockerd" in ps.stdout


from ..errors import ArchrError
