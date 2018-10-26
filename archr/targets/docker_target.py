import subprocess
import docker
import json

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

        self._target_args = target_args
        self._target_path = target_path
        self._target_env = target_env
        self.image = None
        self.container = None
        self.subprocess = None

    def build(self, *args, **kwargs):
        self.image = self._client.images.get(self.image_id)
        self._target_args = (
            self._target_args or
            (self.image.attrs['Config']['Entrypoint'] or [ ]) + (self.image.attrs['Config']['Cmd'] or [ ])
        )
        self._target_env = self._target_env or self.image.attrs['Config']['Env']
        self._target_path = self._target_path or self._target_args[0]
        return self

    def inject_file(self, from_path, to_path, perms=None):
        pass

    def remove(self):
        if self.container:
            self.container.remove(force=True)

    def start(self):
        self.container = self._client.containers.run(
            self.image,
            entrypoint=['/bin/sh'], command=[], environment=self._target_env,
            detach=True, auto_remove=True,
            stdin_open=True, stdout=True, stderr=True,
            privileged=True, security_opt=["seccomp=unconfined"], #for now, hopefully...
            #network_mode='bridge', ports={11111:11111, self.target_port:self.target_port}
        )
        return self

    def stop(self):
        if self.container:
            self.container.kill()

    def run_command(
        self, args=None, args_prefix=None, args_suffix=None, aslr=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ): #pylint:disable=arguments-differ
        command_args = args or self._target_args
        if args_prefix:
            command_args = args_prefix + command_args
        if args_suffix:
            command_args = command_args + args_suffix
        if not aslr:
            command_args = ['setarch', 'x86_64', '-R'] + command_args

        docker_args = [ "docker", "exec", "-i" ]
        for e in self._target_env:
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
