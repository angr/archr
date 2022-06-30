import subprocess
import sys
import tempfile
import logging
import shlex
import io
import os
import re
import tarfile
import yaml
import json

from . import Target

docker = None

l = logging.getLogger("archr.target.docker_compose_target")


class DockerComposeImageTarget(Target):
    """
    Provides access to a target that is provided as a docker-compose.yml file.
    Although this object shares some similarity with the docker target, many of the features provided by the docker target
    are not implemented through the API but via the docker-compose yml file, thus, this object inherits from Target instead.
    """

    def __init__(self, docker_compose_path="", pull=False,  **kwargs):

        if sys.platform == "win32":
            raise ArchrError("DockerComposeImageTarget has not been tested on Windows.")

        super().__init__(**kwargs)

        self.service_name = ""
        self.container_id = ""
        self.image_id = ""
        self.docker_compose_path = os.path.abspath(docker_compose_path)
        self.container_proc = ""
        self.network_settings = None
        self.container = None
        if not os.path.exists(self.docker_compose_path):
            raise ArchrError(f"Error supplied docker compose path does not exist {docker_compose_path}")

        os.chdir(self.docker_compose_path)

        self.image_name = ""

        if pull:
            self._pull()

    #
    # Lifecycle
    #

    def build(self, pull=False):  # pylint:disable=arguments-differ

        p = subprocess.Popen(["docker-compose", "build", "--no-cache"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        regex = r".*writing image sha256:([a-f0-9]{64})"

        lines = stderr.decode("latin-1").splitlines()
        for line in lines:
            match = re.match(regex, line)
            if match:
                self.image_id = match.group(1)
                break

        return self

    def start(self):  # pylint:disable=arguments-differ
        docker_cmd = ["docker-compose", "up", "-d"]

        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path)
        p.wait(timeout=30)

        self.init_docker_names()
        self.init_container_info()

        return self

    def save(self, repository=None, tag=None, **kwargs):
        raise ArchrError("unsupported")

    def restart(self):
        self.stop()
        self.start()
        return self

    def stop(self):
        subprocess.check_call(["docker-compose", "stop"], cwd=self.docker_compose_path)
        self.container = None
        return self

    def remove(self):
        if self.container is not None:
            self.stop()
        subprocess.check_call(["docker-compose", "rm", "-f", self.service_name], cwd=self.docker_compose_path)
        return self

    def init_docker_names(self):
        dc_fpath = f"{self.docker_compose_path}/docker-compose.yml"
        with open(dc_fpath) as rf:
            data = yaml.load(rf, Loader=yaml.FullLoader)

        service_name = list(data["services"].keys())[0]

        image_body = os.path.abspath(self.docker_compose_path)

        if image_body.endswith("/"):
            image_body = image_body[:-1]

        image_body = os.path.basename(image_body).lower().replace(".", "")
        docker_cmd = ["docker-compose", "ps", service_name]

        # for some reason Popen was not playing nice with the -q option to just get the sha container id
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout, stderr = p.communicate()

        self.service_name = service_name
        container_line = stdout.decode("latin-1").splitlines()[2].strip()  # we want the first line after the top 2 headers
        self.container_id = container_line.split(" ")[0].strip()

        self.image_name = f"{image_body}_{service_name}"
        l.debug(f"GOT {self.service_name=} {self.container_id=} {self.image_name=}")

    def init_container_info(self):
        docker_cmd = ["docker", "inspect", self.container_id]

        l.debug(f"Docker command is: {' '.join(docker_cmd)}")
        p = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        strjson = stdout.decode("latin-1")
        inspected_containers = json.loads(strjson)

        self.container = inspected_containers[0]
        self.network_settings = self.container["NetworkSettings"]

    #
    # File access
    #
    @property
    def _merged_path(self):
        return self.container['GraphDriver']['Data']['MergedDir']

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        if tarball_contents is not None:
            raise ArchrError("Tarball contens not supported in docker_compose_target")

        docker_cmd = ["docker", "cp", tarball_path, f"{self.container_id}:{target_path}"]
        p = self.run_command(docker_cmd)
        p.wait(timeout=300)

        if p.returncode != 0:
            raise ArchrError(f"Received Error code when attempting to copy tarball {tarball_path} to {self.container_id}:{target_path}")

        p.terminate()

    def retrieve_tarball(self, target_path, dereference=False):

        with tempfile.NamedTemporaryFile(dir='/tmp', delete=False) as tmpfile:
            temp_fpath = tmpfile.name

        docker_cmd = ["docker", "cp", f"{self.container_id}:{target_path}", temp_fpath]

        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path)
        p.wait(timeout=300)
        if p.returncode != 0:
            raise ArchrError(f"Received Error code when attempting to copy tarball from {self.container_id}:{target_path}")
        p.terminate()

        with open(temp_fpath, "rb") as rf:
            data = rf.read()

        if tarfile.is_tarfile(temp_fpath):
            return data

        l.debug("Retrieved file was not in tar format, changing data into tar format")
        with io.BytesIO() as f:
            with tarfile.open(fileobj=f, mode='w') as t:
                i = tarfile.TarInfo(name=os.path.basename(target_path))
                i.size = len(data)
                i.mode = 0o777
                t.addfile(i, fileobj=io.BytesIO(data))

            f.seek(0)
            data = f.read()
            return data

    def realpath(self, target_path):
        l.warning("docker target realpath is not implemented. things may break.")
        return target_path

    def add_volume(self, src_path, dst_path, mode="rw"):

        raise ArchrError("add_volume not supported by docker_compose_target, to add a volume please modify the docker-compose.yml for this target")

    def resolve_local_path(self, target_path):
        local_path = self.local_workdir + "/" + target_path  # os.path.join fucks up with absolute paths
        if not os.path.exists(local_path):
            self.retrieve_into(target_path, os.path.dirname(local_path))
        return local_path

    #
    # Info access
    #

    @property
    def ipv4_address(self):
        if self.network_settings is None:
            return None

        return [n["IPAddress"] for n in self.network_settings["Networks"].values() if len(n["IPAddress"]) > 0]

    @property
    def ipv6_address(self):

        if self.network_settings is None:
            return None
        return [n["GlobalIPv6Address"] for n in self.network_settings["Networks"].values() if len(n["GlobalIPv6Address"]) > 0]


    @property
    def tcp_ports(self):
        ports = []
        try:
            ports.extend([int(k.split('/')[0])
                          for k in self.container['Config']['ExposedPorts'].keys() if 'tcp' in k])
        except KeyError:
            pass
        try:
            if self.container['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self.container['Config']['Env'] if k.startswith('TCP_PORT')])
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
                          for k in self.container['Config']['ExposedPorts'].keys() if 'udp' in k])
        except KeyError:
            pass
        try:
            if self.container['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self.container['Config']['Env'] if k.startswith('UDP_PORT')])
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
        return self.container['Config'].get('User', 'root')

    def get_proc_pid(self, proc):
        if not self.container:
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
    ):  # pylint:disable=arguments-differ
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

        docker_args = [ "docker-compose", "exec", "-T" ]

        if privileged:
            docker_args.append("--privileged")
        if env is not None:
            for ekey,eval in env.items():
                docker_args += [ "-e", f"{ekey}={eval}" ]
        if user:
            docker_args += [ "-u", user ]
        docker_args.append(self.service_name)

        l.debug("running command: %s", " ".join(docker_args + args))

        return subprocess.Popen(docker_args + args,
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0) #pylint:disable=consider-using-with

    def run_companion_command(self, args, env=None, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        raise ArchrError("DockerComposeImageTarget does not support run_companion_command ")

    #
    # Docker wrappers
    #
    def _pull(self):
        subprocess.check_call(["docker-compose","pull"], cwd=self.docker_compose_path)


def check_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def check_dockerd_running() -> bool:
    ps = subprocess.run(["ps", "-aux"], stdout=subprocess.PIPE, check=True)
    return b"dockerd" in ps.stdout


from ..errors import ArchrError
