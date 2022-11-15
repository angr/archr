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
import traceback

docker = None

l = logging.getLogger("archr.target.docker_compose_target")
l.setLevel(logging.DEBUG)


class TargetInfoClass:
    def __init__(self, config):
        self.attrs = config


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
        self._container = None
        self.image_info = None
        self.removed = False
        self.startup_command = []
        if not os.path.exists(self.docker_compose_path):
            raise ArchrError(f"Error supplied docker compose path does not exist {docker_compose_path}")

        os.chdir(self.docker_compose_path)
        self.docker_compose_filepath = os.path.join(self.docker_compose_path,"docker-compose.yml")
        print(self.docker_compose_filepath)
        print(docker_compose_path)
        assert os.path.exists(self.docker_compose_filepath)

        self.image_name = ""

        if pull:
            self._pull()

        self.remove()

    #
    # Lifecycle
    #

    def build(self, pull=False, config=None):  # pylint:disable=arguments-differ
        #"--no-cache"
        p = subprocess.Popen(["docker-compose", "-f",self.docker_compose_filepath, "build",], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        regex = r"(.*writing image sha256:|Successfully built )([a-f0-9]{12,64})"

        lines = stderr.decode("latin-1").splitlines() + stdout.decode("latin-1").splitlines()
        for line in lines:
            match = re.match(regex, line)
            if match:
                self.image_id = match.group(2)
                break

        print(stderr)
        print(stdout)

        self.init_image_name()

        #self.config_for_archr()

        self._do_config(config)

        self.image_info = self.init_image_info() # should be called after _do_config b/c commit changes image_id

        return self

    def _do_config(self, config):
        pre_image_info = self.init_image_info()
        entrypoint = pre_image_info['Config']['Entrypoint'] or []
        cmd = pre_image_info['Config']['Cmd'] or []
        print(f"{cmd=} {entrypoint=}")
        docker_cmd = ["docker", "run", "--rm", "-id", self.image_name, '/bin/bash']
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(timeout=30)
        print(' '.join(docker_cmd))
        tmp_container_id = stdout.decode('latin-1').strip()
        self.container_id = tmp_container_id  # self.container_id used by inject_tarball
        if not self.container_id:
            print("no container_id, WTF")
        if config:
            config(self)
        entrystr = " ".join(entrypoint)

        docker_cmd = ["docker", "commit", """--change""", f'entrypoint {" ".join(entrypoint)}', """--change""", f'CMD {" ".join(cmd)}', tmp_container_id, self.image_name]
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(timeout=30)
        stdout = stdout.decode("latin-1").strip()
        print(' '.join(docker_cmd))
        if stdout.startswith("sha256:"):
            self.image_id = stdout[7:]
        print(f"{' '.join(docker_cmd)}")
        docker_cmd = ["docker", "kill", tmp_container_id]
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait(timeout=30)

        docker_cmd = ["docker", "rm", tmp_container_id]
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait(timeout=30)

        docker_cmd = ["docker-compose", "-f",self.docker_compose_filepath, "down"]
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait(timeout=30)

        self.container_id = None

    def start(self):  # pylint:disable=arguments-differ
        self.removed = False
        docker_cmd = ["docker-compose","-f",self.docker_compose_filepath, "--env-file", os.path.join("/tmp", "foreign_witcher.env"), "up", "-d", self.service_name]

        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path)
        p.wait(timeout=30)

        self.init_docker_names()
        self.init__container()

        return self

    def start_entrypoint(self):
        entrypoint = (self.image.attrs['Config']['Entrypoint'] or self.image.attrs['Config']['Cmd'] or [])
        docker_cmd = ["docker-compose", "-f",self.docker_compose_filepath, "exec", "-T", "-d", self.service_name] + entrypoint
        l.info(f"Starting up backend service inside container.  {' '.join(entrypoint)}\nDocker CMD: {' '.join(docker_cmd)}")

        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path)
        p.wait(timeout=30)

        return self

    def save(self, repository=None, tag=None, **kwargs):
        raise ArchrError("unsupported")

    def restart(self):
        self.stop()
        self.start()
        return self

    def _stop(self):
        #subprocess.Popen(["docker-compose", "-f",self.docker_compose_filepath, "stop"], cwd=self.docker_compose_path)
        l.info("Stopping docker container with docker-compose ")
        subprocess.Popen(f"docker-compose -f {self.docker_compose_filepath} down &", cwd=self.docker_compose_path, shell=True)
        self.removed = True
        self._container = None

        return self

    def stop(self):
        self.remove()

    def remove(self):
        if self._container is not None:
            self._stop()
        try:
            if not self.removed:
                l.info("Container not removed, stopping docker container with docker-compose ")
                p = subprocess.Popen(f"docker-compose -f {self.docker_compose_filepath} down &", shell=True, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                #stdout, stderr = p.communicate(timeout=30)
                self.removed = True

        except subprocess.CalledProcessError as cpe:
            pass
        except Exception as ex:
            traceback.print_exc()
            l.exception(ex)

        return self

    def init_image_name(self):
        dc_fpath = f"{self.docker_compose_path}/docker-compose.yml"
        with open(dc_fpath) as rf:
            data = yaml.load(rf, Loader=yaml.FullLoader)

        self.service_name = list(data["services"].keys())[0]

        image_body = os.path.abspath(self.docker_compose_path)

        if image_body.endswith("/"):
            image_body = image_body[:-1]

        image_body = os.path.basename(image_body).lower().replace(".", "")

        self.image_name = f"{image_body}_{self.service_name}"

    def init_docker_names(self):

        docker_cmd = ["docker-compose", "-f",self.docker_compose_filepath, "ps", self.service_name, '-q']

        # for some reason Popen was not playing nice with the -q option to just get the sha container id
        p = subprocess.Popen(docker_cmd, cwd=self.docker_compose_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout, stderr = p.communicate()
        print(f"docker ps :: STDOUT is {stdout} STDERR is {stderr}");
        container_line = stdout.decode("latin-1").splitlines()[2].strip()  # we want the first line after the top 2 headers
        l.info(container_line)
        self.container_id = container_line.split(" ")[0].strip()

        l.info(f"GOT {self.service_name=} {self.container_id=} {self.image_name=}")

    def init_image_info(self):
        docker_cmd = ["docker", "inspect", self.image_name]

        l.debug(f"Docker command is: {' '.join(docker_cmd)}")
        p = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        strjson = stdout.decode("latin-1")
        inspected_containers = json.loads(strjson)

        return inspected_containers[0]

    def init__container(self):
        docker_cmd = ["docker", "inspect", self.container_id]

        l.info(f"Docker command is: {' '.join(docker_cmd)}")
        p = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        strjson = stdout.decode("latin-1")
        inspected_containers = json.loads(strjson)

        self._container = inspected_containers[0]
        self.network_settings = self._container["NetworkSettings"]

    #
    # File access
    #
    @property
    def _merged_path(self):
        return self._container['GraphDriver']['Data']['MergedDir']

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        if tarball_contents is not None:
            raise ArchrError("Tarball contens not supported in docker_compose_target")

        docker_cmd = ["docker", "cp", tarball_path, f"{self.container_id}:{target_path}"]
        l.debug(f"Docker copy command: {' '.join(docker_cmd)}")
        p = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(timeout=300)

        if p.returncode != 0:
            raise ArchrError(f"Received Error code when attempting to copy tarball {tarball_path} to {self.container_id}:{target_path}\n{stdout}\n{stderr}")

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
    def image(self):
        return TargetInfoClass(self.image_info)

    @property
    def container(self):
        return TargetInfoClass(self._container)

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
                          for k in self._container['Config']['ExposedPorts'].keys() if 'tcp' in k])
        except KeyError:
            pass
        try:
            if self._container['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self._container['Config']['Env'] if k.startswith('TCP_PORT')])
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
                          for k in self._container['Config']['ExposedPorts'].keys() if 'udp' in k])
        except KeyError:
            pass
        try:
            if self._container['Config']['Env']:
                ports.extend([int(k.split('=')[-1])
                              for k in self._container['Config']['Env'] if k.startswith('UDP_PORT')])
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
        return self._container['Config'].get('User', 'root')

    def get_proc_pid(self, proc):
        if not self._container:
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
    def run_setup_command(self, cmd, fail=True):
        p = self._run_command(cmd, env=None, building=True)
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            print(f"Command sent = {' '.join(cmd)}")
            print(f"{stdout=}")
            print(f"\033[31m{stderr=}\033[0m")
            if fail:
                raise Exception("Error command failed to run successfully against docker container")
        return p.returncode

    def _run_command(
            self, args, env,
            user=None, aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, use_qemu=False,
            privileged=False, building=True
    ):  # pylint:disable=arguments-differ
        if self._container is None and not building:
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

        if building:
            docker_args = ["docker", "exec", "-i"]
        else:
            docker_args = [ "docker-compose", "-f",self.docker_compose_filepath, "exec", "-T" ]


        if privileged:
            docker_args.append("--privileged")
        if env is not None:
            for ekey,eval in env.items():
                docker_args += [ "-e", f"{ekey}={eval}" ]
        if user:
            docker_args += [ "-u", user ]
        if building:
            docker_args.append(self.container_id)
        else:
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
        subprocess.check_call(["docker-compose","-f",self.docker_compose_filepath, "pull"], cwd=self.docker_compose_path)


def check_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def check_dockerd_running() -> bool:
    ps = subprocess.run(["ps", "-aux"], stdout=subprocess.PIPE, check=True)
    return b"dockerd" in ps.stdout


from ..errors import ArchrError
