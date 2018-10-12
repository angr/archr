import re

from .common import Autom
import docker
import shutil
import tempfile
from ..models.autom import AutomDescription, CrashingInput
import os
import angr

class DockerAutom(Autom):
    """
    Describes an autom in the form of a Docker
    """

    image = None
    container = None

    def __init__(self, autom_info: AutomDescription,
                 docker_dir=None,
                 target_path=None,
                 target_args=None,
                 target_port=None,
                 target_arch=None,
                 *args, **kwargs):
        self._client = docker.client.from_env()
        self.project = None
        self.extracted_fs = None
        self.logs = None

        if docker_dir:
            self.docker_dir = docker_dir
            self.target_path = target_path
            self.target_args = target_args
            self.target_port = target_port
            self.target_arch = target_arch

        else:
            self.docker_dir = autom_info.payload.docker_dir
            self.target_path = autom_info.target.binary_path
            self.target_args = autom_info.target.binary_args
            self.target_port = autom_info.target.binary_port
            self.target_arch = autom_info.arch

        assert self.target_path.startswith("/")

    def build(self, *args, **kwargs):
        temp_dir = tempfile.mkdtemp()
        temp_docker_dir = os.path.join(temp_dir, "docker_dir")
        shutil.copytree(self.docker_dir, temp_docker_dir)
        self.image, self.logs = self._client.images.build(path=temp_docker_dir)

    def run(self, thing=None, rr_trace=False, disable_aslr=False):
        #
        # Hold the container open
        if not self.container:
            self.container = self._client.containers.run(self.image, command='/bin/bash',
                                                         tty=True, detach=True, privileged=True,
                                                         security_opt=["seccomp=unconfined"], network_mode='bridge',
                                                         ports={11111:11111, self.target_port:self.target_port})
        if thing:
            binargs = [thing]
        binargs = [self.target_path] + self.target_args
        if rr_trace:
            binargs = ['../rr/bin/rr', 'record', '-n'] + binargs
        if disable_aslr:
            binargs = ['setarch', self.target_arch, '-R'] + binargs
        return self.container.exec_run(binargs, detach=True)

    def stop(self):
        if self.container:
            self.container.kill()

    def get_logs(self):
        return self.logs

    def get_last_rr_trace(self):
        self.container.exec_run('pkill rr')
        return self.container.exec_run('../rr/bin/rr dump -d /home/victim/.local/share/rr/latest-trace').output

    def get_memory_map(self):
        assert(self.container is not None)
        mem_map_str = self.container.exec_run('setarch %s -R ldd %s' % (self.target_arch, self.target_path)).output
        entries = [l.strip() for l in mem_map_str.decode('utf-8').splitlines()]
        extractor = re.compile(r'((?P<libpath>.*) )?\((?P<addr>.*?)\)$')
        parsed = []
        for entry in entries:
            if '=>' in entry:
                lhs, rhs = entry.split('=>')
                libname = lhs.strip()
                m = extractor.fullmatch(rhs.strip())
                assert m
                libaddr = int(m.group('addr'), 16)
            else:
                m = extractor.fullmatch(entry)
                assert m
                libname = os.path.basename(m.group('libpath'))
                libaddr = int(m.group('addr'), 16)
            parsed.append((libname, libaddr))
        return parsed

    def save(self):
        if not self.container:
            self.run()
        tarstream, _ = self.container.get_archive("/")
        outfn = tempfile.mkdtemp() + "/out.tar"
        with open(outfn, 'wb') as f:
            for chunk in tarstream:
                f.write(chunk)
        return outfn

    def load(self):
        # TODO Import the actual pre-built docker container, inverse of save()
        pass

    def angr_project(self):
        if self.project:
            return self.project
        fsdir = self._get_fs()
        lib_paths = [os.path.join(fsdir, 'usr/lib'),
                     os.path.join(fsdir, 'lib'),
                     os.path.join(fsdir, 'lib/i386-linux-gnu')]
        lib_opts = { lib : {'base_addr' : libaddr} for lib, libaddr in self.get_memory_map() }
        the_binary = os.path.join(fsdir, self.target_path.lstrip("/"))
        p = angr.Project(the_binary, load_options={'ld_path':lib_paths, 'lib_opts':lib_opts})
        self.project = p
        return p

    def angr_full_init_state(self, crashing_input: CrashingInput=None):
        args = None
        if not self.extracted_fs:
            self._get_fs()
        if not self.project:
            self.angr_project()
        if crashing_input:
            if crashing_input.type == 'args':
                args = crashing_input.input_args
        s = self.project.factory.full_init_state(concrete_fs=True, chroot=self.extracted_fs, args=None)
        # TODO: Preconstrain input based on the crash other than args
        return s



    def _get_fs(self):
        if self.extracted_fs:
            return self.extracted_fs
        fsdir = tempfile.mkdtemp()
        tarstuff = self.save()
        cmdline = 'tar -C %s -x --exclude="/dev" -f %s' % (fsdir, tarstuff)
        os.system(cmdline)
        self.extracted_fs = fsdir
        return fsdir
