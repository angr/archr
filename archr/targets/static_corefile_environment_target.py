import shutil
import subprocess
import tempfile
import logging
import zipfile

import docker
import shlex
import os
import re

l = logging.getLogger("archr.target.static_environment_target")

from . import Target

class StaticCorefileEnvironmentTarget(Target):
    """
    Describes a target without the ability to directly run it (e.g. we can describe any information we have about the execution of the target)
    """

    def __init__(
        self, rootfs_path, core_path, crash_address, crash_block, bad_bytes=b'\0 ', user=None, **kwargs
        ):
        super().__init__(**kwargs)

        self._user = user
        self.core_path = core_path
        self.crash_address = crash_address
        self.crash_block = crash_block
        self.bad_bytes = bad_bytes
        self.rootfs_path = os.path.expanduser(os.path.abspath(rootfs_path))
    #
    # Lifecycle
    #

    def start(self, user=None, name=None, working_dir=None, labels=None, entry_point=None): #pylint:disable=arguments-differ
        raise NotImplementedError

    def save(self, repository=None, tag=None, **kwargs):
        raise NotImplementedError

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        raise NotImplementedError

    def retrieve_tarball(self, target_path, dereference=False):
        # import ipdb; ipdb.set_trace()
        local_path = self.resolve_local_path(target_path)
        common_prefix = os.path.commonpath([local_path, self.rootfs_path])
        assert common_prefix == self.rootfs_path

        relpath = os.path.relpath(local_path, start=self.rootfs_path)

        with tempfile.NamedTemporaryFile(prefix='tarball_static_env_', suffix='.tar', mode='w+b') as tmpfile:
            shutil.make_archive(tmpfile.name[:-4], 'tar', root_dir=os.path.dirname(local_path), base_dir=os.path.basename(local_path))
            with open(tmpfile.name, 'rb') as f:
                return f.read()

    def realpath(self, target_path):
        l.warning("static environment target realpath is not implemented. things may break.")
        raise NotImplementedError
        return target_path

    def add_volume(self, src_path, dst_path, mode="rw"):
        raise NotImplementedError

    def resolve_local_path(self, target_path):
        relpath = os.path.relpath(target_path, start='/')
        local_path = os.path.join(self.rootfs_path, relpath)
        return local_path


    #
    # Info access
    #

    @property
    def ipv4_address(self):
        raise NotImplementedError

    @property
    def ipv6_address(self):
        raise NotImplementedError

    @property
    def tcp_ports(self):
        return []

    @property
    def udp_ports(self):
        return []

    @property
    def tmpwd(self):
        return "/tmp/"

    @property
    def user(self):
        if self._user is not None:
            return self._user
        return 'root'

    def get_proc_pid(self, proc):
        raise NotImplementedError
        return None
    #
    # Execution
    #

    def _run_command(
        self, args, env,
        user=None, aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ):
        raise NotImplementedError

    def run_companion_command(
            self, args, env=None,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ):
        raise NotImplementedError


from ..errors import ArchrError
