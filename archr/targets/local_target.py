import collections
import subprocess
import contextlib
import tempfile
import tarfile
import logging
import shutil
import io
import os
import re

l = logging.getLogger("archr.target.local_target")

from . import Target


class LocalTarget(Target):
    """
    Describes a target running on the local host.
    """

    def __init__(self, target_args, target_path=None, target_env=None, target_cwd=None, tcp_ports=(), udp_ports=(),
                 use_qemu=False, ipv4_address="localhost", **kwargs):
        if type(target_args) is str:
            target_args = [target_args]
        if target_path is None and target_args is not None:
            target_path = os.path.abspath(target_args[0])
        if type(target_path) is str:
            target_path = os.path.abspath(target_path)
        if target_cwd is None:
            target_cwd = os.getcwd()
        super().__init__(
            target_args=target_args,
            target_path=target_path,
            target_env=target_env or [ k+"="+v for k,v in os.environ.items() ],
            target_cwd=target_cwd or "/",
            **kwargs
        )
        self._ipv4_address = ipv4_address
        self._tcp_ports = tcp_ports
        self._udp_ports = udp_ports
        self.use_qemu = use_qemu

        self._tmpwd = tempfile.mkdtemp(prefix="archr_local_")

    #
    # Lifecycle
    #

    def remove(self):
        with contextlib.suppress(OSError):
            shutil.rmtree(self._tmpwd)
        super().remove()
        return self

    #
    # File access
    #

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        t = tarfile.TarFile(name=tarball_path, mode="r", fileobj=io.BytesIO(tarball_contents) if tarball_contents else None)
        with contextlib.suppress(FileExistsError):
            os.makedirs(target_path)
        t.extractall(path=target_path)

    def retrieve_tarball(self, target_path, dereference=False):
        f = io.BytesIO()
        t = tarfile.TarFile(fileobj=f, mode="w", dereference=dereference)
        t.add(target_path, arcname=os.path.basename(target_path.rstrip('/'))) # stupid docker compatibility --- it just uses the basename
        f.seek(0)
        return f.read()

    def resolve_local_path(self, target_path):
        return target_path

    def realpath(self, target_path):
        return os.path.realpath(target_path)

    #
    # Info access
    #

    @property
    def ipv4_address(self):
        return self._ipv4_address

    @property
    def ipv6_address(self):
        return "::1"

    @property
    def tcp_ports(self):
        return self._tcp_ports

    @property
    def udp_ports(self):
        return self._udp_ports

    @property
    def tmpwd(self):
        return self._tmpwd

    def get_proc_pid(self, proc):
        p = self._run_command(args="ps -A -o comm,pid".split(), env=[])
        output = p.stdout.read().decode('utf-8')
        regex = r"{}\s+(\d+)".format(proc)
        matches = re.findall(regex, output)
        if not matches:
            return None
        else:
            return int(matches[0])


    #
    # Execution
    #

    def run_command(
        self, args=None, args_prefix=None, args_suffix=None, env=None, # for us
        **kwargs # for subclasses
        ):
        args = args if args else self.target_args

        # if the target binary has to be executed with Qemu, we post-process the args here. This behavior is overridable
        # by specifying args_prefix
        if not args_prefix and self.use_qemu and args[0] == os.path.basename(self.target_path):
            qemu = QEMUTracerAnalyzer.qemu_variant(self.target_os, self.target_arch, False)
            qemu_path = os.path.join(self.tmpwd, "shellphish_qemu", qemu)
            args = [qemu_path] + args

        return super().run_command(args=args, args_prefix=args_prefix, args_suffix=args_suffix, env=env, **kwargs)

    def _run_command(
        self, args, env,
        aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs,
        ): #pylint:disable=arguments-differ,no-self-use
        if not aslr and self.target_arch in ['x86_64', 'i386']:
            args = args[::]
            if not args[0].startswith('/'):
                args[0] = "./" + args[0]
            # "setarch x86_64 -R elfname" will complain. it expects "setarch x86_64 -R ./elfname"
            args = ['setarch', 'x86_64', '-R'] + args

        return subprocess.Popen(
            args,
            env=collections.OrderedDict(e.split("=", 1) for e in env),
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0,
            cwd=self.target_cwd,
        )


from ..analyzers import QEMUTracerAnalyzer
