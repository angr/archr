import collections
import subprocess
import contextlib
import tarfile
import logging
import io
import os

l = logging.getLogger("archr.target.local_target")

from . import Target

class LocalTarget(Target):
    """
    Describes a target running on the local host.
    """

    def __init__(self, target_args, target_path=None, target_env=None, target_cwd=None, tcp_ports=(), udp_ports=(), **kwargs):
        super().__init__(
            target_args=target_args,
            target_path=target_path or target_args[0],
            target_env=target_env or [ k+"="+v for k,v in os.environ.items() ],
            target_cwd=target_cwd or "/",
            **kwargs
        )
        self._tcp_ports = tcp_ports
        self._udp_ports = udp_ports

    #
    # Lifecycle
    #

    def start(self):
        return self

    def restart(self):
        return self

    def stop(self):
        return self

    def remove(self):
        return self

    #
    # File access
    #

    def mount_local(self, where=None):
        self._local_path = "/"
        return self

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        t = tarfile.TarFile(name=tarball_path, mode="r", fileobj=io.BytesIO(tarball_contents) if tarball_contents else None)
        with contextlib.suppress(FileExistsError):
            os.makedirs(target_path)
        t.extractall(path=target_path)

    def retrieve_tarball(self, target_path):
        f = io.BytesIO()
        t = tarfile.TarFile(fileobj=f, mode="w")
        t.add(target_path, arcname=os.path.basename(target_path)) # stupid docker compatibility --- it just uses the basename
        f.seek(0)
        return f.read()

    #
    # Info access
    #

    @property
    def ipv4_address(self):
        return "127.13.37.1"

    @property
    def tcp_ports(self):
        return self._tcp_ports

    @property
    def udp_ports(self):
        return self._udp_ports

    #
    # Execution
    #

    def _run_command(
        self, args, env,
        aslr=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ): #pylint:disable=arguments-differ,no-self-use
        if not aslr:
            args = ['setarch', 'x86_64', '-R'] + args

        return subprocess.Popen(
            args,
            env=collections.OrderedDict(e.split("=", 1) for e in env),
            stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0
        )
