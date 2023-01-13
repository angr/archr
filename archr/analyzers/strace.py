import contextlib
import logging
import os

from . import ContextAnalyzer

l = logging.getLogger("archr.analyzers.strace")


def super_yama():
    with open("/proc/sys/kernel/yama/ptrace_scope", "rb") as c:
        if c.read().strip() != b"0":
            l.warning("/proc/sys/kernel/yama/ptrace_scope needs to be '0'. I am setting this system-wide.")
            import docker  # pylint:disable=import-outside-toplevel

            try:
                client = docker.from_env()
                client.containers.run(
                    "ubuntu:jammy", "echo 0 | tee /proc/sys/kernel/yama/ptrace_scope", privileged=True
                )
            finally:
                client.close()


class STraceAnalyzer(ContextAnalyzer):
    """
    Launches a process under strace
    """

    REQUIRED_BINARY = "/usr/bin/strace"

    @contextlib.contextmanager
    def fire_context(self, trace_args=None, args_prefix=None, **kwargs):  # pylint:disable=arguments-differ
        """
        Starts strace with a fresh process.

        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        fire_path = os.path.join(self.target.tmpwd, "strace", "fire")
        args_prefix = (args_prefix or []) + [fire_path] + (trace_args or []) + ["--"]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        try:
            flight.result = flight.process.stderr.read()  # illegal, technically
        except ValueError:
            flight.result = b""


class STraceAttachAnalyzer(ContextAnalyzer):
    """
    Attaches to a process with strace
    """

    REQUIRED_BINARY = "/usr/bin/strace"

    @contextlib.contextmanager
    def fire_context(self, pid, trace_args=None, args_prefix=None, **kwargs):  # pylint:disable=arguments-differ
        """
        Starts strace attaching to a given process

        :param pid: PID of target process, if already existing
        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        super_yama()

        fire_path = os.path.join(self.target.tmpwd, "strace", "fire")
        args_prefix = (args_prefix or []) + [fire_path] + (trace_args or []) + ["-p", str(pid), "--"]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        flight.result = flight.process.stderr.read()
