import contextlib
import logging
import os

from . import ContextBow
from . import Flight

l = logging.getLogger("archr.arsenal.strace")

def super_yama():
    with open("/proc/sys/kernel/yama/ptrace_scope", 'rb') as c:
        if c.read().strip() != b"0":
            l.warning("/proc/sys/kernel/yama/ptrace_scope needs to be '0'. I am setting this system-wide.")
            os.system(_super_yama_cmd)

_super_yama_cmd = "echo 0 | docker run --rm --privileged -i ubuntu tee /proc/sys/kernel/yama/ptrace_scope"

class STraceBow(ContextBow):
    """
    Launches a process under strace
    """

    REQUIRED_BINARY = "/usr/bin/strace"

    @contextlib.contextmanager
    def fire_context(self, trace_args=None, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        Starts strace with a fresh process.

        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        args_prefix = (args_prefix or []) + ["/tmp/strace/fire"] + (trace_args or []) + ["--"]
        with self.target.run_context(args_prefix=args_prefix, **kwargs) as p:
            flight = Flight(self.target, p)
            yield flight
        flight.result = p.stderr.read()


class STraceAttachBow(ContextBow):
    """
    Attaches to a process with strace
    """

    REQUIRED_BINARY = "/usr/bin/strace"

    @contextlib.contextmanager
    def fire_context(self, pid, trace_args=None, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        Starts strace attaching to a given process

        :param pid: PID of target process, if already existing
        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        super_yama()

        args_prefix = (args_prefix or []) + ["/tmp/strace/fire"] + (trace_args or []) + ["-p", str(pid), "--"]
        with self.target.run_context(args_prefix=args_prefix, **kwargs) as p:
            flight = Flight(self.target, p)
            yield flight
            flight.result = p.stderr.read()
