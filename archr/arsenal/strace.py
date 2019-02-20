import contextlib
import logging
import os

from . import ContextBow

l = logging.getLogger("archr.arsenal.strace")

_super_yama_cmd = "echo 0 | docker run --rm --privileged -i ubuntu tee /proc/sys/kernel/yama/ptrace_scope"

class STraceBow(ContextBow):
    """
    Returns an strace instance connected to a running instance of the target.
    """

    REQUIRED_ARROW = "strace"

    @contextlib.contextmanager
    def fire_context(self, pid=None, trace_args=None, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        Starts strace with a fresh process or attaches strace to an already existing process.

        :param pid: PID of target process, if already existing
        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """
        with open("/proc/sys/kernel/yama/ptrace_scope", 'rb') as c:
            if c.read().strip() != b"0":
                l.warning("/proc/sys/kernel/yama/ptrace_scope needs to be '0'. I am setting this system-wide.")
                os.system(_super_yama_cmd)

        args_prefix = (args_prefix or []) + ["/tmp/strace/fire"] + (trace_args or []) + (["-p", str(pid)] if pid is not None else []) + ["--"]
        with self.target.run_context(args_prefix=args_prefix, **kwargs) as r:
            yield r
