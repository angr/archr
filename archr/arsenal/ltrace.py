from . import ContextBow
from .strace import super_yama
import logging
from contextlib import contextmanager

l = logging.getLogger("archr.arsenal.ltrace")


class LTraceBow(ContextBow):
    """
    Returns an ltrace instance which has launched a fresh instance of the process
    """

    REQUIRED_ARROW = "ltrace"

    @contextmanager
    def fire_context(self, args_prefix=None, trace_args=None, **kwargs):
        """
        Starts ltrace with a fresh process.
        :param trace_args: Options for ltrace
        :return: Target instance returned by run_command
        """

        args_prefix = (args_prefix or []) + ["/tmp/ltrace/fire"] + (trace_args or []) + ["--"]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        flight.result = flight.process.stderr.read() # illegal, technically


class LTraceAttachBow(ContextBow):
    """
    Returns an ltrace instance attached to a running instance of the target.
    """

    REQUIRED_ARROW = "ltrace"

    @contextmanager
    def fire_context(self, pid=None, ltrace_args=None, **kwargs):
        """
        Attaches ltrace to an already existing process.
        :param pid: PID of target process
        :param ltrace_args: Options for ltrace
        :param kwargs: Additional arguments
        :return:
        """

        super_yama()

        cmd_args = ["/tmp/ltrace/fire"] + (ltrace_args or []) + ["-p", "%d" % pid]
        with self.target.flight_context(args=cmd_args, **kwargs) as flight:
            yield flight
        flight.result = flight.process.stderr.read() # illegal, technically
