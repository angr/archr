from . import ContextBow, Flight
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
    def fire_context(self, proc_name, proc_args=None, ltrace_args=None, **kwargs):
        """
        Starts ltrace with a fresh process.
        :param proc_name: The name of the process to start
        :param proc_args: Arguments for the process
        :param ltrace_args: Options for ltrace
        :return: Target instance returned by run_command
        """

        args_suffix = ["--", "%s" % proc_name] + proc_args
        with self.target.run_command(args_prefix=["/tmp/ltrace/fire"], args=ltrace_args, args_suffix=args_suffix, **kwargs) as p:
            flight = Flight(self.target, p)
            yield flight
            flight.result = p.stderr.read()


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

        cmd_args = ltrace_args + ["-p", "%d" % pid]

        with self.target.run_command(args_prefix=["/tmp/ltrace/fire"], args=cmd_args, **kwargs) as p:
            flight = Flight(self.target, p)
            yield flight
            p.kill()
            flight.result = p.stderr.read()
