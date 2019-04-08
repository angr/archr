from . import ContextBow, Bow, Flight
import logging

l = logging.getLogger("archr.arsenal.ltrace")


class LTraceBow(ContextBow):
    """
    Returns an ltrace instance connected to a running instance of the target.
    """

    REQUIRED_ARROW = "ltrace"

    def fire_context(self, proc_name, proc_args=None, ltrace_args=None, **kwargs):
        """
        Starts ltrace with a fresh process.
        :param args: Args passed to target.run_command
        :return: Target instance returned by run_command
        """

        args_suffix = ["--", "%s" % proc_name] + proc_args
        with self.target.run_command(args_prefix=["/tmp/ltrace/fire"], args=ltrace_args, args_suffix=args_suffix, **kwargs) as p:
            flight = Flight(self.target, p)
            yield flight
            flight.result = p.stderr.read()

class LTraceAttachBow(Bow):
    def fire(self, pid=None, ltrace_args=None, **kwargs):
        """
        Attaches ltrace to an already existing process.
        :param pid: PID of target process
        :param kwargs: Additional arguments
        :return:
        """

        l.warning("LtraceBow.fire only works with sufficient ptrace permissions in /proc/sys/kernel/yama/ptrace_scope "
                  "or when executed as root")

        cmd_args = ltrace_args + ["-p", "%d" % pid]

        with self.target.run_command(args_prefix=["/tmp/ltrace/fire"], args=cmd_args, **kwargs) as p:
            p.wait()
        return p.stderr.read()
