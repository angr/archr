from . import Bow
import logging

l = logging.getLogger("archr.arsenal.ltrace")

class LTraceBow(Bow):
    """
    Returns an ltrace instance connected to a running instance of the target.
    """

    REQUIRED_ARROW = "ltrace"

    def fire(self, pid=None, args=None, **kwargs):
        """
        :param pid: PID of target process, leave 'None' to start up a fresh instance of the target process
        :param kwargs: Additional arguments
        :return:
        """
        l.warning("LtraceBow only works with sufficient ptrace permissions in /proc/sys/kernel/yama/ptrace_scope or "
                  "when executed as root")
        if pid:
            pid_option = ["-p", "%d" % pid]
            cmd_args = args + pid_option
        else:
            cmd_args = args

        return self.target.run_command(args_prefix=["/tmp/ltrace/fire"], args=cmd_args, **kwargs)
