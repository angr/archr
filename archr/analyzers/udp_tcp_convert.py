from . import ContextAnalyzer
import contextlib
import logging
import os

l = logging.getLogger("archr.analyzers.udp_tcp_convert")

class UDPTCPConvert(ContextAnalyzer):
    REQUIRED_IMPLANT = "udp_tcp_convert"

    def __init__(self, target, timeout=10, local_trace_dir=None, symbolic_fd=None):
        super().__init__(target)

    @contextlib.contextmanager
    def fire_context(self, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        Starts strace attaching to a given process

        :param pid: PID of target process, if already existing
        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        fire_path = os.path.join(self.target.tmpwd, "udp_tcp_convert", "fire")
        args_prefix = (args_prefix or []) + [fire_path]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        flight.result = flight.process.stderr.read()
