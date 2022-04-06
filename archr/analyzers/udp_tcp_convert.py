import contextlib
import logging
import os

from . import ContextAnalyzer
l = logging.getLogger("archr.analyzers.udp_tcp_convert")

class UDPTCPConvert(ContextAnalyzer):
    """
    Returns a fresh instance of the process LD_PRELOADed to convert it's udp sockets to tcp
    """

    REQUIRED_IMPLANT = "udp_tcp_convert"

    def __init__(self, target):
        super().__init__(target)
        self.lib_path = os.path.join(self.target.tmpwd, "udp_tcp_convert", "libudp_to_tcp.so")

    @contextlib.contextmanager
    def fire_context(self, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        LD_PRELOAD a given process converting it's udp sockets into tcp

        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        fire_path = os.path.join(self.target.tmpwd, "udp_tcp_convert", "fire")
        args_prefix = (args_prefix or []) + [fire_path]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        flight.result = flight.process.stderr.read()
