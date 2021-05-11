import os
import logging

l = logging.getLogger("archr.analyzers.memory_map")

from . import ContextAnalyzer

class GDBServerAnalyzer(ContextAnalyzer):
    """
    Launches a gdb server.
    """

    REQUIRED_IMPLANT = "gdbserver"

    def fire_context(self, port=31337, aslr=False, **kwargs): #pylint:disable=arguments-differ
        fire_path = os.path.join(self.target.tmpwd, "gdbserver", "fire")
        return self.target.flight_context(args_prefix=[fire_path, "0.0.0.0:%d"%port], aslr=aslr, **kwargs)
