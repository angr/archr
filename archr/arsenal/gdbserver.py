import os
import logging

l = logging.getLogger("archr.arsenal.memory_map")

from . import ContextBow

class GDBServerBow(ContextBow):
    """
    Launches a gdb server.
    """

    REQUIRED_ARROW = "gdbserver"

    def fire_context(self, port=31337, aslr=False, **kwargs):
        fire_path = os.path.join(self.target.tmpwd, "gdbserver", "fire")
        return self.target.flight_context(args_prefix=[fire_path, "0.0.0.0:%d"%port], aslr=aslr, **kwargs)
