import contextlib
import logging

l = logging.getLogger("archr.arsenal.memory_map")

from . import ContextBow

class GDBServerBow(ContextBow):
    """
    Launches a gdb server.
    """

    REQUIRED_ARROW = "gdbserver"

    @contextlib.contextmanager
    def fire_context(self, port=31337, aslr=False, **kwargs):
        with self.target.run_context(args_prefix=["/tmp/gdbserver/fire", "0.0.0.0:%d"%port], aslr=aslr, **kwargs) as p:
            yield p
