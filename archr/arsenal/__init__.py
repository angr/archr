import os
import time
from contextlib import contextmanager
#from typing import ContextManager

class Bow:
    REQUIRED_ARROW = None
    REQUIRED_BINARY = None

    def __init__(self, target, arrow_bundle=None, arrow_binary=None):
        """
        Initializes the bow.
        :param Target target: the target to work on
        """
        self.target = target
        if arrow_bundle is not None:
            self.REQUIRED_ARROW = arrow_bundle
        if arrow_binary is not None:
            self.REQUIRED_BINARY = arrow_binary
        self.nock()

    def nock(self):
        """
        Prepare the arrow (inject it into the target).
        """
        if self.REQUIRED_ARROW:
            with arrows.bundle(self.REQUIRED_ARROW) as b:
                self.target.inject_path(b, os.path.join(self.target.tmpwd, self.REQUIRED_ARROW))
        if self.REQUIRED_BINARY:
            with arrows.bundle_binary(self.REQUIRED_BINARY) as b:
                self.target.inject_path(b, os.path.join(self.target.tmpwd, os.path.basename(self.REQUIRED_BINARY)))

    def fire(self, *args, **kwargs):
        """
        Fire the bow at the target.
        """
        raise NotImplementedError()


class ContextBow(Bow):
    """
    A Bow base class for bows that implement a fire_context instead of a fire.
    Provides a default .fire() that replays a testcase.
    """

    def fire(self, *args, testcase=None, channel=None, **kwargs): #pylint:disable=arguments-differ
        with self.fire_context(*args, **kwargs) as flight:
            r = flight.default_channel if channel is None else flight.get_channel(channel)
            if type(testcase) is bytes:
                r.write(testcase)
            elif type(testcase) in (list, tuple):
                for s in testcase:
                    r.write(s)
                    time.sleep(0.1)
            elif testcase is None:
                pass
            else:
                raise ValueError("invalid testcase type %s" % type(testcase))

        return flight.result

    @contextmanager
    def fire_context(self, *args, **kwargs):  # -> ContextManager[Flight]:
        """
        A context manager for the bow. Should yield a Flight object.
        """
        with self.target.flight_context(*args, **kwargs) as flight:
            yield flight


from .. import _angr_available
if _angr_available:
    from .angr_project import angrProjectBow
    from .angr_state import angrStateBow
from .qemu_tracer import QEMUTracerBow
from .datascout import DataScoutBow
from .gdbserver import GDBServerBow
from .core import CoreBow
from .ltrace import LTraceBow, LTraceAttachBow
from .strace import STraceBow, STraceAttachBow
from .input_fd import InputFDBow
from .rr import RRTracerBow, RRReplayBow
from .. import arrows
