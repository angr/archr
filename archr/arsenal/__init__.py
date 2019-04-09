import os
import time
from contextlib import contextmanager
#from typing import ContextManager

from ..arrowheads import ArrowheadLog
from ..targets import Flight


class Bow:
    REQUIRED_ARROW = None
    REQUIRED_BINARY = None

    def __init__(self, target):
        """
        Initializes the bow.
        :param Target target: the target to work on
        """
        self.target = target
        self.nock()

    def nock(self):
        """
        Prepare the arrow (inject it into the target).
        """
        if self.REQUIRED_ARROW:
            with arrows.bundle(self.REQUIRED_ARROW) as b:
                self.target.inject_path(b, "/tmp/%s" % self.REQUIRED_ARROW)
        if self.REQUIRED_BINARY:
            with arrows.bundle_binary(self.REQUIRED_BINARY) as b:
                self.target.inject_path(b, "/tmp/%s" % os.path.basename(self.REQUIRED_BINARY))

    def fire(self, *args, **kwargs):
        """
        Fire the bow at the target.
        """
        raise NotImplementedError()

class ContextBow(Bow):
    """
    A Bow base class for bows that implement a fire_context instead of a fire.
    Provides a default .fire() that replays a testcase (an Arrowhead).
    """

    def fire(self, *args, testcase=None, **kwargs): #pylint:disable=arguments-differ
        with self.fire_context(*args, **kwargs) as flight:
            if testcase is not None:
                if type(testcase) is bytes:
                    testcase = Arrowhead.oneshot(testcase)
                testcase.run(flight)
            else:
                time.sleep(0.2)
        return flight.result

    @contextmanager
    def fire_context(self, *args, **kwargs):  # -> ContextManager[Flight]:
        """
        A context manager for the bow. Should yield a Flight object.
        """

        with self.target.run_context(*args, **kwargs) as p:
            flight = Flight(self.target, p)
            try:
                yield flight
            finally:
                flight.stop(timeout=60)


from .angr_project import angrProjectBow
from .angr_state import angrStateBow
from .qemu_tracer import QEMUTracerBow
from .datascout import DataScoutBow
from .gdbserver import GDBServerBow
from .core import CoreBow
from .ltrace import LTraceBow, LTraceAttachBow
from .strace import STraceBow, STraceAttachBow
from .input_fd import InputFDBow
from .rr import RRTracerBow
from .. import arrows
