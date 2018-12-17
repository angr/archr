import sys

class Bow:
    REQUIRED_ARROWS = []

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
        if type(self.REQUIRED_ARROWS) in {str, bytes}:
            self.REQUIRED_ARROWS = [self.REQUIRED_ARROWS]

        for arrow in self.REQUIRED_ARROWS:
            with arrows.bundle(arrow) as b:
                self.target.inject_path(b, "/tmp/%s" % arrow)

    def fire(self, *args, **kwargs):
        """
        Fire the bow at the target.
        """
        raise NotImplementedError()

from .angr_project import angrProjectBow
from .angr_state import angrStateBow
from .nc import NetCatBow
from .qemu_tracer import QEMUTracerBow
from .datascout import DataScoutBow
from .gdbserver import GDBServerBow
from .rr import RRTracerBow
from .. import arrows
