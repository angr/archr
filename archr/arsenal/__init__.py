import subprocess
import time
import sys
import os

class Flight:
    """
    A flight is the result of firing a bow at a given target.
    Yes, the metaphor is getting stretched a little thin.
    """
    def __init__(self, target):
        self.target = target


class ProcessFlight(Flight):
    """
    A process flight is a flight for a bow which has spawned a process in the target.
    """
    def __init__(self, target, process):
        super().__init__(target)
        self.process = process
        self.connections = []

    @property
    def default_input(self):
        if not self.target.tcp_ports and not self.target.udp_ports:
            return self.process.stdin
        elif not self.connections:
            nc = NetCatBow(self.target).fire(run=False).nc
            self.connections.append(nc)
            return nc
        else:
            return self.connections[0]

    @property
    def default_output(self):
        if not self.target.tcp_ports and not self.target.udp_ports:
            return self.process.output
        elif not self.connections:
            nc = NetCatBow(self.target).fire(run=False).nc
            self.connections.append(nc)
            return nc
        else:
            return self.connections[0]

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
    Provides a default .fire() that replays a testcase consisting of a series of strings/bytes.
    """

    def fire(self, *args, testcase=None, **kwargs): #pylint:disable=arguments-differ
        with self.fire_context(*args, **kwargs) as r:
            proc = r.process
            testcase.run(proc)
            proc.stdin.close()

        return r

    def fire_context(self, *args, **kwargs):
        """
        A context manager for the bow. Should yield an object that has a "process" attribute.
        """
        raise NotImplementedError()



from .angr_project import angrProjectBow
from .angr_state import angrStateBow
from .nc import NetCatBow
from .qemu_tracer import QEMUTracerBow
from .datascout import DataScoutBow
from .gdbserver import GDBServerBow
from .core import CoreBow
from .ltrace import LTraceBow
from .strace import STraceBow
from .input_fd import InputFDBow
from .rr import RRTracerBow
from .. import arrows
