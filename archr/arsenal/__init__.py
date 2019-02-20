import subprocess
import time
import sys
import os

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

    def fire(self, *args, testcase=(), **kwargs): #pylint:disable=arguments-differ
        if type(testcase) in [ str, bytes ]:
            testcase = [ testcase ]

        with self.fire_context(*args, **kwargs) as r:
            if isinstance(r, subprocess.Popen):
                proc = r
            else:
                proc = r.process

            for t in testcase:
                proc.stdin.write(t.encode('utf-8') if type(t) is str else t)
                time.sleep(0.01)
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
from .. import arrows
