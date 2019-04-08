import logging

l = logging.getLogger("archr.arsenal.input_fd")

from . import Bow
from ..arrowhead import Arrowhead

class InputFDBow(Bow):
    """
    Figures out what file descriptor the target uses to read input.
    """

    def fire(self, **kwargs): #pylint:disable=arguments-differ
        strace = STraceBow(self.target).fire(trace_args=["-f"], testcase=Arrowhead.oneshot(b"aRcHr"*0x1000))
        archr_lines = [ line for line in strace.splitlines() if b"aRcHr" in line ]
        archr_read = [ line for line in archr_lines if line.startswith(b"read") or line.startswith(b"recv") ]
        fd = archr_read[0].split()[0].split(b"(")[1].split(b",")[0]
        return int(fd)

from .strace import STraceBow
