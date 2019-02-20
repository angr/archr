import logging
import time

l = logging.getLogger("archr.arsenal.angr_state")

from . import Bow

class InputFDBow(Bow):
    """
    Figures out what file descriptor the target uses to read input.
    """

    def fire(self, **kwargs): #pylint:disable=arguments-differ
        with STraceBow(self.target).fire_context(trace_args=["-f"]) as stb:
            time.sleep(1)
            ncb = NetCatBow(self.target).fire(run=False)
            ncb.write(b"aRcHr"*0x1000)
            ncb.close()

        trace = stb.stderr.read()
        archr_lines = [ line for line in trace.splitlines() if b"aRcHr" in line ]
        archr_read = [ line for line in archr_lines if line.startswith(b"read") or line.startswith(b"recv") ]
        fd = archr_read[0].split()[0].split(b"(")[1].split(b",")[0]
        return int(fd)

from .nc import NetCatBow
from .strace import STraceBow
