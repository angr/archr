import logging
import time

from .base import Analyzer
from .strace import STraceAnalyzer

log = logging.getLogger("archr.analyzers.input_fd")


class InputFDAnalyzer(Analyzer):
    """
    Figures out what file descriptor the target uses to read input.
    """

    def fire(self):  # pylint:disable=arguments-differ
        with STraceAnalyzer(self.target).fire_context(trace_args=["-f"]) as flight:
            time.sleep(0.1)
            flight.default_channel.write(b"aRcHr" * 0x1000)
            flight.default_channel.recv_until(b"aRcHr")
            flight.default_channel.close()
        strace = flight.result
        archr_lines = [line for line in strace.splitlines() if b"aRcHr" in line]
        archr_read = [line for line in archr_lines if line.startswith((b"read", b"recv"))]
        fd = archr_read[0].split()[0].split(b"(")[1].split(b",")[0]
        return int(fd)
