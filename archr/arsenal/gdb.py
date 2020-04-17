from ..errors import ArchrError
from . import ContextBow
import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import os
import time

l = logging.getLogger("archr.arsenal.gdb")


class GDBResult:
    returncode = None
    signal = None
    crashed = False
    timed_out = False


class GDBBow(ContextBow):
    REQUIRED_ARROW = "gdb"

    def __init__(self, target, timeout=10, local_trace_dir=None, symbolic_fd=None):
        super().__init__(target)
        self.timeout = timeout
        self.local_trace_dir = local_trace_dir



class RRReplayBow(ContextBow):
    def __init__(self, target, timeout):
        super().__init__(target)
        self.timeout = timeout

    @contextlib.contextmanager
    def fire_context(self, prefix_args=None, gdb_args=None, trace_dir=None, gdb_script=None, sleep_time=0.1):
        """Run the target with gdb.

        Keyword arguments:
        prefix_args -- additional commands BEFORE the gdb command (default None)
        gdb_args -- addition args for gdb (default None)
        gdb_script -- Path of an optional gdb_script file (default None)
        """

        fire_path = os.path.join(self.target.tmpwd, "gdb", "fire")
        gdb_command = []
        if prefix_args:
            gdb_command += prefix_args
        gdb_command += [fire_path]
        if gdb_args:
            gdb_command += gdb_args
        if gdb_script:
            paths = {}
            d_src = os.path.dirname(gdb_script)
            d_dst = os.path.dirname(fire_path)
            paths[d_dst] = d_src
            self.target.inject_paths(paths)
            script_remote_path = os.path.join(
                d_dst, os.path.basename(gdb_script))
            gdb_command += ["-x", script_remote_path]

        r = GDBResult()
        try:
            with self.target.flight_context(gdb_command, timeout=self.timeout, result=r) as flight:
                # TODO: we need a better way of dealing with this, dnsmasq is too slow at initializing
                time.sleep(sleep_time)
                yield flight
        except subprocess.TimeoutExpired:
            r.timed_out = True
        else:
            r.timed_out = False

            r.returncode = flight.process.returncode
            assert r.returncode is not None

            # did a crash occur?
            if r.returncode in [139, -11]:
                r.crashed = True
                r.signal = signal.SIGSEGV
            elif r.returncode == [132, -9]:
                r.crashed = True
                r.signal = signal.SIGILL
