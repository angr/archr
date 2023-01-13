from ..errors import ArchrError
from . import ContextAnalyzer
import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import os
import time

l = logging.getLogger("archr.analyzers.gdb")


class FakeTempdir:
    def __init__(self, path):
        self.name = path

    def cleanup(self):
        return


class GDBResult:
    returncode = None
    signal = None
    crashed = False
    timed_out = False

    def __init__(self, trace_dir=None):
        if trace_dir is None:
            self.trace_dir = tempfile.TemporaryDirectory(prefix="gdb_trace_dir_")
        else:
            self.trace_dir = FakeTempdir(trace_dir)


class GDBAnalyzer(ContextAnalyzer):
    REQUIRED_IMPLANT = "gdb"

    def __init__(self, target, local_trace_dir=None, timeout=10):
        super().__init__(target)
        self.timeout = timeout
        self.local_trace_dir = local_trace_dir

    @contextlib.contextmanager
    def fire_context(self, prefix_args=None, gdb_args=None, gdb_script=None, sleep_time=0.1):
        """Run the target with gdb.

        Keyword arguments:
        prefix_args -- additional commands BEFORE the gdb command (default None)
        gdb_args -- addition args for gdb (default None)
        gdb_script -- Path of an optional gdb_script file (default None)
        """

        if self.local_trace_dir:
            if os.path.exists(self.local_trace_dir):
                shutil.rmtree(self.local_trace_dir)
            os.mkdir(self.local_trace_dir)
        else:
            self.local_trace_dir = tempfile.mkdtemp(prefix="/tmp/gdb_tracer_")

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
            script_remote_path = os.path.join(d_dst, os.path.basename(gdb_script))
            gdb_command += ["-x", script_remote_path]
            gdb_command += ["--args"]
            gdb_command += self.target.target_args

        r = GDBResult(trace_dir=self.local_trace_dir)
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
