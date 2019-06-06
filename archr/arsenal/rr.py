import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import os
import re
import time

l = logging.getLogger("archr.arsenal.rr_tracer")

from . import ContextBow

try:
    import trraces
except ImportError:
    trraces = None


class FakeTempdir:
    def __init__(self, path):
        self.name = path

    def cleanup(self):
        return

def fix_perf():
    with open("/proc/sys/kernel/perf_event_paranoid", 'rb') as c:
        if c.read().strip() != b"-1":
            l.warning("/proc/sys/kernel/perf_event_paranoid needs to be '-1'. I am setting this system-wide.")
            os.system(_super_perf_cmd)
_super_perf_cmd = "echo 0 | docker run --rm --privileged -i ubuntu tee /proc/sys/kernel/perf_event_paranoid"

class RRTraceResult:
    returncode = None
    signal = None
    crashed = False
    timed_out = False

    trace_dir = None
    symbolic_fd = None

    def __init__(self, trace_dir=None, symbolic_fd=None):
        if trace_dir is None:
            self.trace_dir = tempfile.TemporaryDirectory(prefix='rr_trace_dir_')
        else:
            self.trace_dir = FakeTempdir(trace_dir)
        self.symbolic_fd = symbolic_fd

    def tracer_technique(self, **kwargs):
        if trraces is None:
            raise Exception("need to install trraces")
        return trraces.replay_interfaces.angr.technique.Trracer(self.trace_dir.name, symbolic_fd=self.symbolic_fd, **kwargs)


class RRTracerBow(ContextBow):
    REQUIRED_ARROW = "rr"
    REMOTE_TRACE_DIR_PREFIX = "/tmp/rr_trace_"

    def __init__(self, target, timeout=10, local_trace_dir=None, symbolic_fd=None):
        super().__init__(target)
        self.timeout = timeout
        self.local_trace_dir = local_trace_dir
        self.symbolic_fd = symbolic_fd

    @contextlib.contextmanager
    def _target_mk_tmpdir(self):
        tmpdir = tempfile.mktemp(prefix=self.REMOTE_TRACE_DIR_PREFIX)
        self.target.run_command(["rm", "-rf", tmpdir]).wait()
        self.target.run_command(["mkdir", tmpdir]).wait()
        try:
            yield tmpdir
        finally:
            self.target.run_command(["rmdir", tmpdir])

    @staticmethod
    @contextlib.contextmanager
    def _local_mk_tmpdir():
        tmpdir = tempfile.mkdtemp(prefix="/tmp/rr_tracer_")
        try:
            yield tmpdir
        finally:
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(tmpdir)

    def find_target_home_dir(self):
        with self.target.run_context(['env']) as p:
            stdout, stderr = p.communicate()
            assert not stderr.split()
            home_dir = stdout.split(b'\nHOME=')[1].split(b'\n')[0]
            return home_dir.decode("utf-8")

    @contextlib.contextmanager
    def fire_context(self, save_core=False, record_magic=False, report_bad_args=False):
        if save_core or record_magic or report_bad_args:
            raise ArchrError("I can't do any of these things!")

        fix_perf()

        if self.local_trace_dir:
            if os.path.exists(self.local_trace_dir):
                shutil.rmtree(self.local_trace_dir)
            os.mkdir(self.local_trace_dir)
        else:
            self.local_trace_dir = tempfile.mkdtemp(prefix="/tmp/rr_tracer_")


        with self._target_mk_tmpdir() as remote_tmpdir:
            fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
            record_command = [fire_path, 'record', '-n']
            record_command += trraces.rr_unsupported_cpuid_features.rr_cpuid_filter_cmd_line_args()
            record_command += self.target.target_args
            record_env = ['_RR_TRACE_DIR=' + remote_tmpdir]
            r = RRTraceResult(trace_dir=self.local_trace_dir, symbolic_fd=self.symbolic_fd)
            try:
                with self.target.flight_context(record_command, env=record_env, timeout=self.timeout, result=r) as flight:
                    # TODO: we need a better way of dealing with this, dnsmasq is too slow at initializing
                    time.sleep(0.1)
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

            path = remote_tmpdir + '/latest-trace/'
            fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
            self.target.run_command([fire_path, 'pack', path]).communicate()
            with self._local_mk_tmpdir() as local_tmpdir:
                self.target.retrieve_into(path, local_tmpdir)
                os.rename(local_tmpdir + '/latest-trace/', r.trace_dir.name.rstrip('/'))

            assert os.path.isfile(os.path.join(r.trace_dir.name, 'version'))

    def _build_command(self, options=None):
        """
        Here, we build the tracing command.
        """

        #
        # First, the arrow invocation
        #
        fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
        cmd_args = [fire_path] + options

        #
        # Now, we add the program arguments.
        #
        cmd_args += self.target.target_args

        return cmd_args


from ..errors import ArchrError
