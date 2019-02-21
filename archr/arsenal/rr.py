import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import time
import os

l = logging.getLogger("archr.arsenal.rr_tracer")

from . import Bow

try:
    import trraces
except ImportError:
    trraces = None


class FakeTempdir:
    def __init__(self, path):
        self.name = path

    def cleanup(self):
        return


class RRTraceResults:
    process = None

    returncode = None
    signal = None
    crashed = False
    timed_out = False

    trace_dir = None

    def __init__(self, trace_dir=None):
        if trace_dir is None:
            self.trace_dir = tempfile.TemporaryDirectory(prefix='rr_trace_dir_')
        else:
            self.trace_dir = FakeTempdir(trace_dir)

    def tracer_technique(self, **kwargs):
        if trraces is None:
            raise Exception("need to install trraces")
        return trraces.replay_interfaces.angr.technique.Trracer(os.path.join(self.trace_dir.name, 'latest-trace'), **kwargs)


class RRTracerBow(Bow):
    REQUIRED_ARROW = "rr"

    def __init__(self, target, timeout=10, local_trace_dir='/tmp/rr_trace/'):
        super().__init__(target)
        self.timeout = timeout
        self.local_trace_dir = local_trace_dir

    @contextlib.contextmanager
    def _target_mk_tmpdir(self):
        tmpdir = tempfile.mktemp(prefix="/tmp/rr_tracer_")
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

    def fire(self, *args, testcase=(), **kwargs):  # pylint:disable=arguments-differ
        if type(testcase) in [str, bytes]:
            testcase = [testcase]

        with self.fire_context(*args, **kwargs) as r:
            for t in testcase:
                r.process.stdin.write(t.encode('utf-8') if type(t) is str else t)
                time.sleep(0.01)
            r.process.stdin.close()

        return r

    def find_target_home_dir(self):
        with self.target.run_context(['env']) as p:
            stdout, stderr = p.communicate()
            assert not stderr.split()
            home_dir = stdout.split(b'HOME=')[1].split(b'\n')[0]
            return home_dir.decode("utf-8")

    @contextlib.contextmanager
    def fire_context(self, save_core=False, record_magic=False, report_bad_args=False):
        if save_core or record_magic or report_bad_args:
            raise ArchrError("I can't do any of these things!")

        if self.local_trace_dir and os.path.exists(self.local_trace_dir):
            shutil.rmtree(self.local_trace_dir)
            os.mkdir(self.local_trace_dir)

        record_command = ['/tmp/rr/fire', 'record', '-n'] + self.target.target_args
        record_env = ['RR_COPY_ALL_FILES=1']
        with self.target.run_context(record_command, env=record_env, timeout=self.timeout) as p:
            r = RRTraceResults(trace_dir=self.local_trace_dir)
            r.process = p

            try:
                yield r
                r.timed_out = False

                r.returncode = r.process.wait()
                assert r.returncode is not None

                # did a crash occur?
                if r.returncode in [139, -11]:
                    r.crashed = True
                    r.signal = signal.SIGSEGV
                elif r.returncode == [132, -9]:
                    r.crashed = True
                    r.signal = signal.SIGILL

            except subprocess.TimeoutExpired:
                r.timed_out = True

        self.target.run_command(['/tmp/rr/fire', 'pack']).communicate()
        path = self.find_target_home_dir() + '/.local/share/rr/latest-trace/'
        with self._local_mk_tmpdir() as tmpdir:
            self.target.retrieve_into(path, tmpdir)
            shutil.move(tmpdir + '/latest-trace/', r.trace_dir.name)

    def _build_command(self, options=None):
        """
        Here, we build the tracing command.
        """

        #
        # First, the arrow invocation
        #
        cmd_args = ["/tmp/rr/fire"] + options

        #
        # Now, we add the program arguments.
        #
        cmd_args += self.target.target_args

        return cmd_args


from ..errors import ArchrError
