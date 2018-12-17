import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import time
import glob
import re
import os

l = logging.getLogger("archr.arsenal.rr_tracer")

from . import Bow


class TraceResults:
    process = None
    socket = None

    # results
    rr_trace_dir = None
    returncode = None
    signal = None
    crashed = None
    timed_out = None

    # introspection
    trace = None
    crash_address = None
    base_address = None
    magic_contents = None
    core_path = None



class RRTracerBow(Bow):
    REQUIRED_ARROWS = ["rr", "gdb"]

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

    @contextlib.contextmanager
    def fire_context(self, timeout=10, **kwargs):
        assert self.target.target_path.startswith(
            "/"), "The qemu tracer currently chdirs into a temporary directory, and cannot handle relative argv[0] paths."

        with self._target_mk_tmpdir() as tmpdir:
            tmp_prefix = tempfile.mktemp(dir='/tmp', prefix="rr_tracer-")

            with self.target.run_context(self._build_command(['record', '-n']), timeout=timeout) as p:
                r = TraceResults()
                r.process = p

                try:
                    yield r
                    r.timed_out = False
                except subprocess.TimeoutExpired:
                    r.timed_out = True

            #with self.target.run_context(["/tmp/rr/fire", 'replay', '-d', ''])
            import ipdb; ipdb.set_trace()
            if not r.timed_out:
                r.returncode = r.process.returncode

                # did a crash occur?
                if r.returncode in [139, -11]:
                    r.crashed = True
                    r.signal = signal.SIGSEGV
                elif r.returncode == [132, -9]:
                    r.crashed = True
                    r.signal = signal.SIGILL

            # if local_core_filename:
            #     target_cores = self.target.resolve_glob(os.path.join(tmpdir, "qemu_*.core"))
            #     if len(target_cores) != 1:
            #         raise ArchrError("expected 1 core file but found %d" % len(target_cores))
            #     with self._local_mk_tmpdir() as local_tmpdir:
            #         self.target.retrieve_into(target_cores[0], local_tmpdir)
            #         cores = glob.glob(os.path.join(local_tmpdir, "qemu_*.core"))
            #         shutil.move(cores[0], local_core_filename)
            #         r.core_path = local_core_filename
            #
            # if target_trace_filename:
            #     trace = self.target.retrieve_contents(target_trace_filename)
            #     trace_iter = iter(trace.splitlines())
            #
            #     # Find where qemu loaded the binary. Primarily for PIE
            #     r.base_address = int(next(t.split()[1] for t in trace_iter if t.startswith(b"start_code")),
            #                          16)  # pylint:disable=stop-iteration-return
            #
            #     # record the trace
            #     r.trace = [
            #         int(_trace_re.match(t).group('addr'), 16) for t in trace_iter if t.startswith(b"Trace ")
            #     ]
            #
            #     # grab the faulting address
            #     if r.crashed:
            #         r.crash_address = r.trace[-1]
            #
            #     l.debug("Trace consists of %d basic blocks", len(r.trace))
            #
            # if target_magic_filename:
            #     r.magic_contents = self.target.retrieve_contents(target_magic_filename)
            #     assert len(
            #         r.magic_contents) == 0x1000, "Magic content read from QEMU improper size, should be a page in length"

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
