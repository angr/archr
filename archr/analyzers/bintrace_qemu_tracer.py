import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import glob
import re
import os
import importlib

from io import BytesIO


l = logging.getLogger(__file__)

from . import ContextAnalyzer
from .. import _angr_available

if _angr_available:
    import angr

from ..utils import filter_strace_output, get_file_maps


try:
    have_bintrace_qemu = importlib.import_module("bintrace-qemu")
except ModuleNotFoundError:
    have_bintrace_qemu = False


class BintraceQEMUTracerError(BaseException):
    pass


class QemuTraceResult:
    # results
    returncode = None
    signal = None
    crashed = None
    timed_out = None
    tracepath = None

    # introspection
    trace = None
    mapped_files = None
    crash_address = None
    base_address = None
    image_base = None
    entry_point = None
    magic_contents = None
    halfway_core_path = None
    core_path = None
    taint_fd = None

    def tracer_technique(self, **kwargs):
        return angr.exploration_techniques.Tracer(self.trace, crash_addr=self.crash_address, **kwargs)


_trace_old_re = re.compile(rb"Trace (.*) \[(?P<addr>.*)\].*")
_trace_new_re = re.compile(rb"Trace (.*) \[(?P<something1>.*)\/(?P<addr>.*)\/(?P<flags>.*)\].*")


class BintraceQEMUTracerAnalyzer(ContextAnalyzer):
    REQUIRED_IMPLANT = "bintrace_qemu"

    def __init__(self, target, timeout=10, ld_linux=None, ld_preload=None, library_path=None, seed=None, **kwargs):
        super().__init__(target, **kwargs)
        self.timeout = timeout
        self.ld_linux = ld_linux
        self.ld_preload = ld_preload
        self.library_path = library_path
        self.seed = seed

        assert self.target.target_os != "cgc"

    def pickup_env(self):
        for e in self.target.target_env:
            key, value = e.split("=", 1)
            if key == "LD_PRELOAD" and self.ld_preload is None:
                self.ld_preload = value
            if key == "LD_LIBRARY_PATH" and self.library_path is None:
                self.library_path = value

    @contextlib.contextmanager
    def _target_mk_tmpdir(self):
        tmpdir = tempfile.mktemp(prefix="/tmp/tracer_target_")
        self.target.run_command(["mkdir", tmpdir]).wait()
        self.target.run_command(["chmod", "777", tmpdir]).wait()
        try:
            yield tmpdir
        finally:
            self.target.run_command(["rm", "-rf", tmpdir])

    @staticmethod
    @contextlib.contextmanager
    def _local_mk_tmpdir():
        tmpdir = tempfile.mkdtemp(prefix="/tmp/tracer_local_")
        try:
            yield tmpdir
        finally:
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(tmpdir)

    @staticmethod
    def line_iter(content):
        io = BytesIO(content)
        for line in io:
            yield line.strip()

    @contextlib.contextmanager
    def fire_context(self, record_trace=True, **kwargs):  # pylint:disable=arguments-differ
        with self._target_mk_tmpdir() as tmpdir:
            tmp_prefix = tempfile.mktemp(dir="/tmp", prefix="tracer-")
            target_trace_filename = tmp_prefix + ".trace"
            target_cmd = self._build_command(target_trace_filename)

            l.debug("launch QEMU with command: %s", " ".join(target_cmd))
            r = QemuTraceResult()

            try:
                with self.target.flight_context(target_cmd, timeout=self.timeout, result=r, **kwargs) as flight:
                    yield flight
            except subprocess.TimeoutExpired:
                r.timed_out = True
            else:
                r.timed_out = False
                r.returncode = flight.process.returncode

                # did a crash occur?
                if r.returncode in [139, -11]:
                    r.crashed = True
                    r.signal = signal.SIGSEGV
                elif r.returncode == [132, -9]:
                    r.crashed = True
                    r.signal = signal.SIGILL

            l.debug(
                "Qemu tracer returned with code=%s timed_out=%s crashed=%s signal=%s",
                r.returncode,
                r.timed_out,
                r.crashed,
                r.signal,
            )

            trace_output_dir = tempfile.TemporaryDirectory(prefix="tracer-")
            trace_outputs = self.target.resolve_glob(target_trace_filename + "*")
            l.debug("Found trace files: %s", trace_outputs)
            for f in trace_outputs:
                l.debug("Copying %s", f)
                data = self.target.retrieve_contents(f)
                with open(os.path.join(trace_output_dir.name, os.path.basename(f)), "wb") as f:
                    f.write(data)

            tracefile = tempfile.NamedTemporaryFile(prefix="tracer-", suffix=".tar.gz", delete=False)
            tracefile.close()

            r.tracepath = tracefile.name
            l.debug("Compressing trace file")
            subprocess.run(
                ["tar", "czvf", os.path.basename(r.tracepath), os.path.basename(trace_output_dir.name)],
                check=True,
                cwd="/tmp",
            )
            l.error("Trace saved to %s", r.tracepath)
            trace_output_dir.cleanup()

    @staticmethod
    def qemu_variant(target_os, target_arch, record_trace):
        """
        Need to know if we're tracking or not, specifically for what cgc qemu to use.
        """

        if target_os == "cgc":
            suffix = "tracer" if record_trace else "base"
            qemu_variant = "shellphish-qemu-cgc-%s" % suffix
        else:
            qemu_variant = "shellphish-qemu-linux-%s" % target_arch

        return qemu_variant

    def _build_command(self, trace_filename=None):
        """
        Here, we build the tracing command.
        """

        fire_path = os.path.join(self.target.tmpwd, "bintrace_qemu", "fire")
        cmd_args = [fire_path, trace_filename or "/out.trace"]

        if self.ld_preload:
            cmd_args += ["-E", "LD_PRELOAD=" + self.ld_preload]

        if self.library_path and not self.ld_linux:
            cmd_args += ["-E", "LD_LIBRARY_PATH=" + self.library_path]

        # now set up the loader
        if self.ld_linux:
            cmd_args += [self.ld_linux]
            if self.library_path:
                cmd_args += ["--library-path", self.library_path]

        # Now, we add the program arguments.
        cmd_args += ["--"]  # separate QEMU arguments and target arguments
        cmd_args += self.target.target_args

        l.info("tracer invocation: " + str(cmd_args))

        return cmd_args
