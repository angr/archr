import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import angr
import glob
import re
import os


l = logging.getLogger("archr.arsenal.qemu_tracer")

from . import ContextBow

class QemuTraceResult:
    # results
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

    def tracer_technique(self, **kwargs):
        return angr.exploration_techniques.Tracer(self.trace, crash_addr=self.crash_address, **kwargs)

_trace_old_re = re.compile(br'Trace (.*) \[(?P<addr>.*)\].*')
_trace_new_re = re.compile(br'Trace (.*) \[(?P<something1>.*)\/(?P<addr>.*)\/(?P<flags>.*)\].*')

class QEMUTracerBow(ContextBow):
    REQUIRED_ARROW = "shellphish_qemu"

    def __init__(self, target, timeout=10, ld_linux=None, library_path=None, seed=None, **kwargs):
        super().__init__(target, **kwargs)
        self.timeout = timeout
        self.ld_linux = ld_linux
        self.library_path = library_path
        self.seed = seed

    @contextlib.contextmanager
    def _target_mk_tmpdir(self):
        tmpdir = tempfile.mktemp(prefix="/tmp/tracer_target_")
        self.target.run_command(["mkdir", tmpdir]).wait()
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

    @contextlib.contextmanager
    def fire_context(self, record_trace=True, record_magic=False, save_core=False):
        with self._target_mk_tmpdir() as tmpdir:
            tmp_prefix = tempfile.mktemp(dir='/tmp', prefix="tracer-")
            target_trace_filename = tmp_prefix + ".trace" if record_trace else None
            target_magic_filename = tmp_prefix + ".magic" if record_magic else None
            local_core_filename = tmp_prefix + ".core" if save_core else None

            target_cmd = self._build_command(trace_filename=target_trace_filename, magic_filename=target_magic_filename, coredump_dir=tmpdir)

            r = QemuTraceResult()

            try:
                with self.target.flight_context(target_cmd, timeout=self.timeout, result=r) as flight:
                    yield flight
            except subprocess.TimeoutExpired:
                r.timed_out = True
            else:
                r.timed_out = False
                r.returncode = flight.process.returncode

                # did a crash occur?
                if r.returncode in [ 139, -11 ]:
                    r.crashed = True
                    r.signal = signal.SIGSEGV
                elif r.returncode == [ 132, -9 ]:
                    r.crashed = True
                    r.signal = signal.SIGILL

            if local_core_filename:
                target_cores = self.target.resolve_glob(os.path.join(tmpdir, "qemu_*.core"))
                if len(target_cores) != 1:
                    raise ArchrError("expected 1 core file but found %d" % len(target_cores))
                with self._local_mk_tmpdir() as local_tmpdir:
                    self.target.retrieve_into(target_cores[0], local_tmpdir)
                    cores = glob.glob(os.path.join(local_tmpdir, "qemu_*.core"))
                    shutil.move(cores[0], local_core_filename)
                    r.core_path = local_core_filename

            if target_trace_filename:
                trace = self.target.retrieve_contents(target_trace_filename)
                trace_iter = iter(trace.splitlines())

                # Find where qemu loaded the binary. Primarily for PIE
                r.base_address = int(next(t.split()[1] for t in trace_iter if t.startswith(b"start_code")), 16) #pylint:disable=stop-iteration-return

                # record the trace
                _trace_re = _trace_old_re if self.target.target_os == 'cgc' else _trace_new_re
                r.trace = [
                    int(_trace_re.match(t).group('addr'), 16) for t in trace_iter if t.startswith(b"Trace ")
                ]

                # grab the faulting address
                if r.crashed:
                    lastline = trace.split(b'\n')[-2]
                    if lastline.startswith(b"Trace") or lastline.find(b"Segmentation") == -1:
                        l.warning("Trace return code was less than zero, but the last line of the trace does not"
                                  "contain the uncaught exception error from qemu."
                                  "If using an older version of shellphish_qemu try using 'ulimit -Sc 0' or "
                                  "updating to a newer version of shellphish_qemu.")
                    r.crash_address = int(lastline.split(b'[')[1].split(b']')[0], 16)

                l.debug("Trace consists of %d basic blocks", len(r.trace))

            if target_magic_filename:
                r.magic_contents = self.target.retrieve_contents(target_magic_filename)
                if len(r.magic_contents) != 0x1000:
                    raise ArchrError("Magic content read from QEMU improper size, should be a page in length")



    @staticmethod
    def qemu_variant(target_os, target_arch, record_trace):
        """
        Need to know if we're tracking or not, specifically for what cgc qemu to use.
        """

        if target_os == 'cgc':
            suffix = "tracer" if record_trace else "base"
            qemu_variant = "shellphish-qemu-cgc-%s" % suffix
        else:
            qemu_variant = "shellphish-qemu-linux-%s" % target_arch

        return qemu_variant

    def _build_command(self, trace_filename=None, magic_filename=None, coredump_dir=None, report_bad_args=None):
        """
        Here, we build the tracing command.
        """

        #
        # First, the arrow invocation
        #

        qemu_variant = self.qemu_variant(self.target.target_os, self.target.target_arch, trace_filename is not None)
        # cmd_args = [ "sudo", "/tmp/shellphish_qemu/fire", qemu_variant]
        fire_path = os.path.join(self.target.tmpwd, "shellphish_qemu", "fire")
        cmd_args = [fire_path, qemu_variant]
        cmd_args += [ "-C", coredump_dir]

        #
        # Next, we build QEMU options.
        #

        # hardcode an argv[0]
        #cmd_args += [ "-0", program_args[0] ]

        # record trace
        if trace_filename:
            cmd_args += ["-d", "nochain,exec,page", "-D", trace_filename] if 'cgc' not in qemu_variant else ["-d", "exec", "-D", trace_filename]
        else:
            cmd_args += ["-enable_double_empty_exiting"]

        # save CGC magic page
        if magic_filename:
            if 'cgc' not in qemu_variant:
                raise ArchrError("Specified magic page dump on non-cgc architecture")
            cmd_args += ["-magicdump", magic_filename]

        if self.seed is not None:
            cmd_args.append("-seed")
            cmd_args.append(str(self.seed))

        if report_bad_args:
            cmd_args += ["-report_bad_args"]

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in qemu_variant:
            cmd_args += ["-m", "8G"]

        if 'cgc' not in qemu_variant and "LD_BIND_NOW=1" not in self.target.target_env:
            l.warning("setting LD_BIND_NOW=1. This will have an effect on the environment.")
            cmd_args += ['-E', 'LD_BIND_NOW=1']

        if self.library_path and not self.ld_linux:
            l.warning("setting LD_LIBRARY_PATH. This will have an effect on the environment. Consider using --library-path instead")
            cmd_args += ['-E', 'LD_LIBRARY_PATH=' + self.library_path]

        # now set up the loader
        if self.ld_linux:
            cmd_args += [self.ld_linux]
            if self.library_path:
                cmd_args += ['--library-path', self.library_path]

        # Now, we add the program arguments.
        cmd_args += self.target.target_args

        return cmd_args

from ..errors import ArchrError
