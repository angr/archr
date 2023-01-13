from ..errors import ArchrError
from . import ContextAnalyzer
import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import os
import re
import time

l = logging.getLogger("archr.analyzers.rr_tracer")


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
    with open("/proc/sys/kernel/perf_event_paranoid", "rb") as c:
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
    remote_trace_dir = None
    symbolic_fd = None

    def __init__(self, trace_dir=None, symbolic_fd=None):
        if trace_dir is None:
            self.trace_dir = tempfile.TemporaryDirectory(prefix="rr_trace_dir_")
        else:
            self.trace_dir = FakeTempdir(trace_dir)
        self.symbolic_fd = symbolic_fd

    def tracer_technique(self, **kwargs):
        if trraces is None:
            raise Exception("need to install trraces")
        return trraces.replay_interfaces.angr.technique.Trracer(
            self.trace_dir.name, symbolic_fd=self.symbolic_fd, **kwargs
        )


class RRAnalyzer(ContextAnalyzer):
    REQUIRED_IMPLANT = "rr"
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
        with self.target.run_context(["env"]) as p:
            stdout, stderr = p.communicate()
            assert not stderr.split()
            home_dir = stdout.split(b"\nHOME=")[1].split(b"\n")[0]
            return home_dir.decode("utf-8")

    def _build_command(self, options=None):
        """
        Here, we build the tracing command.
        """

        #
        # First, the implant invocation
        #
        fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
        cmd_args = [fire_path] + options

        #
        # Now, we add the program arguments.
        #
        cmd_args += self.target.target_args

        return cmd_args


class RRTracerAnalyzer(RRAnalyzer):
    @contextlib.contextmanager
    def fire_context(self, save_core=False, record_magic=False, report_bad_args=False, rr_args=None, sleep_time=0.1):
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
            record_command = [fire_path, "record", "-n"]
            if trraces:
                record_command += trraces.rr_unsupported_cpuid_features.rr_cpuid_filter_cmd_line_args()
            if rr_args:
                record_command += rr_args
            record_command += self.target.target_args
            record_env = ["_RR_TRACE_DIR=" + remote_tmpdir]
            r = RRTraceResult(trace_dir=self.local_trace_dir, symbolic_fd=self.symbolic_fd)
            try:
                with self.target.flight_context(
                    record_command,
                    env=record_env,
                    timeout=self.timeout,
                    result=r,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ) as flight:
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
            path = remote_tmpdir + "/latest-trace/"
            r.remote_trace_dir = path
            fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
            self.target.run_command([fire_path, "pack", path]).communicate()
            with self._local_mk_tmpdir() as local_tmpdir:
                self.target.retrieve_into(path, local_tmpdir)
                os.rename(local_tmpdir + "/latest-trace/", r.trace_dir.name.rstrip("/"))

            assert os.path.isfile(os.path.join(r.trace_dir.name, "version"))


class RRReplayAnalyzer(RRAnalyzer):
    @contextlib.contextmanager
    def fire_context(self, rr_args=None, trace_dir=None, gdb_script=None, pid=None):
        """Run an rr-replay inside the target.

        Keyword arguments:
        rr_args -- additional rr arguments (default None)
        trace_dir -- directory containing the rr-trace in the target (default None)
        gdb_script -- Path of an optional gdb_script file (default None)
        pid -- pid to attach instead of the initial one, see rr(1) (Give N/-N for the Nth/Nth-last pid in the trace)
        """
        fix_perf()

        fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
        replay_command = [fire_path, "replay"]
        if trraces:
            replay_command += trraces.rr_unsupported_cpuid_features.rr_cpuid_filter_cmd_line_args()
        if rr_args:
            replay_command += rr_args
        if gdb_script:
            paths = {}
            d_src = os.path.dirname(gdb_script)
            d_dst = os.path.dirname(fire_path)
            paths[d_dst] = d_src
            self.target.inject_paths(paths)
            script_remote_path = os.path.join(d_dst, os.path.basename(gdb_script))
            replay_command += ["-x", script_remote_path]
        if pid:
            actual_pid = self.get_trace_pid(trace_dir, pid)
            if not actual_pid:
                l.error("archr-ERROR: Couldn't get PID: %d from trace %s", pid, trace_dir)
                return None
            replay_command += ["-p", str(actual_pid)]
        if trace_dir:
            replay_command += [trace_dir]
        r = RRTraceResult(trace_dir=self.local_trace_dir, symbolic_fd=self.symbolic_fd)
        try:
            with self.target.flight_context(replay_command, timeout=self.timeout, result=r) as flight:
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

    def get_trace_pid(self, trace_dir, pid_idx):
        pids = []
        fire_path = os.path.join(self.target.tmpwd, "rr", "fire")
        ps_command = [fire_path, "ps"]
        ps_command += [trace_dir]
        with self.target.flight_context(ps_command, timeout=self.timeout) as flight:
            channel = flight.get_channel("stdio")
            output = channel.read().decode("utf-8")
            for line in output.split("\n"):
                parts = line.split("\t")
                try:
                    pid = int(parts[0])
                    pids.append(pid)
                except:
                    continue
        if abs(pid_idx) > len(pids):
            return None
        return pids[pid_idx]
