import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import os
import re

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


# ---------------- RR cpuid command line utilities ----------------

# from rr cpufeatures

def _parse(s):
    return [int(v, base=0) for v in s.split(',')]

def _bits(*i):
    v = 0
    for x in i:
        v |= 1 << x
    return v

def _get_disable_cpuid_features(cpu_features):
    disable_cpu_regex = re.compile('(?<=--disable-cpuid-features )0x[a-fA-F0-9]+(,0x[a-fA-F0-9]+)*')
    return _parse(disable_cpu_regex.search(cpu_features).group())

def _get_disable_cpuid_features_ext(cpu_features):
    disable_cpu_regex_ext = re.compile('(?<=--disable-cpuid-features-ext )0x[a-fA-F0-9]+(,0x[a-fA-F0-9]+)*')
    return _parse(disable_cpu_regex_ext.search(cpu_features).group())

def _get_disable_cpuid_features_xsave(cpu_features):
    disable_cpu_regex_xsave = re.compile('(?<=--disable-cpuid-features-xsave )0x[a-fA-F0-9]+(,0x[a-fA-F0-9]+)*')
    return _parse(disable_cpu_regex_xsave.search(cpu_features).group())

def _cpuid_cmd_line_args():
    try:
        cpu_features = subprocess.check_output('rr cpufeatures', shell=True).decode('utf-8')
    except subprocess.CalledProcessError:
        raise Exception('Please install rr or add rr to your PATH')

    feat_ECX, feat_EDX = _get_disable_cpuid_features(cpu_features)
    ext_EBX, ext_ECX, ext_EDX = _get_disable_cpuid_features_ext(cpu_features)
    xsave_EAX, = _get_disable_cpuid_features_xsave(cpu_features)

    f = {
        'feat': {
            'edx': dict(sse2=26, FXSR_FXSAVE=24),
            'ecx': dict(xsave=26, osxsave=27, avx=28)
            },
        'ext': {
            'ebx': dict(avx2=5, avx512pf=26),
            'ecx': dict(),
            'edx': dict(),
            },
        'xsave': {
            'eax': dict(XSAVEC=1, XG1=2) # XG1 gatex XGETBV instruction, XSAVEC gates XSAVEC instruction
            }
        }

    feat_ECX |= _bits(*f['feat']['ecx'].values())
    feat_EDX |= _bits(*f['feat']['edx'].values())
    ext_EBX |= _bits(*f['ext']['ebx'].values())
    ext_ECX |= _bits(*f['ext']['ecx'].values())
    ext_EDX |= _bits(*f['ext']['edx'].values())
    xsave_EAX |= _bits(*f['xsave']['eax'].values())
    return [
        '--disable-cpuid-features', '0x{:x},0x{:x}'.format(feat_ECX, feat_EDX),
        '--disable-cpuid-features-ext', '0x{:x},0x{:x},0x{:x}'.format(ext_EBX, ext_ECX, ext_EDX),
        '--disable-cpuid-features-xsave', '0x{:x}'.format(xsave_EAX),
    ]

# ---------------- End RR cpuid command line utilities ----------------

class RRTraceResult:
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


class RRTracerBow(ContextBow):
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

        fix_perf()

        if self.local_trace_dir and os.path.exists(self.local_trace_dir):
            shutil.rmtree(self.local_trace_dir)
            os.mkdir(self.local_trace_dir)

        record_command = ['/tmp/rr/fire', 'record', '-n']  + _cpuid_cmd_line_args() + self.target.target_args
        record_env = ['RR_COPY_ALL_FILES=1']
        r = RRTraceResult(trace_dir=self.local_trace_dir)
        try:
            with self.target.flight_context(record_command, env=record_env, timeout=self.timeout, result=r) as flight:
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
