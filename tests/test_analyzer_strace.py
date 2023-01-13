from time import sleep

import archr
import unittest

from common import build_container

BIN_CAT = "/bin/cat"
STRACE_ARGS = "-f".split()


class TestAnalyzerStrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("cat")
        build_container("socat")

    def check_strace_proc(self, t, **kwargs):  # pylint:disable=no-self-use
        b = archr.analyzers.STraceAnalyzer(t)
        trace = b.fire(args_suffix=["/etc/passwd"], trace_args=STRACE_ARGS, **kwargs).splitlines()
        assert any(b"open" in t and b"passwd" in t for t in trace)
        assert any(b"read" in t and b"root" in t for t in trace)
        assert any(b"write" in t and b"root" in t for t in trace)

    def check_strace_attach(self, t, **kwargs):  # pylint:disable=no-self-use
        target = t.run_command()  # start target
        b = archr.analyzers.STraceAttachAnalyzer(t)
        pid = target.pid if isinstance(t, archr.targets.LocalTarget) else t.get_proc_pid("socat")
        with b.fire_context(pid=pid, trace_args=STRACE_ARGS, **kwargs) as flight:
            sleep(2)
            nc = flight.get_channel("tcp:0")
            nc.send(b"ahoi!")
            assert nc.readuntil(b"ahoi!", timeout=5) == b"ahoi!"
            nc.close()
            target.terminate()

        trace = flight.result.splitlines()
        assert any(b"read" in t and b"ahoi" in t for t in trace)
        assert any(b"write" in t and b"ahoi" in t for t in trace)

    def test_strace_proc_local(self):
        with archr.targets.LocalTarget(["/bin/cat"]).build().start() as t:
            self.check_strace_proc(t)

    def test_strace_proc_docker(self):
        with archr.targets.DockerImageTarget("archr-test:cat").build().start() as t:
            self.check_strace_proc(t)

    def test_strace_attach_local(self):
        with archr.targets.LocalTarget(
            "socat tcp-l:9137,reuseaddr exec:cat".split(), tcp_ports=[9137]
        ).build().start() as t:
            self.check_strace_attach(t)

    def test_strace_attach_docker(self):
        with archr.targets.DockerImageTarget("archr-test:socat").build().start() as t:
            self.check_strace_attach(t)


if __name__ == "__main__":
    unittest.main()
