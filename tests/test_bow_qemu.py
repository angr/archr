import contextlib
import signal
import archr
import os
import unittest

from common import build_container


class TestBowQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("crasher")
        build_container("crash-on-input")
        build_container("vuln_stacksmash")
        build_container("shellcode_tester")

    def test_arrow_injection_docker(self):
        with archr.targets.DockerImageTarget('archr-test:crasher').build().start() as t:
            archr.arsenal.QEMUTracerBow(t)
            fire_path = os.path.join(t.tmpwd, "shellphish_qemu", "fire")
            assert t.retrieve_contents(fire_path).startswith(b"#!/bin/sh")

    def test_arrow_injection_local(self):
        with archr.targets.LocalTarget([os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]).build().start() as t:
            archr.arsenal.QEMUTracerBow(t)
            fire_path = os.path.join(t.tmpwd, "shellphish_qemu", "fire")
            assert t.retrieve_contents(fire_path).startswith(b"#!/bin/sh")

    def crasher_checks(self, t):
        b = archr.arsenal.QEMUTracerBow(t)
        r = b.fire(save_core=True)

        # arbitrary check
        assert len(r.trace) > 100
        assert not r.timed_out
        assert r.crashed
        assert r.crash_address == 0x400000060a
        assert r.signal == signal.SIGSEGV
        assert os.path.exists(r.core_path)
        assert os.path.getsize(r.core_path) > 0

    def crash_on_input_checks(self, t):
        crashing = b"A"*120
        b = archr.arsenal.QEMUTracerBow(t)
        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crashing)
            flight.default_channel.shutdown_wr()
            #flight.default_channel.recvall()

        assert flight.result.crashed

    def shellcode_checks(self, t):
        crash = b"A" * 272
        b = archr.arsenal.QEMUTracerBow(t)

        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crash)
            flight.default_channel.shutdown_wr()
            #flight.default_channel.recvall()

        assert not flight.result.timed_out
        assert flight.result.crashed

    def vuln_stacksmash_checks(self, t):
        crash = b"A" * 227

        b = archr.arsenal.QEMUTracerBow(t)

        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crash)
            flight.default_channel.shutdown_wr()
            #flight.default_channel.recvall()

        assert not flight.result.timed_out
        assert flight.result.crashed

    def test_crasher_trace(self):
        with archr.targets.DockerImageTarget('archr-test:crasher').build().start() as t:
            self.crasher_checks(t)

    def test_crash_on_input_trace(self):
        with archr.targets.DockerImageTarget('archr-test:crash-on-input').build().start() as t:
            self.crash_on_input_checks(t)

    def test_vuln_stacksmash(self):
        with archr.targets.DockerImageTarget('archr-test:vuln_stacksmash', target_arch='i386').build().start() as t:
            self.vuln_stacksmash_checks(t)

    def test_shellcode_tester(self):
        with archr.targets.DockerImageTarget('archr-test:shellcode_tester', target_os='cgc').build().start() as t:
            self.shellcode_checks(t)

    def test_crasher_trace_local(self):
        with archr.targets.LocalTarget([os.path.realpath(os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher"))]).build().start() as t:
            self.crasher_checks(t)


if __name__ == '__main__':
    unittest.main()
