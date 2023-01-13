import contextlib
import signal
import archr
import os
import unittest

import logging

logging.basicConfig(level=logging.DEBUG)

from common import build_container


class TestAnalyzerBintraceQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("crasher")
        build_container("crash-on-input")

    def test_implant_injection_docker(self):
        with archr.targets.DockerImageTarget("archr-test:crasher").build().start() as t:
            archr.analyzers.BintraceQEMUTracerAnalyzer(t)
            fire_path = os.path.join(t.tmpwd, "bintrace_qemu", "fire")
            assert t.retrieve_contents(fire_path).startswith(b"#!/bin/sh")

    def test_implant_injection_local(self):
        with archr.targets.LocalTarget(
            [os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]
        ).build().start() as t:
            archr.analyzers.BintraceQEMUTracerAnalyzer(t)
            fire_path = os.path.join(t.tmpwd, "bintrace_qemu", "fire")
            assert t.retrieve_contents(fire_path).startswith(b"#!/bin/sh")

    def crasher_checks(self, t):
        b = archr.analyzers.BintraceQEMUTracerAnalyzer(t)
        r = b.fire()

        assert r.tracepath
        assert not r.timed_out
        assert r.crashed
        assert r.signal == signal.SIGSEGV

    def crash_on_input_checks(self, t):
        crashing = b"A" * 120
        b = archr.analyzers.BintraceQEMUTracerAnalyzer(t)
        with b.fire_context() as flight:
            flight.default_channel.send(crashing)
            flight.default_channel.shutdown_wr()
            # flight.default_channel.recvall()

        assert flight.result.crashed

    def test_crasher_trace(self):
        with archr.targets.DockerImageTarget("archr-test:crasher").build().start() as t:
            self.crasher_checks(t)

    def test_crash_on_input_trace(self):
        with archr.targets.DockerImageTarget("archr-test:crash-on-input").build().start() as t:
            self.crash_on_input_checks(t)

    def test_crasher_trace_local(self):
        with archr.targets.LocalTarget(
            [os.path.realpath(os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher"))]
        ).build().start() as t:
            self.crasher_checks(t)


if __name__ == "__main__":
    unittest.main()
