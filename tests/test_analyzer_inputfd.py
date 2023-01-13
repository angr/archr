import archr
import os
import unittest

from common import build_container


class TestAnalyzerInputFd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("socat-echo")

    def test_id_network(self):
        with archr.targets.DockerImageTarget("archr-test:socat-echo").build().start() as t:
            fd = archr.analyzers.InputFDAnalyzer(t).fire()
            assert fd == 8

    def test_id_network_local(self):
        with archr.targets.LocalTarget(
            "socat PIPE tcp-l:4817,reuseaddr".split(), tcp_ports=[4817]
        ).build().start() as t:
            fd = archr.analyzers.InputFDAnalyzer(t).fire()
            assert fd == 8


if __name__ == "__main__":
    unittest.main()
