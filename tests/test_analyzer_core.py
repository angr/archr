import subprocess
import archr
import unittest

from common import build_container


class TestAnalyzerCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("crasher")

    def test_crasher(self):
        with archr.targets.DockerImageTarget("archr-test:crasher").build().start() as t:
            cb = archr.analyzers.CoreAnalyzer(t)
            r = cb.fire()
            assert b"LSB core file" in subprocess.check_output(["file", r.local_core_path])

    def test_crasher_noperms(self):
        with archr.targets.DockerImageTarget("archr-test:crasher").build().start(user="nobody") as t:
            cb = archr.analyzers.CoreAnalyzer(t)
            r = cb.fire()
            assert b"LSB core file" in subprocess.check_output(["file", r.local_core_path])


if __name__ == "__main__":
    unittest.main()
