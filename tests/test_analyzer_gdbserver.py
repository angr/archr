import pygdbmi.gdbcontroller
import archr
import unittest

from common import build_container


class TestGdbServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-false")
        build_container("entrypoint-env")

    def gdb_do(self, t):
        with archr.analyzers.GDBServerAnalyzer(t).fire_context(port=31337) as gbf:
            gc = pygdbmi.gdbcontroller.GdbController()
            gc.write("target remote %s:%d" % (t.ipv4_address, 31337))
            gc.write("continue")
            gc.exit()
            return gbf.process

    def check_gdb_cat(self, t):
        p = self.gdb_do(t)
        assert b"Child exited with status 1" in p.stderr.read()

    @unittest.skip("broken")
    def test_cat_docker(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-false").build().start() as t:
            self.check_gdb_cat(t)

    @unittest.skip("broken")
    def test_env_order(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            a = self.gdb_do(t).stdout.read()
            b = self.gdb_do(t).stdout.read()
            c = self.gdb_do(t).stdout.read()
            assert a == b
            assert b == c

    @unittest.skip("broken")
    def test_cat_local(self):
        with archr.targets.LocalTarget(["/bin/false"]).build().start() as t:
            self.check_gdb_cat(t)


if __name__ == "__main__":
    unittest.main()
