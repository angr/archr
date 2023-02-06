import contextlib
import tempfile
import shutil
import archr
import os
import io
import unittest

from common import build_container


@unittest.skip("broken")
class TestDockerTargetFs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")

    def test_env_injection(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            t.inject_path("/etc/passwd", "/poo")
            rf = t.retrieve_contents("/poo")
            with open("/etc/passwd", "rb") as lf:
                assert lf.read() == rf

            t.inject_paths({"/poobin": "/bin", "/poolib": "/lib64"})
            rf = t.retrieve_contents("/poobin/true")
            with open("/bin/true", "rb") as lf:
                assert lf.read() == rf

    def test_env_retrieval(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            assert t.retrieve_contents("/etc/passwd").startswith(b"root:")
            t.inject_path("/etc/passwd", "/poo")
            with open("/etc/passwd", "rb") as lf:
                assert lf.read() == t.retrieve_contents("/poo")

            tmpdir = tempfile.mkdtemp()
            try:
                assert not os.path.exists(os.path.join(tmpdir, ".dockerenv"))
                t.retrieve_into("/.dockerenv", tmpdir)
                assert os.path.exists(os.path.join(tmpdir, ".dockerenv"))
                assert not os.path.exists(os.path.join(tmpdir, "etc/passwd"))
                t.retrieve_into("/etc", tmpdir)
                assert os.path.exists(os.path.join(tmpdir, "etc/passwd"))
                with open(os.path.join(tmpdir, "etc/passwd"), "rb") as rf:
                    assert rf.read().startswith(b"root:")
            finally:
                shutil.rmtree(tmpdir)

    def test_retrieval_context(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            # first, try temporary file
            with t.retrieval_context("/tmp/foo0") as o:
                assert o.startswith("/tmp")
                t.run_command(["cp", "/etc/passwd", "/tmp/foo0"]).wait()
            with open(o) as f:
                assert f.read().startswith("root:")
            os.unlink(o)

            # then, try named file
            with tempfile.NamedTemporaryFile() as tf:
                with t.retrieval_context("/tmp/foo1", tf.name) as o:
                    assert o == tf.name
                    t.run_command(["cp", "/etc/passwd", "/tmp/foo1"]).wait()
                with open(tf.name) as f:
                    assert f.read().startswith("root:")

            # then, try named BytesIO
            f = io.BytesIO()
            with t.retrieval_context("/tmp/foo2", f) as o:
                assert o is f
                t.run_command(["cp", "/etc/passwd", "/tmp/foo2"]).wait()
            f.seek(0)
            assert f.read().startswith(b"root:")

            # now, try a stack with a retrieval and a run context
            with contextlib.ExitStack() as stack:
                g = io.BytesIO()
                stack.enter_context(t.retrieval_context("/tmp/foo3", g))
                stack.enter_context(t.run_context(["cp", "/etc/passwd", "/tmp/foo3"]))
            g.seek(0)
            assert g.read().startswith(b"root:")

            # now, try that with a glob
            with contextlib.ExitStack() as stack:
                g = io.BytesIO()
                stack.enter_context(t.retrieval_context("/tmp/globtes*", g, glob=True))
                stack.enter_context(t.run_context(["cp", "/etc/passwd", "/tmp/globtest"]))
            g.seek(0)
            assert g.read().startswith(b"root:")

    def test_content_injection(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            t.inject_contents({"/foo": b"asdf", "/bar": b"fdsa"})
            assert t.retrieve_contents("/foo") == b"asdf"
            assert t.retrieve_contents("/bar") == b"fdsa"

    def test_glob_retrieval(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            assert t.retrieve_glob("/etc/hostna*").startswith(t.container.id[:5].encode("utf-8"))

        # and now, with mounts
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            assert t.retrieve_glob("/etc/hostna*").startswith(t.container.id[:5].encode("utf-8"))

    def test_temporary_replacement(self):
        with open("/etc/passwd", "rb") as pw:
            opw = pw.read()
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            with t.replacement_context("/etc/passwd", opw) as tpw:
                assert opw != tpw
                assert t.retrieve_contents("/etc/passwd") == opw
            assert t.retrieve_contents("/etc/passwd") == tpw

    def test_tmp_bind(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env", bind_tmp=True).build().start() as t:
            t.inject_contents({"/tmp/foo": b"asdf", "/tmp/bar": b"fdsa"})
            assert t.retrieve_contents("/tmp/foo") == b"asdf"
            assert t.retrieve_contents("/tmp/bar") == b"fdsa"
            assert open(os.path.join(t.tmp_bind, "foo"), "rb").read() == b"asdf"
            assert open(os.path.join(t.tmp_bind, "bar"), "rb").read() == b"fdsa"
        assert not os.path.exists(t.tmp_bind)

    def test_local_workdir(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env", bind_tmp=True).build().start() as t:
            assert os.path.exists(t.local_workdir)
            t.inject_contents({"/tmp/foo": b"asdf"})
            assert t.retrieve_contents("/tmp/foo") == b"asdf"
            assert os.path.exists(t.resolve_local_path("/tmp/foo"))
            assert open(t.resolve_local_path("/tmp/foo"), "rb").read() == b"asdf"
        assert not os.path.exists(t.local_workdir)


if __name__ == "__main__":
    unittest.main()
