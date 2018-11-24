import contextlib
import tempfile
import shutil
import archr
import os
import io

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_env_mount():
    t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start().mount_local()
    assert os.path.exists(os.path.join(t.local_path, "./"+t.target_path))
    t.stop()
    assert not os.path.exists(os.path.join(t.local_path, "./"+t.target_path))

def test_env_injection():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        t.mount_local()
        t.inject_path("/etc/passwd", "/poo")
        with open("/etc/passwd") as lf, open(t.resolve_local_path("/poo")) as rf:
            assert lf.read() == rf.read()

        t.inject_paths({"/poobin": "/bin", "/poolib": "/lib64"})
        assert len(os.listdir("/bin")) == len(os.listdir(t.resolve_local_path("/poobin")))
        assert len(os.listdir("/lib64")) == len(os.listdir(t.resolve_local_path("/poolib")))

def test_env_retrieval():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        assert t.retrieve_contents("/etc/passwd").startswith(b"root:")
        t.inject_path("/etc/passwd", "/poo")
        with open("/etc/passwd", 'rb') as lf:
            assert lf.read() == t.retrieve_contents("/poo")

        tmpdir = tempfile.mkdtemp()
        try:
            assert not os.path.exists(os.path.join(tmpdir, ".dockerenv"))
            t.retrieve_into("/.dockerenv", tmpdir)
            assert os.path.exists(os.path.join(tmpdir, ".dockerenv"))
            assert not os.path.exists(os.path.join(tmpdir, "etc/passwd"))
            t.retrieve_into("/etc", tmpdir)
            assert os.path.exists(os.path.join(tmpdir, "etc/passwd"))
            with open(os.path.join(tmpdir, "etc/passwd"), 'rb') as rf:
                assert rf.read().startswith(b"root:")
        finally:
            shutil.rmtree(tmpdir)

def test_retrieval_context():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:

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

def test_content_injection():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        t.inject_contents({"/foo": b"asdf", "/bar": b"fdsa"})
        assert t.retrieve_contents("/foo") == b"asdf"
        assert t.retrieve_contents("/bar") == b"fdsa"

def test_glob_retrieval():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        assert t.retrieve_glob("/etc/hostna*").startswith(t.container.id[:5].encode('utf-8'))

    # and now, with mounts
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        t.mount_local()
        assert t.retrieve_glob("/etc/hostna*").startswith(t.container.id[:5].encode('utf-8'))

def test_temporary_replacement():
    with open("/etc/passwd", 'rb') as pw:
        opw = pw.read()
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        with t.replacement_context("/etc/passwd", opw) as tpw:
            assert opw != tpw
            assert t.retrieve_contents("/etc/passwd") == opw
        assert t.retrieve_contents("/etc/passwd") == tpw

if __name__ == '__main__':
    test_glob_retrieval()
    test_retrieval_context()
    test_env_mount()
    test_env_injection()
    test_env_retrieval()
