import tempfile
import shutil
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_env_mount():
    t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
    assert os.path.exists(os.path.join(t.local_path, "./"+t.target_path))
    t.stop()
    assert not os.path.exists(os.path.join(t.local_path, "./"+t.target_path))

def test_env_injection():
    t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
    t.inject_path("/etc/passwd", "/poo")
    with open("/etc/passwd") as lf, open(t.resolve_local_path("/poo")) as rf:
        assert lf.read() == rf.read()

    t.inject_paths([("/bin", "/poobin"), ("/lib64", "/poolib")])
    assert len(os.listdir("/bin")) == len(os.listdir(t.resolve_local_path("/poobin")))
    assert len(os.listdir("/lib64")) == len(os.listdir(t.resolve_local_path("/poolib")))
    t.stop()

def test_env_retrieval():
    t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
    assert t.retrieve_file_contents("/etc/passwd").startswith(b"root:")
    t.inject_path("/etc/passwd", "/poo")
    with open("/etc/passwd", 'rb') as lf:
        assert lf.read() == t.retrieve_file_contents("/poo")

    tmpdir = tempfile.mkdtemp()
    try:
        assert not os.path.exists(os.path.join(tmpdir, ".dockerenv"))
        t.retrieve_path("/.dockerenv", tmpdir)
        assert os.path.exists(os.path.join(tmpdir, ".dockerenv"))
        assert not os.path.exists(os.path.join(tmpdir, "etc/passwd"))
        t.retrieve_path("/etc", tmpdir)
        assert os.path.exists(os.path.join(tmpdir, "etc/passwd"))
        with open(os.path.join(tmpdir, "etc/passwd"), 'rb') as rf:
            assert rf.read().startswith(b"root:")
    finally:
        shutil.rmtree(tmpdir)

if __name__ == '__main__':
    test_env_mount()
    test_env_injection()
    test_env_retrieval()
