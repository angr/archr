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

if __name__ == '__main__':
    test_env_mount()
    test_env_injection()
