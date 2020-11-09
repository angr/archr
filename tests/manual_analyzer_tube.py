import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_tube_network():
    t = archr.targets.DockerImageTarget('archr-test:nccat').build().start()
    b = archr.analyzers.TubeAnalyzer(t)
    r = b.fire()
    r.send("hello!")
    assert r.readuntil("hello!", timeout=5) == b"hello!"

def test_tube_stdio():
    t = archr.targets.DockerImageTarget('archr-test:cat').build().start()
    b = archr.analyzers.TubeAnalyzer(t)
    r = b.fire()
    r.send("hello!")
    assert r.readuntil("hello!", timeout=5) == b"hello!"

if __name__ == '__main__':
    test_tube_network()
    test_tube_stdio()
