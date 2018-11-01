import archr
import nclib
import time
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_netcat_network():
    with archr.targets.DockerImageTarget('archr-test:nccat').build() as t:
        b = archr.bows.NetCatBow(t)
        try:
            r = b.fire()
        except nclib.NetcatError:
            time.sleep(5)
            r = b.fire()
        r.send(b"hello!")
        assert r.readuntil(b"hello!", timeout=5) == b"hello!"

def test_netcat_stdio():
    with archr.targets.DockerImageTarget('archr-test:cat').build() as t:
        b = archr.bows.NetCatBow(t)
        r = b.fire()
        r.send(b"hello!")
        assert r.readuntil(b"hello!", timeout=5) == b"hello!"

if __name__ == '__main__':
    test_netcat_network()
    test_netcat_stdio()
