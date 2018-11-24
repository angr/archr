import archr
import nclib
import time
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def netcat_checks(t):
    b = archr.arsenal.NetCatBow(t)
    try:
        r = b.fire()
    except nclib.NetcatError:
        time.sleep(5)
        r = b.fire()
    r.send(b"hello!")
    assert r.readuntil(b"hello!", timeout=5) == b"hello!"

def test_netcat_network():
    with archr.targets.DockerImageTarget('archr-test:nccat').build().start() as t:
        netcat_checks(t)

def test_netcat_network_local():
    with archr.targets.LocalTarget("socat tcp-l:1337,reuseaddr exec:cat".split(), tcp_ports=[1337]).build().start() as t:
        netcat_checks(t)

def test_netcat_stdio():
    with archr.targets.DockerImageTarget('archr-test:cat').build().start() as t:
        b = archr.arsenal.NetCatBow(t)
        r = b.fire()
        r.send(b"hello!")
        assert r.readuntil(b"hello!", timeout=5) == b"hello!"

if __name__ == '__main__':
    test_netcat_network_local()
    test_netcat_network()
    test_netcat_stdio()
