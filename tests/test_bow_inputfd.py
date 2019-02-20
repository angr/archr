import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))


def test_id_network():
    with archr.targets.DockerImageTarget('archr-test:socat-echo').build().start() as t:
        fd = archr.arsenal.InputFDBow(t).fire()
        assert fd == 8

def test_id_network_local():
    with archr.targets.LocalTarget("socat PIPE tcp-l:4817,reuseaddr".split(), tcp_ports=[4817]).build().start() as t:
        fd = archr.arsenal.InputFDBow(t).fire()
        assert fd == 8

if __name__ == '__main__':
    test_id_network_local()
    test_id_network()
