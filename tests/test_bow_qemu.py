import signal
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_arrow_injection():
    with archr.targets.DockerImageTarget('archr-test:crasher').build() as t:
        archr.bows.QEMUTracerBow(t)
        assert t.retrieve_contents("/tmp/shellphish_qemu/fire").startswith(b"#!/bin/sh")

def test_crasher_trace():
    with archr.targets.DockerImageTarget('archr-test:crasher').build() as t:
        b = archr.bows.QEMUTracerBow(t)
        r = b.fire(save_core=True)

        # arbitrary check
        assert len(r.trace) > 100
        assert r.crashed
        assert r.crash_address == 0x40000005fa
        assert r.signal == signal.SIGSEGV
        assert os.path.exists(r.core_path)
        assert os.path.getsize(r.core_path) > 0

if __name__ == '__main__':
    test_crasher_trace()
    test_arrow_injection()
