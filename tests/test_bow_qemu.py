import contextlib
import signal
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_arrow_injection_docker():
    with archr.targets.DockerImageTarget('archr-test:crasher').build() as t:
        archr.arsenal.QEMUTracerBow(t)
        assert t.retrieve_contents("/tmp/shellphish_qemu/fire").startswith(b"#!/bin/sh")

def test_arrow_injection_local():
    with contextlib.suppress(FileNotFoundError):
        os.unlink("/tmp/shellphish_qemu/fire")
    with archr.targets.LocalTarget([os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]).build() as t:
        archr.arsenal.QEMUTracerBow(t)
        assert t.retrieve_contents("/tmp/shellphish_qemu/fire").startswith(b"#!/bin/sh")

def crasher_checks(t):
    b = archr.arsenal.QEMUTracerBow(t)
    r = b.fire(save_core=True)

    # arbitrary check
    assert len(r.trace) > 100
    assert r.crashed
    assert r.crash_address == 0x40000005fa
    assert r.signal == signal.SIGSEGV
    assert os.path.exists(r.core_path)
    assert os.path.getsize(r.core_path) > 0

def test_crasher_trace():
    with archr.targets.DockerImageTarget('archr-test:crasher').build() as t:
        crasher_checks(t)

def test_crasher_trace_local():
    with archr.targets.LocalTarget([os.path.realpath(os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher"))]).build() as t:
        crasher_checks(t)

if __name__ == '__main__':
    test_arrow_injection_docker()
    test_arrow_injection_local()
    test_crasher_trace()
    test_crasher_trace_local()
