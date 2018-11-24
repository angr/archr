import contextlib
import signal
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_arrow_injection_docker():
    with archr.targets.DockerImageTarget('archr-test:crasher').build().start() as t:
        archr.arsenal.QEMUTracerBow(t)
        assert t.retrieve_contents("/tmp/shellphish_qemu/fire").startswith(b"#!/bin/sh")

def test_arrow_injection_local():
    with contextlib.suppress(FileNotFoundError):
        os.unlink("/tmp/shellphish_qemu/fire")
    with archr.targets.LocalTarget([os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]).build().start() as t:
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

def crash_on_input_checks(t):
    crashing = "A"*120
    b = archr.arsenal.QEMUTracerBow(t)
    r = b.fire(save_core=True, testcase=crashing)

    assert r.crashed

def shellcode_checks(t):
    crash = b"A" * 272
    b = archr.arsenal.QEMUTracerBow(t)
    r = b.fire(save_core=True, testcase=crash)

    assert r.crashed

def vuln_stacksmash_checks(t):
    crash = b"A" * 227

    b = archr.arsenal.QEMUTracerBow(t)
    r = b.fire(save_core=True, testcase=crash)

    assert r.crashed


def test_crasher_trace():
    with archr.targets.DockerImageTarget('archr-test:crasher').build().start() as t:
        crasher_checks(t)

def test_crash_on_input_trace():
    with archr.targets.DockerImageTarget('archr-test:crash-on-input').build().start() as t:
        crash_on_input_checks(t)

def test_vuln_stacksmash():
    with archr.targets.DockerImageTarget('archr-test:vuln_stacksmash', target_arch='i386').build().start() as t:
        vuln_stacksmash_checks(t)
        
def test_shellcode_tester():
    with archr.targets.DockerImageTarget('archr-test:shellcode_tester', target_os='cgc').build().start() as t:
        shellcode_checks(t)
        


def test_crasher_trace_local():
    with archr.targets.LocalTarget([os.path.realpath(os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher"))]).build().start() as t:
        crasher_checks(t)

if __name__ == '__main__':
    test_arrow_injection_docker()
    test_arrow_injection_local()
    test_crasher_trace()
    test_crasher_trace_local()
    test_crash_on_input_trace()
