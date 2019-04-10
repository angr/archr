from time import sleep

import archr
import os

BIN_CAT = "/bin/cat"
CAT_ARGS = ["/etc/passwd"]
LTRACE_ARGS = "-f -e malloc+free+open+read+write+socket+bind+accept-@libc.so* -n 2".split()


def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))


def ltrace_proc(t, **kwargs):
    b = archr.arsenal.LTraceBow(t)
    with b.fire_context(trace_args=LTRACE_ARGS, **kwargs) as flight:
        sleep(1)
        flight.process.terminate()
    return flight.result


def ltrace_attach(t, p, **kwargs):
    b = archr.arsenal.LTraceAttachBow(t)
    pid = p.pid if isinstance(t, archr.targets.LocalTarget) else t.get_proc_pid('socat')
    with b.fire_context(pid=pid, trace_args=LTRACE_ARGS, **kwargs) as flight:
        sleep(0.1)
        nc = flight.get_channel('tcp:0') # misuse of flight
        nc.send(b'ahoi!')
        assert nc.readuntil(b'ahoi!', timeout=5) == b'ahoi!'

    return flight.result


def check_ltrace_proc(t, **kwargs):
    output = ltrace_proc(t, **kwargs)
    assert b'cat->open' in output
    assert b'cat->malloc' in output
    assert b'cat->read' in output


def check_ltrace_attach(t, **kwargs):
    target = t.run_command() # start target
    output = ltrace_attach(t, target, **kwargs)
    target.terminate()
    assert b'exe->accept' in output
    assert b'exe->malloc' in output
    assert b'exe->free' in output
    assert b'exe->read' in output
    assert b'exe->write' in output


def test_ltrace_proc_local():
    with archr.targets.LocalTarget(["/bin/cat", "/etc/passwd"]).build().start() as t:
        check_ltrace_proc(t)


def test_ltrace_proc_docker():
    with archr.targets.DockerImageTarget('archr-test:cat', target_args=['/bin/cat', '/etc/passwd']).build().start() as t:
        check_ltrace_proc(t)


def test_ltrace_attach_local():
    with archr.targets.LocalTarget("socat tcp-l:7573,reuseaddr exec:cat".split(), tcp_ports=[7573]).build().start() as t:
        check_ltrace_attach(t)


def test_ltrace_attach_docker():
    with archr.targets.DockerImageTarget('archr-test:socat').build().start() as t:
        check_ltrace_attach(t)


if __name__ == '__main__':
    test_ltrace_attach_local()
    test_ltrace_proc_local()
    test_ltrace_proc_docker()
    test_ltrace_attach_docker()
