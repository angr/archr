from time import sleep

import nclib
import archr
import os

BIN_CAT = "/bin/cat"
STRACE_ARGS = "-f".split()


def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))



def check_strace_proc(t, **kwargs):
    b = archr.arsenal.STraceBow(t)
    p = b.fire(args_suffix=["/etc/passwd"], trace_args=STRACE_ARGS, **kwargs)
    trace = p.stderr.read().splitlines()
    assert any(b'open' in t and b'passwd' in t for t in trace)
    assert any(b'read' in t and b'root' in t for t in trace)
    assert any(b'write' in t and b'root' in t for t in trace)


def check_strace_attach(t, **kwargs):
    target = t.run_command() # start target
    b = archr.arsenal.STraceBow(t)
    pid = t.get_proc_pid('socat')
    assert pid is not None
    with b.fire_context(pid=pid, trace_args=STRACE_ARGS, **kwargs) as p:
        sleep(1)
        nc = nclib.Netcat((t.ipv4_address, t.tcp_ports[0]))
        nc.send(b'ahoi!')
        assert nc.readuntil(b'ahoi!', timeout=5) == b'ahoi!'
        nc.close()
        target.terminate()

    trace = p.stderr.read().splitlines()
    assert any(b'read' in t and b'ahoi' in t for t in trace)
    assert any(b'write' in t and b'ahoi' in t for t in trace)


def test_strace_proc_local():
    with archr.targets.LocalTarget(["/bin/cat"]).build().start() as t:
        check_strace_proc(t)


def test_strace_proc_docker():
    with archr.targets.DockerImageTarget('archr-test:cat').build().start() as t:
        check_strace_proc(t)


def test_strace_attach_local():
    with archr.targets.LocalTarget("socat tcp-l:1337,reuseaddr exec:cat".split(), tcp_ports=[1337]).build().start() as t:
        check_strace_attach(t)


def test_strace_attach_docker():
    with archr.targets.DockerImageTarget('archr-test:socat').build().start() as t:
        check_strace_attach(t)


if __name__ == '__main__':
    test_strace_proc_local()
    test_strace_proc_docker()
    test_strace_attach_local()
    test_strace_attach_docker()
