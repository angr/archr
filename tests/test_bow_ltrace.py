from time import sleep

import nclib
import archr
import os

CAT_ARGS = "-e malloc+free+open+read+write+socket+bind+accept-@libc.so* -n 2 -- /bin/cat /etc/passwd".split()
NC_ARGS = "-f -e malloc+free+open+read+write+socket+bind+accept-@libc.so* -n 2".split()


def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))


def ltrace_proc(t, **kwargs):
    b = archr.arsenal.LTraceBow(t)
    r = b.fire(**kwargs)
    return r


def ltrace_attach(t, **kwargs):
    b = archr.arsenal.LTraceBow(t)
    pid = t.get_proc_pid('socat')
    assert pid != None
    r = b.fire(pid=pid, **kwargs)
    sleep(1)
    nc = nclib.Netcat((t.ipv4_address, t.tcp_ports[0]))
    nc.send(b'ahoi!')
    assert nc.readuntil(b'ahoi!', timeout=5) == b'ahoi!'

    return r


def check_ltrace_proc(t, **kwargs):
    p = ltrace_proc(t, **kwargs)
    output = p.stderr.read()
    assert b'cat->open' in output
    assert b'cat->malloc' in output
    assert b'cat->read' in output


def check_ltrace_attach(t, **kwargs):
    target = t.run_command() # start target
    p = ltrace_attach(t, **kwargs)
    target.terminate()
    output = p.stderr.read()
    assert b'exe->accept' in output
    assert b'exe->malloc' in output
    assert b'exe->free' in output
    assert b'exe->read' in output
    assert b'exe->write' in output


def test_ltrace_proc_local():
    with archr.targets.LocalTarget(["/bin/cat"]).build().start() as t:
        check_ltrace_proc(t, args=CAT_ARGS)


def test_ltrace_proc_docker():
    with archr.targets.DockerImageTarget('archr-test:cat').build().start() as t:
        check_ltrace_proc(t, args=CAT_ARGS)


def test_ltrace_attach_local():
    with archr.targets.LocalTarget("socat tcp-l:1337,reuseaddr exec:cat".split(), tcp_ports=[1337]).build().start() as t:
        check_ltrace_attach(t, args=NC_ARGS)


def test_ltrace_attach_docker():
    with archr.targets.DockerImageTarget('archr-test:socat').build().start() as t:
        check_ltrace_attach(t, args=NC_ARGS)


if __name__ == '__main__':
    test_ltrace_proc_local()
    test_ltrace_proc_docker()
    test_ltrace_attach_local()
    test_ltrace_attach_docker()
