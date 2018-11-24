import socket
import archr
import time
import os

def test_local_cat():
    with archr.targets.LocalTarget(["/bin/cat"]).build().start() as t:
        p = t.run_command()
        p.stdin.write(b"Hello!\n")
        assert p.stdout.read(7) == b"Hello!\n"

def test_local_true():
    with archr.targets.LocalTarget(["/bin/true"]).build().start() as t:
        p = t.run_command()
        p.wait()
        assert p.returncode == 0

def test_local_false():
    with archr.targets.LocalTarget(["/bin/false"]).build().start() as t:
        p = t.run_command()
        p.wait()
        assert p.returncode == 1

def test_local_crasher():
    with archr.targets.LocalTarget([os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]).build().start() as t:
        p = t.run_command()
        p.wait()
        assert p.returncode == -11

def test_local_nccat():
    with archr.targets.LocalTarget("socat tcp-l:1337,reuseaddr exec:cat".split(), tcp_ports=[1337]).build().start() as t:
        t.run_command()
        assert t.tcp_ports == [ 1337 ]
        try:
            s = socket.create_connection((t.ipv4_address, 1337))
        except ConnectionRefusedError:
            time.sleep(5)
            s = socket.create_connection((t.ipv4_address, 1337))
        s.send(b"Hello\n")
        assert s.recv(6) == b"Hello\n"

def test_local_env_context():
    with archr.targets.LocalTarget(["/usr/bin/env"], target_env=["ARCHR=HAHA"]).build().start() as t:
        with t.run_command() as p:
            stdout,_ = p.communicate()
        assert b"ARCHR=HAHA" in stdout.split(b'\n')

if __name__ == '__main__':
    test_local_cat()
    test_local_true()
    test_local_false()
    test_local_nccat()
    test_local_crasher()
    test_local_env_context()
