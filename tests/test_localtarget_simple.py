import socket
import archr
import time
import os
import unittest


class TestLocalTarget(unittest.TestCase):
    def test_local_cat(self):
        with archr.targets.LocalTarget(["/bin/cat"]).build().start() as t:
            p = t.run_command()
            p.stdin.write(b"Hello!\n")
            assert p.stdout.read(7) == b"Hello!\n"

    def test_local_true(self):
        with archr.targets.LocalTarget(["/bin/true"]).build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == 0

    def test_local_false(self):
        with archr.targets.LocalTarget(["/bin/false"]).build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == 1

    def test_local_crasher(self):
        with archr.targets.LocalTarget(
            [os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]
        ).build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == -11

    def test_local_nccat(self):
        with archr.targets.LocalTarget(
            "socat tcp-l:40001,reuseaddr exec:cat".split(), tcp_ports=[40001], ipv4_address="127.0.0.1"
        ).build().start() as t:
            t.run_command()
            assert t.tcp_ports == [40001]
            try:
                s = socket.create_connection((t.ipv4_address, 40001))
            except ConnectionRefusedError:
                time.sleep(5)
                s = socket.create_connection((t.ipv4_address, 40001))
            s.send(b"Hello\n")
            assert s.recv(6) == b"Hello\n"

    def test_local_env_context(self):
        with archr.targets.LocalTarget(["/usr/bin/env"], target_env=["ARCHR=HAHA"]).build().start() as t:
            with t.run_command() as p:
                stdout, _ = p.communicate()
            assert b"ARCHR=HAHA" in stdout.split(b"\n")


if __name__ == "__main__":
    unittest.main()
