import socket

import docker.errors

import archr
import time
import unittest

from common import build_container


class TestDockerTargetSimple(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("cat")
        build_container("cat-stderr")
        build_container("entrypoint-true")
        build_container("entrypoint-false")
        build_container("crasher")
        build_container("nccat")
        build_container("entrypoint-env")
        build_container("entrypoint-sh-env")
        build_container("entrypoint-setarch-env")

    def test_cat(self):
        with archr.targets.DockerImageTarget("archr-test:cat").build().start() as t:
            p = t.run_command()
            p.stdin.write(b"Hello!\n")
            assert p.stdout.read(7) == b"Hello!\n"

    def test_cat_stderr(self):
        with archr.targets.DockerImageTarget("archr-test:cat-stderr").build().start() as t:
            p = t.run_command()
            p.stdin.write(b"Hello!\n")
            assert p.stderr.read(7) == b"Hello!\n"

    def test_entrypoint_true(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-true").build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == 0

    def test_entrypoint_false(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-false").build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == 1

    def test_entrypoint_crasher(self):
        with archr.targets.DockerImageTarget("archr-test:crasher").build().start() as t:
            p = t.run_command()
            p.wait()
            assert p.returncode == 139

    def test_entrypoint_env(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            p = t.run_command()
            stdout, _ = p.communicate()
            assert b"ARCHR=YES" in stdout.split(b"\n")

    def test_nccat_simple(self):
        with archr.targets.DockerImageTarget("archr-test:nccat").build().start() as t:
            t.run_command()
            assert t.tcp_ports == [1337]
            try:
                s = socket.create_connection((t.ipv4_address, 1337))
            except ConnectionRefusedError:
                time.sleep(5)
                s = socket.create_connection((t.ipv4_address, 1337))
            s.send(b"Hello\n")
            assert s.recv(6) == b"Hello\n"

    def test_context_env(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            with t.run_command() as p:
                stdout, _ = p.communicate()
            assert b"ARCHR=YES" in stdout.split(b"\n")

    def test_user(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start(user="nobody") as t:
            assert t.run_command(["touch", "/"]).wait() != 0
            assert t.run_command(["touch", "/"], user="root").wait() == 0

    def test_entrypoint_tricky(self):
        t = archr.targets.DockerImageTarget("archr-test:entrypoint-sh-env").build()
        assert t.target_args == ["/usr/bin/env", "YEAH"]
        t = archr.targets.DockerImageTarget("archr-test:entrypoint-setarch-env").build()
        assert t.target_args == ["/usr/bin/env", "HAHAHA"]

    def test_timeout(self):
        t = archr.targets.DockerImageTarget("archr-test:cat").build().start(timeout=3)
        import time

        time.sleep(8)
        # the target should be gone by now
        try:
            t.container.top()
            assert False, "The container did not exit after timeout."
        except docker.errors.NotFound:
            pass


if __name__ == "__main__":
    unittest.main()
