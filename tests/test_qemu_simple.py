import unittest
import socket
import archr
import time
import os

from common import qemu_test_path

class TestQEMUSystemTargetSimple(unittest.TestCase):
    def test_pwncollege_minimal(self):
        with archr.targets.QEMUSystemTarget(
            qemu_test_path("pwnkernel-bzImage"), initrd_path=qemu_test_path("pwnkernel-initramfs.cpio.gz"),
            target_path="/hello", target_args=["/hello"]
        ).start() as q:
            assert q._share_mounted
            assert b"root" in q.retrieve_contents("/etc/passwd")
            q.inject_contents({"/root/foo": b"ARCHR_TEST_A"})
            assert b"ARCHR_TEST_A" in q.retrieve_contents("/root/foo")
            assert q.run_command("echo hey".split()).stdout.read(3) == b"hey"
            assert q.run_command("echo hi".split()).stdout.read(2) == b"hi"
            assert q.run_command().communicate()[0] == b"HELLO PWN COLLEGE!\n"

if __name__ == '__main__':
    unittest.main()
