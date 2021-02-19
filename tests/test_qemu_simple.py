import unittest
import socket
import archr
import time
import os

OUR_PATH = os.path.dirname(__file__)
def p(s):
    return os.path.join(OUR_PATH, "qemus", s)

class TestQEMUSystemTargetSimple(unittest.TestCase):
    def test_pwncollege_minimal(self):
        with archr.targets.QEMUSystemTarget(p("pwnkernel-bzImage"), initrd_path=p("pwnkernel-initramfs.cpio.gz")).start() as q:
            assert q._share_mounted
            assert b"root" in q.retrieve_contents("/etc/passwd")
            q.inject_contents({"/root/foo": b"ARCHR_TEST_A"})
            assert b"ARCHR_TEST_A" in q.retrieve_contents("/root/foo")
            assert q.run_command("echo hey".split()).stdout.read(3) == b"hey"
            assert q.run_command("echo hi".split()).stdout.read(2) == b"hi"

if __name__ == '__main__':
    unittest.main()
