import tempfile
import shutil
import archr
import os
import unittest

from common import build_container


class TestShellcodeHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-false")

    def test_dockerfile_hook(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-false").build().start() as t:
            assert t.run_command().wait() == 1
            with t.shellcode_context(asm_code="mov rax, 0x3c; mov rdi, 0x2a; syscall") as p:
                assert p.wait() == 42
            assert t.run_command().wait() == 1

    def test_local_hook(self):
        # copy out /bin/false, because we can't overwrite it obviously
        tf = tempfile.mktemp()
        shutil.copy("/bin/false", tf)
        with archr.targets.LocalTarget([tf]).build().start() as t:
            assert t.run_command().wait() == 1
            with t.shellcode_context(asm_code="mov rax, 0x3c; mov rdi, 0x2a; syscall") as p:
                assert p.wait() == 42
            assert t.run_command().wait() == 1
        os.unlink(tf)


if __name__ == "__main__":
    unittest.main()
