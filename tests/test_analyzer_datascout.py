import tempfile
import struct
import shutil
import archr
import os
import unittest

from common import build_container, qemu_test_path


class TestShellcode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")
        build_container("vuln_stacksmash")

    def shellcode_checks(self, t):
        b = archr.analyzers.DataScoutAnalyzer(t)
        if t.SUPPORTS_RETURNCODES:
            with t.shellcode_context(asm_code=b.exit_shellcode(exit_code=123)) as p:
                stdout,_ = p.communicate()
                assert p.wait() == 123

        with t.shellcode_context(asm_code=b.echo_shellcode("TESTING THIS THING!")) as p:
            stdout,_ = p.communicate()
            assert stdout == b"TESTING THIS THING!"

        with t.shellcode_context(asm_code=b.echo_shellcode("TESTING THIS THING!") + b.exit_shellcode()) as p:
            stdout,_ = p.communicate()
            assert stdout == b"TESTING THIS THING!"
            if t.SUPPORTS_RETURNCODES:
                assert p.wait() == 42

        with t.shellcode_context(asm_code=b.sendfile_shellcode("/proc/self/cmdline")) as p:
            stdout,_ = p.communicate()
            assert stdout == t.target_path.encode('utf-8') + b'\0'

    def test_shellcode_amd64(self):
        with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
            self.shellcode_checks(t)
    def test_shellcode_i386(self):
        with archr.targets.DockerImageTarget('archr-test:vuln_stacksmash', target_arch='i386').build().start() as t:
            self.shellcode_checks(t)
    def test_shellcode_qemu(self):
        with archr.targets.QEMUSystemTarget(
            qemu_test_path("pwnkernel-bzImage"), initrd_path=qemu_test_path("pwnkernel-initramfs.cpio.gz"),
            target_path="/hello", target_args=["/hello"]
        ).start() as t:
            self.shellcode_checks(t)


class TestDatascout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")

    def datascout_checks(self, t, static=False):
        b = archr.analyzers.DataScoutAnalyzer(t)
        argv, env, aux, maps = b.fire()

        assert argv == [ a.encode('utf-8') for a in t.target_args ]
        assert b"ARCHR=YES" in env

        if not static:
            ld_addr = next(addr for name, addr in maps.items() if 'linux-gnu/ld-' in name)
            assert ld_addr in struct.unpack("<%dQ"%(len(aux)/8), aux)
        return argv, env, aux, maps

    def test_qemu(self):
        with archr.targets.QEMUSystemTarget(
            qemu_test_path("pwnkernel-bzImage"), initrd_path=qemu_test_path("pwnkernel-initramfs.cpio.gz"),
            target_path="/hello", target_args=["/hello"], target_env={"ARCHR":"YES"}
        ).start() as t:
            _,_,_,maps = self.datascout_checks(t, static=True)
            qemu_ref = {
                '/hello': 0x400000,
                '[heap]': 0x4c3000,
                '[heap-end]': 0x4c5000,
                '[vvar]': 0x7ffff7ffb000,
                '[vvar-end]': 0x7ffff7ffe000,
                '[vdso]': 0x7ffff7ffe000,
                '[vdso-end]': 0x7ffff7fff000,
                '[stack]': 0x7ffffffde000,
                '[stack-end]': 0x7ffffffff000,
                '[vsyscall]': 0xffffffffff600000,
                '[vsyscall-end]': 0xffffffffff601000
            }
            assert all(maps[x] == qemu_ref[x] for x in qemu_ref), maps

    def test_datascout(self):
        with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
            _,_,_,maps = self.datascout_checks(t)
            docker_ref = {
                '/usr/lib/x86_64-linux-gnu/libc-2.31.so': 0x7ffff7dd5000,
                '/usr/lib/x86_64-linux-gnu/ld-2.31.so': 0x7ffff7fcf000,
                '[stack-end]': 0x7ffffffff000,
                '[heap]': 0x555555560000,
                '[vvar]': 0x7ffff7fcb000,
                '[vdso]': 0x7ffff7fce000,
                '[vsyscall]': 0xffffffffff600000
            }
            assert all(maps[x] == docker_ref[x] for x in docker_ref), maps

    def test_datascout_local(self):
        # copy to a writable location
        tf = tempfile.mktemp()
        shutil.copy("/usr/bin/env", tf)
        with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build().start() as t:
            _,_,_,maps = self.datascout_checks(t)
            local_maps_expected = [
                "linux-gnu/libc-",
                "linux-gnu/ld-",
                "[stack-end]",
                "[heap]",
                "[vvar]",
                "[vdso]",
                "[vsyscall]",
            ]
            for map_expected in local_maps_expected:
                assert any(map_expected in name for name in maps)

        os.unlink(tf)

class TestStackSmash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("vuln_stacksmash")

    # 32-bit vuln_stacksmash
    def test_stacksmash(self):
        with archr.targets.DockerImageTarget('archr-test:vuln_stacksmash', target_arch='i386').build().start() as t:
            b = archr.analyzers.DataScoutAnalyzer(t)
            argv, env, aux, maps = b.fire()

            assert b"PWD=/" in env
            assert maps['/usr/lib/i386-linux-gnu/ld-2.31.so'] in struct.unpack("<%dI"%(len(aux)/4), aux)
            assert '[stack-end]' in maps
            assert '[heap]' in maps
            assert '[vvar]' in maps
            assert '[vdso]' in maps


if __name__ == '__main__':
    unittest.main()
