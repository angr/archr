import tempfile
import struct
import shutil
import archr
import os
import unittest

from common import build_container


class TestShellcode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")
        build_container("vuln_stacksmash")

    def shellcode_checks(self, t):
        b = archr.analyzers.DataScoutAnalyzer(t)
        with t.shellcode_context(asm_code=b.exit_shellcode(exit_code=123)) as p:
            stdout, _ = p.communicate()
            assert p.wait() == 123

        with t.shellcode_context(asm_code=b.echo_shellcode("TESTING THIS THING!")) as p:
            stdout, _ = p.communicate()
            assert stdout == b"TESTING THIS THING!"

        with t.shellcode_context(asm_code=b.echo_shellcode("TESTING THIS THING!") + b.exit_shellcode()) as p:
            stdout, _ = p.communicate()
            assert stdout == b"TESTING THIS THING!"
            assert p.wait() == 42

        with t.shellcode_context(asm_code=b.read_file_shellcode("/proc/self/cmdline")) as p:
            stdout, _ = p.communicate()
            assert stdout == t.target_path.encode("utf-8") + b"\0"

    def test_shellcode_amd64(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            self.shellcode_checks(t)

    def test_shellcode_i386(self):
        with archr.targets.DockerImageTarget("archr-test:vuln_stacksmash", target_arch="i386").build().start() as t:
            self.shellcode_checks(t)


class TestDatascout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")

    def datascout_checks(self, t):
        b = archr.analyzers.DataScoutAnalyzer(t)
        argv, env, aux, maps = b.fire()

        ld_addr = next(addr for name, addr in maps.items() if "linux-gnu/ld-" in name)

        assert argv == [a.encode("utf-8") for a in t.target_args]
        assert b"ARCHR=YES" in env
        assert ld_addr in struct.unpack("<%dQ" % (len(aux) / 8), aux)
        return argv, env, aux, maps

    def test_datascout(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            _, _, _, maps = self.datascout_checks(t)
            assert (
                next(v for k, v in maps.items() if k.startswith("/usr/lib/x86_64-linux-gnu/libc-")) & 0xFFFFFF000000
                == 0x7FFFF7000000
            )
            assert (
                next(v for k, v in maps.items() if k.startswith("/usr/lib/x86_64-linux-gnu/ld-")) & 0xFFFFFF000000
                == 0x7FFFF7000000
            )
            assert maps["[stack-end]"] == 0x7FFFFFFFF000
            assert maps["[vsyscall]"] == 0xFFFFFFFFFF600000
            assert maps["[vdso]"] & 0xFFFFFF000000 == 0x7FFFF7000000
            assert maps["[vvar]"] & 0xFFFFFF000000 == 0x7FFFF7000000
            assert maps["[heap]"] == 0x555555560000

    def test_datascout_local(self):
        # copy to a writable location
        tf = tempfile.mktemp()
        shutil.copy("/usr/bin/env", tf)
        with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build().start() as t:
            _, _, _, maps = self.datascout_checks(t)
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
        with archr.targets.DockerImageTarget("archr-test:vuln_stacksmash", target_arch="i386").build().start() as t:
            b = archr.analyzers.DataScoutAnalyzer(t)
            argv, env, aux, maps = b.fire()

            assert b"PWD=/" in env
            assert maps["/usr/lib/i386-linux-gnu/ld-2.31.so"] in struct.unpack("<%dI" % (len(aux) / 4), aux)
            assert "[stack-end]" in maps
            assert "[heap]" in maps
            assert "[vvar]" in maps
            assert "[vdso]" in maps


if __name__ == "__main__":
    unittest.main()
