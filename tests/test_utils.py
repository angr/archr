import subprocess
import tempfile
import archr
import os
import unittest


def test_hook():
    with open("/bin/false", "rb") as off:
        ofb = off.read()
    nfn = tempfile.mktemp()
    nfb = archr.utils.hook_entry(ofb, "mov rax, 0x3c; mov rdi, 0x2a; syscall")
    with open(nfn, "wb") as nff:
        nff.write(nfb)
    os.chmod(nfn, 0o755)
    assert subprocess.Popen(["/bin/false"]).wait() == 1
    assert subprocess.Popen([nfn]).wait() == 42
    os.unlink(nfn)


def test_deps():
    assert sorted(archr.utils.lib_dependencies("/bin/false")) == [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/ld-linux-x86-64.so.2",
    ]


if __name__ == "__main__":
    unittest.main()
