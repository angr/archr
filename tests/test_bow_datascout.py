import subprocess
import tempfile
import struct
import shutil
import archr
import os

def test_echo_shellcode():
    with open("/bin/false", 'rb') as off:
        ofb = off.read()
    nfn = tempfile.mktemp()
    nfb = archr.utils.hook_entry(ofb, archr.arsenal.datascout.echo_shellcode("TESTING THIS THING!"))
    with open(nfn, 'wb') as nff:
        nff.write(nfb)
    os.chmod(nfn, 0o755)
    assert subprocess.Popen(["/bin/false"]).wait() == 1
    p = subprocess.Popen([nfn], stdout=subprocess.PIPE)
    assert p.communicate()[0] == b"TESTING THIS THING!"
    assert p.wait() == 42
    os.unlink(nfn)

def test_sendfile_shellcode():
    with open("/bin/false", 'rb') as off:
        ofb = off.read()
    nfn = tempfile.mktemp()
    nfb = archr.utils.hook_entry(ofb, archr.arsenal.datascout.sendfile_shellcode("/proc/self/cmdline"))
    with open(nfn, 'wb') as nff:
        nff.write(nfb)
    os.chmod(nfn, 0o755)
    assert subprocess.Popen(["/bin/false"]).wait() == 1
    p = subprocess.Popen([nfn], stdout=subprocess.PIPE)
    assert p.communicate()[0].startswith(nfn.encode('utf-8'))
    assert p.wait() == 42
    os.unlink(nfn)

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def datascout_checks(t):
    b = archr.arsenal.DataScoutBow(t)
    env, aux, maps = b.fire()

    assert b"ARCHR=YES" in env
    assert maps['/lib/x86_64-linux-gnu/ld-2.27.so'] in struct.unpack("<%dQ"%(len(aux)/8), aux)
    return env, aux, maps

def test_datascout():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        _,_,maps = datascout_checks(t)
        docker_ref = {
            '/lib/x86_64-linux-gnu/libc-2.27.so': 0x7ffff79e4000,
            '/lib/x86_64-linux-gnu/ld-2.27.so': 0x7ffff7dd5000,
            '[stack-end]': 0x7ffffffff000,
            '[heap]': 0x55555575d000,
            '[vvar]': 0x7ffff7ff7000,
            '[vdso]': 0x7ffff7ffa000,
            '[vsyscall]': 0xffffffffff600000
        }
        assert all(maps[x] == docker_ref[x] for x in docker_ref)

def test_datascout_local():
    # copy to a writable location
    tf = tempfile.mktemp()
    shutil.copy("/usr/bin/env", tf)
    with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build() as t:
        _,_,maps = datascout_checks(t)
        local_ref = {
            '/lib/x86_64-linux-gnu/libc-2.27.so': 0x7ffff79e4000,
            '/lib/x86_64-linux-gnu/ld-2.27.so': 0x7ffff7dd5000,
            '[stack-end]': 0x7ffffffff000,
            '[heap]': 0x55555575d000,
            '[vvar]': 0x7ffff7ff7000,
            '[vdso]': 0x7ffff7ffa000,
            '[vsyscall]': 0xffffffffff600000
        }
        assert all(maps[x] == local_ref[x] for x in local_ref)

    os.unlink(tf)

if __name__ == '__main__':
    test_echo_shellcode()
    test_sendfile_shellcode()
    test_datascout_local()
    test_datascout()
