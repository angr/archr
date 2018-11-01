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
    nfb = archr.utils.hook_entry(ofb, archr.arsenal.datascout.echo_shellcode(b"TESTING THIS THING!"))
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
    nfb = archr.utils.hook_entry(ofb, archr.arsenal.datascout.sendfile_shellcode(b"/proc/self/cmdline"))
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
    env, aux = b.fire()

    assert b"ARCHR=YES" in env
    m = archr.arsenal.MemoryMapBow(t)
    mm = m.fire()
    assert mm['/lib64/ld-linux-x86-64.so.2'] in struct.unpack("<%dQ"%(len(aux)/8), aux)

def test_datascout():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        datascout_checks(t)

def test_datascout_local():
    # copy to a writable location
    tf = tempfile.mktemp()
    shutil.copy("/usr/bin/env", tf)
    with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build() as t:
        datascout_checks(t)
    os.unlink(tf)

if __name__ == '__main__':
    test_echo_shellcode()
    test_sendfile_shellcode()
    test_datascout_local()
    test_datascout()
