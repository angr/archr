import subprocess
import tempfile
import struct
import archr
import os

def test_echo_shellcode():
    with open("/bin/false", 'rb') as off:
        ofb = off.read()
    nfn = tempfile.mktemp()
    nfb = archr.utils.hook_entry(ofb, archr.bows.datascout.echo_shellcode(b"TESTING THIS THING!"))
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
    nfb = archr.utils.hook_entry(ofb, archr.bows.datascout.sendfile_shellcode(b"/proc/self/cmdline"))
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

def test_datascout():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        b = archr.bows.DataScoutBow(t)
        env, aux = b.fire()

        assert sum(1 for i in env if i == b"ARCHR=YES")
        m = archr.bows.MemoryMapBow(t)
        mm = m.fire()
        assert mm['/lib64/ld-linux-x86-64.so.2'] in struct.unpack("<%dQ"%(len(aux)/8), aux)

if __name__ == '__main__':
    test_echo_shellcode()
    test_sendfile_shellcode()
    test_datascout()
