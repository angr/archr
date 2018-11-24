import subprocess
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_crasher():
    with archr.targets.DockerImageTarget('archr-test:crasher').build().start() as t:
        cb = archr.arsenal.CoreBow(t)
        r = cb.fire()
        assert b"LSB core file" in subprocess.check_output(["file", r.local_core_path])

def test_crasher_noperms():
    with archr.targets.DockerImageTarget('archr-test:crasher').build().start(user="nobody") as t:
        cb = archr.arsenal.CoreBow(t)
        r = cb.fire()
        assert b"LSB core file" in subprocess.check_output(["file", r.local_core_path])

if __name__ == '__main__':
    test_crasher_noperms()
    test_crasher()
