import pygdbmi.gdbcontroller
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def gdb_do(t):
    with archr.arsenal.GDBServerBow(t).fire_context(port=31337) as gbf:
        gc = pygdbmi.gdbcontroller.GdbController()
        gc.write("target remote %s:%d" % (t.ipv4_address, 31337))
        gc.write("continue")
        gc.exit()
        return gbf


def check_gdb_cat(t):
    p = gdb_do(t)
    assert b"Child exited with status 1" in p.stderr.read()

def test_cat_docker():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-false').build().start() as t:
        check_gdb_cat(t)

def test_env_order():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        a = gdb_do(t).stdout.read()
        b = gdb_do(t).stdout.read()
        c = gdb_do(t).stdout.read()
        assert a == b
        assert b == c

def test_cat_local():
    with archr.targets.LocalTarget(["/bin/false"]).build().start() as t:
        check_gdb_cat(t)

if __name__ == '__main__':
    test_cat_docker()
    test_cat_local()
    test_env_order()
