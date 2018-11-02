import socket
import archr
import time
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def check_gdb_cat(t):
    b = archr.arsenal.GDBServerBow(t)
    with b.fire_context(port=31337) as p:
        time.sleep(2)
        s = socket.create_connection((t.ipv4_address, 31337))
        p.terminate()
        assert s

def test_cat_docker():
    with archr.targets.DockerImageTarget('archr-test:cat').build() as t:
        check_gdb_cat(t)

def test_cat_local():
    with archr.targets.LocalTarget(["/bin/cat"]).build() as t:
        check_gdb_cat(t)

if __name__ == '__main__':
    test_cat_docker()
    test_cat_local()
