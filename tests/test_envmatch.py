import pygdbmi.gdbcontroller
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def parse_output(s):
    return { w.split(b":")[0]: int(w.split(b":")[1], 16) for w in s.splitlines() }

def gdb_do(t):
    with archr.arsenal.GDBServerBow(t).fire_context(port=31337) as gbf:
        gc = pygdbmi.gdbcontroller.GdbController()
        gc.write("target remote %s:%d" % (t.ipv4_address, 31337))
        gc.write("continue")
        gc.exit()
        return gbf

def test_offsetprinter():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        reference_env = t.run_command(aslr=False).stdout.read()
        gdb_env = gdb_do(t).stdout.read()
        assert set(reference_env.splitlines()) == set(gdb_env.splitlines())

    with archr.targets.DockerImageTarget('archr-test:offsetprinter').build() as t:
        reference_str = t.run_command(aslr=False).stdout.read()
        reference = parse_output(reference_str)
        assert parse_output(t.run_command(aslr=False).stdout.read()) == reference

        gdb_str = gdb_do(t).stdout.read()
        assert parse_output(gdb_str) == reference

if __name__ == '__main__':
    test_offsetprinter()
