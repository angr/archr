import pygdbmi.gdbcontroller
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def parse_output(s):
    return { w.split(b":")[0]: int(w.split(b":")[1], 16) for w in s.splitlines() }

def do_gdb(t):
    with archr.arsenal.GDBServerBow(t).fire_context(port=31337) as gbf:
        gc = pygdbmi.gdbcontroller.GdbController()
        gc.write("target remote %s:%d" % (t.ipv4_address, 31337))
        gc.write("continue")
        gc.exit()
        return gbf

def do_qemu(t):
    with archr.arsenal.QEMUTracerBow(t).fire_context() as qbf:
        return qbf.process

def test_offsetprinter():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        reference_env = t.run_command(aslr=False).stdout.read()
        gdb_env = do_gdb(t).stdout.read()
        assert set(reference_env.splitlines()) == set(gdb_env.splitlines())
        qemu_env = do_qemu(t).stdout.read()
        assert set(reference_env.splitlines()) == set(qemu_env.splitlines())

    with archr.targets.DockerImageTarget('archr-test:offsetprinter').build() as t:
        reference_str = t.run_command(aslr=False).stdout.read()
        reference_dct = parse_output(reference_str)
        assert parse_output(t.run_command(aslr=False).stdout.read()) == reference_dct

        gdb_str = do_gdb(t).stdout.read()
        assert parse_output(gdb_str) == reference_dct

        qemu_str = do_qemu(t).stdout.read()
        qemu_dct = parse_output(qemu_str)
        for s in [ b'MAIN',  b'STDOUT', b'SMALL_MALLOC', b'BIG_MALLOC', b'MMAP' ]:
            assert hex(qemu_dct[s])[-3:] == hex(reference_dct[s])[-3:]
        assert qemu_dct[b'STACK'] - qemu_dct[b'ARGV'] == reference_dct[b'STACK'] - reference_dct[b'ARGV']
        assert qemu_dct[b'STACK'] - qemu_dct[b'ENVP'] == reference_dct[b'STACK'] - reference_dct[b'ENVP']

if __name__ == '__main__':
    test_offsetprinter()
