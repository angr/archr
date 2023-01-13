import pygdbmi.gdbcontroller
import archr
import unittest

from common import build_container


class TestSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")
        build_container("offsetprinter64")
        build_container("offsetprinter32")
        build_container("stackprinter64")

    def parse_output(self, s):
        return {w.split(b":")[0]: int(w.split(b":")[1], 16) for w in s.splitlines()}

    def do_gdb(self, t):
        with archr.analyzers.GDBServerAnalyzer(t).fire_context(port=31337) as gbf:
            gc = pygdbmi.gdbcontroller.GdbController()
            gc.write("target remote %s:%d" % (t.ipv4_address, 31337))
            gc.write("continue")
            gc.exit()
            return gbf.process

    def do_qemu(self, t):
        with archr.analyzers.QEMUTracerAnalyzer(t).fire_context() as qbf:
            return qbf.process

    @unittest.skip("broken")
    def test_env(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            reference_env = t.run_command(aslr=False).stdout.read()
            gdb_env = self.do_gdb(t).stdout.read()
            assert set(reference_env.splitlines()) == set(gdb_env.splitlines())
            qemu_env = self.do_qemu(t).stdout.read()
            assert set(reference_env.splitlines()) == set(qemu_env.splitlines())

    def check_offsetprinter(self, t):
        reference_str = t.run_command(aslr=False).stdout.read()
        reference_dct = self.parse_output(reference_str)
        assert self.parse_output(t.run_command(aslr=False).stdout.read()) == reference_dct

        gdb_str = self.do_gdb(t).stdout.read()
        assert self.parse_output(gdb_str) == reference_dct

        qemu_str = self.do_qemu(t).stdout.read()
        qemu_dct = self.parse_output(qemu_str)
        for s in [b"MAIN", b"STDOUT", b"SMALL_MALLOC", b"BIG_MALLOC", b"MMAP"]:
            assert hex(qemu_dct[s])[-3:] == hex(reference_dct[s])[-3:]
        assert qemu_dct[b"STACK"] - qemu_dct[b"ARGV"] == reference_dct[b"STACK"] - reference_dct[b"ARGV"]
        assert qemu_dct[b"STACK"] - qemu_dct[b"ENVP"] == reference_dct[b"STACK"] - reference_dct[b"ENVP"]

        # COMMENTED OUT PENDING LIBC INIT OFFSETS
        # dsb = archr.analyzers.DataScoutAnalyzer(t)
        # apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
        # asb = archr.analyzers.angrStateAnalyzer(t, apb)
        # project = apb.fire(use_sim_procedures=False)
        # state = asb.fire(add_options={angr.sim_options.STRICT_PAGE_ACCESS}) # for now
        # simgr = project.factory.simulation_manager(state)
        ##assert not simgr.active[0].memory.load(0x7ffff7dd48f8, project.arch.bytes).symbolic # __libc_multiple_threads sanity check
        # simgr.run()
        # assert len(simgr.errored) == 0
        # assert len(simgr.deadended) == 1
        # assert len(sum(simgr.stashes.values(), [])) == 1
        ##assert simgr.deadended[0].posix.dumps(1) == reference_str

    @unittest.skip("broken")
    def test_offsetprinter64(self):
        # with archr.targets.DockerImageTarget('archr-test:offsetprinter').build().start() as t:
        t = archr.targets.DockerImageTarget("archr-test:offsetprinter64").build().start()
        self.check_offsetprinter(t)
        t.stop()

    @unittest.skip("broken")
    def test_offsetprinter32(self):
        # with archr.targets.DockerImageTarget('archr-test:offsetprinter').build().start() as t:
        t = archr.targets.DockerImageTarget("archr-test:offsetprinter32", target_arch="i386").build().start()
        self.check_offsetprinter(t)
        t.stop()

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_stack(self):
        import angr

        t = archr.targets.DockerImageTarget("archr-test:stackprinter64").build().start()
        reference_str = t.run_command(aslr=False).stdout.read()

        dsb = archr.analyzers.DataScoutAnalyzer(t)
        apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
        asb = archr.analyzers.angrStateAnalyzer(t, apb)
        project = apb.fire(use_sim_procedures=False)
        state = asb.fire(add_options={angr.sim_options.STRICT_PAGE_ACCESS})  # for now
        simgr = project.factory.simulation_manager(state)
        simgr.run()
        assert len(simgr.errored) == 0
        assert len(simgr.deadended) == 1
        assert len(sum(simgr.stashes.values(), [])) == 1
        # assert simgr.deadended[0].posix.dumps(1) == reference_str

        t.stop()


if __name__ == "__main__":
    unittest.main()
