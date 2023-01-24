import tempfile
import claripy
import shutil
import archr
import os
import unittest

from common import build_container


class TestangrAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("entrypoint-env")
        build_container("cat-flag")
        build_container("fauxware")
        build_container("syscall_test")

    def angr_checks(self, t):
        dsb = archr.analyzers.DataScoutAnalyzer(t)
        apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
        asb = archr.analyzers.angrStateAnalyzer(t, apb)
        project = apb.fire()
        self.assertTrue(all(obj.binary.startswith("/tmp") for obj in project.loader.all_elf_objects[1:]))
        state = asb.fire()
        initial_stack = state.solver.eval(state.memory.load(state.regs.rsp, 200), cast_to=bytes)
        self.assertIn(b"ARCHR=YES", initial_stack)

        self.assertTrue(state.solver.eval_one(state.posix.brk == apb._mem_mapping["[heap]"]))
        self.assertTrue(
            state.solver.eval_one(
                (state.regs.sp + 0xFFF) & ~claripy.BVV(0xFFF, project.arch.bits) == apb._mem_mapping["[stack-end]"]
            )
        )

        # now screw with the memory map
        apb._mem_mapping["[stack-end]"] = 0x1337000
        state = asb.fire()
        self.assertTrue(
            state.solver.eval_one(
                (state.regs.sp + 0xFFF) & ~claripy.BVV(0xFFF, project.arch.bits) == apb._mem_mapping["[stack-end]"]
            )
        )

        # now check the filesystem resolution
        fd = state.posix.open("/etc/passwd", 0)
        stat = state.posix.fstat(fd)
        self.assertIsNotNone(stat)
        self.assertFalse(state.solver.symbolic(stat.st_size))
        self.assertNotEqual(state.solver.eval(stat.st_size), 0)

        # done
        project.loader.close()

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_env_angr(self):
        with archr.targets.DockerImageTarget("archr-test:entrypoint-env").build().start() as t:
            self.angr_checks(t)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_env_angr_local(self):
        tf = tempfile.mktemp()
        shutil.copy("/usr/bin/env", tf)
        with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build().start() as t:
            self.angr_checks(t)
        os.unlink(tf)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_catflag(self):
        with archr.targets.DockerImageTarget("archr-test:cat-flag").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()
            self.assertEqual(len(simgr.errored), 0)
            self.assertEqual(len(simgr.deadended), 1)
            self.assertEqual(simgr.one_deadended.posix.dumps(1), b"archr-flag\n")

    def _default_fauxware_checks(self, simgr):
        num_authed, num_rejected, num_bypassed = 0, 0, 0
        for s in simgr.deadended:
            if b"Go away" in s.posix.dumps(1):
                num_rejected += 1
            if b"Welcome to the admin console, trusted user!" in s.posix.dumps(1):
                num_authed += 1
                if b"SOSNEAKY" in s.posix.dumps(0):
                    num_bypassed += 1

        self.assertEqual(num_authed, 2)
        self.assertEqual(num_bypassed, 1)
        self.assertEqual(num_rejected, 1)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_fauxware(self):
        with archr.targets.DockerImageTarget("archr-test:fauxware").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()
            self._default_fauxware_checks(simgr)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_fauxware_custom_plt_hooks(self):
        import angr  # pylint:disable=import-outside-toplevel

        original_puts = angr.SIM_PROCEDURES["libc"]["puts"]
        original_read = angr.SIM_PROCEDURES["posix"]["read"]

        class new_puts(angr.SimProcedure):
            def run(self, s):  # pylint:disable=arguments-differ
                self.state.globals["num_puts"] = self.state.globals.get("num_puts", 0) + 1
                return self.inline_call(original_puts, s).ret_expr

        class new_read(angr.SimProcedure):
            def run(self, fd, buf, _len):  # pylint:disable=arguments-differ
                self.state.globals["num_read"] = self.state.globals.get("num_read", 0) + 1
                return self.inline_call(original_read, fd, buf, _len).ret_expr

        with archr.targets.DockerImageTarget("archr-test:fauxware").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb, custom_hooks={"puts": new_puts(), "read": new_read()})
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()

            num_authed, num_rejected, num_bypassed = 0, 0, 0
            for s in simgr.deadended:
                if b"Go away" in s.posix.dumps(1):
                    num_rejected += 1
                    self.assertEqual(s.globals["num_puts"], 2)
                    self.assertEqual(s.globals["num_read"], 5)
                if b"Welcome to the admin console, trusted user!" in s.posix.dumps(1):
                    num_authed += 1
                    if b"SOSNEAKY" in s.posix.dumps(0):
                        num_bypassed += 1
                        self.assertEqual(s.globals["num_puts"], 3)
                        self.assertEqual(s.globals["num_read"], 4)
                    else:
                        self.assertEqual(s.globals["num_puts"], 3)
                        self.assertEqual(s.globals["num_read"], 5)

            self.assertEqual(num_authed, 2)
            self.assertEqual(num_bypassed, 1)
            self.assertEqual(num_rejected, 1)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_fauxware_custom_binary_function_hooks(self):
        import angr  # pylint:disable=import-outside-toplevel

        class rejected(angr.SimProcedure):
            def run(self):  # pylint:disable=arguments-differ
                self.state.posix.stdout.write(None, b"Get outta here!")
                self.exit(1)

        class authorized(angr.SimProcedure):
            def run(self):  # pylint:disable=arguments-differ
                self.state.posix.stdout.write(None, b"Good on ya, mate! Get in 'ere, ya bloody admin.")

        hooks = {"accepted": authorized(), "rejected": rejected()}

        with archr.targets.DockerImageTarget("archr-test:fauxware").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb, custom_hooks=hooks)
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()
            num_authed, num_rejected, num_bypassed = 0, 0, 0
            for s in simgr.deadended:
                if b"Get outta here!" in s.posix.dumps(1):
                    num_rejected += 1
                if b"Good on ya, mate! Get in 'ere, ya bloody admin." in s.posix.dumps(1):
                    num_authed += 1
                    if b"SOSNEAKY" in s.posix.dumps(0):
                        num_bypassed += 1

            self.assertEqual(num_authed, 2)
            self.assertEqual(num_bypassed, 1)
            self.assertEqual(num_rejected, 1)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_syscall_test(self):
        with archr.targets.DockerImageTarget("archr-test:syscall_test").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb)
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()

            self.assertEqual(len(simgr.deadended), 1)
            (exit_code,) = (e.objects["exit_code"] for e in simgr.one_deadended.history.events if e.type == "terminate")
            self.assertEqual(simgr.one_deadended.posix.dumps(1), b"Hello, world!\n")
            self.assertEqual(simgr.one_deadended.solver.eval_one(exit_code), 42)

    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_syscall_test_hooks(self):
        import angr  # pylint:disable=import-outside-toplevel

        original_write = angr.SIM_PROCEDURES["posix"]["write"]

        class new_puts(angr.SimProcedure):
            def run(self, code):  # pylint:disable=arguments-differ
                new_exit = self.state.solver.eval_one(code) + 27
                self.exit(new_exit)

        class new_write(angr.SimProcedure):
            def run(self, fd, buf, _):  # pylint:disable=arguments-differ
                self.state.globals["num_write"] = self.state.globals.get("num_read", 0) + 1
                return self.inline_call(original_write, fd, buf, 5).ret_expr

        syscalls = dict(exit=new_puts(), write=new_write())

        with archr.targets.DockerImageTarget("archr-test:syscall_test").build().start() as t:
            dsb = archr.analyzers.DataScoutAnalyzer(t)
            apb = archr.analyzers.angrProjectAnalyzer(t, dsb, custom_systemcalls=syscalls)
            asb = archr.analyzers.angrStateAnalyzer(t, apb)
            project = apb.fire()
            state = asb.fire()
            simgr = project.factory.simulation_manager(state)
            simgr.run()

            self.assertEqual(len(simgr.deadended), 1)
            (exit_code,) = (e.objects["exit_code"] for e in simgr.one_deadended.history.events if e.type == "terminate")
            self.assertEqual(simgr.one_deadended.posix.dumps(1), b"Hello")
            self.assertEqual(simgr.one_deadended.solver.eval_one(exit_code), 69)


if __name__ == "__main__":
    unittest.main()
