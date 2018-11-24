import tempfile
import claripy
import shutil
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def angr_checks(t):
    dsb = archr.arsenal.DataScoutBow(t)
    apb = archr.arsenal.angrProjectBow(t, dsb)
    asb = archr.arsenal.angrStateBow(t, apb)
    project = apb.fire()
    assert all(obj.binary.startswith(t.local_path) for obj in project.loader.all_elf_objects[1:])
    state = asb.fire()
    initial_stack = state.solver.eval(state.memory.load(state.regs.rsp, 200), cast_to=bytes)
    assert b"ARCHR=YES" in initial_stack

    assert state.solver.eval_one(state.posix.brk == apb._mem_mapping['[heap]'])
    assert state.solver.eval_one((state.regs.sp + 0xfff) & ~claripy.BVV(0xfff, project.arch.bits) == apb._mem_mapping['[stack-end]'])

    # now screw with the memory map
    apb._mem_mapping['[stack-end]'] = 0x1337000
    state = asb.fire()
    assert state.solver.eval_one((state.regs.sp + 0xfff) & ~claripy.BVV(0xfff, project.arch.bits) == apb._mem_mapping['[stack-end]'])
    project.loader.close()

def test_env_angr():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start() as t:
        angr_checks(t)

def test_env_angr_local():
    tf = tempfile.mktemp()
    shutil.copy("/usr/bin/env", tf)
    with archr.targets.LocalTarget([tf], target_env=["ARCHR=YES"]).build().start() as t:
        angr_checks(t)
    os.unlink(tf)

if __name__ == '__main__':
    test_env_angr_local()
    test_env_angr()
