import claripy
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def angr_checks(t):
    mb = archr.bows.MemoryMapBow(t)
    apb = archr.bows.angrProjectBow(t, mb)
    asb = archr.bows.angrStateBow(t, apb)
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
    with archr.targets.DockerImageTarget('archr-test:entrypoint-env').build() as t:
        angr_checks(t)

def test_env_angr_local():
    with archr.targets.LocalTarget(["/usr/bin/env"], target_env=["ARCHR=YES"]).build() as t:
        angr_checks(t)

if __name__ == '__main__':
    test_env_angr_local()
    test_env_angr()
