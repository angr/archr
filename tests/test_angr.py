import archr
import os

def setup_module():
	os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_env_angr():
	t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
	project = t.fire_angr_project()
	assert all(obj.binary.startswith(t.mounted_path) for obj in project.loader.all_elf_objects[1:])
	state = t.fire_angr_full_init_state()
	initial_stack = state.solver.eval(state.memory.load(state.regs.rsp, 200), cast_to=bytes)
	assert b"ARCHR=YES" in initial_stack

if __name__ == '__main__':
	test_env_angr()
