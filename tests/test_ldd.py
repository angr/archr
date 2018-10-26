import archr
import os

def setup_module():
	os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_cat_ldd():
	t = archr.targets.DockerImageTarget('archr-test:cat').build().start()
	s = t.fire_ldd()
	assert s == {'linux-vdso.so.1': 140737354113024, '/lib/x86_64-linux-gnu/libc.so.6': 140737345503232, '/lib64/ld-linux-x86-64.so.2': 140737351864320}
	t.stop()

if __name__ == '__main__':
	test_cat_ldd()
