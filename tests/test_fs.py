import archr
import os

def setup_module():
	os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_env_mount():
	t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
	assert os.path.exists(os.path.join(t.mounted_path, "./"+t.target_path))
	t.stop()
	assert not os.path.exists(os.path.join(t.mounted_path, "./"+t.target_path))

if __name__ == '__main__':
	test_env_mount()
