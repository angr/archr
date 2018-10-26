import archr
import os

def setup_module():
	os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_cat():
	t = archr.targets.DockerImageTarget('archr-test:cat')
	t.build()
	t.start()
	p = t.run_command()
	p.stdin.write(b"Hello!\n")
	assert p.stdout.read(7) == b"Hello!\n"
	t.stop()

if __name__ == '__main__':
	test_cat()
