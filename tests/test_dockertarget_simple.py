import socket
import archr
import os

def setup_module():
	os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_cat():
	t = archr.targets.DockerImageTarget('archr-test:cat').build().start()
	p = t.run_command()
	p.stdin.write(b"Hello!\n")
	assert p.stdout.read(7) == b"Hello!\n"
	t.stop()

def test_cat_stderr():
	t = archr.targets.DockerImageTarget('archr-test:cat-stderr').build().start()
	p = t.run_command()
	p.stdin.write(b"Hello!\n")
	assert p.stderr.read(7) == b"Hello!\n"
	t.stop()

def test_entrypoint_true():
	t = archr.targets.DockerImageTarget('archr-test:entrypoint-true').build().start()
	p = t.run_command()
	p.wait()
	assert p.returncode == 0
	t.stop()

def test_entrypoint_false():
	t = archr.targets.DockerImageTarget('archr-test:entrypoint-false').build().start()
	p = t.run_command()
	p.wait()
	assert p.returncode == 1
	t.stop()

def test_entrypoint_env():
	t = archr.targets.DockerImageTarget('archr-test:entrypoint-env').build().start()
	p = t.run_command()
	stdout,_ = p.communicate()
	assert sum(1 for i in stdout.split(b'\n') if i == b"ARCHR=YES") == 1
	t.stop()

def test_nccat_simple():
	t = archr.targets.DockerImageTarget('archr-test:nccat').build().start()
	p = t.run_command()
	s = socket.create_connection((t.ip_address, 1337))
	s.send(b"Hello\n")
	assert s.recv(6) == b"Hello\n"
	t.stop()

if __name__ == '__main__':
	test_cat()
	test_cat_stderr()
	test_entrypoint_true()
	test_entrypoint_false()
	test_entrypoint_env()
	test_nccat_simple()
