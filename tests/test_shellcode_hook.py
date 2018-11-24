import tempfile
import shutil
import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_dockerfile_hook():
    with archr.targets.DockerImageTarget('archr-test:entrypoint-false').build().start() as t:
        assert t.run_command().wait() == 1
        with t.shellcode_context(asm_code="mov rax, 60; mov rdi, 42; syscall") as p:
            assert p.wait() == 42
        assert t.run_command().wait() == 1

def test_local_hook():
    # copy out /bin/false, because we can't overwrite it obviously
    tf = tempfile.mktemp()
    shutil.copy("/bin/false", tf)
    with archr.targets.LocalTarget([tf]).build().start() as t:
        assert t.run_command().wait() == 1
        with t.shellcode_context(asm_code="mov rax, 60; mov rdi, 42; syscall") as p:
            assert p.wait() == 42
        assert t.run_command().wait() == 1
    os.unlink(tf)

if __name__ == '__main__':
    test_dockerfile_hook()
    test_local_hook()
