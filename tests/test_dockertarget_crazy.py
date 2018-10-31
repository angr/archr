import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_false_hook():
    t = archr.targets.DockerImageTarget('archr-test:entrypoint-false').build().start()
    assert t.run_command().wait() == 1
    with t.shellcode_context(asm_code="mov rax, 60; mov rdi, 42; syscall") as p:
        assert p.wait() == 42
    assert t.run_command().wait() == 1
    t.stop()

if __name__ == '__main__':
    test_false_hook()
