import archr
import unittest

from common import build_container


class TestAnalyzerQTrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("cat")

    def check_qtrace_results(self, target, **kwargs):
        import qtrace

        analyzer = archr.analyzers.QTraceAnalyzer(target)
        machine = analyzer.fire(args_suffix=["/etc/passwd"], **kwargs)

        syscalls = [
            qtrace.syscalls["x86_64"][e[1]][1]
            for e in machine.filtered_trace("syscall_start")
        ]

        correct_syscalls = [
            "sys_openat",
            "sys_fstat",
            "sys_fadvise64",
            "sys_mmap",
            "sys_read",
            "sys_write",
            "sys_read",
            "sys_munmap",
            "sys_close",
            "sys_close",
            "sys_close",
            "sys_exit_group",
        ]

        assert "\n".join(correct_syscalls) in "\n".join(syscalls)

        pathname_name = machine.argv[0].split("/")[-1]
        program_map_permissions = set(
            e[2] for e in machine.maps.values() if e[0].split("/")[-1] == pathname_name
        )
        correct_permissions = {"r--p", "r-xp", "rw-p"}
        assert program_map_permissions == correct_permissions, (program_map_permissions, machine.maps.items())

    def test_qtrace_local(self):
        with archr.targets.LocalTarget(["/bin/cat"]).build().start() as target:
            self.check_qtrace_results(target)

    def test_qtrace_docker(self):
        with archr.targets.DockerImageTarget(
            "archr-test:cat"
        ).build().start() as target:
            self.check_qtrace_results(target)


if __name__ == "__main__":
    unittest.main()
