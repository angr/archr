import os
import angr
import logging

l = logging.getLogger("archr.analyzers.angr_state")

from . import Analyzer


class SimArchrMount(angr.state_plugins.filesystem.SimConcreteFilesystem):
    def __init__(self, target=None, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.target = self.target
        return o

    def _load_file(self, guest_path):
        from docker.errors import NotFound  # pylint:disable=import-outside-toplevel

        try:
            target_path = self.target.realpath(guest_path)
            content = self.target.retrieve_contents(target_path)
            return angr.SimFile(name="file://" + target_path, content=content, size=len(content))
        except NotFound:
            return None

    def _get_stat(self, guest_path, dereference=False):
        if dereference:
            guest_path = self.target.realpath(guest_path)
        stat_output = (
            self.target.run_command(["stat", "-c", "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o %B", guest_path])
            .communicate()[0]
            .decode()
            .split()
        )

        # parse output
        # st_mode, device number, major type, minor type are in hex
        for i in [3, 6, 9, 10]:
            stat_output[i] = int(stat_output[i], 16)
        stat_output[1:] = [int(x) for x in stat_output[1:]]  # others are int

        # %n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o %C
        (
            _,  # %n file name is ignored
            st_size,  # %s total size, in bytes
            st_blocks,  # %b number of blocks allocated (see %B)
            st_mode,  # %f raw mode in hex
            st_uid,  # %u     user ID of owner
            st_gid,  # %g     group ID of owner
            st_dev,  # %D     device number in hex
            st_ino,  # %i     inode number
            st_nlink,  # %h number of hard links
            _,  # %t major device type in hex, for character/block device special files
            _,  # %T minor device type in hex, for character/block device special files
            st_atime,  # %X time of last access, seconds since Epoch
            st_mtime,  # %Y time of last data modification, seconds since Epoch
            st_ctime,  # %Z time of last status change, seconds since Epoch
            _,  # %W time of file birth, seconds since Epoch; 0 if unknown
            _,  # %o optimal I/O transfer size hint
            st_blksize,  # %B block size
        ) = stat_output
        st_mtime_ns = st_mtime * 1000000
        st_atime_ns = st_atime * 1000000
        st_ctime_ns = st_ctime * 1000000
        WRONG_rdev = 0  # TODO: build from major and minor: https://code.woboq.org/qt5/include/bits/sysmacros.h.html
        st = angr.state_plugins.filesystem.Stat(
            st_dev,
            st_ino,
            st_nlink,
            st_mode,
            st_uid,
            st_gid,
            WRONG_rdev,
            st_size,
            st_blksize,
            st_blocks,
            st_atime,
            st_atime_ns,
            st_mtime,
            st_mtime_ns,
            st_ctime,
            st_ctime_ns,
        )
        return st


class SimArchrProcMount(SimArchrMount):
    def _load_file(self, guest_path):
        """
        For some reason the procfs files cannot be fetched with the docker API, so here we just `cat` instead
        :param guest_path:
        :return:
        """
        # attempt normal loading first
        file = super()._load_file(os.path.join("/proc", guest_path))
        if file is not None:
            return file

        target_path = self.target.realpath(os.path.join("/proc", guest_path.lstrip(os.path.sep)))
        content, error = self.target.run_command(["cat", target_path]).communicate()
        if not error:
            return angr.SimFile(name="file://" + target_path, content=content, size=len(content))
        else:
            assert ": No such file or directory" in error
            return None

    def _get_stat(self, guest_path, dereference=False):
        return super()._get_stat(os.path.join("/proc", guest_path.lstrip(os.path.sep)), dereference=dereference)


class angrStateAnalyzer(Analyzer):
    """
    Constructs an angr state (full init variety) to match the target precisely
    """

    def __init__(self, target, project_analyzer):
        super().__init__(target)
        self.project_analyzer = project_analyzer

    def fire(self, **kwargs):  # pylint:disable=arguments-differ
        project = self.project_analyzer.fire()
        if "cwd" not in kwargs:
            cwd = os.path.dirname(self.project_analyzer.target.target_path)
            kwargs["cwd"] = bytes(cwd, "utf-8")

        concrete_fs = kwargs.pop("concrete_fs", True)
        chroot = kwargs.pop("chroot", "/ARCHR-INVALID")
        stack_end = kwargs.pop("stack_end", self.project_analyzer._mem_mapping.get("[stack-end]", None))
        args = kwargs.pop("args", self.target.main_binary_args)
        env = kwargs.pop("env", self.target.target_env)
        brk = kwargs.pop("brk", self.project_analyzer._mem_mapping.get("[heap]", None))

        s = project.factory.full_init_state(
            concrete_fs=concrete_fs, chroot=chroot, stack_end=stack_end, args=args, env=env, brk=brk, **kwargs
        )
        s.fs.mount("/", SimArchrMount(self.target))
        s.fs.set_state(s)
        return s
