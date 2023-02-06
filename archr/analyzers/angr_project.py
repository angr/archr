import tempfile
import logging
import angr
import cle
import os

from angr.simos import SimUserland
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment

l = logging.getLogger("archr.analyzers.angr")

from . import Analyzer


def _extract_mapping_from_core_file(core_path):
    with open(core_path, "rb") as core_file:
        core_elf = ELFFile(core_file)
        for segment in core_elf.iter_segments():
            if isinstance(segment, NoteSegment):
                notes = list(segment.iter_notes())
                break
        else:
            l.warning(
                "The core file @ %s does not contain a NOTE segment, you should fix that. We "
                "will attempt to get the mapped addresses from the scout_analyzer instead I guess.",
                core_path,
            )
            return None
    for note in notes:
        if note["n_type"] == "NT_FILE":
            file_note = note
            break
    else:
        l.warning(
            "Could not find an NT_FILE note in the core file @ %s. This is bad, and you should fix "
            "it. We will fall back to trying to extract the mappings from the scout_analyzer.",
            core_path,
        )
        return None

    mappings = file_note["n_desc"]["Elf_Nt_File_Entry"]
    paths = [p.decode() for p in file_note["n_desc"]["filename"]]
    assert len(paths) == len(mappings)
    mem_map = {}
    for fpath, mapping in zip(paths, mappings):
        mem_map[fpath] = min(mem_map.get(fpath, mapping["vm_start"]), mapping["vm_start"])

    return mem_map


class angrProjectAnalyzer(Analyzer):
    """
    Constructs an angr project to match the target precisely
    """

    def __init__(self, target, scout_analyzer=None, custom_hooks=None, custom_systemcalls=None, static_simproc=False):
        # pylint:disable=too-many-arguments
        """

        :param target:          The target to work on.
        :param scout_analyzer:      The scout analyzer.
        :param static_simproc:  When enabled, angr will hook functions in the main binary with SimProcedures if
                                available. This is useful when dealing with statically linked binaries.
        :type static_simproc:   bool
        """

        super().__init__(target)
        self.scout_analyzer = scout_analyzer
        self.static_simproc = static_simproc

        self.custom_hooks = {} if custom_hooks is None else dict(custom_hooks)
        self.custom_syscalls = {} if custom_systemcalls is None else dict(custom_systemcalls)

        self.project = None
        self._mem_mapping = None
        self._lib_folder = None

    def fire(
        self, core_path=None, return_loader=False, project_kwargs=None, **cle_args
    ):  # pylint:disable=arguments-differ
        # if the the project is already created, return what the user wants
        if self.project is not None:
            return self.project if not return_loader else self.project.loader

        auto_load_libs = cle_args.get("auto_load_libs", True)

        # from now on, try to create a angr project
        if project_kwargs is None:
            project_kwargs = dict(auto_load_libs=auto_load_libs)

        # TODO: this introduce file leak. However, we probably need some redesign to fix it
        tmpdir = tempfile.mkdtemp(prefix="archr_angr_project_analyzer")
        self._lib_folder = tmpdir
        self.target.retrieve_into(self.target.target_path, tmpdir)
        the_binary = os.path.join(tmpdir, os.path.basename(self.target.target_path))

        # preload the binary to decide if it supports setting library options or base addresses
        cle_args.update(cle_args.pop("load_options", {}))
        cle_args.pop("use_sim_procedures", None)  # TODO do something less hacky than this
        preload_kwargs = dict(cle_args)
        preload_kwargs["auto_load_libs"] = False
        preloader = cle.Loader(the_binary, **preload_kwargs)

        self._mem_mapping = None

        if core_path is not None:
            self._mem_mapping = _extract_mapping_from_core_file(core_path)

        if self._mem_mapping is None and self.scout_analyzer is not None:
            _, _, _, self._mem_mapping = self.scout_analyzer.fire()

        self._mem_mapping = self._mem_mapping or {}

        target_libs = [lib for lib in self._mem_mapping if lib.startswith("/")]
        the_libs = []
        for target_lib in target_libs:
            local_lib = os.path.join(tmpdir, os.path.basename(target_lib))
            self.target.retrieve_into(target_lib, tmpdir)
            if auto_load_libs:
                the_libs.append(local_lib)
        lib_opts = {os.path.basename(lib): {"base_addr": libaddr} for lib, libaddr in self._mem_mapping.items()}
        bin_opts = {}
        if preloader.main_object.pic:
            bin_opts = lib_opts.get(os.path.basename(self.target.target_path), {})

        # if a core dump is specified, create a project based on the core dump
        if core_path:
            file_mapping = {}

            # grab remote libraries to local machine and build the mapping
            for remote_path in self._mem_mapping:
                # use heuristic to distinguish file mappings from others
                if not remote_path.startswith("/"):
                    continue
                self.target.retrieve_into(remote_path, tmpdir)
                local_path = os.path.join(tmpdir, os.path.basename(remote_path))
                file_mapping[remote_path] = local_path

            bin_opts = {"backend": "elfcore", "executable": the_binary, "remote_file_mapping": file_mapping}
            self.project = angr.Project(core_path, main_opts=bin_opts, rebase_granularity=0x1000, **project_kwargs)
            if not return_loader:
                self._apply_all_hooks()
            self.project.loader.main_object = self.project.loader.elfcore_object._main_object
            return self.project if not return_loader else self.project.loader

        if return_loader:
            return cle.Loader(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **cle_args)
        self.project = angr.Project(
            the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **project_kwargs
        )

        self._apply_all_hooks()

        if return_loader:
            return self.project.loader
        return self.project

    def _apply_all_hooks(self):
        if self.static_simproc:
            self._apply_simprocedures()

        for location, hook in self.custom_hooks.items():
            if type(location) is str:
                self.project.hook_symbol(location, hook)
                l.debug("Hooking symbol %s -> %s...", location, hook.display_name)
            else:
                self.project.hook(location, hook)
                l.debug("Hooking %s -> %s...", location, hook.display_name)

        if self.custom_syscalls:
            assert isinstance(self.project.simos, SimUserland)

            for name, sys_sim in self.custom_syscalls.items():
                l.debug("Hooking system call %s with %s", name, sys_sim)
                self.project.simos.syscall_library.procedures[name] = sys_sim

    def _apply_simprocedures(self):
        """
        Apply SimProcedures to functions inside the main binary.

        :return: None
        """

        # all SimProcedures indexed by name, assuming no name conflicts exist
        simprocs = {}
        for _, simproc_dict in angr.SIM_PROCEDURES.items():
            for name, simproc in simproc_dict.items():
                simprocs[name] = simproc

        for sym in self.project.loader.main_object.symbols:
            if sym.type == cle.SymbolType.TYPE_FUNCTION and sym.name in simprocs:
                l.debug("Hooking symbol %s in binary %s.", sym.name, self.project.filename)
                self.project.hook_symbol(sym.name, simprocs[sym.name]())
