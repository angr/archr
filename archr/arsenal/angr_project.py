import logging
import angr
import cle
import os

l = logging.getLogger("archr.arsenal.angr")

from . import Bow

class angrProjectBow(Bow):
    """
    Describes a target in the form of a Docker image.
    """

    def __init__(self, target, scout_bow, static_simproc=False):
        """

        :param target:          The target to work on.
        :param scout_bow:       The scout bow.
        :param static_simproc:  When enabled, angr will hook functions in the main binary with SimProcedures if
                                available. This is useful when dealing with statically linked binaries.
        :type static_simproc:   bool
        """

        super(angrProjectBow, self).__init__(target)
        self.scout_bow = scout_bow
        self.static_simproc = static_simproc
        self.target.mount_local()

        self.project = None
        self._mem_mapping = None

    def fire(self, return_loader=False, **kwargs): #pylint:disable=arguments-differ
        if self.project is None:

            the_binary = self.target.resolve_local_path(self.target.target_path)

            # preload the binary to decide if it supports setting library options or base addresses
            preloader = cle.Loader(the_binary, **kwargs)
            if preloader.main_object.os == "cgc":
                # CGC binaries do not have libraries to load
                the_libs = { }
                lib_opts = { }
                # CGC binaries cannot be rebased
                bin_opts = { }
                self._mem_mapping = { }
            else:
                _,_,_,self._mem_mapping = self.scout_bow.fire()
                the_libs = [ self.target.resolve_local_path(lib) for lib in self._mem_mapping if lib.startswith("/") ]
                lib_opts = { os.path.basename(lib) : {'base_addr' : libaddr} for lib, libaddr in self._mem_mapping.items() }
                bin_opts = { "base_addr": 0x555555554000 }

            if return_loader:
                return cle.Loader(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **kwargs)
            self.project = angr.Project(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **kwargs)

            if self.static_simproc:
                self._apply_simprocedures()

        if return_loader:
            return self.project.loader
        return self.project

    def _apply_simprocedures(self):
        """
        Apply SimProcedures to functions inside the main binary.

        :return: None
        """

        # all SimProcedures indexed by name, assuming no name conflicts exist
        simprocs = { }
        for _, simproc_dict in angr.SIM_PROCEDURES.items():
            for name, simproc in simproc_dict.items():
                simprocs[name] = simproc

        for sym in self.project.loader.main_object.symbols:
            if sym.type == cle.SymbolType.TYPE_FUNCTION and sym.name in simprocs:
                l.debug("Hooking symbol %s in binary %s.", sym.name, self.project.filename)
                self.project.hook_symbol(sym.name, simprocs[sym.name]())
