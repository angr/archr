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

    def __init__(self, target, scout_bow):
        super(angrProjectBow, self).__init__(target)
        self.scout_bow = scout_bow
        self.target.mount_local()

        self.project = None
        self._mem_mapping = None

    def fire(self, return_loader=False, **kwargs): #pylint:disable=arguments-differ
        if self.project is None:
            _,_,_,self._mem_mapping = self.scout_bow.fire()
            the_libs = [ self.target.resolve_local_path(lib) for lib in self._mem_mapping if lib.startswith("/") ]
            lib_opts = { os.path.basename(lib) : {'base_addr' : libaddr} for lib, libaddr in self._mem_mapping.items() }
            bin_opts = { "base_addr": 0x555555554000 }
            the_binary = self.target.resolve_local_path(self.target.target_path)

            if return_loader:
                return cle.Loader(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **kwargs)
            self.project = angr.Project(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **kwargs)
        if return_loader:
            return self.project.loader
        return self.project
