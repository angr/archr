import logging

l = logging.getLogger("archr.bows.memory_map")

from . import Bow

class MemoryMapBow(Bow):
    """
    Gets a memory map of the target.
    """

    def fire(self): #pylint:disable=arguments-differ
        mem_map_str,_ = self.target.run_command([ "ldd", self.target.target_path ], aslr=False).communicate()
        return parse_ldd(mem_map_str)

from ..utils import parse_ldd
