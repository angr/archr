import logging

l = logging.getLogger("archr.bows.memory_map")

from . import Bow

class MemoryMapBow(Bow):
    """
    Gets a memory map of the target.
    """

    def fire(self): #pylint:disable=arguments-differ
        mem_map_str,_ = self.target.run_command([ "ldd", self.target.target_path ], aslr=False).communicate()
        entries = [l.strip() for l in mem_map_str.decode('utf-8').splitlines()]
        parsed = { }
        for entry in entries:
            if '=>' in entry:
                libname, paren_addr = entry.split('=>')[1].split()
            else:
                libname, paren_addr = entry.split()
            libaddr = int(paren_addr.strip("()"), 16)
            parsed[libname] = libaddr
        return parsed
