import logging

l = logging.getLogger("archr.bows.memory_map")

from . import Bow

class MemoryMapBow(Bow):
    """
    Gets a memory map of the target.
    """

    def fire(self): #pylint:disable=arguments-differ
        ldd_map_str,_ = self.target.run_command([ "ldd", self.target.target_path ], aslr=False).communicate()
        lib_addrs = parse_ldd(ldd_map_str)

        mapped_addrs,_ = self.target.run_command([ "cat", "/proc/self/maps" ], aslr=False).communicate()
        lib_addrs['stack'] = int(next(m for m in mapped_addrs.splitlines() if m.endswith(b'[stack]')).split(b'-')[0], 16)
        lib_addrs['heap'] = int(next(m for m in mapped_addrs.splitlines() if m.endswith(b'[heap]')).split(b'-')[0], 16)

        lib_addrs.update({
            v.decode('utf-8'): int(next(m for m in mapped_addrs.splitlines() if m.endswith(v)).split(b'-')[0], 16)
            for v in [ b"[vvar]", b"[vdso]", b"[vsyscall]" ]
            if v in mapped_addrs
        })

        return lib_addrs

from ..utils import parse_ldd
