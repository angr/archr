import logging

l = logging.getLogger("archr.bows.memory_map")

from . import Bow

class MemoryMapBow(Bow):
    """
    Gets a memory map of the target.
    """

    def fire(self, aslr=False): #pylint:disable=arguments-differ
        ldd_map_str,_ = self.target.run_command([ "ldd", self.target.target_path ], aslr=aslr).communicate()
        lib_addrs = parse_ldd(ldd_map_str)

        mapped_addrs,_ = self.target.run_command([ "cat", "/proc/self/maps" ], aslr=aslr).communicate()
        lib_addrs['[stack-end]'] = int(next(m for m in mapped_addrs.splitlines() if m.endswith(b'[stack]')).split(b'-')[1].split(b' ')[0], 16)

        lib_addrs.update({
            v.decode('utf-8'): int(next(m for m in mapped_addrs.splitlines() if m.endswith(v)).split(b'-')[0], 16)
            for v in [ b"[heap]", b"[vvar]", b"[vdso]", b"[vsyscall]" ]
            if v in mapped_addrs
        })

        return lib_addrs

from ..utils import parse_ldd
