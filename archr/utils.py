import subprocess
import struct
import cle
import io

def parse_ldd(mem_map_str):
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

def parse_proc_maps(proc_str):
    entries = [ l.strip() for l in proc_str.splitlines() ]
    parsed = { }
    for entry in entries:
        what = entry.split()[-1].decode('utf-8')
        addr_range = entry.split()[0]
        start,end = addr_range.split(b"-")
        if what in parsed:
            continue
        if what.startswith("/"):
            parsed[what] = int(start, 16)
        elif what.startswith("["):
            parsed[what] = int(start, 16)
            parsed[what.rstrip("]")+"-end]"] = int(end, 16)
    return parsed

def lib_dependencies(filepath):
    mem_map_str,_ = subprocess.Popen([ "ldd", filepath ], stdout=subprocess.PIPE).communicate()
    return [ lib for lib in parse_ldd(mem_map_str) if lib != "linux-vdso.so.1" ]

def hook_entry(binary, asm_code=None, bin_code=None):
    main_bin = io.BytesIO(binary)
    b = cle.Loader(main_bin, auto_load_libs=False, perform_relocations=False)
    start_addr = b.main_object.addr_to_offset(b.main_object.entry)
    arch = b.main_object.arch
    if arch.name in ('ARMHF', 'ARMEL') and arch.is_thumb(start_addr): # OMG, thumb mode is a disaster
        start_addr &= (~1) # recover the real address
        main_bin.seek(start_addr)
        padding = (4 - (start_addr + 8) % 4) % 4 # we hardcode the shellcode so that its length is 8

        # we can' use arch.asm here because the shellcode THUMB, 8+padding-4 because the shellcode has length 8+padding,
        # we also need to take into account that in arm, pc points to two instructions ahead, which is 4 bytes in thumb mode
        main_bin.write(b'xF\x00\xf1' + struct.pack('<H', 8+padding-4) + b'\x00G' + b'A'*padding)

        # now place our payload after this mini shellcode
        start_addr += 8 + padding
    main_bin.seek(start_addr)
    main_bin.write(b.main_object.arch.asm(asm_code) if asm_code else bin_code)
    main_bin.seek(0)
    return main_bin.read()

def hook_addr(binary, addr, asm_code=None, bin_code=b''):
    main_bin = io.BytesIO(binary)
    loader = cle.Loader(main_bin, auto_load_libs=False, perform_relocations=False)
    offset = loader.main_object.addr_to_offset(addr)
    main_bin.seek(offset)
    main_bin.write(loader.main_object.arch.asm(asm_code) if asm_code else bin_code)
    main_bin.seek(0)
    return main_bin.read()
