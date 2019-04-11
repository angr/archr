import subprocess
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
        elif what.startswith("/"):
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
    b = cle.Loader(main_bin, auto_load_libs=False, perform_relocations=False, main_opts={'base_addr': 0})
    start_addr = b.main_object.addr_to_offset(b.main_object.entry)
    main_bin.seek(start_addr)
    main_bin.write(b.main_object.arch.asm(asm_code) if asm_code else bin_code)
    main_bin.seek(0)
    return main_bin.read()
