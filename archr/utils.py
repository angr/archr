import subprocess

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

def lib_dependencies(filepath):
    mem_map_str,_ = subprocess.Popen([ "ldd", filepath ], stdout=subprocess.PIPE).communicate()
    return [ lib for lib in parse_ldd(mem_map_str) if lib != "linux-vdso.so.1" ]
