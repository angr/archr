import subprocess
import struct
import re
import logging
import cle
import io

from . import strace_parser

l = logging.getLogger("archr.utils")


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

def filter_strace_output(lines):
    """
    a function to filter QEMU logs returning only the strace entries

    Parameters
    ----------
    lines : list
        a list of strings representing the lines from a QEMU log/trace.

    Returns
    -------
    list
        a list of strings representing only the strace log entries
        the entries will also be cleaned up if a page dump occurs in the middle of them
    """

    #we only want the strace lines, so remove/ignore lines that start with the following:
    line_starts= ['^[\d,a-f]{16}-', # pylint: disable=anomalous-backslash-in-string
                      '^page',
                      '^start',
                      '^host',
                      '^Locating',
                      '^guest_base',
                      '^end_',
                      '^brk',
                      '^entry',
                      '^argv_',
                      '^env_',
                      '^auxv_',
                      '^Trace',
                      '^--- SIGSEGV',
                      '^qemu'
                      ]
    filter_string = '|'.join(line_starts)

    filtered = []
    prev_line = ""
    for line in lines:
        if re.match(filter_string,line):
            continue
        # workaround for https://gitlab.com/qemu-project/qemu/-/issues/654
        if re.search("page layout changed following target_mmap",line):
            prev_line = line.replace("page layout changed following target_mmap","")
            continue
        if re.match('^ = |^= ', line):
            line = prev_line+line

        filtered.append(line)
    return filtered


def get_file_maps(strace_log_lines):
    """
    a function to return a mapping of filenames and associated mmaped addressed for process under QEMU
    this is accomplished by tracking the filenames through file-desciptors across mmap() calls.

    Parameters
    ----------
    strace_log_lines : list
        a list of strings representing only the strace info logged by QEMU

    Returns
    -------
    dict
        a dictionary of filenames and mmapped addresses associated with each file

    """
    files = {
        'open':{},
        'closed':{}
    }

    entries = strace_parser.parse(strace_log_lines)
    entries = [entry for entry in entries if entry.syscall in ('openat','mmap','mmap2','close')]

    for entry in entries:
        # for an openat, create a dict entry for the file descriptor
        # the entry should be a tuple of the filename, and mmaps (initially empty)
        if entry.syscall == 'openat':
            fd = entry.syscall.result
            # only care about file descriptors other than STDIN,STDOUT,STDERR
            # also ignore errors
            if fd >= 3:
                #use only the base filename
                filename = entry.syscall.args[1].split("/")[-1]
                #tracking if an executable page was ever mapped from the file descriptor
                files['open'][fd] = [filename,[]]

        # if a file descriptor is closed, we need to remove it from the open files dictionary
        # we want to track the mmaps, so move it to 'closed' by file name since the file descriptor can be re-used.
        elif entry.syscall == 'close':
            fd = entry.syscall.args[0]
            # only care about file descriptors other than STDIN,STDOUT,STDERR
            if fd >= 3:
                filename = files['open'][fd][0]
                mmaps = files['open'][fd][1]

                # if we never mapped any pages, then we don't care about it.
                if mmaps:
                    # otherwise move to 'closed'
                    files['closed'][filename] = mmaps
                
                del files['open'][fd]

        # we can use the file descriptor to look up the dict entry to update the mmaps
        #TODO: track sizes which should be capturable from the mmap arguments
        elif entry.syscall in ('mmap', 'mmap2'):
            # only care about valid file descriptors
            fd = entry.syscall.args[4]
            if fd >= 3:
                files['open'][fd][1].append(entry.syscall.result)

    #lets "close" everything that never got closed
    for fd,(filename,mmaps) in files['open'].items():
        files['closed'][filename] = mmaps

    return files['closed']


def hook_addr(binary, addr, asm_code=None, bin_code=b''):
    main_bin = io.BytesIO(binary)
    loader = cle.Loader(main_bin, auto_load_libs=False, perform_relocations=False)
    offset = loader.main_object.addr_to_offset(addr)
    main_bin.seek(offset)
    main_bin.write(loader.main_object.arch.asm(asm_code) if asm_code else bin_code)
    main_bin.seek(0)
    return main_bin.read()
