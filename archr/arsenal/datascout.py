import logging

l = logging.getLogger("archr.arsenal.datascout")

from . import Bow

def _encode_bytes(s):
    encoded_name = [ "0" ] + [ s[i:i+8].ljust(8, "\0")[::-1].encode('utf-8').hex() for i in range(0, len(s), 8) ][::-1]
    return "".join("mov rax, 0x%s; push rax; " % word for word in encoded_name)

def sendfile_shellcode(filename):
    return (
        _encode_bytes(filename) +
        "mov rdi, rsp; xor rsi, rsi; mov rax, 2; syscall;" + # n = open(path, O_RDONLY)
        "mov rdi, 1; mov rsi, rax; mov rdx, 0; mov r10, 0x1000000; mov rax, 40; syscall;" + # sendfile(1, n, 0, 0x1000000)
        "mov rax, 40; syscall;" * 5 + # sendfile(1, n, 0, 0x1000000)
        "mov rdi, 42; mov rax, 60; syscall;" # exit(42)
    )

def echo_shellcode(what):
    return (
        _encode_bytes(what) +
        "mov rdi, 1; mov rsi, rsp; mov rdx, %d; mov rax, 1; syscall;" % len(what) + # n = write(1, rsp, 0x1000)
        "mov rdi, 42; mov rax, 60; syscall;" # exit(42)
    )

def brk_shellcode():
    return "mov rax, 12; xor rdi, rdi; syscall; mov rdi, rax; add rdi, 0x1000; mov rax, 12; syscall;"

class DataScoutBow(Bow):
    """
    Grabs the environment and auxiliary vector from the target.
    """

    def __init__(self, target):
        super().__init__(target)
        self.env = None
        self.auxv = None
        self.map = None

    def fire(self, aslr=False): #pylint:disable=arguments-differ
        if not self.env:
            with self.target.shellcode_context(asm_code=sendfile_shellcode("/proc/self/environ"), aslr=aslr) as p:
                env_str,_ = p.communicate()
                self.env = env_str.split(b'\0')

        if not self.auxv:
            with self.target.shellcode_context(asm_code=sendfile_shellcode("/proc/self/auxv"), aslr=aslr) as p:
                aux_str,_ = p.communicate()
                self.auxv = aux_str

        if not self.map:
            with self.target.shellcode_context(asm_code=brk_shellcode() + sendfile_shellcode("/proc/self/maps"), aslr=aslr) as p:
                map_str,_ = p.communicate()
                self.map = parse_proc_maps(map_str)

        return self.env, self.auxv, self.map

from ..utils import parse_proc_maps
