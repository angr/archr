import logging

l = logging.getLogger("archr.arsenal.datascout")

from . import Bow

class DataScoutBow(Bow):
    """
    Grabs the environment and auxiliary vector from the target.
    """

    def _encode_bytes(self, s):
        if self.target.target_arch == 'x86_64':
            encoded_name = [ "0" ] + [ s[i:i+8].ljust(8, "\0")[::-1].encode('utf-8').hex() for i in range(0, len(s), 8) ][::-1]
            return "".join("mov rax, 0x%s; push rax; " % word for word in encoded_name)
        elif self.target.target_arch == 'i386':
            encoded_name = [ "0" ] + [ s[i:i+4].ljust(4, "\0")[::-1].encode('utf-8').hex() for i in range(0, len(s), 4) ][::-1]
            return "".join("mov eax, 0x%s; push eax; " % word for word in encoded_name)
        else:
            raise NotImplementedError()

    def sendfile_shellcode(self, filename):
        if self.target.target_arch == 'x86_64':
            return (
                self._encode_bytes(filename) +
                "mov rdi, rsp; xor rsi, rsi; mov rax, 2; syscall;" + # n = open(path, O_RDONLY)
                "mov rdi, 1; mov rsi, rax; mov rdx, 0; mov r10, 0x1000000; mov rax, 40; syscall;" + # sendfile(1, n, 0, 0x1000000)
                "mov rax, 40; syscall;" * 5 # sendfile(1, n, 0, 0x1000000)
            )
        elif self.target.target_arch == 'i386':
            return (
                self._encode_bytes(filename) +
                "mov ebx, esp; xor ecx, ecx; mov eax, 5; int 0x80;" + # n = open(path, O_RDONLY)
                "mov ebx, 1; mov ecx, eax; mov edx, 0; mov esi, 0x1000000; mov eax, 187; int 0x80;" + # sendfile(1, n, 0, 0x1000000)
                "mov eax, 187; int 0x80;" * 5 # sendfile(1, n, 0, 0x1000000)
            )
        else:
            raise NotImplementedError()

    def echo_shellcode(self, what):
        if self.target.target_arch == 'x86_64':
            return (
                self._encode_bytes(what) +
                "mov rdi, 1; mov rsi, rsp; mov rdx, %d; mov rax, 1; syscall;" % len(what) # n = write(1, rsp, 0x1000)
            )
        elif self.target.target_arch == 'i386':
            return (
                self._encode_bytes(what) +
                "mov ebx, 1; mov ecx, esp; mov edx, %d; mov eax, 4; int 0x80;" % len(what) # n = write(1, rsp, 0x1000)
            )
        else:
            raise NotImplementedError()

    def brk_shellcode(self):
        if self.target.target_arch == 'x86_64':
            return "mov rax, 12; xor rdi, rdi; syscall; mov rdi, rax; add rdi, 0x1000; mov rax, 12; syscall;"
        elif self.target.target_arch == 'i386':
            return "mov eax, 45; xor ebx, ebx; int 0x80; mov ebx, eax; add ebx, 0x1000; mov eax, 45; int 0x80;"
        else:
            raise NotImplementedError()

    def exit_shellcode(self, exit_code=42):
        if self.target.target_arch == 'x86_64':
                return "mov rdi, %d; mov rax, 60; syscall;" % exit_code # exit(42)
        elif self.target.target_arch == 'i386':
                return "mov ebx, %d; mov eax, 1; int 0x80;" % exit_code # exit(42)
        else:
            raise NotImplementedError()

    def __init__(self, target):
        super().__init__(target)
        self.env = None
        self.argv = None
        self.auxv = None
        self.map = None

    def fire(self, aslr=False, **kwargs): #pylint:disable=arguments-differ
        if not self.argv:
            with self.target.shellcode_context(asm_code=self.sendfile_shellcode("/proc/self/cmdline") + self.exit_shellcode(), aslr=aslr, **kwargs) as p:
                arg_str,_ = p.communicate()
                self.argv = arg_str.split(b'\0')[:-1]

        if not self.env:
            with self.target.shellcode_context(asm_code=self.sendfile_shellcode("/proc/self/environ") + self.exit_shellcode(), aslr=aslr, **kwargs) as p:
                env_str,_ = p.communicate()
                self.env = env_str.split(b'\0')[:-1]

        if not self.auxv:
            with self.target.shellcode_context(asm_code=self.sendfile_shellcode("/proc/self/auxv") + self.exit_shellcode(), aslr=aslr, **kwargs) as p:
                aux_str,_ = p.communicate()
                self.auxv = aux_str

        if not self.map:
            with self.target.shellcode_context(asm_code=self.brk_shellcode() + self.sendfile_shellcode("/proc/self/maps") + self.exit_shellcode(), aslr=aslr, **kwargs) as p:
                map_str,_ = p.communicate()
                self.map = parse_proc_maps(map_str)

        return self.argv, self.env, self.auxv, self.map

from ..utils import parse_proc_maps
