import logging

l = logging.getLogger("archr.analyzers.datascout")

from ..errors import ArchrError
from . import Analyzer

# Keystone engine 0.9.2 (incorrectly) defaults to radix 16. so we'd better off only using 0x-prefixed integers from now.
# See the related PR: https://github.com/keystone-engine/keystone/pull/382
# and the related issue: https://github.com/keystone-engine/keystone/issues/436


class DataScoutAnalyzer(Analyzer):
    """
    Grabs the environment and auxiliary vector from the target.
    """

    REQUIRED_IMPLANT = "shellphish_qemu"

    def __init__(self, target, analyzer=None):
        super().__init__(target)
        self.env = None
        self.argv = None
        self.auxv = None
        self.map = None
        self.analyzer = analyzer

    def _pushstr(self, s):
        """
        push a string onto stack
        """
        def _cutstr(bits, little=True):
            w = bits // 8  # word size
            byte_order = -1 if little else 1
            n = ["0"] + [s[i:i + w].ljust(w, "\0")[::byte_order].encode('utf-8').hex() for i in range(0, len(s), w)][::-1]
            return n

        if self.target.target_arch == 'x86_64':
            elems = _cutstr(64)
            return "".join("mov rax, 0x%s; push rax; " % word for word in elems)
        elif self.target.target_arch == 'i386':
            elems = _cutstr(32)
            return "".join("mov eax, 0x%s; push eax; " % word for word in elems)
        elif self.target.target_arch in ('mips', 'mipsel'):
            elems = _cutstr(32, little=self.target.target_arch != 'mips')
            return "".join("li $t0, 0x%s; addi $sp, $sp, -4; sw $t0, 0($sp);" % word for word in elems)
        elif self.target.target_arch == 'arm':
            elems = _cutstr(32)
            return "".join(f"movw r0, #0x{word} & 0xffff; movt r0, #0x{word} >> 16; push {{r0}};" for word in elems)
        else:
            raise NotImplementedError()

    def read_file_shellcode(self, filename):
        """
        shellcode to read the content of a file
        """
        if self.target.target_arch == 'x86_64':
            return (
                self._pushstr(filename) +
                "mov rdi, rsp; xor rsi, rsi; xor rdx, rdx; mov rax, 2; syscall;" + # fd = open(path, O_RDONLY, 0)
                "mov r12, rax; sub rsp, 0x1000;" + # alloca 0x1000
                "loop_head:" +
                "xor rax, rax; mov rdi, r12; mov rsi, rsp; mov rdx, 0x1000; syscall;" + # n = read(fd, rsp, 0x1000)
                "mov r13, rax;" + # save n
                "mov rax, 1; mov rdi, 1; mov rsi, rsp; mov rdx, r13; syscall;" + # write(1, rsp, n)
                "test r13, r13; jnz loop_head;" # loop untill we are done with the file
            )
        elif self.target.target_arch == 'i386':
            return (
                self._pushstr(filename) +
                "mov ebx, esp; xor ecx, ecx; xor edx, edx; mov eax, 5; int 0x80;" + # n = open(path, O_RDONLY, 0)
                "mov esi, eax; sub esp, 0x1000;" + # alloca 0x1000, fd = esi
                "loop_head:" +
                "mov eax, 3; mov ebx, esi; mov ecx, esp; mov edx, 0x1000; int 0x80;" + # n = read(fd, rsp, 0x1000)
                "mov edi, eax;"+ # save n
                "mov eax, 4; mov ebx, 1; mov ecx, esp; mov edx, edi; int 0x80;" + # write(1, rsp, n)
                "test edi, edi; jnz loop_head;" # loop untill we are done with the file
            )
        elif self.target.target_arch in ('mips', 'mipsel'):
            return (
                self._pushstr(filename) +
                "move $a0, $sp; xor $a1, $a1, $a1; xor $a2, $a2, $a2; li $v0, 0xfa5; syscall;" +  # n = open(path, O_RDONLY, 0)
                "move $s0, $v0; li $a0, 0x1000; sub $sp, $sp, $a0;" + # alloca 0x1000, fd = $s0
                "loop_head:" +
                "li $v0, 0xfa3; move $a0, $s0; move $a1, $sp; li $a2, 0x1000; syscall;" + # n = read(fd, rsp, 0x1000)
                "move $s1, $v0;" + # save n
                "li $v0, 0xfa4; li $a0, 1; move $a1, $sp; move $a2, $s1; syscall;" + # write(1, rsp, n)
                "bne $s1, 0, loop_head;" # loop untill we are done with the file
            )
        elif self.target.target_arch == 'arm':
            return (
                self._pushstr(filename) +
                "mov r0, sp; eor r1, r1; eor r2, r2; mov r7, #5; svc 0;" +  # n = open(path, O_RDONLY, 0)
                "mov r8, r0; sub sp, sp, 0x1000;" + # alloca 0x1000, fd = $r8
                "loop_head:" +
                "mov r7, #3; mov r0, r8; mov r1, sp; mov r2, 0x1000; svc 0;" + # n = read(fd, rsp, 0x1000)
                "mov r9, r0;" + # save n to r9
                "mov r7, #4; mov r0, 1; mov r1, sp; mov r2, r9; svc 0;" + # write(1, rsp, n)
                "cmp r9, #0; bne loop_head;" # loop untill we are done with the file
            )
        else:
            raise NotImplementedError("Unknown target architecure: \"%s\"!" % self.target.target_arch)

    def echo_shellcode(self, what):
        if self.target.target_arch == 'x86_64':
            return (
                self._pushstr(what) +
                "mov rdi, 1; mov rsi, rsp; mov rdx, %#x; mov rax, 1; syscall;" % len(what) # n = write(1, rsp, 0x1000)
            )
        elif self.target.target_arch == 'i386':
            return (
                self._pushstr(what) +
                "mov ebx, 1; mov ecx, esp; mov edx, %#x; mov eax, 4; int 0x80;" % len(what) # n = write(1, esp, 0x1000)
            )
        elif self.target.target_arch in ('mips', 'mipsel'):
            return (
                self._pushstr(what) +
                "li $a0, 1; move $a1, $sp; li $a2, %#x; li $v0, 0xfa4; syscall;" % len(what)  # n = write(1, sp, 0x1000)
            )
        elif self.target.target_arch == 'arm':
            return (
                self._pushstr(what) +
                "mov r0, #1; mov r1, sp; mov r2, #%#x; mov r7, #4; svc 0;" % len(what)  # n = write(1, sp, 0x1000)
            )
        else:
            raise NotImplementedError()

    def brk_shellcode(self):
        if self.target.target_arch == 'x86_64':
            return "mov rax, 0xc; xor rdi, rdi; syscall; mov rdi, rax; add rdi, 0x1000; mov rax, 0xc; syscall;"
        elif self.target.target_arch == 'i386':
            # n = brk 0
            # brk n + 0x1000
            return "mov eax, 0x2d; xor ebx, ebx; int 0x80; mov ebx, eax; add ebx, 0x1000; mov eax, 0x2d; int 0x80;"
        elif self.target.target_arch in ('mips', 'mipsel'):
            # n = brk 0
            # brk n + 0x1000
            return "xor $a0, $a0, $a0; li $v0, 0xfcd; syscall; add $a0, $v0, 0x1000; li $v0, 0xfcd; syscall;"
        elif self.target.target_arch == 'arm':
            # n = brk 0
            # brk n + 0x1000
            return "eor r0, r0; mov r7, #0x2d; svc 0; add r0, #0x1000; mov r7, #0x2d; svc 0;"
        else:
            raise NotImplementedError()

    def exit_shellcode(self, exit_code=42):
        if self.target.target_arch == 'x86_64':
            return "mov rdi, %#x; mov rax, 0x3c; syscall;" % exit_code # exit(code)
        elif self.target.target_arch == 'i386':
            return "mov ebx, %#x; mov eax, 1; int 0x80;" % exit_code # exit(code)
        elif self.target.target_arch in ('mips', 'mipsel'):
            return "li $a0, %#x; li $v0, 0xfa1; syscall;" % exit_code  # exit(code)
        elif self.target.target_arch == 'arm':
            return "mov r0, #%#x; mov r7, #1; svc 0;" % exit_code  # exit(code)
        else:
            raise NotImplementedError()

    def run_shellcode(self, shellcode, aslr=False, **kwargs):
        exit_code = 42

        # build the args
        if self.analyzer:
            args = self.analyzer._build_command()
        else:
            args = self.target.target_args

        # run command within the shellcode context
        with self.target.shellcode_context(args, asm_code=shellcode+self.exit_shellcode(exit_code=exit_code), aslr=aslr, **kwargs) as p:
            output, stderr = p.communicate()
            if p.returncode != exit_code:
                raise ArchrError("DataScout failed to get info from the target process.\n"
                                 "stdout: %s\nstderr: %s" % (output, stderr))

        return output

    def fire(self, aslr=False, **kwargs): #pylint:disable=arguments-differ
        if self.target.target_os == 'cgc':
            return [], [], b'', {}


        if not self.argv:
            output = self.run_shellcode(self.read_file_shellcode("/proc/self/cmdline"), aslr=aslr, **kwargs)
            self.argv = output.split(b'\0')[:-1]

        if not self.env:
            output = self.run_shellcode(self.read_file_shellcode("/proc/self/environ"), aslr=aslr, **kwargs)
            self.env = output.split(b'\0')[:-1]

        if not self.auxv:
            output = self.run_shellcode(self.read_file_shellcode("/proc/self/auxv"), aslr=aslr, **kwargs)
            self.auxv = output

        if not self.map:
            output = self.run_shellcode(self.brk_shellcode()+self.read_file_shellcode("/proc/self/maps"), aslr=aslr, **kwargs)
            self.map = parse_proc_maps(output)

        return self.argv, self.env, self.auxv, self.map

from ..utils import parse_proc_maps
