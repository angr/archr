import subprocess
import tempfile
import logging
import random
import shutil
import nclib
import os

l = logging.getLogger("archr.target.qemu_system_target")

from . import Target
class QEMUSystemTarget(Target):
    """
    Describes a target in the form of a QEMU system image.
    """

    SUPPORTS_RETURNCODES = False

    def __init__(
        self, kernel_path, initrd_path=None, disk_path=None,
        qemu_base="/usr/bin/qemu-system-",
        forwarded_ports=(), forwarded_base=0,
        login_user=None, login_pass=None,
        guest_ip="192.168.0.1",
        **kwargs
    ):
        super().__init__(**kwargs)

        self.target_arch = self.target_arch or self._determine_arch()
        self.qemu_base = qemu_base

        self.kernel_path = kernel_path
        self.initrd_path = initrd_path
        self.disk_path = disk_path
        self.login_user = login_user
        self.login_pass = login_pass

        self.forwarded_ports = { }
        self.remaining_aux_ports = list(range(20000, 20100))
        for p in forwarded_ports:
            self.forwarded_ports[p] = p+forwarded_base
        aux_base = random.randrange(0,10000)
        for i in self.remaining_aux_ports:
            self.forwarded_ports[i] = i+aux_base

        self.guest_ip = guest_ip
        self.guest_network = guest_ip.rsplit(".", 1)[0] + ".0"

        if login_user: assert type(login_user) is bytes
        if login_pass: assert type(login_pass) is bytes

        self.qemu_process = None
        self.qemu_stdio = None
        self.share_path = tempfile.mkdtemp(prefix="archr_qemu_")
        self._share_mounted = False

    #
    # Lifecycle
    #

    def _determine_arch(self):
        # TODO
        return "x86_64"

    @property
    def qemu_path(self):
        return self.qemu_base + self._determine_arch()

    @property
    def qemu_cmd(self):
        return (
            [ "/usr/bin/qemu-system-x86_64", "-nographic", "-monitor", "none", "-append", "console=ttyS0", "-kernel", self.kernel_path ]
        ) + (
            [ "-initrd", self.initrd_path ] if self.initrd_path else [ ]
        ) + (
            [ "-drive", f"file={self.disk_path}" ] if self.disk_path else [ ]
        ) + (
            [
                "-fsdev", f"local,security_model=none,id=fsdev0,path={self.share_path}",
                "-device", "virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare"
            ] if self.share_path else [ ]
        ) + (
            [ "-net", "nic", "-net", f"user,net={self.guest_network}/24," + ",".join(
                f"hostfwd=tcp:0.0.0.0:{hp}-{self.guest_ip}:{gp}" for gp,hp in self.forwarded_ports.items()
            ) ]
        )

    def build(self):
        return self

    def start(self):
        self.qemu_process = subprocess.Popen(self.qemu_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=2)#subprocess.DEVNULL)
        self.qemu_stdio = nclib.merge([self.qemu_process.stdout], sock_send=self.qemu_process.stdin)
        # my kingdom for readrepeat...
        while self.qemu_stdio.readall(timeout=5):
            pass

        # log in
        if self.login_user:
            self.qemu_stdio.sendline(self.login_user)
        if self.login_pass:
            self.qemu_stdio.sendline(self.login_pass)

        while self.qemu_stdio.readall(timeout=1):
            pass

        self.qemu_stdio.sendline(b"echo ARCHR_TEST1")
        assert b"ARCHR_TEST1" in self.qemu_stdio.readall(timeout=1)

        # minor setup
        #self.qemu_stdio.sendline(b"[ -e /dev/null ] || mknod /dev/null c 1 3")

        # mount the shared drive
        self.qemu_stdio.sendline(b"mkdir -p /archr_mnt")
        self.qemu_stdio.sendline(b"mount -t 9p -o trans=virtio,version=9p2000.L,nosuid hostshare /archr_mnt")
        with open(os.path.join(self.share_path, "archr_test"), "w") as f:
            f.write("ARCHR_TEST2")
        self.qemu_stdio.sendline(b"cat /archr_mnt/archr_test")
        if b"ARCHR_TEST2" in self.qemu_stdio.readall(timeout=1):
            self._share_mounted = True

        return self

    def restart(self):
        return self.stop().start()

    def stop(self):
        self.qemu_process.kill()
        return self

    def remove(self):
        return self

    #
    # File access
    #

    def inject_tarball(self, target_path, tarball_path=None, tarball_contents=None):
        if self._share_mounted:
            host_path = tempfile.mktemp(dir=self.share_path, suffix=".tar", prefix="inject-")
            guest_path = os.path.join("/archr_mnt", os.path.basename(host_path))
            if tarball_path:
                shutil.copy(tarball_path, host_path)
            else:
                with open(host_path, "wb") as f:
                    f.write(tarball_contents)
                self.qemu_stdio.sendline(f"tar x -f {guest_path} -C {os.path.dirname(target_path)}; echo ARCHR_DONE".encode('latin1'))
                self.qemu_stdio.readuntil(b"ARCHR_DONE") # the echo
                self.qemu_stdio.readuntil(b"ARCHR_DONE")
                self.qemu_stdio.readall(timeout=0.5)
        else:
            raise NotImplementedError("injecting tarball without p9 requires network insanity")

    def retrieve_tarball(self, target_path, dereference=False):
        if self._share_mounted:
            host_path = tempfile.mktemp(dir=self.share_path, suffix=".tar", prefix="retrieve-")
            guest_path = os.path.join("/archr_mnt", os.path.basename(host_path))
            self.qemu_stdio.sendline(f"tar c {'-h' if dereference else ''} -f {guest_path} -C {os.path.dirname(target_path)} {os.path.basename(target_path)}; echo ARCHR_DONE".encode('latin1'))
            self.qemu_stdio.readuntil(b"ARCHR_DONE") # the echo
            self.qemu_stdio.readuntil(b"ARCHR_DONE")
            self.qemu_stdio.readall(timeout=0.5)
            return open(host_path, "rb").read()
        else:
            raise NotImplementedError("retrieving tarball without p9 requires network insanity")

    def realpath(self, target_path):
        l.warning("qemu target realpath is not implemented. things may break.")
        return target_path

    def resolve_local_path(self, target_path):
        local_path = tempfile.mktemp()
        self.retrieve_into(target_path, os.path.dirname(local_path))
        return local_path


    #
    # Info access
    #

    @property
    def ipv4_address(self):
        return "127.0.0.1"

    @property
    def ipv6_address(self):
        return "::1"

    @property
    def tcp_ports(self):
        return self.forwarded_ports

    @property
    def udp_ports(self):
        return self.forwarded_ports

    @property
    def tmpwd(self):
        return "/tmp"

    def get_proc_pid(self, proc):
        # TODO
        pass

    #
    # Execution
    #

    def get_aux_port(self):
        return self.remaining_aux_ports.pop()

    def _run_command(
        self, args, env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
        **kwargs
    ): #pylint:disable=arguments-differ
        if "aslr" in kwargs:
            l.warning("QEMU system target doesn't yet support disabling ASLR (though it should be easy).")
            kwargs.pop("aslr")
        aux_port = self.get_aux_port()
        cmd = "\n"*5
        cmd += "".join(f"""{e}="{v}" """ for e,v in env.items()) if env else ""
        cmd += f"nc -v -l -p {aux_port} -e "
        cmd += " ".join(args)
        cmd += " &"
        self.qemu_stdio.sendline(cmd.encode("latin1"))
        self.qemu_stdio.readuntil(b"listening on")
        self.qemu_stdio.readuntil(str(aux_port).encode('latin1'))
        return subprocess.Popen(f"nc localhost {self.forwarded_ports[aux_port]}".split(), stdout=stdout, stderr=stderr, stdin=stdin, **kwargs)
