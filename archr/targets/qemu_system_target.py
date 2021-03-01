import subprocess
import tempfile
import logging
import random
import string
import shutil
import nclib
import os
import struct
from time import sleep
import re
import signal


import angr
from archr.analyzers import ContextAnalyzer
from contextlib import contextmanager
import contextlib
import os.path
import sys

gdb_path = "/data/gdb"
import os

from pwn import ELF, Core

l = logging.getLogger("archr.target.qemu_system_target")


#
# This block tracer depends on QEMU being patched and run with the associated
# plugin. See below for launch args.
#
MESSAGE_TYPE_START = 0
MESSAGE_TYPE_TRACE = 1

from threading import Thread


class BlockTracer(Thread):
    def __init__(self, remote, target):
        super().__init__()
        self.target = target
        self.remote = remote
        self.tracer = nclib.Netcat(remote)
        self.trace = []
        self.should_stop = False
        self.send_start_msg()

    def send_start_msg(self):
        e = ELF(self.target)

        entry_addr = e.symbols["_start"]

        regions = []
        for s in ["_start"]:
            addr = e.symbols[s]
            regions.append((addr, e.read(addr, 32)))

        msg = struct.pack("<QH", entry_addr, len(regions))
        for (addr, data) in regions:
            msg += struct.pack("<QH", addr, len(data)) + data

        hdr_fmt = "<HH"
        msg = (
            struct.pack(
                hdr_fmt, MESSAGE_TYPE_START, struct.calcsize(hdr_fmt) + len(msg)
            )
            + msg
        )

        self.tracer.send(msg)

    def recv_trace_msg(self):
        msg_fmt = "<HHQ"
        msg_expected_len = struct.calcsize(msg_fmt)
        data = self.tracer.recv_exactly(msg_expected_len, timeout=1)
        if len(data) == 0:
            return None
        msg_type, msg_len, addr = struct.unpack(msg_fmt, data)
        assert msg_len == msg_expected_len
        return addr

    def run(self):
        while not self.should_stop:
            addr = self.recv_trace_msg()
            if addr is None:
                continue
            # print(hex(addr))
            self.trace.append(addr)

    def stop(self):
        self.should_stop = True
        self.join()
        return self.trace


#
# FIXME: This simply spawns GDB using Popen and shoves in a script to trigger
# core dumps. This could be done better, probably using the GDB Python API. For
# now, keep it hacky and simple.
#
class GdbInteraction(Thread):
    def __init__(self, target, pid, bp_addr=None, bp_num_ignore=0):
        super().__init__()
        self.target = target
        self.pid = pid
        self.bp_addr = bp_addr
        self.bp_num_ignore = bp_num_ignore
        self.should_stop = False
        self.signal = None

        crash_id = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        self.crash_core_path = f"{target.local_workdir}/crash_{crash_id}.core"
        self.halfway_core_path = f"{target.local_workdir}/halfway_{crash_id}.core"

    def run(self):
        # target_process_name = os.path.basename(self.target.target_args[0])

        script_src = f"""set pagination off
target extended-remote 127.0.0.1:1234
attach {self.pid}
catch signal SIGSEGV
commands
generate-core-file {self.crash_core_path}
continue
end
"""
        if self.bp_addr is not None:
            script_src += f"""break *{hex(self.bp_addr)}
commands
generate-core-file {self.halfway_core_path}
delete 2
continue
end
ignore 2 {self.bp_num_ignore - 1}
"""
        script_src += "continue\n"

        self.script_fd = tempfile.NamedTemporaryFile("w")
        self.script_fd.write(script_src)
        self.script_fd.flush()

        print(script_src)

        self.process = subprocess.Popen(
            [gdb_path, "-x", self.script_fd.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        m = nclib.merge([self.process.stdout, self.process.stderr])
        while not self.should_stop:
            line = m.readline(timeout=1)
            if line:
                signal_prefix = b"Program terminated with signal "
                if signal_prefix in line:
                    assert self.signal is None
                    signal_name = line[len(signal_prefix) :].split(b",")[0].decode()
                    self.signal = signal.Signals[signal_name]
                # TODO: remove this
                with open("LOG", "a+") as f:
                    f.write(line.decode())
        self.process.kill()

    def stop(self):
        self.should_stop = True
        self.join()


class QemuTraceResult:
    # results
    returncode = None
    signal = None
    crashed = None
    timed_out = None

    # introspection
    trace = None
    crash_address = None
    base_address = None
    magic_contents = None
    core_path = None

    def tracer_technique(self, **kwargs):
        return angr.exploration_techniques.Tracer(
            self.trace, crash_addr=self.crash_address, **kwargs
        )


import urllib

# FIXME: Move to analyzers
class QEMUSystemTracerAnalyzer(ContextAnalyzer):
    def __init__(
        self,
        target,
        timeout=10,
        ld_linux=None,
        ld_preload=None,
        library_path=None,
        seed=None,
        **kwargs,
    ):
        super().__init__(target, **kwargs)
        self.timeout = timeout
        self.ld_linux = ld_linux
        self.ld_preload = ld_preload
        self.library_path = library_path
        self.seed = seed

    @contextlib.contextmanager
    def fire_context(
        self,
        record_trace=True,
        record_magic=False,
        save_core=False,
        crash_addr=None,
        trace_bb_addr=None,
        taint=None,
        **kwargs,
    ):
        local_target_path = self.target.resolve_local_path(self.target.target_path)
        remote_target_launch_cmd = self.target.target_args
        target_process_name = os.path.basename(self.target.target_args[0])

        self.tracer = BlockTracer(("127.0.0.1", 4242), local_target_path)
        self.tracer.start()
        self.gdb = None

        r = QemuTraceResult()

        try:
            # Before launching, ensure process is not running
            self.target.run_command(["killall", target_process_name]).communicate(b"\n")

            # self.target.run_command(['killall', 'gdbserver'])
            self.target.run_command(["gdbserver", "--multi", "0.0.0.0:1234"])

            with self.target.flight_context(
                remote_target_launch_cmd, timeout=self.timeout, result=r, **kwargs
            ) as flight:

                print("Waiting for service to come up")
                sleep(5)

                pid = self.target.find_process_id("gdbserver")
                if pid is None:
                    raise Exception("No gdbserver!")

                pid = self.target.find_process_id(target_process_name)
                if pid is None:
                    raise Exception("Target process failed to launch!")

                print(f"Launching GDB -- {pid}", flush=True)
                bp_addr, bp_num_ignore = crash_addr or (None, 1)
                bp_num_ignore -= 1
                self.gdb = GdbInteraction(self.target, pid, bp_addr, bp_num_ignore)
                self.gdb.start()

                yield flight

        except subprocess.TimeoutExpired:
            r.timed_out = True
            self.target.run_command(["killall", target_process_name])
        except Exception as e:
            print("Unexpected error:", sys.exc_info()[0])
            print(e)
            exit(1)
            raise
        else:
            r.timed_out = False
            # FIXME: We have no way to get this information yet
            r.returncode = 0
            # # did a crash occur?
            # if r.returncode in [ 139, -11 ]:
            #     r.crashed = True
            #     r.signal = signal.SIGSEGV
            # elif r.returncode == [ 132, -9 ]:
            #     r.crashed = True
            #     r.signal = signal.SIGILL

        self.tracer.stop()
        if self.gdb:
            self.gdb.stop()
            if self.gdb.signal == signal.SIGSEGV:
                r.crashed = True
                r.core_path = self.gdb.crash_core_path
                r.crash_address = Core(r.core_path).pc
            if bp_addr:
                assert os.path.exists(self.gdb.halfway_core_path)
                r.core_path = self.gdb.halfway_core_path  # FIXME: store separately
        trace = self.tracer.trace
        if trace_bb_addr is not None:
            # FIXME: this is insanely wrong
            trace = [trace[-1]]
            # addr, count = trace_bb_addr
            # index = [i for i, n in enumerate(trace) if n == addr][count - 1]
            # trace = trace[index:]
            # import ipdb; ipdb.set_trace()
        r.trace = trace

    def pickup_env(self):
        pass  # TODO: delete, rex wants to call this for some reason


from . import Target


class QEMUSystemTarget(Target):
    """
    Describes a target in the form of a QEMU system image.
    """

    SUPPORTS_RETURNCODES = False

    def __init__(
        self,
        kernel_path,
        initrd_path=None,
        disk_path=None,
        qemu_base="/usr/bin/qemu-system-",
        arch=None,
        machine=None,
        dtb=None,
        kargs=None,
        plugins=None,
        forwarded_ports=(),
        forwarded_base=0,
        login_user=None,
        login_pass=None,
        guest_ip="192.168.0.1",
        debug_shell=False,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.target_arch = self.target_arch or self._determine_arch()
        self.qemu_base = qemu_base

        self.kernel_path = kernel_path
        self.initrd_path = initrd_path
        self.disk_path = disk_path
        self.login_user = login_user
        self.login_pass = login_pass

        self.qemu_arch = arch or "x86_64"
        self.qemu_machine = machine
        self.qemu_dtb = dtb
        self.qemu_kargs = kargs
        self.qemu_plugins = plugins

        self.forwarded_ports = {}
        self._tcp_ports = {}
        self.remaining_aux_ports = list(range(20000, 20100))
        for i, p in enumerate(forwarded_ports):
            self._tcp_ports[i] = p + forwarded_base
            self.forwarded_ports[p] = p + forwarded_base
        aux_base = random.randrange(0, 10000)
        for i in self.remaining_aux_ports:
            self.forwarded_ports[i] = i + aux_base

        self.guest_ip = ""  # guest_ip
        self.guest_network = guest_ip.rsplit(".", 1)[0] + ".0"

        self.debug_shell = debug_shell

        if login_user:
            assert type(login_user) is bytes
        if login_pass:
            assert type(login_pass) is bytes

        self.qemu_process = None
        self.qemu_stdio = None
        self.share_path = tempfile.mkdtemp(prefix="archr_qemu_")
        self._share_mounted = False

    #
    # Lifecycle
    #

    def _determine_arch(self):
        return self.qemu_arch

    @property
    def qemu_path(self):
        return self.qemu_base + self._determine_arch()

    # cmd = f'''{qemu} \
    #     -M vexpress-a9 \
    #     -kernel {images_base}/zImage \
    #     -dtb {images_base}/vexpress-v2p-ca9.dtb \
    #     -drive file={images_base}/rootfs.qcow2,if=sd \
    #     -append "root=/dev/mmcblk0 console=ttyAMA0,115200" \
    #     -net nic -net user,hostfwd=tcp:127.0.0.1:2222-:2222,hostfwd=tcp:127.0.0.1:8080-:8080,hostfwd=tcp:127.0.0.1:1234-:1234 \
    #     -display none -nographic \
    #     -plugin file={pathlib.Path(__file__).parent.absolute() / "libqtrace.so"},{args} \
    #     -snapshot
    # '''

    @property
    def qemu_cmd(self):
        return (
            (
                [
                    self.qemu_path,
                    "-nographic",
                    "-monitor",
                    "none",
                    "-append",
                    "console=ttyS0" if self.qemu_kargs is None else self.qemu_kargs,
                    "-kernel",
                    self.kernel_path,
                ]
            )
            + (["-M", self.qemu_machine] if self.qemu_machine else [])
            + (["-dtb", self.qemu_dtb] if self.qemu_dtb else [])
            + (["-initrd", self.initrd_path] if self.initrd_path else [])
            + (["-drive", f"file={self.disk_path}"] if self.disk_path else [])
            + (
                [
                    "-fsdev",
                    f"local,security_model=none,id=fsdev0,path={self.share_path}",
                    "-device",
                    "virtio-9p-device,id=fs0,fsdev=fsdev0,mount_tag=hostshare",
                ]
                if self.share_path
                else []
            )
            + (
                # [ "-net", "nic", "-net", f"user,net={self.guest_network}/24," + ",".join(
                [
                    "-net",
                    "nic",
                    "-net",
                    f"user,"
                    + ",".join(
                        f"hostfwd=tcp:0.0.0.0:{hp}-{self.guest_ip}:{gp}"
                        for gp, hp in self.forwarded_ports.items()
                    ),
                ]
            )
            + (self.qemu_plugins if self.qemu_plugins else [])
        )

    def build(self):
        return self

    def start(self):
        print(" ".join(self.qemu_cmd))
        self.qemu_process = subprocess.Popen(
            self.qemu_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.qemu_stdio = nclib.merge(
            [self.qemu_process.stdout], sock_send=self.qemu_process.stdin
        )

        original_send = self.qemu_stdio._send

        def send(self, data):
            l.debug("[qemu_stdio] send: %s", repr(data))
            return original_send(data)

        self.qemu_stdio._send = send.__get__(self.qemu_stdio)

        original_recv = self.qemu_stdio._recv

        def recv(self, size, timeout=None):
            data = original_recv(size, timeout=timeout)
            l.debug("[qemu_stdio] recv: %s", repr(data))
            return data

        self.qemu_stdio._recv = recv.__get__(self.qemu_stdio)

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
        # self.qemu_stdio.sendline(b"[ -e /dev/null ] || mknod /dev/null c 1 3")

        # mount the shared drive
        self.qemu_stdio.sendline(b"mkdir -p /archr_mnt")
        self.qemu_stdio.sendline(
            b"mount -t 9p -o trans=virtio,version=9p2000.L,nosuid hostshare /archr_mnt"
        )
        with open(os.path.join(self.share_path, "archr_test"), "w") as f:
            f.write("ARCHR_TEST2")
        self.qemu_stdio.sendline(b"cat /archr_mnt/archr_test")
        if b"ARCHR_TEST2" in self.qemu_stdio.readall(timeout=1):
            self._share_mounted = True

        # Disable ASLR
        self.qemu_stdio.sendline(b"echo 0 > /proc/sys/kernel/randomize_va_space")

        # Given that we want a core file, assume that we want the whole thing.
        self.qemu_stdio.sendline(b"echo 0xff > /proc/$$/coredump_filter")

        if self.debug_shell:
            aux_port = self.get_aux_port()
            cmd = "\n" * 5
            cmd += f"nc -v -v -l -p {aux_port} -e /bin/sh &\n\n"
            self.qemu_stdio.sendline(cmd.encode("latin1"))
            self.qemu_stdio.readuntil(b"istening on")
            self.qemu_stdio.readuntil(str(aux_port).encode("latin1"))
            print(f"Listening on {self.forwarded_ports[aux_port]}", flush=True)
            self.qemu_stdio.readuntil("Connection from")

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
            host_path = tempfile.mktemp(
                dir=self.share_path, suffix=".tar", prefix="inject-"
            )
            guest_path = os.path.join("/archr_mnt", os.path.basename(host_path))
            if tarball_path:
                shutil.copy(tarball_path, host_path)
            else:
                with open(host_path, "wb") as f:
                    f.write(tarball_contents)
                self.qemu_stdio.sendline(
                    f"tar x -f {guest_path} -C {os.path.dirname(target_path)}; echo ARCHR_DONE".encode(
                        "latin1"
                    )
                )
                # self.qemu_stdio.readuntil(b"ARCHR_DONE") # the echo
                # self.qemu_stdio.readuntil(b"ARCHR_DONE")
                for _ in range(2):
                    for b in b"ARCHR_DONE":
                        self.qemu_stdio.readuntil(bytes([b]))
                self.qemu_stdio.readall(timeout=0.5)
        else:
            raise NotImplementedError(
                "injecting tarball without p9 requires network insanity"
            )

    def retrieve_tarball(self, target_path, dereference=False):
        if self._share_mounted:
            host_path = tempfile.mktemp(
                dir=self.share_path, suffix=".tar", prefix="retrieve-"
            )
            guest_path = os.path.join("/archr_mnt", os.path.basename(host_path))
            self.qemu_stdio.sendline(
                f"tar c {'-h' if dereference else ''} -f {guest_path} -C {os.path.dirname(target_path)} {os.path.basename(target_path)}; echo ARCHR_DONE".encode(
                    "latin1"
                )
            )
            # self.qemu_stdio.readuntil(b"ARCHR_DONE") # the echo
            # self.qemu_stdio.readuntil(b"ARCHR_DONE")
            for _ in range(2):
                for b in b"ARCHR_DONE":
                    self.qemu_stdio.readuntil(bytes([b]))
            self.qemu_stdio.readall(timeout=0.5)
            return open(host_path, "rb").read()
        else:
            raise NotImplementedError(
                "retrieving tarball without p9 requires network insanity"
            )

    def realpath(self, target_path):
        l.warning("qemu target realpath is not implemented. things may break.")
        return target_path

    def resolve_local_path(self, target_path):
        local_path = (
            self.local_workdir + "/" + target_path
        )  # os.path.join fucks up with absolute paths
        if not os.path.exists(local_path):
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
        return {**self.forwarded_ports, **self._tcp_ports}

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
        self,
        args,
        env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        **kwargs,
    ):  # pylint:disable=arguments-differ
        if "aslr" in kwargs:
            l.warning(
                "QEMU system target doesn't yet support disabling ASLR (though it should be easy)."
            )
            kwargs.pop("aslr")
        aux_port = self.get_aux_port()
        cmd = "\n" * 5
        cmd += f"nc -v -v -l -p {aux_port} -e /bin/sh &\n\n"
        self.qemu_stdio.sendline(cmd.encode("latin1"))
        self.qemu_stdio.readuntil(b"istening on")
        self.qemu_stdio.readuntil(str(aux_port).encode("latin1"))
        p = subprocess.Popen(
            f"nc localhost {self.forwarded_ports[aux_port]}".split(),
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            **kwargs,
        )
        import shlex

        if args != self.target_args:
            env = env.copy()
            env.pop("LD_PRELOAD", None)  # LD_PRELOAD is a nightmare

        cmd = "".join(f"{k}='{v}' " for k, v in env.items()) if env else ""
        cmd += " ".join(f"{a}" for a in args)
        inj = "exec /bin/sh -c " + shlex.quote(cmd) + "\n"
        print("sending:" + inj)
        p.stdin.write(inj.encode("latin1"))
        p.stdin.flush()  # IMPORTANT
        return p

    def find_process_id(self, process_name):
        p = self.run_command(["ps", "|", "grep", process_name])
        output, _ = p.communicate()
        for l in output.decode("utf8").splitlines():
            m = re.findall(r"\s*(\d+)\s*(\w+)\s*(.+)", l)
            if len(m) == 0:
                continue
            p, u, c = m[0]
            if re.findall("grep", c):
                continue
            return int(p)
        return None
