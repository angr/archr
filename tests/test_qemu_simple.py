import unittest
import socket
import archr
import time
import os
import pathlib

from common import qemu_test_path

# class TestQEMUSystemTargetSimple(unittest.TestCase):
#     def test_pwncollege_minimal(self):
#         with archr.targets.QEMUSystemTarget(
#             qemu_test_path("pwnkernel-bzImage"), initrd_path=qemu_test_path("pwnkernel-initramfs.cpio.gz"),
#             target_path="/hello", target_args=["/hello"]
#         ).start() as q:
#             assert q._share_mounted
#             assert b"root" in q.retrieve_contents("/etc/passwd")
#             q.inject_contents({"/root/foo": b"ARCHR_TEST_A"})
#             assert b"ARCHR_TEST_A" in q.retrieve_contents("/root/foo")
#             assert q.run_command("echo hey".split()).stdout.read(3) == b"hey"
#             assert q.run_command("echo hi".split()).stdout.read(2) == b"hi"
#             assert q.run_command().communicate()[0] == b"HELLO PWN COLLEGE!\n"

# class TestQEMUSystemTargetSimple(unittest.TestCase):
#     def test_pwncollege_minimal(self):
#         with archr.targets.QEMUSystemTarget(
#             qemu_test_path("pwnkernel-bzImage"), initrd_path=qemu_test_path("pwnkernel-initramfs.cpio.gz"),
#             target_path="/hello", target_args=["/hello"]
#         ).start() as q:
#             assert q._share_mounted
#             assert b"root" in q.retrieve_contents("/etc/passwd")
#             q.inject_contents({"/root/foo": b"ARCHR_TEST_A"})
#             assert b"ARCHR_TEST_A" in q.retrieve_contents("/root/foo")
#             assert q.run_command("echo hey".split()).stdout.read(3) == b"hey"
#             assert q.run_command("echo hi".split()).stdout.read(2) == b"hi"
#             assert q.run_command().communicate()[0] == b"HELLO PWN COLLEGE!\n"

# if __name__ == '__main__':
#     unittest.main()


qemu_base = pathlib.Path(__file__).absolute()
qemu_base = qemu_base.parent.parent.parent.absolute()
qemu_base = qemu_base / 'qtrace'

qemu_plugin_str = [f"-plugin", f"file={qemu_base / 'qemu_system_plugin' / 'libqtrace.so'}"]

qemu_base = qemu_base / 'qemu' / 'build' / 'arm-softmmu'
qemu_base = str(qemu_base) + '/qemu-system-'

from IPython import embed

with archr.targets.QEMUSystemTarget(
    qemu_test_path('images/zImage'),
    disk_path=qemu_test_path('images/rootfs.qcow2') + ',if=sd,cache=writeback',
    qemu_base=qemu_base,
    arch='arm', machine='vexpress-a9',
    dtb=qemu_test_path('images/vexpress-v2p-ca9.dtb'),
    kargs='root=/dev/mmcblk0 console=ttyAMA0,115200',
    plugins=qemu_plugin_str,
    forwarded_ports=[8080],
    target_path="crashing-http-server", target_args=["/root/crashing-http-server", "-p", "8080"],
    login_user=b'root'
    ).start() as t:
        # assert q.run_command("echo hey".split()).stdout.read(3) == b"hey"
        b = archr.targets.QEMUSystemTracerAnalyzer(t)
        r = b.fire(save_core=True)
        print(r.trace)
        embed()