import unittest
import socket
import archr
import time
import os
import pathlib
import logging

from common import qemu_test_path


qemu_base = pathlib.Path(__file__).absolute()
qemu_base = qemu_base.parent.parent.parent.absolute()
qemu_base = qemu_base / "qtrace"

qemu_plugin_str = [
    f"-plugin",
    f"file={qemu_base / 'qemu_system_plugin' / 'libqtrace.so'}",
]

qemu_base = qemu_base / "qemu" / "build" / "arm-softmmu"
qemu_base = str(qemu_base) + "/qemu-system-"

logging.getLogger("archr.target.actions").setLevel(logging.DEBUG)
logging.getLogger("archr.target.qemu_system_target").setLevel(logging.DEBUG)

with open("/data/tenda_cn_ac9_v15/new_pre_fire_input", "rb") as f:
    pre_fire_input = f.read()

with open("/data/tenda_cn_ac9_v15/crash_input", "rb") as f:
    crash_input = f.read()


with archr.targets.QEMUSystemTarget(
    qemu_test_path("images/zImage"),
    disk_path=qemu_test_path("images/rootfs.qcow2") + ",if=sd,cache=writeback",
    qemu_base=qemu_base,
    arch="arm",
    machine="vexpress-a9",
    dtb=qemu_test_path("images/vexpress-v2p-ca9.dtb"),
    kargs="root=/dev/mmcblk0 console=ttyAMA0,115200",
    plugins=qemu_plugin_str,
    forwarded_ports=[80, 1234],  # HTTP, GDB
    target_path="/bin/httpd",
    target_args=["/bin/httpd"],
    target_env={
        "LD_PRELOAD": "/lib/libnvram-faker.so:/lib/libdl.so.0:/lib/custbind.so"
    },
    login_user=b"root",
).start() as target:

    actions = [
        archr.targets.actions.WaitAction(1),
        archr.targets.actions.OpenChannelAction("tcp:80"),
        archr.targets.actions.SendAction(pre_fire_input, "tcp:80"),
        archr.targets.actions.WaitAction(10),
        archr.targets.actions.CloseChannelAction("tcp:80"),
        archr.targets.actions.WaitAction(1),
        archr.targets.actions.OpenChannelAction("tcp:80"),
        archr.targets.actions.SendAction(crash_input, "tcp:80"),
        archr.targets.actions.WaitAction(10),
    ]

    for _ in range(2):
        tracer = archr.targets.QEMUSystemTracerAnalyzer(target)
        result = tracer.fire(
            actions=actions,
            save_core=True,
            crash_addr=(0x7CD6C, 1),
        )

        print(f"Trace length: {len(result.trace)}")
        print(f"Core Path: {result.core_path}")
        print(f"Timed Out: {result.timed_out}")
        print(f"Crashed: {result.crashed}")
        print(f"Trace End: {[hex(e) for e in result.trace[-3:]]}")
