import contextlib
import subprocess
import tempfile
import logging
import signal
import shutil
import glob
import time
import re
import os

from io import BytesIO

import angr

l = logging.getLogger("archr.analyzers.qemu_tracer")

from .qemu_tracer import QEMUTracerAnalyzer, QemuTraceResult, QEMUTracerError

class Core_FakeQemuTraceResult(QemuTraceResult):
    def tracer_technique(self, **kwargs):
        return angr.exploration_techniques.ExplorationTechnique(**kwargs)


class Core_FakeQEMUTracerAnalyzer(QEMUTracerAnalyzer):
    REQUIRED_IMPLANT = None

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)

    def pickup_env(self):
        return

    def fire(self, *args, **kwargs): # pylint:disable=arguments-differ
        raise NotImplementedError
        # r = Core_FakeQemuTraceResult()
        # import ipdb; ipdb.set_trace()
        #
        # r.timed_out = False
        # r.returncode = 139
        # r.crashed = True
        # r.signal = signal.SIGSEGV
        #
        # r.core_path = None
        # r.halfway_core_path = self.target.core_path
        # r.crash_address = 0x72616162
        # r.trace = []
        # return r
