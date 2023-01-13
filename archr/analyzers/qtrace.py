import os
import socket
import time
import contextlib
import logging

import qtrace

from . import Analyzer

l = logging.getLogger("archr.analyzers.qtrace")


class QTraceAnalyzer(Analyzer):
    REQUIRED_IMPLANT = "qtrace"

    def fire(self, machine_type=None, **kwargs):
        if machine_type is None:
            machine_type = qtrace.TraceMachine

        fire_path = os.path.join(self.target.tmpwd, "qtrace", "fire")
        args_prefix = [fire_path, "--"]

        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            process = flight.process
            argv = self.target.target_args

            def start(machine):
                host = self.target.ipv4_address
                machine.trace_socket = qtrace.create_connection((host, 4242), sleep_time=0.1)
                machine.gdb = machine.gdb_client((host, 1234), machine)
                machine.std_streams = (
                    process.stdin,
                    process.stdout,
                    process.stderr,
                )

            machine = machine_type(argv)

            machine.start = start.__get__(machine)

            machine.run()

            return machine
