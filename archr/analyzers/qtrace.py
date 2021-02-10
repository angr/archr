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
            argv = []

            address = (self.target.ipv4_address, 4242)
            for _ in range(10):
                with contextlib.suppress(ConnectionRefusedError, OSError):
                    trace_socket = socket.create_connection(address)
                    break
                time.sleep(1)
            else:
                raise ConnectionRefusedError(
                    "Failed to connect to qtrace's trace socket!"
                )

            std_streams = (process.stdin, process.stdout, process.stderr)

            machine = machine_type(
                argv, trace_socket=trace_socket, std_streams=std_streams
            )
            machine.process = process  # TODO: refactor
            machine.run()

            return machine
