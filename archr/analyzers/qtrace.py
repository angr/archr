import contextlib
import logging
import os

import qtrace

l = logging.getLogger("archr.analyzers.qtrace")


class QtraceAnalyzer(ContextAnalyzer):
    """
    Launches a process under qtrace
    """

    REQUIRED_IMPLANT = "qtrace"

    @contextlib.contextmanager
    def fire_context(
        self, trace_args=None, args_prefix=None, **kwargs
    ):  # pylint:disable=arguments-differ
        """
        Starts qtrace with a fresh process.

        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        fire_path = os.path.join(self.target.tmpwd, "qtrace", "fire")
        args_prefix = (args_prefix or []) + [fire_path] + (trace_args or []) + ["--"]
        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight
        try:
            flight.result = flight.process.stderr.read()  # illegal, technically
        except ValueError:
            flight.result = b""
