import contextlib
import tempfile
import logging
import os

l = logging.getLogger("archr.analyzers.core_analyzer")

from . import ContextAnalyzer

class CoreResults:
    local_core_path = None
    target_core_path = None

_super_core_cmd = "echo core | docker run --rm --privileged -i ubuntu tee /proc/sys/kernel/core_pattern"
class CoreAnalyzer(ContextAnalyzer):
    """
    Runs the target and retrieves a core file. Assumes a /proc/sys/kernel/core_pattern is "core".
    """

    def __init__(self, *args, **kwargs):
        with open("/proc/sys/kernel/core_pattern", 'rb') as c:
            if c.read().strip() != b"core":
                l.warning("/proc/sys/kernel/core_pattern needs to be 'core'. I am setting this system-wide.")
                os.system(_super_core_cmd)
        super().__init__(*args, **kwargs)
        if type(self.target) is not targets.DockerImageTarget:
            l.warning("When using a LocalTarget, this Analyzer will chmod 777 your CWD!!! Be careful.")

    @contextlib.contextmanager
    def fire_context(self, **kwargs): #pylint:disable=arguments-differ
        if self.target.run_command(["chmod","777",os.path.dirname(self.target.target_path)], user="root").wait() != 0:
            raise ArchrError("failed to chmod CWD. core will *not* drop")

        r = CoreResults()
        r.target_core_path = os.path.join(os.path.dirname(self.target.target_path), "core")
        r.local_core_path = tempfile.mktemp(prefix="arch_core_")
        try:
            with self.target.flight_context(result=r, **kwargs) as flight:
                yield flight
        finally:
            with open(r.local_core_path, 'wb') as c:
                c.write(self.target.retrieve_contents(r.target_core_path))

from ..errors import ArchrError
from .. import targets
