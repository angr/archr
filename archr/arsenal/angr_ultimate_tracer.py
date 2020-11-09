import subprocess
from typing import TYPE_CHECKING
import logging

try:
    import angr
except ImportError:
    syscall_agent = None

try:
    import syscall_agent
except ImportError:
    syscall_agent = None


from . import Bow

if TYPE_CHECKING:
    from .angr_project import angrProjectBow


_l = logging.getLogger(__name__)


class angrUltimateTracerBow(Bow):
    """
    Construct an angr project with ultimate tracer enabled. All syscalls will be out-sourced to an external syscall
    agent.
    """
    def __init__(self, target, project_bow: 'angrProjectBow'):
        if angr is None or syscall_agent is None:
            raise ImportError("Failed to import angr or syscall_agent. Make sure angr and syscall_agent are installed.")

        super().__init__(target)
        self.project_bow: 'angrProjectBow' = project_bow

    def _invoke_syscall_agent(self, project: 'angr.Project') -> subprocess.Popen:
        """
        Invoke the expected syscall agent.
        """
        agent = syscall_agent.manager.get_agent(project.arch.name)
        if agent is None:
            raise RuntimeError("Cannot find a syscall agent for project %r (architecture %s)" % (project,
                                                                                                 project.arch.name))
        project.bureau.start()  # get it ready to receive connections
        proc = agent.launch("tcp://127.0.0.1:%d" % project.bureau.zmq_port)  # launch the agent process
        return proc

    def make_project(self):
        if self.project_bow.project is not None:
            return self.project_bow.project

        engine = angr.engines.UberEngineSyscallTracing
        if self.project_bow.project is not None:
            _l.warning("An angr project was created. Destroying it.")
            self.project_bow.project = None

        project = self.project_bow.fire(project_kwargs={
            'auto_load_libs': True,
            'engine': engine,
            'use_sim_procedures': False,
        })

        return project

    def fire(self, *args, state: 'angr.SimState'=None, **kwargs):
        project = self.make_project()
        proc = self._invoke_syscall_agent(project)

        if state is None:
            raise ValueError('"state" must be specified')

        sim_manager = project.factory.simulation_manager(state)
        results = sim_manager.explore()

        print(results.deadended[0].posix.dumps(1).decode("ascii"))

        # terminate the agent
        proc.terminate()
