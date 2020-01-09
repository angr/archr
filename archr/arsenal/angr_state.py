import os
import angr
import logging

l = logging.getLogger("archr.arsenal.angr_state")

from . import Bow

class SimArchrMount(angr.state_plugins.filesystem.SimConcreteFilesystem):
    def __init__(self, target=None, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.target = self.target
        return o

    def _load_file(self, guest_path):
        content = self.target.retrieve_contents(guest_path)
        return angr.SimFile(name='file://' + guest_path, content=content, size=len(content))

class angrStateBow(Bow):
    """
    Constructs an angr state (full init variety) to match the target precisely
    """

    def __init__(self, target, project_bow):
        super(angrStateBow, self).__init__(target)
        self.project_bow = project_bow

    def fire(self, **kwargs): #pylint:disable=arguments-differ
        project = self.project_bow.fire()
        if 'cwd' not in kwargs:
            cwd = os.path.dirname(self.project_bow.target.target_path)
            kwargs['cwd'] = bytes(cwd, 'utf-8')

        s = project.factory.full_init_state(
            concrete_fs=True, chroot="/ARCHR-INVALID",
            stack_end=self.project_bow._mem_mapping.get('[stack-end]', None), args=self.target.main_binary_args,
            env=self.target.target_env,
            brk=self.project_bow._mem_mapping.get('[heap]', None),
            **kwargs
        )
        s.fs.mount("/", SimArchrMount(self.target))
        return s
