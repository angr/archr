from abc import ABC
from abc import abstractmethod

class Target(ABC):
    """
    An autom defines a packetized unit of vulnerable software
    """

    @abstractmethod
    def __init__(self, *args, **kwargs):
        """
        Create an autom

        Should provide:
        - The base metadata (architecture, version, .... ..)
        - The image, if needed, or Dockerfile/Vagrant....

        Produces a state ready to run build()
        :param args:
        :param kwargs:
        """
        pass


    #
    # Lifecycle
    #

    @abstractmethod
    def build(self, *args, **kwargs):
        """
        Some automs require a "build" step.  For example, Vagrant/Docker/Ansible will need to run for some targets
        This step should begin with the metadata passed to the constructor, and produce a state ready for run()
        :return:
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start the target.
        :return:
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Start the target.
        :return:
        """
        pass

    def __enter__(self): return self.start()
    def __exit__(self, *args): return self.stop()


    #
    # Usage
    #

    @abstractmethod
    def run_command(self, *args, **kwargs):
        """
        Run a command inside the target.
        :return:
        """
        pass


    @abstractmethod
    def inject_file(self, from_path, to_path, perms=None):
        """
        Inject a file into the target.
        :return:
        """
        pass

from .docker_target import DockerImageTarget
