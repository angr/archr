from abc import ABC
from abc import abstractmethod

class Autom(ABC):
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
        For restoring saved Automs, use load() isntead.
        :param args:
        :param kwargs:
        """
        pass

    @abstractmethod
    def build(self, *args, **kwargs):
        """
        Some automs require a "build" step.  For example, Vagrant/Docker/Ansible will need to run for some targets
        This step should begin with the metadata passed to the constructor, and produce a state ready for run()
        :return:
        """
        pass

    @abstractmethod
    def run(self):
        """
        Run the autom.
        Self-explanatory

        If this method does not except, one should be able to call interact()
        :return:
        """
        pass

    @abstractmethod
    def get_logs(self):
        pass

    @abstractmethod
    def interact(self, *args, **kwargs):
        """
        Return a means of interacting with the binary.
        This could be:
        - A IP/port number
        - A socket
        - A URL
        ....

        :param args:
        :param kwargs:
        :return:
        """
        pass

    @staticmethod
    @abstractmethod
    def load(*args, **kwargs):
        """
        Given a serialized version of an autom, create a loaded version of the autom, ready to call run()

        :param args:
        :param kwargs:
        :return:
        """
        pass

    def save(self, *args, **kwargs):
        """
        Store the current state of the autom, such that it can be passed later to load() to produce a runnable result.
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def interact(self):
        # TODO
        pass
