import os
import socket
#from typing import ContextManager


class Flight:
    """
    A flight is the result of firing a bow at a given target, connecting to a running process.
    Yes, the metaphor is getting stretched a little thin.
    The process may be remote (i.e. was not launched by us), in which case the actual process attribute is None.

    A Flight is generally the result of ContextBow.fire_context.
    It has a result field, which is normally returned from ContexBow.fire.
    """
    def __init__(self, target, process, result=None):
        self.target = target
        self.process = process
        self._channels = {}
        self.result = result

    def get_channel(self, channel_name):
        # TODO: this doesn't quite work bc we will want to open multiple connections to tcp:0 for example
        # how to represent this...?
        channel = self._channels.get(channel_name, None)
        if channel is not None:
            return channel
        channel = self.open_channel(channel_name)
        self._channels[channel_name] = channel
        return channel

    def open_channel(self, channel_name):
        if ':' not in channel_name:
            if self.process is None:
                raise ValueError("Can't get stdio for remote process")
            if channel_name == 'stdin':
                return self.process.stdin
            elif channel_name == 'stdout':
                return self.process.stdout
            elif channel_name == 'stderr':
                return self.process.stderr
            else:
                raise ValueError("Bad channel", channel_name)
        else:
            kind, idx = channel_name.split(':', 1)
            if kind == 'tcp':
                mapping = self.target.tcp_ports
                sock_type = socket.SOCK_STREAM
            elif kind == 'udp':
                mapping = self.target.udp_ports
                sock_type = socket.SOCK_DGRAM
            else:
                raise ValueError("Bad channel", kind)

            try:
                port = mapping[int(idx)]
            except ValueError as e:
                raise ValueError("Channel number is not a number", channel_name) from e
            except LookupError as e:
                raise ValueError("No mapping for channel number", kind, idx) from e

            # TODO switch between ipv4 and ipv6 here
            sock = socket.socket(family=socket.AF_INET, type=sock_type)
            sock.connect((self.target.ipv4_address, port))
            return sock


    @property
    def default_input(self):
        if self.target.tcp_ports:
            channel = 'tcp:0'
        elif self.target.udp_ports:
            channel = 'udp:0'
        elif self.process:
            channel = 'stdin'
        else:
            raise ValueError("Target has no channels defined")

        return self.get_channel(channel)

    @property
    def default_output(self):
        if self.target.tcp_ports:
            channel = 'tcp:0'
        elif self.target.udp_ports:
            channel = 'udp:0'
        elif self.process:
            channel = 'stdout'
        else:
            raise ValueError("Target has no channels defined")

        return self.get_channel(channel)


class Bow:
    REQUIRED_ARROW = None
    REQUIRED_BINARY = None

    def __init__(self, target):
        """
        Initializes the bow.
        :param Target target: the target to work on
        """
        self.target = target
        self.nock()

    def nock(self):
        """
        Prepare the arrow (inject it into the target).
        """
        if self.REQUIRED_ARROW:
            with arrows.bundle(self.REQUIRED_ARROW) as b:
                self.target.inject_path(b, "/tmp/%s" % self.REQUIRED_ARROW)
        if self.REQUIRED_BINARY:
            with arrows.bundle_binary(self.REQUIRED_BINARY) as b:
                self.target.inject_path(b, "/tmp/%s" % os.path.basename(self.REQUIRED_BINARY))

    def fire(self, *args, **kwargs):
        """
        Fire the bow at the target.
        """
        raise NotImplementedError()

class ContextBow(Bow):
    """
    A Bow base class for bows that implement a fire_context instead of a fire.
    Provides a default .fire() that replays a testcase (an Arrowhead).
    """

    def fire(self, *args, testcase=None, **kwargs): #pylint:disable=arguments-differ
        with self.fire_context(*args, **kwargs) as flight:
            if testcase is not None:
                testcase.run(flight)
            flight.process.wait()
        return flight.result

    def fire_context(self, *args, **kwargs):  # -> ContextManager[Flight]:
        """
        A context manager for the bow. Should yield a Flight object.
        """
        raise NotImplementedError()



from .angr_project import angrProjectBow
from .angr_state import angrStateBow
from .qemu_tracer import QEMUTracerBow
from .datascout import DataScoutBow
from .gdbserver import GDBServerBow
from .core import CoreBow
from .ltrace import LTraceBow
from .strace import STraceBow
from .input_fd import InputFDBow
from .rr import RRTracerBow
from .. import arrows
