import time
import logging
from abc import abstractmethod

import nclib

l = logging.getLogger("archr.target.actions")

class ActionError(BaseException):
    pass

class Action:
    def __init__(self):
        self.interaction = None

    @abstractmethod
    def perform(self):
        """
        Specify how to perform an action
        """
        raise NotImplementedError()

class OpenChannelAction(Action):
    def __init__(self, channel_name=None):
        super().__init__()
        self.channel_name = channel_name

    def _open_channel(self, channel_name):
        if channel_name == 'stdio':
            process = self.interaction.process
            if process is None:
                raise ValueError("Can't get stdio for remote process")
            channel = nclib.merge([process.stdout, process.stderr], sock_send=process.stdin)
        elif ':' in channel_name:
            target = self.interaction.target
            kind, idx = channel_name.split(':', 1)
            if kind in ('tcp', 'tcp6'):
                ipv6 = kind == 'tcp6'
                mapping = target.tcp_ports
                udp = False
            elif kind in ('udp', 'udp6'):
                ipv6 = kind == 'udp6'
                mapping = target.udp_ports
                udp = True
            else:
                raise ValueError("Bad channel", kind)

            address = target.ipv6_address if ipv6 else target.ipv4_address
            # if we run in network_mode=host we don't get an IP
            if not address:
                address = 'localhost'

            try:
                port = mapping[int(idx)]
            except ValueError as e:
                raise ValueError("Channel number is not a number", channel_name) from e
            except LookupError as e:
                raise ValueError("No mapping for channel number", kind, idx) from e

            channel = nclib.Netcat((address, port), udp=udp, ipv6=ipv6, retry=30)
        else:
            raise ValueError("Bad channel", channel_name)

        logger = nclib.logger.StandardLogger(nclib.simplesock.SimpleLogger('archr.log'))
        channel.add_logger(logger)
        return channel

    def perform(self):
        if not self.interaction:
            raise ActionError("No interaction context to perform %s" % self.__class__)
        if self.channel_name is None:
            self.channel_name = self.interaction.default_channel_name
        l.debug("[OpenChannelAction] openning channel: %s", self.channel_name)
        channel = self._open_channel(self.channel_name)
        self.interaction._channels[self.channel_name] = channel
        return channel

class SendAction(Action):

    def __init__(self, data, channel_name=None):
        super().__init__()
        self.channel_name = channel_name
        self.data = data

    def perform(self):
        if not self.interaction:
            raise ActionError("No interaction context to perform %s" % self.__class__)
        if self.channel_name is None:
            self.channel_name = self.interaction.default_channel_name
        l.debug("[SendAction] sending data to channel %s: %s", self.channel_name, self.data)
        channel = self.interaction.get_channel(self.channel_name)
        channel.write(self.data)

class WaitAction(Action):
    def __init__(self, seconds):
        super().__init__()
        self.seconds = seconds

    def perform(self):
        if not self.interaction:
            raise ActionError("No interaction context to perform %s" % self.__class__)
        l.debug("[WaitAction] waiting for %d seconds", self.seconds)
        time.sleep(self.seconds)

class CloseChannelAction(Action):
    def __init__(self, channel_name=None):
        super().__init__()
        self.channel_name = channel_name

    def perform(self):
        if not self.interaction:
            raise ActionError("No interaction context to perform %s" % self.__class__)
        if self.channel_name is None:
            self.channel_name = self.interaction.default_channel_name
        l.debug("[CloseChannelAction] closing channel: %s", self.channel_name)
        channel = self.interaction.get_channel(self.channel_name)
        channel.shutdown_wr()
        channel.close()
        assert channel.closed
        self.interaction._channels.pop(self.channel_name)
        # TODO: if the channel type is stdin, close the process as well.
