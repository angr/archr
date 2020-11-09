import socket
import subprocess
import time
import logging

import nclib


l = logging.getLogger("archr.target.flight")


class Flight:
    """
    A flight is a running process in a running target.
    The process may be remote (i.e. was not launched by us), in which case the actual process attribute is None.

    A Flight is generally the result of ContextAnalyzer.fire_context.
    It has a result field, which is normally returned from ContexAnalyzer.fire.
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
        if channel_name == 'stdio':
            if self.process is None:
                raise ValueError("Can't get stdio for remote process")
            channel = nclib.merge([self.process.stdout, self.process.stderr], sock_send=self.process.stdin)
        elif ':' in channel_name:
            kind, idx = channel_name.split(':', 1)
            if kind in ('tcp', 'tcp6'):
                ipv6 = kind == 'tcp6'
                mapping = self.target.tcp_ports
                udp = False
            elif kind in ('udp', 'udp6'):
                ipv6 = kind == 'udp6'
                mapping = self.target.udp_ports
                udp = True
            else:
                raise ValueError("Bad channel", kind)

            address = self.target.ipv6_address if ipv6 else self.target.ipv4_address
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

    @property
    def default_channel(self):
        if self.target.tcp_ports and self.target.ip_version == 4:
            channel = 'tcp:0'
        elif self.target.tcp_ports and self.target.ip_version == 6:
            channel = 'tcp6:0'
        elif self.target.udp_ports and self.target.ip_version == 4:
            channel = 'udp:0'
        elif self.target.udp_ports and self.target.ip_version == 6:
            channel = 'udp6:0'
        elif self.process:
            channel = 'stdio'
        else:
            raise ValueError("Target has no channels defined")

        return self.get_channel(channel)

    def stop(self, timeout=1, timeout_exception=True):
        for sock in self._channels.values():
            if not sock.closed:
                sock.shutdown_wr()
        if self.process is not None:
            self.process.stdin.close()
            #time.sleep(2)
            #if self.process.poll() is None:
            #    print("Hung process")
            #    import ipdb; ipdb.set_trace()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait()
                if timeout_exception:
                    raise
