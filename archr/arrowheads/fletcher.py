import sys
import time
import socket

import nclib

from . import Arrowhead


class Log:
    def __init__(self, channel_name, direction, data):
        self.channel_name = channel_name
        self.direction = direction
        self.data = data

    def write(self, data):
        self.data.append({
            'time': time.time(),
            'data': data,
            'channel': self.channel_name,
            'direction': self.direction
        })


class ArrowheadFletcher(Arrowhead):
    """
    An arrowhead fletcher will allow a user to create an arrowhead by logging interactions that are performed when
    running the target program.

    :param channel_map:  A mapping from user channels to target channels: {str user_channel, str target_channel)
    """

    def __init__(self, insock=sys.stdin, outsock=sys.stdout, verbose=False):
        # TODO: use this channel_map, for now we are just going to map stdin/stdout
        self.insock = insock
        self.outsock = outsock
        self.verbose = verbose
        self.result = []


    def run(self, flight):
        self.result = []

        channel = flight.default_channel

        def log(sock, direction):
            name = {
                flight.process.stdin: 'stdin',
                flight.process.stdout: 'stdout',
                flight.process.stderr: 'stderr',
            }.get(sock)
            if not name:
                if type(sock) is socket.socket:
                    # TODO: it is always TCP
                    name = f'tcp/{sock.getpeername()[1]}'
                else:
                    name = 'unknown'

            return Log(name, direction, self.result)

        channel.log_send = log(channel.sock_send, 'send')

        if type(channel.sock) is nclib.merge.MergePipes:
            for sub_channel in channel.sock.readables:
                sub_channel.log_recv = log(sub_channel.sock, 'recv')
        else:
            channel.log_recv = log(channel.sock, 'recv')

        channel.verbose = self.verbose

        channel.interact(self.insock, self.outsock)
