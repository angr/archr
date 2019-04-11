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

    :param insock:  The user's input into the target
    :param outsock:  The target's output from the target
    """

    def __init__(self, insock=sys.stdin, outsock=sys.stdout):
        self.insock = insock
        self.outsock = outsock
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
                    name = 'tcp/' + str(sock.getpeername()[1])
                else:
                    name = 'unknown'

            return Log(name, direction, self.result)

        channel.log_send = log(channel.sock_send, 'send')

        if type(channel.sock) is nclib.merge.MergePipes:
            for sub_channel in channel.sock.readables:
                sub_channel.log_recv = log(sub_channel.sock, 'recv')
        else:
            channel.log_recv = log(channel.sock, 'recv')

        channel.interact(self.insock, self.outsock)
