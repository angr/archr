import sys
import time

import nclib

from . import Arrowhead


class Log(nclib.logger.Logger):
    def __init__(self, channel_name, log):
        self.channel_name = channel_name
        self.log = log

    def _entry(self, direction, data):
        self.log.append({
            'time': time.time(),
            'data': data,
            'channel': self.channel_name,
            'direction': direction
        })

    def buffering(self, data):
        self._entry('recv', data)

    def sending(self, data):
        self._entry('send', data)


class ArrowheadFletcher(Arrowhead):
    """
    An arrowhead fletcher will allow a user to create an arrowhead by logging interactions that are performed when
    running the target program.

    :param insock:  The user's input into the target
    :param outsock:  The target's output from the target
    """

    def __init__(self, insock=sys.stdin, outsock=sys.stdout):
        super().__init__()
        self.insock = insock
        self.outsock = outsock
        self.result = []


    def run(self, flight):
        self.result = []

        channel = flight.default_channel

        if flight.target.tcp_ports:
            name = 'tcp/%d' % flight.target.tcp_ports[0]
        elif flight.target.udp_ports:
            name = 'udp/%d' % flight.target.udp_ports[0]
        else:
            name = 'stdio'

        logger = Log(name, self.result)
        channel.add_logger(logger)
        channel.interact(self.insock, self.outsock)
