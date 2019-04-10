import time
import sys

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

    def __init__(self, channel_map):
        # TODO: use this channel_map, for now we are just going to map stdin/stdout
        self.channel_map = channel_map
        self.result = []


    def run(self, flight):
        self.result = []

        default_channel = flight.default_channel
        default_name = [k for k, v in flight._channels.items() if v == default_channel][0]

        default_channel.log_send = Log(default_name, 'send', self.result)
        default_channel.log_recv = Log(default_name, 'recv', self.result)
        default_channel.interact()
