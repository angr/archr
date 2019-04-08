import time

class Arrowhead:
    """
    An arrowhead is a testcase. Many bows will use one to define the exact interaction that should be performed when
    running the target program in a specific way.

    :param inputs:  A list of tuples: (float timestamp, str channel, bytes data)
    """
    def __init__(self, inputs):
        self.inputs = inputs

    @classmethod
    def oneshot(cls, data, channel=None):
        return cls([(0.0, channel, data)])

    def run(self, flight):
        starttime = time.time()

        for timestamp, channel_name, data in self.inputs:
            channel = flight.get_channel(channel_name)
            now = time.time() - starttime
            if now < timestamp:
                time.sleep(timestamp - now)
            channel.write(data)
