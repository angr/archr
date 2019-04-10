import time


class Arrowhead:
    """
    An arrowhead defines the interaction that should be performed when running the target program in a specific way.
    """
    def __init__(self):
        raise NotImplementedError

    def run(self, flight):
        raise NotImplementedError


class ArrowheadLog(Arrowhead):
    """
    An arrowhead log is a testcase. Many bows will use one to define the exact interaction that should be performed
    when running the target program in a specific way.

    :param inputs:  A list of tuples: (float timestamp, str channel, bytes data)
    """
    def __init__(self, inputs):
        self.inputs = inputs

    @classmethod
    def oneshot(cls, data, channel=None):
        return cls([(0.0, channel, data)])

    def run(self, flight):
        time.sleep(0.1)
        starttime = time.time()

        for timestamp, channel_name, data in self.inputs:
            if channel_name is None:
                channel = flight.default_channel
            else:
                channel = flight.get_channel(channel_name)
            now = time.time() - starttime
            if now < timestamp:
                time.sleep(timestamp - now)
            if data:
                channel.write(data)
            else:
                channel.shutdown_wr()


from .fletcher import ArrowheadFletcher
