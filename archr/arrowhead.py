import time

class Arrowhead:
    """
    An arrowhead is a testcase. Many bows will use one to define the exact interaction that should be performed when
    running the target program in a specific way.
    """
    def __init__(self, input_data, encoding='utf-8'):
        if type(input_data) is str:
            input_data = input_data.encode(self.encoding)
        if type(input_data) is bytes:
            input_data = [input_data]

        self.input_data = input_data
        self.encoding = encoding

    def run(self, moving_target):
        pipe = moving_target.default_input

        for packet in self.input_data:
            time.sleep(0.01)
            pipe.write(packet)
