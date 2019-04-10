import nclib
import socket
import subprocess

class Flight:
    """
    A flight is a running process in a running target.
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
            if channel_name == 'stdio':
                stdout = nclib.Netcat(sock=self.process.stdout)
                stderr = nclib.Netcat(sock=self.process.stderr)
                merged_output = nclib.merge.MergePipes([stdout, stderr])

                def close(self):
                    for nc in self.readables:
                        nc.close()
                merged_output.close = close.__get__(merged_output, nclib.merge.MergePipes)

                return nclib.Netcat(sock=merged_output, sock_send=self.process.stdin)
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
            return nclib.Netcat(sock)


    @property
    def default_channel(self):
        if self.target.tcp_ports:
            channel = 'tcp:0'
        elif self.target.udp_ports:
            channel = 'udp:0'
        elif self.process:
            channel = 'stdio'
        else:
            raise ValueError("Target has no channels defined")

        return self.get_channel(channel)

    def stop(self, timeout=1):
        for sock in self._channels.values():
            sock.close()
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
                raise
