import subprocess
import logging

from .actions import OpenChannelAction


l = logging.getLogger("archr.target.flight")

class InteractionError(BaseException):
    pass
class Interaction:
    """
    An Interaction specifies how to interact with a target
    An Interaction is generally the result of ContextAnalyzer.fire_context.
    It has a result field, which is normally returned from ContexAnalyzer.fire.
    """
    def __init__(self, target, process, actions=None, result=None):
        self.target = target
        self.process = process
        self._channels = {}
        self.result = result

        if actions is None:
            l.warning("No actions specified, make sure this is what you want!")
            actions = ()
        self.actions = actions
        assert type(actions) in (list, tuple), "actions must be a list or a tuple"
        for act in self.actions:
            act.interaction = self

    def get_channel(self, channel_name):
        # TODO: this doesn't quite work bc we will want to open multiple connections to tcp:0 for example
        # how to represent this...?
        channel = self._channels.get(channel_name, None)
        if channel is not None:
            return channel

        # for backward compatibility where the code interact with the flight object directly
        act = OpenChannelAction(channel_name=channel_name)
        act.interaction = self
        channel = act.perform()
        if channel:
            return channel

        raise InteractionError(f"channel {channel_name} is not open")

    @property
    def default_channel_name(self):
        if self.target.tcp_ports and self.target.ip_version == 4:
            name = 'tcp:0'
        elif self.target.tcp_ports and self.target.ip_version == 6:
            name = 'tcp6:0'
        elif self.target.udp_ports and self.target.ip_version == 4:
            name = 'udp:0'
        elif self.target.udp_ports and self.target.ip_version == 6:
            name = 'udp6:0'
        elif self.process:
            name = 'stdio'
        else:
            raise ValueError("Target has no default channel defined")
        return name

    @property
    def default_channel(self):
        channel_name = self.default_channel_name
        return self.get_channel(channel_name)

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

    def start(self):

        # sanity check
        ret = self.process.poll()
        if ret is not None:
            l.error("The target process crashed with return value: %d", ret)
            stdout, stderr = self.process.communicate()
            l.debug("stdout:\n%s", stdout.decode())
            l.debug("stderr:\n%s", stderr.decode())
            raise ValueError("The target process crashed before communication")

        for act in self.actions:
            act.perform()

# backward compatibility
Flight = Interaction
