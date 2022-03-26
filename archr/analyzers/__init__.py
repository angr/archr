import os
import time
import logging
from contextlib import contextmanager
from archr.targets.actions import OpenChannelAction, SendAction, CloseChannelAction

l = logging.getLogger(name=__name__)

class Analyzer:
    REQUIRED_IMPLANT = None
    REQUIRED_BINARY = None

    def __init__(self, target, implant_bundle=None, implant_binary=None):
        """
        Initializes the analyzer.
        :param Target target: the target to work on
        """
        self.target = target
        if implant_bundle is not None:
            self.REQUIRED_IMPLANT = implant_bundle
        if implant_binary is not None:
            self.REQUIRED_BINARY = implant_binary
        self.nock()

    def nock(self):
        """
        Prepare the implant (inject it into the target).
        """
        if self.REQUIRED_IMPLANT:
            with implants.bundle(self.REQUIRED_IMPLANT) as b:
                self.target.inject_path(b, os.path.join(self.target.tmpwd, self.REQUIRED_IMPLANT))
        if self.REQUIRED_BINARY:
            with implants.bundle_binary(self.REQUIRED_BINARY) as b:
                self.target.inject_path(b, os.path.join(self.target.tmpwd, os.path.basename(self.REQUIRED_BINARY)))

    def fire(self, *args, **kwargs):
        """
        Fire the analyzer at the target.
        """
        raise NotImplementedError()


class ContextAnalyzer(Analyzer):
    """
    A Analyzer base class for analyzers that implement a fire_context instead of a fire.
    Provides a default .fire() that replays a testcase.
    """

    def fire(self, *args, testcase=None, pre_fire_hook=None, channel=None, delay=0, actions=None, **kwargs): #pylint:disable=arguments-differ
        if actions is None and testcase is not None:
            if type(testcase) is bytes:
                open_act = OpenChannelAction(channel_name=channel)
                send_act = SendAction(testcase, channel_name=channel)
                actions = [open_act, send_act]
            elif type(testcase) is list:
                open_act = OpenChannelAction(channel_name=channel)
                actions = [open_act]
                for write in testcase:
                    actions.append(SendAction(write, channel_name=channel))
            else:
                raise TypeError("Unsupported type for testcase")

        kwargs['actions'] = actions

        with self.fire_context(*args, **kwargs) as flight:
            if delay:
                l.info("sleep for %d seconds waiting for the target to initialize", delay)
                time.sleep(delay)  # wait for the target to initialize
            if pre_fire_hook is not None:
                pre_fire_hook(self, flight, channel=channel, testcase=testcase)
            self._fire_testcase(flight, channel=channel)

        return flight.result

    def _fire_testcase(self, flight, channel=None): #pylint:disable=no-self-use
        flight.start()
        return flight.get_channel(channel)

    @contextmanager
    def fire_context(self, *args, **kwargs):  # -> ContextManager[Flight]:
        """
        A context manager for the analyzer. Should yield a Flight object.
        """
        with self.target.flight_context(*args, **kwargs) as flight:
            yield flight


from .. import _angr_available, _qtrace_available

if _angr_available:
    from .angr_project import angrProjectAnalyzer
    from .angr_state import angrStateAnalyzer
    from .angr_ultimate_tracer import angrUltimateTracerAnalyzer
if _qtrace_available:
    from .qtrace import QTraceAnalyzer
from .qemu_tracer import QEMUTracerAnalyzer
from .bintrace_qemu_tracer import BintraceQEMUTracerAnalyzer
from .datascout import DataScoutAnalyzer
from .gdbserver import GDBServerAnalyzer
from .core import CoreAnalyzer
from .ltrace import LTraceAnalyzer, LTraceAttachAnalyzer
from .strace import STraceAnalyzer, STraceAttachAnalyzer
from .input_fd import InputFDAnalyzer
from .rr import RRTracerAnalyzer, RRReplayAnalyzer
from .gdb import GDBAnalyzer
from .tcpdump import TCPDumpAnalyzer
from .udp_tcp_convert import UDPTCPConvert
from .. import implants

# backwards compatibility
if _angr_available:
    angrProjectBow = angrProjectAnalyzer
    angrStateBow = angrStateAnalyzer
    angrUltimateTracerBow = angrUltimateTracerAnalyzer
QEMUTracerBow = QEMUTracerAnalyzer
BintraceQEMUTracerBow = BintraceQEMUTracerAnalyzer
DataScoutBow = DataScoutAnalyzer
GDBServerBow = GDBServerAnalyzer
CoreBow = CoreAnalyzer
UDPTCPConvertBow = UDPTCPConvert
LTraceBow = LTraceAnalyzer
LTraceAttachBow = LTraceAttachAnalyzer
STraceBow = STraceAnalyzer
STraceAttachBow = STraceAttachAnalyzer
InputFDBow = InputFDAnalyzer
RRTracerBow = RRTracerAnalyzer
RRReplayBow = RRReplayAnalyzer
GDBBow = GDBAnalyzer
