import collections
import subprocess
import json
import contextlib
import logging

from . import ContextAnalyzer


l = logging.getLogger("archr.analyzers.tcpdump")


class TCPDumpAnalyzer(ContextAnalyzer):
    """
    Launches a process under tcpdump
    """

    pcap_path = "/tmp/target.pcap"

    def extract_conversations(self):
        tshark = self.target.run_companion_command(
            [
                "tshark",
                "-r",
                self.pcap_path,
                "-T",
                "json",
                "-e",
                "tcp.stream",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "tcp.payload",
                "-e",
                "tcp.flags.fin",
            ],
            stdin=subprocess.DEVNULL,
        )

        pcap_data, _ = tshark.communicate()
        pcap_data = json.loads(pcap_data)
        packets = [{k: v[0] for k, v in e["_source"]["layers"].items()} for e in pcap_data]

        conversations = collections.defaultdict(list)

        for packet in packets:
            if not packet:
                continue
            payload = bytes.fromhex(packet.get("tcp.payload", ""))
            fin = packet["tcp.flags.fin"] == "1"
            if not payload and not fin:
                continue
            stream = int(packet["tcp.stream"])
            src = int(packet["tcp.srcport"])
            dst = int(packet["tcp.dstport"])
            conversations[stream].append((src, dst, payload))
            if payload and fin:
                payload = ""
                conversations[stream].append((src, dst, payload))

        return dict(conversations)

    @contextlib.contextmanager
    def fire_context(self, port=None, *args, **kwargs):
        """
        Starts tcpdump with a fresh process.
        """
        if port is None:
            port = self.target.tcp_ports[0]
        tcpdump = self.target.run_companion_command(
            [
                "tcpdump",
                "-i",
                "any",
                "-w",
                self.pcap_path,
                "--immediate-mode",
                "--packet-buffered",
                f"tcp port {port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )

        tcpdump.stderr.read(0x1000)

        with self.target.flight_context(*args, **kwargs) as flight:
            yield flight

        self.target.run_companion_command(["pkill", "tcpdump"]).wait()
        tcpdump.communicate()

        flight.result = self.extract_conversations()
