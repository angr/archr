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

    @contextlib.contextmanager
    def fire_context(self, args_prefix=None, **kwargs): #pylint:disable=arguments-differ
        """
        Starts tcpdump with a fresh process.

        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """
        pcap_path = "/tmp/target.pcap"

        tcpdump = self.target.run_companion_command(
            ["tcpdump", "-i", "any", "-w", pcap_path, "--immediate-mode"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )

        tcpdump.stderr.read(0x1000)

        with self.target.flight_context(args_prefix=args_prefix, **kwargs) as flight:
            yield flight

        self.target.run_companion_command(["pkill", "tcpdump"]).wait()
        tcpdump.communicate()

        tshark = self.target.run_companion_command(
            [
                "tshark",
                "-r", pcap_path,
                "-T", "json",
                "-e", "tcp.payload",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
            ],
            stdin=subprocess.DEVNULL,
        )

        pcap_data, _ = tshark.communicate()
        pcap_data = json.loads(pcap_data)
        packets = [
            {k: v[0] for k, v in e['_source']['layers'].items()}
            for e in pcap_data
        ]

        conversations = collections.defaultdict(list)

        for packet in packets:
            if not packet:
                continue
            payload = bytes.fromhex(packet.get("tcp.payload", ""))
            if not payload:
                continue
            src = int(packet["tcp.srcport"])
            dst = int(packet["tcp.dstport"])
            conversation_id = tuple(sorted((src, dst)))
            conversations[conversation_id].append((src, dst, payload))

        flight.result = dict(conversations)
