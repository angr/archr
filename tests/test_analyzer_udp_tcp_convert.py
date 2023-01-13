import unittest
from time import sleep

import archr

from common import build_container


class TestAnalyzerUDPTCPConvert(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_container("udp_tcp_convert")

    def check_udp_tcp_convert(self, t, **kwargs):  # pylint:disable=no-self-use
        target = t.run_command()  # start target
        b = archr.analyzers.UDPTCPConvert(t)
        with b.fire_context(args=["/udp_tcp_convert/udp_server"], **kwargs) as flight:
            sleep(2)
            p = t.run_command(["/udp_tcp_convert/tcp_client"])
            output = p.stdout.read()
            assert b"connection with the server failed" not in output

        flight_output = flight.process.stdout.read()

        # All UDP methods were invoked
        assert b"Calling socket" in flight_output
        assert b"Calling recvfrom" in flight_output
        assert b"Calling sendto" in flight_output

        # Actually received data from client proc
        assert b"Hello from TCP client" in flight_output

    def test_udp_tcp_convert_proc_docker(self):
        with archr.targets.DockerImageTarget("archr-test:udp_tcp_convert").build().start() as t:
            self.check_udp_tcp_convert(t)


if __name__ == "__main__":
    unittest.main()
