import socket
import nclib

from . import Bow

class NetCatBow(Bow):
    """
    Returns a pwntools tube connected to a running instance of the target.
    """

    def fire(self, stderr=True): #pylint:disable=arguments-differ
        """
        Returns a tube connected to the process.

        :param bool stderr: If the target is a console app, whether to include stderr.
        """
        if self.target.tcp_ports:
            self.target.run_command()
            r = nclib.Netcat((self.target.ipv4_address, self.target.tcp_ports[0]))
            return r
        elif self.target.udp_ports:
            self.target.run_command()
            r = nclib.Netcat((self.target.ipv4_address, self.target.tcp_ports[0]), udp=True)
            return r
        else:
            sl, sr = socket.socketpair()
            self.target.run_command(stdin=sr, stdout=sr, stderr=sr if stderr else None)
            r = nclib.Netcat(sock=sl)
            return r
