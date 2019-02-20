import socket
import nclib

from . import Bow

class NetCatBow(Bow):
    """
    Returns an nclib instance connected to a running instance of the target.
    """

    def fire(self, run=True, stderr=True, **kwargs): #pylint:disable=arguments-differ
        """
        Returns a tube connected to the process.

        :param bool stderr: If the target is a console app, whether to include stderr.
        :param bool run: Start the target (and pass kwargs along).
        :param kwargs: kwargs to pass through to run_command
        :returns: an nclib.NetCat
        """
        if self.target.tcp_ports:
            if run:
                self.target.run_command(**kwargs)
            r = nclib.Netcat((self.target.ipv4_address, self.target.tcp_ports[0]))
            return r
        elif self.target.udp_ports:
            if run:
                self.target.run_command(**kwargs)
            r = nclib.Netcat((self.target.ipv4_address, self.target.tcp_ports[0]), udp=True)
            return r
        else:
            assert run
            sl, sr = socket.socketpair()
            self.target.run_command(stdin=sr, stdout=sr, stderr=sr if stderr else None)
            r = nclib.Netcat(sock=sl)
            return r
