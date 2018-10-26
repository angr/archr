import subprocess
import socket
import pwnlib

from . import Bow

class TubeBow(Bow):
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
			r = pwnlib.tubes.remote.remote(self.target.ipv4_address, self.target.tcp_ports[0])
			return r
		elif self.target.udp_ports:
			self.target.run_command()
			r = pwnlib.tubes.remote.remote(self.target.ipv4_address, self.target.tcp_ports[0], typ='udp')
			return r
		else:
			sl, sr = socket.socketpair()
			self.target.run_command(stdin=sr, stdout=sr, stderr=sr if stderr else None)
			r = pwnlib.tubes.sock.sock(pwnlib.timeout.Timeout.default)
			r.sock = sl
			r.rhost = 'archr'
			r.rport = 0
			return r
