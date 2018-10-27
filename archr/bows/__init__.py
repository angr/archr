import sys

class Bow:
	def __init__(self, target):
		"""
		Initializes the bow.
		:param Target target: the target to work on
		"""
		self.target = target

	def fire(self, *args, **kwargs):
		"""
		Fire the bow at the target.
		"""
		raise NotImplementedError()

from .angr_project import angrProjectBow
from .angr_state import angrStateBow
from .memory_map import MemoryMapBow
from .nc import NetCatBow

if 'nose' not in sys.modules:
	from .tube import TubeBow
