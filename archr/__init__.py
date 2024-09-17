__version__ = "9.2.118"

import logging

_LOG = logging.getLogger("archr")

try:
    import angr

    _angr_available = True
except ImportError:
    _LOG.debug("angr import failed. angr support disabled")
    _angr_available = False

try:
    import qtrace

    _qtrace_available = True
except ImportError:
    _LOG.debug("qtrace import failed. qtrace support disabled")
    _qtrace_available = False

from . import targets
from . import implants
from . import utils
from . import analyzers

# backwards compatibility
arrows = implants
arsenal = analyzers
