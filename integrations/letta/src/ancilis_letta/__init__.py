"""ancilis-letta — Letta integration for Ancilis evidence capture.

Letta (formerly MemGPT) builds stateful, memory-persistent agents whose
``archival_memory`` and ``core_memory`` blocks store user-supplied content
across sessions. ancilis-letta records every message, tool call, and memory
operation as cryptographically chained evidence — without ever storing raw
memory contents.
"""

from ancilis_letta._producer import LettaProducer
from ancilis_letta._version import __version__
from ancilis_letta.recorder import record_response
from ancilis_letta.wrapper import wrap_client

__all__ = [
    "LettaProducer",
    "record_response",
    "wrap_client",
    "__version__",
]
