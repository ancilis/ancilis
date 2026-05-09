"""ancilis-agno — Agno integration for Ancilis evidence capture.

Agno (formerly Phidata) is the "FastAPI of agents" — a fast, modular framework
with first-class primitives for memory, knowledge bases, and teams of
cooperating agents. ancilis-agno records every run, tool call, memory
write, knowledge query, and team-member delegation as cryptographically
chained evidence — without ever storing raw memory text, raw knowledge
queries, or raw tool-arg values.
"""

from ancilis_agno._producer import AgnoProducer
from ancilis_agno._version import __version__
from ancilis_agno.wrapper import wrap_agent, wrap_team

__all__ = [
    "AgnoProducer",
    "wrap_agent",
    "wrap_team",
    "__version__",
]
