"""Ancilis — runtime policy enforcement for AI agents."""

from ancilis.config import load_config
from ancilis.evidence import EvidenceRecord, EvidenceStore


def __getattr__(name: str):
    """Lazy import for AncilisMiddleware to avoid hard mcp dependency at import time."""
    if name == "AncilisMiddleware":
        from ancilis.middleware.middleware import AncilisMiddleware

        return AncilisMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["AncilisMiddleware", "EvidenceRecord", "EvidenceStore", "load_config"]
