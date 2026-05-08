"""Ancilis Cover — compliance intelligence for AI-assisted development."""

from typing import Any

__all__ = ["main"]


def __getattr__(name: str) -> Any:
    if name == "main":
        from ancilis.mcp_server.cover.server import main as _main
        return _main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
