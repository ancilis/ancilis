"""Helpers for the SDK demo orchestration flow."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

DEMO_INTEGRATION_NAME_BASE = "Finance Demo SDK"


def build_demo_integration_name(
    db_path: str | Path,
    *,
    base_name: str = DEMO_INTEGRATION_NAME_BASE,
) -> str:
    """Return a stable demo integration name for the current evidence store path."""
    normalized_path = str(Path(db_path).expanduser())
    fingerprint = sha256(normalized_path.encode("utf-8")).hexdigest()[:8]
    return f"{base_name} ({fingerprint})"


def build_demo_integration_payload(
    db_path: str | Path,
    *,
    name: str | None = None,
) -> dict[str, Any]:
    """Build the sdk_direct integration payload for the current demo evidence store."""
    normalized_path = str(Path(db_path).expanduser())
    return {
        "name": name or build_demo_integration_name(normalized_path),
        "source_type": "sdk_direct",
        "config": {
            "api_key_hint": "demo-local",
            "transport": {
                "mode": "local_file",
                "paths": [normalized_path],
                "scan_home_dir": False,
            },
            "sync": {
                "mode": "incremental",
                "batch_size": 500,
            },
        },
    }
