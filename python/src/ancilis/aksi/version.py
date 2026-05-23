"""AKSI framework version metadata."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from ancilis._shared import shared_path

DEFAULT_AKSI_FRAMEWORK_VERSION = "0.6"


@lru_cache(maxsize=1)
def load_framework_metadata() -> dict[str, Any]:
    """Load frozen AKSI framework metadata from shared assets."""
    try:
        data = json.loads(shared_path("aksi_version.json").read_text())
    except Exception:  # noqa: BLE001 - keep SDK imports usable if assets are absent
        return {"framework_version": DEFAULT_AKSI_FRAMEWORK_VERSION}
    return data if isinstance(data, dict) else {"framework_version": DEFAULT_AKSI_FRAMEWORK_VERSION}


def framework_version() -> str:
    version = load_framework_metadata().get("framework_version")
    return version if isinstance(version, str) and version else DEFAULT_AKSI_FRAMEWORK_VERSION


AKSI_FRAMEWORK_VERSION = framework_version()
