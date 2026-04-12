"""Version check utilities — PyPI cache and live fetch for ancilis doctor."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

_CACHE_PATH = Path.home() / ".ancilis" / "version_cache.json"
_CACHE_TTL_SECONDS = 3600  # 1 hour
_PYPI_URL = "https://pypi.org/pypi/ancilis/json"


def read_cache() -> dict | None:
    """Return cached version info dict if fresh, else None."""
    try:
        if not _CACHE_PATH.exists():
            return None
        data = json.loads(_CACHE_PATH.read_text())
        if time.time() - data.get("fetched_at", 0) > _CACHE_TTL_SECONDS:
            return None
        return data
    except Exception:
        return None


def fetch_latest_version(timeout: int = 1) -> str | None:
    """Fetch the latest ancilis version from PyPI. Returns version string or None."""
    try:
        with urllib.request.urlopen(_PYPI_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
            latest = data["info"]["version"]
        # Update cache
        try:
            _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_PATH.write_text(
                json.dumps({"latest_version": latest, "fetched_at": time.time()})
            )
        except Exception:
            pass
        return latest
    except Exception:
        return None
