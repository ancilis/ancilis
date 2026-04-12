"""PR-07: Transport Security evaluator."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult

# Localhost addresses are exempt from transport security checks (local dev)
_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Parameter keys that may contain URLs/endpoints
_URL_KEYS = ("url", "endpoint", "baseUrl", "base_url", "server", "host", "api_url")


def _is_localhost(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host in _LOCALHOST_HOSTS
    except Exception:
        return False


def _extract_urls(params: dict[str, Any]) -> list[str]:
    """Extract URL strings from top-level and nested parameter values."""
    urls: list[str] = []
    for key in _URL_KEYS:
        val = params.get(key)
        if isinstance(val, str) and val:
            urls.append(val)
    # Also walk nested dicts one level deep
    for val in params.values():
        if isinstance(val, dict):
            for key in _URL_KEYS:
                nested = val.get(key)
                if isinstance(nested, str) and nested:
                    urls.append(nested)
    return urls


class PR07TransportEvaluator:
    control_id = "PR-07"
    control_name = "Transport Security"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        urls_checked: list[str] = []
        insecure_urls: list[str] = []
        localhost_exempt: list[str] = []

        # Gather URLs from parameters
        candidate_urls = _extract_urls(action.parameters.raw)

        # Also check action context server_url if present
        server_url = getattr(action.context, "server_url", None)
        if server_url and isinstance(server_url, str):
            candidate_urls.append(server_url)

        for url in candidate_urls:
            lower = url.lower()
            if lower.startswith("http://") or lower.startswith("ws://"):
                if _is_localhost(url):
                    localhost_exempt.append(url)
                else:
                    insecure_urls.append(url)
                    urls_checked.append(url)
            else:
                urls_checked.append(url)

        evidence: dict[str, Any] = {
            "urls_checked": urls_checked,
            "insecure_urls": insecure_urls,
            "localhost_exempt": localhost_exempt,
        }

        duration_ms = (time.perf_counter() - start) * 1000

        if insecure_urls:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Insecure transport detected: {len(insecure_urls)} URL(s) use http:// or ws://.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        if not candidate_urls:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="No URLs found in action parameters — nothing to validate.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="All URLs use secure transport (https:// or wss://).",
            evidence_data=evidence,
            duration_ms=duration_ms,
        )
