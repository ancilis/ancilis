"""OSV.dev batch vulnerability lookup client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ancilis.deps.manifest import Dependency

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 10
_BATCH_SIZE = 1000


@dataclass
class Vuln:
    id: str
    summary: str
    severity: str
    aliases: list[str] = field(default_factory=list)
    affected_versions: str = ""
    fixed_version: str | None = None


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_severity(vuln_data: dict[str, Any]) -> str:
    """Map OSV vulnerability data to a severity string."""
    for sev in vuln_data.get("severity", []):
        score_type = sev.get("type", "")
        score_str = sev.get("score", "")
        if score_type in ("CVSS_V3", "CVSS_V2") and score_str:
            try:
                return _cvss_to_severity(float(score_str))
            except ValueError:
                pass
    db_specific = vuln_data.get("database_specific", {})
    db_sev = db_specific.get("severity", "") if isinstance(db_specific, dict) else ""
    if isinstance(db_sev, str) and db_sev:
        upper = db_sev.upper()
        if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return upper
    return "LOW"


def _extract_fixed_version(vuln_data: dict[str, Any], pkg_name: str) -> str | None:
    """Return the earliest fixed version from affected ranges, or None."""
    for affected in vuln_data.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed:
                    return fixed
    return None


def _affected_summary(vuln_data: dict[str, Any]) -> str:
    """Build a concise affected-versions string (max 3 ranges)."""
    parts: list[str] = []
    for affected in vuln_data.get("affected", []):
        for rng in affected.get("ranges", []):
            introduced = None
            fixed = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if introduced or fixed:
                parts.append(f">={introduced or '0'}{', <' + fixed if fixed else ''}")
    return "; ".join(parts[:3])


class OSVClient:
    """Query OSV.dev /v1/querybatch for known vulnerabilities."""

    def __init__(self) -> None:
        self._error: str | None = None

    @property
    def last_error(self) -> str | None:
        return self._error

    def query_batch(
        self,
        deps: list[Dependency],
        ecosystem: str = "PyPI",
    ) -> dict[str, list[Vuln]]:
        """Return {package_name: [Vuln, ...]} for all vulnerable packages.

        On network failure sets ``last_error`` and returns an empty dict.
        Batches requests at 1 000 entries per OSV API limit.
        Deps without a pinned version are silently skipped.
        """
        self._error = None
        versioned = [d for d in deps if d.version is not None]
        if not versioned:
            return {}

        results: dict[str, list[Vuln]] = {}
        for i in range(0, len(versioned), _BATCH_SIZE):
            batch = versioned[i : i + _BATCH_SIZE]
            chunk = self._query_chunk(batch, ecosystem)
            if chunk is None:
                return {}
            results.update(chunk)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _query_chunk(
        self,
        deps: list[Dependency],
        ecosystem: str,
    ) -> dict[str, list[Vuln]] | None:
        """Send one batch request; return None on any network/parse error."""
        queries = [
            {
                "package": {"name": d.name, "ecosystem": ecosystem},
                "version": d.version,
            }
            for d in deps
        ]
        payload = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            _OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body = json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self._error = str(exc)
            return None
        except json.JSONDecodeError as exc:
            self._error = f"Invalid JSON from OSV.dev: {exc}"
            return None

        out: dict[str, list[Vuln]] = {}
        for dep, result in zip(deps, body.get("results", []), strict=False):
            vulns: list[Vuln] = []
            for v in result.get("vulns", []):
                vulns.append(
                    Vuln(
                        id=v.get("id", ""),
                        summary=v.get("summary", ""),
                        severity=_extract_severity(v),
                        aliases=v.get("aliases", []),
                        affected_versions=_affected_summary(v),
                        fixed_version=_extract_fixed_version(v, dep.name),
                    )
                )
            if vulns:
                out[dep.name] = vulns
        return out
