"""OSV.dev batch vulnerability lookup — returns structured VulnerabilityFinding results."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from ancilis.dependencies.detector import Dependency

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 10
_MAX_RETRIES = 2
_BATCH_SIZE = 1000


@dataclass
class VulnerabilityFinding:
    cve_id: str
    package_name: str
    installed_version: str
    severity: str  # "critical" | "high" | "medium" | "low"
    cvss_score: float | None
    fixed_version: str | None
    summary: str
    aliases: list[str] = field(default_factory=list)
    affected_versions: str = ""


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cvss_score(vuln_data: dict) -> float | None:
    for sev in vuln_data.get("severity", []):
        score_type = sev.get("type", "")
        score_str = sev.get("score", "")
        if score_type in ("CVSS_V3", "CVSS_V2") and score_str:
            try:
                return float(score_str)
            except ValueError:
                pass
    return None


def _extract_severity(vuln_data: dict) -> tuple[str, float | None]:
    """Return (severity_string, cvss_score_or_None)."""
    score = _extract_cvss_score(vuln_data)
    if score is not None:
        return _cvss_to_severity(score), score
    # Fall back to database_specific.severity
    db_sev = vuln_data.get("database_specific", {}).get("severity", "")
    if db_sev:
        mapped = db_sev.lower()
        if mapped in ("critical", "high", "medium", "low"):
            return mapped, None
    return "low", None


def _extract_fixed_version(vuln_data: dict, pkg_name: str) -> str | None:
    for affected in vuln_data.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _affected_summary(vuln_data: dict) -> str:
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


def _query_chunk(
    deps: list[Dependency],
    ecosystem: str = "PyPI",
) -> tuple[list[VulnerabilityFinding], str | None]:
    """Send one OSV batch request; return (findings, error_or_None)."""
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

    last_exc: str | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body = json.loads(resp.read().decode())
            break
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_exc = str(exc)
            if attempt == _MAX_RETRIES:
                return [], last_exc
        except json.JSONDecodeError as exc:
            return [], f"Invalid JSON from OSV.dev: {exc}"
    else:
        return [], last_exc  # type: ignore[return-value]

    findings: list[VulnerabilityFinding] = []
    for dep, result in zip(deps, body.get("results", []), strict=False):
        for v in result.get("vulns", []):
            severity, cvss_score = _extract_severity(v)
            findings.append(
                VulnerabilityFinding(
                    cve_id=v.get("id", ""),
                    package_name=dep.name,
                    installed_version=dep.version or "",
                    severity=severity,
                    cvss_score=cvss_score,
                    fixed_version=_extract_fixed_version(v, dep.name),
                    summary=v.get("summary", ""),
                    aliases=v.get("aliases", []),
                    affected_versions=_affected_summary(v),
                )
            )
    return findings, None


def query_osv_batch(
    deps: list[Dependency],
    ecosystem: str = "PyPI",
) -> tuple[list[VulnerabilityFinding], str | None]:
    """Query OSV.dev for all *deps* and return (findings, error_or_None).

    Deps without a pinned version are silently skipped.
    On network failure returns ([], error_message). Non-blocking.
    """
    versioned = [d for d in deps if d.version]
    if not versioned:
        return [], None

    all_findings: list[VulnerabilityFinding] = []
    for i in range(0, len(versioned), _BATCH_SIZE):
        batch = versioned[i : i + _BATCH_SIZE]
        chunk_findings, err = _query_chunk(batch, ecosystem)
        if err is not None:
            return [], err
        all_findings.extend(chunk_findings)

    return all_findings, None
