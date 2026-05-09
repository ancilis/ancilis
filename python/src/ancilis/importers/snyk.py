"""Snyk findings importer — converts Snyk REST API issue exports to AKSI EvaluationResults.

Snyk (https://snyk.io) is the dominant developer-security platform: it scans
dependencies (Open Source), source code (Snyk Code), containers, and IaC for
vulnerabilities and license violations. As AI agents (Claude Code, Cursor,
Devin, etc.) ship code, Snyk is one of the most likely places where the
resulting vulnerabilities surface — the SDK already imports generic SARIF
findings, but Snyk's policy / license / risk fields are richer than SARIF
permits.

This importer ingests Snyk REST ``/orgs/{org}/issues`` exports in four shapes:

  1. ``{"data":   [...]}``  — canonical REST API envelope
  2. ``{"issues": [...]}``  — convenience envelope (some CLI / connectors)
  3. JSONL                   — one issue per line
  4. single object           — a bare issue

Mapping (see ``shared/mappings/snyk-aksi-controls.json``):

  * status=open  + severity=critical                              → PR-03 FAIL
  * status=open  + severity=high                                  → PR-03 FAIL
  * status=open  + severity=medium + exploit_maturity=mature      → PR-03 FAIL  (treat as high)
  * status=open  + severity=medium                                → PR-03 FLAG
  * status=open  + severity=low                                   → PR-03 PASS  (captured, non-blocking)
  * status=resolved                                               → PR-05 PASS  (audit trail of fix)
  * status=ignored + ignored_reason=null                          → PR-02 FAIL  (governance violation)
  * status=ignored + ignored_reason set + sev=critical/high       → PR-02 FLAG  (re-review required)
  * type=license + license_severity=high                          → PR-04 FAIL  (legal risk)
  * type=license + license_severity=medium                        → PR-04 FLAG
  * type=container + severity=critical                            → PR-03 FAIL  (production-image vuln)
  * is_fixable=False + severity=critical/high                     → PR-03 FLAG  (no fix — accept-risk)
  * is_disregarded=True                                           → PR-02 FAIL  (Snyk bypass = compliance violation)

Synthetic findings:

  * > N critical+high open issues in the same project (default 10)
    → DE-01 FAIL  (broken-windows signal)
  * > N AI-introduced findings in same scan (default 5)
    → PR-03 FLAG  (agent quality drift)
  * Same package_name+package_version with critical issue across
    > N projects (default 3) → PR-03 FLAG  (organization-wide exposure)

Sanitization (security-critical — Snyk findings can carry sensitive data):

  * ``title`` raw is NOT stored. Only the first 80 chars + sha256 of the full
    title are captured; full title text could carry leaked secret values that
    Snyk Code surfaced (e.g. "Hardcoded credential: <secret>").
  * ``code_file_path`` is normalized to its directory + base file extension
    only; filename suffixes (e.g. ``private-key.pem``) may carry secret-bearing
    naming conventions and are dropped.
  * ``ignored_reason`` raw is NOT stored. Only its length + sha256 are captured;
    free-form justification text may contain sensitive details.
  * Original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``snyk`` Python package; this importer is a pure
JSON parser.
"""

from __future__ import annotations

import fnmatch  # noqa: F401  (parity with sarif.py — pattern matching reserved for future glob mappings)
import hashlib
import json
import os
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/snyk.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "snyk-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Defaults if mapping JSON is missing/malformed; mirrors the canonical mapping table.
_DEFAULT_MAPPINGS: dict[str, dict[str, str]] = {
    "status_open_critical":      {"control": "PR-03", "result": "FAIL"},
    "status_open_high":          {"control": "PR-03", "result": "FAIL"},
    "status_open_medium_mature": {"control": "PR-03", "result": "FAIL"},
    "status_open_medium":        {"control": "PR-03", "result": "FLAG"},
    "status_open_low":           {"control": "PR-03", "result": "PASS"},
    "status_resolved":           {"control": "PR-05", "result": "PASS"},
    "ignored_no_reason":         {"control": "PR-02", "result": "FAIL"},
    "ignored_with_reason_high":  {"control": "PR-02", "result": "FLAG"},
    "license_high":              {"control": "PR-04", "result": "FAIL"},
    "license_medium":            {"control": "PR-04", "result": "FLAG"},
    "container_critical":        {"control": "PR-03", "result": "FAIL"},
    "unfixable_critical":        {"control": "PR-03", "result": "FLAG"},
    "disregarded":               {"control": "PR-02", "result": "FAIL"},
}

_DEFAULT_SYNTHETICS: dict[str, dict[str, str]] = {
    "high_density":              {"control": "DE-01", "result": "FAIL"},
    "ai_assisted_concentration": {"control": "PR-03", "result": "FLAG"},
    "cross_project_pattern":     {"control": "PR-03", "result": "FLAG"},
}

_DEFAULT_HIGH_DENSITY_THRESHOLD = 10
_DEFAULT_AI_ASSISTED_CONCENTRATION_THRESHOLD = 5
_DEFAULT_CROSS_PROJECT_THRESHOLD = 3

# Title prefix kept verbatim; the full title is hashed separately.
_TITLE_PREFIX_LEN = 80


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the snyk-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _sanitize_title(title: str | None) -> dict[str, Any]:
    """Reduce a finding title to (prefix, length, sha256). Never store raw."""
    if not isinstance(title, str) or not title:
        return {"prefix": "", "length": 0, "sha256": ""}
    sha = hashlib.sha256(title.encode("utf-8")).hexdigest()
    return {
        "prefix": title[:_TITLE_PREFIX_LEN],
        "length": len(title),
        "sha256": sha,
    }


def _normalize_code_file_path(path: str | None) -> str | None:
    """Return ``directory/<ext>`` for a Snyk code path, dropping filename.

    A raw path like ``src/utils/private-key.pem`` becomes ``src/utils/<.pem>``;
    a raw path like ``app/handlers/login.js`` becomes ``app/handlers/<.js>``.
    Filename stems (``private-key``, ``login``) are dropped because Snyk Code
    sometimes surfaces secret-bearing filenames; the directory + extension is
    sufficient to triage the finding without leaking those names.
    """
    if not isinstance(path, str) or not path:
        return None
    norm = path.replace("\\", "/").strip()
    if not norm:
        return None
    directory, filename = os.path.split(norm)
    _, ext = os.path.splitext(filename)
    ext_marker = f"<{ext}>" if ext else "<no-ext>"
    if directory:
        return f"{directory}/{ext_marker}"
    return ext_marker


def _hash_ignored_reason(reason: str | None) -> dict[str, Any] | None:
    """Reduce an ignored_reason free-form string to (length, sha256)."""
    if reason is None:
        return None
    if not isinstance(reason, str):
        return None
    return {
        "length": len(reason),
        "sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Classification — pure function returning the signal key for a finding
# ---------------------------------------------------------------------------


def _classify_attrs(attrs: dict[str, Any]) -> str | None:
    """Return the canonical signal-key for a Snyk issue's attributes.

    Priority follows the ``_metadata.signal_priority`` ordering:
        disregarded → ignored_no_reason → container_critical →
        license_high/medium → status_open_* → ignored_with_reason_high →
        unfixable_critical → status_resolved
    Returns ``None`` if no rule fires (e.g. resolved + low + non-license).
    """
    issue_type = (attrs.get("type") or "").strip().lower()
    severity = (attrs.get("effective_severity_level") or attrs.get("severity") or "").strip().lower()
    status = (attrs.get("status") or "").strip().lower()
    exploit_maturity = (attrs.get("exploit_maturity") or "").strip().lower()
    is_fixable = bool(attrs.get("is_fixable", True))
    is_disregarded = bool(attrs.get("is_disregarded", False))
    license_severity = (attrs.get("license_severity") or "").strip().lower()
    ignored_reason = attrs.get("ignored_reason")

    # Highest priority — disregarded overrides everything else.
    if is_disregarded:
        return "disregarded"

    # Ignored governance.
    if status == "ignored":
        if ignored_reason is None or (isinstance(ignored_reason, str) and ignored_reason.strip() == ""):
            return "ignored_no_reason"
        if severity in ("critical", "high"):
            return "ignored_with_reason_high"
        # Ignored with reason at low/medium = silent; no FAIL but record below.
        return None

    # Container criticals first — production-image risk dominates type=package_vulnerability default.
    if issue_type == "container" and severity == "critical":
        return "container_critical"

    # License findings — only fire when type=license.
    if issue_type == "license":
        if license_severity == "high":
            return "license_high"
        if license_severity == "medium":
            return "license_medium"

    # Open-status severity ladder.
    if status == "open":
        if severity == "critical":
            return "status_open_critical"
        if severity == "high":
            return "status_open_high"
        if severity == "medium":
            if exploit_maturity == "mature":
                return "status_open_medium_mature"
            return "status_open_medium"
        if severity == "low":
            return "status_open_low"

    # Unfixable (only fires if not already classified above as critical/high open FAIL).
    # Used for resolved-but-still-on-record or non-open critical/high without a fix.
    if not is_fixable and severity in ("critical", "high") and status != "resolved":
        return "unfixable_critical"

    if status == "resolved":
        return "status_resolved"

    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SnykImporter:
    """Parse a Snyk REST API issues export and convert each issue to an EvaluationResult."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        high_density_threshold: int | None = None,
        ai_assisted_concentration_threshold: int | None = None,
        cross_project_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        raw_mappings = table.get("mappings") if isinstance(table, dict) else None
        self._mappings: dict[str, dict[str, str]] = (
            raw_mappings if isinstance(raw_mappings, dict) and raw_mappings else _DEFAULT_MAPPINGS
        )
        raw_synth = table.get("synthetics") if isinstance(table, dict) else None
        self._synthetics: dict[str, dict[str, str]] = (
            raw_synth if isinstance(raw_synth, dict) and raw_synth else _DEFAULT_SYNTHETICS
        )

        self.high_density_threshold = (
            high_density_threshold
            if high_density_threshold is not None
            else int(meta.get("high_density_threshold", _DEFAULT_HIGH_DENSITY_THRESHOLD))
        )
        self.ai_assisted_concentration_threshold = (
            ai_assisted_concentration_threshold
            if ai_assisted_concentration_threshold is not None
            else int(meta.get("ai_assisted_concentration_threshold", _DEFAULT_AI_ASSISTED_CONCENTRATION_THRESHOLD))
        )
        self.cross_project_threshold = (
            cross_project_threshold
            if cross_project_threshold is not None
            else int(meta.get("cross_project_threshold", _DEFAULT_CROSS_PROJECT_THRESHOLD))
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Snyk issues export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        issues = self._issues_from_text(text)
        return self._build_results(issues, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Snyk issue content from a JSON or JSONL string."""
        issues = self._issues_from_text(content)
        return self._build_results(issues, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _issues_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"data":[]}`` / ``{"issues":[]}`` / JSONL / single object."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [e for e in doc if isinstance(e, dict)]
            if isinstance(doc, dict):
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                if "issues" in doc and isinstance(doc["issues"], list):
                    return [e for e in doc["issues"] if isinstance(e, dict)]
                # Single issue.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        issue_key: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "snyk",
            "source_tool_name": "snyk",
            "source_tool_version": "",
        }
        if issue_key is not None:
            provenance["issue_key"] = issue_key
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        issues: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — aggregate per-project criticals/highs and AI-assisted counts,
        # plus cross-project package occurrences.
        per_project_high_count: dict[str, int] = {}
        ai_assisted_count = 0
        package_critical_projects: dict[tuple[str, str], set[str]] = {}

        for issue in issues:
            attrs = _attrs_of(issue)
            severity = (attrs.get("effective_severity_level") or attrs.get("severity") or "").strip().lower()
            status = (attrs.get("status") or "").strip().lower()
            project_id = str(attrs.get("project_id") or "")
            ai_assisted = bool(attrs.get("ai_assisted", False))
            package_name = str(attrs.get("package_name") or "")
            package_version = str(attrs.get("package_version") or "")

            if status == "open" and severity in ("critical", "high") and project_id:
                per_project_high_count[project_id] = per_project_high_count.get(project_id, 0) + 1
            if ai_assisted:
                ai_assisted_count += 1
            if severity == "critical" and package_name and package_version and project_id:
                package_critical_projects.setdefault((package_name, package_version), set()).add(project_id)

        results: list[EvaluationResult] = []
        for issue in issues:
            res = self._parse_issue(issue, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        # ---- Synthetic findings ----

        # 1. High-density per-project broken-windows signal.
        for project_id, count in sorted(per_project_high_count.items()):
            if count > self.high_density_threshold:
                results.append(
                    self._synthetic_high_density(
                        project_id=project_id,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        # 2. AI-assisted concentration synthetic.
        if ai_assisted_count > self.ai_assisted_concentration_threshold:
            results.append(
                self._synthetic_ai_assisted(
                    count=ai_assisted_count,
                    file_sha256=file_sha256,
                )
            )

        # 3. Cross-project package pattern.
        for (pkg, ver), projects in sorted(package_critical_projects.items()):
            if len(projects) > self.cross_project_threshold:
                results.append(
                    self._synthetic_cross_project(
                        package_name=pkg,
                        package_version=ver,
                        projects=sorted(projects),
                        file_sha256=file_sha256,
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Per-issue parsing
    # ------------------------------------------------------------------

    def _parse_issue(
        self,
        issue: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        attrs = _attrs_of(issue)
        signal = _classify_attrs(attrs)
        # Issue key: prefer attributes.key, then top-level id.
        issue_key = str(attrs.get("key") or issue.get("id") or "") or None

        # If no rule fires, still emit a PASS audit-trail record so the file is
        # captured (mirrors sarif.py's clean-scan behavior, but per-issue).
        if signal is None:
            return self._neutral_record(issue, attrs, file_sha256=file_sha256, issue_key=issue_key)

        mapping = self._mappings.get(signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-03", "result": "FLAG"}))
        control_id = mapping.get("control", "PR-03")
        result_level = mapping.get("result", "FLAG")
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        evidence_data = _build_evidence_data(attrs, signal=signal)
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, issue_key=issue_key,
        )

        title_info = evidence_data.get("title", {})
        prefix = title_info.get("prefix", "") if isinstance(title_info, dict) else ""
        package_name = attrs.get("package_name") or ""
        detail_parts: list[str] = [signal]
        if prefix:
            detail_parts.append(prefix)
        if package_name:
            detail_parts.append(f"pkg={package_name}")
        detail = " | ".join(detail_parts)

        decision = (
            "BLOCK" if result_level == "FAIL"
            else "FLAG" if result_level == "FLAG"
            else "ALLOW"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"snyk-{(issue_key or uuid.uuid4().hex[:8]).replace(' ', '_')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snyk_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=control_name,
                    result=result_level,
                    detail=detail,
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=f"Snyk issue {issue_key or '<no-key>'} signal={signal}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _neutral_record(
        self,
        issue: dict[str, Any],
        attrs: dict[str, Any],
        *,
        file_sha256: str | None,
        issue_key: str | None,
    ) -> EvaluationResult:
        """Emit a PASS audit-trail record for issues no rule fired on."""
        evidence_data = _build_evidence_data(attrs, signal="none")
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, issue_key=issue_key,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"snyk-{(issue_key or uuid.uuid4().hex[:8]).replace(' ', '_')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snyk_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=f"Snyk issue {issue_key or '<no-key>'} captured (no rule fired)",
                    evidence_data=evidence_data,
                )
            ],
            decision="ALLOW",
            decision_reason=f"Snyk issue {issue_key or '<no-key>'} no-rule audit-trail",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    # ------------------------------------------------------------------
    # Synthetic builders
    # ------------------------------------------------------------------

    def _synthetic_high_density(
        self,
        *,
        project_id: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("high_density", _DEFAULT_SYNTHETICS["high_density"])
        control_id = synth.get("control", "DE-01")
        result_level = synth.get("result", "FAIL")
        synth_id = f"snyk-high-density-{project_id}"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "high_density",
            "project_id": project_id,
            "open_critical_high_count": count,
            "threshold": self.high_density_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_key=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snyk_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Snyk synthetic finding: project {project_id!r} has "
                        f"{count} open critical+high issues (threshold "
                        f"{self.high_density_threshold}) — broken-windows signal"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Snyk: synthetic high-density pattern for project {project_id!r}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_ai_assisted(
        self,
        *,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("ai_assisted_concentration", _DEFAULT_SYNTHETICS["ai_assisted_concentration"])
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        synth_id = "snyk-ai-assisted-concentration"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "ai_assisted_concentration",
            "ai_assisted_count": count,
            "threshold": self.ai_assisted_concentration_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_key=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snyk_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Snyk synthetic finding: {count} AI-assisted findings in scan "
                        f"(threshold {self.ai_assisted_concentration_threshold}) — agent quality drift"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason="Imported from Snyk: synthetic AI-assisted-concentration pattern",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_cross_project(
        self,
        *,
        package_name: str,
        package_version: str,
        projects: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("cross_project_pattern", _DEFAULT_SYNTHETICS["cross_project_pattern"])
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        synth_id = f"snyk-cross-project-{package_name}-{package_version}"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "cross_project_pattern",
            "package_name": package_name,
            "package_version": package_version,
            "projects": projects,
            "project_count": len(projects),
            "threshold": self.cross_project_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_key=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snyk_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Snyk synthetic finding: package {package_name}@{package_version} has "
                        f"a critical issue across {len(projects)} projects "
                        f"(threshold {self.cross_project_threshold}) — organization-wide exposure"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Snyk: synthetic cross-project pattern for "
                f"{package_name}@{package_version}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attrs_of(issue: dict[str, Any]) -> dict[str, Any]:
    """Return the issue's ``attributes`` block, or the issue itself for flat shapes."""
    attrs = issue.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return issue


def _build_evidence_data(attrs: dict[str, Any], *, signal: str) -> dict[str, Any]:
    """Capture sanitized evidence data for a Snyk issue."""
    title_info = _sanitize_title(attrs.get("title") if isinstance(attrs.get("title"), str) else None)
    code_path_norm = _normalize_code_file_path(
        attrs.get("code_file_path") if isinstance(attrs.get("code_file_path"), str) else None
    )
    ignored_reason_info = _hash_ignored_reason(
        attrs.get("ignored_reason") if attrs.get("ignored_reason") is not None else None
    )

    code_line_raw = attrs.get("code_line")
    code_line = code_line_raw if isinstance(code_line_raw, int) and not isinstance(code_line_raw, bool) else None

    cvss_score_raw = attrs.get("cvss_score")
    cvss_score = (
        cvss_score_raw if isinstance(cvss_score_raw, (int, float)) and not isinstance(cvss_score_raw, bool)
        else None
    )

    return {
        "signal": signal,
        "issue_key": str(attrs.get("key") or "") or None,
        "type": attrs.get("type"),
        "severity": attrs.get("severity"),
        "effective_severity_level": attrs.get("effective_severity_level"),
        "cvss_score": cvss_score,
        "cvss_vector": attrs.get("cvss_vector"),
        "exploit_maturity": attrs.get("exploit_maturity"),
        "status": attrs.get("status"),
        "is_fixable": attrs.get("is_fixable"),
        "is_patchable": attrs.get("is_patchable"),
        "is_pinnable": attrs.get("is_pinnable"),
        "is_upgradable": attrs.get("is_upgradable"),
        "is_ignored": attrs.get("is_ignored"),
        "is_disregarded": attrs.get("is_disregarded"),
        "package_name": attrs.get("package_name"),
        "package_version": attrs.get("package_version"),
        "fixed_in_version": attrs.get("fixed_in_version"),
        "language": attrs.get("language"),
        "scan_target_type": attrs.get("scan_target_type"),
        "project_id": attrs.get("project_id"),
        "project_name": attrs.get("project_name"),
        "org_id": attrs.get("org_id"),
        "ai_assisted": bool(attrs.get("ai_assisted", False)),
        "license": attrs.get("license"),
        "license_severity": attrs.get("license_severity"),
        "first_introduced": attrs.get("first_introduced"),
        "title": title_info,
        "code_file_path_normalized": code_path_norm,
        "code_line": code_line,
        "ignored_reason_redacted": ignored_reason_info,
    }
