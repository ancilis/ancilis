"""SonarQube findings importer — converts ``/api/issues/search`` and quality-gate exports to AKSI EvaluationResults.

SonarQube (https://www.sonarsource.com/products/sonarqube/) is the dominant
code-quality + SAST platform: it surfaces bugs, vulnerabilities, code smells,
security hotspots, and now (2025+) explicit AI-generated-code analysis via
SonarQube AI CodeFix. As agents (Claude Code, Cursor, Devin, etc.) ship code,
SonarQube is one of the most likely places where the resulting issues
surface — distinct from Snyk (SCA) and Semgrep (custom rules), SonarQube has
rich quality dimensions (bugs, vulnerabilities, code smells, hotspots,
coverage) and a quality-gate concept that gates deployment on multiple
metrics simultaneously.

This importer ingests SonarQube exports in five shapes:

  1. ``{"issues":   [...]}``        — canonical issues-search envelope
  2. ``{"hotspots": [...]}``        — security-hotspots envelope
  3. ``{"quality_gate": {...}}``    — quality-gate-status envelope
  4. ``{"data":     [...]}``        — convenience envelope
  5. JSONL                            — one record per line
  6. mixed envelopes                  — ``{"issues":[...], "hotspots":[...], "quality_gate":{...}}``

Mapping (see ``shared/mappings/sonarqube-aksi-controls.json``):

  Issues:
    * type=VULNERABILITY severity=BLOCKER status=OPEN/CONFIRMED → PR-03 FAIL
    * type=VULNERABILITY severity=CRITICAL                      → PR-03 FAIL
    * type=VULNERABILITY severity=MAJOR                         → PR-03 FLAG
    * type=BUG severity=BLOCKER                                 → PR-03 FAIL
    * type=BUG severity=CRITICAL                                → PR-03 FLAG
    * type=CODE_SMELL                                           → PR-05 PASS
    * cwe ∋ CWE-78/89/94/79                                     → PR-03 FAIL  (top OWASP injections)
    * cwe ∋ CWE-798                                             → DE-01 FAIL  (hardcoded creds)
    * cwe ∋ CWE-327/330                                         → PR-04 FAIL  (broken crypto)
    * status=RESOLVED resolution=FALSE-POSITIVE                 → PR-05 PASS
    * status=RESOLVED resolution=WONTFIX sev∈{BLOCKER,CRITICAL} → PR-02 FAIL
    * impacts.softwareQuality=SECURITY sev∈{HIGH,BLOCKER}       → PR-04 FAIL
    * is_ai_generated=true sev∈{BLOCKER,CRITICAL}               → PR-03 FAIL
    * confidence=LOW sev∈{BLOCKER,CRITICAL}                     → PR-03 FLAG
    * new_code=true sev∈{BLOCKER,CRITICAL}                      → PR-03 FAIL
    * quality_gate_breached=true                                → PR-03 FAIL

  Hotspots:
    * status=TO_REVIEW vulnerability_probability=HIGH           → PR-04 FLAG
    * status=REVIEWED resolution=SAFE                           → PR-05 PASS
    * is_ai_generated=true vulnerability_probability=HIGH       → PR-04 FAIL

  Quality Gate:
    * status=ERROR + new_security_rating ≥ 3                    → PR-04 FAIL
    * status=ERROR + coverage threshold breach                  → PR-05 FLAG
    * status=ERROR + > 3 conditions                             → PR-03 FAIL
    * status=WARN                                               → PR-05 FLAG

Synthetic findings:

  * > N OPEN BLOCKER vulns in same project (default 5)
    → DE-01 FAIL  (broken-project signal)
  * > N is_ai_generated=true issues in scan (default 10)
    → PR-03 FLAG  (agent quality drift)
  * Same CWE > N occurrences (default 5) across distinct files
    → PR-03 FLAG  (systemic issue)

Sanitization (security-critical — SonarQube findings can carry sensitive data):

  * ``component`` is normalized to ``directory/<.ext>`` only — full paths can
    encode tenant/customer identifiers. Line numbers (``line``, ``textRange``
    offsets) without source content are preserved as they are useful and safe.
  * ``message`` raw is NOT stored. Only ``message_length`` (when supplied) and
    sha256 are captured; SonarQube messages can interpolate the matched code
    (e.g. the actual hardcoded secret value or unsanitized SQL string).
  * ``assignee`` raw is NOT stored. Only its length + sha256 are captured;
    full identities are PII.
  * ``author_name`` raw is NOT stored. Only its length + sha256 are captured.
  * ``hash`` (SonarQube line-hash) is reduced to its last 8 chars; full hash
    can fingerprint exact source content.
  * Issue ``key`` is preserved verbatim (opaque identifier).
  * ``project`` name is preserved verbatim — project names are structural and
    needed to attribute the high-density synthetic.
  * Original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``sonarqube-api`` Python package; this importer
is a pure JSON parser.
"""

from __future__ import annotations

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
#   <repo>/python/src/ancilis/importers/sonarqube.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "sonarqube-aksi-controls.json"
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
    "vulnerability_blocker_open":     {"control": "PR-03", "result": "FAIL"},
    "vulnerability_critical_open":    {"control": "PR-03", "result": "FAIL"},
    "vulnerability_major":            {"control": "PR-03", "result": "FLAG"},
    "bug_blocker":                    {"control": "PR-03", "result": "FAIL"},
    "bug_critical":                   {"control": "PR-03", "result": "FLAG"},
    "code_smell_audit":               {"control": "PR-05", "result": "PASS"},
    "critical_cwe_command_injection": {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_sql_injection":     {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_code_injection":    {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_xss":               {"control": "PR-03", "result": "FAIL"},
    "hardcoded_credentials":          {"control": "DE-01", "result": "FAIL"},
    "broken_crypto":                  {"control": "PR-04", "result": "FAIL"},
    "false_positive_resolution":      {"control": "PR-05", "result": "PASS"},
    "wontfix_blocker":                {"control": "PR-02", "result": "FAIL"},
    "security_impact_high":           {"control": "PR-04", "result": "FAIL"},
    "ai_generated_critical":          {"control": "PR-03", "result": "FAIL"},
    "low_confidence_critical":        {"control": "PR-03", "result": "FLAG"},
    "new_code_critical":              {"control": "PR-03", "result": "FAIL"},
    "quality_gate_breached":          {"control": "PR-03", "result": "FAIL"},
    "hotspot_to_review_high":         {"control": "PR-04", "result": "FLAG"},
    "hotspot_reviewed_safe":          {"control": "PR-05", "result": "PASS"},
    "ai_hotspot_high":                {"control": "PR-04", "result": "FAIL"},
    "qg_error_security_rating":       {"control": "PR-04", "result": "FAIL"},
    "qg_error_coverage":              {"control": "PR-05", "result": "FLAG"},
    "qg_error_multi_dim":             {"control": "PR-03", "result": "FAIL"},
    "qg_warn":                        {"control": "PR-05", "result": "FLAG"},
}

_DEFAULT_SYNTHETICS: dict[str, dict[str, str]] = {
    "high_density_blocker_per_project": {"control": "DE-01", "result": "FAIL"},
    "ai_generated_concentration":       {"control": "PR-03", "result": "FLAG"},
    "cross_cwe_pattern":                {"control": "PR-03", "result": "FLAG"},
}

_DEFAULT_HIGH_DENSITY_BLOCKER_PER_PROJECT = 5
_DEFAULT_AI_GENERATED_CONCENTRATION = 10
_DEFAULT_CROSS_CWE_THRESHOLD = 5

_DEFAULT_CRITICAL_CWES: tuple[str, ...] = (
    "CWE-78",
    "CWE-89",
    "CWE-94",
    "CWE-79",
    "CWE-798",
    "CWE-327",
    "CWE-330",
)

# CWE → critical-CWE signal-key (priority ordering preserved in classification).
_CRITICAL_CWE_SIGNALS: dict[str, str] = {
    "CWE-78":  "critical_cwe_command_injection",
    "CWE-89":  "critical_cwe_sql_injection",
    "CWE-94":  "critical_cwe_code_injection",
    "CWE-79":  "critical_cwe_xss",
    "CWE-798": "hardcoded_credentials",
    "CWE-327": "broken_crypto",
    "CWE-330": "broken_crypto",
}


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the sonarqube-aksi-controls.json mapping; tolerate missing file."""
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


def _hash_text(text: str | None) -> dict[str, Any] | None:
    """Reduce a free-form string to (length, sha256). Never store raw."""
    if text is None:
        return None
    if not isinstance(text, str):
        return None
    return {
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _normalize_component(component: str | None) -> str | None:
    """Return ``directory/<ext>`` for a SonarQube component, dropping filename.

    SonarQube component strings are formatted ``project-key:src/auth/login.js``;
    the project prefix and filename stem can encode tenant / customer
    identifiers. We strip the project prefix (if any), drop the filename stem,
    and keep ``directory/<.ext>`` only. Line numbers without source content
    are safe and useful, so they are preserved separately.
    """
    if not isinstance(component, str) or not component:
        return None
    # Strip project-key prefix ``proj:`` if present.
    if ":" in component:
        component = component.split(":", 1)[1]
    norm = component.replace("\\", "/").strip()
    if not norm:
        return None
    directory, filename = os.path.split(norm)
    _, ext = os.path.splitext(filename)
    ext_marker = f"<{ext}>" if ext else "<no-ext>"
    if directory:
        return f"{directory}/{ext_marker}"
    return ext_marker


def _truncate_hash(hash_val: str | None) -> str | None:
    """Reduce a SonarQube line-hash to its last 8 chars (safer fingerprint)."""
    if not isinstance(hash_val, str) or not hash_val:
        return None
    return hash_val[-8:]


def _normalize_cwe(cwe_list: Any) -> list[str]:
    """Normalize CWE entries to canonical ``CWE-N`` form.

    SonarQube returns CWEs as either ``"CWE-798"`` strings or bare ``"798"``
    strings depending on API version.
    """
    codes: list[str] = []
    if not isinstance(cwe_list, list):
        return codes
    for entry in cwe_list:
        if not isinstance(entry, str):
            continue
        head = entry.strip()
        if not head:
            continue
        if head.upper().startswith("CWE-"):
            codes.append(head.upper())
        elif head.isdigit():
            codes.append(f"CWE-{head}")
    return codes


def _str_list(value: Any) -> list[str]:
    """Return a list[str] from any input, dropping non-strings."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


# ---------------------------------------------------------------------------
# Classification — pure functions returning the signal key for a record
# ---------------------------------------------------------------------------


def _classify_issue(
    issue: dict[str, Any],
    *,
    critical_cwes: tuple[str, ...],
) -> str | None:
    """Return the canonical signal-key for a SonarQube issue.

    Priority order (highest first):
        quality_gate_breached → ai_generated_critical →
        critical_cwe_* / hardcoded_credentials / broken_crypto →
        wontfix_blocker → false_positive_resolution →
        security_impact_high → new_code_critical → low_confidence_critical →
        type+severity ladder (vulnerability/bug/code_smell)
    """
    issue_type = (issue.get("type") or "").strip().upper()
    severity = (issue.get("severity") or "").strip().upper()
    status = (issue.get("status") or "").strip().upper()
    resolution = (issue.get("resolution") or "").strip().upper() if issue.get("resolution") else None
    cwe_codes = _normalize_cwe(issue.get("cwe"))
    is_ai_generated = bool(issue.get("is_ai_generated", False))
    confidence = (issue.get("confidence") or "").strip().upper()
    new_code = bool(issue.get("new_code", False))
    quality_gate_breached = bool(issue.get("quality_gate_breached", False))

    impacts = issue.get("impacts") if isinstance(issue.get("impacts"), list) else []
    has_security_high = False
    for imp in impacts:
        if not isinstance(imp, dict):
            continue
        sw_quality = (imp.get("softwareQuality") or "").strip().upper()
        imp_sev = (imp.get("severity") or "").strip().upper()
        if sw_quality == "SECURITY" and imp_sev in ("HIGH", "BLOCKER"):
            has_security_high = True
            break

    # 1. Quality-gate breach attached to the issue dominates.
    if quality_gate_breached:
        return "quality_gate_breached"

    # 2. AI-generated critical/blocker — agent-introduced critical issue.
    if is_ai_generated and severity in ("BLOCKER", "CRITICAL"):
        return "ai_generated_critical"

    # 3. Critical CWEs always FAIL regardless of severity/status.
    for cwe in cwe_codes:
        if cwe in critical_cwes and cwe in _CRITICAL_CWE_SIGNALS:
            return _CRITICAL_CWE_SIGNALS[cwe]

    # 4. WONTFIX on critical/blocker = waiving without governance.
    if status == "RESOLVED" and resolution == "WONTFIX" and severity in ("BLOCKER", "CRITICAL"):
        return "wontfix_blocker"

    # 5. False-positive resolution = audit-trail PASS.
    if status == "RESOLVED" and resolution == "FALSE-POSITIVE":
        return "false_positive_resolution"

    # 6. Security software-quality impact at HIGH/BLOCKER.
    if has_security_high:
        return "security_impact_high"

    # 7. New-code critical/blocker — newly introduced critical issue.
    if new_code and severity in ("BLOCKER", "CRITICAL"):
        return "new_code_critical"

    # 8. Low-confidence critical/blocker — flag for re-review.
    if confidence == "LOW" and severity in ("BLOCKER", "CRITICAL"):
        return "low_confidence_critical"

    # 9. Type + severity ladder.
    if issue_type == "VULNERABILITY":
        if severity == "BLOCKER" and status in ("OPEN", "CONFIRMED", "REOPENED"):
            return "vulnerability_blocker_open"
        if severity == "BLOCKER":
            # BLOCKER but RESOLVED/CLOSED — fall through to no-signal (audit only).
            return None
        if severity == "CRITICAL":
            return "vulnerability_critical_open"
        if severity == "MAJOR":
            return "vulnerability_major"

    if issue_type == "BUG":
        if severity == "BLOCKER":
            return "bug_blocker"
        if severity == "CRITICAL":
            return "bug_critical"

    if issue_type == "CODE_SMELL":
        return "code_smell_audit"

    return None


def _classify_hotspot(hotspot: dict[str, Any]) -> str | None:
    """Return the signal-key for a SonarQube security hotspot."""
    status = (hotspot.get("status") or "").strip().upper()
    resolution = (hotspot.get("resolution") or "").strip().upper() if hotspot.get("resolution") else None
    probability = (hotspot.get("vulnerability_probability") or "").strip().upper()
    is_ai_generated = bool(hotspot.get("is_ai_generated", False))

    # AI-introduced HIGH-probability hotspot — most severe.
    if is_ai_generated and probability == "HIGH":
        return "ai_hotspot_high"

    if status == "TO_REVIEW" and probability == "HIGH":
        return "hotspot_to_review_high"

    if status == "REVIEWED" and resolution == "SAFE":
        return "hotspot_reviewed_safe"

    return None


def _classify_quality_gate(qg: dict[str, Any]) -> str | None:
    """Return the signal-key for a SonarQube quality-gate record.

    Priority (highest first):
        qg_error_multi_dim   (status=ERROR + > 3 conditions)
        qg_error_security_rating
        qg_error_coverage
        qg_warn
    """
    status = (qg.get("status") or "").strip().upper()
    conditions = qg.get("conditions") if isinstance(qg.get("conditions"), list) else []
    error_conditions = [
        c for c in conditions
        if isinstance(c, dict) and (c.get("status") or "").strip().upper() == "ERROR"
    ]

    if status == "ERROR":
        # Multi-dimension breakdown takes precedence.
        if len(error_conditions) > 3:
            return "qg_error_multi_dim"
        # Inspect specific conditions.
        for cond in error_conditions:
            metric = (cond.get("metric") or "").strip().lower()
            if metric in ("new_security_rating", "security_rating"):
                actual_raw = cond.get("actual_value")
                try:
                    actual_int = int(str(actual_raw))
                except (TypeError, ValueError):
                    actual_int = 0
                if actual_int >= 3:
                    return "qg_error_security_rating"
            if "coverage" in metric:
                return "qg_error_coverage"
        # ERROR without a recognized condition — still a deployment-block.
        return "qg_error_multi_dim"

    if status == "WARN":
        return "qg_warn"

    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SonarQubeImporter:
    """Parse SonarQube issues / hotspots / quality-gate exports to EvaluationResults."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        high_density_blocker_per_project: int | None = None,
        ai_generated_concentration: int | None = None,
        cross_cwe_threshold: int | None = None,
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

        raw_critical_cwes = meta.get("critical_cwes") if isinstance(meta, dict) else None
        if isinstance(raw_critical_cwes, list) and raw_critical_cwes:
            self._critical_cwes: tuple[str, ...] = tuple(
                str(c).upper() for c in raw_critical_cwes if isinstance(c, str)
            )
        else:
            self._critical_cwes = _DEFAULT_CRITICAL_CWES

        self.high_density_blocker_per_project = (
            high_density_blocker_per_project
            if high_density_blocker_per_project is not None
            else int(meta.get("high_density_blocker_per_project", _DEFAULT_HIGH_DENSITY_BLOCKER_PER_PROJECT))
        )
        self.ai_generated_concentration = (
            ai_generated_concentration
            if ai_generated_concentration is not None
            else int(meta.get("ai_generated_concentration", _DEFAULT_AI_GENERATED_CONCENTRATION))
        )
        self.cross_cwe_threshold = (
            cross_cwe_threshold
            if cross_cwe_threshold is not None
            else int(meta.get("cross_cwe_threshold", _DEFAULT_CROSS_CWE_THRESHOLD))
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a SonarQube JSON/JSONL export file from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        issues, hotspots, quality_gates = self._records_from_text(text)
        return self._build_results(
            issues=issues, hotspots=hotspots, quality_gates=quality_gates, file_sha256=file_sha256,
        )

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse SonarQube JSON/JSONL content from a string."""
        issues, hotspots, quality_gates = self._records_from_text(content)
        return self._build_results(
            issues=issues, hotspots=hotspots, quality_gates=quality_gates, file_sha256=None,
        )

    # -- Internals ----------------------------------------------------------

    def _records_from_text(
        self, text: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Detect ``{"issues":[]}`` / ``{"hotspots":[]}`` / ``{"quality_gate":{...}}`` /
        ``{"data":[]}`` / JSONL / single object. Returns
        (issues, hotspots, quality_gates).
        """
        stripped = text.lstrip()
        if not stripped:
            return [], [], []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return self._partition_records(list(_iter_jsonl(text)))
            if isinstance(doc, list):
                return self._partition_records([e for e in doc if isinstance(e, dict)])
            if isinstance(doc, dict):
                issues: list[dict[str, Any]] = []
                hotspots: list[dict[str, Any]] = []
                quality_gates: list[dict[str, Any]] = []
                if "issues" in doc and isinstance(doc["issues"], list):
                    issues.extend(e for e in doc["issues"] if isinstance(e, dict))
                if "hotspots" in doc and isinstance(doc["hotspots"], list):
                    hotspots.extend(e for e in doc["hotspots"] if isinstance(e, dict))
                if "quality_gate" in doc and isinstance(doc["quality_gate"], dict):
                    quality_gates.append(doc["quality_gate"])
                if "data" in doc and isinstance(doc["data"], list):
                    di, dh, dq = self._partition_records(
                        [e for e in doc["data"] if isinstance(e, dict)]
                    )
                    issues.extend(di)
                    hotspots.extend(dh)
                    quality_gates.extend(dq)
                if issues or hotspots or quality_gates:
                    return issues, hotspots, quality_gates
                # Bare single record.
                return self._partition_records([doc])
            return [], [], []
        return self._partition_records(list(_iter_jsonl(text)))

    @staticmethod
    def _partition_records(
        records: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Auto-detect record kind by structural signals.

        - ``status`` ∈ {OK, WARN, ERROR} + ``conditions`` → quality-gate
        - ``vulnerability_probability`` or ``hotspot_status`` → hotspot
        - everything else with a ``rule`` / ``component`` / ``key`` → issue
        """
        issues: list[dict[str, Any]] = []
        hotspots: list[dict[str, Any]] = []
        quality_gates: list[dict[str, Any]] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            status_val = (rec.get("status") or "").strip().upper() if isinstance(rec.get("status"), str) else ""
            # An issue can carry an ``is_security_hotspot`` flag and still be an
            # issue — we only treat a record as a hotspot when it has a non-null
            # ``vulnerability_probability`` or a non-null ``hotspot_status`` AND
            # no issue-only field like ``type``.
            has_hotspot_signal = (
                rec.get("vulnerability_probability") is not None
                or (rec.get("hotspot_status") is not None and not rec.get("type"))
            )
            if has_hotspot_signal:
                hotspots.append(rec)
                continue
            if "conditions" in rec and status_val in ("OK", "WARN", "ERROR") and not rec.get("type"):
                quality_gates.append(rec)
                continue
            issues.append(rec)
        return issues, hotspots, quality_gates

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "sonarqube",
            "source_tool_name": "sonarqube",
            "source_tool_version": "",
        }
        if finding_id is not None:
            provenance["finding_id"] = finding_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        *,
        issues: list[dict[str, Any]],
        hotspots: list[dict[str, Any]],
        quality_gates: list[dict[str, Any]],
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — aggregate per-project OPEN BLOCKER vulns, AI-generated
        # counts, and per-CWE file sets.
        per_project_blocker_count: dict[str, int] = {}
        ai_generated_count = 0
        per_cwe_components: dict[str, set[str]] = {}

        for issue in issues:
            issue_type = (issue.get("type") or "").strip().upper()
            severity = (issue.get("severity") or "").strip().upper()
            status = (issue.get("status") or "").strip().upper()
            project = str(issue.get("project") or "")
            component = str(issue.get("component") or "")
            cwe_codes = _normalize_cwe(issue.get("cwe"))
            is_ai_generated = bool(issue.get("is_ai_generated", False))

            if (
                issue_type == "VULNERABILITY"
                and severity == "BLOCKER"
                and status in ("OPEN", "CONFIRMED", "REOPENED")
                and project
            ):
                per_project_blocker_count[project] = per_project_blocker_count.get(project, 0) + 1
            if is_ai_generated:
                ai_generated_count += 1
            if component and cwe_codes:
                for cwe in cwe_codes:
                    per_cwe_components.setdefault(cwe, set()).add(component)

        results: list[EvaluationResult] = []

        for issue in issues:
            res = self._parse_issue(issue, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        for hotspot in hotspots:
            res = self._parse_hotspot(hotspot, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        for qg in quality_gates:
            res = self._parse_quality_gate(qg, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        # ---- Synthetic findings ----

        # 1. High-density per-project broken-project signal.
        for project, count in sorted(per_project_blocker_count.items()):
            if count > self.high_density_blocker_per_project:
                results.append(
                    self._synthetic_high_density(
                        project=project,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        # 2. AI-generated concentration synthetic.
        if ai_generated_count > self.ai_generated_concentration:
            results.append(
                self._synthetic_ai_generated(
                    count=ai_generated_count,
                    file_sha256=file_sha256,
                )
            )

        # 3. Cross-CWE systemic-issue synthetic.
        for cwe, components in sorted(per_cwe_components.items()):
            if len(components) > self.cross_cwe_threshold:
                results.append(
                    self._synthetic_cross_cwe(
                        cwe=cwe,
                        components=sorted(components),
                        file_sha256=file_sha256,
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Per-record parsing
    # ------------------------------------------------------------------

    def _parse_issue(
        self,
        issue: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        signal = _classify_issue(issue, critical_cwes=self._critical_cwes)
        finding_id = str(issue.get("key") or "") or None

        if signal is None:
            return self._neutral_issue_record(issue, file_sha256=file_sha256, finding_id=finding_id)

        return self._issue_eval_result(
            issue=issue, signal=signal, finding_id=finding_id, file_sha256=file_sha256,
        )

    def _issue_eval_result(
        self,
        *,
        issue: dict[str, Any],
        signal: str,
        finding_id: str | None,
        file_sha256: str | None,
    ) -> EvaluationResult:
        mapping = self._mappings.get(
            signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-03", "result": "FLAG"})
        )
        control_id = mapping.get("control", "PR-03")
        result_level = mapping.get("result", "FLAG")
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        evidence_data = _build_issue_evidence(issue, signal=signal)
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )

        rule = evidence_data.get("rule") or ""
        component_norm = evidence_data.get("component_normalized") or ""
        detail_parts: list[str] = [signal]
        if rule:
            detail_parts.append(rule)
        if component_norm:
            detail_parts.append(f"component={component_norm}")
        detail = " | ".join(detail_parts)

        decision = (
            "BLOCK" if result_level == "FAIL"
            else "FLAG" if result_level == "FLAG"
            else "ALLOW"
        )

        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sonarqube-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
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
            decision_reason=f"SonarQube issue {finding_id or '<no-id>'} signal={signal}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _neutral_issue_record(
        self,
        issue: dict[str, Any],
        *,
        file_sha256: str | None,
        finding_id: str | None,
    ) -> EvaluationResult:
        """Emit a PASS audit-trail record for issues no rule fired on."""
        evidence_data = _build_issue_evidence(issue, signal="none")
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )
        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sonarqube-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=f"SonarQube issue {finding_id or '<no-id>'} captured (no rule fired)",
                    evidence_data=evidence_data,
                )
            ],
            decision="ALLOW",
            decision_reason=f"SonarQube issue {finding_id or '<no-id>'} no-rule audit-trail",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _parse_hotspot(
        self,
        hotspot: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        signal = _classify_hotspot(hotspot)
        finding_id = str(hotspot.get("key") or "") or None

        if signal is None:
            return self._neutral_hotspot_record(hotspot, file_sha256=file_sha256, finding_id=finding_id)

        mapping = self._mappings.get(
            signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-04", "result": "FLAG"})
        )
        control_id = mapping.get("control", "PR-04")
        result_level = mapping.get("result", "FLAG")
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        evidence_data = _build_hotspot_evidence(hotspot, signal=signal)
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )

        rule = evidence_data.get("rule") or ""
        component_norm = evidence_data.get("component_normalized") or ""
        detail_parts: list[str] = [signal]
        if rule:
            detail_parts.append(rule)
        if component_norm:
            detail_parts.append(f"component={component_norm}")
        detail = " | ".join(detail_parts)

        decision = (
            "BLOCK" if result_level == "FAIL"
            else "FLAG" if result_level == "FLAG"
            else "ALLOW"
        )

        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sonarqube-hotspot-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
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
            decision_reason=f"SonarQube hotspot {finding_id or '<no-id>'} signal={signal}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _neutral_hotspot_record(
        self,
        hotspot: dict[str, Any],
        *,
        file_sha256: str | None,
        finding_id: str | None,
    ) -> EvaluationResult:
        evidence_data = _build_hotspot_evidence(hotspot, signal="none")
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )
        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sonarqube-hotspot-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=f"SonarQube hotspot {finding_id or '<no-id>'} captured (no rule fired)",
                    evidence_data=evidence_data,
                )
            ],
            decision="ALLOW",
            decision_reason=f"SonarQube hotspot {finding_id or '<no-id>'} no-rule audit-trail",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _parse_quality_gate(
        self,
        qg: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        signal = _classify_quality_gate(qg)
        finding_id = str(qg.get("project") or qg.get("id") or "") or None

        if signal is None:
            return None  # status=OK quality-gate is silent (deployment passes).

        mapping = self._mappings.get(
            signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-03", "result": "FLAG"})
        )
        control_id = mapping.get("control", "PR-03")
        result_level = mapping.get("result", "FLAG")
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        evidence_data = _build_quality_gate_evidence(qg, signal=signal)
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )

        status = evidence_data.get("status") or ""
        detail = f"{signal} | quality_gate_status={status}"

        decision = (
            "BLOCK" if result_level == "FAIL"
            else "FLAG" if result_level == "FLAG"
            else "ALLOW"
        )

        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sonarqube-qg-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
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
            decision_reason=f"SonarQube quality-gate {finding_id or '<no-id>'} signal={signal}",
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
        project: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get(
            "high_density_blocker_per_project",
            _DEFAULT_SYNTHETICS["high_density_blocker_per_project"],
        )
        control_id = synth.get("control", "DE-01")
        result_level = synth.get("result", "FAIL")
        synth_id = f"sonarqube-high-density-{hashlib.sha256(project.encode('utf-8')).hexdigest()[:12]}"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "high_density_blocker_per_project",
            "project": project,
            "open_blocker_vuln_count": count,
            "threshold": self.high_density_blocker_per_project,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"SonarQube synthetic finding: project {project!r} has "
                        f"{count} OPEN BLOCKER vulnerabilities (threshold "
                        f"{self.high_density_blocker_per_project}) — broken-project signal"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from SonarQube: synthetic high-density pattern in project {project!r}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_ai_generated(
        self,
        *,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get(
            "ai_generated_concentration", _DEFAULT_SYNTHETICS["ai_generated_concentration"]
        )
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        synth_id = "sonarqube-ai-generated-concentration"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "ai_generated_concentration",
            "ai_generated_count": count,
            "threshold": self.ai_generated_concentration,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"SonarQube synthetic finding: {count} is_ai_generated=true issues in scan "
                        f"(threshold {self.ai_generated_concentration}) — agent quality drift"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason="Imported from SonarQube: synthetic AI-generated-concentration pattern",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_cross_cwe(
        self,
        *,
        cwe: str,
        components: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("cross_cwe_pattern", _DEFAULT_SYNTHETICS["cross_cwe_pattern"])
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        slug = hashlib.sha256(cwe.encode("utf-8")).hexdigest()[:12]
        synth_id = f"sonarqube-cross-cwe-{slug}"
        normalized_components = sorted({_normalize_component(c) or "<unknown>" for c in components})
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "cross_cwe_pattern",
            "cwe": cwe,
            "components_normalized": normalized_components,
            "file_count": len(components),
            "threshold": self.cross_cwe_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sonarqube_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"SonarQube synthetic finding: CWE {cwe} appears across "
                        f"{len(components)} distinct components (threshold "
                        f"{self.cross_cwe_threshold}) — systemic issue"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from SonarQube: synthetic cross-CWE pattern for {cwe}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )


# ---------------------------------------------------------------------------
# Evidence data builders
# ---------------------------------------------------------------------------


def _build_issue_evidence(issue: dict[str, Any], *, signal: str) -> dict[str, Any]:
    """Capture sanitized evidence data for a SonarQube issue.

    Captures: rule, severity, type, status, resolution, cwe list, owaspTop10,
    sansTop25, attribute (clean-code attribute), impacts list,
    is_ai_generated, confidence, new_code, line, project (verbatim — needed
    for synthetic), quality_gate_breached, debt, effort, hotspot_status,
    is_security_hotspot, creationDate, updateDate, textRange (line-level
    only), component_normalized (directory/<.ext>), assignee_redacted,
    author_redacted, hash_truncated, message_redacted.

    NEVER captures: full component path including filename stem, raw message,
    raw assignee, raw author_name, raw hash, raw textRange offsets are kept
    (they are line-level structural data and don't carry source content).
    """
    text_range_raw = issue.get("textRange") if isinstance(issue.get("textRange"), dict) else {}
    text_range: dict[str, Any] = {}
    for key in ("startLine", "endLine", "startOffset", "endOffset"):
        v = text_range_raw.get(key)
        if isinstance(v, int) and not isinstance(v, bool):
            text_range[key] = v

    line_raw = issue.get("line")
    line = line_raw if isinstance(line_raw, int) and not isinstance(line_raw, bool) else None

    message_length_raw = issue.get("message_length")
    message_length = (
        message_length_raw if isinstance(message_length_raw, int) and not isinstance(message_length_raw, bool)
        else None
    )

    impacts_raw = issue.get("impacts") if isinstance(issue.get("impacts"), list) else []
    impacts: list[dict[str, str]] = []
    for imp in impacts_raw:
        if not isinstance(imp, dict):
            continue
        sw_quality = imp.get("softwareQuality") if isinstance(imp.get("softwareQuality"), str) else None
        sev = imp.get("severity") if isinstance(imp.get("severity"), str) else None
        if sw_quality and sev:
            impacts.append({"softwareQuality": sw_quality, "severity": sev})

    return {
        "signal": signal,
        "key": str(issue.get("key") or "") or None,
        "rule": issue.get("rule") if isinstance(issue.get("rule"), str) else None,
        "severity": issue.get("severity") if isinstance(issue.get("severity"), str) else None,
        "type": issue.get("type") if isinstance(issue.get("type"), str) else None,
        "status": issue.get("status") if isinstance(issue.get("status"), str) else None,
        "resolution": issue.get("resolution") if isinstance(issue.get("resolution"), str) else None,
        "cwe": _normalize_cwe(issue.get("cwe")),
        "owaspTop10": _str_list(issue.get("owaspTop10")),
        "sansTop25": _str_list(issue.get("sansTop25")),
        "tags": _str_list(issue.get("tags")),
        "attribute": issue.get("attribute") if isinstance(issue.get("attribute"), str) else None,
        "impacts": impacts,
        "is_ai_generated": bool(issue.get("is_ai_generated", False)),
        "ai_assisted": bool(issue.get("is_ai_generated", False)),
        "confidence": issue.get("confidence") if isinstance(issue.get("confidence"), str) else None,
        "new_code": bool(issue.get("new_code", False)),
        "line": line,
        "textRange": text_range or None,
        "project": str(issue.get("project") or "") or None,
        "component_normalized": _normalize_component(
            issue.get("component") if isinstance(issue.get("component"), str) else None
        ),
        "is_security_hotspot": bool(issue.get("is_security_hotspot", False)),
        "hotspot_status": issue.get("hotspot_status") if isinstance(issue.get("hotspot_status"), str) else None,
        "quality_gate_breached": bool(issue.get("quality_gate_breached", False)),
        "effort": issue.get("effort") if isinstance(issue.get("effort"), str) else None,
        "debt": issue.get("debt") if isinstance(issue.get("debt"), str) else None,
        "creationDate": issue.get("creationDate") if isinstance(issue.get("creationDate"), str) else None,
        "updateDate": issue.get("updateDate") if isinstance(issue.get("updateDate"), str) else None,
        "message_length": message_length,
        "message_redacted": _hash_text(issue.get("message") if isinstance(issue.get("message"), str) else None),
        "assignee_redacted": _hash_text(issue.get("assignee") if isinstance(issue.get("assignee"), str) else None),
        "author_redacted": _hash_text(
            issue.get("author_name") if isinstance(issue.get("author_name"), str) else None
        ),
        "hash_truncated": _truncate_hash(issue.get("hash") if isinstance(issue.get("hash"), str) else None),
    }


def _build_hotspot_evidence(hotspot: dict[str, Any], *, signal: str) -> dict[str, Any]:
    """Capture sanitized evidence data for a SonarQube security hotspot."""
    line_raw = hotspot.get("line")
    line = line_raw if isinstance(line_raw, int) and not isinstance(line_raw, bool) else None

    return {
        "signal": signal,
        "key": str(hotspot.get("key") or "") or None,
        "rule": hotspot.get("rule") if isinstance(hotspot.get("rule"), str) else None,
        "status": hotspot.get("status") if isinstance(hotspot.get("status"), str) else None,
        "resolution": hotspot.get("resolution") if isinstance(hotspot.get("resolution"), str) else None,
        "vulnerability_probability": (
            hotspot.get("vulnerability_probability")
            if isinstance(hotspot.get("vulnerability_probability"), str) else None
        ),
        "is_ai_generated": bool(hotspot.get("is_ai_generated", False)),
        "ai_assisted": bool(hotspot.get("is_ai_generated", False)),
        "line": line,
        "project": str(hotspot.get("project") or "") or None,
        "component_normalized": _normalize_component(
            hotspot.get("component") if isinstance(hotspot.get("component"), str) else None
        ),
        "creationDate": hotspot.get("creationDate") if isinstance(hotspot.get("creationDate"), str) else None,
        "updateDate": hotspot.get("updateDate") if isinstance(hotspot.get("updateDate"), str) else None,
        "message_redacted": _hash_text(
            hotspot.get("message") if isinstance(hotspot.get("message"), str) else None
        ),
        "assignee_redacted": _hash_text(
            hotspot.get("assignee") if isinstance(hotspot.get("assignee"), str) else None
        ),
    }


def _build_quality_gate_evidence(qg: dict[str, Any], *, signal: str) -> dict[str, Any]:
    """Capture sanitized evidence data for a quality-gate record."""
    raw_conditions = qg.get("conditions") if isinstance(qg.get("conditions"), list) else []
    conditions: list[dict[str, Any]] = []
    for cond in raw_conditions:
        if not isinstance(cond, dict):
            continue
        c: dict[str, Any] = {}
        for key in ("metric", "actual_value", "status", "comparator", "error_threshold"):
            v = cond.get(key)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                c[key] = v
        if c:
            conditions.append(c)

    return {
        "signal": signal,
        "status": qg.get("status") if isinstance(qg.get("status"), str) else None,
        "project": str(qg.get("project") or "") or None,
        "conditions": conditions,
        "condition_count": len(conditions),
        "error_condition_count": sum(
            1 for c in conditions if (c.get("status") or "").upper() == "ERROR"
        ),
    }
