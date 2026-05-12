# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Semgrep findings importer — converts ``semgrep --json`` output to AKSI EvaluationResults.

Semgrep (https://semgrep.dev) is the dominant developer-first SAST (static
analysis) platform: fast, custom-rule-friendly, and increasingly AI-aware. As
agents (Claude Code, Cursor, Devin, etc.) ship code, Semgrep is one of the
most likely places where insecure patterns surface — taint flows, command/SQL
injection, hardcoded credentials, broken crypto, and other vulnerability
classes that pure dependency scanners (Snyk SCA) miss. The SDK already has a
generic SARIF importer (Semgrep can also emit SARIF), but Semgrep's native
JSON contains richer metadata (confidence/likelihood/impact, CWE, OWASP,
``ai-generated``, ``validation_state``) that is dropped during SARIF
serialization.

This importer ingests Semgrep CLI JSON in four shapes:

  1. ``{"results":[...]}``   — canonical CLI envelope
  2. ``{"data":   [...]}``   — convenience envelope (some integrations)
  3. JSONL                    — one result per line
  4. single object            — a bare result

Mapping (see ``shared/mappings/semgrep-aksi-controls.json``):

  * extra.severity=ERROR   + category=security + confidence=HIGH   → PR-03 FAIL
  * extra.severity=ERROR   + category=security + confidence=MEDIUM → PR-03 FAIL
  * extra.severity=ERROR   + category=security + confidence=LOW    → PR-03 FLAG
  * extra.severity=WARNING + category=security                     → PR-03 FLAG
  * extra.severity=INFO    + category=security                     → PR-03 PASS
  * category=best-practice + severity=ERROR                        → PR-05 FLAG
  * category=correctness   + severity=ERROR                        → PR-03 FLAG
  * category=performance                                           → PR-05 PASS
  * cwe ∋ CWE-78/CWE-89/CWE-94/CWE-79                              → PR-03 FAIL  (top OWASP injections always FAIL)
  * cwe ∋ CWE-798                                                  → DE-01 FAIL  (secret in code)
  * cwe ∋ CWE-327 / CWE-330                                        → PR-04 FAIL  (crypto weakness)
  * validation_state=CONFIRMED_VALID                               → DE-01 FAIL  (Semgrep Pro confirmed real secret)
  * validation_state=CONFIRMED_INVALID                             → PR-05 PASS  (false-positive audit trail)
  * is_ignored=true                                                → PR-02 FLAG  (verify justification)
  * likelihood=HIGH + impact=HIGH                                  → PR-03 FAIL  (escalates any base mapping)

Synthetic findings:

  * > N ERRORs in same file (default 5) → PR-03 FLAG (broken-file signal)
  * > N ai-generated=true findings in scan (default 10) → PR-03 FLAG (agent quality drift)
  * Same vulnerability_class across > N distinct files (default 5)
    → PR-03 FLAG (systemic issue)

Sanitization (security-critical — Semgrep findings can carry sensitive data):

  * ``extra.message`` raw is NOT stored. Only its length + sha256 are captured;
    free-form messages can interpolate the matched code (e.g. the actual
    hardcoded secret value, the user-controlled SQL string).
  * ``metavars`` values are NEVER stored — they contain the literal user code
    that matched the pattern (often the very thing that's vulnerable).
  * ``rendered_fix`` raw is NOT stored. Only its length + sha256 are captured;
    fixes routinely include the surrounding source code.
  * ``path`` is normalized to ``directory/<.ext>`` (filename dropped) — this
    matches the Snyk-importer pattern. Filenames like ``aws-creds.json`` carry
    secret-bearing naming conventions; line numbers without source content are
    safe and useful, so they ARE preserved.
  * Original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``semgrep`` Python package — Semgrep is a
separate CLI; this importer is a pure JSON parser.
"""

from __future__ import annotations

import fnmatch  # noqa: F401  (parity with snyk.py / sarif.py — reserved for future glob mappings)
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
#   <repo>/python/src/ancilis/importers/semgrep.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "semgrep-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default mappings if the JSON file is missing/malformed; mirrors the canonical table.
_DEFAULT_MAPPINGS: dict[str, dict[str, str]] = {
    "security_error_high_confidence":   {"control": "PR-03", "result": "FAIL"},
    "security_error_medium_confidence": {"control": "PR-03", "result": "FAIL"},
    "security_error_low_confidence":    {"control": "PR-03", "result": "FLAG"},
    "security_warning":                 {"control": "PR-03", "result": "FLAG"},
    "security_info":                    {"control": "PR-03", "result": "PASS"},
    "best_practice_error":              {"control": "PR-05", "result": "FLAG"},
    "correctness_error":                {"control": "PR-03", "result": "FLAG"},
    "performance_any":                  {"control": "PR-05", "result": "PASS"},
    "critical_cwe_command_injection":   {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_sql_injection":       {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_code_injection":      {"control": "PR-03", "result": "FAIL"},
    "critical_cwe_xss":                 {"control": "PR-03", "result": "FAIL"},
    "hardcoded_credentials":            {"control": "DE-01", "result": "FAIL"},
    "broken_crypto":                    {"control": "PR-04", "result": "FAIL"},
    "validated_secret_confirmed":       {"control": "DE-01", "result": "FAIL"},
    "validated_secret_invalid":         {"control": "PR-05", "result": "PASS"},
    "is_ignored":                       {"control": "PR-02", "result": "FLAG"},
    "likelihood_impact_high":           {"control": "PR-03", "result": "FAIL"},
}

_DEFAULT_SYNTHETICS: dict[str, dict[str, str]] = {
    "high_density_per_file":     {"control": "PR-03", "result": "FLAG"},
    "ai_assisted_concentration": {"control": "PR-03", "result": "FLAG"},
    "cross_rule_pattern":        {"control": "PR-03", "result": "FLAG"},
}

_DEFAULT_HIGH_DENSITY_PER_FILE = 5
_DEFAULT_AI_ASSISTED_CONCENTRATION = 10
_DEFAULT_CROSS_RULE_THRESHOLD = 5

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
    """Load the semgrep-aksi-controls.json mapping; tolerate missing file."""
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


def _normalize_path(path: str | None) -> str | None:
    """Return ``directory/<ext>`` for a Semgrep finding path, dropping filename.

    A raw path like ``src/utils/aws-creds.json`` becomes ``src/utils/<.json>``;
    a raw path like ``app/handlers/login.py`` becomes ``app/handlers/<.py>``.
    Filename stems can carry secret-bearing naming conventions; the directory
    + extension is sufficient to triage the finding without leaking those.
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


def _extract_cwe_codes(cwe_list: Any) -> list[str]:
    """Extract canonical 'CWE-N' codes from Semgrep's metadata.cwe list.

    Semgrep stores CWE entries as full strings like
    ``"CWE-78: Improper Neutralization of Special Elements used in an OS Command"``.
    """
    codes: list[str] = []
    if not isinstance(cwe_list, list):
        return codes
    for entry in cwe_list:
        if not isinstance(entry, str):
            continue
        # Take the prefix up to the first colon or whitespace.
        head = entry.split(":", 1)[0].strip()
        head = head.split()[0] if head else head
        if head.upper().startswith("CWE-"):
            codes.append(head.upper())
    return codes


# ---------------------------------------------------------------------------
# Classification — pure function returning the signal key for a result
# ---------------------------------------------------------------------------


def _classify_result(
    res: dict[str, Any],
    *,
    critical_cwes: tuple[str, ...],
) -> str | None:
    """Return the canonical signal-key for a Semgrep result.

    Priority order (highest first):
        validated_secret_confirmed
        critical_cwe_* / hardcoded_credentials / broken_crypto
        likelihood_impact_high
        is_ignored
        validated_secret_invalid
        severity+category combos (security/correctness/best-practice/performance)
    """
    extra = res.get("extra") if isinstance(res.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

    severity = (extra.get("severity") or "").strip().upper()
    category = (metadata.get("category") or "").strip().lower()
    confidence = (metadata.get("confidence") or "").strip().upper()
    likelihood = (metadata.get("likelihood") or "").strip().upper()
    impact = (metadata.get("impact") or "").strip().upper()
    validation_state = extra.get("validation_state")
    is_ignored = bool(extra.get("is_ignored", False))
    cwe_codes = _extract_cwe_codes(metadata.get("cwe"))

    # 1. Confirmed-valid secret (Semgrep Pro validated) — top priority.
    if validation_state == "CONFIRMED_VALID":
        return "validated_secret_confirmed"

    # 2. Critical CWEs always FAIL regardless of confidence/severity.
    for cwe in cwe_codes:
        if cwe in critical_cwes and cwe in _CRITICAL_CWE_SIGNALS:
            return _CRITICAL_CWE_SIGNALS[cwe]

    # 3. likelihood=HIGH + impact=HIGH escalates to FAIL.
    if likelihood == "HIGH" and impact == "HIGH":
        return "likelihood_impact_high"

    # 4. is_ignored: governance flag (verify justification).
    if is_ignored:
        return "is_ignored"

    # 5. Confirmed-invalid secret: false-positive audit trail.
    if validation_state == "CONFIRMED_INVALID":
        return "validated_secret_invalid"

    # 6. Severity + category combos.
    if category == "security":
        if severity == "ERROR":
            if confidence == "HIGH":
                return "security_error_high_confidence"
            if confidence == "MEDIUM":
                return "security_error_medium_confidence"
            if confidence == "LOW":
                return "security_error_low_confidence"
            # Confidence unspecified — treat like MEDIUM (FAIL) to be conservative.
            return "security_error_medium_confidence"
        if severity == "WARNING":
            return "security_warning"
        if severity == "INFO":
            return "security_info"

    if category == "correctness" and severity == "ERROR":
        return "correctness_error"

    if category == "best-practice" and severity == "ERROR":
        return "best_practice_error"

    if category == "performance":
        return "performance_any"

    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SemgrepImporter:
    """Parse a Semgrep ``--json`` export and convert each result to an EvaluationResult."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        high_density_per_file: int | None = None,
        ai_assisted_concentration: int | None = None,
        cross_rule_threshold: int | None = None,
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

        self.high_density_per_file = (
            high_density_per_file
            if high_density_per_file is not None
            else int(meta.get("high_density_per_file", _DEFAULT_HIGH_DENSITY_PER_FILE))
        )
        self.ai_assisted_concentration = (
            ai_assisted_concentration
            if ai_assisted_concentration is not None
            else int(meta.get("ai_assisted_concentration", _DEFAULT_AI_ASSISTED_CONCENTRATION))
        )
        self.cross_rule_threshold = (
            cross_rule_threshold
            if cross_rule_threshold is not None
            else int(meta.get("cross_rule_threshold", _DEFAULT_CROSS_RULE_THRESHOLD))
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Semgrep JSON/JSONL export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        results = self._results_from_text(text)
        return self._build_results(results, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Semgrep JSON/JSONL content from a string."""
        results = self._results_from_text(content)
        return self._build_results(results, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _results_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"results":[]}`` / ``{"data":[]}`` / JSONL / single result."""
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
                if "results" in doc and isinstance(doc["results"], list):
                    return [e for e in doc["results"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single result.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "semgrep",
            "source_tool_name": "semgrep",
            "source_tool_version": "",
        }
        if finding_id is not None:
            provenance["finding_id"] = finding_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        findings: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — aggregate per-file ERROR counts, AI-generated counts,
        # and per-vulnerability-class file sets.
        per_file_error_count: dict[str, int] = {}
        ai_assisted_count = 0
        per_vuln_class_files: dict[str, set[str]] = {}

        for f in findings:
            extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
            metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            severity = (extra.get("severity") or "").strip().upper()
            path_raw = f.get("path") if isinstance(f.get("path"), str) else ""
            ai_generated = bool(metadata.get("ai-generated", False))
            vuln_class = metadata.get("vulnerability_class")

            if severity == "ERROR" and path_raw:
                per_file_error_count[path_raw] = per_file_error_count.get(path_raw, 0) + 1
            if ai_generated:
                ai_assisted_count += 1
            if isinstance(vuln_class, list) and path_raw:
                for vc in vuln_class:
                    if isinstance(vc, str) and vc:
                        per_vuln_class_files.setdefault(vc, set()).add(path_raw)
            elif isinstance(vuln_class, str) and vuln_class and path_raw:
                per_vuln_class_files.setdefault(vuln_class, set()).add(path_raw)

        results: list[EvaluationResult] = []
        for f in findings:
            res = self._parse_finding(f, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        # ---- Synthetic findings ----

        # 1. High-density per-file broken-file signal.
        for path_raw, count in sorted(per_file_error_count.items()):
            if count > self.high_density_per_file:
                results.append(
                    self._synthetic_high_density(
                        path_raw=path_raw,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        # 2. AI-assisted concentration synthetic.
        if ai_assisted_count > self.ai_assisted_concentration:
            results.append(
                self._synthetic_ai_assisted(
                    count=ai_assisted_count,
                    file_sha256=file_sha256,
                )
            )

        # 3. Cross-rule (vulnerability-class) systemic-issue synthetic.
        for vuln_class, paths in sorted(per_vuln_class_files.items()):
            if len(paths) > self.cross_rule_threshold:
                results.append(
                    self._synthetic_cross_rule(
                        vulnerability_class=vuln_class,
                        paths=sorted(paths),
                        file_sha256=file_sha256,
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Per-finding parsing
    # ------------------------------------------------------------------

    def _parse_finding(
        self,
        finding: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        signal = _classify_result(finding, critical_cwes=self._critical_cwes)
        finding_id = (
            str(finding.get("fingerprint") or finding.get("syntactic_id") or finding.get("check_id") or "")
            or None
        )

        if signal is None:
            return self._neutral_record(finding, file_sha256=file_sha256, finding_id=finding_id)

        mapping = self._mappings.get(signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-03", "result": "FLAG"}))
        control_id = mapping.get("control", "PR-03")
        result_level = mapping.get("result", "FLAG")
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        evidence_data = _build_evidence_data(finding, signal=signal)
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )

        check_id = evidence_data.get("check_id") or ""
        path_norm = evidence_data.get("path_normalized") or ""
        detail_parts: list[str] = [signal]
        if check_id:
            detail_parts.append(check_id)
        if path_norm:
            detail_parts.append(f"path={path_norm}")
        detail = " | ".join(detail_parts)

        decision = (
            "BLOCK" if result_level == "FAIL"
            else "FLAG" if result_level == "FLAG"
            else "ALLOW"
        )

        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"semgrep-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="semgrep_import",
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
            decision_reason=f"Semgrep finding {finding_id or '<no-id>'} signal={signal}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _neutral_record(
        self,
        finding: dict[str, Any],
        *,
        file_sha256: str | None,
        finding_id: str | None,
    ) -> EvaluationResult:
        """Emit a PASS audit-trail record for findings no rule fired on."""
        evidence_data = _build_evidence_data(finding, signal="none")
        evidence_data["source_provenance"] = self._source_provenance(
            file_sha256=file_sha256, finding_id=finding_id,
        )
        action_id_suffix = (finding_id or uuid.uuid4().hex[:8]).replace(" ", "_")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"semgrep-{action_id_suffix}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="semgrep_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=f"Semgrep finding {finding_id or '<no-id>'} captured (no rule fired)",
                    evidence_data=evidence_data,
                )
            ],
            decision="ALLOW",
            decision_reason=f"Semgrep finding {finding_id or '<no-id>'} no-rule audit-trail",
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
        path_raw: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("high_density_per_file", _DEFAULT_SYNTHETICS["high_density_per_file"])
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        path_norm = _normalize_path(path_raw) or "<unknown>"
        synth_id = f"semgrep-high-density-{hashlib.sha256(path_raw.encode('utf-8')).hexdigest()[:12]}"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "high_density_per_file",
            "path_normalized": path_norm,
            "error_count": count,
            "threshold": self.high_density_per_file,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="semgrep_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Semgrep synthetic finding: file {path_norm!r} has "
                        f"{count} ERROR-level findings (threshold "
                        f"{self.high_density_per_file}) — broken-file signal"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Semgrep: synthetic high-density pattern in {path_norm!r}"
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
        synth = self._synthetics.get(
            "ai_assisted_concentration", _DEFAULT_SYNTHETICS["ai_assisted_concentration"]
        )
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        synth_id = "semgrep-ai-assisted-concentration"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "ai_assisted_concentration",
            "ai_assisted_count": count,
            "threshold": self.ai_assisted_concentration,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="semgrep_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Semgrep synthetic finding: {count} ai-generated=true findings in scan "
                        f"(threshold {self.ai_assisted_concentration}) — agent quality drift"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason="Imported from Semgrep: synthetic AI-assisted-concentration pattern",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_cross_rule(
        self,
        *,
        vulnerability_class: str,
        paths: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("cross_rule_pattern", _DEFAULT_SYNTHETICS["cross_rule_pattern"])
        control_id = synth.get("control", "PR-03")
        result_level = synth.get("result", "FLAG")
        # Hash the class to keep the action_id stable but path-free.
        slug = hashlib.sha256(vulnerability_class.encode("utf-8")).hexdigest()[:12]
        synth_id = f"semgrep-cross-rule-{slug}"
        normalized_paths = sorted({_normalize_path(p) or "<unknown>" for p in paths})
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "cross_rule_pattern",
            "vulnerability_class": vulnerability_class,
            "paths_normalized": normalized_paths,
            "file_count": len(paths),
            "threshold": self.cross_rule_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, finding_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="semgrep_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Semgrep synthetic finding: vulnerability_class {vulnerability_class!r} "
                        f"appears across {len(paths)} distinct files (threshold "
                        f"{self.cross_rule_threshold}) — systemic issue"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Semgrep: synthetic cross-rule pattern for "
                f"{vulnerability_class!r}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )


# ---------------------------------------------------------------------------
# Evidence data builder
# ---------------------------------------------------------------------------


def _build_evidence_data(finding: dict[str, Any], *, signal: str) -> dict[str, Any]:
    """Capture sanitized evidence data for a Semgrep finding.

    Captures: check_id, path_normalized, severity, category, cwe list,
    owasp list, confidence, impact, likelihood, vulnerability_class,
    technology, validation_state, is_ignored, ai-generated, source-rule-url,
    fingerprint, syntactic_id, start/end line numbers, message_redacted
    (length+sha), rendered_fix_redacted (length+sha).

    NEVER captures: extra.message raw, metavars values, rendered_fix raw,
    full path filename.
    """
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

    check_id = finding.get("check_id") if isinstance(finding.get("check_id"), str) else None
    path_norm = _normalize_path(finding.get("path") if isinstance(finding.get("path"), str) else None)

    start = finding.get("start") if isinstance(finding.get("start"), dict) else {}
    end = finding.get("end") if isinstance(finding.get("end"), dict) else {}
    start_line = start.get("line") if isinstance(start.get("line"), int) and not isinstance(start.get("line"), bool) else None
    start_col = start.get("col") if isinstance(start.get("col"), int) and not isinstance(start.get("col"), bool) else None
    end_line = end.get("line") if isinstance(end.get("line"), int) and not isinstance(end.get("line"), bool) else None
    end_col = end.get("col") if isinstance(end.get("col"), int) and not isinstance(end.get("col"), bool) else None

    severity = extra.get("severity") if isinstance(extra.get("severity"), str) else None
    category = metadata.get("category") if isinstance(metadata.get("category"), str) else None
    confidence = metadata.get("confidence") if isinstance(metadata.get("confidence"), str) else None
    impact = metadata.get("impact") if isinstance(metadata.get("impact"), str) else None
    likelihood = metadata.get("likelihood") if isinstance(metadata.get("likelihood"), str) else None
    technology = metadata.get("technology") if isinstance(metadata.get("technology"), list) else None
    cwe_codes = _extract_cwe_codes(metadata.get("cwe"))
    owasp = metadata.get("owasp") if isinstance(metadata.get("owasp"), list) else None
    vuln_class_raw = metadata.get("vulnerability_class")
    if isinstance(vuln_class_raw, list):
        vulnerability_class: list[str] | None = [v for v in vuln_class_raw if isinstance(v, str)]
    elif isinstance(vuln_class_raw, str):
        vulnerability_class = [vuln_class_raw]
    else:
        vulnerability_class = None

    source_rule_url = metadata.get("source-rule-url") if isinstance(metadata.get("source-rule-url"), str) else None
    shortlink = metadata.get("shortlink") if isinstance(metadata.get("shortlink"), str) else None
    subcategory = metadata.get("subcategory") if isinstance(metadata.get("subcategory"), list) else None
    references = metadata.get("references") if isinstance(metadata.get("references"), list) else None
    ai_generated = bool(metadata.get("ai-generated", False))

    validation_state = extra.get("validation_state")
    is_ignored = bool(extra.get("is_ignored", False))

    fingerprint = finding.get("fingerprint") if isinstance(finding.get("fingerprint"), str) else None
    syntactic_id = finding.get("syntactic_id") if isinstance(finding.get("syntactic_id"), str) else None

    message_redacted = _hash_text(extra.get("message") if isinstance(extra.get("message"), str) else None)
    rendered_fix_redacted = _hash_text(extra.get("rendered_fix") if isinstance(extra.get("rendered_fix"), str) else None)

    return {
        "signal": signal,
        "check_id": check_id,
        "path_normalized": path_norm,
        "start_line": start_line,
        "start_col": start_col,
        "end_line": end_line,
        "end_col": end_col,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "impact": impact,
        "likelihood": likelihood,
        "technology": technology,
        "cwe": cwe_codes,
        "owasp": owasp,
        "vulnerability_class": vulnerability_class,
        "subcategory": subcategory,
        "references": references,
        "source_rule_url": source_rule_url,
        "shortlink": shortlink,
        "ai_assisted": ai_generated,
        "validation_state": validation_state,
        "is_ignored": is_ignored,
        "fingerprint": fingerprint,
        "syntactic_id": syntactic_id,
        "message_redacted": message_redacted,
        "rendered_fix_redacted": rendered_fix_redacted,
    }
