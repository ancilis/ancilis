"""Composio tool-execution audit importer — maps third-party agent tool calls to AKSI controls.

Composio (https://composio.dev) is an agent tool platform that exposes 250+
third-party integrations (Gmail, Slack, GitHub, Salesforce, Jira, Notion, ...)
as connectable actions for autonomous agents. Each tool call carries its own
auth scope, optional approval state, and external destination risk: a
``GMAIL_SEND_EMAIL`` action is qualitatively different from an internal LLM
completion because it can move data to a third-party SaaS or external recipient.

This importer ingests the ``/api/v1/actions/executed`` and
``/api/v1/triggers/logs`` payloads in three on-disk shapes:

  1. ``{"executions": [...]}`` — primary executions envelope
  2. ``{"data": [...]}``        — generic data envelope
  3. JSONL                       — one execution per line

Signal mapping (see shared/mappings/composio-aksi-controls.json):
  * ``result_status=success`` & ``approval_status=approved``       → PR-02 PASS
  * ``result_status=success`` & ``approval_required=true`` &
    ``approval_status`` is null                                    → PR-02 FAIL  (missing approval)
  * ``result_status=success`` & ``approval_required=false``        → PR-02 PASS
  * ``result_status=failure``                                      → DE-01 FAIL
  * ``result_status=rate_limited``                                 → PR-02 FLAG  (capacity / abuse)
  * ``result_status=auth_expired``                                 → PR-01 FLAG  (identity / re-auth)
  * ``approval_status=denied``                                     → PR-05 PASS  (audit trail of denial)
  * ``external_destination_kind in {"email","chat","crm"}``        → PR-04 FLAG  (exfil surface)
  * ``triggered_by=webhook``                                       → PR-01 FLAG  (external trigger)
  * ``triggered_by=scheduler``                                     → PR-05 PASS  (audit-trail expected)
  * ``redact_pii_in_input=false`` & destination in
    ``{"email","chat"}``                                           → PR-04 FLAG  (PII surface)
  * ``scopes_used`` matches a broad-scope pattern (``*.write``,
    ``admin.*``, ``*.delete``)                                     → PR-02 FLAG
  * cross-app pattern: same ``agent_id`` touching > N apps in
    the export (default N=5)                                       → PR-02 FLAG  (synthetic finding)

Sanitization: input parameter values are NEVER stored. Only the
``input_param_keys`` array and a count are surfaced — never raw email bodies,
chat messages, or record payloads. The original file is hashed (sha256) for
source provenance.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/composio-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/composio.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "composio-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CROSS_APP_THRESHOLD = 5
_DEFAULT_BROAD_SCOPE_PATTERNS: tuple[str, ...] = ("*.write", "admin.*", "*.delete")
_DEFAULT_EXTERNAL_DESTINATIONS: frozenset[str] = frozenset({"email", "chat", "crm"})
_DEFAULT_PII_DESTINATIONS: frozenset[str] = frozenset({"email", "chat"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the composio-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


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


def _scopes_match_broad(
    scopes: list[str], patterns: tuple[str, ...]
) -> list[str]:
    """Return any scopes that match a broad-scope glob pattern."""
    hits: list[str] = []
    for scope in scopes:
        for pattern in patterns:
            if fnmatch.fnmatchcase(scope, pattern):
                hits.append(scope)
                break
    return hits


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ComposioImporter:
    """Parse a Composio tool-execution export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_app_threshold: int | None = None,
        broad_scope_patterns: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Cross-app threshold precedence: explicit arg > mapping metadata > default.
        if cross_app_threshold is not None:
            self.cross_app_threshold = int(cross_app_threshold)
        else:
            self.cross_app_threshold = int(
                meta.get("cross_app_threshold", _DEFAULT_CROSS_APP_THRESHOLD)
            )
        # Broad-scope patterns precedence: explicit arg > mapping metadata > default.
        if broad_scope_patterns is not None:
            self.broad_scope_patterns = tuple(str(p) for p in broad_scope_patterns)
        else:
            meta_patterns = meta.get("broad_scope_patterns")
            if isinstance(meta_patterns, list) and meta_patterns:
                self.broad_scope_patterns = tuple(str(p) for p in meta_patterns)
            else:
                self.broad_scope_patterns = _DEFAULT_BROAD_SCOPE_PATTERNS
        # External-destination kinds (PR-04 surface).
        meta_ext = meta.get("external_destination_kinds")
        if isinstance(meta_ext, list) and meta_ext:
            self.external_destination_kinds = frozenset(str(k) for k in meta_ext)
        else:
            self.external_destination_kinds = _DEFAULT_EXTERNAL_DESTINATIONS
        # PII destination kinds (subset where unredacted PII matters).
        meta_pii = meta.get("pii_destination_kinds")
        if isinstance(meta_pii, list) and meta_pii:
            self.pii_destination_kinds = frozenset(str(k) for k in meta_pii)
        else:
            self.pii_destination_kinds = _DEFAULT_PII_DESTINATIONS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Composio export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        executions = self._executions_from_text(text)
        return self._build_results(executions, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Composio export content from a JSON or JSONL string."""
        executions = self._executions_from_text(content)
        return self._build_results(executions, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _executions_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"executions": [...]}`` / ``{"data": [...]}`` / JSONL."""
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
                if "executions" in doc and isinstance(doc["executions"], list):
                    return [e for e in doc["executions"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single execution object.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        executions: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-execution EvaluationResults plus cross-app synthetic findings."""
        # First pass: aggregate apps per agent_id for cross-app pattern detection.
        agent_apps: dict[str, set[str]] = {}
        for exec_ in executions:
            agent_id = exec_.get("agent_id")
            app = exec_.get("app")
            if isinstance(agent_id, str) and isinstance(app, str) and app:
                agent_apps.setdefault(agent_id, set()).add(app)

        cross_app_agents = {
            agent_id: sorted(apps)
            for agent_id, apps in agent_apps.items()
            if len(apps) > self.cross_app_threshold
        }

        results = [
            self._parse_execution(
                exec_,
                file_sha256=file_sha256,
                cross_app_agents=cross_app_agents,
            )
            for exec_ in executions
        ]

        # Synthetic per-agent cross-app pattern finding.
        for agent_id, apps in sorted(cross_app_agents.items()):
            results.append(
                self._synthetic_cross_app_result(
                    agent_id=agent_id,
                    apps=apps,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "composio",
            "source_tool_name": "composio",
            "source_tool_version": "",
        }
        if execution_id is not None:
            provenance["execution_id"] = execution_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_execution(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_app_agents: dict[str, list[str]],
    ) -> EvaluationResult:
        execution_id = str(entry.get("id") or uuid.uuid4())
        action = str(entry.get("action") or "UNKNOWN")
        app = str(entry.get("app") or "unknown")
        connection_id = str(entry.get("connection_id") or "")
        user_id = entry.get("user_id")
        agent_id_field = entry.get("agent_id")
        auth_scheme = str(entry.get("auth_scheme") or "")
        scopes_used_raw = entry.get("scopes_used") or []
        scopes_used = (
            [str(s) for s in scopes_used_raw]
            if isinstance(scopes_used_raw, list)
            else []
        )
        input_param_keys_raw = entry.get("input_param_keys") or []
        input_param_keys = (
            [str(k) for k in input_param_keys_raw]
            if isinstance(input_param_keys_raw, list)
            else []
        )
        try:
            input_param_count = int(
                entry.get("input_param_count")
                if entry.get("input_param_count") is not None
                else len(input_param_keys)
            )
        except (TypeError, ValueError):
            input_param_count = len(input_param_keys)

        result_status = str(entry.get("result_status") or "").strip().lower()
        error_code = entry.get("error_code")
        try:
            latency_ms = float(entry.get("latency_ms") or 0.0)
        except (TypeError, ValueError):
            latency_ms = 0.0
        executed_at = (
            entry.get("executed_at")
            or datetime.now(timezone.utc).isoformat()
        )
        triggered_by = str(entry.get("triggered_by") or "").strip().lower()
        approval_required = bool(entry.get("approval_required", False))
        approval_status_raw = entry.get("approval_status")
        approval_status = (
            str(approval_status_raw).strip().lower()
            if isinstance(approval_status_raw, str) and approval_status_raw.strip()
            else None
        )
        redact_pii_in_input = entry.get("redact_pii_in_input")
        external_destination_kind = (
            str(entry.get("external_destination_kind") or "").strip().lower()
        )

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            execution_id=execution_id,
        )

        common_evidence: dict[str, Any] = {
            "composio_execution_id": execution_id,
            "action": action,
            "app": app,
            "connection_id": connection_id,
            "user_id": str(user_id) if user_id is not None else None,
            "agent_id_observed": (
                str(agent_id_field) if agent_id_field is not None else None
            ),
            "auth_scheme": auth_scheme,
            "scopes_used": scopes_used,
            "scope_summary": {
                "count": len(scopes_used),
                "scopes": scopes_used,
            },
            "input_param_keys": input_param_keys,
            "input_param_count": input_param_count,
            "result_status": result_status,
            "error_code": str(error_code) if error_code is not None else None,
            "latency_ms": latency_ms,
            "executed_at": str(executed_at),
            "triggered_by": triggered_by,
            "approval_required": approval_required,
            "approval_status": approval_status,
            "redact_pii_in_input": (
                bool(redact_pii_in_input)
                if redact_pii_in_input is not None
                else None
            ),
            "external_destination_kind": external_destination_kind or None,
            "source_provenance": source_provenance,
            "source_tool": "composio",
        }

        control_results: list[ControlResult] = []

        # 1. result_status / approval — primary signal.
        if result_status == "failure":
            signal = "result_status_failure"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"failed (error_code={error_code!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif result_status == "rate_limited":
            signal = "result_status_rate_limited"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"rate-limited (capacity / abuse signal)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif result_status == "auth_expired":
            signal = "result_status_auth_expired"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"auth_expired — connection {connection_id} requires re-auth"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif result_status == "success":
            if approval_required and approval_status is None:
                # Successful action that should have required approval but
                # has no approval record — this is the most important signal.
                signal = "missing_approval"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Composio execution {execution_id} action {action} on {app} "
                            f"required approval but none was recorded "
                            f"(approval_required=true, approval_status=null)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif approval_status == "approved":
                signal = "result_status_success_approved"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Composio execution {execution_id} action {action} on {app} "
                            f"succeeded with approval recorded"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif not approval_required:
                signal = "result_status_success_no_approval_required"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Composio execution {execution_id} action {action} on {app} "
                            f"succeeded (no approval required for this action)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Edge: success with approval_status in a non-approved/null state
                # (e.g. "pending" but action ran). Treat as missing-approval FAIL.
                signal = "missing_approval"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Composio execution {execution_id} action {action} on {app} "
                            f"succeeded with approval_status={approval_status!r} "
                            f"(approval not granted)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        else:
            # Unknown / missing result_status — surface as PR-02 FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"has unrecognized result_status={entry.get('result_status')!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "result_status_unknown"},
                )
            )

        # 2. Denied approval — additive PR-05 PASS (audit trail of denial).
        # We log the denial as evidence the audit trail is functioning, regardless
        # of result_status (a denied approval typically pairs with a non-success status,
        # but the audit trail itself is healthy).
        if approval_status == "denied":
            signal = "denied_approval"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"approval was denied — audit trail of denial recorded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. External destination — additive PR-04 FLAG (exfil surface).
        if external_destination_kind in self.external_destination_kinds:
            signal = "external_destination"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"targets external destination kind={external_destination_kind!r} "
                        f"(data exfiltration surface)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. Trigger source — webhook is FLAG, scheduler is PASS.
        if triggered_by == "webhook":
            signal = "trigger_webhook"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"was triggered by an external webhook — verify provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif triggered_by == "scheduler":
            signal = "trigger_scheduler"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"was triggered by scheduler — audit-trail expected"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 5. PII redaction — flag when destination is PII-sensitive and redaction is off.
        if (
            redact_pii_in_input is False
            and external_destination_kind in self.pii_destination_kinds
        ):
            signal = "pii_unredacted"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"sends to {external_destination_kind!r} without input PII "
                        f"redaction (redact_pii_in_input=false)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Broad scope — additive PR-02 FLAG.
        broad_hits = _scopes_match_broad(scopes_used, self.broad_scope_patterns)
        if broad_hits:
            signal = "broad_scope"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} action {action} on {app} "
                        f"used broad scope(s): {', '.join(broad_hits)} "
                        f"(patterns={list(self.broad_scope_patterns)})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "broad_scope_matches": broad_hits,
                        "broad_scope_patterns": list(self.broad_scope_patterns),
                    },
                )
            )

        # 7. Cross-app pattern — surface on each contributing execution as informational
        # context (the synthetic per-agent finding is added separately).
        if isinstance(agent_id_field, str) and agent_id_field in cross_app_agents:
            signal = "cross_app_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Composio execution {execution_id} agent {agent_id_field} "
                        f"is part of a cross-app pattern "
                        f"({len(cross_app_agents[agent_id_field])} apps > "
                        f"threshold {self.cross_app_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_app_apps": cross_app_agents[agent_id_field],
                        "cross_app_threshold": self.cross_app_threshold,
                    },
                )
            )

        # Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Composio: action={action} app={app} "
            f"result_status={result_status or 'unknown'} "
            f"approval_required={approval_required} "
            f"approval_status={approval_status or 'null'} "
            f"triggered_by={triggered_by or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"composio-{execution_id[:32]}",
            timestamp=str(executed_at),
            agent_id=self.agent_id,
            source_type="composio_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_ms,
            session_id=connection_id or None,
        )

    def _synthetic_cross_app_result(
        self,
        *,
        agent_id: str,
        apps: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-agent cross-app pattern finding.

        Not tied to any single execution. Captures the agent_id, the apps it
        touched, and the threshold used so downstream posture analysis can
        answer "which agents are spreading across our SaaS surface?".
        """
        signal = "cross_app_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"composio-cross-app-{agent_id}"
        evidence: dict[str, Any] = {
            "composio_execution_id": synthetic_id,
            "agent_id_observed": agent_id,
            "cross_app_apps": apps,
            "cross_app_app_count": len(apps),
            "cross_app_threshold": self.cross_app_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                execution_id=synthetic_id,
            ),
            "source_tool": "composio",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Composio synthetic finding: agent {agent_id} touched "
                f"{len(apps)} apps in this export "
                f"({', '.join(apps)}) — exceeds cross-app threshold "
                f"{self.cross_app_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="composio_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Composio: synthetic cross-app pattern for "
                f"agent={agent_id} apps={len(apps)}>threshold="
                f"{self.cross_app_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
