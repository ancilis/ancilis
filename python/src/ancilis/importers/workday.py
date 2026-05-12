"""Workday System Audit Log importer — maps HR/finance audit events to AKSI controls.

Workday (https://workday.com) is the dominant enterprise HR + finance system.
Workday holds compensation, performance, benefits, time-off, and background-check
records — the densest concentration of regulated PII in most enterprises. AI
agents reading employee data via Workday APIs trigger massive PII exposure
(HIPAA-adjacent benefits data, SOX-relevant compensation, GDPR/PIPEDA
cross-jurisdiction worker records). The Workday System Audit Log is the
canonical evidence source for who-touched-which-employee-record.

This importer ingests Workday System Audit Log exports in three on-disk shapes:

  1. ``{"events": [...]}`` — primary audit envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one event per line

Signal mapping (see shared/mappings/workday-aksi-controls.json):
  * event_type=Login result=Success                       → PR-01 PASS
  * event_type=Login result=Failed                        → PR-01 FLAG
  * event_type=View_Worker actor=Regular target=self       → PR-04 PASS
    (self-service)
  * event_type=View_Worker by Service Account /
    Integration Admin                                      → PR-04 FLAG
  * event_type=View_Compensation / View_Salary             → PR-04 FAIL
    (compensation data is highest-PII; SOX-relevant)
  * event_type=View_Compensation by Service Account        → PR-04 FAIL → BLOCK
    (compensation data exfiltration is the worst pattern)
  * event_type=View_Performance by Service Account         → PR-04 FAIL
  * event_type=View_PII records_affected > threshold
    (default 50)                                           → PR-04 FAIL
    (mass-PII view = exfil pattern)
  * event_type=Edit_Compensation                           → PR-02 FAIL
    (compensation modification = high-impact financial)
  * event_type=Edit_Worker by Service Account              → PR-02 FLAG
  * event_type=Add_Worker                                  → PR-05 PASS
    (audit trail of hire)
  * event_type=Terminate_Worker                            → PR-05 PASS captured
    (sensitive lifecycle event)
  * event_type=Configure_Security / Modify_Security_Group
    / Grant_Permission / Revoke_Permission                 → PR-02 FAIL
  * event_type=Bulk_Edit records_affected > 100            → PR-02 FAIL
  * event_type=Export_Data records_affected > 100          → PR-04 FAIL
    (bulk export)
  * event_type=Run_Report on sensitive objects             → PR-04 FLAG
    {Compensation, Performance_Review, Background_Check}
  * event_type=Custom_Report_Run by Service Account        → PR-04 FLAG
  * event_type=Integration_Run by Integration Admin        → captured PASS
  * action.approval_required=true + approver_id=null       → PR-02 FAIL
    (missing required approval)
  * environment=Production + actor.user_type=Implementer   → PR-02 FLAG
  * tls_version in {TLSv1.0, TLSv1.1}                      → PR-04 FAIL
  * is_compliance_relevant=true → captured normally with elevated priority
  * cross-worker pattern: actor accessing > N target_workers in 1h
    (default 30)                                           → PR-04 FAIL synthetic
  * out-of-region: actor accessing > N target_workers
    in different region (default 10) — GDPR/PIPEDA          → PR-04 FLAG synthetic

Sanitization (security-critical — Workday IDs encode tenant + org structure;
worker names are PII; cost-center IDs reveal org topology):
  * ``actor.worker_id`` reduced to last-8 only.
  * ``actor.worker_name`` is stored as length only — never the value.
  * ``actor.username`` is stored as length + sha256 (full username never stored).
  * ``target_worker.worker_id`` reduced to last-8 only.
  * ``target_worker.name`` is stored as length only.
  * ``target_worker.cost_center`` reduced to last-8 only (cost centers
    encode org structure).
  * ``target_worker.position`` is stored verbatim (job title is non-sensitive
    structural metadata).
  * ``system_info.client_ip`` reduced to ``A.B.0.0/16`` for public IPv4;
    RFC1918 / loopback preserved verbatim; IPv6 reduced to ``/32``.
  * ``system_info.integration_system_id`` reduced to last-8 only.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``xmltodict`` or any Workday client; Workday audit
log JSON exports are parsed with the standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/workday.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "workday-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_SENSITIVE_OBJECTS: frozenset[str] = frozenset(
    {"Compensation", "Performance_Review", "Background_Check"}
)
_DEFAULT_COMPENSATION_EVENT_TYPES: frozenset[str] = frozenset(
    {"View_Compensation", "View_Salary", "Edit_Compensation"}
)
_DEFAULT_LEGACY_TLS: frozenset[str] = frozenset({"TLSv1.0", "TLSv1.1"})
_DEFAULT_SERVICE_ACCOUNT_TYPES: frozenset[str] = frozenset(
    {"Service Account", "Integration Admin"}
)

_DEFAULT_MASS_PII_THRESHOLD = 50
_DEFAULT_BULK_EXPORT_THRESHOLD = 100
_DEFAULT_BULK_EDIT_THRESHOLD = 100
_DEFAULT_CROSS_WORKER_THRESHOLD = 30
_DEFAULT_CROSS_REGION_THRESHOLD = 10
_DEFAULT_CROSS_WORKER_WINDOW_SECONDS = 3600


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the workday-aksi-controls.json mapping; tolerate missing file."""
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


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _last_8(value: Any) -> str | None:
    """Return last-8 chars of a string-like identifier, or None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    if len(v) <= 8:
        return v
    return v[-8:]


def _length_or_none(value: Any) -> int | None:
    """Return ``len(value)`` if ``value`` is a non-empty string, else ``None``."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    return len(v)


def _sha256_hex(value: Any) -> str | None:
    """Return SHA-256 hex digest of a string value, or ``None`` if not string."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize client_ip to a privacy-aware form.

    * RFC1918 / loopback / link-local preserved verbatim.
    * Public IPv4 reduced to ``A.B.0.0/16``.
    * Public IPv6 reduced to first 32 bits + ``::/32``.
    * Hostnames preserved verbatim.
    """
    if not isinstance(source_ip, str):
        return None
    ip = source_ip.strip()
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ip
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.0.0/16"
        return ip
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _parse_iso(ts: str | None) -> datetime | None:
    if not isinstance(ts, str):
        return None
    s = ts.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class WorkdayImporter:
    """Parse a Workday System Audit Log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        mass_pii_threshold: int | None = None,
        bulk_export_threshold: int | None = None,
        bulk_edit_threshold: int | None = None,
        cross_worker_threshold: int | None = None,
        cross_region_threshold: int | None = None,
        cross_worker_window_seconds: int | None = None,
        sensitive_object_types: Iterable[str] | None = None,
        compensation_event_types: Iterable[str] | None = None,
        legacy_tls_versions: Iterable[str] | None = None,
        service_account_user_types: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        thresholds = meta.get("threshold_metadata", {}) if isinstance(meta, dict) else {}
        if not isinstance(thresholds, dict):
            thresholds = {}

        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Threshold precedence: explicit arg > mapping metadata > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            value = thresholds.get(key)
            if isinstance(value, (int, float)):
                return int(value)
            return default

        self.mass_pii_threshold = _resolve_int(
            mass_pii_threshold, "mass_pii_threshold", _DEFAULT_MASS_PII_THRESHOLD
        )
        self.bulk_export_threshold = _resolve_int(
            bulk_export_threshold, "bulk_export_threshold", _DEFAULT_BULK_EXPORT_THRESHOLD
        )
        self.bulk_edit_threshold = _resolve_int(
            bulk_edit_threshold, "bulk_edit_threshold", _DEFAULT_BULK_EDIT_THRESHOLD
        )
        self.cross_worker_threshold = _resolve_int(
            cross_worker_threshold, "cross_worker_threshold", _DEFAULT_CROSS_WORKER_THRESHOLD
        )
        self.cross_region_threshold = _resolve_int(
            cross_region_threshold, "cross_region_threshold", _DEFAULT_CROSS_REGION_THRESHOLD
        )
        self.cross_worker_window_seconds = _resolve_int(
            cross_worker_window_seconds,
            "cross_worker_window_seconds",
            _DEFAULT_CROSS_WORKER_WINDOW_SECONDS,
        )

        if sensitive_object_types is not None:
            self.sensitive_object_types = frozenset(
                str(o) for o in sensitive_object_types
            )
        else:
            meta_sens = meta.get("sensitive_object_types")
            if isinstance(meta_sens, list) and meta_sens:
                self.sensitive_object_types = frozenset(str(o) for o in meta_sens)
            else:
                self.sensitive_object_types = _DEFAULT_SENSITIVE_OBJECTS

        if compensation_event_types is not None:
            self.compensation_event_types = frozenset(
                str(o) for o in compensation_event_types
            )
        else:
            meta_comp = meta.get("compensation_event_types")
            if isinstance(meta_comp, list) and meta_comp:
                self.compensation_event_types = frozenset(str(o) for o in meta_comp)
            else:
                self.compensation_event_types = _DEFAULT_COMPENSATION_EVENT_TYPES

        if legacy_tls_versions is not None:
            self.legacy_tls_versions = frozenset(str(t) for t in legacy_tls_versions)
        else:
            meta_tls = meta.get("legacy_tls_versions")
            if isinstance(meta_tls, list) and meta_tls:
                self.legacy_tls_versions = frozenset(str(t) for t in meta_tls)
            else:
                self.legacy_tls_versions = _DEFAULT_LEGACY_TLS

        if service_account_user_types is not None:
            self.service_account_user_types = frozenset(
                str(t) for t in service_account_user_types
            )
        else:
            meta_sa = meta.get("service_account_user_types")
            if isinstance(meta_sa, list) and meta_sa:
                self.service_account_user_types = frozenset(str(t) for t in meta_sa)
            else:
                self.service_account_user_types = _DEFAULT_SERVICE_ACCOUNT_TYPES

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Workday System Audit Log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Workday audit-log content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events": [...]}`` / ``{"data": [...]}`` / JSONL / single event."""
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
                if "events" in doc and isinstance(doc["events"], list):
                    return [e for e in doc["events"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass: aggregate cross-worker access (per actor → distinct
        # target_workers within sliding 1h window) and out-of-region access.
        actor_targets: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        actor_out_of_region: dict[str, set[str]] = defaultdict(set)
        for ev in events:
            actor = ev.get("actor") or {}
            target = ev.get("target_worker") or {}
            actor_id = actor.get("worker_id") if isinstance(actor, dict) else None
            target_id = target.get("worker_id") if isinstance(target, dict) else None
            ts = _parse_iso(str(ev.get("timestamp") or ""))
            if (
                isinstance(actor_id, str)
                and actor_id
                and isinstance(target_id, str)
                and target_id
                and actor_id != target_id
                and ts is not None
            ):
                actor_targets[actor_id].append((ts, target_id))

            actor_region = actor.get("region") if isinstance(actor, dict) else None
            target_region = target.get("region") if isinstance(target, dict) else None
            if (
                isinstance(actor_id, str)
                and actor_id
                and isinstance(target_id, str)
                and target_id
                and isinstance(actor_region, str)
                and isinstance(target_region, str)
                and actor_region
                and target_region
                and actor_region != target_region
            ):
                actor_out_of_region[actor_id].add(target_id)

        cross_worker_actors: dict[str, int] = {}
        window = self.cross_worker_window_seconds
        for actor_id, entries in actor_targets.items():
            entries.sort(key=lambda t: t[0])
            max_unique = 0
            j = 0
            seen: dict[str, int] = {}
            for i in range(len(entries)):
                t_i, tgt_i = entries[i]
                seen[tgt_i] = seen.get(tgt_i, 0) + 1
                while (t_i - entries[j][0]).total_seconds() > window:
                    t_j, tgt_j = entries[j]
                    seen[tgt_j] -= 1
                    if seen[tgt_j] <= 0:
                        del seen[tgt_j]
                    j += 1
                if len(seen) > max_unique:
                    max_unique = len(seen)
            if max_unique > self.cross_worker_threshold:
                cross_worker_actors[actor_id] = max_unique

        cross_region_actors = {
            actor_id: sorted(targets)
            for actor_id, targets in actor_out_of_region.items()
            if len(targets) > self.cross_region_threshold
        }

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_worker_actors=cross_worker_actors,
                cross_region_actors=cross_region_actors,
            )
            for ev in events
        ]

        # Synthetic per-actor cross-worker findings.
        for actor_id, count in sorted(cross_worker_actors.items()):
            results.append(
                self._synthetic_cross_worker_result(
                    actor_id=actor_id,
                    unique_target_count=count,
                    file_sha256=file_sha256,
                )
            )
        # Synthetic out-of-region findings.
        for actor_id, targets in sorted(cross_region_actors.items()):
            results.append(
                self._synthetic_out_of_region_result(
                    actor_id=actor_id,
                    target_ids=targets,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "workday_audit_log",
            "source_tool_name": "workday_audit_log",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_worker_actors: dict[str, int],
        cross_region_actors: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id = str(event.get("event_id") or uuid.uuid4())
        event_type = str(event.get("event_type") or "Unknown")
        timestamp = str(
            event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        )

        # -- Actor ----------------------------------------------------------
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_worker_id_raw = actor.get("worker_id")
        actor_worker_id_last8 = _last_8(actor_worker_id_raw)
        actor_worker_id_full = (
            str(actor_worker_id_raw) if isinstance(actor_worker_id_raw, str) else None
        )
        actor_name_length = (
            actor.get("worker_name_length")
            if isinstance(actor.get("worker_name_length"), int)
            else _length_or_none(actor.get("worker_name"))
        )
        actor_username_length = _length_or_none(actor.get("username"))
        actor_username_sha256 = _sha256_hex(actor.get("username"))
        user_type = (
            str(actor.get("user_type"))
            if isinstance(actor.get("user_type"), str)
            else None
        )

        # -- Target worker --------------------------------------------------
        target = event.get("target_worker") or {}
        if not isinstance(target, dict):
            target = {}
        target_worker_id_raw = target.get("worker_id")
        target_worker_id_last8 = _last_8(target_worker_id_raw)
        target_worker_id_full = (
            str(target_worker_id_raw) if isinstance(target_worker_id_raw, str) else None
        )
        target_name_length = (
            target.get("name_length")
            if isinstance(target.get("name_length"), int)
            else _length_or_none(target.get("name"))
        )
        target_position = (
            str(target.get("position"))
            if isinstance(target.get("position"), str)
            else None
        )
        target_cost_center_last8 = _last_8(target.get("cost_center"))
        target_region = (
            str(target.get("region"))
            if isinstance(target.get("region"), str)
            else None
        )
        actor_region = (
            str(actor.get("region"))
            if isinstance(actor.get("region"), str)
            else None
        )

        # -- Action ---------------------------------------------------------
        action = event.get("action") or {}
        if not isinstance(action, dict):
            action = {}
        action_objects_raw = action.get("objects")
        action_objects: list[str] = (
            [str(o) for o in action_objects_raw if isinstance(o, str)]
            if isinstance(action_objects_raw, list)
            else []
        )
        try:
            records_affected = int(action.get("records_affected") or 0)
        except (TypeError, ValueError):
            records_affected = 0
        is_bulk = bool(action.get("is_bulk"))
        is_self_service = bool(action.get("is_self_service"))
        approval_required = bool(action.get("approval_required"))
        approver_id_raw = action.get("approver_id")
        approver_id_last8 = _last_8(approver_id_raw)
        approver_present = isinstance(approver_id_raw, str) and bool(
            approver_id_raw.strip()
        )

        # -- System info ----------------------------------------------------
        system_info = event.get("system_info") or {}
        if not isinstance(system_info, dict):
            system_info = {}
        client_ip = _classify_source_ip(system_info.get("client_ip"))
        integration_system_id_last8 = _last_8(system_info.get("integration_system_id"))
        integration_system_id_present = isinstance(
            system_info.get("integration_system_id"), str
        ) and bool(str(system_info.get("integration_system_id")).strip())
        tenant_id = (
            str(system_info.get("tenant_id"))
            if isinstance(system_info.get("tenant_id"), str)
            else None
        )
        environment = (
            str(system_info.get("environment"))
            if isinstance(system_info.get("environment"), str)
            else None
        )
        tls_version = (
            str(system_info.get("tls_version"))
            if isinstance(system_info.get("tls_version"), str)
            else None
        )

        # -- Result ---------------------------------------------------------
        result_block = event.get("result") or {}
        if not isinstance(result_block, dict):
            result_block = {}
        status = (
            str(result_block.get("status"))
            if isinstance(result_block.get("status"), str)
            else None
        )
        error_code = (
            str(result_block.get("error_code"))
            if isinstance(result_block.get("error_code"), str)
            else None
        )
        sensitivity_level = (
            str(result_block.get("sensitivity_level"))
            if isinstance(result_block.get("sensitivity_level"), str)
            else None
        )

        is_compliance_relevant = bool(event.get("is_compliance_relevant"))

        # Determine whether this is a self-service action (actor == target).
        is_self_target = (
            isinstance(actor_worker_id_full, str)
            and isinstance(target_worker_id_full, str)
            and actor_worker_id_full == target_worker_id_full
        )

        common_evidence: dict[str, Any] = {
            "workday_event_id": event_id,
            "event_type": event_type,
            "event_time": timestamp,
            "actor_worker_id_last8": actor_worker_id_last8,
            "actor_worker_name_length": actor_name_length,
            "actor_username_length": actor_username_length,
            "actor_username_sha256": actor_username_sha256,
            "user_type": user_type,
            "actor_region": actor_region,
            "target_worker_id_last8": target_worker_id_last8,
            "target_worker_name_length": target_name_length,
            "target_position": target_position,
            "target_cost_center_last8": target_cost_center_last8,
            "target_region": target_region,
            "action_objects": action_objects,
            "records_affected": records_affected,
            "is_bulk": is_bulk,
            "is_self_service": is_self_service or is_self_target,
            "approval_required": approval_required,
            "approver_id_last8": approver_id_last8,
            "approver_present": approver_present,
            "client_ip_redacted": client_ip,
            "integration_system_id_last8": integration_system_id_last8,
            "tenant_id": tenant_id,
            "environment": environment,
            "tls_version": tls_version,
            "result_status": status,
            "error_code": error_code,
            "sensitivity_level": sensitivity_level,
            "is_compliance_relevant": is_compliance_relevant,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "workday_audit_log",
        }

        control_results: list[ControlResult] = []
        primary_emitted = False

        is_service_account = (
            user_type is not None and user_type in self.service_account_user_types
        )

        # ------------------------------------------------------------------
        # 1. Login
        # ------------------------------------------------------------------
        if event_type == "Login":
            if status == "Success":
                signal = "login_success"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Workday event {event_id} Login by actor "
                            f"{actor_worker_id_last8 or 'unknown'} succeeded"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "login_failed"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Workday event {event_id} Login by actor "
                            f"{actor_worker_id_last8 or 'unknown'} failed "
                            f"(status={status!r}, error={error_code!r})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 2. View_Worker — self-service vs service-account
        # ------------------------------------------------------------------
        elif event_type == "View_Worker":
            if user_type == "Regular" and is_self_target:
                signal = "view_self_service"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Workday event {event_id} View_Worker self-service "
                            f"(actor=target={actor_worker_id_last8 or 'unknown'})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True
            elif is_service_account:
                signal = "service_account_view_worker"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Workday event {event_id} View_Worker by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} "
                            f"on target {target_worker_id_last8 or 'unknown'} — "
                            f"service-account access to employee data"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 3. View_Compensation / View_Salary — highest-PII data.
        # ------------------------------------------------------------------
        elif event_type in {"View_Compensation", "View_Salary"}:
            if is_service_account:
                signal = "service_account_view_compensation"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} {event_type} by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} — "
                            f"compensation-data exfiltration by service account "
                            f"is the highest-risk pattern"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "view_compensation_or_salary"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} {event_type} by actor "
                            f"{actor_worker_id_last8 or 'unknown'} — "
                            f"compensation data is highest-PII / SOX-relevant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 4. View_Performance by service account
        # ------------------------------------------------------------------
        elif event_type == "View_Performance":
            if is_service_account:
                signal = "service_account_view_performance"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} View_Performance by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} — "
                            f"performance-review access by service account"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 5. View_PII — mass-PII view = exfil pattern.
        # ------------------------------------------------------------------
        elif event_type == "View_PII":
            if records_affected > self.mass_pii_threshold:
                signal = "mass_pii_view"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} View_PII records_affected="
                            f"{records_affected} exceeds threshold "
                            f"{self.mass_pii_threshold} — mass-PII view"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "mass_pii_threshold": self.mass_pii_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 6. Edit_Compensation — financial-impact modification.
        # ------------------------------------------------------------------
        elif event_type == "Edit_Compensation":
            signal = "edit_compensation"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Workday event {event_id} Edit_Compensation by actor "
                        f"{actor_worker_id_last8 or 'unknown'} on target "
                        f"{target_worker_id_last8 or 'unknown'} — high-impact "
                        f"financial action"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 7. Edit_Worker by service account
        # ------------------------------------------------------------------
        elif event_type == "Edit_Worker":
            if is_service_account:
                signal = "edit_worker_by_service_account"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Workday event {event_id} Edit_Worker by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} — "
                            f"programmatic mutation of employee record"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 8. Add_Worker — audit trail of hire.
        # ------------------------------------------------------------------
        elif event_type == "Add_Worker":
            signal = "add_worker_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Workday event {event_id} Add_Worker — audit trail "
                        f"of new-hire lifecycle event"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 9. Terminate_Worker — sensitive lifecycle event captured.
        # ------------------------------------------------------------------
        elif event_type == "Terminate_Worker":
            signal = "terminate_worker_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Workday event {event_id} Terminate_Worker — "
                        f"sensitive lifecycle event captured for audit"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 10. Security configuration changes.
        # ------------------------------------------------------------------
        elif event_type in {
            "Configure_Security",
            "Modify_Security_Group",
            "Grant_Permission",
            "Revoke_Permission",
        }:
            signal = "security_configuration_change"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Workday event {event_id} {event_type} by actor "
                        f"{actor_worker_id_last8 or 'unknown'} — "
                        f"security configuration change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 11. Bulk_Edit — mass HR data modification.
        # ------------------------------------------------------------------
        elif event_type == "Bulk_Edit":
            if records_affected > self.bulk_edit_threshold:
                signal = "bulk_edit"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} Bulk_Edit "
                            f"records_affected={records_affected} exceeds "
                            f"threshold {self.bulk_edit_threshold} — mass HR "
                            f"data modification"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "bulk_edit_threshold": self.bulk_edit_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 12. Export_Data — bulk export.
        # ------------------------------------------------------------------
        elif event_type == "Export_Data":
            if records_affected > self.bulk_export_threshold:
                signal = "bulk_export_data"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Workday event {event_id} Export_Data "
                            f"records_affected={records_affected} exceeds "
                            f"threshold {self.bulk_export_threshold} — "
                            f"bulk-export exfiltration surface"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "bulk_export_threshold": self.bulk_export_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 13. Run_Report — surface runs that target sensitive objects.
        # ------------------------------------------------------------------
        elif event_type == "Run_Report":
            if any(o in self.sensitive_object_types for o in action_objects):
                signal = "report_run_sensitive_object"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Workday event {event_id} Run_Report on sensitive "
                            f"objects {action_objects} by actor "
                            f"{actor_worker_id_last8 or 'unknown'}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 14. Custom_Report_Run by service account.
        # ------------------------------------------------------------------
        elif event_type == "Custom_Report_Run":
            if is_service_account:
                signal = "custom_report_service_account"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Workday event {event_id} Custom_Report_Run by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} — "
                            f"custom reports often target sensitive data"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 15. Integration_Run by Integration Admin — captured PASS.
        # ------------------------------------------------------------------
        elif event_type == "Integration_Run":
            if user_type == "Integration Admin":
                signal = "integration_run_captured"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Workday event {event_id} Integration_Run by "
                            f"{user_type} {actor_worker_id_last8 or 'unknown'} — "
                            f"programmatic flow captured for audit"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: missing required approval — independent of event type.
        # ------------------------------------------------------------------
        if approval_required and not approver_present:
            signal = "missing_required_approval"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Workday event {event_id} {event_type} requires "
                        f"approval but approver_id is null — broken approval "
                        f"workflow"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: implementer role on production environment.
        # ------------------------------------------------------------------
        if environment == "Production" and user_type == "Implementer":
            signal = "implementer_on_production"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Workday event {event_id} {event_type} by Implementer "
                        f"{actor_worker_id_last8 or 'unknown'} in Production — "
                        f"unusual role on prod tenant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: legacy TLS — independent of event type.
        # ------------------------------------------------------------------
        if tls_version is not None and tls_version in self.legacy_tls_versions:
            signal = "legacy_tls"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Workday event {event_id} {event_type} negotiated "
                        f"legacy {tls_version} — fails modern crypto controls"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: per-event cross-worker pattern marker (for traceability).
        # ------------------------------------------------------------------
        if (
            isinstance(actor_worker_id_full, str)
            and actor_worker_id_full in cross_worker_actors
        ):
            signal = "cross_worker_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Workday event {event_id} actor "
                        f"{actor_worker_id_last8 or 'unknown'} is part of a "
                        f"cross-worker access pattern "
                        f"({cross_worker_actors[actor_worker_id_full]} unique "
                        f"target workers in 1h > threshold "
                        f"{self.cross_worker_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_worker_unique_count": cross_worker_actors[
                            actor_worker_id_full
                        ],
                        "cross_worker_threshold": self.cross_worker_threshold,
                    },
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: per-event out-of-region marker (for traceability).
        # ------------------------------------------------------------------
        if (
            isinstance(actor_worker_id_full, str)
            and actor_worker_id_full in cross_region_actors
            and isinstance(target_region, str)
            and isinstance(actor_region, str)
            and actor_region != target_region
        ):
            signal = "out_of_region_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Workday event {event_id} actor in {actor_region} "
                        f"accessing target in {target_region} — part of "
                        f"out-of-region pattern (GDPR/PIPEDA cross-jurisdiction)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_region_target_count": len(
                            cross_region_actors[actor_worker_id_full]
                        ),
                        "cross_region_threshold": self.cross_region_threshold,
                    },
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: compliance-relevant capture (elevated priority surfacing).
        # ------------------------------------------------------------------
        if is_compliance_relevant:
            signal = "compliance_relevant_capture"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Workday event {event_id} {event_type} flagged "
                        f"is_compliance_relevant — captured with elevated "
                        f"priority (sensitivity={sensitivity_level!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Fallback: unrecognized / unmatched event — surface as PR-05 FLAG.
        # ------------------------------------------------------------------
        if not primary_emitted:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Workday event {event_id} event_type={event_type!r} "
                        f"did not match any classified pattern — surfaced for "
                        f"review"
                    ),
                    evidence_data={**common_evidence, "signal": "unknown_event"},
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
            f"Imported from Workday System Audit Log: event_type={event_type} "
            f"actor={actor_worker_id_last8 or 'unknown'} "
            f"user_type={user_type or 'unknown'} "
            f"target={target_worker_id_last8 or 'none'} "
            f"records_affected={records_affected} "
            f"environment={environment or 'unknown'} "
            f"compliance_relevant={is_compliance_relevant}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"workday-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="workday_audit_log_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_cross_worker_result(
        self,
        *,
        actor_id: str,
        unique_target_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_worker_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        actor_id_last8 = _last_8(actor_id) or actor_id
        synthetic_id = f"workday-cross-worker-{actor_id_last8}"
        evidence: dict[str, Any] = {
            "workday_event_id": synthetic_id,
            "actor_worker_id_last8": actor_id_last8,
            "cross_worker_unique_count": unique_target_count,
            "cross_worker_threshold": self.cross_worker_threshold,
            "cross_worker_window_seconds": self.cross_worker_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "workday_audit_log",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Workday synthetic finding: actor {actor_id_last8} accessed "
                f"{unique_target_count} unique target workers within a "
                f"{self.cross_worker_window_seconds}-second window (> threshold "
                f"{self.cross_worker_threshold}) — mass-PII access pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="workday_audit_log_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Workday System Audit Log: synthetic cross-worker "
                f"pattern for actor={actor_id_last8} "
                f"unique_targets={unique_target_count}>threshold="
                f"{self.cross_worker_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_out_of_region_result(
        self,
        *,
        actor_id: str,
        target_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "out_of_region_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        actor_id_last8 = _last_8(actor_id) or actor_id
        target_ids_last8 = [_last_8(t) or t for t in target_ids]
        synthetic_id = f"workday-out-of-region-{actor_id_last8}"
        evidence: dict[str, Any] = {
            "workday_event_id": synthetic_id,
            "actor_worker_id_last8": actor_id_last8,
            "cross_region_target_ids_last8": target_ids_last8,
            "cross_region_target_count": len(target_ids),
            "cross_region_threshold": self.cross_region_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "workday_audit_log",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Workday synthetic finding: actor {actor_id_last8} accessed "
                f"{len(target_ids)} target workers in different regions "
                f"(> threshold {self.cross_region_threshold}) — "
                f"GDPR/PIPEDA cross-jurisdiction pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="workday_audit_log_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Workday System Audit Log: synthetic out-of-region "
                f"pattern for actor={actor_id_last8} "
                f"cross_region_targets={len(target_ids)}>threshold="
                f"{self.cross_region_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
