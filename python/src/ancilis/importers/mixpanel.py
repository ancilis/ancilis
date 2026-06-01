# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Mixpanel analytics importer — converts Mixpanel event/audit exports to AKSI EvaluationResults.

Mixpanel (https://mixpanel.com) is a product-analytics platform whose
``/2.0/export`` API streams raw user events and whose Engage profile API
exposes per-user attributes. Agents that emit events to Mixpanel commonly
include user identifiers and free-form properties — a fertile surface for
PII leakage through event payloads. Mixpanel also exposes an admin-side
audit log covering project membership, API keys, retention policy
changes, data exports, and GDPR deletion requests.

Wire shapes accepted (auto-detected):

  1. ``{"events": [...]}``     — primary events envelope
  2. ``{"audit_log": [...]}``  — admin audit envelope
  3. ``{"data": [...]}``       — mixed envelope; per-record dispatch by
                                  presence of ``event`` (event) vs ``action``
                                  (audit log)
  4. JSONL                      — one event or audit record per line

Signal mapping (see ``shared/mappings/mixpanel-aksi-controls.json``):

Events:
  * ``sensitive_patterns_matched`` contains ``ssn_like_pattern``        → PR-04 FAIL → BLOCK
  * ``sensitive_patterns_matched`` contains ``credit_card_like_pattern``→ PR-04 FAIL → BLOCK
  * ``sensitive_patterns_matched`` contains ``email``                   → PR-04 FLAG (email leak)
  * ``contains_sensitive_pattern=true`` (no specific kind)              → PR-04 FLAG
  * ``event=$identify`` / ``$alias`` with stable identifier             → PR-04 FLAG (cross-session linking)
  * ``event=$people_set`` w/ sensitive property keys                    → PR-04 FAIL
  * ``event_property_count > over_tracking_threshold`` (default 30)     → PR-04 FLAG (over-tracking)
  * ``data_residency_region != server_geo``                             → PR-04 FLAG (cross-region / GDPR)
  * EU-resident user with ``tracking_consent_recorded=false``           → PR-04 FAIL (GDPR consent)
  * Non-EU user with ``tracking_consent_recorded=false``                → PR-05 FLAG (CCPA territory)
  * ``is_imported=true``                                                → PR-05 PASS (audit trail)

Audit log:
  * ``action=data_export``                                              → PR-04 FLAG (exfil surface)
  * ``action=data_residency_changed``                                   → PR-04 FAIL (GDPR-relevant)
  * ``action=retention_policy_changed``                                 → PR-04 FLAG (audit completeness)
  * ``action=gdpr_deletion_request``                                    → PR-05 PASS (compliance audit)
  * ``action=api_key_created`` & ``actor.is_service_account=false``     → PR-01 FLAG (human-issued key)
  * ``action=webhook_url_added`` & host not in allowlist                → PR-04 FLAG (external dest)
  * ``action=project_member_added``                                     → PR-02 FLAG

Synthetic findings (per agent_id, across the export):
  * > N events containing sensitive patterns within a 1h window         → PR-04 FAIL
    (default N=100, configurable via mapping ``high_volume_threshold``)
  * > X% of events from same agent contain sensitive patterns           → PR-04 FAIL
    (default X=5%, configurable via mapping ``pii_concentration_threshold``)

Sanitization — what we DO NOT store:
  * raw ``properties`` dict values (only the key list + count + boolean
    sensitive markers + the ``sensitive_patterns_matched`` taxonomy)
  * full ``distinct_id`` (last 8 chars only)
  * full ``$user_id`` (last 8 chars only)
  * full ``$device_id`` (last 8 chars only)
  * full ``$ip`` (masked to /16)
  * raw values of ``email``, ``first_name``, ``ssn``, ``credit_card`` —
    these surface only via ``sensitive_patterns_matched``
  * full webhook URL (host only, last 64 chars)

The SDK is importable without ``mixpanel`` installed; this importer parses
the JSON wire format directly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/mixpanel-aksi-controls.json.
def _resolve_mapping_path() -> Path:
    """Locate ``shared/mappings/mixpanel-aksi-controls.json`` by walking upward."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "shared" / "mappings" / "mixpanel-aksi-controls.json"
        if candidate.exists():
            return candidate
    return here.parents[4] / "shared" / "mappings" / "mixpanel-aksi-controls.json"


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_HIGH_VOLUME_THRESHOLD = 100
_DEFAULT_HIGH_VOLUME_WINDOW_SECONDS = 3600
_DEFAULT_PII_CONCENTRATION_THRESHOLD = 0.05
_DEFAULT_OVER_TRACKING_THRESHOLD = 30
_DEFAULT_SENSITIVE_EVENT_PROPERTY_KEYS: frozenset[str] = frozenset(
    {
        "ssn",
        "credit_card",
        "phone",
        "passport",
        "full_address",
        "tax_id",
        "bank_account",
        "date_of_birth",
        "drivers_license",
    }
)
_DEFAULT_BLOCK_PATTERN_KINDS: frozenset[str] = frozenset(
    {"ssn_like_pattern", "credit_card_like_pattern"}
)
_DEFAULT_FLAG_PATTERN_KINDS: frozenset[str] = frozenset({"email"})
_DEFAULT_IDENTITY_LINKING_EVENTS: frozenset[str] = frozenset(
    {"$identify", "$alias", "$create_alias"}
)
_DEFAULT_PEOPLE_SET_EVENTS: frozenset[str] = frozenset(
    {"$people_set", "$people_set_once", "$people_union", "$people_append"}
)
_DEFAULT_EU_REGIONS: frozenset[str] = frozenset(
    {"EU", "DE", "FR", "IE", "NL", "ES", "IT"}
)


def _load_mapping_table() -> dict[str, Any]:
    """Load the Mixpanel mapping table; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


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


def _last_n(value: Any, n: int = 8) -> str | None:
    """Return last n characters of a stringified id, or None if absent."""
    if value is None:
        return None
    s = str(value)
    if not s:
        return None
    return s[-n:]


def _mask_ip(ip: Any) -> str | None:
    """Mask an IPv4 address to /16 (first two octets); return None if not parseable."""
    if not isinstance(ip, str) or not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.0.0/16"
    # IPv6 best-effort: keep first 32 bits.
    if ":" in ip:
        chunks = ip.split(":")
        if len(chunks) >= 2:
            return f"{chunks[0]}:{chunks[1]}::/32"
    return None


def _host_only(url: Any) -> str | None:
    """Return scheme://host from a URL; tolerate non-URL strings."""
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return None
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"[:128]
    return url[:64]


def _coerce_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "y", "1"):
            return True
        if v in ("false", "no", "n", "0"):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return None


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


class MixpanelImporter:
    """Parse Mixpanel event/audit exports and convert to ``EvaluationResult`` records.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        high_volume_threshold: synthetic finding triggers when same agent emits
            more than this many sensitive-pattern events in the export's
            ``high_volume_window_seconds`` (default 100/3600s).
        pii_concentration_threshold: synthetic finding triggers when more than
            this fraction of an agent's events carry sensitive patterns
            (default 0.05).
        over_tracking_threshold: per-event flag triggers when
            ``event_property_count`` exceeds this value (default 30).
        sensitive_event_property_keys: property keys whose presence on a
            ``$people_set`` event triggers PR-04 FAIL (default to mapping).
        webhook_allowlist: hosts (scheme://host) considered safe webhook
            destinations (default empty → all webhooks flagged).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        high_volume_threshold: int | None = None,
        pii_concentration_threshold: float | None = None,
        over_tracking_threshold: int | None = None,
        sensitive_event_property_keys: Iterable[str] | None = None,
        webhook_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        if high_volume_threshold is not None:
            self.high_volume_threshold = int(high_volume_threshold)
        else:
            self.high_volume_threshold = _coerce_int(
                meta.get("high_volume_threshold"),
                _DEFAULT_HIGH_VOLUME_THRESHOLD,
            )
        self.high_volume_window_seconds = _coerce_int(
            meta.get("high_volume_window_seconds"),
            _DEFAULT_HIGH_VOLUME_WINDOW_SECONDS,
        )

        if pii_concentration_threshold is not None:
            self.pii_concentration_threshold = float(pii_concentration_threshold)
        else:
            raw = meta.get("pii_concentration_threshold")
            try:
                self.pii_concentration_threshold = (
                    float(raw)
                    if isinstance(raw, (int, float))
                    else _DEFAULT_PII_CONCENTRATION_THRESHOLD
                )
            except (TypeError, ValueError):
                self.pii_concentration_threshold = (
                    _DEFAULT_PII_CONCENTRATION_THRESHOLD
                )

        if over_tracking_threshold is not None:
            self.over_tracking_threshold = int(over_tracking_threshold)
        else:
            self.over_tracking_threshold = _coerce_int(
                meta.get("over_tracking_threshold"),
                _DEFAULT_OVER_TRACKING_THRESHOLD,
            )

        if sensitive_event_property_keys is not None:
            self.sensitive_event_property_keys = frozenset(
                str(k).lower() for k in sensitive_event_property_keys
            )
        else:
            meta_keys = meta.get("sensitive_event_property_keys")
            if isinstance(meta_keys, list) and meta_keys:
                self.sensitive_event_property_keys = frozenset(
                    str(k).lower() for k in meta_keys
                )
            else:
                self.sensitive_event_property_keys = (
                    _DEFAULT_SENSITIVE_EVENT_PROPERTY_KEYS
                )

        block_kinds = meta.get("block_sensitive_pattern_kinds")
        if isinstance(block_kinds, list) and block_kinds:
            self.block_pattern_kinds = frozenset(str(k) for k in block_kinds)
        else:
            self.block_pattern_kinds = _DEFAULT_BLOCK_PATTERN_KINDS

        flag_kinds = meta.get("flag_sensitive_pattern_kinds")
        if isinstance(flag_kinds, list) and flag_kinds:
            self.flag_pattern_kinds = frozenset(str(k) for k in flag_kinds)
        else:
            self.flag_pattern_kinds = _DEFAULT_FLAG_PATTERN_KINDS

        identity_events = meta.get("identity_linking_events")
        if isinstance(identity_events, list) and identity_events:
            self.identity_linking_events = frozenset(
                str(e) for e in identity_events
            )
        else:
            self.identity_linking_events = _DEFAULT_IDENTITY_LINKING_EVENTS

        people_events = meta.get("people_set_events")
        if isinstance(people_events, list) and people_events:
            self.people_set_events = frozenset(str(e) for e in people_events)
        else:
            self.people_set_events = _DEFAULT_PEOPLE_SET_EVENTS

        eu_regions = meta.get("eu_data_residency_regions")
        if isinstance(eu_regions, list) and eu_regions:
            self.eu_regions = frozenset(str(r).upper() for r in eu_regions)
        else:
            self.eu_regions = _DEFAULT_EU_REGIONS

        if webhook_allowlist is not None:
            self.webhook_allowlist = frozenset(
                str(h).rstrip("/") for h in webhook_allowlist
            )
        else:
            meta_allow = meta.get("webhook_allowlist")
            if isinstance(meta_allow, list):
                self.webhook_allowlist = frozenset(
                    str(h).rstrip("/") for h in meta_allow
                )
            else:
                self.webhook_allowlist = frozenset()

    # ----------------------------------------------------------------- public

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Mixpanel export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events, audit_logs = self._records_from_text(text)
        return self._build_results(
            events, audit_logs, file_sha256=file_sha256
        )

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Mixpanel export content from a JSON or JSONL string."""
        events, audit_logs = self._records_from_text(content)
        return self._build_results(events, audit_logs, file_sha256=None)

    # ----------------------------------------------------------------- shape

    def _records_from_text(
        self, text: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Auto-detect events vs audit logs from JSON / JSONL content."""
        stripped = text.lstrip()
        if not stripped:
            return [], []

        events: list[dict[str, Any]] = []
        audit_logs: list[dict[str, Any]] = []

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return self._dispatch_records(list(_iter_jsonl(text)))

            if isinstance(doc, list):
                return self._dispatch_records(
                    [r for r in doc if isinstance(r, dict)]
                )
            if isinstance(doc, dict):
                # Explicit envelopes.
                ev = doc.get("events")
                if isinstance(ev, list):
                    events.extend(r for r in ev if isinstance(r, dict))
                au = doc.get("audit_log")
                if isinstance(au, list):
                    audit_logs.extend(r for r in au if isinstance(r, dict))
                # Mixed `data` envelope: dispatch per-record.
                data = doc.get("data")
                if isinstance(data, list):
                    e2, a2 = self._dispatch_records(
                        [r for r in data if isinstance(r, dict)]
                    )
                    events.extend(e2)
                    audit_logs.extend(a2)
                # Single bare record.
                if not events and not audit_logs:
                    e2, a2 = self._dispatch_records([doc])
                    events.extend(e2)
                    audit_logs.extend(a2)
                return events, audit_logs
            return [], []

        return self._dispatch_records(list(_iter_jsonl(text)))

    @staticmethod
    def _dispatch_records(
        records: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Dispatch a flat list of records into events vs audit-log buckets."""
        events: list[dict[str, Any]] = []
        audit_logs: list[dict[str, Any]] = []
        for r in records:
            if "event" in r:
                events.append(r)
            elif "action" in r:
                audit_logs.append(r)
            else:
                # Unknown shape — drop silently to avoid noisy false positives.
                continue
        return events, audit_logs

    # ----------------------------------------------------------------- build

    def _source_provenance(
        self, *, file_sha256: str | None, record_id: str | None = None
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "mixpanel",
            "source_tool_name": "mixpanel",
            "source_tool_version": "v2",
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        events: list[dict[str, Any]],
        audit_logs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not events and not audit_logs:
            return [self._empty_result(file_sha256=file_sha256)]

        # First pass: aggregate sensitive-event counts per agent for synthetic
        # findings. We use the upstream-supplied agent_id from event properties.
        agent_event_total: dict[str, int] = {}
        agent_sensitive_count: dict[str, int] = {}
        agent_sensitive_times: dict[str, list[int]] = {}
        for event in events:
            props = (
                event.get("properties")
                if isinstance(event.get("properties"), dict)
                else {}
            )
            agent_id = props.get("agent_id")
            if not isinstance(agent_id, str) or not agent_id:
                continue
            agent_event_total[agent_id] = agent_event_total.get(agent_id, 0) + 1
            sensitive = _coerce_bool(props.get("contains_sensitive_pattern"))
            if sensitive is True:
                agent_sensitive_count[agent_id] = (
                    agent_sensitive_count.get(agent_id, 0) + 1
                )
                ts = event.get("time")
                if isinstance(ts, (int, float)) and ts > 0:
                    agent_sensitive_times.setdefault(agent_id, []).append(int(ts))

        results: list[EvaluationResult] = []
        for event in events:
            results.append(
                self._parse_event(event, file_sha256=file_sha256)
            )
        for entry in audit_logs:
            results.append(
                self._parse_audit_entry(entry, file_sha256=file_sha256)
            )

        # Synthetic: high-volume sensitive-pattern bursts.
        for agent_id, times in sorted(agent_sensitive_times.items()):
            if not times:
                continue
            times.sort()
            window = self.high_volume_window_seconds
            i = 0
            best = 0
            for j, t in enumerate(times):
                while i <= j and t - times[i] > window:
                    i += 1
                run = j - i + 1
                if run > best:
                    best = run
            if best > self.high_volume_threshold:
                results.append(
                    self._synthetic_high_volume_result(
                        agent_id=agent_id,
                        burst_count=best,
                        window_seconds=window,
                        file_sha256=file_sha256,
                    )
                )

        # Synthetic: PII concentration per agent. Require at least 5 events to
        # avoid false positives from tiny exports (e.g. 1/1=100%).
        for agent_id, total in sorted(agent_event_total.items()):
            sensitive = agent_sensitive_count.get(agent_id, 0)
            if total < 5 or sensitive <= 0:
                continue
            ratio = sensitive / total
            if ratio > self.pii_concentration_threshold:
                results.append(
                    self._synthetic_pii_concentration_result(
                        agent_id=agent_id,
                        sensitive_count=sensitive,
                        total_count=total,
                        ratio=ratio,
                        file_sha256=file_sha256,
                    )
                )

        return results

    # ----------------------------------------------------------------- event

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        event_name = _coerce_str(event.get("event")) or "unknown"
        time_raw = event.get("time")
        try:
            time_int = int(time_raw) if isinstance(time_raw, (int, float)) else 0
        except (TypeError, ValueError, OverflowError):
            time_int = 0
        if time_int > 0:
            try:
                timestamp = datetime.fromtimestamp(
                    time_int, tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError, OverflowError):
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        insert_id = _coerce_str(event.get("insert_id"))
        distinct_id = event.get("distinct_id")
        props = (
            event.get("properties")
            if isinstance(event.get("properties"), dict)
            else {}
        )

        # Property keys (do NOT store values).
        if isinstance(props.get("property_keys"), list):
            property_keys = [str(k) for k in props.get("property_keys")]
        else:
            property_keys = sorted(str(k) for k in props)
        try:
            property_count = int(
                props.get("event_property_count")
                if props.get("event_property_count") is not None
                else len(property_keys)
            )
        except (TypeError, ValueError):
            property_count = len(property_keys)

        sensitive_flag = _coerce_bool(props.get("contains_sensitive_pattern"))
        patterns_matched_raw = props.get("sensitive_patterns_matched") or []
        patterns_matched = (
            [str(p) for p in patterns_matched_raw]
            if isinstance(patterns_matched_raw, list)
            else []
        )
        agent_id_observed = props.get("agent_id")
        is_imported = _coerce_bool(props.get("is_imported"))
        consent = _coerce_bool(props.get("tracking_consent_recorded"))
        server_geo = _coerce_str(props.get("server_geo")).upper() or None
        residency = _coerce_str(props.get("data_residency_region")).upper() or None
        mp_lib = _coerce_str(props.get("mp_lib")) or None
        mp_processing_time_ms = props.get("mp_processing_time_ms")
        try:
            mp_processing_ms_f = (
                float(mp_processing_time_ms)
                if isinstance(mp_processing_time_ms, (int, float))
                else 0.0
            )
        except (TypeError, ValueError):
            mp_processing_ms_f = 0.0

        # Sanitized identifiers.
        common_evidence: dict[str, Any] = {
            "event": event_name,
            "insert_id": insert_id or None,
            "distinct_id_suffix": _last_n(distinct_id, 8),
            "user_id_suffix": _last_n(props.get("$user_id"), 8),
            "device_id_suffix": _last_n(props.get("$device_id"), 8),
            "ip_masked": _mask_ip(props.get("$ip")),
            "mp_lib": mp_lib,
            "mp_processing_time_ms": mp_processing_ms_f,
            "event_property_count": property_count,
            "property_keys": property_keys,
            "contains_sensitive_pattern": (
                bool(sensitive_flag) if sensitive_flag is not None else None
            ),
            "sensitive_patterns_matched": patterns_matched,
            "agent_id_observed": (
                str(agent_id_observed)
                if isinstance(agent_id_observed, str)
                else None
            ),
            "is_imported": (
                bool(is_imported) if is_imported is not None else None
            ),
            "server_geo": server_geo,
            "data_residency_region": residency,
            "tracking_consent_recorded": (
                bool(consent) if consent is not None else None
            ),
            "source_tool": "mixpanel",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=insert_id or None,
            ),
        }

        control_results: list[ControlResult] = []
        identity = (
            (insert_id or _last_n(distinct_id, 8) or uuid.uuid4().hex)[:32]
        )

        # 1. Sensitive-pattern matches drive PR-04 BLOCK / FLAG.
        ssn_hit = any(p in self.block_pattern_kinds and "ssn" in p for p in patterns_matched)
        cc_hit = any(
            p in self.block_pattern_kinds and "credit_card" in p
            for p in patterns_matched
        )
        email_hit = any(p in self.flag_pattern_kinds for p in patterns_matched)
        if ssn_hit:
            signal = "sensitive_pattern_ssn"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Mixpanel event {event_name!r} (insert_id={insert_id or '?'}) "
                        f"contains SSN-like pattern in properties — analytics PII leak"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )
        if cc_hit:
            signal = "sensitive_pattern_credit_card"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Mixpanel event {event_name!r} (insert_id={insert_id or '?'}) "
                        f"contains credit-card-like pattern in properties — PCI surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )
        if email_hit and not ssn_hit and not cc_hit:
            signal = "sensitive_pattern_email"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel event {event_name!r} contains email pattern "
                        f"in properties — should be hashed before transmission"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )
        if (
            sensitive_flag is True
            and not ssn_hit
            and not cc_hit
            and not email_hit
        ):
            signal = "sensitive_pattern_generic"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel event {event_name!r} marked "
                        f"contains_sensitive_pattern=true (kinds="
                        f"{patterns_matched or 'unspecified'})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )

        # 2. $people_set with sensitive property keys → PR-04 FAIL.
        if event_name in self.people_set_events:
            sensitive_keys = sorted(
                k
                for k in property_keys
                if k.lower() in self.sensitive_event_property_keys
            )
            if sensitive_keys:
                signal = "people_set_sensitive_property"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Mixpanel {event_name} sets sensitive profile "
                            f"properties: {', '.join(sensitive_keys)} — these "
                            f"should never be stored on a profile"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "sensitive_property_keys": sensitive_keys,
                        },
                        duration_ms=mp_processing_ms_f,
                    )
                )

        # 3. Identity linking ($identify / $alias) with stable id → PR-04 FLAG.
        if event_name in self.identity_linking_events:
            stable_id = props.get("$user_id") or distinct_id
            if isinstance(stable_id, str) and stable_id:
                signal = "identity_linking"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Mixpanel {event_name} performs cross-session "
                            f"identity linking (stable id suffix="
                            f"{_last_n(stable_id, 8)}) — privacy-relevant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                        duration_ms=mp_processing_ms_f,
                    )
                )

        # 4. Over-tracking — too many properties on one event.
        if property_count > self.over_tracking_threshold:
            signal = "over_tracking"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel event {event_name!r} carries "
                        f"{property_count} properties (> threshold "
                        f"{self.over_tracking_threshold}) — fishing for properties"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "over_tracking_threshold": self.over_tracking_threshold,
                    },
                    duration_ms=mp_processing_ms_f,
                )
            )

        # 5. Cross-region tracking — residency != server_geo.
        if residency and server_geo and residency != server_geo:
            signal = "cross_region_tracking"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel event {event_name!r} crossed regions: "
                        f"data_residency={residency} vs server_geo={server_geo} "
                        f"— GDPR-relevant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )

        # 6. Consent: EU FAIL, non-EU FLAG.
        if consent is False:
            in_eu = bool(residency and residency in self.eu_regions)
            if in_eu:
                signal = "eu_no_consent"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Mixpanel event {event_name!r} from EU residency "
                            f"{residency} has tracking_consent_recorded=false "
                            f"— GDPR consent missing"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                        duration_ms=mp_processing_ms_f,
                    )
                )
            else:
                signal = "non_eu_no_consent"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Mixpanel event {event_name!r} has "
                            f"tracking_consent_recorded=false (residency="
                            f"{residency or 'unknown'}) — CCPA territory"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                        duration_ms=mp_processing_ms_f,
                    )
                )

        # 7. is_imported=true → PR-05 PASS audit-trail evidence.
        if is_imported is True:
            signal = "is_imported"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Mixpanel event {event_name!r} is_imported=true "
                        f"— retroactive audit trail recorded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                    duration_ms=mp_processing_ms_f,
                )
            )

        # Guarantee at least one control result.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Mixpanel event {event_name!r} imported "
                        f"(no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "event_default"},
                    duration_ms=mp_processing_ms_f,
                )
            )

        decision = self._decision(control_results)
        decision_reason = (
            f"Imported from Mixpanel: event={event_name} "
            f"insert_id={insert_id or 'null'} "
            f"contains_sensitive_pattern={sensitive_flag} "
            f"patterns={patterns_matched or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mixpanel-event-{identity}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="mixpanel_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=mp_processing_ms_f,
            session_id=(
                str(agent_id_observed)
                if isinstance(agent_id_observed, str)
                else None
            ),
        )

    # ----------------------------------------------------------------- audit

    def _parse_audit_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        action = _coerce_str(entry.get("action")) or "unknown"
        timestamp_raw = entry.get("timestamp")
        if isinstance(timestamp_raw, str) and timestamp_raw.strip():
            timestamp = timestamp_raw
        elif isinstance(timestamp_raw, (int, float)) and timestamp_raw > 0:
            try:
                timestamp = datetime.fromtimestamp(
                    float(timestamp_raw), tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError, OverflowError):
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        actor = entry.get("actor") if isinstance(entry.get("actor"), dict) else {}
        details = (
            entry.get("details") if isinstance(entry.get("details"), dict) else {}
        )

        actor_user_id = actor.get("user_id")
        actor_email = actor.get("email")
        actor_email_domain = None
        if isinstance(actor_email, str) and "@" in actor_email:
            actor_email_domain = actor_email.split("@", 1)[1]
        is_service_account = _coerce_bool(actor.get("is_service_account"))

        webhook_url = details.get("webhook_url") or details.get("webhook_url_host")
        webhook_host = _host_only(webhook_url)

        common_evidence: dict[str, Any] = {
            "audit_action": action,
            "actor_user_id_suffix": _last_n(actor_user_id, 8),
            "actor_email_domain": actor_email_domain,
            "actor_is_service_account": (
                bool(is_service_account)
                if is_service_account is not None
                else None
            ),
            "target_project_id": _coerce_str(details.get("target_project_id"))
            or None,
            "previous_value": _coerce_str(details.get("previous_value")) or None,
            "new_value": _coerce_str(details.get("new_value")) or None,
            "webhook_url_host": webhook_host,
            "source_tool": "mixpanel",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=f"audit-{action}-{timestamp}",
            ),
        }

        control_results: list[ControlResult] = []

        if action == "data_residency_changed":
            signal = "audit_data_residency_changed"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Mixpanel audit: data residency changed "
                        f"({common_evidence['previous_value']!r} → "
                        f"{common_evidence['new_value']!r}) — GDPR-relevant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif action == "data_export":
            signal = "audit_data_export"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel audit: analytics data export performed "
                        f"by actor (suffix={common_evidence['actor_user_id_suffix']}) "
                        f"— exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif action == "retention_policy_changed":
            signal = "audit_retention_policy_changed"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Mixpanel audit: retention policy changed "
                        f"({common_evidence['previous_value']!r} → "
                        f"{common_evidence['new_value']!r}) — audit completeness"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif action == "gdpr_deletion_request":
            signal = "audit_gdpr_deletion_request"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        "Mixpanel audit: GDPR deletion request recorded "
                        "— compliance-mandated audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif action == "api_key_created":
            if is_service_account is False:
                signal = "audit_api_key_created_human"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Mixpanel audit: API key created by human actor "
                            f"(suffix={common_evidence['actor_user_id_suffix']}) "
                            f"— prefer service-account-issued keys"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif action == "webhook_url_added":
            in_allow = (
                bool(webhook_host)
                and webhook_host.rstrip("/") in self.webhook_allowlist
            )
            if not in_allow:
                signal = "audit_webhook_url_added"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Mixpanel audit: webhook URL added pointing to "
                            f"{webhook_host or 'unknown'} (not in allowlist) "
                            f"— external destination"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif action == "project_member_added":
            signal = "audit_project_member_added"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        "Mixpanel audit: project member added — verify scope "
                        "of new principal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Mixpanel audit action {action!r} imported "
                        f"(no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "audit_default"},
                )
            )

        decision = self._decision(control_results)
        decision_reason = (
            f"Imported from Mixpanel audit: action={action} "
            f"actor_is_service_account={is_service_account}"
        )
        identity = (action + "-" + (timestamp or uuid.uuid4().hex))[:48]

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mixpanel-audit-{identity}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="mixpanel_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # ----------------------------------------------------------------- synth

    def _synthetic_high_volume_result(
        self,
        *,
        agent_id: str,
        burst_count: int,
        window_seconds: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_sensitive"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"mixpanel-high-volume-{agent_id}"
        evidence: dict[str, Any] = {
            "agent_id_observed": agent_id,
            "burst_count": burst_count,
            "window_seconds": window_seconds,
            "high_volume_threshold": self.high_volume_threshold,
            "synthetic": True,
            "source_tool": "mixpanel",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Mixpanel synthetic finding: agent {agent_id} emitted "
                f"{burst_count} sensitive-pattern events in a "
                f"{window_seconds}s window (> threshold "
                f"{self.high_volume_threshold})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mixpanel_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Mixpanel: synthetic high-volume sensitive "
                f"agent={agent_id} burst={burst_count}>"
                f"{self.high_volume_threshold} window={window_seconds}s"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_pii_concentration_result(
        self,
        *,
        agent_id: str,
        sensitive_count: int,
        total_count: int,
        ratio: float,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "pii_concentration"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"mixpanel-pii-concentration-{agent_id}"
        evidence: dict[str, Any] = {
            "agent_id_observed": agent_id,
            "sensitive_count": sensitive_count,
            "total_count": total_count,
            "ratio": ratio,
            "pii_concentration_threshold": self.pii_concentration_threshold,
            "synthetic": True,
            "source_tool": "mixpanel",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Mixpanel synthetic finding: agent {agent_id} has "
                f"{sensitive_count}/{total_count} ({ratio:.1%}) sensitive-pattern "
                f"events (> threshold {self.pii_concentration_threshold:.1%})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mixpanel_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Mixpanel: synthetic pii_concentration "
                f"agent={agent_id} ratio={ratio:.3f}>"
                f"{self.pii_concentration_threshold:.3f}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # ----------------------------------------------------------------- empty

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty Mixpanel export (no events or audit records)",
            evidence_data={
                "source_provenance": provenance,
                "event_count": 0,
                "audit_count": 0,
            },
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mixpanel-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mixpanel_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Mixpanel export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    # ----------------------------------------------------------------- util

    @staticmethod
    def _decision(results: list[ControlResult]) -> str:
        if any(cr.result == "FAIL" for cr in results):
            return "BLOCK"
        if any(cr.result == "FLAG" for cr in results):
            return "FLAG"
        return "ALLOW"
