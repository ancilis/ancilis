# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""PostHog analytics + LLM-observability importer.

PostHog (https://posthog.com) is the leading open-source product-analytics
platform with strong AI-native focus: ``$ai_generation`` / ``$ai_metric`` /
``$ai_trace`` / ``$ai_span`` / ``$ai_error`` events for LLM observability,
plus session replay, feature flags, experiments, and surveys. Distinct from
Mixpanel: PostHog ships its own AI Engineer features (LLM tracing with
prompt + completion capture, hallucination/toxicity/safety metrics) AND
session recordings — both are top-tier exfiltration surfaces.

Wire shapes accepted (auto-detected):

  1. ``{"events": [...]}``     — primary capture-events envelope
  2. ``{"audit_log": [...]}``  — admin activity-log envelope
  3. ``{"data": [...]}``       — mixed envelope; per-record dispatch by
                                  presence of ``event`` (event) vs
                                  ``activity`` (audit log)
  4. JSONL                      — one event or audit record per line
  5. Mixed envelope             — both ``events`` and ``audit_log`` keys

Signal mapping (see ``shared/mappings/posthog-aksi-controls.json``):

Events:
  * ``event=$ai_generation`` & ``$ai_is_error=false``                   → PR-01 PASS (LLM call audit)
  * ``event=$ai_generation`` & ``$ai_is_error=true``                    → DE-01 FAIL (AI call failure)
  * ``event=$ai_metric`` & metric in {hallucination, toxicity} > thr    → PR-03 FAIL
  * ``event=$ai_metric`` & metric=safety < safety_floor                 → DE-01 FAIL
  * ``event=$ai_error``                                                 → DE-01 FAIL
  * ``event=$identify`` w/ ``$set`` containing sensitive keys           → PR-04 FAIL → BLOCK
  * ``event=$set`` / ``$set_once`` with sensitive keys                  → PR-04 FAIL
  * ``properties.contains_sensitive_pattern=true``                      → PR-04 FLAG (or FAIL on ssn/cc kinds)
  * ``sensitive_patterns_matched`` ⊇ {ssn_like, credit_card_like}       → PR-04 FAIL → BLOCK
  * ``$session_recording_started`` on EU geoip w/o explicit consent     → PR-04 FLAG
  * ``$pageview`` on EU geoip + no consent indicator                    → PR-04 FLAG
  * ``$ai_total_cost_usd`` > threshold (default $1)                     → PR-04 FLAG
  * ``$feature_flag_called``                                            → PR-05 PASS (audit)

Audit log:
  * ``activity=insight_shared_publicly``                                → PR-04 FAIL
  * ``activity=recording_share_link_created``                           → PR-04 FAIL → BLOCK
  * ``activity=data_export``                                            → PR-04 FLAG
  * ``activity=api_key_created``                                        → PR-01 FLAG
  * ``activity=plugin_installed``                                       → PR-01 FLAG
  * ``activity=webhook_url_changed`` not in allowlist                   → PR-04 FLAG
  * ``activity=team_member_role_changed`` & new_role=admin              → PR-02 FLAG

Synthetic findings (per agent_id, across the export):
  * PII concentration (> threshold of events carry sensitive patterns)  → PR-04 FAIL
  * AI error rate (> threshold of $ai_generation events errored)        → DE-01 FAIL
  * Recording-share burst (> N share links in window)                   → PR-04 FAIL

Sanitization — what we DO NOT store:
  * raw ``properties.$ai_input_state`` / ``$ai_output_state`` — these
    contain prompt + completion text. Only length + sha256 are stored.
  * raw ``$set`` values — only the key list and sensitive_patterns_matched
  * full ``distinct_id`` (last 8 chars only)
  * full ``$ip`` (masked to /16)
  * full ``item_id`` (last 8 chars only)
  * ``changes[].before`` / ``after`` raw values — only the field name
  * full ``actor.email`` — domain only

The SDK is importable without ``posthog`` installed; this importer parses
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


def _resolve_mapping_path() -> Path:
    """Locate ``shared/mappings/posthog-aksi-controls.json`` by walking upward."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "shared" / "mappings" / "posthog-aksi-controls.json"
        if candidate.exists():
            return candidate
    return here.parents[4] / "shared" / "mappings" / "posthog-aksi-controls.json"


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_PII_CONCENTRATION_THRESHOLD = 0.05
_DEFAULT_AI_ERROR_RATE_THRESHOLD = 0.10
_DEFAULT_AI_ERROR_RATE_MIN_EVENTS = 10
_DEFAULT_RECORDING_SHARE_BURST_THRESHOLD = 3
_DEFAULT_RECORDING_SHARE_BURST_WINDOW_SECONDS = 3600
_DEFAULT_AI_COST_THRESHOLD_USD = 1.0
_DEFAULT_AI_HALLUCINATION_THRESHOLD = 0.5
_DEFAULT_AI_TOXICITY_THRESHOLD = 0.5
_DEFAULT_AI_SAFETY_FLOOR = 0.5
_DEFAULT_SENSITIVE_EVENT_PROPERTY_KEYS: frozenset[str] = frozenset(
    {
        "ssn",
        "credit_card",
        "full_name",
        "ssn_last4",
        "drivers_license",
        "passport",
        "tax_id",
        "bank_account",
        "date_of_birth",
        "phone",
        "full_address",
    }
)
_DEFAULT_BLOCK_PATTERN_KINDS: frozenset[str] = frozenset(
    {"ssn_like", "credit_card_like", "ssn_like_pattern", "credit_card_like_pattern"}
)
_DEFAULT_FLAG_PATTERN_KINDS: frozenset[str] = frozenset({"email"})
_DEFAULT_AI_GENERATION_EVENTS: frozenset[str] = frozenset(
    {"$ai_generation", "$ai_span", "$ai_trace"}
)
_DEFAULT_AI_METRIC_EVENTS: frozenset[str] = frozenset({"$ai_metric"})
_DEFAULT_AI_ERROR_EVENTS: frozenset[str] = frozenset({"$ai_error"})
_DEFAULT_IDENTIFY_EVENTS: frozenset[str] = frozenset(
    {"$identify", "$set", "$set_once"}
)
_DEFAULT_SESSION_RECORDING_EVENTS: frozenset[str] = frozenset(
    {"$session_recording_started", "session_recording_started"}
)
_DEFAULT_AI_HIGH_SEVERITY_METRICS: frozenset[str] = frozenset(
    {"hallucination", "toxicity"}
)
_DEFAULT_AI_SAFETY_METRICS: frozenset[str] = frozenset({"safety"})
_DEFAULT_EU_REGIONS: frozenset[str] = frozenset(
    {
        "EU", "DE", "FR", "IE", "NL", "ES", "IT", "AT", "BE", "DK",
        "FI", "GR", "PL", "PT", "SE",
    }
)


def _load_mapping_table() -> dict[str, Any]:
    """Load the PostHog mapping table; tolerate missing file."""
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
    """Mask an IPv4 address to /16; return None if not parseable."""
    if not isinstance(ip, str) or not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.0.0/16"
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


def _coerce_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return float(value)
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


def _ts_to_epoch(ts: Any) -> int:
    """Best-effort conversion of an ISO-8601 timestamp or epoch to int seconds."""
    if isinstance(ts, (int, float)) and ts > 0:
        try:
            return int(ts)
        except (TypeError, ValueError, OverflowError):
            return 0
    if isinstance(ts, str) and ts.strip():
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return int(datetime.fromisoformat(s).timestamp())
        except (ValueError, TypeError):
            return 0
    return 0


class PostHogImporter:
    """Parse PostHog event/audit exports and convert to ``EvaluationResult`` records.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        pii_concentration_threshold: synthetic finding triggers when more than
            this fraction of an agent's events carry sensitive patterns
            (default 0.05).
        ai_error_rate_threshold: synthetic finding triggers when more than this
            fraction of an agent's $ai_generation events have $ai_is_error=true
            (default 0.10).
        ai_cost_threshold_usd: per-event flag triggers when
            ``$ai_total_cost_usd`` exceeds this (default $1).
        ai_hallucination_threshold: $ai_metric metric_name=hallucination value
            > threshold → PR-03 FAIL.
        ai_toxicity_threshold: same as above for ``toxicity``.
        ai_safety_floor: $ai_metric metric_name=safety value < floor → DE-01
            FAIL.
        sensitive_event_property_keys: keys whose presence on an
            $identify/$set/$set_once event triggers PR-04 FAIL → BLOCK.
        webhook_allowlist: hosts (scheme://host) considered safe webhook
            destinations (default empty → all webhooks flagged).
        recording_share_burst_threshold: synthetic finding when an actor
            creates more than this many recording share links in the window.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        pii_concentration_threshold: float | None = None,
        ai_error_rate_threshold: float | None = None,
        ai_cost_threshold_usd: float | None = None,
        ai_hallucination_threshold: float | None = None,
        ai_toxicity_threshold: float | None = None,
        ai_safety_floor: float | None = None,
        sensitive_event_property_keys: Iterable[str] | None = None,
        webhook_allowlist: Iterable[str] | None = None,
        recording_share_burst_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        def _meta_float(key: str, default: float, override: float | None) -> float:
            if override is not None:
                try:
                    return float(override)
                except (TypeError, ValueError):
                    return default
            raw = meta.get(key)
            try:
                return float(raw) if isinstance(raw, (int, float)) else default
            except (TypeError, ValueError):
                return default

        self.pii_concentration_threshold = _meta_float(
            "pii_concentration_threshold",
            _DEFAULT_PII_CONCENTRATION_THRESHOLD,
            pii_concentration_threshold,
        )
        self.ai_error_rate_threshold = _meta_float(
            "ai_error_rate_threshold",
            _DEFAULT_AI_ERROR_RATE_THRESHOLD,
            ai_error_rate_threshold,
        )
        self.ai_error_rate_min_events = _coerce_int(
            meta.get("ai_error_rate_min_events"),
            _DEFAULT_AI_ERROR_RATE_MIN_EVENTS,
        )
        self.ai_cost_threshold_usd = _meta_float(
            "ai_cost_threshold_usd",
            _DEFAULT_AI_COST_THRESHOLD_USD,
            ai_cost_threshold_usd,
        )
        self.ai_hallucination_threshold = _meta_float(
            "ai_hallucination_threshold",
            _DEFAULT_AI_HALLUCINATION_THRESHOLD,
            ai_hallucination_threshold,
        )
        self.ai_toxicity_threshold = _meta_float(
            "ai_toxicity_threshold",
            _DEFAULT_AI_TOXICITY_THRESHOLD,
            ai_toxicity_threshold,
        )
        self.ai_safety_floor = _meta_float(
            "ai_safety_floor",
            _DEFAULT_AI_SAFETY_FLOOR,
            ai_safety_floor,
        )

        if recording_share_burst_threshold is not None:
            self.recording_share_burst_threshold = int(
                recording_share_burst_threshold
            )
        else:
            self.recording_share_burst_threshold = _coerce_int(
                meta.get("recording_share_burst_threshold"),
                _DEFAULT_RECORDING_SHARE_BURST_THRESHOLD,
            )
        self.recording_share_burst_window_seconds = _coerce_int(
            meta.get("recording_share_burst_window_seconds"),
            _DEFAULT_RECORDING_SHARE_BURST_WINDOW_SECONDS,
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

        ai_gen = meta.get("ai_generation_events")
        if isinstance(ai_gen, list) and ai_gen:
            self.ai_generation_events = frozenset(str(e) for e in ai_gen)
        else:
            self.ai_generation_events = _DEFAULT_AI_GENERATION_EVENTS

        ai_metric = meta.get("ai_metric_events")
        if isinstance(ai_metric, list) and ai_metric:
            self.ai_metric_events = frozenset(str(e) for e in ai_metric)
        else:
            self.ai_metric_events = _DEFAULT_AI_METRIC_EVENTS

        ai_err_evts = meta.get("ai_error_events")
        if isinstance(ai_err_evts, list) and ai_err_evts:
            self.ai_error_events = frozenset(str(e) for e in ai_err_evts)
        else:
            self.ai_error_events = _DEFAULT_AI_ERROR_EVENTS

        identify_events = meta.get("identify_events")
        if isinstance(identify_events, list) and identify_events:
            self.identify_events = frozenset(str(e) for e in identify_events)
        else:
            self.identify_events = _DEFAULT_IDENTIFY_EVENTS

        rec_events = meta.get("session_recording_events")
        if isinstance(rec_events, list) and rec_events:
            self.session_recording_events = frozenset(
                str(e) for e in rec_events
            )
        else:
            self.session_recording_events = _DEFAULT_SESSION_RECORDING_EVENTS

        hi_metrics = meta.get("ai_high_severity_metrics")
        if isinstance(hi_metrics, list) and hi_metrics:
            self.ai_high_severity_metrics = frozenset(
                str(m).lower() for m in hi_metrics
            )
        else:
            self.ai_high_severity_metrics = _DEFAULT_AI_HIGH_SEVERITY_METRICS

        safety_metrics = meta.get("ai_safety_metrics")
        if isinstance(safety_metrics, list) and safety_metrics:
            self.ai_safety_metrics = frozenset(
                str(m).lower() for m in safety_metrics
            )
        else:
            self.ai_safety_metrics = _DEFAULT_AI_SAFETY_METRICS

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
        """Parse a PostHog export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events, audit_logs = self._records_from_text(text)
        return self._build_results(
            events, audit_logs, file_sha256=file_sha256
        )

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse PostHog export content from a JSON or JSONL string."""
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
                ev = doc.get("events")
                if isinstance(ev, list):
                    events.extend(r for r in ev if isinstance(r, dict))
                au = doc.get("audit_log")
                if isinstance(au, list):
                    audit_logs.extend(r for r in au if isinstance(r, dict))
                data = doc.get("data")
                if isinstance(data, list):
                    e2, a2 = self._dispatch_records(
                        [r for r in data if isinstance(r, dict)]
                    )
                    events.extend(e2)
                    audit_logs.extend(a2)
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
            if "activity" in r and "event" not in r:
                audit_logs.append(r)
            elif "event" in r:
                events.append(r)
            elif "activity" in r:
                audit_logs.append(r)
            else:
                continue
        return events, audit_logs

    # ----------------------------------------------------------------- build

    def _source_provenance(
        self, *, file_sha256: str | None, record_id: str | None = None
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "posthog",
            "source_tool_name": "posthog",
            "source_tool_version": "v1",
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

        # First pass: aggregate per-agent counters for synthetic findings.
        agent_event_total: dict[str, int] = {}
        agent_sensitive_count: dict[str, int] = {}
        agent_ai_total: dict[str, int] = {}
        agent_ai_errors: dict[str, int] = {}
        actor_share_times: dict[str, list[int]] = {}

        for event in events:
            props = (
                event.get("properties")
                if isinstance(event.get("properties"), dict)
                else {}
            )
            agent_id = props.get("agent_id")
            if isinstance(agent_id, str) and agent_id:
                agent_event_total[agent_id] = (
                    agent_event_total.get(agent_id, 0) + 1
                )
                if _coerce_bool(props.get("contains_sensitive_pattern")) is True:
                    agent_sensitive_count[agent_id] = (
                        agent_sensitive_count.get(agent_id, 0) + 1
                    )
                event_name = _coerce_str(event.get("event"))
                if event_name in self.ai_generation_events:
                    agent_ai_total[agent_id] = (
                        agent_ai_total.get(agent_id, 0) + 1
                    )
                    if _coerce_bool(props.get("$ai_is_error")) is True:
                        agent_ai_errors[agent_id] = (
                            agent_ai_errors.get(agent_id, 0) + 1
                        )

        for entry in audit_logs:
            activity = _coerce_str(entry.get("activity"))
            if activity == "recording_share_link_created":
                actor = (
                    entry.get("actor")
                    if isinstance(entry.get("actor"), dict)
                    else {}
                )
                actor_id = _coerce_str(actor.get("id")) or "unknown"
                ts = _ts_to_epoch(entry.get("timestamp"))
                if ts > 0:
                    actor_share_times.setdefault(actor_id, []).append(ts)

        results: list[EvaluationResult] = []
        for event in events:
            results.append(self._parse_event(event, file_sha256=file_sha256))
        for entry in audit_logs:
            results.append(
                self._parse_audit_entry(entry, file_sha256=file_sha256)
            )

        # Synthetic: PII concentration per agent.
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

        # Synthetic: AI error rate per agent.
        for agent_id, total in sorted(agent_ai_total.items()):
            errors = agent_ai_errors.get(agent_id, 0)
            if total < self.ai_error_rate_min_events or errors <= 0:
                continue
            ratio = errors / total
            if ratio > self.ai_error_rate_threshold:
                results.append(
                    self._synthetic_ai_error_rate_result(
                        agent_id=agent_id,
                        error_count=errors,
                        total_count=total,
                        ratio=ratio,
                        file_sha256=file_sha256,
                    )
                )

        # Synthetic: recording-share burst per actor.
        for actor_id, times in sorted(actor_share_times.items()):
            if not times:
                continue
            times.sort()
            window = self.recording_share_burst_window_seconds
            i = 0
            best = 0
            for j, t in enumerate(times):
                while i <= j and t - times[i] > window:
                    i += 1
                run = j - i + 1
                if run > best:
                    best = run
            if best > self.recording_share_burst_threshold:
                results.append(
                    self._synthetic_recording_share_burst_result(
                        actor_id=actor_id,
                        burst_count=best,
                        window_seconds=window,
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
        timestamp_raw = event.get("timestamp")
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

        event_id = _coerce_str(event.get("id"))
        distinct_id = event.get("distinct_id")
        props = (
            event.get("properties")
            if isinstance(event.get("properties"), dict)
            else {}
        )

        if isinstance(props.get("property_keys"), list):
            property_keys = [str(k) for k in props.get("property_keys")]
        else:
            property_keys = sorted(str(k) for k in props)

        sensitive_flag = _coerce_bool(props.get("contains_sensitive_pattern"))
        patterns_matched_raw = props.get("sensitive_patterns_matched") or []
        patterns_matched = (
            [str(p) for p in patterns_matched_raw]
            if isinstance(patterns_matched_raw, list)
            else []
        )

        ai_provider = _coerce_str(props.get("$ai_provider")) or None
        ai_model = _coerce_str(props.get("$ai_model")) or None
        ai_input_tokens = _coerce_int(props.get("$ai_input_tokens"))
        ai_output_tokens = _coerce_int(props.get("$ai_output_tokens"))
        ai_total_cost = _coerce_float(props.get("$ai_total_cost_usd"))
        ai_latency = _coerce_float(props.get("$ai_latency"))
        ai_is_error = _coerce_bool(props.get("$ai_is_error"))
        ai_error_msg = _coerce_str(props.get("$ai_error")) or None
        ai_trace_id = _coerce_str(props.get("$ai_trace_id")) or None
        ai_parent_id = _coerce_str(props.get("$ai_parent_id")) or None
        ai_metric_name = _coerce_str(props.get("$ai_metric_name")).lower() or None
        ai_metric_value = _coerce_float(props.get("$ai_metric_value"))

        def _state_summary(value: Any) -> dict[str, Any] | None:
            if value is None:
                return None
            try:
                serialized = json.dumps(value, sort_keys=True, default=str)
            except (TypeError, ValueError):
                serialized = str(value)
            return {
                "length": len(serialized),
                "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            }

        ai_input_state_summary = _state_summary(props.get("$ai_input_state"))
        ai_output_state_summary = _state_summary(props.get("$ai_output_state"))

        set_payload = (
            props.get("$set") if isinstance(props.get("$set"), dict) else None
        )
        set_once_payload = (
            props.get("$set_once")
            if isinstance(props.get("$set_once"), dict)
            else None
        )
        set_keys = sorted(set_payload.keys()) if set_payload else []
        set_once_keys = sorted(set_once_payload.keys()) if set_once_payload else []

        feature_flag = _coerce_str(props.get("$feature_flag")) or None
        feature_flag_response = props.get("$feature_flag_response")
        session_recording_started = _coerce_bool(
            props.get("$session_recording_started")
        )
        recording_disabled = _coerce_bool(
            props.get("recording_disabled_for_user")
        )
        country = _coerce_str(props.get("$geoip_country_code")).upper() or None
        ph_lib = _coerce_str(props.get("$lib")) or None
        org_id = _coerce_str(props.get("org_id")) or None
        project_id = _coerce_str(props.get("project_id")) or None
        agent_id_observed = props.get("agent_id")

        common_evidence: dict[str, Any] = {
            "event": event_name,
            "event_id_suffix": _last_n(event_id, 8),
            "distinct_id_suffix": _last_n(distinct_id, 8),
            "ip_masked": _mask_ip(props.get("$ip")),
            "geoip_country_code": country,
            "lib": ph_lib,
            "org_id": org_id,
            "project_id": project_id,
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
            "ai_provider": ai_provider,
            "ai_model": ai_model,
            "ai_input_tokens": ai_input_tokens,
            "ai_output_tokens": ai_output_tokens,
            "ai_total_cost_usd": ai_total_cost,
            "ai_latency": ai_latency,
            "ai_is_error": (
                bool(ai_is_error) if ai_is_error is not None else None
            ),
            "ai_trace_id_suffix": _last_n(ai_trace_id, 8),
            "ai_parent_id_suffix": _last_n(ai_parent_id, 8),
            "ai_metric_name": ai_metric_name,
            "ai_metric_value": ai_metric_value,
            "ai_input_state_summary": ai_input_state_summary,
            "ai_output_state_summary": ai_output_state_summary,
            "set_keys": set_keys,
            "set_once_keys": set_once_keys,
            "feature_flag": feature_flag,
            "feature_flag_response": (
                feature_flag_response
                if isinstance(feature_flag_response, (bool, str, int, float))
                else None
            ),
            "session_recording_started": (
                bool(session_recording_started)
                if session_recording_started is not None
                else None
            ),
            "recording_disabled_for_user": (
                bool(recording_disabled)
                if recording_disabled is not None
                else None
            ),
            "source_tool": "posthog",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=event_id or None,
            ),
        }

        control_results: list[ControlResult] = []
        identity = (
            (event_id or _last_n(distinct_id, 8) or uuid.uuid4().hex)[:32]
        )

        # 1. AI generation events.
        if event_name in self.ai_generation_events:
            if ai_is_error is True:
                signal = "ai_generation_error"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"PostHog {event_name} reported $ai_is_error=true "
                            f"(provider={ai_provider}, model={ai_model}, "
                            f"error={ai_error_msg!r}) — AI call failure"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                        duration_ms=ai_latency * 1000.0,
                    )
                )
            else:
                signal = "ai_generation_pass"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"PostHog {event_name} succeeded "
                            f"(provider={ai_provider}, model={ai_model}, "
                            f"in={ai_input_tokens}t out={ai_output_tokens}t "
                            f"cost=${ai_total_cost:.4f})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                        duration_ms=ai_latency * 1000.0,
                    )
                )

        # 2. AI metrics — hallucination, toxicity, safety.
        if event_name in self.ai_metric_events and ai_metric_name:
            if ai_metric_name in self.ai_high_severity_metrics:
                threshold = (
                    self.ai_hallucination_threshold
                    if ai_metric_name == "hallucination"
                    else self.ai_toxicity_threshold
                )
                if ai_metric_value > threshold:
                    signal = (
                        "ai_metric_high_hallucination"
                        if ai_metric_name == "hallucination"
                        else "ai_metric_high_toxicity"
                    )
                    control_id = _control_for(signal, self._mappings, "PR-03")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(
                                control_id, control_id
                            ),
                            result="FAIL",
                            detail=(
                                f"PostHog $ai_metric metric_name="
                                f"{ai_metric_name} value="
                                f"{ai_metric_value:.3f} exceeds threshold "
                                f"{threshold:.3f}"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
            elif (
                ai_metric_name in self.ai_safety_metrics
                and ai_metric_value < self.ai_safety_floor
            ):
                signal = "ai_metric_low_safety"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"PostHog $ai_metric safety value="
                            f"{ai_metric_value:.3f} below floor "
                            f"{self.ai_safety_floor:.3f}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # 3. AI error events.
        if event_name in self.ai_error_events:
            signal = "ai_error_event"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"PostHog {event_name} captured AI error "
                        f"(error={ai_error_msg!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. $identify / $set / $set_once with sensitive keys → PR-04 BLOCK.
        if event_name in self.identify_events:
            sensitive_keys = sorted(
                k
                for k in (set_keys + set_once_keys)
                if k.lower() in self.sensitive_event_property_keys
            )
            if sensitive_keys:
                signal = "set_sensitive_property"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"PostHog {event_name} sets sensitive profile "
                            f"properties: {', '.join(sensitive_keys)} — "
                            f"these should never be persisted on a profile"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "sensitive_set_keys": sensitive_keys,
                        },
                    )
                )

        # 5. Sensitive-pattern signals from properties.
        ssn_hit = any(
            p in self.block_pattern_kinds and "ssn" in p
            for p in patterns_matched
        )
        cc_hit = any(
            p in self.block_pattern_kinds and "credit_card" in p
            for p in patterns_matched
        )
        email_hit = any(
            p in self.flag_pattern_kinds for p in patterns_matched
        )
        if ssn_hit:
            signal = "sensitive_pattern_ssn"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"PostHog event {event_name!r} contains SSN-like "
                        f"pattern in properties — analytics PII leak"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
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
                        f"PostHog event {event_name!r} contains credit-card-like "
                        f"pattern in properties — PCI surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
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
                        f"PostHog event {event_name!r} contains email pattern "
                        f"in properties — should be hashed before transmission"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
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
                        f"PostHog event {event_name!r} marked "
                        f"contains_sensitive_pattern=true (kinds="
                        f"{patterns_matched or 'unspecified'})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Session recording started on EU geoip without consent → FLAG.
        in_eu = bool(country and country in self.eu_regions)
        is_recording_event = (
            event_name in self.session_recording_events
            or session_recording_started is True
        )
        if (
            is_recording_event
            and in_eu
            and recording_disabled is not True
        ):
            signal = "session_recording_eu_no_consent"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog session recording started for EU user "
                        f"(country={country}) without explicit consent — "
                        f"GDPR-relevant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 7. $pageview on EU geoip without consent indicator.
        if (
            event_name == "$pageview"
            and in_eu
            and recording_disabled is not True
        ):
            signal = "pageview_eu_no_consent"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog $pageview from EU user (country={country}) "
                        f"with no consent indicator — GDPR-relevant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 8. AI cost overage.
        if (
            event_name in self.ai_generation_events
            and ai_total_cost > self.ai_cost_threshold_usd
        ):
            signal = "ai_high_cost"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog $ai_generation total_cost_usd="
                        f"{ai_total_cost:.4f} > threshold "
                        f"{self.ai_cost_threshold_usd:.2f}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 9. $feature_flag_called → audit PASS.
        if event_name == "$feature_flag_called":
            signal = "feature_flag_called"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"PostHog feature flag {feature_flag or '?'} "
                        f"evaluated (response={feature_flag_response!r}) "
                        f"— audit captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
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
                        f"PostHog event {event_name!r} imported "
                        f"(no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "event_default"},
                )
            )

        decision = self._decision(control_results)
        decision_reason = (
            f"Imported from PostHog: event={event_name} "
            f"id_suffix={_last_n(event_id, 8) or 'null'} "
            f"contains_sensitive_pattern={sensitive_flag}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"posthog-event-{identity}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="posthog_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=ai_latency * 1000.0,
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
        activity = _coerce_str(entry.get("activity")) or "unknown"
        scope = _coerce_str(entry.get("scope")) or None
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
        detail = (
            entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        )

        actor_id = actor.get("id")
        actor_email = actor.get("email")
        actor_email_domain = None
        if isinstance(actor_email, str) and "@" in actor_email:
            actor_email_domain = actor_email.split("@", 1)[1]
        is_service_account = _coerce_bool(actor.get("is_service_account"))

        item_id = entry.get("item_id")
        new_value = detail.get("new_value")
        changes_raw = detail.get("changes")
        change_fields: list[str] = []
        if isinstance(changes_raw, list):
            for c in changes_raw:
                if isinstance(c, dict) and isinstance(c.get("field"), str):
                    change_fields.append(c["field"])

        webhook_url = (
            new_value
            if isinstance(new_value, str)
            and (
                new_value.startswith("http://")
                or new_value.startswith("https://")
            )
            else detail.get("webhook_url")
        )
        webhook_host = _host_only(webhook_url)

        common_evidence: dict[str, Any] = {
            "audit_activity": activity,
            "audit_scope": scope,
            "actor_id_suffix": _last_n(actor_id, 8),
            "actor_email_domain": actor_email_domain,
            "actor_is_service_account": (
                bool(is_service_account)
                if is_service_account is not None
                else None
            ),
            "item_id_suffix": _last_n(item_id, 8),
            "change_fields": change_fields,
            "webhook_url_host": webhook_host,
            "source_tool": "posthog",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=f"audit-{activity}-{timestamp}",
            ),
        }

        control_results: list[ControlResult] = []

        if activity == "insight_shared_publicly":
            signal = "audit_insight_shared_publicly"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"PostHog audit: insight (item suffix="
                        f"{_last_n(item_id, 8)}) shared publicly — "
                        f"analytics may include user values; public share "
                        f"= exposure"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "recording_share_link_created":
            signal = "audit_recording_share_link_created"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"PostHog audit: session-recording share link created "
                        f"(item suffix={_last_n(item_id, 8)}) — recording = "
                        f"full-fidelity user PII; public share is top-priority "
                        f"exfil → BLOCK"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "data_export":
            signal = "audit_data_export"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: data export performed by actor "
                        f"(suffix={_last_n(actor_id, 8)}) — exfil surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "api_key_created":
            signal = "audit_api_key_created"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: API key created by actor "
                        f"(suffix={_last_n(actor_id, 8)}, "
                        f"service_account={is_service_account}) — verify"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "plugin_installed":
            signal = "audit_plugin_installed"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: plugin installed (item suffix="
                        f"{_last_n(item_id, 8)}) — new automation surface, "
                        f"verify plugin source"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "webhook_url_changed":
            in_allow = (
                bool(webhook_host)
                and webhook_host.rstrip("/") in self.webhook_allowlist
            )
            if not in_allow:
                signal = "audit_webhook_url_changed"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"PostHog audit: webhook URL changed to "
                            f"{webhook_host or 'unknown'} (not in allowlist) "
                            f"— external destination"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif activity == "team_member_role_changed":
            new_role_str = ""
            if isinstance(new_value, str):
                new_role_str = new_value.lower()
            elif isinstance(detail.get("new_role"), str):
                new_role_str = str(detail.get("new_role")).lower()
            if new_role_str == "admin":
                signal = "audit_role_admin_changed"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"PostHog audit: team member role changed to "
                            f"admin (actor suffix={_last_n(actor_id, 8)}) — "
                            f"verify scope expansion"
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
                        f"PostHog audit activity {activity!r} imported "
                        f"(no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "audit_default"},
                )
            )

        decision = self._decision(control_results)
        decision_reason = (
            f"Imported from PostHog audit: activity={activity} "
            f"scope={scope} actor_is_service_account={is_service_account}"
        )
        identity = (activity + "-" + (timestamp or uuid.uuid4().hex))[:48]

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"posthog-audit-{identity}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="posthog_import",
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
        synthetic_id = f"posthog-pii-concentration-{agent_id}"
        evidence: dict[str, Any] = {
            "agent_id_observed": agent_id,
            "sensitive_count": sensitive_count,
            "total_count": total_count,
            "ratio": ratio,
            "pii_concentration_threshold": self.pii_concentration_threshold,
            "synthetic": True,
            "source_tool": "posthog",
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
                f"PostHog synthetic finding: agent {agent_id} has "
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
            source_type="posthog_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from PostHog: synthetic pii_concentration "
                f"agent={agent_id} ratio={ratio:.3f}>"
                f"{self.pii_concentration_threshold:.3f}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_ai_error_rate_result(
        self,
        *,
        agent_id: str,
        error_count: int,
        total_count: int,
        ratio: float,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "ai_error_rate_high"
        control_id = _control_for(signal, self._mappings, "DE-01")
        synthetic_id = f"posthog-ai-error-rate-{agent_id}"
        evidence: dict[str, Any] = {
            "agent_id_observed": agent_id,
            "error_count": error_count,
            "total_count": total_count,
            "ratio": ratio,
            "ai_error_rate_threshold": self.ai_error_rate_threshold,
            "synthetic": True,
            "source_tool": "posthog",
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
                f"PostHog synthetic finding: agent {agent_id} has "
                f"{error_count}/{total_count} ({ratio:.1%}) AI generations "
                f"with $ai_is_error=true (> threshold "
                f"{self.ai_error_rate_threshold:.1%})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="posthog_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from PostHog: synthetic ai_error_rate "
                f"agent={agent_id} ratio={ratio:.3f}>"
                f"{self.ai_error_rate_threshold:.3f}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_recording_share_burst_result(
        self,
        *,
        actor_id: str,
        burst_count: int,
        window_seconds: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "recording_share_burst"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"posthog-recording-share-burst-{actor_id}"
        evidence: dict[str, Any] = {
            "actor_id_suffix": _last_n(actor_id, 8),
            "burst_count": burst_count,
            "window_seconds": window_seconds,
            "recording_share_burst_threshold": (
                self.recording_share_burst_threshold
            ),
            "synthetic": True,
            "source_tool": "posthog",
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
                f"PostHog synthetic finding: actor {_last_n(actor_id, 8)} "
                f"created {burst_count} session-recording share links in a "
                f"{window_seconds}s window (> threshold "
                f"{self.recording_share_burst_threshold}) — autonomous "
                f"recording exfil pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="posthog_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from PostHog: synthetic recording_share_burst "
                f"actor_suffix={_last_n(actor_id, 8)} burst={burst_count}>"
                f"{self.recording_share_burst_threshold} "
                f"window={window_seconds}s"
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
            detail="Empty PostHog export (no events or audit records)",
            evidence_data={
                "source_provenance": provenance,
                "event_count": 0,
                "audit_count": 0,
            },
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"posthog-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="posthog_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty PostHog export ingested",
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
