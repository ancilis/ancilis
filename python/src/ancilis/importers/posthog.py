"""PostHog analytics importer — converts PostHog event/audit exports to AKSI EvaluationResults.

PostHog (https://posthog.com) is the leading open-source product-analytics
platform, frequently self-hosted by privacy-conscious organizations. Its
``/api/projects/<id>/events`` endpoint streams raw user/agent events
(``$pageview``, ``$identify``, ``$set``, ``$autocapture``,
``$feature_flag_called``, ``$ai_generation``, ``$exception``, plus custom
events such as ``agent_action``) and a parallel ``/api/projects/<id>/activity_log``
exposes admin-side audit activity over scopes including ``FeatureFlag``,
``Cohort``, ``Insight``, ``Dashboard``, ``Plugin``, ``Action``, ``User``,
``Organization``, ``Team`` and ``PersonalApiKey``.

Wire shapes accepted (auto-detected):

  1. ``{"events": [...]}``      — primary events envelope
  2. ``{"audit_log": [...]}``   — admin audit envelope
  3. ``{"data": [...]}``        — mixed envelope; per-record dispatch by
                                   presence of ``event`` (event) vs
                                   ``activity`` (audit log)
  4. JSONL                       — one event or audit record per line

Signal mapping (see ``shared/mappings/posthog-aksi-controls.json``):

Events:
  * ``sensitive_patterns_matched`` contains ``ssn_like``                 → PR-04 FAIL → BLOCK
  * ``sensitive_patterns_matched`` contains ``credit_card_like``         → PR-04 FAIL → BLOCK
  * ``sensitive_patterns_matched`` contains ``email``                    → PR-04 FLAG
  * ``contains_sensitive_pattern=true`` (no specific kind)               → PR-04 FLAG
  * ``event=$identify`` / ``$set`` w/ non-anonymous distinct_id          → PR-04 FLAG (cross-session linking)
  * ``event=$exception`` w/ ``$exception_type`` set                      → DE-01 FLAG (production error)
  * ``event=$ai_generation`` (AI generation captured — posture data)     → PR-05 PASS
  * ``$ai_total_cost_usd > ai_cost_threshold_usd`` (default $1)          → PR-04 FLAG (high-cost generation)
  * ``event=$feature_flag_called`` w/ agent-* prefix flag                → PR-05 PASS captured
  * ``event_property_keys`` count > over_tracking_threshold (default 30) → PR-04 FLAG (over-tracking)
  * EU residency + ``tracking_consent_recorded=false``                   → PR-04 FAIL (GDPR consent)
  * ``is_sample_event=true``                                             → PR-05 PASS (sampled — audit trail)

Audit log:
  * ``activity=deleted`` scope in {Dashboard, Insight, Cohort}           → PR-02 FLAG (analytics asset deletion)
  * ``activity=deleted`` scope=FeatureFlag                               → PR-02 FLAG (feature-flag removal)
  * ``activity=exported``                                                → PR-04 FLAG (analytics export)
  * ``activity=created`` scope=Plugin + plugin_url_host not allowlisted  → PR-04 FAIL (untrusted plugin)
  * ``activity=created`` scope=PersonalApiKey & is_system_actor=false    → PR-01 FLAG (human key issuance)
  * ``activity=updated`` scope=Organization                              → PR-02 FLAG (org-level config)
  * ``activity=updated`` scope=Team                                      → PR-02 FLAG (team permissions)

Synthetic findings (per agent_id, across the export):
  * > N sensitive-pattern events within a 1h window                     → PR-04 FAIL
    (default N=100, configurable via mapping ``high_volume_threshold``)
  * > X% of agent's events contain sensitive patterns                   → PR-04 FAIL
    (default X=5%, configurable via mapping ``pii_concentration_threshold``;
    requires min sample of 5 events)

Sanitization — what we DO NOT store:
  * raw ``properties`` dict values (only the property-key list, count and
    boolean sensitive markers + the ``sensitive_patterns_matched`` taxonomy)
  * full ``distinct_id`` (last 8 chars only)
  * full ``$user_id`` (last 8 chars only)
  * full ``$session_id`` (last 8 chars only)
  * full ``$ip`` (masked to /16)
  * full ``actor_email`` (DOMAIN ONLY)
  * full ``plugin_url`` (host only)
  * raw ``$exception_message`` — only ``$exception_message_length``
  * ``$current_url_host`` is already host-only by upstream — stored verbatim

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


# Mapping table lives at <repo>/shared/mappings/posthog-aksi-controls.json.
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

_DEFAULT_HIGH_VOLUME_THRESHOLD = 100
_DEFAULT_HIGH_VOLUME_WINDOW_SECONDS = 3600
_DEFAULT_PII_CONCENTRATION_THRESHOLD = 0.05
_DEFAULT_OVER_TRACKING_THRESHOLD = 30
_DEFAULT_AI_COST_THRESHOLD_USD = 1.0
_DEFAULT_BLOCK_PATTERN_KINDS: frozenset[str] = frozenset(
    {"ssn_like", "credit_card_like", "ssn_like_pattern", "credit_card_like_pattern"}
)
_DEFAULT_FLAG_PATTERN_KINDS: frozenset[str] = frozenset({"email"})
_DEFAULT_IDENTITY_LINKING_EVENTS: frozenset[str] = frozenset(
    {"$identify", "$set", "$alias", "$create_alias"}
)
_DEFAULT_AI_GENERATION_EVENTS: frozenset[str] = frozenset({"$ai_generation"})
_DEFAULT_EXCEPTION_EVENTS: frozenset[str] = frozenset({"$exception"})
_DEFAULT_FEATURE_FLAG_EVENTS: frozenset[str] = frozenset({"$feature_flag_called"})
_DEFAULT_AGENT_FLAG_PREFIXES: tuple[str, ...] = ("agent-", "agent_", "ai-", "ai_")
_DEFAULT_ANON_PREFIXES: tuple[str, ...] = ("anon", "anonymous", "$anon", "guest-")
_DEFAULT_EU_REGIONS: frozenset[str] = frozenset(
    {"EU", "DE", "FR", "IE", "NL", "ES", "IT"}
)
_DEFAULT_ASSET_DELETION_SCOPES: frozenset[str] = frozenset(
    {"Dashboard", "Insight", "Cohort"}
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
    """Mask an IPv4 address to /16 (first two octets); return None if not parseable."""
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


def _parse_iso_to_epoch(value: Any) -> int:
    """Best-effort ISO8601 → epoch seconds; return 0 if not parseable."""
    if not isinstance(value, str) or not value:
        return 0
    s = value.strip()
    # Normalize trailing Z to +00:00 for fromisoformat.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return int(dt.timestamp())
    except (OverflowError, OSError, ValueError):
        return 0


class PostHogImporter:
    """Parse PostHog event/audit exports and convert to ``EvaluationResult`` records.

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
            event_property_keys count exceeds this value (default 30).
        ai_cost_threshold_usd: per-event flag triggers when
            ``$ai_total_cost_usd`` exceeds this value (default 1.0).
        plugin_url_allowlist: hosts (scheme://host) considered trusted plugin
            sources (default empty → all third-party plugins flagged FAIL).
        agent_feature_flag_prefixes: prefixes that classify a feature flag as
            agent-rollout-related (default ``agent-``, ``agent_``, ``ai-``, ``ai_``).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        high_volume_threshold: int | None = None,
        pii_concentration_threshold: float | None = None,
        over_tracking_threshold: int | None = None,
        ai_cost_threshold_usd: float | None = None,
        plugin_url_allowlist: Iterable[str] | None = None,
        agent_feature_flag_prefixes: Iterable[str] | None = None,
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

        if ai_cost_threshold_usd is not None:
            self.ai_cost_threshold_usd = float(ai_cost_threshold_usd)
        else:
            raw_cost = meta.get("ai_cost_threshold_usd")
            try:
                self.ai_cost_threshold_usd = (
                    float(raw_cost)
                    if isinstance(raw_cost, (int, float))
                    else _DEFAULT_AI_COST_THRESHOLD_USD
                )
            except (TypeError, ValueError):
                self.ai_cost_threshold_usd = _DEFAULT_AI_COST_THRESHOLD_USD

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

        ai_events = meta.get("ai_generation_events")
        if isinstance(ai_events, list) and ai_events:
            self.ai_generation_events = frozenset(str(e) for e in ai_events)
        else:
            self.ai_generation_events = _DEFAULT_AI_GENERATION_EVENTS

        exc_events = meta.get("exception_events")
        if isinstance(exc_events, list) and exc_events:
            self.exception_events = frozenset(str(e) for e in exc_events)
        else:
            self.exception_events = _DEFAULT_EXCEPTION_EVENTS

        ff_events = meta.get("feature_flag_events")
        if isinstance(ff_events, list) and ff_events:
            self.feature_flag_events = frozenset(str(e) for e in ff_events)
        else:
            self.feature_flag_events = _DEFAULT_FEATURE_FLAG_EVENTS

        if agent_feature_flag_prefixes is not None:
            self.agent_flag_prefixes = tuple(
                str(p) for p in agent_feature_flag_prefixes
            )
        else:
            meta_prefixes = meta.get("agent_feature_flag_prefixes")
            if isinstance(meta_prefixes, list) and meta_prefixes:
                self.agent_flag_prefixes = tuple(str(p) for p in meta_prefixes)
            else:
                self.agent_flag_prefixes = _DEFAULT_AGENT_FLAG_PREFIXES

        anon_prefixes = meta.get("anonymous_distinct_id_prefixes")
        if isinstance(anon_prefixes, list) and anon_prefixes:
            self.anon_prefixes = tuple(str(p) for p in anon_prefixes)
        else:
            self.anon_prefixes = _DEFAULT_ANON_PREFIXES

        eu_regions = meta.get("eu_data_residency_regions")
        if isinstance(eu_regions, list) and eu_regions:
            self.eu_regions = frozenset(str(r).upper() for r in eu_regions)
        else:
            self.eu_regions = _DEFAULT_EU_REGIONS

        asset_scopes = meta.get("audit_asset_deletion_scopes")
        if isinstance(asset_scopes, list) and asset_scopes:
            self.asset_deletion_scopes = frozenset(str(s) for s in asset_scopes)
        else:
            self.asset_deletion_scopes = _DEFAULT_ASSET_DELETION_SCOPES

        if plugin_url_allowlist is not None:
            self.plugin_url_allowlist = frozenset(
                str(h).rstrip("/") for h in plugin_url_allowlist
            )
        else:
            meta_allow = meta.get("plugin_url_allowlist")
            if isinstance(meta_allow, list):
                self.plugin_url_allowlist = frozenset(
                    str(h).rstrip("/") for h in meta_allow
                )
            else:
                self.plugin_url_allowlist = frozenset()

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
            elif "activity" in r:
                audit_logs.append(r)
            else:
                # Unknown shape — drop silently.
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

        # First pass: aggregate sensitive-event counts per agent for synthetic
        # findings, using both ISO timestamps and integer-epoch fallbacks.
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
                ts_epoch = _parse_iso_to_epoch(event.get("timestamp"))
                if ts_epoch <= 0:
                    raw_time = event.get("time")
                    if isinstance(raw_time, (int, float)) and raw_time > 0:
                        ts_epoch = int(raw_time)
                if ts_epoch > 0:
                    agent_sensitive_times.setdefault(agent_id, []).append(ts_epoch)

        results: list[EvaluationResult] = []
        for event in events:
            results.append(
                self._parse_event(event, file_sha256=file_sha256)
            )
        for entry in audit_logs:
            results.append(
                self._parse_audit_entry(entry, file_sha256=file_sha256)
            )

        # Synthetic: high-volume sensitive-pattern bursts (sliding window).
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

        # Synthetic: PII concentration per agent. Require min 5 events.
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

    def _is_anonymous_distinct_id(self, distinct_id: Any) -> bool:
        if not isinstance(distinct_id, str) or not distinct_id:
            return True
        lower = distinct_id.lower()
        return any(
            lower.startswith(prefix.lower()) for prefix in self.anon_prefixes
        )

    def _is_agent_feature_flag(self, flag: Any) -> bool:
        if not isinstance(flag, str) or not flag:
            return False
        lower = flag.lower()
        return any(lower.startswith(p.lower()) for p in self.agent_flag_prefixes)

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        event_name = _coerce_str(event.get("event")) or "unknown"
        ts_raw = event.get("timestamp")
        if isinstance(ts_raw, str) and ts_raw.strip():
            timestamp = ts_raw
        else:
            time_raw = event.get("time")
            if isinstance(time_raw, (int, float)) and time_raw > 0:
                try:
                    timestamp = datetime.fromtimestamp(
                        float(time_raw), tz=timezone.utc
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

        # Property-key list — DO NOT store the raw values map.
        if isinstance(props.get("event_property_keys"), list):
            property_keys = [str(k) for k in props.get("event_property_keys")]
        else:
            property_keys = sorted(str(k) for k in props)
        property_count = len(property_keys)

        sensitive_flag = _coerce_bool(props.get("contains_sensitive_pattern"))
        patterns_matched_raw = props.get("sensitive_patterns_matched") or []
        patterns_matched = (
            [str(p) for p in patterns_matched_raw]
            if isinstance(patterns_matched_raw, list)
            else []
        )
        agent_id_observed = props.get("agent_id")
        is_sample_event = _coerce_bool(props.get("is_sample_event"))
        consent = _coerce_bool(props.get("tracking_consent_recorded"))
        residency = _coerce_str(props.get("data_residency_region")).upper() or None
        lib = _coerce_str(props.get("$lib")) or None
        lib_version = _coerce_str(props.get("$lib_version")) or None
        current_url_host = _coerce_str(props.get("$current_url_host")) or None

        ai_provider = _coerce_str(props.get("ai_provider")) or None
        ai_model = _coerce_str(props.get("ai_model")) or None
        ai_input_tokens = _coerce_int(props.get("$ai_input_tokens"))
        ai_output_tokens = _coerce_int(props.get("$ai_output_tokens"))
        ai_total_cost_usd = _coerce_float(props.get("$ai_total_cost_usd"))

        exception_type = _coerce_str(props.get("$exception_type")) or None
        exception_message_length = _coerce_int(
            props.get("$exception_message_length")
        )

        feature_flag = _coerce_str(props.get("$feature_flag")) or None
        feature_flag_response: Any = props.get("$feature_flag_response")
        if isinstance(feature_flag_response, bool):
            feature_flag_response_repr: Any = feature_flag_response
        elif feature_flag_response is None:
            feature_flag_response_repr = None
        else:
            feature_flag_response_repr = _coerce_str(feature_flag_response) or None

        # Sanitized identifiers.
        common_evidence: dict[str, Any] = {
            "event": event_name,
            "event_id": event_id or None,
            "distinct_id_suffix": _last_n(distinct_id, 8),
            "user_id_suffix": _last_n(props.get("$user_id"), 8),
            "session_id_suffix": _last_n(props.get("$session_id"), 8),
            "ip_masked": _mask_ip(props.get("$ip")),
            "current_url_host": current_url_host,
            "lib": lib,
            "lib_version": lib_version,
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
            "ai_provider": ai_provider,
            "ai_model": ai_model,
            "ai_input_tokens": ai_input_tokens,
            "ai_output_tokens": ai_output_tokens,
            "ai_total_cost_usd": ai_total_cost_usd,
            "exception_type": exception_type,
            "exception_message_length": exception_message_length,
            "feature_flag": feature_flag,
            "feature_flag_response": feature_flag_response_repr,
            "is_sample_event": (
                bool(is_sample_event) if is_sample_event is not None else None
            ),
            "data_residency_region": residency,
            "tracking_consent_recorded": (
                bool(consent) if consent is not None else None
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

        # 1. Sensitive-pattern matches drive PR-04 BLOCK / FLAG.
        ssn_hit = any(
            (p in self.block_pattern_kinds and "ssn" in p) for p in patterns_matched
        )
        cc_hit = any(
            (p in self.block_pattern_kinds and "credit_card" in p)
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
                        f"PostHog event {event_name!r} (id={event_id or '?'}) "
                        f"contains SSN-like pattern in properties — analytics PII leak"
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
                        f"PostHog event {event_name!r} (id={event_id or '?'}) "
                        f"contains credit-card-like pattern in properties — PCI surface"
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

        # 2. Identity linking ($identify / $set) with non-anonymous distinct_id.
        if (
            event_name in self.identity_linking_events
            and not self._is_anonymous_distinct_id(distinct_id)
        ):
            signal = "identity_linking"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog {event_name} performs cross-session "
                        f"identity linking (distinct_id suffix="
                        f"{_last_n(distinct_id, 8)}) — privacy-relevant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. Exception event with concrete exception_type → DE-01 FLAG.
        if event_name in self.exception_events and exception_type:
            signal = "exception_event"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog $exception captured exception_type="
                        f"{exception_type!r} (msg_len={exception_message_length}) "
                        f"— production error baseline signal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. AI generation captured (PR-05 PASS) and cost threshold (PR-04 FLAG).
        if event_name in self.ai_generation_events:
            signal = "ai_generation"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"PostHog $ai_generation captured "
                        f"(provider={ai_provider!r} model={ai_model!r} "
                        f"input_tokens={ai_input_tokens} output_tokens="
                        f"{ai_output_tokens} cost_usd={ai_total_cost_usd}) — "
                        f"AI generation posture data"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        if ai_total_cost_usd > self.ai_cost_threshold_usd:
            signal = "ai_cost_high"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog event {event_name!r} reports AI cost "
                        f"${ai_total_cost_usd:.4f} > threshold "
                        f"${self.ai_cost_threshold_usd:.4f} on a single event "
                        f"— large single-call AI spend"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "ai_cost_threshold_usd": self.ai_cost_threshold_usd,
                    },
                )
            )

        # 5. Feature-flag agent rollout — PR-05 PASS captured.
        if (
            event_name in self.feature_flag_events
            and self._is_agent_feature_flag(feature_flag)
        ):
            signal = "feature_flag_agent"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"PostHog $feature_flag_called {feature_flag!r}="
                        f"{feature_flag_response_repr!r} — agent-rollout flag captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Over-tracking — too many properties on one event.
        if property_count > self.over_tracking_threshold:
            signal = "over_tracking"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog event {event_name!r} carries "
                        f"{property_count} properties (> threshold "
                        f"{self.over_tracking_threshold}) — fishing for properties"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "over_tracking_threshold": self.over_tracking_threshold,
                    },
                )
            )

        # 7. EU residency + missing consent → PR-04 FAIL.
        if (
            consent is False
            and residency is not None
            and residency in self.eu_regions
        ):
            signal = "eu_no_consent"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"PostHog event {event_name!r} from EU residency "
                        f"{residency} has tracking_consent_recorded=false "
                        f"— GDPR consent missing"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 8. Sampled event → PR-05 PASS audit-trail evidence.
        if is_sample_event is True:
            signal = "is_sample_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"PostHog event {event_name!r} is_sample_event=true "
                        f"— sampled event recorded for audit trail"
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
            f"id={event_id or 'null'} "
            f"contains_sensitive_pattern={sensitive_flag} "
            f"patterns={patterns_matched or 'none'}"
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
            total_duration_ms=0.0,
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
        scope = _coerce_str(entry.get("scope")) or "unknown"
        timestamp_raw = entry.get("created_at") or entry.get("timestamp")
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

        actor_id = entry.get("actor_id")
        actor_email = entry.get("actor_email")
        actor_email_domain = None
        if isinstance(actor_email, str) and "@" in actor_email:
            actor_email_domain = actor_email.split("@", 1)[1]
        is_system_actor = _coerce_bool(entry.get("is_system_actor"))

        detail = (
            entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        )
        plugin_name = _coerce_str(detail.get("plugin_name")) or None
        plugin_url_host = _host_only(
            detail.get("plugin_url_host") or detail.get("plugin_url")
        )
        name_length = _coerce_int(detail.get("name_length"))
        changes_raw = detail.get("changes")
        change_fields: list[str] = []
        if isinstance(changes_raw, list):
            for ch in changes_raw:
                if isinstance(ch, dict):
                    field = ch.get("field")
                    if isinstance(field, str) and field:
                        change_fields.append(field)

        common_evidence: dict[str, Any] = {
            "audit_activity": activity,
            "audit_scope": scope,
            "actor_id_suffix": _last_n(actor_id, 8),
            "actor_email_domain": actor_email_domain,
            "is_system_actor": (
                bool(is_system_actor) if is_system_actor is not None else None
            ),
            "plugin_name": plugin_name,
            "plugin_url_host": plugin_url_host,
            "name_length": name_length,
            "change_fields": sorted(set(change_fields)) or None,
            "source_tool": "posthog",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=f"audit-{activity}-{scope}-{timestamp}",
            ),
        }

        control_results: list[ControlResult] = []

        if activity == "deleted" and scope in self.asset_deletion_scopes:
            signal = "audit_asset_deleted"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: {scope} deleted by actor "
                        f"(suffix={common_evidence['actor_id_suffix']}) "
                        f"— analytics asset removal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "deleted" and scope == "FeatureFlag":
            signal = "audit_feature_flag_deleted"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: FeatureFlag deleted by actor "
                        f"(suffix={common_evidence['actor_id_suffix']}) "
                        f"— code-impact removal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "exported":
            signal = "audit_data_export"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: {scope} exported by actor "
                        f"(suffix={common_evidence['actor_id_suffix']}) "
                        f"— analytics exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "created" and scope == "Plugin":
            in_allow = (
                bool(plugin_url_host)
                and plugin_url_host.rstrip("/") in self.plugin_url_allowlist
            )
            if not in_allow:
                signal = "audit_plugin_untrusted"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"PostHog audit: Plugin installed from "
                            f"{plugin_url_host or 'unknown'} (not in allowlist) "
                            f"— untrusted plugin source"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif activity == "created" and scope == "PersonalApiKey":
            if is_system_actor is False:
                signal = "audit_personal_api_key_created"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"PostHog audit: PersonalApiKey created by human actor "
                            f"(suffix={common_evidence['actor_id_suffix']}) "
                            f"— prefer system-actor-issued keys"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif activity == "updated" and scope == "Organization":
            signal = "audit_org_config_changed"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: Organization configuration updated "
                        f"(fields={change_fields or 'unspecified'}) "
                        f"— org-level scope change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif activity == "updated" and scope == "Team":
            signal = "audit_team_permissions_changed"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"PostHog audit: Team configuration updated "
                        f"(fields={change_fields or 'unspecified'}) "
                        f"— team-permission scope change"
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
                        f"PostHog audit activity {activity!r} scope={scope!r} "
                        f"imported (no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "audit_default"},
                )
            )

        decision = self._decision(control_results)
        decision_reason = (
            f"Imported from PostHog audit: activity={activity} scope={scope} "
            f"is_system_actor={is_system_actor}"
        )
        identity = (activity + "-" + scope + "-" + (timestamp or uuid.uuid4().hex))[
            :48
        ]

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
        synthetic_id = f"posthog-high-volume-{agent_id}"
        evidence: dict[str, Any] = {
            "agent_id_observed": agent_id,
            "burst_count": burst_count,
            "window_seconds": window_seconds,
            "high_volume_threshold": self.high_volume_threshold,
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
                f"PostHog synthetic finding: agent {agent_id} emitted "
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
            source_type="posthog_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from PostHog: synthetic high-volume sensitive "
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
