# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Zapier audit-log importer — maps low-code AI workflow events to AKSI controls.

Zapier (https://zapier.com) is the dominant low-code automation platform with
7000+ app integrations, used heavily for AI workflows via Zapier AI Actions,
Natural-Language Actions, and ChatGPT plugins. Distinct from n8n (self-hosted,
workflow-execution shape) — Zapier zaps execute in Zapier's SaaS, so the
audit-log shape is different: actor identity, app-connection lifecycle,
AI Action creation/invocation, public share-link events, and team role
changes are the load-bearing signals.

Audit log access is via the Team / Company plan audit log API plus SCIM
events. This importer ingests the payload in four shapes:

  1. ``{"audit_logs": [...]}`` — primary audit-log envelope
  2. ``{"events": [...]}``     — generic events envelope
  3. ``{"data": [...]}``       — generic data envelope
  4. JSONL                       — one event per line

Signal mapping (see shared/mappings/zapier-aksi-controls.json):

  * ``zap.run`` & ``task_status=success``                   → PR-05 PASS  (audit trail)
  * ``zap.failed``                                          → DE-01 FAIL  (zap failure)
  * ``zap.run`` & ``contains_code_step=true``               → PR-03 FLAG  (Code by Zapier — arbitrary JS/Python)
  * ``zap.run`` & ``contains_webhook_step=true`` &
    ``webhook_target_host`` not in allowlist                → PR-04 FLAG  (external webhook destination)
  * ``zap.run`` with sensitive ``action_apps`` AND
    ``data_processed_bytes > 10MB``                         → PR-04 FLAG  (large data transit)
  * ``zap.created`` by non-admin actor + sensitive
    ``action_apps``                                         → PR-04 FLAG  (member shipping sensitive zap)
  * ``zap.deleted`` of production zap                       → PR-02 FLAG  (audit completeness)
  * ``zap.turned_off`` on critical zap                      → PR-02 FLAG  (silent disablement)
  * ``team_member.invited``                                 → PR-02 FLAG  (collaborator addition)
  * ``team_member.removed``                                 → PR-05 PASS  (audit)
  * ``team_role.changed`` to Admin/Owner from lower role    → PR-02 FAIL  (privilege escalation)
  * ``app_connection.created``                              → PR-01 FLAG  (new credential surface)
  * ``connection.shared``                                   → PR-01 FLAG  (credential sharing)
  * ``manual_zap.share_link_created``                       → PR-04 FLAG  (public share-link exfil)
  * ``ai_action.created``                                   → PR-01 FLAG  (new agent-callable surface)
  * ``ai_action.executed``                                  → captured (AI action invocation evidence)
  * ``chatgpt_action.invoked``                              → captured (ChatGPT-via-Zapier flow)
  * ``export.ran``                                          → PR-04 FLAG  (data export from Zapier)
  * ``actor.role=Member`` triggering ``zap.deleted`` on
    production zap                                          → PR-02 FLAG  (over-privileged member)
  * ``is_authenticated_partner=true``                       → PR-01 PASS  (OAuth-app-driven action audit)
  * ``trigger_app=webhook``                                 → PR-01 PASS  (webhook trigger evidence)

Synthetic findings (cross-event aggregation):

  * Same actor running > N ``zap.run`` events in 1h
    (default 1000)                                          → PR-05 FLAG  (high-volume zaps)
  * Same Zap calling > N distinct external apps in a single
    run (default 5)                                         → PR-04 FLAG  (cross-app surface)
  * Same actor creating > N ``ai_action.created`` events
    in 1h (default 5)                                       → PR-01 FLAG  (AI Action burst)

Sanitization (non-negotiable):

  * ``zap_name`` is NEVER stored — only ``zap_name_length``.
  * ``actor.email`` is reduced to its DOMAIN ONLY.
  * ``actor.user_id`` keeps only the LAST 8 characters.
  * ``zap_id`` and ``zap_owner_id`` keep only the LAST 8 characters.
  * ``team_id`` keeps only the LAST 8 characters.
  * ``chatgpt_action_id`` keeps only the LAST 8 characters.
  * ``webhook_target_host`` is reduced to host ONLY (via urlsplit).
  * ``ip_address`` is masked to /16 (first two IPv4 octets).

The original file is hashed (sha256) for source_provenance.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/zapier-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/zapier.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "zapier-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_SENSITIVE_APPS: tuple[str, ...] = (
    "postgresql",
    "mongodb",
    "sftp",
    "dropbox",
    "google-drive",
    "salesforce",
    "hubspot",
    "stripe",
    "quickbooks",
    "xero",
    "zoho",
    "mailchimp",
)
_DEFAULT_LARGE_DATA_THRESHOLD = 10_000_000
_DEFAULT_HIGH_VOLUME_THRESHOLD = 1000
_DEFAULT_HIGH_VOLUME_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_APP_THRESHOLD = 5
_DEFAULT_AI_ACTION_BURST = 5
_DEFAULT_AI_ACTION_BURST_WINDOW_SECONDS = 3600
_DEFAULT_PRIVILEGED_ROLES: frozenset[str] = frozenset({"admin", "owner"})
_DEFAULT_CRITICAL_TAGS: frozenset[str] = frozenset({"production", "prod", "critical"})
_DEFAULT_CRITICAL_MIN_RUNS_PER_DAY = 100


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the zapier-aksi-controls.json mapping; tolerate missing file."""
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


def _last8(value: Any) -> str | None:
    """Return last 8 chars of an identifier; None if absent."""
    if value is None:
        return None
    s = str(value)
    if not s:
        return None
    return s[-8:]


def _email_domain(email: Any) -> str | None:
    """Reduce an email to its domain part; None if not parseable."""
    if not isinstance(email, str) or "@" not in email:
        return None
    domain = email.split("@", 1)[1].strip().lower()
    return domain or None


def _host_of(value: Any) -> str:
    """Extract a hostname from a URL or bare host string."""
    if not isinstance(value, str) or not value.strip():
        return ""
    candidate = value.strip()
    if "://" not in candidate:
        candidate = "//" + candidate
    parsed = urlsplit(candidate)
    return (parsed.hostname or "").lower()


def _mask_ip(ip: Any) -> str | None:
    """Mask an IPv4 address to /16 (first two octets). Pass IPv6 through."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    raw = ip.strip()
    parts = raw.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.0.0/16"
    # IPv6 or unrecognized — preserve only the first hextet group as a coarse mask.
    if ":" in raw:
        first = raw.split(":", 1)[0]
        return f"{first}::/32"
    return None


def _host_allowlisted(host: str, allowlist: Iterable[str]) -> bool:
    """Return True if ``host`` matches an allowlist entry (suffix-aware)."""
    if not host:
        return True  # No host claim → not classifiable as external.
    host_l = host.lower()
    for entry in allowlist:
        e = (entry or "").strip().lower().lstrip("*.")
        if not e:
            continue
        if host_l == e or host_l.endswith("." + e):
            return True
    return False


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Best-effort ISO-8601 parse into an aware UTC datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    # Tolerate trailing 'Z'.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ZapierImporter:
    """Parse a Zapier audit-log export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        sensitive_apps: Iterable[str] | None = None,
        large_data_threshold: int | None = None,
        high_volume_threshold: int | None = None,
        cross_app_threshold: int | None = None,
        ai_action_burst: int | None = None,
        webhook_allowlist: Iterable[str] | None = None,
        privileged_roles: Iterable[str] | None = None,
        critical_zap_tags: Iterable[str] | None = None,
        critical_min_runs_per_day: int | None = None,
        high_volume_window_seconds: int | None = None,
        ai_action_burst_window_seconds: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        self.sensitive_apps = self._resolve_str_set(
            sensitive_apps, meta.get("sensitive_apps"), _DEFAULT_SENSITIVE_APPS
        )
        self.large_data_threshold = self._resolve_int(
            large_data_threshold,
            meta.get("large_data_threshold"),
            _DEFAULT_LARGE_DATA_THRESHOLD,
        )
        self.high_volume_threshold = self._resolve_int(
            high_volume_threshold,
            meta.get("high_volume_threshold"),
            _DEFAULT_HIGH_VOLUME_THRESHOLD,
        )
        self.cross_app_threshold = self._resolve_int(
            cross_app_threshold,
            meta.get("cross_app_threshold"),
            _DEFAULT_CROSS_APP_THRESHOLD,
        )
        self.ai_action_burst = self._resolve_int(
            ai_action_burst,
            meta.get("ai_action_burst"),
            _DEFAULT_AI_ACTION_BURST,
        )
        self.high_volume_window_seconds = self._resolve_int(
            high_volume_window_seconds,
            meta.get("high_volume_window_seconds"),
            _DEFAULT_HIGH_VOLUME_WINDOW_SECONDS,
        )
        self.ai_action_burst_window_seconds = self._resolve_int(
            ai_action_burst_window_seconds,
            meta.get("ai_action_burst_window_seconds"),
            _DEFAULT_AI_ACTION_BURST_WINDOW_SECONDS,
        )
        if webhook_allowlist is not None:
            self.webhook_allowlist = tuple(str(p) for p in webhook_allowlist)
        else:
            meta_allow = meta.get("webhook_allowlist")
            if isinstance(meta_allow, list):
                self.webhook_allowlist = tuple(str(p) for p in meta_allow)
            else:
                self.webhook_allowlist = ()
        if privileged_roles is not None:
            self.privileged_roles = frozenset(
                str(r).strip().lower() for r in privileged_roles if str(r).strip()
            )
        else:
            meta_priv = meta.get("privileged_roles")
            if isinstance(meta_priv, list) and meta_priv:
                self.privileged_roles = frozenset(
                    str(r).strip().lower() for r in meta_priv if str(r).strip()
                )
            else:
                self.privileged_roles = _DEFAULT_PRIVILEGED_ROLES

        # Critical zap heuristic configuration.
        crit_meta = meta.get("critical_zap_indicators") or {}
        if not isinstance(crit_meta, dict):
            crit_meta = {}
        if critical_zap_tags is not None:
            self.critical_zap_tags = frozenset(
                str(t).strip().lower() for t in critical_zap_tags if str(t).strip()
            )
        else:
            tag_meta = crit_meta.get("tags")
            if isinstance(tag_meta, list) and tag_meta:
                self.critical_zap_tags = frozenset(
                    str(t).strip().lower() for t in tag_meta if str(t).strip()
                )
            else:
                self.critical_zap_tags = _DEFAULT_CRITICAL_TAGS
        self.critical_min_runs_per_day = self._resolve_int(
            critical_min_runs_per_day,
            crit_meta.get("min_runs_per_day"),
            _DEFAULT_CRITICAL_MIN_RUNS_PER_DAY,
        )

    @staticmethod
    def _resolve_int(explicit: int | None, meta_value: Any, default: int) -> int:
        if explicit is not None:
            return int(explicit)
        if isinstance(meta_value, (int, float)) and not isinstance(meta_value, bool):
            return int(meta_value)
        return default

    @staticmethod
    def _resolve_str_set(
        explicit: Iterable[str] | None,
        meta_value: Any,
        default: tuple[str, ...],
    ) -> frozenset[str]:
        if explicit is not None:
            return frozenset(str(s).strip().lower() for s in explicit if str(s).strip())
        if isinstance(meta_value, list) and meta_value:
            return frozenset(
                str(s).strip().lower() for s in meta_value if str(s).strip()
            )
        return frozenset(default)

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Zapier audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Zapier audit-log content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"audit_logs":[]}`` / ``{"events":[]}`` / ``{"data":[]}`` / JSONL."""
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
                for key in ("audit_logs", "events", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [e for e in doc[key] if isinstance(e, dict)]
                # Single event object.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "zapier",
            "source_tool_name": "zapier",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # -- Sanitization -------------------------------------------------------

    def _sanitize_actor(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {
                "user_id_last8": None,
                "email_domain": None,
                "is_admin": False,
                "role": None,
            }
        role = raw.get("role")
        return {
            "user_id_last8": _last8(raw.get("user_id")),
            "email_domain": _email_domain(raw.get("email")),
            "is_admin": bool(raw.get("is_admin", False)),
            "role": str(role).strip() if isinstance(role, str) and role.strip() else None,
        }

    def _is_zap_critical(self, entry: dict[str, Any]) -> bool:
        """Heuristic: zap is 'critical/production' if tagged or above runs-per-day floor."""
        tags_raw = entry.get("zap_tags") or entry.get("tags") or []
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if isinstance(t, str) and t.strip().lower() in self.critical_zap_tags:
                    return True
        runs_per_day = entry.get("zap_runs_per_day")
        try:
            if runs_per_day is not None and int(runs_per_day) > self.critical_min_runs_per_day:
                return True
        except (TypeError, ValueError):
            pass
        return bool(entry.get("is_production")) or bool(entry.get("production"))

    # -- Build results ------------------------------------------------------

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — collect actor activity for synthetic findings.
        # Each entry: list of (timestamp_dt, action_apps_set) for zap.run;
        # separate list of (timestamp_dt,) for ai_action.created.
        actor_runs: dict[str, list[datetime]] = {}
        actor_ai_creates: dict[str, list[datetime]] = {}

        for ev in events:
            action = str(ev.get("action") or "").strip().lower()
            actor = ev.get("actor") if isinstance(ev.get("actor"), dict) else {}
            actor_key = _last8(actor.get("user_id")) if isinstance(actor, dict) else None
            ts = _parse_iso_timestamp(ev.get("timestamp"))
            if ts is None:
                continue
            if action == "zap.run" and actor_key:
                actor_runs.setdefault(actor_key, []).append(ts)
            elif action == "ai_action.created" and actor_key:
                actor_ai_creates.setdefault(actor_key, []).append(ts)

        # Compute synthetic burst flags by 1-hour window per actor.
        high_volume_actors = self._actors_exceeding(
            actor_runs,
            window_seconds=self.high_volume_window_seconds,
            threshold=self.high_volume_threshold,
        )
        ai_burst_actors = self._actors_exceeding(
            actor_ai_creates,
            window_seconds=self.ai_action_burst_window_seconds,
            threshold=self.ai_action_burst,
        )

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                high_volume_actors=high_volume_actors,
                ai_burst_actors=ai_burst_actors,
            )
            for ev in events
        ]
        # Drop None entries (skipped events).
        results = [r for r in results if r is not None]

        # Synthetic findings — one per qualifying actor.
        for actor_key, peak in sorted(high_volume_actors.items()):
            results.append(
                self._synthetic_high_volume_result(
                    actor_key=actor_key,
                    peak_count=peak,
                    file_sha256=file_sha256,
                )
            )
        for actor_key, peak in sorted(ai_burst_actors.items()):
            results.append(
                self._synthetic_ai_burst_result(
                    actor_key=actor_key,
                    peak_count=peak,
                    file_sha256=file_sha256,
                )
            )
        return results

    @staticmethod
    def _actors_exceeding(
        actor_events: dict[str, list[datetime]],
        *,
        window_seconds: int,
        threshold: int,
    ) -> dict[str, int]:
        """Return actors whose peak events-in-rolling-window exceeds threshold.

        Map: actor_key → peak count observed in any rolling window.
        """
        out: dict[str, int] = {}
        for actor_key, stamps in actor_events.items():
            if not stamps:
                continue
            sorted_stamps = sorted(stamps)
            peak = 0
            left = 0
            for right in range(len(sorted_stamps)):
                while (
                    sorted_stamps[right] - sorted_stamps[left]
                ).total_seconds() > window_seconds:
                    left += 1
                window_count = right - left + 1
                if window_count > peak:
                    peak = window_count
            if peak > threshold:
                out[actor_key] = peak
        return out

    def _parse_event(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        high_volume_actors: dict[str, int],
        ai_burst_actors: dict[str, int],
    ) -> EvaluationResult | None:
        event_id = str(entry.get("id") or uuid.uuid4())
        action = str(entry.get("action") or "").strip().lower()
        timestamp = (
            entry.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        actor_safe = self._sanitize_actor(entry.get("actor"))
        actor_role = (actor_safe.get("role") or "").strip().lower()
        is_privileged_actor = (
            actor_safe.get("is_admin") is True
            or actor_role in self.privileged_roles
        )

        # Zap-level fields (sanitized).
        zap_id_last8 = _last8(entry.get("zap_id"))
        zap_owner_id_last8 = _last8(entry.get("zap_owner_id"))
        try:
            zap_name_length = int(entry.get("zap_name_length") or 0)
        except (TypeError, ValueError):
            zap_name_length = 0
        trigger_app_raw = entry.get("trigger_app")
        trigger_app = (
            str(trigger_app_raw).strip().lower()
            if isinstance(trigger_app_raw, str) and trigger_app_raw.strip()
            else None
        )
        action_apps_raw = entry.get("action_apps") or []
        action_apps = (
            [str(a).strip().lower() for a in action_apps_raw if str(a).strip()]
            if isinstance(action_apps_raw, list)
            else []
        )
        try:
            action_count = int(entry.get("action_count") or 0)
        except (TypeError, ValueError):
            action_count = 0
        try:
            steps_count = int(entry.get("steps_count") or 0)
        except (TypeError, ValueError):
            steps_count = 0
        contains_code_step = bool(entry.get("contains_code_step", False))
        contains_webhook_step = bool(entry.get("contains_webhook_step", False))
        requires_premium_app = bool(entry.get("requires_premium_app", False))
        team_id_last8 = _last8(entry.get("team_id"))
        try:
            team_size = int(entry.get("team_size") or 0)
        except (TypeError, ValueError):
            team_size = 0
        is_shared_team = bool(entry.get("is_shared_team", False))
        try:
            task_count_in_run = int(entry.get("task_count_in_run") or 0)
        except (TypeError, ValueError):
            task_count_in_run = 0
        task_status_raw = entry.get("task_status")
        task_status = (
            str(task_status_raw).strip().lower()
            if isinstance(task_status_raw, str) and task_status_raw.strip()
            else None
        )
        try:
            execution_duration_ms = float(entry.get("execution_duration_ms") or 0.0)
        except (TypeError, ValueError):
            execution_duration_ms = 0.0
        try:
            data_processed_bytes = int(entry.get("data_processed_bytes") or 0)
        except (TypeError, ValueError):
            data_processed_bytes = 0
        webhook_target_host = _host_of(entry.get("webhook_target_host"))
        chatgpt_action_id_last8 = _last8(entry.get("chatgpt_action_id"))
        is_authenticated_partner = bool(entry.get("is_authenticated_partner", False))
        ip_masked = _mask_ip(entry.get("ip_address"))

        sensitive_action_apps = sorted(
            a for a in action_apps if a in self.sensitive_apps
        )
        distinct_action_apps = sorted(set(action_apps))

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            event_id=event_id,
        )

        common_evidence: dict[str, Any] = {
            "zapier_event_id": event_id,
            "action": action,
            "actor": actor_safe,
            "zap_id_last8": zap_id_last8,
            "zap_owner_id_last8": zap_owner_id_last8,
            "zap_name_length": zap_name_length,
            "trigger_app": trigger_app,
            "action_apps": action_apps,
            "action_count": action_count,
            "steps_count": steps_count,
            "contains_code_step": contains_code_step,
            "contains_webhook_step": contains_webhook_step,
            "requires_premium_app": requires_premium_app,
            "team_id_last8": team_id_last8,
            "team_size": team_size,
            "is_shared_team": is_shared_team,
            "task_count_in_run": task_count_in_run,
            "task_status": task_status,
            "execution_duration_ms": execution_duration_ms,
            "data_processed_bytes": data_processed_bytes,
            "webhook_target_host": webhook_target_host or None,
            "chatgpt_action_id_last8": chatgpt_action_id_last8,
            "is_authenticated_partner": is_authenticated_partner,
            "ip_masked": ip_masked,
            "sensitive_action_apps": sensitive_action_apps,
            "timestamp": str(timestamp),
            "source_provenance": source_provenance,
            "source_tool": "zapier",
        }

        control_results: list[ControlResult] = []

        # 1. Action-specific signals.
        if action == "zap.failed":
            self._emit_zap_failed(
                control_results, common_evidence, event_id, zap_id_last8
            )
        elif action == "zap.run":
            self._emit_zap_run(
                control_results,
                common_evidence,
                event_id=event_id,
                zap_id_last8=zap_id_last8,
                task_status=task_status,
                contains_code_step=contains_code_step,
                contains_webhook_step=contains_webhook_step,
                webhook_target_host=webhook_target_host,
                sensitive_action_apps=sensitive_action_apps,
                data_processed_bytes=data_processed_bytes,
                distinct_action_apps=distinct_action_apps,
            )
        elif action == "zap.created":
            if sensitive_action_apps and not is_privileged_actor:
                self._emit_signal(
                    control_results,
                    signal="member_creates_sensitive_zap",
                    default_control="PR-04",
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: non-admin actor "
                        f"role={actor_role or 'member'!r} created zap with "
                        f"sensitive apps={sensitive_action_apps} — review "
                        f"data-handling scope"
                    ),
                    common=common_evidence,
                    extra={"sensitive_apps_in_zap": sensitive_action_apps},
                )
        elif action == "zap.deleted":
            if self._is_zap_critical(entry):
                self._emit_signal(
                    control_results,
                    signal="member_deletes_production_zap",
                    default_control="PR-02",
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: zap {zap_id_last8!r} marked "
                        f"production was deleted (audit-completeness signal) "
                        f"by actor role={actor_role or 'unknown'!r}"
                    ),
                    common=common_evidence,
                    extra={"is_member_actor": not is_privileged_actor},
                )
        elif action == "zap.turned_off":
            if self._is_zap_critical(entry):
                self._emit_signal(
                    control_results,
                    signal="production_zap_turned_off",
                    default_control="PR-02",
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: critical zap "
                        f"{zap_id_last8!r} was turned off by actor role="
                        f"{actor_role or 'unknown'!r} — silent disablement"
                    ),
                    common=common_evidence,
                )
        elif action == "team_member.invited":
            self._emit_signal(
                control_results,
                signal="team_member_invited",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: team member invited "
                    f"(team_id_last8={team_id_last8!r}) — collaborator "
                    f"addition for audit"
                ),
                common=common_evidence,
            )
        elif action == "team_member.removed":
            self._emit_signal(
                control_results,
                signal="team_member_removed",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: team member removed "
                    f"(team_id_last8={team_id_last8!r}) — audit recorded"
                ),
                common=common_evidence,
            )
        elif action == "team_role.changed":
            self._emit_role_changed(
                control_results, entry, common_evidence, event_id
            )
        elif action == "app_connection.created":
            self._emit_signal(
                control_results,
                signal="app_connection_created",
                default_control="PR-01",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: app connection created "
                    f"(new credential surface) — review OAuth scope and "
                    f"actor role={actor_role or 'unknown'!r}"
                ),
                common=common_evidence,
            )
        elif action == "app_connection.deleted":
            # Captured as a PASS audit event — no signal escalation.
            self._emit_signal(
                control_results,
                signal="app_connection_deleted",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: app connection deleted — "
                    f"audit recorded"
                ),
                common=common_evidence,
            )
        elif action == "connection.shared":
            self._emit_signal(
                control_results,
                signal="connection_shared",
                default_control="PR-01",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: app connection shared "
                    f"across team — credential sharing should be audited"
                ),
                common=common_evidence,
            )
        elif action == "manual_zap.share_link_created":
            self._emit_signal(
                control_results,
                signal="public_share_link",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap share-link created "
                    f"(zap_id_last8={zap_id_last8!r}) — public share-link "
                    f"is an exfiltration surface"
                ),
                common=common_evidence,
            )
        elif action == "ai_action.created":
            self._emit_signal(
                control_results,
                signal="ai_action_created",
                default_control="PR-01",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: AI Action created — new "
                    f"agent-callable surface; verify scope and approval"
                ),
                common=common_evidence,
            )
        elif action == "ai_action.executed":
            self._emit_signal(
                control_results,
                signal="ai_action_executed",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: AI Action executed "
                    f"(invocation evidence captured)"
                ),
                common=common_evidence,
            )
        elif action == "chatgpt_action.invoked":
            self._emit_signal(
                control_results,
                signal="chatgpt_action_invoked",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: ChatGPT-via-Zapier action "
                    f"invoked (chatgpt_action_id_last8="
                    f"{chatgpt_action_id_last8!r})"
                ),
                common=common_evidence,
            )
        elif action == "export.ran":
            self._emit_signal(
                control_results,
                signal="export_ran",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: export ran (data leaving "
                    f"Zapier) — review destination and scope"
                ),
                common=common_evidence,
            )
        elif action == "webhook.received":
            self._emit_signal(
                control_results,
                signal="webhook_received",
                default_control="PR-01",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: webhook received "
                    f"(host={webhook_target_host or 'unknown'!r})"
                ),
                common=common_evidence,
            )
        elif action == "task.executed":
            self._emit_signal(
                control_results,
                signal="task_executed",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: task executed "
                    f"(audit recorded)"
                ),
                common=common_evidence,
            )
        else:
            # Unknown action — surface as PR-02 FLAG so it doesn't silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: unrecognized "
                        f"action={entry.get('action')!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "action_unknown"},
                )
            )

        # 2. Cross-cutting captures (additive, lower severity).
        if is_authenticated_partner and action == "zap.run":
            self._emit_signal(
                control_results,
                signal="authenticated_partner_action",
                default_control="PR-01",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: action driven by "
                    f"authenticated partner OAuth app"
                ),
                common=common_evidence,
            )
        if trigger_app == "webhook" and action == "zap.run":
            self._emit_signal(
                control_results,
                signal="webhook_trigger",
                default_control="PR-01",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: zap triggered by webhook "
                    f"(host={webhook_target_host or 'unknown'!r})"
                ),
                common=common_evidence,
            )

        # 3. Synthetic-pattern context — flag contributing events.
        actor_key = actor_safe.get("user_id_last8")
        if isinstance(actor_key, str):
            if actor_key in high_volume_actors and action == "zap.run":
                self._emit_signal(
                    control_results,
                    signal="high_volume_runs",
                    default_control="PR-05",
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: actor "
                        f"user_id_last8={actor_key!r} is part of high-volume "
                        f"zap.run pattern (peak={high_volume_actors[actor_key]} "
                        f"in {self.high_volume_window_seconds}s window > "
                        f"threshold {self.high_volume_threshold})"
                    ),
                    common=common_evidence,
                    extra={
                        "high_volume_peak": high_volume_actors[actor_key],
                        "high_volume_threshold": self.high_volume_threshold,
                        "high_volume_window_seconds": self.high_volume_window_seconds,
                    },
                )
            if actor_key in ai_burst_actors and action == "ai_action.created":
                self._emit_signal(
                    control_results,
                    signal="ai_action_burst",
                    default_control="PR-01",
                    result="FLAG",
                    detail=(
                        f"Zapier event {event_id}: actor "
                        f"user_id_last8={actor_key!r} is part of AI Action "
                        f"burst pattern (peak={ai_burst_actors[actor_key]} "
                        f"in {self.ai_action_burst_window_seconds}s window > "
                        f"threshold {self.ai_action_burst})"
                    ),
                    common=common_evidence,
                    extra={
                        "ai_action_burst_peak": ai_burst_actors[actor_key],
                        "ai_action_burst_threshold": self.ai_action_burst,
                        "ai_action_burst_window_seconds": self.ai_action_burst_window_seconds,
                    },
                )

        # Decision aggregation.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Zapier: action={action or 'unknown'} "
            f"task_status={task_status or 'n/a'} "
            f"actor_role={actor_role or 'unknown'} "
            f"trigger_app={trigger_app or 'none'} "
            f"action_apps_count={len(action_apps)} "
            f"sensitive_apps={len(sensitive_action_apps)}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"zapier-{event_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="zapier_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=execution_duration_ms,
            session_id=zap_id_last8 or None,
        )

    # -- Per-action emitters -----------------------------------------------

    def _emit_signal(
        self,
        control_results: list[ControlResult],
        *,
        signal: str,
        default_control: str,
        result: str,
        detail: str,
        common: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> None:
        control_id = _control_for(signal, self._mappings, default_control)
        evidence: dict[str, Any] = {**common, "signal": signal}
        if extra:
            evidence.update(extra)
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result=result,
                detail=detail,
                evidence_data=evidence,
            )
        )

    def _emit_zap_failed(
        self,
        control_results: list[ControlResult],
        common_evidence: dict[str, Any],
        event_id: str,
        zap_id_last8: str | None,
    ) -> None:
        self._emit_signal(
            control_results,
            signal="zap_failed",
            default_control="DE-01",
            result="FAIL",
            detail=(
                f"Zapier event {event_id}: zap "
                f"{zap_id_last8!r} reported failure"
            ),
            common=common_evidence,
        )

    def _emit_zap_run(
        self,
        control_results: list[ControlResult],
        common_evidence: dict[str, Any],
        *,
        event_id: str,
        zap_id_last8: str | None,
        task_status: str | None,
        contains_code_step: bool,
        contains_webhook_step: bool,
        webhook_target_host: str,
        sensitive_action_apps: list[str],
        data_processed_bytes: int,
        distinct_action_apps: list[str],
    ) -> None:
        # Primary status — success → PR-05 PASS, anything else → PR-02 FLAG.
        if task_status == "success":
            self._emit_signal(
                control_results,
                signal="zap_run_success",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} ran "
                    f"successfully — audit trail recorded"
                ),
                common=common_evidence,
            )
        elif task_status in {"failed", "throttled"}:
            sub_signal = (
                "zap_failed" if task_status == "failed" else "zap_run_throttled"
            )
            sub_default = "DE-01" if task_status == "failed" else "PR-02"
            sub_result = "FAIL" if task_status == "failed" else "FLAG"
            self._emit_signal(
                control_results,
                signal=sub_signal,
                default_control=sub_default,
                result=sub_result,
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} "
                    f"task_status={task_status!r}"
                ),
                common=common_evidence,
            )
        else:
            self._emit_signal(
                control_results,
                signal="zap_run_unknown_status",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} ran "
                    f"with unrecognized task_status={task_status!r}"
                ),
                common=common_evidence,
            )

        # Code-by-Zapier step — arbitrary JS/Python surface.
        if contains_code_step:
            self._emit_signal(
                control_results,
                signal="code_step_used",
                default_control="PR-03",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} ran "
                    f"with Code-by-Zapier step (arbitrary JS/Python surface)"
                ),
                common=common_evidence,
            )

        # Webhook step to non-allowlisted host.
        if (
            contains_webhook_step
            and webhook_target_host
            and not _host_allowlisted(webhook_target_host, self.webhook_allowlist)
        ):
            self._emit_signal(
                control_results,
                signal="external_webhook_step",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} sent "
                    f"to non-allowlisted webhook host "
                    f"{webhook_target_host!r} (external egress)"
                ),
                common=common_evidence,
                extra={
                    "webhook_target_host": webhook_target_host,
                    "webhook_allowlist": list(self.webhook_allowlist),
                },
            )

        # Large data through sensitive app.
        if (
            sensitive_action_apps
            and data_processed_bytes > self.large_data_threshold
        ):
            self._emit_signal(
                control_results,
                signal="large_data_sensitive_app",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} "
                    f"transited {data_processed_bytes} bytes through "
                    f"sensitive app(s) {sensitive_action_apps} "
                    f"(> {self.large_data_threshold}-byte threshold)"
                ),
                common=common_evidence,
                extra={
                    "large_data_threshold": self.large_data_threshold,
                    "sensitive_action_apps": sensitive_action_apps,
                },
            )

        # Cross-app run — single zap touching > N distinct external apps.
        if len(distinct_action_apps) > self.cross_app_threshold:
            self._emit_signal(
                control_results,
                signal="cross_app_run",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"Zapier event {event_id}: zap {zap_id_last8!r} touched "
                    f"{len(distinct_action_apps)} distinct apps "
                    f"({distinct_action_apps}) in a single run "
                    f"> threshold {self.cross_app_threshold}"
                ),
                common=common_evidence,
                extra={
                    "cross_app_apps": distinct_action_apps,
                    "cross_app_threshold": self.cross_app_threshold,
                },
            )

    def _emit_role_changed(
        self,
        control_results: list[ControlResult],
        entry: dict[str, Any],
        common_evidence: dict[str, Any],
        event_id: str,
    ) -> None:
        new_role = str(entry.get("new_role") or "").strip().lower()
        old_role = str(entry.get("old_role") or "").strip().lower()
        is_promotion = (
            new_role in self.privileged_roles
            and old_role not in self.privileged_roles
        )
        if is_promotion:
            self._emit_signal(
                control_results,
                signal="role_promotion",
                default_control="PR-02",
                result="FAIL",
                detail=(
                    f"Zapier event {event_id}: privilege escalation — "
                    f"role changed from {old_role or 'unknown'!r} to "
                    f"{new_role!r}"
                ),
                common=common_evidence,
                extra={
                    "old_role": old_role or None,
                    "new_role": new_role or None,
                },
            )
        else:
            # Lateral or demotion — record as audit PASS.
            self._emit_signal(
                control_results,
                signal="role_changed",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"Zapier event {event_id}: role changed from "
                    f"{old_role or 'unknown'!r} to {new_role or 'unknown'!r}"
                ),
                common=common_evidence,
                extra={
                    "old_role": old_role or None,
                    "new_role": new_role or None,
                },
            )

    # -- Synthetic results --------------------------------------------------

    def _synthetic_high_volume_result(
        self,
        *,
        actor_key: str,
        peak_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_runs"
        control_id = _control_for(signal, self._mappings, "PR-05")
        synthetic_id = f"zapier-high-volume-{actor_key}"
        evidence: dict[str, Any] = {
            "zapier_event_id": synthetic_id,
            "actor_user_id_last8": actor_key,
            "high_volume_peak": peak_count,
            "high_volume_threshold": self.high_volume_threshold,
            "high_volume_window_seconds": self.high_volume_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "zapier",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Zapier synthetic finding: actor user_id_last8={actor_key!r} "
                f"executed {peak_count} zap.run events in a "
                f"{self.high_volume_window_seconds}s window — exceeds "
                f"threshold {self.high_volume_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zapier_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Zapier: synthetic high-volume runs "
                f"actor={actor_key} peak={peak_count}>threshold="
                f"{self.high_volume_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_ai_burst_result(
        self,
        *,
        actor_key: str,
        peak_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "ai_action_burst"
        control_id = _control_for(signal, self._mappings, "PR-01")
        synthetic_id = f"zapier-ai-burst-{actor_key}"
        evidence: dict[str, Any] = {
            "zapier_event_id": synthetic_id,
            "actor_user_id_last8": actor_key,
            "ai_action_burst_peak": peak_count,
            "ai_action_burst_threshold": self.ai_action_burst,
            "ai_action_burst_window_seconds": self.ai_action_burst_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "zapier",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Zapier synthetic finding: actor user_id_last8={actor_key!r} "
                f"created {peak_count} ai_action.created events in a "
                f"{self.ai_action_burst_window_seconds}s window — exceeds "
                f"threshold {self.ai_action_burst}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zapier_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Zapier: synthetic AI Action burst "
                f"actor={actor_key} peak={peak_count}>threshold="
                f"{self.ai_action_burst}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
