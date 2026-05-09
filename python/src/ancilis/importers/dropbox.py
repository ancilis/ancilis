"""Dropbox team-audit-log importer — maps Dropbox activity to AKSI controls.

Dropbox (https://dropbox.com) is one of the original mass-market cloud-storage
platforms — heavily used by SMBs and an increasing share of mid-market
enterprise. Agents now read, write, share, and collaborate inside Dropbox at
scale: RAG corpora, generated reports, intermediate artifacts, customer-facing
deliverables. Dropbox's ``/2/team_log/get_events`` feed captures the
data-loss-prevention signals that govern team-level content: file uploads /
downloads / deletes, shared-link transitions (visibility, expiration), file
requests, external-collaborator additions, member invitations, app linking,
login attempts, team-policy changes, data-residency moves, EMM (Enterprise
Mobility Management) state changes, watermark application, and DLP-rule
matches.

This importer ingests Dropbox team-event JSON exports in three on-disk shapes:

  1. ``{"events": [...]}`` — Dropbox team-log envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                 — one event per line

Each event is materialized as its own ``EvaluationResult``.

Signal mapping (see shared/mappings/dropbox-aksi-controls.json):
  * ``file_download`` by actor=app/admin/reseller + sensitive extension → PR-04 FAIL
  * ``file_upload``   by actor=app                                       → PR-04 PASS
  * ``file_delete``   by actor=app                                       → PR-02 FLAG
  * ``shared_link_create`` visibility=public                             → DE-01 FAIL → BLOCK
  * ``shared_link_create`` visibility=password_only / team_and_password  → PR-04 FLAG
  * ``shared_link_create`` visibility=team_only                          → PR-05 PASS
  * ``shared_link_create`` expires_at=null + visibility != team_only     → PR-04 FAIL
  * ``file_share_anyone_member_add``                                     → DE-01 FAIL → BLOCK
  * ``file_external_member_add``                                         → PR-04 FLAG
  * ``member_invited`` participant domain != tenant primary              → PR-04 FLAG
  * ``team_policy_changed``                                              → PR-02 FAIL
  * ``data_residency_change``                                            → PR-04 FAIL
  * ``app_link_team``                                                    → PR-01 FLAG
  * ``app_unlink_team``                                                  → PR-05 PASS
  * ``login_fail``                                                       → PR-01 FLAG
  * ``dlp_match`` dlp_severity=high                                      → PR-04 FAIL → BLOCK
  * ``dlp_match`` dlp_severity=medium                                    → PR-04 FLAG
  * ``watermark_apply``                                                  → PR-04 PASS
  * ``emm_enabled``                                                      → PR-05 PASS
  * ``emm_state_change`` disabled                                        → PR-02 FAIL
  * actor.tag=dropbox (system)                                           → PR-05 PASS
  * details.is_two_factor_required=false on team_policy_changed          → PR-01 FAIL
  * Bulk-download pattern: same actor with > N file_download in 1h
    (default 50)                                                         → PR-04 FAIL → BLOCK
  * Cross-team-share pattern: same actor with > N external-member adds
    in 1h (default 10)                                                   → PR-04 FLAG

Sanitization (security-critical — Dropbox team-event records identify the
items themselves, the actor's email, the IP, and free-form parameters):
  * ``actor.email`` is reduced to ``@domain`` only — never the local-part.
  * ``actor.display_name`` is NEVER stored — only ``display_name_length`` if
    provided.
  * ``context.email`` (full) is NEVER stored — only ``email_length`` if
    provided.
  * ``participants[].user.email`` / ``email_domain`` retain ``@domain`` only.
  * ``assets[].path`` raw is NEVER stored — only ``path_length`` if provided.
  * ``assets[].file_id`` keeps only the trailing 8 characters.
  * ``details.new_value`` / ``previous_value`` retain length + sha256 only.
  * ``origin.ip_address`` is masked to /16 (IPv4) or /32-hextet (IPv6);
    private / loopback / link-local addresses are preserved verbatim.
  * ``origin.user_agent`` retains first 80 chars + sha256 of full value.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``dropbox``; team-event JSON exports are parsed
with the standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/dropbox.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "dropbox-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_BULK_DOWNLOAD_THRESHOLD = 50
_DEFAULT_BULK_DOWNLOAD_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_TEAM_SHARE_THRESHOLD = 10
_DEFAULT_CROSS_TEAM_SHARE_WINDOW_SECONDS = 3600

_DEFAULT_SENSITIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "csv",
        "xlsx",
        "xls",
        "sqlite",
        "sqlite3",
        "db",
        "tsv",
        "parquet",
        "json",
        "sql",
        "bak",
    }
)

# Dropbox actor types that signal non-human / agent activity.
_AGENT_ACTOR_TAGS: frozenset[str] = frozenset({"app", "admin", "reseller"})
_SYSTEM_ACTOR_TAG: str = "dropbox"

# Cross-team-share contributor event types.
_CROSS_TEAM_SHARE_EVENT_TYPES: frozenset[str] = frozenset(
    {"file_external_member_add", "file_share_anyone_member_add"}
)

# user_agent capture: first N chars + sha256 of full.
_USER_AGENT_PREFIX_LEN = 80


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load dropbox-aksi-controls.json; tolerate a missing/invalid file."""
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


def _classify_ip(ip_value: str | None) -> str | None:
    """Reduce an IP to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not ip_value or not isinstance(ip_value, str):
        return None
    ip = ip_value.strip()
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


def _redact_email(email: str | None) -> str | None:
    """Reduce an email to ``@domain`` only — never store the local-part."""
    if not email or not isinstance(email, str):
        return None
    em = email.strip()
    if "@" not in em:
        return None
    return "@" + em.rsplit("@", 1)[1].lower()


def _normalize_email_domain(domain: str | None) -> str | None:
    """Normalize a domain that may or may not be ``@``-prefixed."""
    if not domain or not isinstance(domain, str):
        return None
    d = domain.strip()
    if not d:
        return None
    if not d.startswith("@"):
        d = "@" + d
    return d.lower()


def _truncate_id(value: str | None) -> str | None:
    """Keep only the trailing 8 characters of a Dropbox id."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return s[-8:]


def _redact_string_value(value: str | None) -> dict[str, Any] | None:
    """Capture length + sha256 of an arbitrary string."""
    if not value or not isinstance(value, str):
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return {"length": len(value), "sha256": digest}


def _redact_user_agent(value: str | None) -> dict[str, Any] | None:
    """Capture first 80 chars + sha256 of full user-agent."""
    if not value or not isinstance(value, str):
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return {
        "prefix": value[:_USER_AGENT_PREFIX_LEN],
        "length": len(value),
        "sha256": digest,
    }


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v = v / 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None
    return None


def _format_timestamp(value: Any) -> str:
    """Render a timestamp value to an ISO 8601 string (UTC)."""
    dt = _parse_iso_timestamp(value)
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _tag_of(obj: Any) -> str | None:
    """Extract the ``.tag`` discriminator from a Dropbox-shape dict."""
    if not isinstance(obj, dict):
        return None
    raw = obj.get(".tag")
    if isinstance(raw, str) and raw:
        return raw.strip().lower()
    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class DropboxImporter:
    """Parse a Dropbox team-audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bulk_download_threshold: int | None = None,
        bulk_download_window_seconds: int | None = None,
        cross_team_share_threshold: int | None = None,
        cross_team_share_window_seconds: int | None = None,
        sensitive_extensions: Iterable[str] | None = None,
        primary_workspace_domain: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        self.bulk_download_threshold = int(
            bulk_download_threshold
            if bulk_download_threshold is not None
            else meta.get(
                "bulk_download_threshold", _DEFAULT_BULK_DOWNLOAD_THRESHOLD
            )
        )
        self.bulk_download_window_seconds = int(
            bulk_download_window_seconds
            if bulk_download_window_seconds is not None
            else meta.get(
                "bulk_download_window_seconds",
                _DEFAULT_BULK_DOWNLOAD_WINDOW_SECONDS,
            )
        )
        self.cross_team_share_threshold = int(
            cross_team_share_threshold
            if cross_team_share_threshold is not None
            else meta.get(
                "cross_team_share_threshold",
                _DEFAULT_CROSS_TEAM_SHARE_THRESHOLD,
            )
        )
        self.cross_team_share_window_seconds = int(
            cross_team_share_window_seconds
            if cross_team_share_window_seconds is not None
            else meta.get(
                "cross_team_share_window_seconds",
                _DEFAULT_CROSS_TEAM_SHARE_WINDOW_SECONDS,
            )
        )
        if sensitive_extensions is not None:
            self.sensitive_extensions: frozenset[str] = frozenset(
                str(e).strip().lower().lstrip(".")
                for e in sensitive_extensions
                if e
            )
        else:
            meta_exts = meta.get("sensitive_extensions")
            if isinstance(meta_exts, list) and meta_exts:
                self.sensitive_extensions = frozenset(
                    str(e).strip().lower().lstrip(".") for e in meta_exts if e
                )
            else:
                self.sensitive_extensions = _DEFAULT_SENSITIVE_EXTENSIONS
        if primary_workspace_domain is not None:
            self.primary_workspace_domain: str | None = (
                _normalize_email_domain(primary_workspace_domain)
            )
        else:
            meta_domain = meta.get("primary_workspace_domain")
            self.primary_workspace_domain = (
                _normalize_email_domain(meta_domain)
                if isinstance(meta_domain, str) and meta_domain.strip()
                else None
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[Any]:
        """Parse a Dropbox team-event export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Dropbox team-event content from a string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events": [...]}`` / ``{"data": [...]}`` / JSONL / single."""
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

    @staticmethod
    def _actor_identity_key(event: dict[str, Any]) -> str | None:
        """Build a per-actor key for synthetic-pattern aggregation.

        Prefers ``actor.team_member_id``; falls back to email domain or
        actor tag — events lacking any identity hint are excluded from
        synthetic aggregation.
        """
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            return None
        tmid = actor.get("team_member_id")
        if isinstance(tmid, str) and tmid.strip():
            return f"tmid:{tmid.strip()}"
        email = actor.get("email")
        if isinstance(email, str) and "@" in email:
            return f"email:{email.strip().lower()}"
        tag = _tag_of(actor)
        if tag:
            return f"tag:{tag}"
        return None

    @staticmethod
    def _event_type_tag(event: dict[str, Any]) -> str | None:
        """Extract ``event_type[".tag"]`` for a Dropbox event envelope."""
        et = event.get("event_type")
        if isinstance(et, dict):
            return _tag_of(et)
        if isinstance(et, str) and et:
            return et.strip().lower()
        return None

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[Any]:
        """Build per-event EvaluationResults plus bulk + cross-team synthetics."""
        download_events: dict[str, list[datetime]] = {}
        cross_team_events: dict[str, list[datetime]] = {}

        for event in events:
            actor_key = self._actor_identity_key(event)
            if actor_key is None:
                continue
            event_dt = _parse_iso_timestamp(event.get("timestamp"))
            if event_dt is None:
                continue
            ev_type = self._event_type_tag(event)
            if ev_type == "file_download":
                download_events.setdefault(actor_key, []).append(event_dt)
            if ev_type in _CROSS_TEAM_SHARE_EVENT_TYPES:
                cross_team_events.setdefault(actor_key, []).append(event_dt)

        bulk_download_actors: dict[str, int] = {}
        window_dl = timedelta(seconds=self.bulk_download_window_seconds)
        for actor, ts_list in download_events.items():
            if len(ts_list) <= self.bulk_download_threshold:
                continue
            sorted_ts = sorted(ts_list)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while sorted_ts[right] - sorted_ts[left] > window_dl:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.bulk_download_threshold:
                bulk_download_actors[actor] = max_in_window

        cross_team_actors: dict[str, int] = {}
        window_ct = timedelta(seconds=self.cross_team_share_window_seconds)
        for actor, ts_list in cross_team_events.items():
            if len(ts_list) <= self.cross_team_share_threshold:
                continue
            sorted_ts = sorted(ts_list)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while sorted_ts[right] - sorted_ts[left] > window_ct:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.cross_team_share_threshold:
                cross_team_actors[actor] = max_in_window

        results: list[Any] = []
        for event in events:
            result = self._parse_event(
                event,
                file_sha256=file_sha256,
                bulk_download_actors=bulk_download_actors,
                cross_team_actors=cross_team_actors,
            )
            if result is not None:
                results.append(result)

        for actor, count in sorted(bulk_download_actors.items()):
            results.append(
                self._synthetic_bulk_download_result(
                    actor=actor,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for actor, count in sorted(cross_team_actors.items()):
            results.append(
                self._synthetic_cross_team_share_result(
                    actor=actor,
                    count=count,
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
            "source_format": "dropbox_team_log",
            "source_tool_name": "dropbox",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-event parsing — each event becomes one EvaluationResult.
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        bulk_download_actors: dict[str, int],
        cross_team_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        event_id = str(uuid.uuid4())
        ev_type = self._event_type_tag(event)
        ev_category = (
            str(event.get("event_category")).strip().lower()
            if isinstance(event.get("event_category"), str)
            and event.get("event_category")
            else None
        )
        timestamp_iso = _format_timestamp(event.get("timestamp"))

        # --- Actor -------------------------------------------------------
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_tag = _tag_of(actor)
        actor_email_domain = _redact_email(
            actor.get("email") if isinstance(actor.get("email"), str) else None
        )
        actor_display_name_length_raw = actor.get("display_name_length")
        actor_display_name_length: int | None = (
            int(actor_display_name_length_raw)
            if isinstance(actor_display_name_length_raw, (int, float))
            and not isinstance(actor_display_name_length_raw, bool)
            else None
        )
        actor_team_member_id_last8 = _truncate_id(
            actor.get("team_member_id")
            if isinstance(actor.get("team_member_id"), str)
            else None
        )

        # --- Context ------------------------------------------------------
        context = event.get("context") or {}
        if not isinstance(context, dict):
            context = {}
        context_tag = _tag_of(context)
        context_team_member_id_last8 = _truncate_id(
            context.get("team_member_id")
            if isinstance(context.get("team_member_id"), str)
            else None
        )
        context_email_length_raw = context.get("email_length")
        context_email_length: int | None = (
            int(context_email_length_raw)
            if isinstance(context_email_length_raw, (int, float))
            and not isinstance(context_email_length_raw, bool)
            else None
        )

        # --- Participants -------------------------------------------------
        participants_in = event.get("participants") or []
        participant_domains: list[str] = []
        if isinstance(participants_in, list):
            for p in participants_in:
                if not isinstance(p, dict):
                    continue
                user = p.get("user")
                if isinstance(user, dict):
                    dom = user.get("email_domain")
                    if isinstance(dom, str) and dom.strip():
                        normalized = _normalize_email_domain(dom)
                        if normalized:
                            participant_domains.append(normalized)
                            continue
                    full = user.get("email")
                    if isinstance(full, str) and "@" in full:
                        red = _redact_email(full)
                        if red:
                            participant_domains.append(red)

        # --- Assets -------------------------------------------------------
        assets_in = event.get("assets") or []
        assets_redacted: list[dict[str, Any]] = []
        first_asset_extension: str | None = None
        first_asset_size_bytes: int | None = None
        first_asset_file_id_last8: str | None = None
        if isinstance(assets_in, list):
            for a in assets_in:
                if not isinstance(a, dict):
                    continue
                a_tag = _tag_of(a)
                a_path_length_raw = None
                path_obj = a.get("path")
                if isinstance(path_obj, dict):
                    pl = path_obj.get("path_length")
                    if (
                        isinstance(pl, (int, float))
                        and not isinstance(pl, bool)
                    ):
                        a_path_length_raw = int(pl)
                a_extension = (
                    str(a.get("extension")).strip().lower().lstrip(".")
                    if isinstance(a.get("extension"), str)
                    and a.get("extension")
                    else None
                )
                a_size_bytes_raw = a.get("size_bytes")
                a_size_bytes: int | None = (
                    int(a_size_bytes_raw)
                    if isinstance(a_size_bytes_raw, (int, float))
                    and not isinstance(a_size_bytes_raw, bool)
                    else None
                )
                a_file_id_last8 = _truncate_id(
                    a.get("file_id")
                    if isinstance(a.get("file_id"), str)
                    else None
                )
                assets_redacted.append(
                    {
                        "tag": a_tag,
                        "path_length": a_path_length_raw,
                        "extension": a_extension,
                        "size_bytes": a_size_bytes,
                        "file_id_last8": a_file_id_last8,
                    }
                )
                if first_asset_extension is None and a_extension:
                    first_asset_extension = a_extension
                if first_asset_size_bytes is None and a_size_bytes is not None:
                    first_asset_size_bytes = a_size_bytes
                if (
                    first_asset_file_id_last8 is None
                    and a_file_id_last8 is not None
                ):
                    first_asset_file_id_last8 = a_file_id_last8

        # --- Details ------------------------------------------------------
        details = event.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        shared_link_visibility = (
            str(details.get("shared_link_visibility")).strip().lower()
            if isinstance(details.get("shared_link_visibility"), str)
            and details.get("shared_link_visibility")
            else None
        )
        shared_link_expires_at_raw = details.get("shared_link_expires_at")
        shared_link_has_expiry: bool = bool(
            isinstance(shared_link_expires_at_raw, str)
            and shared_link_expires_at_raw.strip()
        )
        external_user_email_domain = _normalize_email_domain(
            details.get("external_user_email_domain")
            if isinstance(details.get("external_user_email_domain"), str)
            else None
        )
        new_value_redacted = _redact_string_value(
            details.get("new_value")
            if isinstance(details.get("new_value"), str)
            else None
        )
        previous_value_redacted = _redact_string_value(
            details.get("previous_value")
            if isinstance(details.get("previous_value"), str)
            else None
        )
        app_id_raw = (
            str(details.get("app_id")).strip()
            if isinstance(details.get("app_id"), str)
            and details.get("app_id")
            else None
        )
        app_id_last8 = _truncate_id(app_id_raw) if app_id_raw else None
        app_name = (
            str(details.get("app_name")).strip()
            if isinstance(details.get("app_name"), str)
            and details.get("app_name")
            else None
        )
        emm_state_change = (
            str(details.get("emm_state_change")).strip().lower()
            if isinstance(details.get("emm_state_change"), str)
            and details.get("emm_state_change")
            else None
        )
        watermark_label = (
            str(details.get("watermark_label")).strip()
            if isinstance(details.get("watermark_label"), str)
            and details.get("watermark_label")
            else None
        )
        dlp_rule_name = (
            str(details.get("dlp_rule_name")).strip()
            if isinstance(details.get("dlp_rule_name"), str)
            and details.get("dlp_rule_name")
            else None
        )
        dlp_severity = (
            str(details.get("dlp_severity")).strip().lower()
            if isinstance(details.get("dlp_severity"), str)
            and details.get("dlp_severity")
            else None
        )
        data_residency_region = (
            str(details.get("data_residency_region")).strip()
            if isinstance(details.get("data_residency_region"), str)
            and details.get("data_residency_region")
            else None
        )
        is_two_factor_required_raw = details.get("is_two_factor_required")
        is_two_factor_required: bool | None = (
            bool(is_two_factor_required_raw)
            if isinstance(is_two_factor_required_raw, bool)
            else None
        )

        # --- Origin -------------------------------------------------------
        origin = event.get("origin") or {}
        if not isinstance(origin, dict):
            origin = {}
        origin_tag = _tag_of(origin)
        origin_ip_redacted = _classify_ip(
            origin.get("ip_address")
            if isinstance(origin.get("ip_address"), str)
            else None
        )
        origin_user_agent_redacted = _redact_user_agent(
            origin.get("user_agent")
            if isinstance(origin.get("user_agent"), str)
            else None
        )
        origin_device_type = (
            str(origin.get("device_type")).strip().lower()
            if isinstance(origin.get("device_type"), str)
            and origin.get("device_type")
            else None
        )

        common_evidence: dict[str, Any] = {
            "dropbox_event_id": event_id,
            "event_category": ev_category,
            "event_type": ev_type,
            "actor_tag": actor_tag,
            "actor_email_domain": actor_email_domain,
            "actor_display_name_length": actor_display_name_length,
            "actor_team_member_id_last8": actor_team_member_id_last8,
            "context_tag": context_tag,
            "context_team_member_id_last8": context_team_member_id_last8,
            "context_email_length": context_email_length,
            "participant_domains": participant_domains,
            "assets": assets_redacted,
            "asset_extension": first_asset_extension,
            "asset_size_bytes": first_asset_size_bytes,
            "asset_file_id_last8": first_asset_file_id_last8,
            "shared_link_visibility": shared_link_visibility,
            "shared_link_has_expiry": shared_link_has_expiry,
            "external_user_email_domain": external_user_email_domain,
            "new_value_redacted": new_value_redacted,
            "previous_value_redacted": previous_value_redacted,
            "app_id_last8": app_id_last8,
            "app_name": app_name,
            "emm_state_change": emm_state_change,
            "watermark_label": watermark_label,
            "dlp_rule_name": dlp_rule_name,
            "dlp_severity": dlp_severity,
            "data_residency_region": data_residency_region,
            "is_two_factor_required": is_two_factor_required,
            "origin_tag": origin_tag,
            "origin_ip_redacted": origin_ip_redacted,
            "origin_user_agent_redacted": origin_user_agent_redacted,
            "origin_device_type": origin_device_type,
            "event_time": timestamp_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "dropbox",
        }

        control_results: list[ControlResult] = []
        is_agent_actor = actor_tag in _AGENT_ACTOR_TAGS
        is_system_actor = actor_tag == _SYSTEM_ACTOR_TAG

        # ----------------------------------------------------------------
        # event_type-driven primary classification
        # ----------------------------------------------------------------
        if ev_type == "file_download":
            agent_sensitive = (
                is_agent_actor
                and first_asset_extension is not None
                and first_asset_extension in self.sensitive_extensions
            )
            if agent_sensitive:
                signal = "agent_sensitive_download"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} file_download by "
                            f"actor_tag={actor_tag!r} on extension="
                            f"{first_asset_extension!r} file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"agent downloading bulk-data file, requires "
                            f"review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "file_upload":
            if is_agent_actor:
                signal = "service_account_upload"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="PASS",
                        detail=(
                            f"Dropbox event {event_id} file_upload by "
                            f"actor_tag={actor_tag!r} on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"service-account write captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "file_delete":
            if is_agent_actor:
                signal = "service_account_delete"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} file_delete by "
                            f"actor_tag={actor_tag!r} on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"bot deleting content, requires review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "shared_link_create":
            if shared_link_visibility == "public":
                signal = "public_share"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} shared_link_create "
                            f"visibility='public' on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"public link, top-priority exfil"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif shared_link_visibility == "team_only":
                signal = "team_only_share"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="PASS",
                        detail=(
                            f"Dropbox event {event_id} shared_link_create "
                            f"visibility='team_only' on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"intra-team share, audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif shared_link_visibility in ("password_only", "team_and_password"):
                signal = "password_protected_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} shared_link_create "
                            f"visibility={shared_link_visibility!r} on "
                            f"file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"password-protected external link"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            # Permanent-share check — applies whenever expiry is missing AND
            # link is not team-only (team-only is treated as governed).
            if (
                not shared_link_has_expiry
                and shared_link_visibility is not None
                and shared_link_visibility != "team_only"
            ):
                signal = "permanent_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} shared_link_create "
                            f"visibility={shared_link_visibility!r} with "
                            f"no expiration on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"permanent share, indefinite exposure window"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "file_share_anyone_member_add":
            signal = "anyone_link_expansion"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} file_share_anyone_member_add"
                        f" on file_id="
                        f"{first_asset_file_id_last8 or 'unknown'} — "
                        f"anyone-link expansion, top-priority exfil"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "file_external_member_add":
            signal = "external_member_add"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} file_external_member_add "
                        f"external_domain="
                        f"{external_user_email_domain or 'unknown'} on "
                        f"file_id="
                        f"{first_asset_file_id_last8 or 'unknown'} — "
                        f"external collaborator added"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "member_invited":
            primary = self.primary_workspace_domain
            external_invite_domains = [
                d
                for d in participant_domains
                if primary is None or d != primary
            ]
            if primary is not None and external_invite_domains:
                signal = "external_member_invited"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} member_invited with "
                            f"participant domains="
                            f"{external_invite_domains!r} (primary="
                            f"{primary!r}) — external invite"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "team_policy_changed":
            # Tenant-level policy change. If 2FA is being disabled, raise
            # PR-01 FAIL alongside PR-02 FAIL.
            signal = "team_policy_change"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} team_policy_changed — "
                        f"tenant-level policy changed, top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            if is_two_factor_required is False:
                signal = "two_factor_disabled"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} team_policy_changed "
                            f"is_two_factor_required=false — tenant-wide "
                            f"2FA disabled, identity weakening"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "data_residency_change":
            signal = "data_residency_change"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} data_residency_change "
                        f"region={data_residency_region or 'unknown'} — "
                        f"GDPR-relevant region change, top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "app_link_team":
            signal = "app_link_team"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} app_link_team app_name="
                        f"{app_name or 'unknown'} app_id_last8="
                        f"{app_id_last8 or 'unknown'} — new automation "
                        f"surface attached to team"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "app_unlink_team":
            signal = "app_unlink_team"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} app_unlink_team app_name="
                        f"{app_name or 'unknown'} — automation surface "
                        f"detached, audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "login_fail":
            signal = "login_fail"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} login_fail "
                        f"actor_domain={actor_email_domain or 'unknown'} — "
                        f"authentication failure"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "dlp_match":
            if dlp_severity == "high":
                signal = "dlp_match_high"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} dlp_match severity=high "
                            f"rule={dlp_rule_name or 'unknown'} on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"DLP rule matched, top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif dlp_severity == "medium":
                signal = "dlp_match_medium"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} dlp_match "
                            f"severity=medium rule="
                            f"{dlp_rule_name or 'unknown'} on file_id="
                            f"{first_asset_file_id_last8 or 'unknown'} — "
                            f"DLP rule matched"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "watermark_apply":
            signal = "watermark_apply"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} watermark_apply label="
                        f"{watermark_label or 'unknown'} on file_id="
                        f"{first_asset_file_id_last8 or 'unknown'} — "
                        f"governance applied"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "emm_enabled":
            signal = "emm_enabled"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} emm_enabled — Enterprise "
                        f"Mobility Management enabled, device security "
                        f"strengthened"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "emm_state_change":
            if emm_state_change == "disabled":
                signal = "emm_disabled"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} emm_state_change="
                            f"disabled — Enterprise Mobility Management "
                            f"disabled, device security weakening"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # System actor — informational PASS to record audit-trail integrity.
        if is_system_actor and not control_results:
            signal = "system_action"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} actor_tag='dropbox' "
                        f"event_type={ev_type!r} — system action, "
                        f"audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Synthetic pattern markers — informational on contributing events.
        # ----------------------------------------------------------------
        actor_key = self._actor_identity_key(event)
        if actor_key and actor_key in bulk_download_actors:
            signal = "bulk_download_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} actor_tmid_last8="
                        f"{actor_team_member_id_last8 or 'unknown'} is part "
                        f"of a bulk-download pattern ("
                        f"{bulk_download_actors[actor_key]} downloads > "
                        f"threshold {self.bulk_download_threshold} in "
                        f"{self.bulk_download_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bulk_download_count":
                            bulk_download_actors[actor_key],
                        "bulk_download_threshold":
                            self.bulk_download_threshold,
                        "bulk_download_window_seconds":
                            self.bulk_download_window_seconds,
                    },
                )
            )
        if actor_key and actor_key in cross_team_actors:
            signal = "cross_team_share_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} actor_tmid_last8="
                        f"{actor_team_member_id_last8 or 'unknown'} is part "
                        f"of a cross-team-share pattern ("
                        f"{cross_team_actors[actor_key]} external-member "
                        f"adds > threshold {self.cross_team_share_threshold} "
                        f"in {self.cross_team_share_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_team_share_count":
                            cross_team_actors[actor_key],
                        "cross_team_share_threshold":
                            self.cross_team_share_threshold,
                        "cross_team_share_window_seconds":
                            self.cross_team_share_window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------
        # No-match fallback — surface unknown event so it is not silent.
        # ----------------------------------------------------------------
        if not control_results:
            signal = "captured_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} event_type={ev_type!r} "
                        f"actor_tag={actor_tag!r} — audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Dropbox team-audit log: event_type="
            f"{ev_type or 'unknown'} event_category="
            f"{ev_category or 'unknown'} actor_tag={actor_tag or 'unknown'} "
            f"actor_domain={actor_email_domain or 'unknown'} file_id="
            f"{first_asset_file_id_last8 or 'unknown'}"
        )

        action_id = f"dropbox-{event_id[:48]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="dropbox_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # -- Synthetic results --------------------------------------------------

    def _synthetic_bulk_download_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "bulk_download_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"dropbox-bulk-download-{uuid.uuid4()}"
        actor_key_short = actor[-32:]
        evidence: dict[str, Any] = {
            "dropbox_event_id": synthetic_id,
            "actor_key": actor_key_short,
            "bulk_download_count": count,
            "bulk_download_threshold": self.bulk_download_threshold,
            "bulk_download_window_seconds": self.bulk_download_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "dropbox",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Dropbox synthetic finding: actor_key={actor_key_short} "
                f"performed {count} downloads in a "
                f"{self.bulk_download_window_seconds}s window — exceeds "
                f"bulk-download threshold {self.bulk_download_threshold} "
                f"(mass-export pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="dropbox_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Dropbox team-audit log: synthetic "
                f"bulk-download pattern for actor_key={actor_key_short} "
                f"count={count}>threshold={self.bulk_download_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_team_share_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_team_share_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"dropbox-cross-team-share-{uuid.uuid4()}"
        actor_key_short = actor[-32:]
        evidence: dict[str, Any] = {
            "dropbox_event_id": synthetic_id,
            "actor_key": actor_key_short,
            "cross_team_share_count": count,
            "cross_team_share_threshold": self.cross_team_share_threshold,
            "cross_team_share_window_seconds":
                self.cross_team_share_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "dropbox",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Dropbox synthetic finding: actor_key={actor_key_short} "
                f"performed {count} external-member adds in a "
                f"{self.cross_team_share_window_seconds}s window — exceeds "
                f"cross-team-share threshold "
                f"{self.cross_team_share_threshold} (mass-external-share "
                f"pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="dropbox_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Dropbox team-audit log: synthetic "
                f"cross-team-share pattern for actor_key={actor_key_short} "
                f"count={count}>threshold="
                f"{self.cross_team_share_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
