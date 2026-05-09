"""Dropbox team-activity-log importer — maps Dropbox audit events to AKSI controls.

Dropbox (https://dropbox.com) is one of the original mass-market cloud-storage
platforms — heavily used by SMBs and an increasing share of mid-market
enterprise. Agents now read, write, share, and collaborate inside Dropbox at
scale: RAG corpora, generated reports, intermediate artifacts, customer-facing
deliverables. Dropbox's ``/2/team_log/get_events`` feed surfaces the data-loss-
prevention signals that today's evidence pipelines rarely capture: file
previews/downloads/uploads/deletes, shared-link transitions (visibility,
allow-download), file requests, external-collaborator additions, member
invitations, app linking, login attempts, team-policy changes, data-residency
moves, EMM exception lists, two-factor changes, SSO changes, team-folder
destructions, admin-role promotions, and Paper-doc external sharing.

This importer ingests Dropbox team-log JSON exports in three on-disk shapes:

  1. ``{"events": [...]}`` — Dropbox team_log envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Each event is materialized as its own ``EvaluationResult``.

Signal mapping (see shared/mappings/dropbox-aksi-controls.json):
  * ``file_preview`` / ``file_download`` by user                         -> PR-04 PASS
  * ``file_download`` by ``actor.tag=app`` on sensitive extension        -> PR-04 FAIL
  * ``file_download`` ``file_size > 1GB``                                -> PR-04 FLAG
  * ``shared_link_create`` audience=``public``                           -> DE-01 FAIL
  * ``shared_link_create`` audience=``password``                         -> PR-04 FLAG
  * ``shared_link_settings_allow_download_disabled`` -> enabled          -> PR-04 FLAG
  * ``shared_link_change_visibility`` -> public                          -> DE-01 FAIL
  * ``shared_link_disable``                                              -> PR-05 PASS
  * ``file_share`` participant domain != team primary                    -> PR-04 FLAG
  * ``file_share`` ``sensitivity_label=confidential`` to external        -> PR-04 FAIL
  * ``team_folder_permanently_delete``                                   -> PR-02 FAIL
  * ``member_change_admin_role`` to privileged role                      -> PR-02 FAIL
  * ``app_link``                                                         -> PR-01 FLAG
  * ``sso_change_settings``                                              -> PR-02 FLAG
  * ``two_step_verification_disable``                                    -> PR-01 FAIL
  * ``data_residency_migration``                                         -> PR-04 FLAG
  * ``emm_create_exceptions_report``                                     -> PR-05 FLAG
  * ``paper_doc_share`` to external domain                               -> PR-04 FLAG
  * ``file_request_create``                                              -> PR-04 FLAG
  * ``access_method=admin_console`` on routine read                      -> PR-02 FLAG
  * ``access_method=sign_in_as``                                         -> PR-01 FLAG
  * ``access_method=api`` by app actor                                   -> PR-05 PASS
  * ``actor.tag=app`` on sensitive extension (non-download events)       -> PR-04 FLAG
  * Bulk-download pattern: same actor with > N file_download in 1h
    (default 50)                                                         -> PR-04 FAIL
  * Cross-team-folder pattern: same actor touching > N team_folders in
    1h (default 5)                                                       -> PR-04 FLAG
  * External-recipient pattern: same actor sharing to > N distinct
    external email domains in 1h (default 10)                            -> PR-04 FLAG

Sanitization (security-critical — Dropbox team-log records identify the items
themselves, the actor's email, the IP, geo data, and free-form parameters):
  * ``asset[].path``        is NEVER stored — only ``path_length`` retained.
  * ``asset[].file_id``     keeps only the trailing 8 characters.
  * ``asset[].display_name`` length only — never the literal name.
  * ``actor.user.email``    is reduced to ``@domain`` only.
  * ``actor.user.display_name`` length only.
  * ``team_member_id``      keeps only the trailing 8 characters.
  * ``shared_link_owner.email`` reduced to ``@domain`` only.
  * ``shared_link_id``      keeps only the trailing 8 characters.
  * ``origin.ip_address``   masked /16 (IPv4) or /32-hextet (IPv6); private /
                            loopback / link-local addresses are preserved.
  * ``origin.geo_location.city`` and ``region`` are dropped entirely; only
                            ``country`` is retained.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``dropbox``; team-log JSON exports are parsed with
the standard library only.
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

_DEFAULT_LARGE_FILE_THRESHOLD = 1_000_000_000  # 1 GB
_DEFAULT_BULK_DOWNLOAD_THRESHOLD = 50
_DEFAULT_BULK_DOWNLOAD_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_TEAM_FOLDER_THRESHOLD = 5
_DEFAULT_CROSS_TEAM_FOLDER_WINDOW_SECONDS = 3600
_DEFAULT_EXTERNAL_RECIPIENT_THRESHOLD = 10
_DEFAULT_EXTERNAL_RECIPIENT_WINDOW_SECONDS = 3600

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

_DEFAULT_AGENT_ACTOR_TAGS: frozenset[str] = frozenset(
    {"app", "admin", "reseller"}
)
_DEFAULT_PUBLIC_AUDIENCES: frozenset[str] = frozenset({"public"})
_DEFAULT_PASSWORD_AUDIENCES: frozenset[str] = frozenset({"password"})
_DEFAULT_TEAM_AUDIENCES: frozenset[str] = frozenset({"team", "members"})
_DEFAULT_PRIVILEGED_ADMIN_ROLES: frozenset[str] = frozenset(
    {"team_admin", "user_management_admin", "admin", "support_admin"}
)


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
    """Keep only the trailing 8 characters of an identifier."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return s[-8:]


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, bool):
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


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None
    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class DropboxImporter:
    """Parse a Dropbox team-activity-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_file_threshold: int | None = None,
        bulk_download_threshold: int | None = None,
        bulk_download_window_seconds: int | None = None,
        cross_team_folder_threshold: int | None = None,
        cross_team_folder_window_seconds: int | None = None,
        external_recipient_threshold: int | None = None,
        external_recipient_window_seconds: int | None = None,
        sensitive_extensions: Iterable[str] | None = None,
        agent_actor_tags: Iterable[str] | None = None,
        public_audiences: Iterable[str] | None = None,
        password_audiences: Iterable[str] | None = None,
        team_audiences: Iterable[str] | None = None,
        privileged_admin_roles: Iterable[str] | None = None,
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
        self.large_file_threshold = int(
            large_file_threshold
            if large_file_threshold is not None
            else meta.get(
                "large_file_threshold_bytes", _DEFAULT_LARGE_FILE_THRESHOLD
            )
        )
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
        self.cross_team_folder_threshold = int(
            cross_team_folder_threshold
            if cross_team_folder_threshold is not None
            else meta.get(
                "cross_team_folder_threshold",
                _DEFAULT_CROSS_TEAM_FOLDER_THRESHOLD,
            )
        )
        self.cross_team_folder_window_seconds = int(
            cross_team_folder_window_seconds
            if cross_team_folder_window_seconds is not None
            else meta.get(
                "cross_team_folder_window_seconds",
                _DEFAULT_CROSS_TEAM_FOLDER_WINDOW_SECONDS,
            )
        )
        self.external_recipient_threshold = int(
            external_recipient_threshold
            if external_recipient_threshold is not None
            else meta.get(
                "external_recipient_threshold",
                _DEFAULT_EXTERNAL_RECIPIENT_THRESHOLD,
            )
        )
        self.external_recipient_window_seconds = int(
            external_recipient_window_seconds
            if external_recipient_window_seconds is not None
            else meta.get(
                "external_recipient_window_seconds",
                _DEFAULT_EXTERNAL_RECIPIENT_WINDOW_SECONDS,
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
        if agent_actor_tags is not None:
            self.agent_actor_tags: frozenset[str] = frozenset(
                str(t).strip().lower() for t in agent_actor_tags if t
            )
        else:
            meta_tags = meta.get("agent_actor_tags")
            self.agent_actor_tags = (
                frozenset(str(t).strip().lower() for t in meta_tags if t)
                if isinstance(meta_tags, list) and meta_tags
                else _DEFAULT_AGENT_ACTOR_TAGS
            )
        if public_audiences is not None:
            self.public_audiences: frozenset[str] = frozenset(
                str(a).strip().lower() for a in public_audiences if a
            )
        else:
            meta_pub = meta.get("public_audiences")
            self.public_audiences = (
                frozenset(str(a).strip().lower() for a in meta_pub if a)
                if isinstance(meta_pub, list) and meta_pub
                else _DEFAULT_PUBLIC_AUDIENCES
            )
        if password_audiences is not None:
            self.password_audiences: frozenset[str] = frozenset(
                str(a).strip().lower() for a in password_audiences if a
            )
        else:
            meta_pwd = meta.get("password_audiences")
            self.password_audiences = (
                frozenset(str(a).strip().lower() for a in meta_pwd if a)
                if isinstance(meta_pwd, list) and meta_pwd
                else _DEFAULT_PASSWORD_AUDIENCES
            )
        if team_audiences is not None:
            self.team_audiences: frozenset[str] = frozenset(
                str(a).strip().lower() for a in team_audiences if a
            )
        else:
            meta_team = meta.get("team_audiences")
            self.team_audiences = (
                frozenset(str(a).strip().lower() for a in meta_team if a)
                if isinstance(meta_team, list) and meta_team
                else _DEFAULT_TEAM_AUDIENCES
            )
        if privileged_admin_roles is not None:
            self.privileged_admin_roles: frozenset[str] = frozenset(
                str(r).strip().lower() for r in privileged_admin_roles if r
            )
        else:
            meta_roles = meta.get("privileged_admin_roles")
            self.privileged_admin_roles = (
                frozenset(str(r).strip().lower() for r in meta_roles if r)
                if isinstance(meta_roles, list) and meta_roles
                else _DEFAULT_PRIVILEGED_ADMIN_ROLES
            )
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
        """Parse a Dropbox team-log export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Dropbox team-log content from a string."""
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

    # -- Sub-extractors -----------------------------------------------------

    def _extract_event_type_tag(self, event: dict[str, Any]) -> str | None:
        et = event.get("event_type")
        if isinstance(et, dict):
            tag = et.get(".tag")
            if isinstance(tag, str) and tag:
                return tag.strip().lower()
        if isinstance(et, str) and et:
            return et.strip().lower()
        return None

    def _extract_actor(self, event: dict[str, Any]) -> dict[str, Any]:
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            return {}
        tag = actor.get(".tag")
        actor_tag = (
            tag.strip().lower() if isinstance(tag, str) and tag else None
        )
        user = actor.get("user") or {}
        if not isinstance(user, dict):
            user = {}
        email_raw = (
            user.get("email") if isinstance(user.get("email"), str) else None
        )
        team_member_id_raw = (
            user.get("team_member_id")
            if isinstance(user.get("team_member_id"), str)
            else None
        )
        account_id_raw = (
            user.get("account_id")
            if isinstance(user.get("account_id"), str)
            else None
        )
        display_name_length = _coerce_int(user.get("display_name_length"))
        return {
            "tag": actor_tag,
            "email_raw": email_raw,
            "email_domain": _redact_email(email_raw),
            "team_member_id_last8": _truncate_id(team_member_id_raw),
            "account_id_last8": _truncate_id(account_id_raw),
            "display_name_length": display_name_length,
            "raw_account_id": account_id_raw,
            "raw_team_member_id": team_member_id_raw,
        }

    def _extract_assets(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        raw = event.get("asset") or []
        if not isinstance(raw, list):
            return []
        out: list[dict[str, Any]] = []
        for a in raw:
            if not isinstance(a, dict):
                continue
            tag = a.get(".tag")
            ext_raw = a.get("file_extension")
            extension = (
                str(ext_raw).strip().lower().lstrip(".")
                if isinstance(ext_raw, str) and ext_raw
                else None
            )
            file_size = _coerce_int(a.get("file_size"))
            sensitivity_raw = a.get("sensitivity_label")
            sensitivity = (
                str(sensitivity_raw).strip().lower()
                if isinstance(sensitivity_raw, str) and sensitivity_raw
                else None
            )
            file_id = (
                a.get("file_id") if isinstance(a.get("file_id"), str) else None
            )
            path_length = _coerce_int(a.get("path_length"))
            display_name_length = _coerce_int(a.get("display_name_length"))
            out.append(
                {
                    "tag": (
                        tag.strip().lower()
                        if isinstance(tag, str) and tag
                        else None
                    ),
                    "file_extension": extension,
                    "file_size": file_size,
                    "sensitivity_label": sensitivity,
                    "file_id_last8": _truncate_id(file_id),
                    "path_length": path_length,
                    "display_name_length": display_name_length,
                }
            )
        return out

    def _extract_participant_domains(
        self, event: dict[str, Any]
    ) -> list[str]:
        raw = event.get("participants") or []
        if not isinstance(raw, list):
            return []
        domains: list[str] = []
        for p in raw:
            if not isinstance(p, dict):
                continue
            user = p.get("user") if isinstance(p.get("user"), dict) else {}
            email_raw = (
                user.get("email")
                if isinstance(user.get("email"), str)
                else None
            )
            domain_raw = (
                user.get("email_domain")
                if isinstance(user.get("email_domain"), str)
                else None
            )
            domain = _normalize_email_domain(domain_raw)
            if domain is None:
                domain = _redact_email(email_raw)
            if domain:
                domains.append(domain)
        return domains

    def _extract_origin(self, event: dict[str, Any]) -> dict[str, Any]:
        origin = event.get("origin") or {}
        if not isinstance(origin, dict):
            return {}
        geo = origin.get("geo_location") or {}
        if not isinstance(geo, dict):
            geo = {}
        country_raw = (
            geo.get("country")
            if isinstance(geo.get("country"), str)
            else None
        )
        country = (
            country_raw.strip().upper()
            if country_raw and country_raw.strip()
            else None
        )
        ip_raw = (
            geo.get("ip_address")
            if isinstance(geo.get("ip_address"), str)
            else None
        )
        access_method = origin.get("access_method") or {}
        am_tag: str | None = None
        if isinstance(access_method, dict):
            t = access_method.get(".tag")
            if isinstance(t, str) and t:
                am_tag = t.strip().lower()
        elif isinstance(access_method, str):
            am_tag = access_method.strip().lower() or None
        return {
            "country": country,
            "ip_address_redacted": _classify_ip(ip_raw),
            "access_method_tag": am_tag,
        }

    def _extract_details(self, event: dict[str, Any]) -> dict[str, Any]:
        details = event.get("details") or {}
        if not isinstance(details, dict):
            return {}
        out: dict[str, Any] = {}
        sl_owner = details.get("shared_link_owner") or {}
        if isinstance(sl_owner, dict):
            sl_email = (
                sl_owner.get("email")
                if isinstance(sl_owner.get("email"), str)
                else None
            )
            out["shared_link_owner_email_domain"] = _redact_email(sl_email)
        audience = details.get("shared_link_audience") or {}
        if isinstance(audience, dict):
            t = audience.get(".tag")
            if isinstance(t, str) and t:
                out["shared_link_audience_tag"] = t.strip().lower()
        elif isinstance(audience, str) and audience:
            out["shared_link_audience_tag"] = audience.strip().lower()
        sl_id = details.get("shared_link_id")
        if isinstance(sl_id, str) and sl_id:
            out["shared_link_id_last8"] = _truncate_id(sl_id)
        new_value = details.get("new_value") or {}
        if isinstance(new_value, dict):
            t = new_value.get(".tag")
            if isinstance(t, str) and t:
                out["new_value_tag"] = t.strip().lower()
        previous_value = details.get("previous_value") or {}
        if isinstance(previous_value, dict):
            t = previous_value.get(".tag")
            if isinstance(t, str) and t:
                out["previous_value_tag"] = t.strip().lower()
        new_visibility = details.get("new_visibility") or {}
        if isinstance(new_visibility, dict):
            t = new_visibility.get(".tag")
            if isinstance(t, str) and t:
                out["new_visibility_tag"] = t.strip().lower()
        new_role = details.get("new_role")
        if isinstance(new_role, dict):
            t = new_role.get(".tag")
            if isinstance(t, str) and t:
                out["new_role_tag"] = t.strip().lower()
        elif isinstance(new_role, str) and new_role:
            out["new_role_tag"] = new_role.strip().lower()
        nva = details.get("new_admin_role")
        if isinstance(nva, dict):
            t = nva.get(".tag")
            if isinstance(t, str) and t:
                out["new_admin_role_tag"] = t.strip().lower()
        elif isinstance(nva, str) and nva:
            out["new_admin_role_tag"] = nva.strip().lower()
        app = details.get("app") or {}
        if isinstance(app, dict):
            app_id = (
                app.get("app_id")
                if isinstance(app.get("app_id"), str)
                else None
            )
            display_name = (
                app.get("display_name")
                if isinstance(app.get("display_name"), str)
                else None
            )
            out["app_id_last8"] = _truncate_id(app_id)
            out["app_display_name_length"] = (
                len(display_name) if display_name else None
            )
        return out

    # -- Result building ---------------------------------------------------

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[Any]:
        """Build per-event EvaluationResults plus synthetic pattern findings."""
        download_events: dict[str, list[datetime]] = {}
        team_folder_events: dict[str, list[tuple[datetime, str]]] = {}
        external_share_events: dict[str, list[tuple[datetime, str]]] = {}

        for event in events:
            actor = self._extract_actor(event)
            actor_key = actor.get("raw_account_id") or actor.get(
                "raw_team_member_id"
            )
            if not actor_key:
                continue
            event_dt = _parse_iso_timestamp(event.get("timestamp"))
            if event_dt is None:
                continue
            ev_tag = self._extract_event_type_tag(event)
            if ev_tag == "file_download":
                download_events.setdefault(actor_key, []).append(event_dt)
            assets = self._extract_assets(event)
            for a in assets:
                if a.get("tag") == "folder" and a.get("file_id_last8"):
                    team_folder_events.setdefault(actor_key, []).append(
                        (event_dt, a["file_id_last8"])
                    )
            if ev_tag in {
                "file_share",
                "shared_link_create",
                "paper_doc_share",
            }:
                domains = self._extract_participant_domains(event)
                primary = self.primary_workspace_domain
                actor_domain = actor.get("email_domain")
                for d in domains:
                    if not d:
                        continue
                    if primary is not None and d == primary:
                        continue
                    if (
                        primary is None
                        and actor_domain is not None
                        and d == actor_domain
                    ):
                        continue
                    external_share_events.setdefault(actor_key, []).append(
                        (event_dt, d)
                    )

        bulk_download_actors: dict[str, int] = {}
        win_dl = timedelta(seconds=self.bulk_download_window_seconds)
        for actor_id, ts_list in download_events.items():
            if len(ts_list) <= self.bulk_download_threshold:
                continue
            sorted_ts = sorted(ts_list)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while sorted_ts[right] - sorted_ts[left] > win_dl:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.bulk_download_threshold:
                bulk_download_actors[actor_id] = max_in_window

        cross_team_folder_actors: dict[str, int] = {}
        win_tf = timedelta(seconds=self.cross_team_folder_window_seconds)
        for actor_id, pairs in team_folder_events.items():
            sorted_pairs = sorted(pairs, key=lambda p: p[0])
            left = 0
            distinct_count: dict[str, int] = {}
            max_distinct = 0
            for right in range(len(sorted_pairs)):
                _, fid_r = sorted_pairs[right]
                distinct_count[fid_r] = distinct_count.get(fid_r, 0) + 1
                while sorted_pairs[right][0] - sorted_pairs[left][0] > win_tf:
                    _, fid_l = sorted_pairs[left]
                    distinct_count[fid_l] -= 1
                    if distinct_count[fid_l] == 0:
                        del distinct_count[fid_l]
                    left += 1
                cur = len(distinct_count)
                if cur > max_distinct:
                    max_distinct = cur
            if max_distinct > self.cross_team_folder_threshold:
                cross_team_folder_actors[actor_id] = max_distinct

        external_recipient_actors: dict[str, int] = {}
        win_er = timedelta(seconds=self.external_recipient_window_seconds)
        for actor_id, pairs in external_share_events.items():
            sorted_pairs = sorted(pairs, key=lambda p: p[0])
            left = 0
            distinct_count: dict[str, int] = {}
            max_distinct = 0
            for right in range(len(sorted_pairs)):
                _, dom_r = sorted_pairs[right]
                distinct_count[dom_r] = distinct_count.get(dom_r, 0) + 1
                while sorted_pairs[right][0] - sorted_pairs[left][0] > win_er:
                    _, dom_l = sorted_pairs[left]
                    distinct_count[dom_l] -= 1
                    if distinct_count[dom_l] == 0:
                        del distinct_count[dom_l]
                    left += 1
                cur = len(distinct_count)
                if cur > max_distinct:
                    max_distinct = cur
            if max_distinct > self.external_recipient_threshold:
                external_recipient_actors[actor_id] = max_distinct

        results: list[Any] = []
        for event in events:
            r = self._parse_event(
                event,
                file_sha256=file_sha256,
                bulk_download_actors=bulk_download_actors,
                cross_team_folder_actors=cross_team_folder_actors,
                external_recipient_actors=external_recipient_actors,
            )
            if r is not None:
                results.append(r)

        for actor_id, count in sorted(bulk_download_actors.items()):
            results.append(
                self._synthetic_bulk_download_result(
                    actor=actor_id, count=count, file_sha256=file_sha256
                )
            )
        for actor_id, count in sorted(cross_team_folder_actors.items()):
            results.append(
                self._synthetic_cross_team_folder_result(
                    actor=actor_id, count=count, file_sha256=file_sha256
                )
            )
        for actor_id, count in sorted(external_recipient_actors.items()):
            results.append(
                self._synthetic_external_recipient_result(
                    actor=actor_id, count=count, file_sha256=file_sha256
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
        cross_team_folder_actors: dict[str, int],
        external_recipient_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        event_id_raw = (
            str(event.get("event_id"))
            if isinstance(event.get("event_id"), str)
            and event.get("event_id")
            else None
        )
        event_id = event_id_raw if event_id_raw else str(uuid.uuid4())

        ev_tag = self._extract_event_type_tag(event)
        timestamp_iso = _format_timestamp(event.get("timestamp"))

        actor = self._extract_actor(event)
        assets = self._extract_assets(event)
        participant_domains = self._extract_participant_domains(event)
        origin = self._extract_origin(event)
        details = self._extract_details(event)

        primary_domain = self.primary_workspace_domain
        actor_domain = actor.get("email_domain")
        external_domains: list[str] = []
        for d in participant_domains:
            if not d:
                continue
            if primary_domain is not None and d == primary_domain:
                continue
            if (
                primary_domain is None
                and actor_domain is not None
                and d == actor_domain
            ):
                continue
            external_domains.append(d)

        is_agent = (
            actor.get("tag") in self.agent_actor_tags
            if actor.get("tag")
            else False
        )
        sensitive_extension_present = any(
            (a.get("file_extension") in self.sensitive_extensions)
            for a in assets
            if a.get("file_extension")
        )

        common_evidence: dict[str, Any] = {
            "dropbox_event_id": event_id,
            "event_type_tag": ev_tag,
            "actor_tag": actor.get("tag"),
            "actor_email_domain": actor.get("email_domain"),
            "actor_team_member_id_last8": actor.get("team_member_id_last8"),
            "actor_account_id_last8": actor.get("account_id_last8"),
            "actor_display_name_length": actor.get("display_name_length"),
            "asset_count": len(assets),
            "asset_tags": [a.get("tag") for a in assets],
            "asset_file_extensions": [
                a.get("file_extension")
                for a in assets
                if a.get("file_extension")
            ],
            "asset_file_sizes": [
                a.get("file_size")
                for a in assets
                if a.get("file_size") is not None
            ],
            "asset_sensitivity_labels": [
                a.get("sensitivity_label")
                for a in assets
                if a.get("sensitivity_label")
            ],
            "asset_file_ids_last8": [
                a.get("file_id_last8")
                for a in assets
                if a.get("file_id_last8")
            ],
            "asset_path_lengths": [
                a.get("path_length")
                for a in assets
                if a.get("path_length") is not None
            ],
            "asset_display_name_lengths": [
                a.get("display_name_length")
                for a in assets
                if a.get("display_name_length") is not None
            ],
            "participant_domains": list(participant_domains),
            "external_recipient_domains": list(external_domains),
            "origin_country": origin.get("country"),
            "origin_ip_redacted": origin.get("ip_address_redacted"),
            "origin_access_method_tag": origin.get("access_method_tag"),
            "shared_link_audience_tag": details.get("shared_link_audience_tag"),
            "shared_link_id_last8": details.get("shared_link_id_last8"),
            "shared_link_owner_email_domain": details.get(
                "shared_link_owner_email_domain"
            ),
            "new_value_tag": details.get("new_value_tag"),
            "previous_value_tag": details.get("previous_value_tag"),
            "new_visibility_tag": details.get("new_visibility_tag"),
            "new_role_tag": details.get("new_role_tag"),
            "new_admin_role_tag": details.get("new_admin_role_tag"),
            "app_id_last8": details.get("app_id_last8"),
            "app_display_name_length": details.get("app_display_name_length"),
            "event_time": timestamp_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "dropbox",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # event_type-driven primary classification
        # ----------------------------------------------------------------
        if ev_tag in {"file_preview", "file_download"}:
            if (
                ev_tag == "file_download"
                and is_agent
                and sensitive_extension_present
            ):
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
                            f"actor.tag={actor.get('tag')!r} on sensitive "
                            f"extension(s) "
                            f"{common_evidence['asset_file_extensions']!r} "
                            f"— agent bulk-data exfil risk"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                large_size: int | None = None
                for a in assets:
                    fs = a.get("file_size")
                    if (
                        isinstance(fs, int)
                        and fs > self.large_file_threshold
                    ):
                        large_size = fs
                        break
                if ev_tag == "file_download" and large_size is not None:
                    signal = "large_download"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(
                                control_id, control_id
                            ),
                            result="FLAG",
                            detail=(
                                f"Dropbox event {event_id} file_download "
                                f"size={large_size}B exceeds threshold "
                                f"{self.large_file_threshold}B — large "
                                f"download"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "large_file_threshold":
                                    self.large_file_threshold,
                            },
                        )
                    )
                else:
                    signal = (
                        "user_preview"
                        if ev_tag == "file_preview"
                        else "user_download"
                    )
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(
                                control_id, control_id
                            ),
                            result="PASS",
                            detail=(
                                f"Dropbox event {event_id} {ev_tag} by "
                                f"actor.tag={actor.get('tag')!r} — "
                                f"read-access audit-trail captured"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                            },
                        )
                    )
        elif ev_tag == "shared_link_create":
            audience = details.get("shared_link_audience_tag")
            if audience in self.public_audiences:
                signal = "public_share_create"
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
                            f"audience={audience!r} — public link, "
                            f"top-priority exfil"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif audience in self.password_audiences:
                signal = "password_share_create"
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
                            f"audience={audience!r} — password-protected "
                            f"external link"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif external_domains:
                signal = "external_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} shared_link_create to "
                            f"external domain(s) {external_domains!r} — "
                            f"external share"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_tag == "shared_link_change_visibility":
            new_vis = details.get("new_visibility_tag") or details.get(
                "new_value_tag"
            )
            if new_vis in self.public_audiences:
                signal = "public_share_visibility_change"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} "
                            f"shared_link_change_visibility new_visibility="
                            f"{new_vis!r} — link expanded to public"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_tag == "shared_link_settings_allow_download_disabled":
            new_val = details.get("new_value_tag")
            signal = "share_allow_download_enabled"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} "
                        f"shared_link_settings_allow_download_disabled "
                        f"new_value={new_val!r} — allow-download setting "
                        f"changed on shared link"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "shared_link_disable":
            signal = "shared_link_disable"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} shared_link_disable — "
                        f"link revoked, audit captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "file_share":
            confidential_external = bool(external_domains) and any(
                a.get("sensitivity_label") == "confidential" for a in assets
            )
            if confidential_external:
                signal = "confidential_external_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} file_share with "
                            f"sensitivity_label=confidential to external "
                            f"domain(s) {external_domains!r} — top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif external_domains:
                signal = "external_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} file_share to "
                            f"external domain(s) {external_domains!r} — "
                            f"external share"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_tag == "team_folder_permanently_delete":
            signal = "team_folder_permanently_delete"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} "
                        f"team_folder_permanently_delete by "
                        f"actor.tag={actor.get('tag')!r} — irreversible "
                        f"team-folder destruction"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "member_change_admin_role":
            new_role = (
                details.get("new_admin_role_tag")
                or details.get("new_role_tag")
                or details.get("new_value_tag")
            )
            if new_role and new_role in self.privileged_admin_roles:
                signal = "admin_promotion"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Dropbox event {event_id} "
                            f"member_change_admin_role new_role={new_role!r} "
                            f"— admin promotion, top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_tag == "app_link":
            signal = "app_link"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} app_link — external app "
                        f"linked to team account"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "sso_change_settings":
            signal = "sso_change"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} sso_change_settings — "
                        f"SSO/auth surface change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "two_step_verification_disable":
            signal = "two_factor_disable"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} "
                        f"two_step_verification_disable — MFA degradation, "
                        f"top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "data_residency_migration":
            signal = "data_residency_change"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} data_residency_migration "
                        f"— GDPR-relevant data location change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "emm_create_exceptions_report":
            signal = "emm_exception_report"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} "
                        f"emm_create_exceptions_report — EMM/MDM exception "
                        f"list generated"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_tag == "paper_doc_share":
            if external_domains:
                signal = "paper_doc_external_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} paper_doc_share to "
                            f"external domain(s) {external_domains!r} — "
                            f"Paper-doc sharing"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_tag == "file_request_create":
            signal = "file_request_create"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} file_request_create — "
                        f"public file-request URL = inbound exfil channel"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Cross-cutting: access_method-driven flags
        # ----------------------------------------------------------------
        am = origin.get("access_method_tag")
        if (
            am == "admin_console"
            and ev_tag in {"file_preview", "file_download"}
        ):
            signal = "admin_console_read"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} access_method=admin_console "
                        f"on routine {ev_tag} — over-privileged access"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        if am == "sign_in_as":
            signal = "sign_in_as"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} access_method=sign_in_as — "
                        f"admin impersonation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        if am == "api" and is_agent:
            signal = "api_app_call"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Dropbox event {event_id} access_method=api by "
                        f"actor.tag={actor.get('tag')!r} — programmatic flow "
                        f"captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # Agent acting on sensitive extension outside of file_download path.
        if (
            is_agent
            and sensitive_extension_present
            and ev_tag is not None
            and ev_tag != "file_download"
        ):
            already_sensitive = any(
                cr.evidence_data.get("signal") == "agent_sensitive_download"
                for cr in control_results
            )
            if not already_sensitive:
                signal = "agent_sensitive_event"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Dropbox event {event_id} {ev_tag} by "
                            f"actor.tag={actor.get('tag')!r} on sensitive "
                            f"extension(s) "
                            f"{common_evidence['asset_file_extensions']!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # Synthetic pattern markers — informational on contributing events.
        # ----------------------------------------------------------------
        actor_key = actor.get("raw_account_id") or actor.get(
            "raw_team_member_id"
        )
        if actor_key and actor_key in bulk_download_actors:
            signal = "bulk_download_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            actor_id_last8 = (
                actor.get("account_id_last8")
                or actor.get("team_member_id_last8")
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Dropbox event {event_id} actor_id_last8="
                        f"{actor_id_last8} is part of a bulk-download "
                        f"pattern ({bulk_download_actors[actor_key]} "
                        f"downloads > threshold "
                        f"{self.bulk_download_threshold} in "
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
        if actor_key and actor_key in cross_team_folder_actors:
            signal = "cross_team_folder_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            actor_id_last8 = (
                actor.get("account_id_last8")
                or actor.get("team_member_id_last8")
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} actor_id_last8="
                        f"{actor_id_last8} is part of a cross-team-folder "
                        f"pattern ({cross_team_folder_actors[actor_key]} "
                        f"distinct folders > threshold "
                        f"{self.cross_team_folder_threshold} in "
                        f"{self.cross_team_folder_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_team_folder_count":
                            cross_team_folder_actors[actor_key],
                        "cross_team_folder_threshold":
                            self.cross_team_folder_threshold,
                        "cross_team_folder_window_seconds":
                            self.cross_team_folder_window_seconds,
                    },
                )
            )
        if actor_key and actor_key in external_recipient_actors:
            signal = "external_recipient_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            actor_id_last8 = (
                actor.get("account_id_last8")
                or actor.get("team_member_id_last8")
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Dropbox event {event_id} actor_id_last8="
                        f"{actor_id_last8} is part of an external-recipient "
                        f"pattern ({external_recipient_actors[actor_key]} "
                        f"distinct external domains > threshold "
                        f"{self.external_recipient_threshold} in "
                        f"{self.external_recipient_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "external_recipient_count":
                            external_recipient_actors[actor_key],
                        "external_recipient_threshold":
                            self.external_recipient_threshold,
                        "external_recipient_window_seconds":
                            self.external_recipient_window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------
        # No-match fallback
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
                        f"Dropbox event {event_id} event_type={ev_tag!r} "
                        f"actor.tag={actor.get('tag')!r} — audit-trail "
                        f"captured"
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
            f"Imported from Dropbox team-activity log: event_type="
            f"{ev_tag or 'unknown'} actor.tag={actor.get('tag') or 'unknown'} "
            f"actor_domain={actor.get('email_domain') or 'unknown'} "
            f"audience={details.get('shared_link_audience_tag') or 'n/a'}"
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
            session_id=event_id_raw,
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
        actor_id_last8 = _truncate_id(actor) or actor
        evidence: dict[str, Any] = {
            "dropbox_event_id": synthetic_id,
            "actor_id_last8": actor_id_last8,
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
                f"Dropbox synthetic finding: actor_id_last8={actor_id_last8} "
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
                f"Imported from Dropbox team-activity log: synthetic bulk-"
                f"download pattern for actor_id_last8={actor_id_last8} "
                f"count={count}>threshold={self.bulk_download_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_team_folder_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_team_folder_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"dropbox-cross-team-folder-{uuid.uuid4()}"
        actor_id_last8 = _truncate_id(actor) or actor
        evidence: dict[str, Any] = {
            "dropbox_event_id": synthetic_id,
            "actor_id_last8": actor_id_last8,
            "cross_team_folder_count": count,
            "cross_team_folder_threshold": self.cross_team_folder_threshold,
            "cross_team_folder_window_seconds":
                self.cross_team_folder_window_seconds,
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
                f"Dropbox synthetic finding: actor_id_last8={actor_id_last8} "
                f"touched {count} distinct team-folders in a "
                f"{self.cross_team_folder_window_seconds}s window — exceeds "
                f"cross-team-folder threshold "
                f"{self.cross_team_folder_threshold} (recon pattern)"
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
                f"Imported from Dropbox team-activity log: synthetic cross-"
                f"team-folder pattern for actor_id_last8={actor_id_last8} "
                f"count={count}>threshold={self.cross_team_folder_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_external_recipient_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "external_recipient_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"dropbox-external-recipient-{uuid.uuid4()}"
        actor_id_last8 = _truncate_id(actor) or actor
        evidence: dict[str, Any] = {
            "dropbox_event_id": synthetic_id,
            "actor_id_last8": actor_id_last8,
            "external_recipient_count": count,
            "external_recipient_threshold": self.external_recipient_threshold,
            "external_recipient_window_seconds":
                self.external_recipient_window_seconds,
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
                f"Dropbox synthetic finding: actor_id_last8={actor_id_last8} "
                f"shared with {count} distinct external domains in a "
                f"{self.external_recipient_window_seconds}s window — exceeds "
                f"external-recipient threshold "
                f"{self.external_recipient_threshold} (mass-share pattern)"
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
                f"Imported from Dropbox team-activity log: synthetic external-"
                f"recipient pattern for actor_id_last8={actor_id_last8} "
                f"count={count}>threshold={self.external_recipient_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
