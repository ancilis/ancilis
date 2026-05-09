"""Box admin-events importer — maps Box content-platform activity to AKSI controls.

Box (https://box.com) is the leading enterprise content management platform —
heavily used in regulated industries (healthcare, finance, legal) where file-
storage governance, retention, watermarking, DLP, and anomaly detection are
non-negotiable. Agents increasingly read, write, share, and collaborate inside
Box at scale: RAG corpora, generated reports, intermediate artifacts, customer-
facing deliverables. Box's ``/2.0/events?stream_type=admin_logs`` feed captures
the data-loss-prevention signals that gate enterprise content: previews,
downloads, uploads, deletions, sharing transitions (link access, expiration),
collaboration invites, role changes, malware tagging, DLP rule hits, watermark
labels, Box Shield anomaly alerts, device-trust failures, and login events.

This importer ingests Box admin-events JSON exports in three on-disk shapes:

  1. ``{"entries": [...]}`` — Box admin-events envelope
  2. ``{"data":    [...]}`` — generic data envelope
  3. JSONL                  — one entry per line

Each entry is materialized as its own ``EvaluationResult``.

Signal mapping (see shared/mappings/box-aksi-controls.json):
  * ``PREVIEW``                                                       → PR-04 PASS
  * ``DOWNLOAD`` by service_account/app on sensitive extension        → PR-04 FAIL
  * ``DOWNLOAD`` size_bytes > threshold (default 1GB)                 → PR-04 FLAG
  * ``UPLOAD``  by service_account                                    → PR-04 PASS
  * ``DELETE``  by service_account                                    → PR-02 FLAG
  * ``SHARE`` shared_link.access=open + is_password_enabled=false     → DE-01 FAIL
  * ``SHARE`` shared_link.access=open + is_password_enabled=true      → PR-04 FLAG
  * ``SHARE_EXPIRATION`` extending or removing expiration             → PR-04 FLAG
  * ``COLLABORATION_INVITE`` external (target_domain != actor_domain) → PR-04 FLAG
  * ``COLLABORATION_ROLE_CHANGE`` new_role in privileged set          → PR-02 FLAG
  * ``FILE_MARKED_MALICIOUS``                                         → DE-01 FAIL
  * ``DLP_VIOLATION``                                                 → PR-04 FAIL
  * ``WATERMARK_LABEL_APPLY``                                         → PR-04 PASS
  * ``SHIELD_ALERT`` shield_alert_priority=high                       → DE-01 FAIL
  * ``SHIELD_ALERT`` shield_alert_priority=medium                     → PR-05 FLAG
  * ``DEVICE_TRUST_CHECK_FAILED``                                     → PR-01 FLAG
  * ``FAILED_LOGIN``                                                  → PR-01 FLAG
  * ``GROUP_ADD_USER`` to admin/security group                        → PR-02 FLAG
  * Bulk-download pattern: same actor_user_id with > N downloads in
    1h (default 30)                                                   → PR-04 FAIL
  * Cross-folder traversal pattern: same actor accessing > N distinct
    folders in 1h (default 100)                                       → PR-04 FLAG

Sanitization (security-critical — Box admin-event records identify the items
themselves, the actor's email and login, the IP, and free-form parameters):
  * ``source.name`` is NEVER stored — only ``name_length`` + sha256.
  * ``source.item_id`` keeps only the trailing 8 characters.
  * ``folder_id`` keeps only the trailing 8 characters.
  * ``actor_user_email`` is reduced to ``@domain`` only — never the local-part.
  * ``actor_user_login`` is NEVER stored verbatim — length + sha256 only.
  * ``accessible_by.id`` / ``accessible_by.login`` are reduced to domain only.
  * ``ip_address`` is masked to /16 (IPv4) or /32-hextet (IPv6); private /
    loopback / link-local addresses are preserved verbatim.
  * ``additional_details``: well-known keys (``reason``, ``new_role``,
    ``previous_role``, ``shared_link_id``, ``dlp_policy_name``,
    ``watermark_label``, ``shield_alert_priority``, ``shield_alert_type``)
    are kept verbatim; everything else is reduced to ``key + sha256`` of the
    stringified value.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``boxsdk``; admin-event JSON exports are parsed
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
#   <repo>/python/src/ancilis/importers/box.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "box-aksi-controls.json"
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
_DEFAULT_BULK_DOWNLOAD_THRESHOLD = 30
_DEFAULT_BULK_DOWNLOAD_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_FOLDER_TRAVERSAL_THRESHOLD = 100
_DEFAULT_CROSS_FOLDER_TRAVERSAL_WINDOW_SECONDS = 3600

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
_DEFAULT_PRIVILEGED_ROLE_SET: frozenset[str] = frozenset(
    {"co-owner", "editor", "owner"}
)
_DEFAULT_PRIVILEGED_GROUP_TOKENS: frozenset[str] = frozenset(
    {"admin", "administrators", "security-admin"}
)

# Box actor types that signal non-human / agent activity.
_AGENT_ACTOR_TYPES: frozenset[str] = frozenset({"service_account", "app"})

# Well-known additional_details keys that are safe to retain verbatim.
_WELL_KNOWN_DETAIL_KEYS: frozenset[str] = frozenset(
    {
        "reason",
        "new_role",
        "previous_role",
        "shared_link_id",
        "dlp_policy_name",
        "watermark_label",
        "shield_alert_priority",
        "shield_alert_type",
    }
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load box-aksi-controls.json; tolerate a missing/invalid file."""
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
    """Keep only the trailing 8 characters of a Box id."""
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


def _redact_additional_details(details: Any) -> dict[str, Any] | None:
    """Sanitize additional_details — keep well-known keys verbatim, hash others."""
    if not isinstance(details, dict):
        return None
    out: dict[str, Any] = {}
    for k, v in details.items():
        key = str(k)
        if key in _WELL_KNOWN_DETAIL_KEYS:
            out[key] = v
        else:
            try:
                stringified = (
                    v if isinstance(v, str) else json.dumps(v, sort_keys=True)
                )
            except (TypeError, ValueError):
                stringified = repr(v)
            digest = hashlib.sha256(stringified.encode("utf-8")).hexdigest()
            out[key] = {"length": len(stringified), "sha256": digest}
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class BoxImporter:
    """Parse a Box admin-events export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_file_threshold: int | None = None,
        bulk_download_threshold: int | None = None,
        bulk_download_window_seconds: int | None = None,
        cross_folder_traversal_threshold: int | None = None,
        cross_folder_traversal_window_seconds: int | None = None,
        sensitive_extensions: Iterable[str] | None = None,
        privileged_role_set: Iterable[str] | None = None,
        privileged_group_tokens: Iterable[str] | None = None,
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
            else meta.get("large_file_threshold", _DEFAULT_LARGE_FILE_THRESHOLD)
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
        self.cross_folder_traversal_threshold = int(
            cross_folder_traversal_threshold
            if cross_folder_traversal_threshold is not None
            else meta.get(
                "cross_folder_traversal_threshold",
                _DEFAULT_CROSS_FOLDER_TRAVERSAL_THRESHOLD,
            )
        )
        self.cross_folder_traversal_window_seconds = int(
            cross_folder_traversal_window_seconds
            if cross_folder_traversal_window_seconds is not None
            else meta.get(
                "cross_folder_traversal_window_seconds",
                _DEFAULT_CROSS_FOLDER_TRAVERSAL_WINDOW_SECONDS,
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
        if privileged_role_set is not None:
            self.privileged_role_set: frozenset[str] = frozenset(
                str(r).strip().lower() for r in privileged_role_set if r
            )
        else:
            meta_roles = meta.get("privileged_role_set")
            if isinstance(meta_roles, list) and meta_roles:
                self.privileged_role_set = frozenset(
                    str(r).strip().lower() for r in meta_roles if r
                )
            else:
                self.privileged_role_set = _DEFAULT_PRIVILEGED_ROLE_SET
        if privileged_group_tokens is not None:
            self.privileged_group_tokens: frozenset[str] = frozenset(
                str(g).strip().lower() for g in privileged_group_tokens if g
            )
        else:
            meta_groups = meta.get("privileged_groups")
            if isinstance(meta_groups, list) and meta_groups:
                self.privileged_group_tokens = frozenset(
                    str(g).strip().lower() for g in meta_groups if g
                )
            else:
                self.privileged_group_tokens = _DEFAULT_PRIVILEGED_GROUP_TOKENS
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
        """Parse a Box admin-events export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Box admin-events content from a string."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"entries": [...]}`` / ``{"data": [...]}`` / JSONL / single."""
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
                if "entries" in doc and isinstance(doc["entries"], list):
                    return [e for e in doc["entries"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[Any]:
        """Build per-entry EvaluationResults plus bulk-download and cross-folder synthetics."""
        download_events: dict[str, list[datetime]] = {}
        folder_events: dict[str, list[tuple[datetime, str]]] = {}

        for entry in entries:
            actor_user_id = (
                str(entry.get("actor_user_id"))
                if isinstance(entry.get("actor_user_id"), str)
                and entry.get("actor_user_id")
                else None
            )
            if not actor_user_id:
                continue
            event_dt = _parse_iso_timestamp(entry.get("created_at"))
            if event_dt is None:
                continue
            ev_type = (
                str(entry.get("event_type") or "").strip().upper() or None
            )
            source = entry.get("source") or {}
            if not isinstance(source, dict):
                source = {}
            if ev_type == "DOWNLOAD":
                download_events.setdefault(actor_user_id, []).append(event_dt)
            folder_id = (
                str(source.get("folder_id"))
                if isinstance(source.get("folder_id"), str)
                and source.get("folder_id")
                else None
            )
            if folder_id:
                folder_events.setdefault(actor_user_id, []).append(
                    (event_dt, folder_id)
                )

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

        cross_folder_traversal_actors: dict[str, int] = {}
        window_fl = timedelta(seconds=self.cross_folder_traversal_window_seconds)
        for actor, pair_list in folder_events.items():
            if len(pair_list) <= self.cross_folder_traversal_threshold:
                # Quick reject when total entries can't possibly exceed threshold.
                # But distinct-folder count could still exceed if all distinct;
                # keep going only if size is large enough to matter.
                pass
            sorted_pairs = sorted(pair_list, key=lambda p: p[0])
            # Sliding window over time, tracking distinct folder ids in window.
            left = 0
            distinct_count: dict[str, int] = {}
            max_distinct = 0
            for right in range(len(sorted_pairs)):
                ts_r, fid_r = sorted_pairs[right]
                distinct_count[fid_r] = distinct_count.get(fid_r, 0) + 1
                while sorted_pairs[right][0] - sorted_pairs[left][0] > window_fl:
                    ts_l, fid_l = sorted_pairs[left]
                    distinct_count[fid_l] -= 1
                    if distinct_count[fid_l] == 0:
                        del distinct_count[fid_l]
                    left += 1
                cur_distinct = len(distinct_count)
                if cur_distinct > max_distinct:
                    max_distinct = cur_distinct
            if max_distinct > self.cross_folder_traversal_threshold:
                cross_folder_traversal_actors[actor] = max_distinct

        results: list[Any] = []
        for entry in entries:
            result = self._parse_entry(
                entry,
                file_sha256=file_sha256,
                bulk_download_actors=bulk_download_actors,
                cross_folder_traversal_actors=cross_folder_traversal_actors,
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
        for actor, count in sorted(cross_folder_traversal_actors.items()):
            results.append(
                self._synthetic_cross_folder_traversal_result(
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
            "source_format": "box_admin_events",
            "source_tool_name": "box",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-entry parsing — each entry becomes one EvaluationResult.
    # ------------------------------------------------------------------

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        bulk_download_actors: dict[str, int],
        cross_folder_traversal_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        event_id_raw = (
            str(entry.get("event_id"))
            if isinstance(entry.get("event_id"), str)
            and entry.get("event_id")
            else None
        )
        event_id = event_id_raw if event_id_raw else str(uuid.uuid4())

        ev_type = (
            str(entry.get("event_type") or "").strip().upper() or None
        )
        timestamp_iso = _format_timestamp(entry.get("created_at"))

        # --- Source object ------------------------------------------------
        source = entry.get("source") or {}
        if not isinstance(source, dict):
            source = {}
        source_item_type = (
            str(source.get("item_type")).strip().lower()
            if isinstance(source.get("item_type"), str)
            and source.get("item_type")
            else None
        )
        source_item_id_last8 = _truncate_id(
            source.get("item_id")
            if isinstance(source.get("item_id"), str)
            else None
        )
        source_folder_id_last8 = _truncate_id(
            source.get("folder_id")
            if isinstance(source.get("folder_id"), str)
            else None
        )
        source_extension = (
            str(source.get("extension")).strip().lower().lstrip(".")
            if isinstance(source.get("extension"), str)
            and source.get("extension")
            else None
        )
        source_size_bytes_raw = source.get("size_bytes")
        source_size_bytes: int | None = (
            int(source_size_bytes_raw)
            if isinstance(source_size_bytes_raw, (int, float))
            and not isinstance(source_size_bytes_raw, bool)
            else None
        )
        # Item-name is NEVER stored — only length + sha256 (if present).
        source_name_raw = (
            source.get("name")
            if isinstance(source.get("name"), str)
            else None
        )
        source_name_length_raw = source.get("name_length")
        if source_name_raw:
            source_name_redacted = _redact_string_value(source_name_raw)
        elif (
            isinstance(source_name_length_raw, (int, float))
            and not isinstance(source_name_length_raw, bool)
        ):
            source_name_redacted = {
                "length": int(source_name_length_raw),
                "sha256": None,
            }
        else:
            source_name_redacted = None

        shared_link = source.get("shared_link") or {}
        if not isinstance(shared_link, dict):
            shared_link = {}
        shared_link_access = (
            str(shared_link.get("access")).strip().lower()
            if isinstance(shared_link.get("access"), str)
            and shared_link.get("access")
            else None
        )
        shared_link_password_enabled_raw = shared_link.get("is_password_enabled")
        shared_link_password_enabled: bool | None = (
            bool(shared_link_password_enabled_raw)
            if isinstance(shared_link_password_enabled_raw, bool)
            else None
        )
        shared_link_effective_access = (
            str(shared_link.get("effective_access")).strip().lower()
            if isinstance(shared_link.get("effective_access"), str)
            and shared_link.get("effective_access")
            else None
        )

        # --- Actor --------------------------------------------------------
        actor_user_id_raw = (
            str(entry.get("actor_user_id"))
            if isinstance(entry.get("actor_user_id"), str)
            and entry.get("actor_user_id")
            else None
        )
        actor_user_id_last8 = _truncate_id(actor_user_id_raw)
        actor_user_email_raw = (
            entry.get("actor_user_email")
            if isinstance(entry.get("actor_user_email"), str)
            else None
        )
        actor_user_email_domain = _redact_email(actor_user_email_raw)
        actor_user_login_redacted = _redact_string_value(
            entry.get("actor_user_login")
            if isinstance(entry.get("actor_user_login"), str)
            else None
        )
        actor_type = (
            str(entry.get("actor_type")).strip().lower()
            if isinstance(entry.get("actor_type"), str)
            and entry.get("actor_type")
            else None
        )
        ip_address_redacted = _classify_ip(
            entry.get("ip_address")
            if isinstance(entry.get("ip_address"), str)
            else None
        )

        # --- accessible_by ------------------------------------------------
        accessible_by = entry.get("accessible_by") or {}
        if not isinstance(accessible_by, dict):
            accessible_by = {}
        accessible_by_type = (
            str(accessible_by.get("type")).strip().lower()
            if isinstance(accessible_by.get("type"), str)
            and accessible_by.get("type")
            else None
        )
        accessible_by_id_last8 = _truncate_id(
            accessible_by.get("id")
            if isinstance(accessible_by.get("id"), str)
            else None
        )
        accessible_by_login_email_domain = _normalize_email_domain(
            accessible_by.get("login_email_domain")
            if isinstance(accessible_by.get("login_email_domain"), str)
            else None
        )
        if accessible_by_login_email_domain is None:
            accessible_by_login_raw = (
                accessible_by.get("login")
                if isinstance(accessible_by.get("login"), str)
                else None
            )
            accessible_by_login_email_domain = _redact_email(
                accessible_by_login_raw
            )

        # --- additional_details ------------------------------------------
        additional_details_redacted = _redact_additional_details(
            entry.get("additional_details")
        )
        new_role: str | None = None
        previous_role: str | None = None
        dlp_policy_name: str | None = None
        watermark_label: str | None = None
        shield_alert_priority: str | None = None
        shield_alert_type: str | None = None
        if isinstance(additional_details_redacted, dict):
            nr = additional_details_redacted.get("new_role")
            if isinstance(nr, str) and nr:
                new_role = nr.strip().lower()
            pr_v = additional_details_redacted.get("previous_role")
            if isinstance(pr_v, str) and pr_v:
                previous_role = pr_v.strip().lower()
            dn = additional_details_redacted.get("dlp_policy_name")
            if isinstance(dn, str) and dn:
                dlp_policy_name = dn
            wl = additional_details_redacted.get("watermark_label")
            if isinstance(wl, str) and wl:
                watermark_label = wl
            sap = additional_details_redacted.get("shield_alert_priority")
            if isinstance(sap, str) and sap:
                shield_alert_priority = sap.strip().lower()
            sat = additional_details_redacted.get("shield_alert_type")
            if isinstance(sat, str) and sat:
                shield_alert_type = sat.strip().lower()

        common_evidence: dict[str, Any] = {
            "box_event_id": event_id,
            "event_type": ev_type,
            "source_item_type": source_item_type,
            "source_item_id_last8": source_item_id_last8,
            "source_folder_id_last8": source_folder_id_last8,
            "source_extension": source_extension,
            "source_size_bytes": source_size_bytes,
            "source_name_redacted": source_name_redacted,
            "shared_link_access": shared_link_access,
            "shared_link_is_password_enabled": shared_link_password_enabled,
            "shared_link_effective_access": shared_link_effective_access,
            "actor_user_id_last8": actor_user_id_last8,
            "actor_user_email_domain": actor_user_email_domain,
            "actor_user_login_redacted": actor_user_login_redacted,
            "actor_type": actor_type,
            "accessible_by_type": accessible_by_type,
            "accessible_by_id_last8": accessible_by_id_last8,
            "accessible_by_login_email_domain":
                accessible_by_login_email_domain,
            "additional_details_redacted": additional_details_redacted,
            "new_role": new_role,
            "previous_role": previous_role,
            "dlp_policy_name": dlp_policy_name,
            "watermark_label": watermark_label,
            "shield_alert_priority": shield_alert_priority,
            "shield_alert_type": shield_alert_type,
            "ip_address_redacted": ip_address_redacted,
            "event_time": timestamp_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "box",
        }

        control_results: list[ControlResult] = []
        is_agent_actor = actor_type in _AGENT_ACTOR_TYPES

        # ----------------------------------------------------------------
        # event_type-driven primary classification
        # ----------------------------------------------------------------
        if ev_type == "PREVIEW":
            signal = "preview_event"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Box event {event_id} PREVIEW on item="
                        f"{source_item_id_last8 or 'unknown'} — read-access "
                        f"audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "DOWNLOAD":
            agent_sensitive = (
                is_agent_actor
                and source_extension is not None
                and source_extension in self.sensitive_extensions
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
                            f"Box event {event_id} DOWNLOAD by "
                            f"actor_type={actor_type!r} on extension="
                            f"{source_extension!r} item="
                            f"{source_item_id_last8 or 'unknown'} — agent "
                            f"downloading bulk-data file, requires review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            if (
                source_size_bytes is not None
                and source_size_bytes > self.large_file_threshold
            ):
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
                            f"Box event {event_id} DOWNLOAD size="
                            f"{source_size_bytes}B exceeds threshold "
                            f"{self.large_file_threshold}B — large download"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "large_file_threshold": self.large_file_threshold,
                        },
                    )
                )
        elif ev_type == "UPLOAD":
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
                            f"Box event {event_id} UPLOAD by "
                            f"actor_type={actor_type!r} on item="
                            f"{source_item_id_last8 or 'unknown'} — "
                            f"service-account write captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "DELETE":
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
                            f"Box event {event_id} DELETE by "
                            f"actor_type={actor_type!r} on item="
                            f"{source_item_id_last8 or 'unknown'} — bot "
                            f"deleting content, requires review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "SHARE":
            if shared_link_access == "open":
                if shared_link_password_enabled is False:
                    signal = "public_unprotected_share"
                    control_id = _control_for(signal, self._mappings, "DE-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(
                                control_id, control_id
                            ),
                            result="FAIL",
                            detail=(
                                f"Box event {event_id} SHARE shared_link.access="
                                f"'open' is_password_enabled=false on item="
                                f"{source_item_id_last8 or 'unknown'} — public "
                                f"unprotected link, top-priority exfil"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                            },
                        )
                    )
                else:
                    signal = "public_protected_share"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(
                                control_id, control_id
                            ),
                            result="FLAG",
                            detail=(
                                f"Box event {event_id} SHARE shared_link.access="
                                f"'open' is_password_enabled=true on item="
                                f"{source_item_id_last8 or 'unknown'} — "
                                f"password-protected public link"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                            },
                        )
                    )
        elif ev_type == "SHARE_EXPIRATION":
            signal = "share_expiration_change"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Box event {event_id} SHARE_EXPIRATION on item="
                        f"{source_item_id_last8 or 'unknown'} — extending or "
                        f"removing expiration extends public-access window"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "COLLABORATION_INVITE":
            target_domain = accessible_by_login_email_domain
            actor_domain = actor_user_email_domain
            primary_domain = self.primary_workspace_domain
            external_vs_actor = (
                target_domain is not None
                and actor_domain is not None
                and target_domain != actor_domain
            )
            external_vs_primary = (
                primary_domain is not None
                and target_domain is not None
                and target_domain != primary_domain
            )
            if external_vs_actor or external_vs_primary:
                signal = "external_collaboration_invite"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Box event {event_id} COLLABORATION_INVITE to "
                            f"target_domain={target_domain!r} (actor_domain="
                            f"{actor_domain!r}, primary_domain="
                            f"{primary_domain!r}) on item="
                            f"{source_item_id_last8 or 'unknown'} — external "
                            f"invite"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "COLLABORATION_ROLE_CHANGE":
            if new_role and new_role in self.privileged_role_set:
                signal = "role_privilege_expansion"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Box event {event_id} COLLABORATION_ROLE_CHANGE "
                            f"new_role={new_role!r} previous_role="
                            f"{previous_role!r} on item="
                            f"{source_item_id_last8 or 'unknown'} — "
                            f"privilege expansion to elevated role"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "FILE_MARKED_MALICIOUS":
            signal = "file_marked_malicious"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Box event {event_id} FILE_MARKED_MALICIOUS on item="
                        f"{source_item_id_last8 or 'unknown'} — Box detected "
                        f"malware, top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "DLP_VIOLATION":
            signal = "dlp_violation"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Box event {event_id} DLP_VIOLATION policy="
                        f"{dlp_policy_name or 'unknown'} on item="
                        f"{source_item_id_last8 or 'unknown'} — DLP rule "
                        f"matched, top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "WATERMARK_LABEL_APPLY":
            signal = "watermark_label_apply"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Box event {event_id} WATERMARK_LABEL_APPLY label="
                        f"{watermark_label or 'unknown'} on item="
                        f"{source_item_id_last8 or 'unknown'} — governance "
                        f"applied"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "SHIELD_ALERT":
            if shield_alert_priority == "high":
                signal = "shield_alert_high"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"Box event {event_id} SHIELD_ALERT priority=high "
                            f"type={shield_alert_type or 'unknown'} on item="
                            f"{source_item_id_last8 or 'unknown'} — Box "
                            f"Shield anomaly detection, top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif shield_alert_priority == "medium":
                signal = "shield_alert_medium"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Box event {event_id} SHIELD_ALERT "
                            f"priority=medium type="
                            f"{shield_alert_type or 'unknown'} on item="
                            f"{source_item_id_last8 or 'unknown'} — Box "
                            f"Shield anomaly detection"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "DEVICE_TRUST_CHECK_FAILED":
            signal = "device_trust_failed"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Box event {event_id} DEVICE_TRUST_CHECK_FAILED "
                        f"actor_domain={actor_user_email_domain or 'unknown'} "
                        f"— untrusted device"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "FAILED_LOGIN":
            signal = "failed_login"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Box event {event_id} FAILED_LOGIN actor_domain="
                        f"{actor_user_email_domain or 'unknown'} — "
                        f"authentication failure"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "GROUP_ADD_USER":
            # Look for group-name-bearing fields in additional_details (the
            # raw value is hashed by _redact_additional_details, so we
            # peek at the original entry once).
            raw_details = entry.get("additional_details") or {}
            group_name = ""
            if isinstance(raw_details, dict):
                for k in ("group_name", "group", "target_group_name"):
                    v = raw_details.get(k)
                    if isinstance(v, str) and v:
                        group_name = v
                        break
            group_lower = group_name.lower()
            is_admin_group = any(
                tok in group_lower for tok in self.privileged_group_tokens
            )
            if is_admin_group:
                signal = "admin_group_add"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"Box event {event_id} GROUP_ADD_USER to admin "
                            f"group on actor_domain="
                            f"{actor_user_email_domain or 'unknown'} — "
                            f"privileged-group membership change"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # Synthetic pattern markers — informational on contributing events.
        # ----------------------------------------------------------------
        if (
            actor_user_id_raw
            and actor_user_id_raw in bulk_download_actors
        ):
            signal = "bulk_download_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Box event {event_id} actor_id_last8="
                        f"{actor_user_id_last8} is part of a bulk-download "
                        f"pattern ("
                        f"{bulk_download_actors[actor_user_id_raw]} "
                        f"downloads > threshold "
                        f"{self.bulk_download_threshold} in "
                        f"{self.bulk_download_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bulk_download_count":
                            bulk_download_actors[actor_user_id_raw],
                        "bulk_download_threshold":
                            self.bulk_download_threshold,
                        "bulk_download_window_seconds":
                            self.bulk_download_window_seconds,
                    },
                )
            )
        if (
            actor_user_id_raw
            and actor_user_id_raw in cross_folder_traversal_actors
        ):
            signal = "cross_folder_traversal_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Box event {event_id} actor_id_last8="
                        f"{actor_user_id_last8} is part of a cross-folder "
                        f"traversal pattern ("
                        f"{cross_folder_traversal_actors[actor_user_id_raw]} "
                        f"distinct folders > threshold "
                        f"{self.cross_folder_traversal_threshold} in "
                        f"{self.cross_folder_traversal_window_seconds}s "
                        f"window — recon pattern)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_folder_traversal_count":
                            cross_folder_traversal_actors[actor_user_id_raw],
                        "cross_folder_traversal_threshold":
                            self.cross_folder_traversal_threshold,
                        "cross_folder_traversal_window_seconds":
                            self.cross_folder_traversal_window_seconds,
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
                        f"Box event {event_id} event_type={ev_type!r} on "
                        f"item={source_item_id_last8 or 'unknown'} — "
                        f"audit-trail captured"
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
            f"Imported from Box admin-events log: event_type="
            f"{ev_type or 'unknown'} actor_type={actor_type or 'unknown'} "
            f"actor_domain={actor_user_email_domain or 'unknown'} item="
            f"{source_item_id_last8 or 'unknown'}"
        )

        action_id = f"box-{event_id[:48]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="box_import",
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
        synthetic_id = f"box-bulk-download-{uuid.uuid4()}"
        actor_id_last8 = _truncate_id(actor) or actor
        evidence: dict[str, Any] = {
            "box_event_id": synthetic_id,
            "actor_user_id_last8": actor_id_last8,
            "bulk_download_count": count,
            "bulk_download_threshold": self.bulk_download_threshold,
            "bulk_download_window_seconds": self.bulk_download_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "box",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Box synthetic finding: actor_id_last8={actor_id_last8} "
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
            source_type="box_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Box admin-events log: synthetic bulk-download "
                f"pattern for actor_id_last8={actor_id_last8} count={count}>"
                f"threshold={self.bulk_download_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_folder_traversal_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_folder_traversal_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"box-cross-folder-traversal-{uuid.uuid4()}"
        actor_id_last8 = _truncate_id(actor) or actor
        evidence: dict[str, Any] = {
            "box_event_id": synthetic_id,
            "actor_user_id_last8": actor_id_last8,
            "cross_folder_traversal_count": count,
            "cross_folder_traversal_threshold":
                self.cross_folder_traversal_threshold,
            "cross_folder_traversal_window_seconds":
                self.cross_folder_traversal_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "box",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Box synthetic finding: actor_id_last8={actor_id_last8} "
                f"accessed {count} distinct folders in a "
                f"{self.cross_folder_traversal_window_seconds}s window — "
                f"exceeds cross-folder traversal threshold "
                f"{self.cross_folder_traversal_threshold} (recon pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="box_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Box admin-events log: synthetic cross-folder "
                f"traversal pattern for actor_id_last8={actor_id_last8} "
                f"count={count}>threshold="
                f"{self.cross_folder_traversal_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
