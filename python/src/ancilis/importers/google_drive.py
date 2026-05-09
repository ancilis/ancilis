"""Google Drive audit-event importer — maps Drive activity to AKSI controls.

Google Drive (https://drive.google.com) is the dominant cloud file-storage
surface for businesses. Agents now read and write Drive files at scale — RAG
corpora, summaries, generated reports, intermediate artifacts — and Drive's
Admin SDK Reports ``/admin/reports/v1/activity/users/all/applications/drive``
feed captures the data-loss-prevention signals that today's evidence pipelines
rarely surface: sharing transitions, downloads, ACL changes, ownership
transfers, and permanent deletions. A service account silently downloading a
spreadsheet, an ACL flipping from ``private`` to ``public_on_the_web``, or a
file shared with a domain outside the org are workflow-altering events whose
absence from evidence makes incident response impossible.

This importer ingests Admin SDK Reports activity exports in three on-disk
shapes:

  1. ``{"items": [...]}`` — Reports API envelope (each item carries one or
     more events, all attributed to a single actor and time)
  2. ``{"data":  [...]}`` — generic data envelope
  3. JSONL                 — one item per line

Each event within an item is materialized as its own ``EvaluationResult`` —
items routinely carry multiple events (e.g. an ACL change with both an
``old_visibility`` parameter and a separate ``permission_change`` event).

Signal mapping (see shared/mappings/google-drive-aksi-controls.json):
  * ``access`` ``view`` / ``preview``                              → PR-04 PASS
  * ``access`` ``download``                                         → PR-04 FLAG
  * ``access`` ``download`` doc_type in {spreadsheet, document, pdf}
    + actor.callerType=APPLICATION_SERVICE_ACCOUNT                  → PR-04 FAIL
    (agent downloading documents — review)
  * ``access`` ``print``                                            → PR-04 FLAG
  * ``acl_change`` ``share_outside_domain``                         → DE-01 FAIL
  * ``acl_change`` visibility old=private new=public_on_the_web /
    people_with_link                                                → PR-04 FAIL
  * ``acl_change`` visibility old=private new=public_in_the_domain → PR-04 FLAG
  * ``acl_change`` ``change_acl_editors``                           → PR-02 FLAG
  * ``acl_change`` target_user_email_domain != actor's primary      → PR-04 FLAG
  * ``user_ownership`` ``ownership_change``                         → PR-02 FLAG
  * ``delete`` ``trash`` (soft delete)                              → PR-05 PASS
  * ``delete`` ``delete`` (permanent)                               → PR-02 FLAG
  * actor.callerType=USER_PUBLIC                                    → PR-01 FAIL
  * file_size_bytes > threshold (default 1GB) on download           → PR-04 FLAG
  * mime_type in restricted-mime list on download by service acct   → PR-04 FLAG
  * Bulk-export pattern: same actor downloads > N files in 1h
    (default N=50)                                                  → PR-04 FAIL
  * Cross-domain-share pattern: same actor shares > N files outside
    domain in 1h (default N=10)                                     → PR-04 FAIL

Sanitization (security-critical — Drive audit logs identify the documents
themselves and can carry user PII in actor / target emails / IPs / parameter
strings):
  * ``doc_id`` keeps only the trailing 8 characters (Drive IDs identify
    documents which are themselves sensitive — full IDs would let anyone
    with a Drive session correlate evidence rows back to live content).
  * ``doc_title`` is NEVER stored — Drive provides ``doc_title_length`` and
    that is the only title-bearing field captured.
  * ``actor.email``, ``target_user_email``, ``owner`` are reduced to
    ``@domain`` only.
  * ``old_value_string`` / ``new_value_string`` retain length + sha256 only.
  * ``ipAddress`` is masked to /16 (IPv4) or /32-hextet (IPv6); private /
    loopback / link-local addresses are preserved verbatim.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``google-api-python-client``; Reports activity
JSON exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch  # noqa: F401  # reserved for future mime-pattern globbing
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/google_drive.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "google-drive-aksi-controls.json"
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
_DEFAULT_CROSS_DOMAIN_SHARE_THRESHOLD = 10
_DEFAULT_CROSS_DOMAIN_SHARE_WINDOW_SECONDS = 3600
_DEFAULT_RESTRICTED_MIMES: frozenset[str] = frozenset(
    {
        "text/csv",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
        "application/x-sqlite3",
        "application/json",
        "application/x-tar",
        "application/zip",
    }
)
_DEFAULT_AGENT_DOWNLOAD_DOC_TYPES: frozenset[str] = frozenset(
    {"spreadsheet", "document", "pdf"}
)

_PUBLIC_VISIBILITIES: frozenset[str] = frozenset(
    {"public_on_the_web", "people_with_link"}
)
_DOMAIN_VISIBILITY = "public_in_the_domain"
_PRIVATE_VISIBILITY = "private"

_SERVICE_ACCOUNT_CALLERTYPE = "APPLICATION_SERVICE_ACCOUNT"
_USER_PUBLIC_CALLERTYPE = "USER_PUBLIC"


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load google-drive-aksi-controls.json; tolerate a missing/invalid file."""
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
    """Normalize a target_user_email_domain that may or may not be ``@``-prefixed."""
    if not domain or not isinstance(domain, str):
        return None
    d = domain.strip()
    if not d:
        return None
    if not d.startswith("@"):
        d = "@" + d
    return d.lower()


def _truncate_doc_id(doc_id: str | None) -> str | None:
    """Keep only the trailing 8 characters of a Drive doc_id."""
    if not doc_id or not isinstance(doc_id, str):
        return None
    s = doc_id.strip()
    if not s:
        return None
    return s[-8:]


def _redact_string_value(value: str | None) -> dict[str, Any] | None:
    """Capture length + sha256 of an arbitrary value-string parameter."""
    if not value or not isinstance(value, str):
        return None
    v = value
    if not v:
        return None
    digest = hashlib.sha256(v.encode("utf-8")).hexdigest()
    return {"length": len(v), "sha256": digest}


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


# ---------------------------------------------------------------------------
# Parameter extraction — Reports API encodes event details as a list of
# ``{"name": ..., "value"|"intValue"|"boolValue"|"stringValue": ...}`` pairs.
# ---------------------------------------------------------------------------


def _params_to_dict(params: Any) -> dict[str, Any]:
    """Flatten Reports-API parameter list into a name → value dict.

    Each parameter has one populated value field (``value`` for strings,
    ``intValue`` for ints, ``boolValue`` for bools, ``stringValue`` for
    long-form text). We pick whichever is present, preferring typed values.
    """
    if not isinstance(params, list):
        return {}
    out: dict[str, Any] = {}
    for entry in params:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        if "boolValue" in entry and entry["boolValue"] is not None:
            out[name] = bool(entry["boolValue"])
        elif "intValue" in entry and entry["intValue"] is not None:
            iv = entry["intValue"]
            if isinstance(iv, str):
                try:
                    out[name] = int(iv)
                except ValueError:
                    out[name] = iv
            else:
                out[name] = iv
        elif "stringValue" in entry and entry["stringValue"] is not None:
            out[name] = entry["stringValue"]
        elif "value" in entry and entry["value"] is not None:
            out[name] = entry["value"]
        elif "multiValue" in entry and isinstance(entry["multiValue"], list):
            out[name] = list(entry["multiValue"])
        elif (
            "multiIntValue" in entry and isinstance(entry["multiIntValue"], list)
        ):
            out[name] = list(entry["multiIntValue"])
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class GoogleDriveImporter:
    """Parse a Google Drive audit export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_file_threshold: int | None = None,
        bulk_download_threshold: int | None = None,
        bulk_download_window_seconds: int | None = None,
        cross_domain_share_threshold: int | None = None,
        cross_domain_share_window_seconds: int | None = None,
        restricted_mimes: Iterable[str] | None = None,
        agent_download_doc_types: Iterable[str] | None = None,
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
        self.cross_domain_share_threshold = int(
            cross_domain_share_threshold
            if cross_domain_share_threshold is not None
            else meta.get(
                "cross_domain_share_threshold",
                _DEFAULT_CROSS_DOMAIN_SHARE_THRESHOLD,
            )
        )
        self.cross_domain_share_window_seconds = int(
            cross_domain_share_window_seconds
            if cross_domain_share_window_seconds is not None
            else meta.get(
                "cross_domain_share_window_seconds",
                _DEFAULT_CROSS_DOMAIN_SHARE_WINDOW_SECONDS,
            )
        )
        if restricted_mimes is not None:
            self.restricted_mimes: frozenset[str] = frozenset(
                str(m).strip().lower() for m in restricted_mimes if m
            )
        else:
            meta_mimes = meta.get("restricted_mimes")
            if isinstance(meta_mimes, list) and meta_mimes:
                self.restricted_mimes = frozenset(
                    str(m).strip().lower() for m in meta_mimes if m
                )
            else:
                self.restricted_mimes = _DEFAULT_RESTRICTED_MIMES
        if agent_download_doc_types is not None:
            self.agent_download_doc_types: frozenset[str] = frozenset(
                str(t).strip().lower() for t in agent_download_doc_types if t
            )
        else:
            meta_dt = meta.get("agent_download_doc_types")
            if isinstance(meta_dt, list) and meta_dt:
                self.agent_download_doc_types = frozenset(
                    str(t).strip().lower() for t in meta_dt if t
                )
            else:
                self.agent_download_doc_types = _DEFAULT_AGENT_DOWNLOAD_DOC_TYPES
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
        """Parse a Google Drive Reports-activity export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        items = self._items_from_text(text)
        return self._build_results(items, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Google Drive Reports-activity content from a string."""
        items = self._items_from_text(content)
        return self._build_results(items, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _items_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"items": [...]}`` / ``{"data": [...]}`` / JSONL / single."""
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
                if "items" in doc and isinstance(doc["items"], list):
                    return [e for e in doc["items"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        items: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[Any]:
        """Build per-event EvaluationResults plus bulk-export and cross-domain-share synthetics."""
        # First pass: collect (event_dt, doc_id_last8) tuples per actor for
        # bulk-download, and (event_dt, target_domain) tuples per actor for
        # cross-domain sharing.
        download_events: dict[str, list[datetime]] = {}
        share_events: dict[str, list[datetime]] = {}

        for item in items:
            actor = item.get("actor") or {}
            if not isinstance(actor, dict):
                continue
            actor_email = (
                actor.get("email") if isinstance(actor.get("email"), str) else None
            )
            if not actor_email:
                continue
            event_id_obj = item.get("id") or {}
            time_field = (
                event_id_obj.get("time")
                if isinstance(event_id_obj, dict)
                else None
            )
            event_dt = _parse_iso_timestamp(time_field)
            if event_dt is None:
                continue
            events = item.get("events") or []
            if not isinstance(events, list):
                continue
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                ev_type = str(ev.get("type") or "").strip().lower()
                ev_name = str(ev.get("name") or "").strip().lower()
                if ev_type == "access" and ev_name == "download":
                    download_events.setdefault(actor_email, []).append(event_dt)
                if ev_type == "acl_change" and ev_name == "share_outside_domain":
                    share_events.setdefault(actor_email, []).append(event_dt)

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

        cross_domain_share_actors: dict[str, int] = {}
        window_sh = timedelta(seconds=self.cross_domain_share_window_seconds)
        for actor, ts_list in share_events.items():
            if len(ts_list) <= self.cross_domain_share_threshold:
                continue
            sorted_ts = sorted(ts_list)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while sorted_ts[right] - sorted_ts[left] > window_sh:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.cross_domain_share_threshold:
                cross_domain_share_actors[actor] = max_in_window

        results: list[Any] = []
        for item in items:
            results.extend(
                self._parse_item(
                    item,
                    file_sha256=file_sha256,
                    bulk_download_actors=bulk_download_actors,
                    cross_domain_share_actors=cross_domain_share_actors,
                )
            )

        for actor, count in sorted(bulk_download_actors.items()):
            results.append(
                self._synthetic_bulk_download_result(
                    actor=actor,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for actor, count in sorted(cross_domain_share_actors.items()):
            results.append(
                self._synthetic_cross_domain_share_result(
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
            "source_format": "google_drive_audit",
            "source_tool_name": "google_drive",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-item parsing — each item carries one or more events; we emit
    # one EvaluationResult per event.
    # ------------------------------------------------------------------

    def _parse_item(
        self,
        item: dict[str, Any],
        *,
        file_sha256: str | None,
        bulk_download_actors: dict[str, int],
        cross_domain_share_actors: dict[str, int],
    ) -> list[Any]:
        id_obj = item.get("id") or {}
        if not isinstance(id_obj, dict):
            id_obj = {}
        item_time = id_obj.get("time")
        unique_qualifier = id_obj.get("uniqueQualifier")
        application_name = (
            str(id_obj.get("applicationName"))
            if isinstance(id_obj.get("applicationName"), str)
            else None
        )

        actor_obj = item.get("actor") or {}
        if not isinstance(actor_obj, dict):
            actor_obj = {}
        actor_email_raw = (
            actor_obj.get("email")
            if isinstance(actor_obj.get("email"), str)
            else None
        )
        actor_email_domain = _redact_email(actor_email_raw)
        actor_caller_type = (
            str(actor_obj.get("callerType")).strip()
            if isinstance(actor_obj.get("callerType"), str)
            and actor_obj.get("callerType")
            else None
        )
        actor_profile_id = (
            str(actor_obj.get("profileId"))
            if isinstance(actor_obj.get("profileId"), str)
            and actor_obj.get("profileId")
            else None
        )
        ip_address_redacted = _classify_ip(
            item.get("ipAddress")
            if isinstance(item.get("ipAddress"), str)
            else None
        )

        events = item.get("events") or []
        if not isinstance(events, list):
            return []

        timestamp_iso = _format_timestamp(item_time)

        results: list[Any] = []
        for idx, ev in enumerate(events):
            if not isinstance(ev, dict):
                continue
            results.append(
                self._parse_event(
                    ev,
                    item_index=idx,
                    item_unique_qualifier=(
                        str(unique_qualifier)
                        if unique_qualifier is not None
                        else None
                    ),
                    application_name=application_name,
                    actor_email_raw=actor_email_raw,
                    actor_email_domain=actor_email_domain,
                    actor_caller_type=actor_caller_type,
                    actor_profile_id=actor_profile_id,
                    ip_address_redacted=ip_address_redacted,
                    timestamp_iso=timestamp_iso,
                    file_sha256=file_sha256,
                    bulk_download_actors=bulk_download_actors,
                    cross_domain_share_actors=cross_domain_share_actors,
                )
            )
        return results

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        item_index: int,
        item_unique_qualifier: str | None,
        application_name: str | None,
        actor_email_raw: str | None,
        actor_email_domain: str | None,
        actor_caller_type: str | None,
        actor_profile_id: str | None,
        ip_address_redacted: str | None,
        timestamp_iso: str,
        file_sha256: str | None,
        bulk_download_actors: dict[str, int],
        cross_domain_share_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        ev_type = str(event.get("type") or "").strip().lower() or None
        ev_name = str(event.get("name") or "").strip().lower() or None
        params = _params_to_dict(event.get("parameters"))

        # Stable per-event id: <unique_qualifier>-<idx> when available.
        if item_unique_qualifier:
            event_id = f"{item_unique_qualifier}-{item_index}"
        else:
            event_id = str(uuid.uuid4())

        # Document parameters.
        doc_id_raw = params.get("doc_id") if isinstance(params.get("doc_id"), str) else None
        doc_id_last8 = _truncate_doc_id(doc_id_raw)
        doc_title_length_raw = params.get("doc_title_length")
        doc_title_length: int | None = (
            int(doc_title_length_raw)
            if isinstance(doc_title_length_raw, (int, float))
            and not isinstance(doc_title_length_raw, bool)
            else None
        )
        doc_type = (
            str(params.get("doc_type")).strip().lower()
            if isinstance(params.get("doc_type"), str)
            and params.get("doc_type")
            else None
        )
        mime_type = (
            str(params.get("mime_type")).strip().lower()
            if isinstance(params.get("mime_type"), str)
            and params.get("mime_type")
            else None
        )
        file_size_bytes_raw = params.get("file_size_bytes")
        file_size_bytes: int | None = (
            int(file_size_bytes_raw)
            if isinstance(file_size_bytes_raw, (int, float))
            and not isinstance(file_size_bytes_raw, bool)
            else None
        )

        visibility = (
            str(params.get("visibility")).strip().lower()
            if isinstance(params.get("visibility"), str)
            and params.get("visibility")
            else None
        )
        old_visibility = (
            str(params.get("old_visibility")).strip().lower()
            if isinstance(params.get("old_visibility"), str)
            and params.get("old_visibility")
            else None
        )
        new_visibility = (
            str(params.get("new_visibility")).strip().lower()
            if isinstance(params.get("new_visibility"), str)
            and params.get("new_visibility")
            else None
        )
        original_object_visibility = (
            str(params.get("original_object_visibility")).strip().lower()
            if isinstance(params.get("original_object_visibility"), str)
            and params.get("original_object_visibility")
            else None
        )

        target_user_email_raw = (
            params.get("target_user_email")
            if isinstance(params.get("target_user_email"), str)
            else None
        )
        target_user_email_domain = _normalize_email_domain(
            params.get("target_user_email_domain")
            if isinstance(params.get("target_user_email_domain"), str)
            else None
        )
        if target_user_email_domain is None and target_user_email_raw:
            target_user_email_domain = _redact_email(target_user_email_raw)

        owner_email_domain = _redact_email(
            params.get("owner") if isinstance(params.get("owner"), str) else None
        )
        primary_event = (
            bool(params.get("primary_event"))
            if "primary_event" in params
            else None
        )
        actor_is_collaborator_account = (
            bool(params.get("actor_is_collaborator_account"))
            if "actor_is_collaborator_account" in params
            else None
        )
        shared_drive_id_raw = (
            params.get("shared_drive_id")
            if isinstance(params.get("shared_drive_id"), str)
            else None
        )
        shared_drive_id = (
            shared_drive_id_raw[-8:]
            if isinstance(shared_drive_id_raw, str) and shared_drive_id_raw
            else None
        )

        old_value_string = _redact_string_value(
            params.get("old_value_string")
            if isinstance(params.get("old_value_string"), str)
            else None
        )
        new_value_string = _redact_string_value(
            params.get("new_value_string")
            if isinstance(params.get("new_value_string"), str)
            else None
        )

        common_evidence: dict[str, Any] = {
            "drive_event_id": event_id,
            "application_name": application_name,
            "type": ev_type,
            "name": ev_name,
            "doc_id_last8": doc_id_last8,
            "doc_title_length": doc_title_length,
            "doc_type": doc_type,
            "mime_type": mime_type,
            "file_size_bytes": file_size_bytes,
            "visibility": visibility,
            "old_visibility": old_visibility,
            "new_visibility": new_visibility,
            "original_object_visibility": original_object_visibility,
            "actor_email_domain": actor_email_domain,
            "actor_caller_type": actor_caller_type,
            "actor_profile_id": actor_profile_id,
            "actor_is_collaborator_account": actor_is_collaborator_account,
            "target_user_email_domain": target_user_email_domain,
            "owner_email_domain": owner_email_domain,
            "primary_event": primary_event,
            "shared_drive_id_last8": shared_drive_id,
            "old_value_string_redacted": old_value_string,
            "new_value_string_redacted": new_value_string,
            "ip_address_redacted": ip_address_redacted,
            "event_time": timestamp_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "google_drive",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Public anonymous access (callerType=USER_PUBLIC) — top-priority
        #    PR-01 FAIL regardless of event type.
        # ----------------------------------------------------------------
        if actor_caller_type == _USER_PUBLIC_CALLERTYPE:
            signal = "public_anonymous_access"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Drive event {event_id} actor.callerType=USER_PUBLIC "
                        f"on doc={doc_id_last8 or 'unknown'} — anonymous "
                        f"public access surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Type-driven primary classification.
        # ----------------------------------------------------------------
        if ev_type == "access":
            if ev_name in {"view", "preview"}:
                signal = "view_event" if ev_name == "view" else "preview_event"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Drive event {event_id} access:{ev_name} on doc="
                            f"{doc_id_last8 or 'unknown'} — read-access "
                            f"audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif ev_name == "download":
                # Service-account agent downloading a document type → FAIL.
                if (
                    actor_caller_type == _SERVICE_ACCOUNT_CALLERTYPE
                    and doc_type
                    and doc_type in self.agent_download_doc_types
                ):
                    signal = "agent_document_download"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FAIL",
                            detail=(
                                f"Drive event {event_id} access:download by "
                                f"APPLICATION_SERVICE_ACCOUNT on doc_type="
                                f"{doc_type!r} doc={doc_id_last8 or 'unknown'} "
                                f"— agent downloading documents, requires review"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                else:
                    signal = "download_event"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} access:download on doc="
                                f"{doc_id_last8 or 'unknown'} doc_type="
                                f"{doc_type or 'unknown'} — file leaving system"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                # Large download flag (additive on top of any download).
                if (
                    file_size_bytes is not None
                    and file_size_bytes > self.large_file_threshold
                ):
                    signal = "large_download"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} access:download size="
                                f"{file_size_bytes}B exceeds threshold "
                                f"{self.large_file_threshold}B — large download"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "large_file_threshold": self.large_file_threshold,
                            },
                        )
                    )
                # Restricted-mime download by service account.
                if (
                    actor_caller_type == _SERVICE_ACCOUNT_CALLERTYPE
                    and mime_type
                    and mime_type in self.restricted_mimes
                ):
                    signal = "restricted_mime_download"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} access:download "
                                f"mime_type={mime_type!r} by "
                                f"APPLICATION_SERVICE_ACCOUNT — data export by "
                                f"agent on restricted mime"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
            elif ev_name == "print":
                signal = "print_event"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Drive event {event_id} access:print on doc="
                            f"{doc_id_last8 or 'unknown'} — physical "
                            f"exfiltration surface"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif ev_type == "acl_change":
            if ev_name == "share_outside_domain":
                signal = "share_outside_domain"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Drive event {event_id} acl_change:"
                            f"share_outside_domain on doc="
                            f"{doc_id_last8 or 'unknown'} target_domain="
                            f"{target_user_email_domain or 'unknown'} — "
                            f"file shared externally, top-priority exfil"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Visibility transition signals — old → new.
                effective_old = old_visibility or original_object_visibility
                effective_new = new_visibility or visibility
                if effective_old == _PRIVATE_VISIBILITY and effective_new in _PUBLIC_VISIBILITIES:
                    signal = "visibility_to_link"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FAIL",
                            detail=(
                                f"Drive event {event_id} acl_change visibility "
                                f"{effective_old!r} -> {effective_new!r} on "
                                f"doc={doc_id_last8 or 'unknown'} — privacy "
                                f"regression to public"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                elif (
                    effective_old == _PRIVATE_VISIBILITY
                    and effective_new == _DOMAIN_VISIBILITY
                ):
                    signal = "visibility_to_domain"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} acl_change visibility "
                                f"{effective_old!r} -> {effective_new!r} on "
                                f"doc={doc_id_last8 or 'unknown'} — workspace-"
                                f"wide visibility increase"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                if ev_name == "change_acl_editors":
                    signal = "acl_editors_change"
                    control_id = _control_for(signal, self._mappings, "PR-02")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} acl_change:"
                                f"change_acl_editors on doc="
                                f"{doc_id_last8 or 'unknown'} — editor list "
                                f"modified"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                # External grant: target domain != actor's primary domain.
                # Only flag if it's not already a share_outside_domain
                # (which is itself stronger and DE-01).
                if (
                    target_user_email_domain
                    and actor_email_domain
                    and target_user_email_domain != actor_email_domain
                    and not any(
                        cr.evidence_data.get("signal") == "share_outside_domain"
                        for cr in control_results
                    )
                ):
                    signal = "external_grant"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Drive event {event_id} acl_change grant "
                                f"to target_domain={target_user_email_domain!r} "
                                f"differs from actor_domain="
                                f"{actor_email_domain!r} on doc="
                                f"{doc_id_last8 or 'unknown'} — external "
                                f"grant"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
        elif ev_type == "user_ownership" and ev_name == "ownership_change":
            signal = "ownership_change"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Drive event {event_id} user_ownership:ownership_change "
                        f"on doc={doc_id_last8 or 'unknown'} — ownership "
                        f"transfer"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif ev_type == "delete":
            if ev_name == "trash":
                signal = "trash_event"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Drive event {event_id} delete:trash on doc="
                            f"{doc_id_last8 or 'unknown'} — soft-delete "
                            f"audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif ev_name == "delete":
                signal = "permanent_delete"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Drive event {event_id} delete:delete on doc="
                            f"{doc_id_last8 or 'unknown'} — irreversible "
                            f"permanent delete"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 3. Synthetic pattern markers — informational on contributing events.
        # ----------------------------------------------------------------
        if actor_email_raw and actor_email_raw in bulk_download_actors:
            signal = "bulk_download_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Drive event {event_id} actor {actor_email_domain} is "
                        f"part of a bulk-download pattern "
                        f"({bulk_download_actors[actor_email_raw]} downloads > "
                        f"threshold {self.bulk_download_threshold} in "
                        f"{self.bulk_download_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bulk_download_count": bulk_download_actors[actor_email_raw],
                        "bulk_download_threshold": self.bulk_download_threshold,
                        "bulk_download_window_seconds": self.bulk_download_window_seconds,
                    },
                )
            )
        if actor_email_raw and actor_email_raw in cross_domain_share_actors:
            signal = "cross_domain_share_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Drive event {event_id} actor {actor_email_domain} is "
                        f"part of a cross-domain-share pattern "
                        f"({cross_domain_share_actors[actor_email_raw]} shares "
                        f"> threshold {self.cross_domain_share_threshold} in "
                        f"{self.cross_domain_share_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_domain_share_count":
                            cross_domain_share_actors[actor_email_raw],
                        "cross_domain_share_threshold":
                            self.cross_domain_share_threshold,
                        "cross_domain_share_window_seconds":
                            self.cross_domain_share_window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 4. No-match fallback — surface unknown event so it is not silent.
        # ----------------------------------------------------------------
        if not control_results:
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Drive event {event_id} type={ev_type!r} name="
                        f"{ev_name!r} has no matching pattern — surfaced for "
                        f"review"
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
            f"Imported from Google Drive audit log: type={ev_type or 'unknown'} "
            f"name={ev_name or 'unknown'} actor={actor_email_domain or 'unknown'} "
            f"callerType={actor_caller_type or 'unknown'} "
            f"doc={doc_id_last8 or 'unknown'}"
        )

        action_id = f"google-drive-{event_id[:48]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="google_drive_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=item_unique_qualifier,
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
        synthetic_id = f"google-drive-bulk-download-{uuid.uuid4()}"
        actor_domain = _redact_email(actor) or actor
        evidence: dict[str, Any] = {
            "drive_event_id": synthetic_id,
            "actor_email_domain": actor_domain,
            "bulk_download_count": count,
            "bulk_download_threshold": self.bulk_download_threshold,
            "bulk_download_window_seconds": self.bulk_download_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "google_drive",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Drive synthetic finding: actor {actor_domain} performed "
                f"{count} downloads in a {self.bulk_download_window_seconds}s "
                f"window — exceeds bulk-download threshold "
                f"{self.bulk_download_threshold} (mass-export pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="google_drive_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Google Drive audit log: synthetic bulk-download "
                f"pattern for actor={actor_domain} count={count}>threshold="
                f"{self.bulk_download_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_domain_share_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_domain_share_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"google-drive-cross-domain-share-{uuid.uuid4()}"
        actor_domain = _redact_email(actor) or actor
        evidence: dict[str, Any] = {
            "drive_event_id": synthetic_id,
            "actor_email_domain": actor_domain,
            "cross_domain_share_count": count,
            "cross_domain_share_threshold": self.cross_domain_share_threshold,
            "cross_domain_share_window_seconds":
                self.cross_domain_share_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "google_drive",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Drive synthetic finding: actor {actor_domain} shared {count} "
                f"files outside domain in a "
                f"{self.cross_domain_share_window_seconds}s window — exceeds "
                f"cross-domain-share threshold "
                f"{self.cross_domain_share_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="google_drive_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Google Drive audit log: synthetic cross-domain-"
                f"share pattern for actor={actor_domain} count={count}>"
                f"threshold={self.cross_domain_share_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
