# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""SharePoint Online + OneDrive for Business importer — maps Microsoft 365 Unified Audit Log activity to AKSI controls.

SharePoint Online and OneDrive for Business are the Microsoft 365 file-storage
tier — the Microsoft cloud-content parallel to Box and Google Drive. Both
products emit unified events through the Microsoft Purview / Office 365
Management Activity API, distinguished by the ``workload`` field
(``OneDrive`` vs ``SharePoint``). Because the audit envelope and field shape
are identical between the two surfaces, a single importer covers both.

Agents now read, write, sync, and share OneDrive/SharePoint content at scale:
RAG corpora, generated reports, intermediate artifacts, customer-facing
deliverables. The Microsoft 365 audit feed surfaces the data-loss-prevention
signals that gate Microsoft cloud storage: file access, downloads, full-
library sync, anonymous links (the SharePoint exfil parallel to Box public-
unprotected), guest sharing, sensitivity-label changes, tenant-level sharing
policy changes, site-collection admin grants, site-permission changes,
site deletions, DLP rule matches, and malware detections.

This importer ingests Microsoft 365 audit JSON exports in three on-disk
shapes:

  1. ``{"events": [...]}`` — Activity API envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Each event is materialized as its own ``EvaluationResult``.

Signal mapping (see shared/mappings/sharepoint-onedrive-aksi-controls.json):
  * ``FileAccessed`` / ``FilePreviewed``                              → PR-04 PASS
  * ``FileDownloaded`` by Application/ServicePrincipal/System on
    sensitive extension                                               → PR-04 FAIL
  * ``FileSyncDownloadedFull`` (full-library sync)                    → PR-04 FLAG
  * ``AnonymousLinkCreated``                                          → DE-01 FAIL
  * ``SecureLinkCreated`` + sharingTargetType=Guest                   → PR-04 FLAG
  * ``SharingInvitationCreated`` to non-tenant-primary domain         → PR-04 FLAG
  * ``FileSensitivityLabelChanged`` to a more permissive label        → PR-04 FAIL
  * ``SharingPolicyChanged``                                          → PR-02 FAIL
  * ``SiteCollectionAdminAdded``                                      → PR-02 FLAG
  * ``SitePermissionsModified`` to AllowAnonymousAccess               → DE-01 FAIL
  * ``SiteDeleted``                                                   → PR-02 FAIL
  * ``DLPRuleMatch`` DLPSeverity=high                                 → PR-04 FAIL
  * ``DLPRuleMatch`` DLPSeverity=medium                               → PR-04 FLAG
  * ``FileMalwareDetected``                                           → DE-01 FAIL
  * ``sharingPermission`` in {FullControl, Owner} to external         → PR-02 FAIL
  * ``resultStatus=Failed`` on FileAccessed                           → PR-02 PASS
  * Bulk-download pattern: same userPrincipalName with > N
    FileDownloaded in 1h (default 50)                                 → PR-04 FAIL
  * Cross-site pattern: same user touching > N siteUrl in 1h
    (default 5)                                                       → PR-04 FLAG

Sanitization (security-critical — Microsoft 365 audit records identify the
items, the user's principal name, the IP, and free-form modified-property
values):
  * ``sourceFileName``        is NEVER stored — only ``length`` (sha256 if raw value present).
  * ``sourceRelativeUrl``     is NEVER stored — only ``length``.
  * ``siteUrl``               keeps only host + first path segment.
  * ``objectId``              keeps only the trailing 8 characters.
  * ``userPrincipalName``     is reduced to ``@domain`` only — never the local-part.
  * ``userAgent``             is reduced to first 80 chars + sha256 of full value.
  * ``modifiedProperties``    keeps property ``name`` only; old/new values
                              become length only (no value text).
  * ``DLPSourceUserName``     is reduced to ``@domain`` only.
  * ``targetUserOrGroupName`` is reduced to ``@domain`` only.
  * ``clientIP`` is masked to /16 (IPv4) or /32-hextet (IPv6); private /
    loopback / link-local addresses are preserved verbatim.
  * Sensitivity-label name (``sensitivityLabelName``) is captured verbatim —
    labels are non-sensitive structured tags.
  * DLP rule name (``DLPRuleName``), severity, and matched-conditions list
    are captured verbatim — these are policy identifiers, not content.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``office365-rest-python-client``; Microsoft 365
audit JSON exports are parsed with the standard library only.
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
from urllib.parse import urlparse


# Path to the shared mapping table.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "sharepoint-onedrive-aksi-controls.json"
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
_DEFAULT_CROSS_SITE_THRESHOLD = 5
_DEFAULT_CROSS_SITE_WINDOW_SECONDS = 3600

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
        "zip",
        "tar",
        "gz",
    }
)

# Microsoft 365 user types that signal non-human / agent activity.
_AGENT_USER_TYPES: frozenset[str] = frozenset(
    {"application", "serviceprincipal", "system"}
)

# Sharing-permission strings that imply broad authority — flagged as risky
# when granted to external (Guest/AnonymousLink) recipients.
_BROAD_PERMISSIONS: frozenset[str] = frozenset({"fullcontrol", "owner"})

# Sharing-target types that are external by definition.
_EXTERNAL_TARGET_TYPES: frozenset[str] = frozenset(
    {"guest", "anonymouslink"}
)

# Tokens we treat as "more permissive than Confidential". Used to detect
# sensitivity-label downgrade.
_DEFAULT_PERMISSIVE_LABEL_TOKENS: frozenset[str] = frozenset(
    {"public", "general", "internal", "non-confidential", "personal"}
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load sharepoint-onedrive-aksi-controls.json; tolerate a missing/invalid file."""
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


def _redact_upn_to_domain(upn: str | None) -> str | None:
    """Reduce a userPrincipalName to ``@domain`` — never store the local-part."""
    if not upn or not isinstance(upn, str):
        return None
    s = upn.strip()
    if "@" not in s:
        return None
    return "@" + s.rsplit("@", 1)[1].lower()


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


def _redact_user_agent(value: str | None) -> dict[str, Any] | None:
    """Reduce a User-Agent to first 80 chars + sha256 of the full value."""
    if not value or not isinstance(value, str):
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return {
        "prefix80": value[:80],
        "length": len(value),
        "sha256": digest,
    }


def _redact_site_url(value: str | None) -> str | None:
    """Keep only host + first path segment of a site URL.

    For SharePoint the canonical site-collection prefix is
    ``/sites/{name}`` or ``/personal/{user}``. We keep the first segment
    (e.g. ``sites``, ``personal``) so the redacted form is the host plus
    the leading container segment — which is non-sensitive.
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        parsed = urlparse(s)
    except ValueError:
        return None
    host = parsed.netloc.lower() if parsed.netloc else ""
    if not host:
        return None
    path = parsed.path or ""
    parts = [p for p in path.split("/") if p]
    if parts:
        return f"{host}/{parts[0]}"
    return host


def _site_key_for_pattern(value: str | None) -> str | None:
    """Derive the site-collection key for cross-site pattern detection.

    This keeps host + the first TWO path segments so that distinct
    SharePoint site collections (``/sites/teamA``, ``/sites/teamB``) are
    counted separately. The key is used ONLY for in-memory pattern
    correlation — it is NEVER stored on evidence; redacted forms always
    use ``_redact_site_url`` (host + first segment only).
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        parsed = urlparse(s)
    except ValueError:
        return None
    host = parsed.netloc.lower() if parsed.netloc else ""
    if not host:
        return None
    path = parsed.path or ""
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2:
        return f"{host}/{parts[0]}/{parts[1]}"
    if parts:
        return f"{host}/{parts[0]}"
    return host


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
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


def _redact_modified_properties(props: Any) -> list[dict[str, Any]] | None:
    """Sanitize modifiedProperties — keep ``name`` verbatim, replace values with length."""
    if not isinstance(props, list):
        return None
    out: list[dict[str, Any]] = []
    for p in props:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        name_str = str(name) if name is not None else None
        old_len = p.get("oldValue_length")
        new_len = p.get("newValue_length")
        old_raw = p.get("oldValue")
        new_raw = p.get("newValue")
        if (
            old_len is None
            and isinstance(old_raw, str)
        ):
            old_len = len(old_raw)
        if (
            new_len is None
            and isinstance(new_raw, str)
        ):
            new_len = len(new_raw)
        out.append(
            {
                "name": name_str,
                "oldValue_length": (
                    int(old_len)
                    if isinstance(old_len, (int, float))
                    and not isinstance(old_len, bool)
                    else None
                ),
                "newValue_length": (
                    int(new_len)
                    if isinstance(new_len, (int, float))
                    and not isinstance(new_len, bool)
                    else None
                ),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SharePointOneDriveImporter:
    """Parse a Microsoft 365 SharePoint/OneDrive Unified Audit export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bulk_download_threshold: int | None = None,
        bulk_download_window_seconds: int | None = None,
        cross_site_threshold: int | None = None,
        cross_site_window_seconds: int | None = None,
        sensitive_extensions: Iterable[str] | None = None,
        agent_user_types: Iterable[str] | None = None,
        tenant_primary_domain: str | None = None,
        permissive_label_tokens: Iterable[str] | None = None,
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
        self.cross_site_threshold = int(
            cross_site_threshold
            if cross_site_threshold is not None
            else meta.get(
                "cross_site_threshold", _DEFAULT_CROSS_SITE_THRESHOLD
            )
        )
        self.cross_site_window_seconds = int(
            cross_site_window_seconds
            if cross_site_window_seconds is not None
            else meta.get(
                "cross_site_window_seconds",
                _DEFAULT_CROSS_SITE_WINDOW_SECONDS,
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
        if agent_user_types is not None:
            self.agent_user_types: frozenset[str] = frozenset(
                str(t).strip().lower() for t in agent_user_types if t
            )
        else:
            meta_types = meta.get("agent_user_types")
            if isinstance(meta_types, list) and meta_types:
                self.agent_user_types = frozenset(
                    str(t).strip().lower() for t in meta_types if t
                )
            else:
                self.agent_user_types = _AGENT_USER_TYPES
        if tenant_primary_domain is not None:
            self.tenant_primary_domain: str | None = (
                _normalize_email_domain(tenant_primary_domain)
            )
        else:
            meta_domain = meta.get("tenant_primary_domain")
            self.tenant_primary_domain = (
                _normalize_email_domain(meta_domain)
                if isinstance(meta_domain, str) and meta_domain.strip()
                else None
            )
        if permissive_label_tokens is not None:
            self.permissive_label_tokens: frozenset[str] = frozenset(
                str(t).strip().lower() for t in permissive_label_tokens if t
            )
        else:
            meta_tokens = meta.get("more_permissive_label_tokens")
            if isinstance(meta_tokens, list) and meta_tokens:
                self.permissive_label_tokens = frozenset(
                    str(t).strip().lower() for t in meta_tokens if t
                )
            else:
                self.permissive_label_tokens = (
                    _DEFAULT_PERMISSIVE_LABEL_TOKENS
                )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[Any]:
        """Parse a SharePoint/OneDrive Unified Audit export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Microsoft 365 audit content from a string."""
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

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[Any]:
        """Build per-event EvaluationResults plus bulk-download and cross-site synthetics."""
        download_events: dict[str, list[datetime]] = {}
        site_events: dict[str, list[tuple[datetime, str]]] = {}

        for event in events:
            upn_raw = (
                str(event.get("userPrincipalName"))
                if isinstance(event.get("userPrincipalName"), str)
                and event.get("userPrincipalName")
                else None
            )
            if not upn_raw:
                continue
            event_dt = _parse_iso_timestamp(event.get("createdDateTime"))
            if event_dt is None:
                continue
            op = (
                str(event.get("operation") or "").strip()
                if event.get("operation")
                else None
            )
            if op == "FileDownloaded":
                download_events.setdefault(upn_raw, []).append(event_dt)
            site_pattern_key = _site_key_for_pattern(
                event.get("siteUrl")
                if isinstance(event.get("siteUrl"), str)
                else None
            )
            if site_pattern_key:
                site_events.setdefault(upn_raw, []).append(
                    (event_dt, site_pattern_key)
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

        cross_site_actors: dict[str, int] = {}
        window_st = timedelta(seconds=self.cross_site_window_seconds)
        for actor, pair_list in site_events.items():
            sorted_pairs = sorted(pair_list, key=lambda p: p[0])
            left = 0
            distinct_count: dict[str, int] = {}
            max_distinct = 0
            for right in range(len(sorted_pairs)):
                _, site_r = sorted_pairs[right]
                distinct_count[site_r] = distinct_count.get(site_r, 0) + 1
                while sorted_pairs[right][0] - sorted_pairs[left][0] > window_st:
                    _, site_l = sorted_pairs[left]
                    distinct_count[site_l] -= 1
                    if distinct_count[site_l] == 0:
                        del distinct_count[site_l]
                    left += 1
                cur_distinct = len(distinct_count)
                if cur_distinct > max_distinct:
                    max_distinct = cur_distinct
            if max_distinct > self.cross_site_threshold:
                cross_site_actors[actor] = max_distinct

        results: list[Any] = []
        for event in events:
            result = self._parse_event(
                event,
                file_sha256=file_sha256,
                bulk_download_actors=bulk_download_actors,
                cross_site_actors=cross_site_actors,
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
        for actor, count in sorted(cross_site_actors.items()):
            results.append(
                self._synthetic_cross_site_result(
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
            "source_format": "microsoft365_unified_audit",
            "source_tool_name": "sharepoint_onedrive",
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
        cross_site_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        event_id_raw = (
            str(event.get("id"))
            if isinstance(event.get("id"), str) and event.get("id")
            else None
        )
        event_id = event_id_raw if event_id_raw else str(uuid.uuid4())

        operation = (
            str(event.get("operation") or "").strip()
            if event.get("operation")
            else None
        )
        timestamp_iso = _format_timestamp(event.get("createdDateTime"))

        # --- User -------------------------------------------------------
        upn_raw = (
            str(event.get("userPrincipalName"))
            if isinstance(event.get("userPrincipalName"), str)
            and event.get("userPrincipalName")
            else None
        )
        upn_domain = _redact_upn_to_domain(upn_raw)
        user_type = (
            str(event.get("userType")).strip().lower()
            if isinstance(event.get("userType"), str)
            and event.get("userType")
            else None
        )

        # --- Workload / context -----------------------------------------
        workload = (
            str(event.get("workload"))
            if isinstance(event.get("workload"), str)
            and event.get("workload")
            else None
        )
        result_status = (
            str(event.get("resultStatus")).strip().lower()
            if isinstance(event.get("resultStatus"), str)
            and event.get("resultStatus")
            else None
        )
        client_ip_redacted = _classify_ip(
            event.get("clientIP")
            if isinstance(event.get("clientIP"), str)
            else None
        )
        user_agent_redacted = _redact_user_agent(
            event.get("userAgent")
            if isinstance(event.get("userAgent"), str)
            else None
        )

        # --- Source file (lengths only) ---------------------------------
        source_file_extension = (
            str(event.get("sourceFileExtension")).strip().lower().lstrip(".")
            if isinstance(event.get("sourceFileExtension"), str)
            and event.get("sourceFileExtension")
            else None
        )
        source_file_name_length_raw = event.get("sourceFileName_length")
        source_file_name_length: int | None = (
            int(source_file_name_length_raw)
            if isinstance(source_file_name_length_raw, (int, float))
            and not isinstance(source_file_name_length_raw, bool)
            else None
        )
        source_relative_url_length_raw = event.get("sourceRelativeUrl_length")
        source_relative_url_length: int | None = (
            int(source_relative_url_length_raw)
            if isinstance(source_relative_url_length_raw, (int, float))
            and not isinstance(source_relative_url_length_raw, bool)
            else None
        )
        # If raw sourceFileName / sourceRelativeUrl are present, we still
        # never store the value — use length only.
        raw_name = event.get("sourceFileName")
        if (
            source_file_name_length is None
            and isinstance(raw_name, str)
        ):
            source_file_name_length = len(raw_name)
        raw_rel = event.get("sourceRelativeUrl")
        if (
            source_relative_url_length is None
            and isinstance(raw_rel, str)
        ):
            source_relative_url_length = len(raw_rel)

        site_url_redacted = _redact_site_url(
            event.get("siteUrl")
            if isinstance(event.get("siteUrl"), str)
            else None
        )
        object_id_last8 = _truncate_id(
            event.get("objectId")
            if isinstance(event.get("objectId"), str)
            else None
        )
        item_type = (
            str(event.get("itemType")).strip().lower()
            if isinstance(event.get("itemType"), str)
            and event.get("itemType")
            else None
        )
        file_size_raw = event.get("fileSize")
        file_size: int | None = (
            int(file_size_raw)
            if isinstance(file_size_raw, (int, float))
            and not isinstance(file_size_raw, bool)
            else None
        )

        # --- Sensitivity label (verbatim — non-sensitive structured tag) -
        sensitivity_label_id = (
            str(event.get("sensitivityLabelId"))
            if isinstance(event.get("sensitivityLabelId"), str)
            and event.get("sensitivityLabelId")
            else None
        )
        sensitivity_label_name = (
            str(event.get("sensitivityLabelName"))
            if isinstance(event.get("sensitivityLabelName"), str)
            and event.get("sensitivityLabelName")
            else None
        )

        # --- Sharing details -------------------------------------------
        sharing_target_type = (
            str(event.get("sharingTargetType")).strip()
            if isinstance(event.get("sharingTargetType"), str)
            and event.get("sharingTargetType")
            else None
        )
        sharing_permission = (
            str(event.get("sharingPermission")).strip()
            if isinstance(event.get("sharingPermission"), str)
            and event.get("sharingPermission")
            else None
        )
        target_domain = _normalize_email_domain(
            event.get("targetUserOrGroupName_domain")
            if isinstance(event.get("targetUserOrGroupName_domain"), str)
            else None
        )

        # --- Modified properties (names only) --------------------------
        modified_properties_redacted = _redact_modified_properties(
            event.get("modifiedProperties")
        )

        # --- DLP / audit data -------------------------------------------
        audit_data = event.get("auditData") or {}
        if not isinstance(audit_data, dict):
            audit_data = {}
        dlp_source_user_domain = _normalize_email_domain(
            audit_data.get("DLPSourceUserName_domain")
            if isinstance(audit_data.get("DLPSourceUserName_domain"), str)
            else None
        )
        if dlp_source_user_domain is None:
            dlp_user_raw = (
                audit_data.get("DLPSourceUserName")
                if isinstance(audit_data.get("DLPSourceUserName"), str)
                else None
            )
            dlp_source_user_domain = _redact_upn_to_domain(dlp_user_raw)
        dlp_rule_name = (
            str(audit_data.get("DLPRuleName"))
            if isinstance(audit_data.get("DLPRuleName"), str)
            and audit_data.get("DLPRuleName")
            else None
        )
        dlp_severity = (
            str(audit_data.get("DLPSeverity")).strip().lower()
            if isinstance(audit_data.get("DLPSeverity"), str)
            and audit_data.get("DLPSeverity")
            else None
        )
        raw_conditions = audit_data.get("DLPMatchedConditions")
        dlp_matched_conditions: list[str] | None = None
        if isinstance(raw_conditions, list):
            dlp_matched_conditions = [
                str(c) for c in raw_conditions if isinstance(c, str) and c
            ]
        dlp_rule_id_last8 = _truncate_id(
            audit_data.get("DLPRuleId")
            if isinstance(audit_data.get("DLPRuleId"), str)
            else None
        )

        common_evidence: dict[str, Any] = {
            "m365_event_id": event_id,
            "operation": operation,
            "workload": workload,
            "user_type": user_type,
            "user_principal_name_domain": upn_domain,
            "client_ip_redacted": client_ip_redacted,
            "user_agent_redacted": user_agent_redacted,
            "result_status": result_status,
            "site_url_redacted": site_url_redacted,
            "object_id_last8": object_id_last8,
            "item_type": item_type,
            "source_file_extension": source_file_extension,
            "source_file_name_length": source_file_name_length,
            "source_relative_url_length": source_relative_url_length,
            "file_size": file_size,
            "sensitivity_label_id": sensitivity_label_id,
            "sensitivity_label_name": sensitivity_label_name,
            "sharing_target_type": sharing_target_type,
            "sharing_permission": sharing_permission,
            "target_user_or_group_name_domain": target_domain,
            "modified_properties_redacted": modified_properties_redacted,
            "dlp_source_user_domain": dlp_source_user_domain,
            "dlp_rule_id_last8": dlp_rule_id_last8,
            "dlp_rule_name": dlp_rule_name,
            "dlp_severity": dlp_severity,
            "dlp_matched_conditions": dlp_matched_conditions,
            "event_time": timestamp_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "sharepoint_onedrive",
        }

        control_results: list[ControlResult] = []
        is_agent_user = (
            user_type is not None and user_type in self.agent_user_types
        )
        is_external_target_type = (
            sharing_target_type is not None
            and sharing_target_type.lower() in _EXTERNAL_TARGET_TYPES
        )
        is_external_target_domain = (
            target_domain is not None
            and self.tenant_primary_domain is not None
            and target_domain != self.tenant_primary_domain
        )
        is_broad_perm = (
            sharing_permission is not None
            and sharing_permission.lower() in _BROAD_PERMISSIONS
        )

        # ----------------------------------------------------------------
        # operation-driven primary classification
        # ----------------------------------------------------------------
        if operation in ("FileAccessed", "FilePreviewed"):
            if result_status == "failed":
                signal = "failed_access_denied"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="PASS",
                        detail=(
                            f"M365 event {event_id} {operation} "
                            f"resultStatus=Failed on object="
                            f"{object_id_last8 or 'unknown'} — access "
                            f"correctly denied"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "file_accessed_or_previewed"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="PASS",
                        detail=(
                            f"M365 event {event_id} {operation} on object="
                            f"{object_id_last8 or 'unknown'} workload="
                            f"{workload or 'unknown'} — read-access audit-"
                            f"trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "FileDownloaded":
            agent_sensitive = (
                is_agent_user
                and source_file_extension is not None
                and source_file_extension in self.sensitive_extensions
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
                            f"M365 event {event_id} FileDownloaded by "
                            f"userType={user_type!r} on extension="
                            f"{source_file_extension!r} object="
                            f"{object_id_last8 or 'unknown'} — agent bulk-"
                            f"export pattern, requires review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "FileSyncDownloadedFull":
            signal = "full_sync_download"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"M365 event {event_id} FileSyncDownloadedFull on "
                        f"site={site_url_redacted or 'unknown'} — full-"
                        f"library sync extracts entire content surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation == "AnonymousLinkCreated":
            signal = "anonymous_link_created"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} AnonymousLinkCreated on "
                        f"object={object_id_last8 or 'unknown'} site="
                        f"{site_url_redacted or 'unknown'} — anonymous "
                        f"link is a top-priority exfil surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation == "SecureLinkCreated":
            if (
                sharing_target_type is not None
                and sharing_target_type.lower() == "guest"
            ):
                signal = "external_guest_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"M365 event {event_id} SecureLinkCreated "
                            f"sharingTargetType=Guest on object="
                            f"{object_id_last8 or 'unknown'} — external "
                            f"guest share, audit recommended"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "SharingInvitationCreated":
            external = False
            if self.tenant_primary_domain is not None:
                if (
                    target_domain is not None
                    and target_domain != self.tenant_primary_domain
                ):
                    external = True
            else:
                # Without a configured tenant primary domain we still flag
                # invitations whose target domain is set and differs from
                # the inviter's UPN domain.
                if (
                    target_domain is not None
                    and upn_domain is not None
                    and target_domain != upn_domain
                ):
                    external = True
            if external:
                signal = "external_sharing_invitation"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"M365 event {event_id} SharingInvitationCreated "
                            f"to target_domain={target_domain!r} (tenant="
                            f"{self.tenant_primary_domain!r}, inviter="
                            f"{upn_domain!r}) on object="
                            f"{object_id_last8 or 'unknown'} — external "
                            f"invitation"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "FileSensitivityLabelChanged":
            new_label = sensitivity_label_name
            label_lower = (new_label or "").strip().lower()
            tokens_match = any(
                tok in label_lower for tok in self.permissive_label_tokens
            )
            # Modified-properties flag the change explicitly.
            if tokens_match and new_label:
                signal = "sensitivity_downgrade"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"M365 event {event_id} "
                            f"FileSensitivityLabelChanged to "
                            f"{new_label!r} on object="
                            f"{object_id_last8 or 'unknown'} — sensitivity "
                            f"downgraded to a more permissive label"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "SharingPolicyChanged":
            signal = "sharing_policy_changed"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} SharingPolicyChanged by "
                        f"upn_domain={upn_domain or 'unknown'} — tenant-"
                        f"level sharing policy mutation, requires review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation == "SiteCollectionAdminAdded":
            signal = "site_admin_added"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"M365 event {event_id} SiteCollectionAdminAdded on "
                        f"site={site_url_redacted or 'unknown'} — admin "
                        f"role grant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation == "SitePermissionsModified":
            anonymous_change = False
            if isinstance(modified_properties_redacted, list):
                for prop in modified_properties_redacted:
                    name = (prop or {}).get("name")
                    if isinstance(name, str) and (
                        "anonymous" in name.lower()
                        or "allowanonymous" in name.lower().replace(" ", "")
                    ):
                        anonymous_change = True
                        break
            # Also peek at raw modifiedProperties values (NOT stored).
            if not anonymous_change:
                raw_props = event.get("modifiedProperties")
                if isinstance(raw_props, list):
                    for p in raw_props:
                        if not isinstance(p, dict):
                            continue
                        nv = p.get("newValue")
                        if (
                            isinstance(nv, str)
                            and "allowanonymous" in nv.lower().replace(" ", "")
                        ):
                            anonymous_change = True
                            break
                        nm = p.get("name")
                        if (
                            isinstance(nm, str)
                            and "anonymous" in nm.lower()
                        ):
                            anonymous_change = True
                            break
            if anonymous_change:
                signal = "anonymous_site_permissions"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"M365 event {event_id} SitePermissionsModified "
                            f"to AllowAnonymousAccess on site="
                            f"{site_url_redacted or 'unknown'} — anonymous "
                            f"site access enabled, top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "SiteDeleted":
            signal = "site_deleted"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} SiteDeleted on site="
                        f"{site_url_redacted or 'unknown'} by upn_domain="
                        f"{upn_domain or 'unknown'} — site destruction"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation == "DLPRuleMatch":
            if dlp_severity == "high":
                signal = "dlp_rule_high"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FAIL",
                        detail=(
                            f"M365 event {event_id} DLPRuleMatch severity="
                            f"high rule={dlp_rule_name or 'unknown'} on "
                            f"object={object_id_last8 or 'unknown'} — DLP "
                            f"rule matched, top-priority"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif dlp_severity == "medium":
                signal = "dlp_rule_medium"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(
                            control_id, control_id
                        ),
                        result="FLAG",
                        detail=(
                            f"M365 event {event_id} DLPRuleMatch severity="
                            f"medium rule={dlp_rule_name or 'unknown'} on "
                            f"object={object_id_last8 or 'unknown'} — DLP "
                            f"rule matched"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif operation == "FileMalwareDetected":
            signal = "file_malware_detected"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} FileMalwareDetected on "
                        f"object={object_id_last8 or 'unknown'} — malware "
                        f"in storage, top-priority"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Cross-cutting: broad permission grant to external recipient.
        # Applies to any sharing/role-grant operation where the resolved
        # permission is FullControl/Owner and the recipient is external.
        # ----------------------------------------------------------------
        if is_broad_perm and (
            is_external_target_type or is_external_target_domain
        ):
            signal = "external_full_control_grant"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} sharingPermission="
                        f"{sharing_permission!r} granted to external "
                        f"target_type={sharing_target_type!r} "
                        f"target_domain={target_domain!r} on object="
                        f"{object_id_last8 or 'unknown'} — over-broad "
                        f"external grant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Synthetic pattern markers — informational on contributing events.
        # ----------------------------------------------------------------
        if upn_raw and upn_raw in bulk_download_actors:
            signal = "bulk_download_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"M365 event {event_id} upn_domain="
                        f"{upn_domain or 'unknown'} is part of a bulk-"
                        f"download pattern ("
                        f"{bulk_download_actors[upn_raw]} downloads > "
                        f"threshold {self.bulk_download_threshold} in "
                        f"{self.bulk_download_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bulk_download_count":
                            bulk_download_actors[upn_raw],
                        "bulk_download_threshold":
                            self.bulk_download_threshold,
                        "bulk_download_window_seconds":
                            self.bulk_download_window_seconds,
                    },
                )
            )
        if upn_raw and upn_raw in cross_site_actors:
            signal = "cross_site_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"M365 event {event_id} upn_domain="
                        f"{upn_domain or 'unknown'} is part of a cross-site "
                        f"pattern ({cross_site_actors[upn_raw]} distinct "
                        f"sites > threshold {self.cross_site_threshold} in "
                        f"{self.cross_site_window_seconds}s window — recon "
                        f"pattern)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_site_count": cross_site_actors[upn_raw],
                        "cross_site_threshold": self.cross_site_threshold,
                        "cross_site_window_seconds":
                            self.cross_site_window_seconds,
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
                        f"M365 event {event_id} operation={operation!r} on "
                        f"object={object_id_last8 or 'unknown'} workload="
                        f"{workload or 'unknown'} — audit-trail captured"
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
            f"Imported from Microsoft 365 Unified Audit Log: operation="
            f"{operation or 'unknown'} workload={workload or 'unknown'} "
            f"userType={user_type or 'unknown'} upn_domain="
            f"{upn_domain or 'unknown'} object="
            f"{object_id_last8 or 'unknown'}"
        )

        action_id = f"m365-{event_id[:48]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="sharepoint_onedrive_import",
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
        synthetic_id = f"m365-bulk-download-{uuid.uuid4()}"
        upn_domain = _redact_upn_to_domain(actor) or "unknown"
        evidence: dict[str, Any] = {
            "m365_event_id": synthetic_id,
            "user_principal_name_domain": upn_domain,
            "bulk_download_count": count,
            "bulk_download_threshold": self.bulk_download_threshold,
            "bulk_download_window_seconds": self.bulk_download_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "sharepoint_onedrive",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"M365 synthetic finding: upn_domain={upn_domain} performed "
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
            source_type="sharepoint_onedrive_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Microsoft 365 Unified Audit Log: synthetic "
                f"bulk-download pattern for upn_domain={upn_domain} "
                f"count={count}>threshold={self.bulk_download_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_site_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_site_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"m365-cross-site-{uuid.uuid4()}"
        upn_domain = _redact_upn_to_domain(actor) or "unknown"
        evidence: dict[str, Any] = {
            "m365_event_id": synthetic_id,
            "user_principal_name_domain": upn_domain,
            "cross_site_count": count,
            "cross_site_threshold": self.cross_site_threshold,
            "cross_site_window_seconds": self.cross_site_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "sharepoint_onedrive",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"M365 synthetic finding: upn_domain={upn_domain} touched "
                f"{count} distinct sites in a "
                f"{self.cross_site_window_seconds}s window — exceeds cross-"
                f"site threshold {self.cross_site_threshold} (recon pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sharepoint_onedrive_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Microsoft 365 Unified Audit Log: synthetic "
                f"cross-site pattern for upn_domain={upn_domain} count="
                f"{count}>threshold={self.cross_site_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
