"""GCP Cloud Audit Logs importer — maps Google Cloud API-call audit records to AKSI controls.

GCP Cloud Audit Logs (https://cloud.google.com/logging/docs/audit) is the
canonical audit trail of a Google Cloud project: every Vertex AI prediction,
Cloud Functions / Cloud Run invocation, GKE control-plane action, IAM policy
mutation, Secret Manager retrieval, Cloud Storage object access, and Cloud KMS
key use is recorded as a ``LogEntry`` with a ``protoPayload`` of type
``google.cloud.audit.AuditLog``. For agents running on Google Cloud, Cloud
Audit Logs is the system-of-record for who-did-what across the entire
infrastructure — far broader than any application-level trace.

This importer ingests Cloud Logging exports in three on-disk shapes:

  1. ``{"entries": [...]}`` — the canonical Cloud Logging export envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one entry per line

Signal mapping (see shared/mappings/gcp-cloud-audit-aksi-controls.json):
  * aiplatform * Predict / GenerateContent / PredictionService.*    → PR-01 PASS
  * aiplatform * PublishModel / DeployModel                         → PR-05 FLAG
  * cloudfunctions * Invoke*                                        → PR-02 PASS
  * storage * storage.objects.get / list                            → PR-04 PASS
  * storage * storage.objects.create / delete                       → PR-04 FLAG
  * iam * SetIamPolicy / CreateRole / CreateServiceAccount / Grant* → PR-02 FLAG
  * iam * CreateServiceAccountKey                                   → PR-01 FLAG
  * iam * DeleteServiceAccountKey / DisableServiceAccount           → PR-05 PASS
  * secretmanager * AccessSecretVersion                             → PR-04 FLAG
  * cloudkms * Decrypt                                              → PR-04 PASS
  * cloudkms * DestroyCryptoKeyVersion / DisableCryptoKey           → PR-02 FAIL
  * status.code=7  PERMISSION_DENIED                                → PR-02 FAIL
  * status.code=16 UNAUTHENTICATED                                  → PR-01 FAIL
  * status.code=8  RESOURCE_EXHAUSTED                               → PR-02 FLAG
  * status.code=13 INTERNAL                                         → DE-01 FAIL
  * status.code=other-non-zero                                      → DE-01 FAIL
  * authorizationInfo[*].granted=false                              → PR-02 PASS (denial audit trail)
  * serviceAccountKeyName present                                   → PR-01 FLAG
  * cross-project pattern (same principalEmail, multiple projectIds)→ PR-02 FLAG synthetic

Sanitization (security-critical — Cloud Audit logs can contain object paths,
secret resource names, and request/response bodies):
  * ``request`` and ``response`` VALUES are NEVER stored. Only the top-level
    KEY LIST is captured (so an analyst can see *what kinds of* fields were
    sent, not the values themselves).
  * ``principalEmail`` local-part is redacted: ``alice@example.com`` →
    ``"***@example.com"``. The domain is preserved because cross-domain
    patterns (e.g. an external personal-domain caller hitting a corporate
    project) are themselves a security signal.
  * ``principalSubject`` is preserved verbatim — these are typed identifiers
    (e.g. ``serviceAccount:foo@bar.iam.gserviceaccount.com``), not secrets.
  * ``serviceAccountKeyName`` is reduced to a last-4 fingerprint. The full
    resource name embeds the key id and is not appropriate to retain.
  * ``callerIp`` is normalized: GCP-internal markers (``gce-internal-ip``,
    ``private``, ``::1``-like) preserved verbatim; RFC1918 preserved verbatim;
    public IPv4 reduced to a /16 pattern; public IPv6 reduced to a /32.
  * ``callerSuppliedUserAgent`` — first 80 chars + sha256 of the full string.
  * ``resourceName`` is trimmed so anything after ``/locations/<region>/`` is
    summarized rather than retained verbatim (the region itself is captured
    as a separate field for posture/region-attribution analysis).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``google-cloud-logging``; Cloud Logging JSON
exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/gcp_cloud_audit.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "gcp-cloud-audit-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallback if the mapping JSON is missing or malformed. Mirrors the
# canonical ``_metadata.method_patterns`` list in the JSON.
_DEFAULT_METHOD_PATTERNS: tuple[dict[str, Any], ...] = (
    {"service_name": "aiplatform.googleapis.com", "method_name": "*Predict*",
     "signal": "vertex_predict", "result": "PASS", "control": "PR-01"},
    {"service_name": "aiplatform.googleapis.com", "method_name": "*GenerateContent*",
     "signal": "vertex_generate_content", "result": "PASS", "control": "PR-01"},
    {"service_name": "aiplatform.googleapis.com", "method_name": "*PredictionService.*",
     "signal": "vertex_predict", "result": "PASS", "control": "PR-01"},
    {"service_name": "aiplatform.googleapis.com", "method_name": "*PublishModel*",
     "signal": "vertex_model_lifecycle", "result": "FLAG", "control": "PR-05"},
    {"service_name": "aiplatform.googleapis.com", "method_name": "*DeployModel*",
     "signal": "vertex_model_lifecycle", "result": "FLAG", "control": "PR-05"},
    {"service_name": "cloudfunctions.googleapis.com", "method_name": "*Invoke*",
     "signal": "cloudfunction_invoke", "result": "PASS", "control": "PR-02"},
    {"service_name": "storage.googleapis.com", "method_name": "*storage.objects.get*",
     "signal": "gcs_read", "result": "PASS", "control": "PR-04"},
    {"service_name": "storage.googleapis.com", "method_name": "*storage.objects.list*",
     "signal": "gcs_read", "result": "PASS", "control": "PR-04"},
    {"service_name": "storage.googleapis.com", "method_name": "*storage.objects.create*",
     "signal": "gcs_write", "result": "FLAG", "control": "PR-04"},
    {"service_name": "storage.googleapis.com", "method_name": "*storage.objects.delete*",
     "signal": "gcs_delete", "result": "FLAG", "control": "PR-04"},
    {"service_name": "iam.googleapis.com", "method_name": "*SetIamPolicy*",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"service_name": "iam.googleapis.com", "method_name": "*CreateRole*",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"service_name": "iam.googleapis.com", "method_name": "*CreateServiceAccount",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"service_name": "iam.googleapis.com", "method_name": "*Grant*",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"service_name": "iam.googleapis.com", "method_name": "*CreateServiceAccountKey*",
     "signal": "iam_key_issuance", "result": "FLAG", "control": "PR-01"},
    {"service_name": "iam.googleapis.com", "method_name": "*DeleteServiceAccountKey*",
     "signal": "iam_key_lifecycle", "result": "PASS", "control": "PR-05"},
    {"service_name": "iam.googleapis.com", "method_name": "*DisableServiceAccount*",
     "signal": "iam_key_lifecycle", "result": "PASS", "control": "PR-05"},
    {"service_name": "secretmanager.googleapis.com", "method_name": "*AccessSecretVersion*",
     "signal": "secret_access", "result": "FLAG", "control": "PR-04"},
    {"service_name": "cloudkms.googleapis.com", "method_name": "*Decrypt*",
     "signal": "kms_decrypt", "result": "PASS", "control": "PR-04"},
    {"service_name": "cloudkms.googleapis.com", "method_name": "*DestroyCryptoKeyVersion*",
     "signal": "kms_destroy_key", "result": "FAIL", "control": "PR-02"},
    {"service_name": "cloudkms.googleapis.com", "method_name": "*DisableCryptoKey*",
     "signal": "kms_destroy_key", "result": "FAIL", "control": "PR-02"},
)

# google.rpc.Code → signal/result/control. Code 0 = OK (no signal emitted).
_DEFAULT_STATUS_CODE_SIGNALS: dict[str, dict[str, str]] = {
    "7":  {"signal": "permission_denied", "result": "FAIL", "control": "PR-02"},
    "16": {"signal": "unauthenticated",   "result": "FAIL", "control": "PR-01"},
    "8":  {"signal": "resource_exhausted", "result": "FLAG", "control": "PR-02"},
    "9":  {"signal": "failed_precondition", "result": "FAIL", "control": "DE-01"},
    "13": {"signal": "internal_error",    "result": "FAIL", "control": "DE-01"},
}

_DEFAULT_CROSS_PROJECT_THRESHOLD = 1

# Internal/private caller-IP markers GCP uses verbatim in audit logs.
_GCP_INTERNAL_IP_MARKERS = frozenset(
    {"gce-internal-ip", "private", ""}
)

# Pattern: ``locations/<region>/...`` — used to extract a coarse region tag
# from resourceName without retaining the full hierarchical path.
_LOCATIONS_RE = re.compile(r"/locations/([^/]+)")


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the gcp-cloud-audit-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_principal_email(email: str | None) -> str | None:
    """Redact local part of an email: ``alice@example.com`` → ``"***@example.com"``.

    The domain is preserved because cross-domain patterns (e.g. a personal-
    domain caller hitting a corporate project) are themselves a posture signal.
    Service accounts (``…@gserviceaccount.com``) are redacted the same way —
    the local part of a service-account email is the account ID, which is an
    identifier the org may consider sensitive.
    """
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if not s or "@" not in s:
        return s or None
    local, _, domain = s.partition("@")
    if not local or not domain:
        return s
    return f"***@{domain}"


def _principal_email_domain(email: str | None) -> str | None:
    """Return the domain part of an email (``alice@example.com`` → ``example.com``)."""
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if "@" not in s:
        return None
    _, _, domain = s.partition("@")
    return domain or None


def _redact_service_account_key_name(name: str | None) -> str | None:
    """Reduce a service-account key resource name to a last-4 fingerprint.

    A key resource name looks like:
      projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/<keyId>

    We surface only the last 4 characters of the keyId. The path itself
    can leak service-account naming conventions and should not be retained.
    """
    if not name or not isinstance(name, str):
        return None
    s = name.strip()
    if not s:
        return None
    # Take the last path segment as the keyId.
    last = s.rsplit("/", 1)[-1]
    if len(last) <= 4:
        return f"key:***{last}"
    return f"key:***{last[-4:]}"


def _classify_caller_ip(caller_ip: str | None) -> str | None:
    """Normalize a Cloud Audit callerIp to a privacy-aware form.

    * GCP-internal markers (``gce-internal-ip``, ``private``) preserved verbatim.
    * RFC1918 / loopback / link-local preserved verbatim.
    * Public IPv4 reduced to a /16 pattern (first two octets + ``.0.0/16``).
    * Public IPv6 reduced to the first 32 bits + ``::/32``.
    * Anything that fails to parse is preserved verbatim (rare service markers).
    """
    if caller_ip is None:
        return None
    if not isinstance(caller_ip, str):
        return None
    ip = caller_ip.strip()
    if not ip:
        return None
    if ip.lower() in _GCP_INTERNAL_IP_MARKERS:
        return "GCP Internal" if ip.lower() == "gce-internal-ip" else ip
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
    # IPv6
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _redact_user_agent(ua: str | None) -> str | None:
    """First 80 chars + sha256 of the full string. Mirrors aws_cloudtrail
    semantics: the prefix gives an analyst the human-readable shape, the hash
    lets them correlate without retaining the full string (which can contain
    SDK build hashes, private telemetry tokens, internal hostnames)."""
    if not ua or not isinstance(ua, str):
        return None
    s = ua.strip()
    if not s:
        return None
    sha = hashlib.sha256(s.encode("utf-8")).hexdigest()
    if len(s) <= 80:
        return f"{s} (sha256={sha})"
    return f"{s[:80]} (sha256={sha})"


def _trim_resource_name(resource_name: str | None) -> str | None:
    """Keep ``projects/<p>/locations/<region>`` prefix and summarize the tail.

    Cloud Audit resource names can embed object paths and key fingerprints
    after the location segment. We retain enough to attribute an event to its
    project + region and replace the rest with ``/...`` so an analyst can see
    that further hierarchy existed without storing it.
    """
    if not resource_name or not isinstance(resource_name, str):
        return None
    s = resource_name.strip()
    if not s:
        return None
    m = _LOCATIONS_RE.search(s)
    if not m:
        # No /locations/ segment — preserve the first two path components only.
        parts = s.split("/")
        if len(parts) > 4:
            return "/".join(parts[:4]) + "/..."
        return s
    end = m.end()
    if end < len(s):
        return s[:end] + "/..."
    return s


def _extract_region(resource_name: str | None) -> str | None:
    """Pull the ``<region>`` token from ``locations/<region>`` if present."""
    if not resource_name or not isinstance(resource_name, str):
        return None
    m = _LOCATIONS_RE.search(resource_name)
    return m.group(1) if m else None


def _extract_project_id(resource_name: str | None) -> str | None:
    """Pull the ``<project>`` token from ``projects/<project>`` if present."""
    if not resource_name or not isinstance(resource_name, str):
        return None
    m = re.search(r"projects/([^/]+)", resource_name)
    return m.group(1) if m else None


def _top_level_keys(value: Any) -> list[str]:
    """Return the sorted top-level keys of a dict (values NEVER captured)."""
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    return []


def _matches_method_pattern(
    service_name: str, method_name: str, pattern: dict[str, Any]
) -> bool:
    src_pat = str(pattern.get("service_name", ""))
    name_pat = str(pattern.get("method_name", ""))
    return (
        fnmatch.fnmatchcase(service_name, src_pat)
        and fnmatch.fnmatchcase(method_name, name_pat)
    )


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class GcpCloudAuditImporter:
    """Parse a GCP Cloud Audit Logs export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_project_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        meta_patterns = meta.get("method_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._method_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._method_patterns = _DEFAULT_METHOD_PATTERNS
        meta_status = meta.get("status_code_signals")
        if isinstance(meta_status, dict) and meta_status:
            self._status_code_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_status.items()
                if isinstance(v, dict)
            }
        else:
            self._status_code_signals = dict(_DEFAULT_STATUS_CODE_SIGNALS)
        if cross_project_threshold is not None:
            self.cross_project_threshold = int(cross_project_threshold)
        else:
            self.cross_project_threshold = int(
                meta.get("cross_project_threshold", _DEFAULT_CROSS_PROJECT_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Cloud Audit export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Cloud Audit export content from a JSON or JSONL string."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"entries": [...]}`` / ``{"data": [...]}`` / JSONL / single entry."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [r for r in doc if isinstance(r, dict)]
            if isinstance(doc, dict):
                if "entries" in doc and isinstance(doc["entries"], list):
                    return [r for r in doc["entries"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-entry EvaluationResults plus cross-project synthetic findings."""
        # First pass: aggregate projectIds per principalEmail.
        principal_projects: dict[str, set[str]] = {}
        for entry in entries:
            payload = entry.get("protoPayload") or {}
            if not isinstance(payload, dict):
                continue
            auth = payload.get("authenticationInfo") or {}
            if not isinstance(auth, dict):
                continue
            email = auth.get("principalEmail")
            if not isinstance(email, str) or not email:
                continue
            project_id = _extract_project_id(payload.get("resourceName") or "")
            if not project_id:
                # Fall back to logName-derived project id: projects/<id>/logs/...
                log_name = entry.get("logName") or ""
                if isinstance(log_name, str):
                    project_id = _extract_project_id(log_name)
            if project_id:
                principal_projects.setdefault(email, set()).add(project_id)

        cross_project_principals = {
            email: sorted(projects)
            for email, projects in principal_projects.items()
            if len(projects) > self.cross_project_threshold
        }

        results = [
            self._parse_entry(
                entry,
                file_sha256=file_sha256,
                cross_project_principals=cross_project_principals,
            )
            for entry in entries
        ]

        for email, projects in sorted(cross_project_principals.items()):
            results.append(
                self._synthetic_cross_project_result(
                    principal_email=email,
                    project_ids=projects,
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
            "source_format": "gcp_cloud_audit",
            "source_tool_name": "gcp_cloud_audit",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_method(
        self, service_name: str, method_name: str
    ) -> dict[str, Any] | None:
        """Find the first method-pattern that matches; ``None`` if no match."""
        for pattern in self._method_patterns:
            if _matches_method_pattern(service_name, method_name, pattern):
                return pattern
        return None

    def _classify_status_code(self, code: int) -> dict[str, str] | None:
        """Resolve a google.rpc.Code; fall back to a generic DE-01 FAIL for
        unmapped non-zero codes."""
        if code == 0:
            return None
        key = str(int(code))
        if key in self._status_code_signals:
            return self._status_code_signals[key]
        return {"signal": "internal_error", "result": "FAIL", "control": "DE-01"}

    # ------------------------------------------------------------------
    # Per-entry parsing
    # ------------------------------------------------------------------

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_project_principals: dict[str, list[str]],
    ) -> EvaluationResult:
        payload = entry.get("protoPayload") or {}
        if not isinstance(payload, dict):
            payload = {}

        # Identity-level fields from the LogEntry envelope.
        operation = entry.get("operation") or {}
        if not isinstance(operation, dict):
            operation = {}
        op_id = str(operation.get("id") or "")
        event_id = str(
            entry.get("insertId")
            or op_id
            or uuid.uuid4()
        )
        timestamp = str(
            entry.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        severity = str(entry.get("severity") or "")
        log_name = str(entry.get("logName") or "")
        trace = str(entry.get("trace") or "")
        span_id = str(entry.get("spanId") or "")
        resource = entry.get("resource") or {}
        if not isinstance(resource, dict):
            resource = {}
        resource_type = str(resource.get("type") or "")

        service_name = str(payload.get("serviceName") or "").strip()
        method_name = str(payload.get("methodName") or "").strip()
        resource_name_raw = (
            payload.get("resourceName")
            if isinstance(payload.get("resourceName"), str)
            else None
        )
        resource_name_trimmed = _trim_resource_name(resource_name_raw)
        region = _extract_region(resource_name_raw)
        project_id = _extract_project_id(resource_name_raw) or _extract_project_id(
            log_name
        )

        # ---- authenticationInfo ----
        auth = payload.get("authenticationInfo") or {}
        if not isinstance(auth, dict):
            auth = {}
        principal_email_raw = (
            auth.get("principalEmail")
            if isinstance(auth.get("principalEmail"), str)
            else None
        )
        principal_email_redacted = _redact_principal_email(principal_email_raw)
        principal_domain = _principal_email_domain(principal_email_raw)
        principal_subject = (
            auth.get("principalSubject")
            if isinstance(auth.get("principalSubject"), str)
            else None
        )
        authority_selector = (
            auth.get("authoritySelector")
            if isinstance(auth.get("authoritySelector"), str)
            else None
        )
        sa_key_name_raw = (
            auth.get("serviceAccountKeyName")
            if isinstance(auth.get("serviceAccountKeyName"), str)
            else None
        )
        sa_key_fingerprint = _redact_service_account_key_name(sa_key_name_raw)
        is_service_account = bool(
            principal_email_raw
            and principal_email_raw.endswith("@gserviceaccount.com")
        ) or bool(
            principal_email_raw
            and ".iam.gserviceaccount.com" in principal_email_raw
        )

        # ---- authorizationInfo ----
        authz_raw = payload.get("authorizationInfo") or []
        granted_count = 0
        denied_count = 0
        permissions: list[str] = []
        if isinstance(authz_raw, list):
            for a in authz_raw:
                if not isinstance(a, dict):
                    continue
                granted = a.get("granted")
                if isinstance(granted, bool):
                    if granted:
                        granted_count += 1
                    else:
                        denied_count += 1
                perm = a.get("permission")
                if isinstance(perm, str) and perm:
                    permissions.append(perm)

        # ---- requestMetadata ----
        req_meta = payload.get("requestMetadata") or {}
        if not isinstance(req_meta, dict):
            req_meta = {}
        caller_ip_raw = (
            req_meta.get("callerIp")
            if isinstance(req_meta.get("callerIp"), str)
            else None
        )
        caller_ip_redacted = _classify_caller_ip(caller_ip_raw)
        user_agent_raw = (
            req_meta.get("callerSuppliedUserAgent")
            if isinstance(req_meta.get("callerSuppliedUserAgent"), str)
            else None
        )
        user_agent_redacted = _redact_user_agent(user_agent_raw)

        # ---- request / response (KEYS ONLY) ----
        request_keys = _top_level_keys(payload.get("request"))
        response_keys = _top_level_keys(payload.get("response"))

        # ---- status ----
        status = payload.get("status") or {}
        if not isinstance(status, dict):
            status = {}
        status_code_raw = status.get("code")
        # An empty {} status means SUCCESS (code 0 implicit).
        if isinstance(status_code_raw, bool) or not isinstance(
            status_code_raw, (int, float)
        ):
            status_code: int = 0
        else:
            status_code = int(status_code_raw)
        status_message = (
            str(status.get("message"))
            if isinstance(status.get("message"), str)
            else ""
        )

        num_response_items_raw = payload.get("numResponseItems")
        if isinstance(num_response_items_raw, (int, str)):
            try:
                num_response_items: int | None = int(num_response_items_raw)
            except (TypeError, ValueError):
                num_response_items = None
        else:
            num_response_items = None

        common_evidence: dict[str, Any] = {
            "gcp_audit_event_id": event_id,
            "service_name": service_name,
            "method_name": method_name,
            "resource_name_trimmed": resource_name_trimmed,
            "region": region,
            "project_id": project_id,
            "log_name": log_name,
            "resource_type": resource_type,
            "severity": severity,
            "timestamp": timestamp,
            "trace": trace,
            "span_id": span_id,
            "operation_id": op_id,
            "principal_email_redacted": principal_email_redacted,
            "principal_domain": principal_domain,
            "principal_subject": principal_subject,
            "authority_selector": authority_selector,
            "is_service_account_principal": is_service_account,
            "service_account_key_fingerprint": sa_key_fingerprint,
            "authorization_granted_count": granted_count,
            "authorization_denied_count": denied_count,
            "authorization_permissions": permissions,
            "caller_ip_redacted": caller_ip_redacted,
            "caller_user_agent_redacted": user_agent_redacted,
            "request_keys": request_keys,
            "response_keys": response_keys,
            "status_code": status_code,
            "status_message": status_message,
            "num_response_items": num_response_items,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "gcp_cloud_audit",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. status.code != 0 — failures are surfaced as the primary signal.
        # PERMISSION_DENIED is PR-02 FAIL (authz boundary), UNAUTHENTICATED is
        # PR-01 FAIL (identity boundary), RESOURCE_EXHAUSTED is PR-02 FLAG.
        # ----------------------------------------------------------------
        status_signal_meta = self._classify_status_code(status_code)
        method_pattern = self._classify_method(service_name, method_name)

        if status_signal_meta is not None:
            signal = status_signal_meta["signal"]
            control_id = _control_for(
                signal, self._mappings, status_signal_meta.get("control", "DE-01")
            )
            result = status_signal_meta.get("result", "FAIL")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"GCP Cloud Audit event {event_id} {service_name}:{method_name} "
                        f"failed with status.code={status_code} ({status_message!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif method_pattern is not None:
            signal = str(method_pattern.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(method_pattern.get("control", "PR-05"))
            )
            result = str(method_pattern.get("result", "PASS"))
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"GCP Cloud Audit event {event_id} {service_name}:{method_name} "
                        f"classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown service/method — surface as PR-05 FLAG so it does not
            # silently pass. Cloud Audit covers thousands of API methods; the
            # mapping table only encodes the high-signal subset.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GCP Cloud Audit event {event_id} {service_name}:{method_name} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. authorizationInfo[*].granted=false — additive PR-02 PASS.
        # The denial itself is the audit-trail evidence (not a failure of the
        # SDK to record). status.code carries the failure if any.
        # ----------------------------------------------------------------
        if denied_count > 0:
            signal = "authorization_denied"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"GCP Cloud Audit event {event_id} {service_name}:{method_name} "
                        f"includes {denied_count} authorization denial(s) — "
                        f"recorded as audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. serviceAccountKeyName present — PR-01 FLAG.
        # Long-lived SA keys are a credential class with elevated risk; the
        # importer surfaces them so a posture report can answer "which key
        # authenticated which call?".
        # ----------------------------------------------------------------
        if sa_key_fingerprint:
            signal = "service_account_key_auth"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GCP Cloud Audit event {event_id} {service_name}:{method_name} "
                        f"authenticated with a service-account key "
                        f"({sa_key_fingerprint})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Cross-project pattern — informational per-entry marker.
        # The synthetic per-principal finding is added in the second pass.
        # ----------------------------------------------------------------
        if (
            isinstance(principal_email_raw, str)
            and principal_email_raw in cross_project_principals
        ):
            signal = "cross_project_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GCP Cloud Audit event {event_id} principal "
                        f"{principal_email_redacted} is part of a cross-project "
                        f"pattern "
                        f"({len(cross_project_principals[principal_email_raw])} "
                        f"projects > threshold {self.cross_project_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_project_project_ids": cross_project_principals[
                            principal_email_raw
                        ],
                        "cross_project_threshold": self.cross_project_threshold,
                    },
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
            f"Imported from GCP Cloud Audit Logs: service_name={service_name} "
            f"method_name={method_name} "
            f"status_code={status_code} "
            f"region={region or 'unknown'} "
            f"project={project_id or 'unknown'}"
        )

        action_id_token = event_id[:32] if event_id else uuid.uuid4().hex
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"gcp-audit-{action_id_token}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="gcp_cloud_audit_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=trace or op_id or None,
        )

    def _synthetic_cross_project_result(
        self,
        *,
        principal_email: str,
        project_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-principal cross-project pattern finding.

        Captures the (redacted) principalEmail, the projectIds it touched, and
        the threshold used so downstream posture analysis can answer "which
        principals are crossing GCP project boundaries?".
        """
        signal = "cross_project_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        principal_redacted = (
            _redact_principal_email(principal_email) or principal_email
        )
        # Use a deterministic, redacted slug for the action_id so the synthetic
        # finding is stable across runs and never embeds the raw email.
        slug = hashlib.sha256(principal_email.encode("utf-8")).hexdigest()[:16]
        synthetic_id = f"gcp-audit-cross-project-{slug}"
        evidence: dict[str, Any] = {
            "gcp_audit_event_id": synthetic_id,
            "principal_email_redacted": principal_redacted,
            "principal_domain": _principal_email_domain(principal_email),
            "cross_project_project_ids": project_ids,
            "cross_project_project_count": len(project_ids),
            "cross_project_threshold": self.cross_project_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "gcp_cloud_audit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"GCP Cloud Audit synthetic finding: principal "
                f"{principal_redacted} touched {len(project_ids)} projects in "
                f"this export ({', '.join(project_ids)}) — exceeds "
                f"cross-project threshold {self.cross_project_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="gcp_cloud_audit_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from GCP Cloud Audit Logs: synthetic cross-project "
                f"pattern for principal={principal_redacted} "
                f"projects={len(project_ids)}>threshold="
                f"{self.cross_project_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
