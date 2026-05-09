"""AWS S3 Server Access Log importer — maps S3 data-plane object access to AKSI controls.

AWS CloudTrail covers IAM/control-plane operations on S3 (bucket creation, policy
changes, ACL grants) but does NOT capture data-plane object access by default —
that goes to S3 Server Access Logs (or, optionally, CloudTrail Data Events).
Agents reading and writing S3 objects (RAG corpora, training data, intermediate
artifacts, model outputs) generate millions of these events. This importer
closes the gap distinct from the CloudTrail importer: it ingests S3 server
access log exports and classifies each object-level operation against AKSI
controls.

Supported on-disk shapes:

  1. ``{"records": [...]}`` — JSON envelope (also accepts ``Records``)
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one record per line
  4. Single-record JSON object
  5. Raw S3 server-access-log text (space-delimited, fields may be quoted) —
     parsed with :func:`shlex.split` since URI/user-agent fields contain spaces

Signal mapping (see shared/mappings/aws-s3-access-aksi-controls.json):
  * ``REST.GET.OBJECT`` 200                       → PR-04 PASS  (read access)
  * ``REST.GET.OBJECT`` on sensitive-prefix       → PR-04 FLAG  (sensitive read)
  * ``REST.PUT.OBJECT`` 200                       → PR-04 PASS  (write captured)
  * ``REST.PUT.OBJECT`` on sensitive-prefix       → PR-04 FLAG  (sensitive write)
  * ``REST.DELETE.OBJECT``                        → PR-05 PASS  (audit trail)
  * ``BATCH.DELETE.OBJECT``                       → PR-02 FLAG  (bulk delete)
  * ``REST.LIST.BUCKETS``                         → PR-04 FLAG  (recon pattern)
  * ``REST.COPY.OBJECT`` cross-bucket             → PR-04 FLAG  (data movement)
  * ``REST.PUT.ACL``                              → PR-02 FLAG  (ACL change)
  * ``REST.PUT.ENCRYPTION``                       → PR-04 PASS  (encryption set)
  * ``REST.PUT.BUCKETPOLICY``                     → PR-02 FLAG  (policy change)
  * 403 + AccessDenied                            → PR-02 PASS  (correctly denied)
  * 403 + AccessDenied on internal service        → PR-02 FLAG  (broken IAM)
  * requester=AnonymousUser / auth=AnonymousUser  → PR-01 FAIL  (public access)
  * tls_version in {TLSv1.0, TLSv1.1}             → PR-04 FAIL  (legacy TLS)
  * signature_version=SigV2                       → PR-04 FLAG  (deprecated)
  * bytes_sent > 100MB on single GET              → PR-04 FLAG  (large egress)
  * bucket name "public/prod/internal" cross-acct → PR-04 FLAG  (boundary cross)
  * Mass-read pattern (>N reads sensitive prefix) → PR-04 FAIL  synthetic
  * Cross-bucket pattern (>N distinct buckets)    → PR-02 FLAG  synthetic
  * Failed-then-success on similar prefix         → PR-01 FLAG  synthetic

Sanitization (security-critical — S3 keys often encode customer IDs, document
names, and tenant structure):
  * ``key`` is normalized to ``directory/`` + ``.extension`` only. Concrete
    example: ``"customers/12345/ssn.pdf"`` → directory ``"customers/"``,
    extension ``".pdf"``. The full key is NEVER stored.
  * ``request_uri`` is broken down to ``operation + bucket + sanitized-key``;
    the raw URI is dropped.
  * ``referer`` and ``user_agent`` are truncated to first 80 chars + sha256.
  * ``remote_ip`` is masked to a ``/16`` (IPv4) or ``/32`` (IPv6) network;
    private/loopback/link-local addresses are preserved verbatim.
  * ``version_id`` retains last 8 characters only.
  * ``bucket`` is preserved verbatim up to 30 chars + last-8 sha256 fingerprint
    when longer (bucket names are public-ish but encode tenant info).
  * ``requester`` IAM-user ARNs are kept intact (they are public identifiers);
    service-role random IDs (``AROA...``, ``AIDA...``) are masked to last-8.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``boto3`` / ``botocore``; S3 access logs are parsed
with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import shlex
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/aws_s3_access.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "aws-s3-access-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default operation patterns — used as fallback if mapping JSON is missing.
_DEFAULT_OPERATION_PATTERNS: tuple[dict[str, Any], ...] = (
    {"operation": "REST.GET.OBJECT", "signal": "s3_object_read",
     "result": "PASS", "control": "PR-04"},
    {"operation": "WEBSITE.GET.OBJECT", "signal": "s3_object_read",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.HEAD.OBJECT", "signal": "s3_object_head",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.PUT.OBJECT", "signal": "s3_object_write",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.POST.OBJECT", "signal": "s3_object_write",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.DELETE.OBJECT", "signal": "s3_object_delete",
     "result": "PASS", "control": "PR-05"},
    {"operation": "BATCH.DELETE.OBJECT", "signal": "s3_batch_delete",
     "result": "FLAG", "control": "PR-02"},
    {"operation": "REST.LIST.BUCKETS", "signal": "s3_list_buckets",
     "result": "FLAG", "control": "PR-04"},
    {"operation": "REST.COPY.OBJECT", "signal": "s3_object_copy",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.COPY.OBJECT_GET", "signal": "s3_object_copy",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.PUT.ACL", "signal": "s3_acl_change",
     "result": "FLAG", "control": "PR-02"},
    {"operation": "REST.GET.ACL", "signal": "s3_acl_read",
     "result": "PASS", "control": "PR-05"},
    {"operation": "REST.PUT.ENCRYPTION", "signal": "s3_encryption_change",
     "result": "PASS", "control": "PR-04"},
    {"operation": "REST.PUT.BUCKETPOLICY", "signal": "s3_bucket_policy_change",
     "result": "FLAG", "control": "PR-02"},
    {"operation": "REST.DELETE.BUCKETPOLICY", "signal": "s3_bucket_policy_change",
     "result": "FLAG", "control": "PR-02"},
    {"operation": "S3.EXPIRE.OBJECT", "signal": "s3_lifecycle_expire",
     "result": "PASS", "control": "PR-05"},
)

_DEFAULT_ERROR_CODE_SIGNALS: dict[str, dict[str, str]] = {
    "AccessDenied": {"signal": "s3_access_denied", "result": "PASS", "control": "PR-02"},
    "AllAccessDisabled": {"signal": "s3_access_denied", "result": "PASS", "control": "PR-02"},
    "InvalidAccessKeyId": {"signal": "s3_access_denied", "result": "FAIL", "control": "PR-01"},
    "SignatureDoesNotMatch": {"signal": "s3_signature_mismatch", "result": "FAIL", "control": "PR-01"},
    "RequestTimeout": {"signal": "s3_request_timeout", "result": "FLAG", "control": "DE-01"},
    "InternalError": {"signal": "s3_internal_error", "result": "FAIL", "control": "DE-01"},
    "ServiceUnavailable": {"signal": "s3_internal_error", "result": "FAIL", "control": "DE-01"},
}

_DEFAULT_SENSITIVE_PREFIX_PATTERNS: tuple[str, ...] = (
    "customer-*",
    "customers/*",
    "payroll/*",
    "hr/*",
    "secrets/*",
    "keys/*",
    "credentials/*",
    "backup/*",
)

_DEFAULT_MASS_READ_THRESHOLD = 100
_DEFAULT_CROSS_BUCKET_THRESHOLD = 5
_DEFAULT_LARGE_EGRESS_BYTES = 100_000_000
_DEFAULT_FAILED_THEN_SUCCESS_WINDOW_S = 3600

_LEGACY_TLS_VERSIONS: frozenset[str] = frozenset({"TLSv1.0", "TLSv1.1", "TLSv1"})
_PUBLIC_BUCKET_NAME_TOKENS: tuple[str, ...] = ("public", "prod", "internal")
_ANONYMOUS_TOKENS: frozenset[str] = frozenset({"AnonymousUser", "anonymous"})

# Raw S3 server access log canonical field order (the v2 default — augmented
# fields like access_point_arn, acl_required appear at the end and may be
# absent in older logs). We pad missing trailing fields with ``"-"``.
_RAW_LOG_FIELDS: tuple[str, ...] = (
    "bucket_owner",
    "bucket",
    "time",
    "remote_ip",
    "requester",
    "request_id",
    "operation",
    "key",
    "request_uri",
    "http_status",
    "error_code",
    "bytes_sent",
    "object_size",
    "total_time_ms",
    "turn_around_time_ms",
    "referer",
    "user_agent",
    "version_id",
    "host_id",
    "signature_version",
    "cipher_suite",
    "auth_type",
    "host_header",
    "tls_version",
    "access_point_arn",
    "acl_required",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
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


def _classify_remote_ip(remote_ip: str | None) -> str | None:
    """Mask a public IPv4 to /16, IPv6 to /32; preserve private/loopback verbatim."""
    if not remote_ip or not isinstance(remote_ip, str):
        return None
    ip = remote_ip.strip()
    if not ip or ip == "-":
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
    # IPv6
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _redact_bucket(bucket: str | None) -> str | None:
    """Bucket names are public-ish, but encode tenant info. Keep first 30 + last-8 fingerprint."""
    if not bucket or not isinstance(bucket, str):
        return None
    b = bucket.strip()
    if not b or b == "-":
        return None
    if len(b) <= 30:
        return b
    fp = hashlib.sha256(b.encode("utf-8")).hexdigest()[:8]
    return f"{b[:30]}...{fp}"


def _redact_requester(requester: str | None) -> str | None:
    """Keep IAM-user ARNs intact; mask AROA/AIDA service-role randoms to last-8."""
    if not requester or not isinstance(requester, str):
        return None
    r = requester.strip()
    if not r or r == "-":
        return None
    # Anonymous markers preserved verbatim.
    if r in _ANONYMOUS_TOKENS:
        return r
    # ARNs are public identifiers — keep intact.
    if r.startswith("arn:"):
        return r
    # Service-role / IAM-user random IDs (``AROA...``, ``AIDA...``, ``AIDX...``).
    # These are 4-char prefix + random tail. Keep prefix + last 8.
    if len(r) > 12 and r[:4].isalpha() and r[:4].isupper():
        # Some logs render as "AROA1234ABCD:session-name" — split on ':' first.
        head, _, tail = r.partition(":")
        if len(head) > 8:
            head = f"{head[:4]}...{head[-8:]}"
        return f"{head}:{tail}" if tail else head
    return r


def _hash_truncate(value: str | None, *, head_len: int = 80) -> str | None:
    """Return ``<first head_len chars>|sha256:<8>`` or ``None`` for empty."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v == "-":
        return None
    digest = hashlib.sha256(v.encode("utf-8")).hexdigest()[:8]
    if len(v) <= head_len:
        return f"{v}|sha256:{digest}"
    return f"{v[:head_len]}|sha256:{digest}"


def _redact_version_id(version_id: str | None) -> str | None:
    if not version_id or not isinstance(version_id, str):
        return None
    v = version_id.strip()
    if not v or v == "-":
        return None
    if len(v) <= 8:
        return v
    return f"...{v[-8:]}"


def _normalize_key(key: str | None) -> tuple[str | None, str | None]:
    """Normalize an S3 key to ``(directory, extension)`` — NEVER store the full key.

    Examples:
      * ``"customers/12345/ssn.pdf"`` -> (``"customers/"``, ``".pdf"``)
      * ``"docs/report"``             -> (``"docs/"``, ``""``)
      * ``"top-level.json"``          -> (``""``, ``".json"``)
      * ``"-"`` / ``""`` / ``None``   -> (``None``, ``None``)
    """
    if not key or not isinstance(key, str):
        return None, None
    k = key.strip()
    if not k or k == "-":
        return None, None
    # Directory = up to and including the FIRST '/' (top-level prefix only —
    # do not leak deep tenant structure like ``customers/<customer-id>/``).
    if "/" in k:
        first_slash = k.index("/")
        directory = k[: first_slash + 1]
    else:
        directory = ""
    # Extension = last '.' suffix on the basename, lowercased; cap at 12 chars.
    basename = k.rsplit("/", 1)[-1]
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1].lower()
        if len(ext) > 12:
            ext = ext[:12]
    else:
        ext = ""
    return directory, ext


def _matches_sensitive_prefix(
    key: str | None, patterns: tuple[str, ...]
) -> str | None:
    """Return the first matching glob pattern, or ``None``."""
    if not key or not isinstance(key, str):
        return None
    k = key.strip()
    if not k or k == "-":
        return None
    for pat in patterns:
        if fnmatch.fnmatchcase(k, pat):
            return pat
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if not v or v == "-":
            return None
        try:
            return int(v)
        except ValueError:
            return None
    return None


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        if not v or v == "-":
            return None
        return v
    return str(value)


def _parse_event_time(value: str | None) -> datetime | None:
    """Parse an S3 access-log time field (``[06/May/2026:12:34:56 +0000]``) or ISO 8601."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v == "-":
        return None
    # Strip square brackets that S3 raw logs use.
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    # Try S3 access-log style first.
    for fmt in (
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            dt = datetime.strptime(v, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Fallback: fromisoformat (handles ``+00:00`` style).
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _bucket_from_request_uri(uri: str | None) -> str | None:
    """Extract bucket name from a virtual-hosted/path-style request URI."""
    if not uri or not isinstance(uri, str):
        return None
    parts = uri.split()
    if len(parts) < 2:
        return None
    path = parts[1]
    # Path-style: ``/<bucket>/<key>?...``
    if path.startswith("/"):
        path = path.lstrip("/")
        if not path:
            return None
        bucket = path.split("/", 1)[0].split("?", 1)[0]
        return bucket or None
    return None


def _is_internal_requester(requester: str | None) -> bool:
    """Heuristic: an internal service if the ARN/principal references a role
    rather than an external/anonymous principal."""
    if not requester or not isinstance(requester, str):
        return False
    r = requester.strip()
    if r in _ANONYMOUS_TOKENS or r == "-":
        return False
    if r.startswith("arn:aws:iam::") and ":role/" in r:
        return True
    if r.startswith("arn:aws:sts::") and ":assumed-role/" in r:
        return True
    # Assumed-role ID prefix.
    return r.startswith("AROA")


def _is_public_bucket_name(bucket: str | None) -> bool:
    if not bucket or not isinstance(bucket, str):
        return False
    low = bucket.lower()
    return any(tok in low for tok in _PUBLIC_BUCKET_NAME_TOKENS)


# ---------------------------------------------------------------------------
# Raw log parsing (space-delimited text format)
# ---------------------------------------------------------------------------


def _parse_raw_log_line(line: str) -> dict[str, Any] | None:
    """Parse a single raw S3 server-access-log line into a record dict.

    The S3 raw format is space-delimited with quoted strings. ``time`` is
    bracketed (``[06/May/2026:12:34:56 +0000]``) — this contains a space, so
    we cannot use plain ``shlex`` directly; we rejoin the bracketed token.
    """
    if not line or not line.strip():
        return None
    raw = line.strip()
    # The bracketed time token contains a space; pre-merge it so shlex sees
    # one atom. Find ``[...]`` first (greedy on closing bracket).
    if "[" in raw and "]" in raw:
        lb = raw.index("[")
        rb = raw.index("]", lb)
        merged_time = raw[lb : rb + 1].replace(" ", " ")  # NBSP placeholder
        raw = raw[:lb] + merged_time + raw[rb + 1 :]
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError:
        return None
    # Restore time spaces.
    tokens = [t.replace(" ", " ") for t in tokens]
    if len(tokens) < 8:
        return None
    # Pad missing trailing fields with "-".
    fields = list(_RAW_LOG_FIELDS)
    record: dict[str, Any] = {}
    for i, name in enumerate(fields):
        record[name] = tokens[i] if i < len(tokens) else "-"
    return record


def _looks_like_raw_log(text: str) -> bool:
    """Heuristic: raw S3 logs start with a hex bucket-owner token (no ``{``/``[``)."""
    stripped = text.lstrip()
    if not stripped:
        return False
    first_char = stripped[0]
    if first_char in "{[":
        return False
    # Bucket owner is a 64-char hex (canonical user ID). Look at the first
    # token of the first line.
    first_line = stripped.splitlines()[0].strip()
    parts = first_line.split(None, 1)
    if not parts:
        return False
    owner = parts[0]
    return len(owner) >= 16 and all(c in "0123456789abcdefABCDEF" for c in owner)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class AwsS3AccessImporter:
    """Parse an S3 server access-log export and convert each record to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        sensitive_prefix_patterns: tuple[str, ...] | list[str] | None = None,
        mass_read_threshold: int | None = None,
        cross_bucket_threshold: int | None = None,
        large_egress_threshold_bytes: int | None = None,
        failed_then_success_window_seconds: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Operation patterns precedence: mapping > defaults.
        meta_ops = meta.get("operation_patterns")
        if isinstance(meta_ops, list) and meta_ops:
            self._operation_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_ops if isinstance(p, dict)
            )
        else:
            self._operation_patterns = _DEFAULT_OPERATION_PATTERNS
        # Error code signals.
        meta_err = meta.get("error_code_signals")
        if isinstance(meta_err, dict) and meta_err:
            self._error_code_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_err.items()
                if isinstance(v, dict)
            }
        else:
            self._error_code_signals = dict(_DEFAULT_ERROR_CODE_SIGNALS)
        # Sensitive prefix patterns: explicit arg > metadata > defaults.
        if sensitive_prefix_patterns is not None:
            self.sensitive_prefix_patterns = tuple(
                str(p) for p in sensitive_prefix_patterns
            )
        else:
            meta_sp = meta.get("sensitive_prefix_patterns")
            if isinstance(meta_sp, list) and meta_sp:
                self.sensitive_prefix_patterns = tuple(str(p) for p in meta_sp)
            else:
                self.sensitive_prefix_patterns = _DEFAULT_SENSITIVE_PREFIX_PATTERNS
        # Numeric thresholds.
        self.mass_read_threshold = int(
            mass_read_threshold
            if mass_read_threshold is not None
            else meta.get("mass_read_threshold", _DEFAULT_MASS_READ_THRESHOLD)
        )
        self.cross_bucket_threshold = int(
            cross_bucket_threshold
            if cross_bucket_threshold is not None
            else meta.get("cross_bucket_threshold", _DEFAULT_CROSS_BUCKET_THRESHOLD)
        )
        self.large_egress_threshold_bytes = int(
            large_egress_threshold_bytes
            if large_egress_threshold_bytes is not None
            else meta.get("large_egress_threshold_bytes", _DEFAULT_LARGE_EGRESS_BYTES)
        )
        self.failed_then_success_window_seconds = int(
            failed_then_success_window_seconds
            if failed_then_success_window_seconds is not None
            else meta.get(
                "failed_then_success_window_seconds",
                _DEFAULT_FAILED_THEN_SUCCESS_WINDOW_S,
            )
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an S3 access-log export file (JSON / JSONL / raw text) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse S3 access-log content from a JSON / JSONL / raw-text string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Auto-detect ``{records}`` / ``{Records}`` / ``{data}`` / JSONL / single / raw."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                jsonl_records = list(_iter_jsonl(text))
                if jsonl_records:
                    return jsonl_records
                return []
            if isinstance(doc, list):
                return [r for r in doc if isinstance(r, dict)]
            if isinstance(doc, dict):
                for key in ("records", "Records", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                return [doc]
            return []
        # Either JSONL or raw S3 access-log text.
        if _looks_like_raw_log(text):
            records: list[dict[str, Any]] = []
            for line in text.splitlines():
                rec = _parse_raw_log_line(line)
                if rec is not None:
                    records.append(rec)
            return records
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Per-record results plus mass-read / cross-bucket / failed-then-success synthetics."""
        # First pass: per-requester aggregations.
        # mass-read: requester -> list of (event_time, bucket, raw_key)
        sensitive_reads: dict[str, list[tuple[datetime | None, str, str]]] = {}
        # cross-bucket: requester -> set[bucket]
        requester_buckets: dict[str, set[str]] = {}
        # failed-then-success: requester -> list[(time, key, status)]
        access_attempts: dict[str, list[tuple[datetime | None, str, int]]] = {}

        for rec in records:
            requester = _coerce_str(rec.get("requester"))
            bucket = _coerce_str(rec.get("bucket"))
            operation = _coerce_str(rec.get("operation")) or ""
            key = _coerce_str(rec.get("key"))
            status = _coerce_int(rec.get("http_status"))
            event_dt = _parse_event_time(_coerce_str(rec.get("time")))

            if requester and bucket:
                requester_buckets.setdefault(requester, set()).add(bucket)

            if (
                requester
                and key
                and operation in {"REST.GET.OBJECT", "WEBSITE.GET.OBJECT"}
                and status == 200
                and _matches_sensitive_prefix(key, self.sensitive_prefix_patterns)
            ):
                sensitive_reads.setdefault(requester, []).append(
                    (event_dt, bucket or "", key)
                )

            if requester and key and status is not None:
                access_attempts.setdefault(requester, []).append(
                    (event_dt, key, status)
                )

        # Determine principals exceeding mass-read threshold within any 1h window.
        mass_read_principals: dict[str, dict[str, Any]] = {}
        for requester, events in sensitive_reads.items():
            count = len(events)
            if count <= self.mass_read_threshold:
                continue
            # Time-window check (1h sliding); if any event lacks a parsed time,
            # fall back to the gross count test.
            triggers_window = False
            timed_events = sorted(
                ((dt, b, k) for dt, b, k in events if dt is not None),
                key=lambda e: e[0],
            )
            if timed_events:
                window = timedelta(seconds=3600)
                left = 0
                for right in range(len(timed_events)):
                    while (
                        timed_events[right][0] - timed_events[left][0] > window
                    ):
                        left += 1
                    if right - left + 1 > self.mass_read_threshold:
                        triggers_window = True
                        break
            else:
                triggers_window = True
            if triggers_window:
                mass_read_principals[requester] = {
                    "read_count": count,
                    "buckets": sorted({b for _, b, _ in events if b}),
                }

        # Cross-bucket pattern principals.
        broad_bucket_principals: dict[str, list[str]] = {
            requester: sorted(bks)
            for requester, bks in requester_buckets.items()
            if len(bks) > self.cross_bucket_threshold
        }

        # Failed-then-success pattern principals.
        failed_then_success_principals: dict[str, dict[str, Any]] = {}
        window = timedelta(seconds=self.failed_then_success_window_seconds)
        for requester, attempts in access_attempts.items():
            timed = sorted(
                ((dt, k, s) for dt, k, s in attempts if dt is not None),
                key=lambda a: a[0],
            )
            triggered = False
            for i, (dt_i, k_i, s_i) in enumerate(timed):
                if s_i != 403:
                    continue
                # Compare prefix: directory + first 8 chars of basename, fallback to first 8 chars.
                prefix_i = _prefix_for_compare(k_i)
                for j in range(i + 1, len(timed)):
                    dt_j, k_j, s_j = timed[j]
                    if dt_j - dt_i > window:
                        break
                    if s_j == 200 and _prefix_for_compare(k_j) == prefix_i:
                        triggered = True
                        failed_then_success_principals[requester] = {
                            "denied_key_prefix": prefix_i,
                            "denied_at": dt_i.isoformat(),
                            "succeeded_at": dt_j.isoformat(),
                        }
                        break
                if triggered:
                    break

        results = [
            self._parse_record(
                rec,
                file_sha256=file_sha256,
                mass_read_principals=mass_read_principals,
                broad_bucket_principals=broad_bucket_principals,
                failed_then_success_principals=failed_then_success_principals,
            )
            for rec in records
        ]

        # Synthetic results.
        for requester, info in sorted(mass_read_principals.items()):
            results.append(
                self._synthetic_mass_read_result(
                    requester=requester,
                    read_count=int(info["read_count"]),
                    buckets=list(info["buckets"]),
                    file_sha256=file_sha256,
                )
            )
        for requester, buckets in sorted(broad_bucket_principals.items()):
            results.append(
                self._synthetic_cross_bucket_result(
                    requester=requester,
                    buckets=buckets,
                    file_sha256=file_sha256,
                )
            )
        for requester, info in sorted(failed_then_success_principals.items()):
            results.append(
                self._synthetic_failed_then_success_result(
                    requester=requester,
                    info=info,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self, *, file_sha256: str | None, event_id: str | None = None
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "aws_s3_access",
            "source_tool_name": "aws_s3_access",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_operation(self, operation: str) -> dict[str, Any] | None:
        for pattern in self._operation_patterns:
            if fnmatch.fnmatchcase(operation, str(pattern.get("operation", ""))):
                return pattern
        return None

    def _classify_error_code(self, error_code: str) -> dict[str, str] | None:
        return self._error_code_signals.get(error_code)

    # ------------------------------------------------------------------
    # Per-record parsing
    # ------------------------------------------------------------------

    def _parse_record(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        mass_read_principals: dict[str, dict[str, Any]],
        broad_bucket_principals: dict[str, list[str]],
        failed_then_success_principals: dict[str, dict[str, Any]],
    ) -> EvaluationResult:
        request_id = _coerce_str(record.get("request_id")) or str(uuid.uuid4())
        event_id = request_id
        operation = _coerce_str(record.get("operation")) or ""
        bucket = _coerce_str(record.get("bucket"))
        bucket_redacted = _redact_bucket(bucket)
        raw_key = _coerce_str(record.get("key"))
        key_dir, key_ext = _normalize_key(raw_key)
        sensitive_match = _matches_sensitive_prefix(
            raw_key, self.sensitive_prefix_patterns
        )

        time_raw = _coerce_str(record.get("time"))
        event_dt = _parse_event_time(time_raw)
        event_time_iso = (
            event_dt.isoformat() if event_dt else (
                time_raw or datetime.now(timezone.utc).isoformat()
            )
        )

        http_status = _coerce_int(record.get("http_status"))
        error_code = _coerce_str(record.get("error_code"))
        bytes_sent = _coerce_int(record.get("bytes_sent"))
        object_size = _coerce_int(record.get("object_size"))
        total_time_ms = _coerce_int(record.get("total_time_ms"))
        turn_around_time_ms = _coerce_int(record.get("turn_around_time_ms"))

        requester_raw = _coerce_str(record.get("requester"))
        requester_redacted = _redact_requester(requester_raw)
        is_anonymous = (
            requester_raw in _ANONYMOUS_TOKENS
            or _coerce_str(record.get("auth_type")) in _ANONYMOUS_TOKENS
            or (
                isinstance(record.get("auth_type"), str)
                and record["auth_type"].strip().lower() == "anonymoususer"
            )
        )

        auth_type = _coerce_str(record.get("auth_type"))
        signature_version = _coerce_str(record.get("signature_version"))
        tls_version = _coerce_str(record.get("tls_version"))
        cipher_suite_present = bool(_coerce_str(record.get("cipher_suite")))
        remote_ip_redacted = _classify_remote_ip(
            _coerce_str(record.get("remote_ip"))
        )
        version_id_redacted = _redact_version_id(
            _coerce_str(record.get("version_id"))
        )
        referer_redacted = _hash_truncate(_coerce_str(record.get("referer")))
        user_agent_redacted = _hash_truncate(_coerce_str(record.get("user_agent")))
        host_header = _coerce_str(record.get("host_header"))
        access_point_arn = _coerce_str(record.get("access_point_arn"))

        # request_uri is decomposed; raw form not stored.
        request_uri_raw = _coerce_str(record.get("request_uri"))
        request_uri_method = None
        request_uri_bucket = None
        if request_uri_raw:
            parts = request_uri_raw.split()
            if parts:
                request_uri_method = parts[0]
            request_uri_bucket = _bucket_from_request_uri(request_uri_raw)

        common_evidence: dict[str, Any] = {
            "s3_request_id": request_id,
            "operation": operation,
            "http_status": http_status,
            "error_code": error_code,
            "bucket_redacted": bucket_redacted,
            "key_directory": key_dir,
            "key_extension": key_ext,
            "key_sensitive_prefix_match": sensitive_match,
            "request_uri_method": request_uri_method,
            "request_uri_bucket": request_uri_bucket,
            "requester_redacted": requester_redacted,
            "auth_type": auth_type,
            "signature_version": signature_version,
            "tls_version": tls_version,
            "cipher_suite_present": cipher_suite_present,
            "remote_ip_redacted": remote_ip_redacted,
            "version_id_redacted": version_id_redacted,
            "referer_redacted": referer_redacted,
            "user_agent_redacted": user_agent_redacted,
            "host_header": host_header,
            "access_point_arn": access_point_arn,
            "bytes_sent": bytes_sent,
            "object_size": object_size,
            "total_time_ms": total_time_ms,
            "turn_around_time_ms": turn_around_time_ms,
            "event_time": event_time_iso,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "aws_s3_access",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Anonymous request — bucket must not be public unless intentional.
        # ----------------------------------------------------------------
        if is_anonymous:
            signal = "anonymous_request"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"S3 request {event_id} on bucket "
                        f"{bucket_redacted or '?'} performed anonymously — "
                        f"public access pattern"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Legacy TLS — protocol downgrade is a PR-04 FAIL.
        # ----------------------------------------------------------------
        if tls_version in _LEGACY_TLS_VERSIONS:
            signal = "legacy_tls"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"S3 request {event_id} used legacy TLS "
                        f"{tls_version!r} — modern endpoints require TLSv1.2+"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Deprecated SigV2 — Sigv2 has been deprecated for new buckets.
        # ----------------------------------------------------------------
        if signature_version == "SigV2":
            signal = "sigv2_deprecated"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} used deprecated signature "
                        f"version SigV2 — migrate clients to SigV4"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Error-code-driven signals.
        # ----------------------------------------------------------------
        error_signal_meta = (
            self._classify_error_code(error_code) if error_code else None
        )
        pattern = self._classify_operation(operation) if operation else None

        if error_signal_meta is not None:
            signal = error_signal_meta["signal"]
            base_result = error_signal_meta.get("result", "PASS")
            control_id = _control_for(
                signal, self._mappings, error_signal_meta.get("control", "PR-02")
            )
            # Broken-IAM heuristic: a 403 AccessDenied to an internal service
            # should be a FLAG (the service was supposed to have access).
            if (
                signal == "s3_access_denied"
                and http_status == 403
                and _is_internal_requester(requester_raw)
            ):
                base_result = "FLAG"
                detail = (
                    f"S3 request {event_id} {operation} returned 403 "
                    f"AccessDenied to internal service {requester_redacted} — "
                    f"likely broken IAM"
                )
            else:
                detail = (
                    f"S3 request {event_id} {operation} failed with "
                    f"error_code={error_code!r} status={http_status}"
                )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=base_result,
                    detail=detail,
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif pattern is not None:
            signal = str(pattern.get("signal", "unknown_operation"))
            control_id = _control_for(
                signal, self._mappings, str(pattern.get("control", "PR-05"))
            )
            result = str(pattern.get("result", "PASS"))
            # Sensitive prefix overrides PASS to FLAG for read/write.
            if signal == "s3_object_read" and sensitive_match:
                signal = "sensitive_prefix_read"
                result = "FLAG"
                control_id = _control_for(signal, self._mappings, "PR-04")
            elif signal == "s3_object_write" and sensitive_match:
                signal = "sensitive_prefix_write"
                result = "FLAG"
                control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"S3 request {event_id} {operation} on "
                        f"bucket={bucket_redacted or '?'} "
                        f"key_dir={key_dir or '-'} "
                        f"classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif operation:
            signal = "unknown_operation"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} operation={operation!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Cross-bucket COPY — REST.COPY.OBJECT where source bucket
        #    differs from destination bucket. The destination bucket is
        #    in `bucket`; the source is in request_uri's x-amz-copy-source
        #    header. We approximate by checking request_uri bucket vs bucket.
        # ----------------------------------------------------------------
        if operation in {"REST.COPY.OBJECT", "REST.COPY.OBJECT_GET"}:
            copy_source_header = _coerce_str(record.get("copy_source"))
            source_bucket: str | None = None
            if copy_source_header:
                # Form: ``/source-bucket/key`` or ``source-bucket/key``.
                cs = copy_source_header.lstrip("/")
                source_bucket = cs.split("/", 1)[0] if cs else None
            elif request_uri_bucket and bucket and request_uri_bucket != bucket:
                source_bucket = request_uri_bucket
            if (
                source_bucket
                and bucket
                and source_bucket != bucket
            ):
                signal = "cross_bucket_copy"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"S3 request {event_id} REST.COPY.OBJECT moves data "
                            f"from {_redact_bucket(source_bucket)} to "
                            f"{bucket_redacted} — cross-bucket data movement"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "source_bucket_redacted": _redact_bucket(source_bucket),
                        },
                    )
                )

        # ----------------------------------------------------------------
        # 6. Large data egress — single GET above threshold.
        # ----------------------------------------------------------------
        if (
            operation in {"REST.GET.OBJECT", "WEBSITE.GET.OBJECT"}
            and bytes_sent is not None
            and bytes_sent > self.large_egress_threshold_bytes
        ):
            signal = "large_egress"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} GET egressed "
                        f"{bytes_sent} bytes (> threshold "
                        f"{self.large_egress_threshold_bytes}) — large data egress"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "egress_threshold_bytes": self.large_egress_threshold_bytes,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 7. Public-bucket-name + cross-account heuristic.
        # If a bucket name contains "public"/"prod"/"internal" AND the
        # requester is from a different account than the bucket-owner-id,
        # surface a PR-04 FLAG. We compare the canonical user IDs.
        # ----------------------------------------------------------------
        bucket_owner = _coerce_str(record.get("bucket_owner"))
        if (
            _is_public_bucket_name(bucket)
            and bucket_owner
            and requester_raw
            and requester_raw not in _ANONYMOUS_TOKENS
            and not _same_principal(bucket_owner, requester_raw)
        ):
            signal = "broad_bucket_access"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} on bucket {bucket_redacted} "
                        f"(name suggests broad scope) by requester "
                        f"{requester_redacted} crosses owner boundary"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. Per-event markers for synthetic patterns.
        # ----------------------------------------------------------------
        if requester_raw and requester_raw in mass_read_principals:
            signal = "mass_data_read"
            control_id = _control_for(signal, self._mappings, "PR-04")
            info = mass_read_principals[requester_raw]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"S3 request {event_id} part of mass-read pattern: "
                        f"{requester_redacted} read {info['read_count']} "
                        f"sensitive-prefix objects (> threshold "
                        f"{self.mass_read_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "mass_read_count": info["read_count"],
                        "mass_read_threshold": self.mass_read_threshold,
                    },
                )
            )
        if requester_raw and requester_raw in broad_bucket_principals:
            signal = "broad_bucket_access"
            control_id = _control_for(signal, self._mappings, "PR-02")
            buckets = broad_bucket_principals[requester_raw]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} requester {requester_redacted} "
                        f"touched {len(buckets)} distinct buckets (> threshold "
                        f"{self.cross_bucket_threshold}) in this export"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "broad_bucket_count": len(buckets),
                        "broad_bucket_threshold": self.cross_bucket_threshold,
                    },
                )
            )
        if requester_raw and requester_raw in failed_then_success_principals:
            signal = "failed_then_success"
            control_id = _control_for(signal, self._mappings, "PR-01")
            info = failed_then_success_principals[requester_raw]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"S3 request {event_id} requester {requester_redacted} "
                        f"matched failed-then-success pattern (denied at "
                        f"{info['denied_at']}, succeeded at {info['succeeded_at']})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "failed_then_success_window_seconds":
                            self.failed_then_success_window_seconds,
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
            f"Imported from AWS S3 server access log: operation={operation} "
            f"bucket={bucket_redacted or '?'} status={http_status} "
            f"error_code={error_code or 'none'} requester={requester_redacted or 'none'}"
        )

        action_id = f"s3access-{event_id[:32]}" if event_id else (
            f"s3access-{uuid.uuid4()}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=event_time_iso,
            agent_id=self.agent_id,
            source_type="aws_s3_access_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=float(total_time_ms or 0),
            session_id=request_id or None,
        )

    # -- Synthetic results --------------------------------------------------

    def _synthetic_mass_read_result(
        self,
        *,
        requester: str,
        read_count: int,
        buckets: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "mass_data_read"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"s3access-mass-read-{uuid.uuid4()}"
        requester_redacted = _redact_requester(requester) or requester
        evidence = {
            "s3_request_id": synthetic_id,
            "requester_redacted": requester_redacted,
            "mass_read_count": read_count,
            "mass_read_threshold": self.mass_read_threshold,
            "mass_read_buckets_redacted": [
                _redact_bucket(b) for b in buckets if b
            ],
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "aws_s3_access",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"S3 synthetic finding: requester {requester_redacted} read "
                f"{read_count} sensitive-prefix objects (> threshold "
                f"{self.mass_read_threshold}) — mass-data exfiltration pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_s3_access_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from AWS S3 access log: synthetic mass-read pattern "
                f"for requester={requester_redacted} count={read_count}>"
                f"threshold={self.mass_read_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_bucket_result(
        self,
        *,
        requester: str,
        buckets: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "broad_bucket_access"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"s3access-cross-bucket-{uuid.uuid4()}"
        requester_redacted = _redact_requester(requester) or requester
        evidence = {
            "s3_request_id": synthetic_id,
            "requester_redacted": requester_redacted,
            "broad_bucket_count": len(buckets),
            "broad_bucket_threshold": self.cross_bucket_threshold,
            "broad_bucket_buckets_redacted": [
                _redact_bucket(b) for b in buckets if b
            ],
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "aws_s3_access",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"S3 synthetic finding: requester {requester_redacted} touched "
                f"{len(buckets)} distinct buckets (> threshold "
                f"{self.cross_bucket_threshold}) — broad access surface"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_s3_access_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from AWS S3 access log: synthetic cross-bucket "
                f"pattern for requester={requester_redacted} "
                f"buckets={len(buckets)}>threshold={self.cross_bucket_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_failed_then_success_result(
        self,
        *,
        requester: str,
        info: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "failed_then_success"
        control_id = _control_for(signal, self._mappings, "PR-01")
        synthetic_id = f"s3access-failed-then-success-{uuid.uuid4()}"
        requester_redacted = _redact_requester(requester) or requester
        evidence = {
            "s3_request_id": synthetic_id,
            "requester_redacted": requester_redacted,
            "failed_then_success_window_seconds":
                self.failed_then_success_window_seconds,
            "denied_key_prefix": info.get("denied_key_prefix"),
            "denied_at": info.get("denied_at"),
            "succeeded_at": info.get("succeeded_at"),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "aws_s3_access",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"S3 synthetic finding: requester {requester_redacted} was "
                f"denied at {info.get('denied_at')} then succeeded at "
                f"{info.get('succeeded_at')} on a similar key prefix — "
                f"potential privilege escalation success"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_s3_access_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from AWS S3 access log: synthetic failed-then-success "
                f"pattern for requester={requester_redacted}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Module-level helpers used by _build_results
# ---------------------------------------------------------------------------


def _prefix_for_compare(key: str) -> str:
    """Return a comparable prefix from a key — directory + first 8 chars of basename."""
    if not key:
        return ""
    if "/" in key:
        first_slash = key.index("/")
        directory = key[: first_slash + 1]
        rest = key[first_slash + 1 :]
    else:
        directory = ""
        rest = key
    return directory + rest[:8]


def _same_principal(bucket_owner: str, requester: str) -> bool:
    """Check whether the requester resolves to the same canonical user as the bucket owner.

    S3 bucket-owner is the canonical user ID (a 64-char hex). The requester is
    typically an IAM ARN or AROA principal — different identifier space, so we
    cannot strictly compare. Best-effort: if the bucket owner appears as a
    substring of the requester (rare but happens with canonical-user ARNs),
    assume same; otherwise, conservatively assume different.
    """
    if not bucket_owner or not requester:
        return False
    if bucket_owner == requester:
        return True
    return bucket_owner in requester
