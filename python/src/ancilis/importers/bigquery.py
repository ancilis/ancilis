"""BigQuery audit-log importer — maps GCP BigQuery Cloud Audit records to AKSI controls.

BigQuery (https://cloud.google.com/bigquery) is Google's cloud data warehouse
and the GCP-native counterpart to Snowflake (covered by ``snowflake.py``).
For agents running on Google Cloud, BigQuery is where customer data, billing
data, product telemetry, and ML training corpora live. The audit surface is
distinct from the generic GCP Cloud Audit importer (``gcp_cloud_audit.py``)
because BigQuery emits its own granular event types — ``jobChange``,
``tableDataRead``, ``datasetChange`` — that carry signals (statementType,
jobType, totalBilledBytes, sensitive-field-read fingerprints) the parent
surface does not parse.

This importer ingests Cloud Logging exports filtered to
``bigquery.googleapis.com`` in three on-disk shapes:

  1. ``{"entries": [...]}`` — the canonical Cloud Logging export envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one entry per line

Signal mapping (see shared/mappings/bigquery-aksi-controls.json):

  * Query SELECT, jobStatus DONE, no error                              → PR-04 PASS
  * Query SELECT on dataset_id matching sensitive patterns              → PR-04 FLAG
  * tableDataRead.fields contains sensitive patterns                    → PR-04 FAIL
  * statementType in {DELETE, DROP_TABLE, TRUNCATE_TABLE} on sensitive  → PR-02 FAIL
  * statementType=DROP_DATASET                                          → PR-02 FAIL (irreversible)
  * methodName ending in DeleteTable / DeleteDataset                    → PR-02 FLAG (audit)
  * methodName=*PatchDataset (permission change)                        → PR-02 FLAG
  * jobType=EXTRACT (export to GCS / external)                          → PR-04 FAIL (exfil)
  * jobType=COPY                                                        → PR-04 FLAG
  * jobType=LOAD from external                                          → PR-04 FLAG
  * useLegacySql=true                                                   → PR-05 FLAG (modernization)
  * totalBytesProcessed > threshold (default 100 GB)                    → PR-04 FLAG (large scan)
  * totalBilledBytes > threshold (default 1 TB)                         → PR-04 FAIL (cost anomaly)
  * jobStatus.error.code=7 (PermissionDenied)                           → PR-02 PASS (correctly denied)
  * jobStatus.error.code=4 (deadline exceeded)                          → DE-01 FLAG
  * jobStatus.error other                                               → DE-01 FAIL
  * authorizationInfo[*].granted=false                                  → PR-02 PASS (audit trail)
  * principalEmail @gserviceaccount.com                                 → captured (service-account)
  * principalEmail with personal/external-domain pattern                → PR-01 FLAG
  * statementType=GRANT/REVOKE                                          → PR-02 FLAG / PR-05 PASS

Cross-record synthetic findings:

  * Same principalEmail touching > N datasets (default 5)                → PR-02 FLAG
  * Same principal with > N sensitive-field-reads in 1h (default 50)    → PR-04 FAIL
  * Same principal cumulative billed_bytes > 10 TB in 1h                 → PR-04 FLAG (cost/exfil)

Sanitization (security-critical — BigQuery audit logs leak SQL, table names,
column names, customer identifiers, dataset IDs, and reservation paths):

  * Query text raw is **never stored**. Only ``query_length`` is captured.
  * ``tableDataRead.fields`` raw VALUES are **never stored**. The importer
    surfaces ``field_count`` (int) and ``sensitive_field_match`` (bool) only.
    Column names themselves can leak schema and PII (e.g. ``ssn_normalized``).
  * ``destinationTable`` full path is dropped — only the project ID is
    redacted away and the leaf segment retained.
  * ``callerIp`` is masked: RFC1918 / loopback preserved verbatim; public
    IPv4 reduced to ``X.Y.0.0/16``; public IPv6 to ``HHHH:HHHH::/32``.
  * ``reservation`` is reduced to last-8-character fingerprint — the full
    path embeds project ids and reservation names that can leak deal context.
  * ``principalEmail`` local part is redacted (``alice@org.com`` →
    ``***@org.com``); the domain is preserved because cross-domain caller
    patterns are themselves a posture signal.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``google-cloud-bigquery``; exports are parsed with
the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/bigquery.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "bigquery-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallbacks if the mapping JSON is missing or malformed.
_DEFAULT_STATEMENT_TYPE_PATTERNS: dict[str, dict[str, str]] = {
    "SELECT":         {"signal": "bq_select",                  "result": "PASS", "control": "PR-04"},
    "INSERT":         {"signal": "bq_dml_write",               "result": "PASS", "control": "PR-04"},
    "UPDATE":         {"signal": "bq_dml_write",               "result": "PASS", "control": "PR-04"},
    "MERGE":          {"signal": "bq_dml_write",               "result": "PASS", "control": "PR-04"},
    "DELETE":         {"signal": "bq_dml_delete",              "result": "PASS", "control": "PR-05"},
    "TRUNCATE_TABLE": {"signal": "bq_dml_delete",              "result": "PASS", "control": "PR-05"},
    "CREATE_TABLE":   {"signal": "bq_schema_change",           "result": "FLAG", "control": "PR-02"},
    "ALTER_TABLE":    {"signal": "bq_schema_change",           "result": "FLAG", "control": "PR-02"},
    "DROP_TABLE":     {"signal": "bq_schema_destruction",      "result": "FAIL", "control": "PR-02"},
    "DROP_DATASET":   {"signal": "bq_dataset_destruction",     "result": "FAIL", "control": "PR-02"},
    "CREATE_VIEW":    {"signal": "bq_schema_change",           "result": "FLAG", "control": "PR-02"},
    "DROP_VIEW":      {"signal": "bq_schema_destruction",      "result": "FAIL", "control": "PR-02"},
    "GRANT":          {"signal": "bq_iam_grant",               "result": "FLAG", "control": "PR-02"},
    "REVOKE":         {"signal": "bq_iam_revoke",              "result": "PASS", "control": "PR-05"},
}

_DEFAULT_JOB_TYPE_PATTERNS: dict[str, dict[str, str]] = {
    "QUERY":   {"signal": "bq_job_query",   "result": "PASS", "control": "PR-04"},
    "LOAD":    {"signal": "bq_job_load",    "result": "FLAG", "control": "PR-04"},
    "EXTRACT": {"signal": "bq_job_extract", "result": "FAIL", "control": "PR-04"},
    "COPY":    {"signal": "bq_job_copy",    "result": "FLAG", "control": "PR-04"},
}

_DEFAULT_ERROR_CODE_PATTERNS: dict[str, dict[str, str]] = {
    "7": {"signal": "bq_permission_denied", "result": "PASS", "control": "PR-02"},
    "4": {"signal": "bq_deadline_exceeded", "result": "FLAG", "control": "DE-01"},
}

_DEFAULT_SENSITIVE_DATASET_PATTERNS: tuple[str, ...] = (
    "*customer*", "*employee*", "*pii*", "*phi*",
    "*audit*", "*payments*", "*ssn*",
)
_DEFAULT_SENSITIVE_FIELD_PATTERNS: tuple[str, ...] = (
    "ssn", "email", "phone", "credit_card", "pii_*",
)
_DEFAULT_EXTERNAL_PRINCIPAL_DOMAINS: tuple[str, ...] = (
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com", "live.com", "aol.com",
)

_DEFAULT_LARGE_SCAN_THRESHOLD_BYTES = 100_000_000_000          # 100 GB
_DEFAULT_LARGE_BILLED_THRESHOLD_BYTES = 1_000_000_000_000      # 1 TB
_DEFAULT_COST_ANOMALY_BILLED_BYTES_THRESHOLD = 10_000_000_000_000  # 10 TB
_DEFAULT_COST_ANOMALY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_DATASET_THRESHOLD = 5
_DEFAULT_HIGH_VOLUME_SENSITIVE_FIELD_THRESHOLD = 50
_DEFAULT_HIGH_VOLUME_SENSITIVE_FIELD_WINDOW_SECONDS = 3600


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the bigquery-aksi-controls.json mapping; tolerate missing file."""
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


def _mask_caller_ip(caller_ip: str | None) -> str | None:
    """Mask a BigQuery callerIp to a privacy-aware form.

    * RFC1918 / loopback / link-local preserved verbatim (already non-routable).
    * Public IPv4 reduced to ``X.Y.0.0/16``.
    * Public IPv6 reduced to ``HHHH:HHHH::/32``.
    * Hostnames / non-IP markers preserved verbatim.
    """
    if not caller_ip or not isinstance(caller_ip, str):
        return None
    ip = caller_ip.strip()
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
    # IPv6
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _redact_principal_email(email: str | None) -> str | None:
    """Redact local part of an email; keep domain.

    ``alice@example.com`` → ``***@example.com``. The domain is preserved
    because cross-domain caller patterns (e.g. a personal-domain caller
    against a corporate dataset) are themselves a posture signal.
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
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if "@" not in s:
        return None
    _, _, domain = s.partition("@")
    return domain or None


def _redact_destination_table(value: Any) -> str | None:
    """Drop project ID; keep dataset.table leaf form for attribution.

    BigQuery destinationTable can be a string like
    ``my-proj:dataset_id.table_id`` or a structured dict
    ``{"projectId": "...", "datasetId": "...", "tableId": "..."}``.
    The project ID is dropped (deal-context leak) and the leaf path retained.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        dataset = value.get("datasetId") or value.get("dataset_id")
        table = value.get("tableId") or value.get("table_id")
        if isinstance(dataset, str) and isinstance(table, str) and dataset and table:
            return f"{dataset}.{table}"
        if isinstance(table, str) and table:
            return table
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # Strip the leading "project:" if present.
    if ":" in s:
        _, _, rest = s.partition(":")
        return rest.strip() or None
    return s


def _redact_reservation(reservation: Any) -> str | None:
    """Reduce a reservation path to a last-8-character fingerprint."""
    if not reservation or not isinstance(reservation, str):
        return None
    s = reservation.strip()
    if not s:
        return None
    if len(s) <= 8:
        return f"reservation:***{s}"
    return f"reservation:***{s[-8:]}"


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    """Case-insensitive fnmatch match."""
    if not value:
        return False
    v = value.lower()
    return any(fnmatch.fnmatchcase(v, pat.lower()) for pat in patterns)


def _matches_field_pattern(field: str, pattern: str) -> bool:
    """Case-insensitive sensitive-field match.

    A pattern containing glob meta-characters (``*?[``) is matched literally
    via ``fnmatchcase``. A bare token (e.g. ``ssn``, ``email``) matches the
    field if the field equals the token OR contains the token as a
    word-boundary-delimited substring (``ssn``, ``ssn_normalized``,
    ``customer_ssn``, ``customer_ssn_canonical`` all match ``ssn``). This
    follows the standard practice of treating the configured tokens as
    semantic-field names that warehouse columns will embed.
    """
    if not field or not pattern:
        return False
    f = field.lower()
    p = pattern.lower()
    if any(ch in p for ch in "*?["):
        return fnmatch.fnmatchcase(f, p)
    if f == p:
        return True
    # Word-boundary: pattern surrounded by start/end-of-string OR underscore.
    return (
        f.startswith(p + "_")
        or f.endswith("_" + p)
        or ("_" + p + "_") in f
    )


def _classify_field_sensitivity(
    fields: list[str], patterns: tuple[str, ...]
) -> dict[str, Any]:
    """Count fields and detect sensitive-pattern matches without leaking values.

    Column names themselves can be PII (e.g. ``customer_ssn_normalized``); we
    return only counts plus a boolean. The raw field list is intentionally not
    surfaced.
    """
    total = len(fields)
    sensitive_count = 0
    for f in fields:
        if not isinstance(f, str):
            continue
        if any(_matches_field_pattern(f, p) for p in patterns):
            sensitive_count += 1
    return {
        "field_count": total,
        "sensitive_field_count": sensitive_count,
        "sensitive_field_match": sensitive_count > 0,
    }


def _parse_iso(ts: Any) -> datetime | None:
    """Best-effort ISO-8601 parse. Returns ``None`` for unparseable inputs."""
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f %z",
            "%Y-%m-%d %H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class BigQueryImporter:
    """Parse a BigQuery audit-log export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_scan_threshold_bytes: int | None = None,
        large_billed_threshold_bytes: int | None = None,
        cost_anomaly_billed_bytes_threshold: int | None = None,
        cost_anomaly_window_seconds: int | None = None,
        cross_dataset_threshold: int | None = None,
        high_volume_sensitive_field_threshold: int | None = None,
        high_volume_sensitive_field_window_seconds: int | None = None,
        sensitive_dataset_patterns: Iterable[str] | None = None,
        sensitive_field_patterns: Iterable[str] | None = None,
        external_principal_domain_patterns: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Statement-type patterns — table > built-in defaults.
        meta_st = meta.get("statement_type_patterns")
        if isinstance(meta_st, dict) and meta_st:
            self._statement_type_patterns: dict[str, dict[str, str]] = {
                str(k).upper(): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_st.items()
                if isinstance(v, dict)
            }
        else:
            self._statement_type_patterns = dict(_DEFAULT_STATEMENT_TYPE_PATTERNS)

        meta_jt = meta.get("job_type_patterns")
        if isinstance(meta_jt, dict) and meta_jt:
            self._job_type_patterns: dict[str, dict[str, str]] = {
                str(k).upper(): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_jt.items()
                if isinstance(v, dict)
            }
        else:
            self._job_type_patterns = dict(_DEFAULT_JOB_TYPE_PATTERNS)

        meta_err = meta.get("error_code_patterns")
        if isinstance(meta_err, dict) and meta_err:
            self._error_code_patterns: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_err.items()
                if isinstance(v, dict)
            }
        else:
            self._error_code_patterns = dict(_DEFAULT_ERROR_CODE_PATTERNS)

        # Sensitive dataset patterns.
        if sensitive_dataset_patterns is not None:
            self.sensitive_dataset_patterns = tuple(
                str(p) for p in sensitive_dataset_patterns
            )
        else:
            meta_pat = meta.get("sensitive_dataset_patterns")
            if isinstance(meta_pat, list) and meta_pat:
                self.sensitive_dataset_patterns = tuple(str(p) for p in meta_pat)
            else:
                self.sensitive_dataset_patterns = _DEFAULT_SENSITIVE_DATASET_PATTERNS

        if sensitive_field_patterns is not None:
            self.sensitive_field_patterns = tuple(
                str(p) for p in sensitive_field_patterns
            )
        else:
            meta_field = meta.get("sensitive_field_patterns")
            if isinstance(meta_field, list) and meta_field:
                self.sensitive_field_patterns = tuple(str(p) for p in meta_field)
            else:
                self.sensitive_field_patterns = _DEFAULT_SENSITIVE_FIELD_PATTERNS

        if external_principal_domain_patterns is not None:
            self.external_principal_domain_patterns = tuple(
                str(p).lower() for p in external_principal_domain_patterns
            )
        else:
            meta_dom = meta.get("external_principal_domain_patterns")
            if isinstance(meta_dom, list) and meta_dom:
                self.external_principal_domain_patterns = tuple(
                    str(p).lower() for p in meta_dom
                )
            else:
                self.external_principal_domain_patterns = (
                    _DEFAULT_EXTERNAL_PRINCIPAL_DOMAINS
                )

        # Numeric thresholds — explicit > meta > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            v = meta.get(key)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        self.large_scan_threshold_bytes = _resolve_int(
            large_scan_threshold_bytes,
            "large_scan_threshold_bytes",
            _DEFAULT_LARGE_SCAN_THRESHOLD_BYTES,
        )
        self.large_billed_threshold_bytes = _resolve_int(
            large_billed_threshold_bytes,
            "large_billed_threshold_bytes",
            _DEFAULT_LARGE_BILLED_THRESHOLD_BYTES,
        )
        self.cost_anomaly_billed_bytes_threshold = _resolve_int(
            cost_anomaly_billed_bytes_threshold,
            "cost_anomaly_billed_bytes_threshold",
            _DEFAULT_COST_ANOMALY_BILLED_BYTES_THRESHOLD,
        )
        self.cost_anomaly_window_seconds = _resolve_int(
            cost_anomaly_window_seconds,
            "cost_anomaly_window_seconds",
            _DEFAULT_COST_ANOMALY_WINDOW_SECONDS,
        )
        self.cross_dataset_threshold = _resolve_int(
            cross_dataset_threshold,
            "cross_dataset_threshold",
            _DEFAULT_CROSS_DATASET_THRESHOLD,
        )
        self.high_volume_sensitive_field_threshold = _resolve_int(
            high_volume_sensitive_field_threshold,
            "high_volume_sensitive_field_threshold",
            _DEFAULT_HIGH_VOLUME_SENSITIVE_FIELD_THRESHOLD,
        )
        self.high_volume_sensitive_field_window_seconds = _resolve_int(
            high_volume_sensitive_field_window_seconds,
            "high_volume_sensitive_field_window_seconds",
            _DEFAULT_HIGH_VOLUME_SENSITIVE_FIELD_WINDOW_SECONDS,
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a BigQuery audit export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse BigQuery audit export content from a JSON or JSONL string."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"entries":[]}`` / ``{"data":[]}`` / JSONL / single entry."""
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

    # -- Build phase --------------------------------------------------------

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-entry EvaluationResults plus cross-record synthetic findings."""
        # First pass: aggregate cross-record patterns.
        principal_datasets: dict[str, set[str]] = {}
        principal_sensitive_field_reads: dict[str, list[datetime]] = {}
        principal_billed_bytes: dict[str, list[tuple[datetime, int]]] = {}

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

            dataset_id, _project_id = self._extract_dataset_project(entry)
            if dataset_id:
                principal_datasets.setdefault(email, set()).add(dataset_id)

            metadata = payload.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}

            # Sensitive-field-read aggregation.
            tdr = metadata.get("tableDataRead") or {}
            if isinstance(tdr, dict):
                fields_raw = tdr.get("fields") or []
                fields = (
                    [str(f) for f in fields_raw if isinstance(f, str)]
                    if isinstance(fields_raw, list)
                    else []
                )
                classified = _classify_field_sensitivity(
                    fields, self.sensitive_field_patterns
                )
                if classified["sensitive_field_match"]:
                    ts = _parse_iso(entry.get("timestamp"))
                    if ts is not None:
                        principal_sensitive_field_reads.setdefault(
                            email, []
                        ).append(ts)

            # Cost-anomaly aggregation.
            job_change = metadata.get("jobChange") or {}
            if isinstance(job_change, dict):
                job = job_change.get("job") or {}
                if isinstance(job, dict):
                    job_stats = job.get("jobStats") or {}
                    if isinstance(job_stats, dict):
                        try:
                            billed = int(job_stats.get("totalBilledBytes") or 0)
                        except (TypeError, ValueError):
                            billed = 0
                        if billed > 0:
                            ts = _parse_iso(entry.get("timestamp"))
                            if ts is not None:
                                principal_billed_bytes.setdefault(
                                    email, []
                                ).append((ts, billed))

        cross_dataset_principals = {
            email: sorted(datasets)
            for email, datasets in principal_datasets.items()
            if len(datasets) > self.cross_dataset_threshold
        }

        # Sliding-window count for sensitive-field reads.
        high_volume_field_principals: dict[str, int] = {}
        for email, times in principal_sensitive_field_reads.items():
            times.sort()
            window = self.high_volume_sensitive_field_window_seconds
            max_count = 0
            j = 0
            for i in range(len(times)):
                while (times[i] - times[j]).total_seconds() > window:
                    j += 1
                count = i - j + 1
                if count > max_count:
                    max_count = count
            if max_count > self.high_volume_sensitive_field_threshold:
                high_volume_field_principals[email] = max_count

        # Sliding-window cumulative billed bytes.
        cost_anomaly_principals: dict[str, int] = {}
        for email, samples in principal_billed_bytes.items():
            samples.sort(key=lambda x: x[0])
            window = self.cost_anomaly_window_seconds
            max_sum = 0
            j = 0
            running = 0
            for i in range(len(samples)):
                running += samples[i][1]
                while (samples[i][0] - samples[j][0]).total_seconds() > window:
                    running -= samples[j][1]
                    j += 1
                if running > max_sum:
                    max_sum = running
            if max_sum > self.cost_anomaly_billed_bytes_threshold:
                cost_anomaly_principals[email] = max_sum

        # ---- Per-entry results.
        results: list[EvaluationResult] = []
        for entry in entries:
            results.append(
                self._parse_entry(
                    entry,
                    file_sha256=file_sha256,
                    cross_dataset_principals=cross_dataset_principals,
                    high_volume_field_principals=high_volume_field_principals,
                    cost_anomaly_principals=cost_anomaly_principals,
                )
            )

        # ---- Synthetic findings.
        for email, datasets in sorted(cross_dataset_principals.items()):
            results.append(
                self._synthetic_cross_dataset_result(
                    principal_email=email,
                    dataset_ids=datasets,
                    file_sha256=file_sha256,
                )
            )
        for email, count in sorted(high_volume_field_principals.items()):
            results.append(
                self._synthetic_sensitive_field_burst_result(
                    principal_email=email,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for email, total in sorted(cost_anomaly_principals.items()):
            results.append(
                self._synthetic_cost_anomaly_result(
                    principal_email=email,
                    total_billed_bytes=total,
                    file_sha256=file_sha256,
                )
            )
        return results

    # -- Provenance ---------------------------------------------------------

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
        record_kind: str = "entry",
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "bigquery_cloud_audit",
            "source_tool_name": "bigquery",
            "source_tool_version": "",
            "record_kind": record_kind,
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # -- Extraction helpers -------------------------------------------------

    @staticmethod
    def _extract_dataset_project(entry: dict[str, Any]) -> tuple[str, str]:
        """Pull (dataset_id, project_id) from resource.labels (preferred) or
        metadata. BigQuery audit entries always carry these on the LogEntry
        ``resource.labels`` block when the methodName is BigQuery-shaped."""
        resource = entry.get("resource") or {}
        labels = resource.get("labels") if isinstance(resource, dict) else None
        if isinstance(labels, dict):
            dataset_id = str(labels.get("dataset_id") or "")
            project_id = str(labels.get("project_id") or "")
        else:
            dataset_id = ""
            project_id = ""
        return dataset_id, project_id

    # ----------------------------------------------------------------------
    # Per-entry parsing
    # ----------------------------------------------------------------------

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_dataset_principals: dict[str, list[str]],
        high_volume_field_principals: dict[str, int],
        cost_anomaly_principals: dict[str, int],
    ) -> EvaluationResult:
        payload = entry.get("protoPayload") or {}
        if not isinstance(payload, dict):
            payload = {}

        insert_id = str(entry.get("insertId") or "")
        timestamp = str(
            entry.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        severity = str(entry.get("severity") or "")
        event_id = insert_id or uuid.uuid4().hex
        action_id_token = event_id[:32]

        method_name = str(payload.get("methodName") or "").strip()
        service_name = str(payload.get("serviceName") or "").strip()

        # Resource-label-derived identity.
        dataset_id, project_id = self._extract_dataset_project(entry)
        resource = entry.get("resource") or {}
        resource_type = (
            str(resource.get("type") or "")
            if isinstance(resource, dict)
            else ""
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
        is_service_account = bool(
            principal_email_raw
            and principal_email_raw.endswith("@gserviceaccount.com")
        ) or bool(
            principal_email_raw
            and ".iam.gserviceaccount.com" in principal_email_raw
        )
        is_external_principal = bool(
            principal_domain
            and not is_service_account
            and principal_domain.lower() in self.external_principal_domain_patterns
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
        caller_ip_masked = _mask_caller_ip(caller_ip_raw)

        # ---- BigQuery metadata (jobChange / tableDataRead / datasetChange) ----
        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        job_change = metadata.get("jobChange") or {}
        if not isinstance(job_change, dict):
            job_change = {}
        job = job_change.get("job") or {}
        if not isinstance(job, dict):
            job = {}
        job_config = job.get("jobConfig") or {}
        if not isinstance(job_config, dict):
            job_config = {}
        query_config = job_config.get("queryConfig") or {}
        if not isinstance(query_config, dict):
            query_config = {}
        job_stats = job.get("jobStats") or {}
        if not isinstance(job_stats, dict):
            job_stats = {}
        job_status = job.get("jobStatus") or {}
        if not isinstance(job_status, dict):
            job_status = {}

        statement_type = str(query_config.get("statementType") or "").upper().strip()
        job_type = str(job_config.get("jobType") or "").upper().strip()
        try:
            query_length = int(query_config.get("query_length") or 0)
        except (TypeError, ValueError):
            query_length = 0
        use_legacy_sql_raw = query_config.get("useLegacySql")
        if isinstance(use_legacy_sql_raw, bool):
            use_legacy_sql: bool | None = use_legacy_sql_raw
        elif isinstance(use_legacy_sql_raw, str):
            cg = use_legacy_sql_raw.strip().lower()
            use_legacy_sql = cg == "true" if cg in ("true", "false") else None
        else:
            use_legacy_sql = None

        destination_table_redacted = _redact_destination_table(
            query_config.get("destinationTable")
        )

        try:
            total_bytes_processed = int(job_stats.get("totalBytesProcessed") or 0)
        except (TypeError, ValueError):
            total_bytes_processed = 0
        try:
            total_billed_bytes = int(job_stats.get("totalBilledBytes") or 0)
        except (TypeError, ValueError):
            total_billed_bytes = 0
        reservation_redacted = _redact_reservation(job_stats.get("reservation"))
        job_state = str(job_status.get("state") or "").upper().strip()

        error = job_status.get("error") or {}
        error_code: int | None = None
        error_reason: str | None = None
        if isinstance(error, dict) and error:
            try:
                error_code = (
                    int(error["code"]) if error.get("code") is not None else None
                )
            except (TypeError, ValueError):
                error_code = None
            if isinstance(error.get("reason"), str) and error["reason"]:
                error_reason = error["reason"]

        # tableDataRead.
        table_data_read = metadata.get("tableDataRead") or {}
        if not isinstance(table_data_read, dict):
            table_data_read = {}
        fields_raw = table_data_read.get("fields") or []
        fields_list = (
            [str(f) for f in fields_raw if isinstance(f, str)]
            if isinstance(fields_raw, list)
            else []
        )
        field_classification = _classify_field_sensitivity(
            fields_list, self.sensitive_field_patterns
        )
        table_data_read_reason = (
            str(table_data_read.get("reason"))
            if isinstance(table_data_read.get("reason"), str)
            else ""
        )

        # datasetChange.
        dataset_change = metadata.get("datasetChange") or {}
        has_dataset_change = bool(dataset_change) and isinstance(dataset_change, dict)

        sensitive_dataset_hit = bool(
            dataset_id and _matches_any(dataset_id, self.sensitive_dataset_patterns)
        )

        common_evidence: dict[str, Any] = {
            "bigquery_event_id": event_id,
            "method_name": method_name,
            "service_name": service_name,
            "statement_type": statement_type,
            "job_type": job_type,
            "dataset_id": dataset_id,
            "project_id": project_id,
            "principal_email_redacted": principal_email_redacted,
            "principal_domain": principal_domain,
            "is_service_account_principal": is_service_account,
            "is_external_principal": is_external_principal,
            "total_bytes_processed": total_bytes_processed,
            "total_billed_bytes": total_billed_bytes,
            "use_legacy_sql": use_legacy_sql,
            "query_length": query_length,
            "destination_table_redacted": destination_table_redacted,
            "reservation_redacted": reservation_redacted,
            "severity": severity,
            "job_state": job_state,
            "error_code": error_code,
            "error_reason": error_reason,
            "authorization_granted_count": granted_count,
            "authorization_denied_count": denied_count,
            "authorization_permissions": permissions,
            "caller_ip_masked": caller_ip_masked,
            "resource_type": resource_type,
            "table_data_read_reason": table_data_read_reason,
            "table_data_read_classification": field_classification,
            "has_dataset_change": has_dataset_change,
            "sensitive_dataset_match": sensitive_dataset_hit,
            "timestamp": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=event_id,
                record_kind="entry",
            ),
            "source_tool": "bigquery",
        }

        control_results: list[ControlResult] = []

        # --------------------------------------------------------------
        # 1. jobStatus.error — failures take precedence over per-type pass.
        # --------------------------------------------------------------
        if error_code is not None:
            err_meta = self._error_code_patterns.get(str(error_code))
            if err_meta is not None:
                signal = err_meta.get("signal", "bq_execution_error")
                control_id = _control_for(
                    signal, self._mappings, err_meta.get("control", "DE-01")
                )
                result = err_meta.get("result", "FLAG")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} returned error_code="
                            f"{error_code} ({error_reason!r})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "bq_execution_error"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} failed with error_code="
                            f"{error_code} ({error_reason!r})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        else:
            # --------------------------------------------------------------
            # 2. Primary classification — sensitive-field read > sensitive
            # dataset > cost anomaly > exfil exports > statementType >
            # jobType > methodName fall-through.
            # --------------------------------------------------------------
            self._append_primary_signal(
                control_results,
                common_evidence=common_evidence,
                event_id=event_id,
                method_name=method_name,
                statement_type=statement_type,
                job_type=job_type,
                dataset_id=dataset_id,
                project_id=project_id,
                total_bytes_processed=total_bytes_processed,
                total_billed_bytes=total_billed_bytes,
                use_legacy_sql=use_legacy_sql,
                sensitive_dataset_hit=sensitive_dataset_hit,
                field_classification=field_classification,
                has_dataset_change=has_dataset_change,
            )

        # --------------------------------------------------------------
        # 3. authorizationInfo[*].granted=false — additive PR-02 PASS.
        # --------------------------------------------------------------
        if denied_count > 0:
            signal = "bq_authorization_denied"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} includes {denied_count} "
                        f"authorization denial(s) — recorded as audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 4. Service-account principal — additive PR-05 PASS (audit trail).
        # --------------------------------------------------------------
        if is_service_account:
            signal = "bq_service_account_principal"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} authenticated as service "
                        f"account {principal_email_redacted}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 5. External / personal-domain principal — PR-01 FLAG.
        # --------------------------------------------------------------
        if is_external_principal:
            signal = "bq_external_principal"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} authenticated by external / "
                        f"personal-domain principal {principal_email_redacted}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 6. useLegacySql=true — PR-05 FLAG (modernization).
        # --------------------------------------------------------------
        if use_legacy_sql is True:
            signal = "bq_legacy_sql"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} executed with "
                        f"useLegacySql=true — modernization concern"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 7. Cross-record-pattern markers (informational; the synthetic
        # finding is added separately).
        # --------------------------------------------------------------
        if (
            isinstance(principal_email_raw, str)
            and principal_email_raw in cross_dataset_principals
        ):
            signal = "bq_cross_dataset_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} principal "
                        f"{principal_email_redacted} is part of a cross-dataset "
                        f"pattern "
                        f"({len(cross_dataset_principals[principal_email_raw])} "
                        f"datasets > threshold {self.cross_dataset_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_dataset_dataset_ids": cross_dataset_principals[
                            principal_email_raw
                        ],
                        "cross_dataset_threshold": self.cross_dataset_threshold,
                    },
                )
            )
        if (
            isinstance(principal_email_raw, str)
            and principal_email_raw in high_volume_field_principals
        ):
            signal = "bq_high_volume_sensitive_field_read"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} principal "
                        f"{principal_email_redacted} is part of a high-volume "
                        f"sensitive-field-read pattern "
                        f"({high_volume_field_principals[principal_email_raw]} "
                        f"reads > threshold "
                        f"{self.high_volume_sensitive_field_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "high_volume_count": high_volume_field_principals[
                            principal_email_raw
                        ],
                        "high_volume_threshold": (
                            self.high_volume_sensitive_field_threshold
                        ),
                    },
                )
            )
        if (
            isinstance(principal_email_raw, str)
            and principal_email_raw in cost_anomaly_principals
        ):
            signal = "bq_cost_anomaly_synthetic"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} principal "
                        f"{principal_email_redacted} is part of a cost-anomaly "
                        f"pattern (cumulative billed bytes "
                        f"{cost_anomaly_principals[principal_email_raw]} > "
                        f"threshold {self.cost_anomaly_billed_bytes_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cost_anomaly_billed_bytes": cost_anomaly_principals[
                            principal_email_raw
                        ],
                        "cost_anomaly_threshold": (
                            self.cost_anomaly_billed_bytes_threshold
                        ),
                    },
                )
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from BigQuery audit log: method_name={method_name} "
            f"statement_type={statement_type or 'none'} "
            f"job_type={job_type or 'none'} "
            f"dataset_id={dataset_id or 'unknown'} "
            f"project_id={project_id or 'unknown'} "
            f"job_state={job_state or 'unknown'} "
            f"error_code={error_code if error_code is not None else 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"bigquery-{action_id_token}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="bigquery_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=insert_id or None,
        )

    def _append_primary_signal(
        self,
        control_results: list[ControlResult],
        *,
        common_evidence: dict[str, Any],
        event_id: str,
        method_name: str,
        statement_type: str,
        job_type: str,
        dataset_id: str,
        project_id: str,
        total_bytes_processed: int,
        total_billed_bytes: int,
        use_legacy_sql: bool | None,
        sensitive_dataset_hit: bool,
        field_classification: dict[str, Any],
        has_dataset_change: bool,
    ) -> None:
        """Apply the methodName + statementType + jobType mapping with overlays.

        Order:
          1. tableDataRead with sensitive-field match → PR-04 FAIL
          2. statementType=DROP_DATASET / DROP_TABLE / DROP_VIEW → PR-02 FAIL
          3. SELECT on sensitive dataset → PR-04 FLAG
          4. SELECT large-scan / large-billed → PR-04 FLAG / FAIL
          5. SELECT default → PR-04 PASS
          6. DELETE/TRUNCATE on sensitive dataset → PR-02 FAIL
          7. statementType pattern table fallback
          8. jobType pattern table fallback (EXTRACT/COPY/LOAD)
          9. methodName-driven IAM (DeleteTable / DeleteDataset / PatchDataset)
        """
        # ---- 1. Sensitive-field read takes precedence (FAIL).
        if field_classification.get("sensitive_field_match"):
            signal = "bq_select_sensitive_field"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} read sensitive fields "
                        f"({field_classification.get('sensitive_field_count')} "
                        f"of {field_classification.get('field_count')}) — "
                        f"sensitive-field selection"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 2. Large billed bytes — cost anomaly FAIL.
        if total_billed_bytes > self.large_billed_threshold_bytes:
            signal = "bq_cost_anomaly"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} billed "
                        f"{total_billed_bytes} bytes (> threshold "
                        f"{self.large_billed_threshold_bytes}) — cost / "
                        f"data-volume anomaly"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 3. statementType-driven destruction signals (high precedence).
        if statement_type in ("DROP_DATASET",):
            signal = "bq_dataset_destruction"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} executed DROP_DATASET — "
                        f"irreversible destruction"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if statement_type in ("DROP_TABLE", "DROP_VIEW"):
            signal = "bq_schema_destruction"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} executed {statement_type} — "
                        f"schema destruction"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 4. DELETE / TRUNCATE on sensitive dataset.
        if statement_type in ("DELETE", "TRUNCATE_TABLE") and sensitive_dataset_hit:
            signal = "bq_dml_delete_sensitive"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} executed {statement_type} on "
                        f"a sensitive dataset"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 5. SELECT — sensitive-dataset / large-scan / default.
        if statement_type == "SELECT":
            if sensitive_dataset_hit:
                signal = "bq_select_sensitive_dataset"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} read from sensitive "
                            f"dataset (matches sensitive_dataset_patterns)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            if total_bytes_processed > self.large_scan_threshold_bytes:
                signal = "bq_large_scan"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} scanned "
                            f"{total_bytes_processed} bytes (> threshold "
                            f"{self.large_scan_threshold_bytes}) — large-scan "
                            f"posture risk"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "bq_select"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} executed SELECT successfully"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 6. statementType pattern table fallback.
        if statement_type:
            pattern = self._statement_type_patterns.get(statement_type)
            if pattern is not None:
                signal = pattern.get("signal", "bq_unknown_method")
                control_id = _control_for(
                    signal, self._mappings, pattern.get("control", "PR-05")
                )
                result = pattern.get("result", "PASS")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} classified by "
                            f"statementType={statement_type} as {signal} "
                            f"({result})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return

        # ---- 7. jobType-driven (EXTRACT / COPY / LOAD).
        if job_type:
            pattern = self._job_type_patterns.get(job_type)
            if pattern is not None:
                signal = pattern.get("signal", "bq_unknown_method")
                control_id = _control_for(
                    signal, self._mappings, pattern.get("control", "PR-04")
                )
                result = pattern.get("result", "PASS")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"BigQuery event {event_id} {method_name} on "
                            f"{project_id}:{dataset_id} classified by "
                            f"jobType={job_type} as {signal} ({result})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return

        # ---- 8. methodName-driven IAM / lifecycle (no statementType / jobType).
        method_lower = method_name.lower()
        if method_lower.endswith("deletetable"):
            signal = "bq_table_delete_audit"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} deleted a table — captured "
                        f"for audit"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if method_lower.endswith("deletedataset"):
            signal = "bq_dataset_delete_audit"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} deleted a dataset — captured "
                        f"for audit"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if "patchdataset" in method_lower and has_dataset_change:
            signal = "bq_iam_dataset_patch"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"BigQuery event {event_id} {method_name} on "
                        f"{project_id}:{dataset_id} patched dataset access — "
                        f"permission change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # ---- 9. Default fall-through — unknown method.
        signal = "bq_unknown_method"
        control_id = _control_for(signal, self._mappings, "PR-05")
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result="FLAG",
                detail=(
                    f"BigQuery event {event_id} {method_name} on "
                    f"{project_id}:{dataset_id} has no matching "
                    f"statementType / jobType / method pattern — surfaced for "
                    f"review"
                ),
                evidence_data={**common_evidence, "signal": signal},
            )
        )

    # ----------------------------------------------------------------------
    # Synthetic findings
    # ----------------------------------------------------------------------

    def _synthetic_cross_dataset_result(
        self,
        *,
        principal_email: str,
        dataset_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bq_cross_dataset_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        principal_redacted = (
            _redact_principal_email(principal_email) or principal_email
        )
        # Deterministic, redacted slug — never embeds the raw email.
        slug = hashlib.sha256(principal_email.encode("utf-8")).hexdigest()[:16]
        synthetic_id = f"bigquery-cross-dataset-{slug}"
        evidence: dict[str, Any] = {
            "bigquery_synthetic_id": synthetic_id,
            "principal_email_redacted": principal_redacted,
            "principal_domain": _principal_email_domain(principal_email),
            "cross_dataset_dataset_ids": dataset_ids,
            "cross_dataset_dataset_count": len(dataset_ids),
            "cross_dataset_threshold": self.cross_dataset_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "bigquery",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"BigQuery synthetic finding: principal {principal_redacted} "
                f"touched {len(dataset_ids)} datasets in this export "
                f"({', '.join(dataset_ids)}) — exceeds cross-dataset threshold "
                f"{self.cross_dataset_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="bigquery_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from BigQuery: synthetic cross-dataset pattern for "
                f"principal={principal_redacted} datasets={len(dataset_ids)}>"
                f"threshold={self.cross_dataset_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_sensitive_field_burst_result(
        self,
        *,
        principal_email: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bq_high_volume_sensitive_field_read"
        control_id = _control_for(signal, self._mappings, "PR-04")
        principal_redacted = (
            _redact_principal_email(principal_email) or principal_email
        )
        slug = hashlib.sha256(principal_email.encode("utf-8")).hexdigest()[:16]
        synthetic_id = f"bigquery-sensitive-field-burst-{slug}"
        evidence: dict[str, Any] = {
            "bigquery_synthetic_id": synthetic_id,
            "principal_email_redacted": principal_redacted,
            "principal_domain": _principal_email_domain(principal_email),
            "high_volume_count": count,
            "high_volume_threshold": self.high_volume_sensitive_field_threshold,
            "high_volume_window_seconds": (
                self.high_volume_sensitive_field_window_seconds
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "bigquery",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"BigQuery synthetic finding: principal {principal_redacted} "
                f"executed {count} sensitive-field reads in 1h "
                f"(> threshold {self.high_volume_sensitive_field_threshold})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="bigquery_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from BigQuery: synthetic sensitive-field-read burst "
                f"for principal={principal_redacted} count={count}>threshold="
                f"{self.high_volume_sensitive_field_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cost_anomaly_result(
        self,
        *,
        principal_email: str,
        total_billed_bytes: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bq_cost_anomaly_synthetic"
        control_id = _control_for(signal, self._mappings, "PR-04")
        principal_redacted = (
            _redact_principal_email(principal_email) or principal_email
        )
        slug = hashlib.sha256(principal_email.encode("utf-8")).hexdigest()[:16]
        synthetic_id = f"bigquery-cost-anomaly-{slug}"
        evidence: dict[str, Any] = {
            "bigquery_synthetic_id": synthetic_id,
            "principal_email_redacted": principal_redacted,
            "principal_domain": _principal_email_domain(principal_email),
            "cost_anomaly_billed_bytes": total_billed_bytes,
            "cost_anomaly_threshold": self.cost_anomaly_billed_bytes_threshold,
            "cost_anomaly_window_seconds": self.cost_anomaly_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "bigquery",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"BigQuery synthetic finding: principal {principal_redacted} "
                f"accumulated {total_billed_bytes} billed bytes in 1h "
                f"(> threshold {self.cost_anomaly_billed_bytes_threshold}) — "
                f"cost / exfiltration signal"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="bigquery_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from BigQuery: synthetic cost-anomaly pattern for "
                f"principal={principal_redacted} "
                f"billed_bytes={total_billed_bytes}>threshold="
                f"{self.cost_anomaly_billed_bytes_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Decision helper
# ---------------------------------------------------------------------------


def _decision_for(control_results: list[ControlResult]) -> str:
    """any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
    if any(cr.result == "FAIL" for cr in control_results):
        return "BLOCK"
    if any(cr.result == "FLAG" for cr in control_results):
        return "FLAG"
    return "ALLOW"
