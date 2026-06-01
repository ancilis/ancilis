"""AWS CloudTrail importer — maps AWS API-call audit records to AKSI controls.

AWS CloudTrail (https://docs.aws.amazon.com/awscloudtrail) is the canonical
audit log of an AWS account: every API call (Bedrock model invocation, Lambda
invocation, S3 access, IAM grant, KMS key use, Secrets Manager retrieval, STS
role assumption, and console action) is recorded as a JSON event. For agents
running on AWS, CloudTrail is the system-of-record for who-did-what across the
entire infrastructure — far broader than any application-level trace.

This importer ingests CloudTrail exports in three on-disk shapes:

  1. ``{"Records": [...]}`` — the canonical CloudTrail S3-export envelope
  2. ``{"data": [...]}``     — generic data envelope
  3. JSONL                    — one record per line

Signal mapping (see shared/mappings/aws-cloudtrail-aksi-controls.json):
  * eventSource=bedrock.amazonaws.com & eventName=InvokeModel/InvokeAgent → PR-01 PASS
  * eventSource=lambda.amazonaws.com & eventName=Invoke*                  → PR-02 PASS
  * eventSource=s3.amazonaws.com & GetObject/ListObjects                  → PR-04 PASS
  * eventSource=s3.amazonaws.com & PutObject/DeleteObject                 → PR-04 FLAG
  * eventSource=iam.amazonaws.com & Attach*Policy/Put*Policy/Create*User  → PR-02 FLAG
  * eventSource=iam.amazonaws.com & Create/Update/DeleteAccessKey         → PR-01 FLAG
  * eventSource=sts.amazonaws.com & AssumeRole*                           → PR-01 PASS
  * eventSource=kms.amazonaws.com & Decrypt                               → PR-04 PASS
  * eventSource=secretsmanager.amazonaws.com & GetSecretValue             → PR-04 FLAG
  * errorCode=AccessDenied*                                               → PR-02 FAIL
  * errorCode=Throttling*                                                 → PR-02 FLAG
  * errorCode=Internal*/Service*                                          → DE-01 FAIL
  * userIdentity.type=Root                                                → PR-01 FAIL
  * MFA=false on iam/kms/secretsmanager calls                             → PR-01 FLAG
  * eventType=AwsConsoleAction                                            → PR-05 FLAG
  * cross-account pattern (one principalId touching > N accountIds)       → PR-02 FLAG synthetic

Sanitization (security-critical — CloudTrail can contain S3 keys, secret
ARNs in request parameters, and access-key material):
  * ``requestParameters`` and ``responseElements`` VALUES are NEVER stored.
    Only the top-level KEY LIST is captured (so an analyst can see *what kinds
    of* parameters were sent, not the values themselves).
  * ``accessKeyId`` is redacted to last-4 only.
  * ``principalId`` is redacted to ``<prefix>...<last-4>`` (AWS principal IDs
    have a 4-char prefix like ``AIDA`` / ``AROA`` / ``AIDX`` that is not
    sensitive).
  * ``sourceIPAddress`` is normalized: ``"AWS Internal"`` is preserved
    verbatim, public addresses are reduced to a /16 pattern, and RFC1918
    private addresses are stored intact (already non-routable).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``boto3``/``botocore``; CloudTrail JSON exports
are parsed with the standard library only.
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
#   <repo>/python/src/ancilis/importers/aws_cloudtrail.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "aws-cloudtrail-aksi-controls.json"
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
# canonical `_metadata.event_patterns` list in the JSON.
_DEFAULT_EVENT_PATTERNS: tuple[dict[str, Any], ...] = (
    {"event_source": "bedrock.amazonaws.com", "event_name": "InvokeModel*",
     "signal": "bedrock_invoke_model", "result": "PASS", "control": "PR-01"},
    {"event_source": "bedrock.amazonaws.com", "event_name": "InvokeAgent*",
     "signal": "bedrock_invoke_agent", "result": "PASS", "control": "PR-01"},
    {"event_source": "bedrock.amazonaws.com", "event_name": "Converse*",
     "signal": "bedrock_invoke_model", "result": "PASS", "control": "PR-01"},
    {"event_source": "lambda.amazonaws.com", "event_name": "Invoke*",
     "signal": "lambda_invoke", "result": "PASS", "control": "PR-02"},
    {"event_source": "s3.amazonaws.com", "event_name": "GetObject",
     "signal": "s3_read", "result": "PASS", "control": "PR-04"},
    {"event_source": "s3.amazonaws.com", "event_name": "ListObject*",
     "signal": "s3_read", "result": "PASS", "control": "PR-04"},
    {"event_source": "s3.amazonaws.com", "event_name": "GetObjectVersion",
     "signal": "s3_read", "result": "PASS", "control": "PR-04"},
    {"event_source": "s3.amazonaws.com", "event_name": "PutObject*",
     "signal": "s3_write", "result": "FLAG", "control": "PR-04"},
    {"event_source": "s3.amazonaws.com", "event_name": "DeleteObject*",
     "signal": "s3_delete", "result": "FLAG", "control": "PR-04"},
    {"event_source": "iam.amazonaws.com", "event_name": "Attach*Policy",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"event_source": "iam.amazonaws.com", "event_name": "Put*Policy",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"event_source": "iam.amazonaws.com", "event_name": "Create*User",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"event_source": "iam.amazonaws.com", "event_name": "Create*Role",
     "signal": "iam_privilege_change", "result": "FLAG", "control": "PR-02"},
    {"event_source": "iam.amazonaws.com", "event_name": "CreateAccessKey",
     "signal": "iam_credential_lifecycle", "result": "FLAG", "control": "PR-01"},
    {"event_source": "iam.amazonaws.com", "event_name": "UpdateAccessKey",
     "signal": "iam_credential_lifecycle", "result": "FLAG", "control": "PR-01"},
    {"event_source": "iam.amazonaws.com", "event_name": "DeleteAccessKey",
     "signal": "iam_credential_lifecycle", "result": "FLAG", "control": "PR-01"},
    {"event_source": "sts.amazonaws.com", "event_name": "AssumeRole*",
     "signal": "sts_assume_role", "result": "PASS", "control": "PR-01"},
    {"event_source": "kms.amazonaws.com", "event_name": "Decrypt",
     "signal": "kms_decrypt", "result": "PASS", "control": "PR-04"},
    {"event_source": "secretsmanager.amazonaws.com", "event_name": "GetSecretValue",
     "signal": "secrets_get_value", "result": "FLAG", "control": "PR-04"},
)

_DEFAULT_ERROR_CODE_SIGNALS: dict[str, dict[str, str]] = {
    "AccessDenied": {"signal": "access_denied", "result": "FAIL", "control": "PR-02"},
    "AccessDeniedException": {"signal": "access_denied", "result": "FAIL", "control": "PR-02"},
    "ThrottlingException": {"signal": "throttling", "result": "FLAG", "control": "PR-02"},
    "Throttling": {"signal": "throttling", "result": "FLAG", "control": "PR-02"},
    "TooManyRequestsException": {"signal": "throttling", "result": "FLAG", "control": "PR-02"},
}

_DEFAULT_ERROR_CODE_PREFIX_SIGNALS: dict[str, dict[str, str]] = {
    "Internal": {"signal": "internal_service_error", "result": "FAIL", "control": "DE-01"},
    "Service": {"signal": "internal_service_error", "result": "FAIL", "control": "DE-01"},
}

_DEFAULT_PRIVILEGED_EVENT_SOURCES: frozenset[str] = frozenset(
    {"iam.amazonaws.com", "kms.amazonaws.com", "secretsmanager.amazonaws.com"}
)

_DEFAULT_CROSS_ACCOUNT_THRESHOLD = 1


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the aws-cloudtrail-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_principal_id(principal_id: str | None) -> str | None:
    """Redact an AWS principal ID to ``<prefix>...<last-4>``.

    AWS principal IDs have a 4-char type prefix (``AIDA`` IAM user, ``AROA``
    IAM role, ``AIDX`` etc.) followed by an account-unique random tail. The
    prefix is not sensitive (it's a public taxonomy), and the last 4 chars
    let an analyst correlate without exposing the full identifier.
    """
    if not principal_id or not isinstance(principal_id, str):
        return None
    pid = principal_id.strip()
    if not pid:
        return None
    if len(pid) <= 8:
        # Short ID — surface the prefix only.
        return pid[:4] + "..." if len(pid) > 4 else pid
    return f"{pid[:4]}...{pid[-4:]}"


def _redact_access_key_id(access_key_id: str | None) -> str | None:
    """Redact an AWS access key ID to last-4 only (``AKIA...XXXX``)."""
    if not access_key_id or not isinstance(access_key_id, str):
        return None
    aki = access_key_id.strip()
    if not aki:
        return None
    if len(aki) <= 4:
        return "***"
    return f"***{aki[-4:]}"


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize a CloudTrail sourceIPAddress to a privacy-aware form.

    * ``"AWS Internal"`` (and similar internal markers) preserved verbatim.
    * RFC1918 private addresses preserved verbatim (already non-routable).
    * Public IPv4 reduced to a /16 pattern (first two octets + ``.0.0/16``).
    * Public IPv6 reduced to the first 32 bits + ``::/32``.
    * Hostnames (some service-linked events use hostnames) preserved verbatim.
    """
    if not source_ip or not isinstance(source_ip, str):
        return None
    ip = source_ip.strip()
    if not ip:
        return None
    # First try to parse as an IP address. If parsing fails, the value is
    # a hostname or service-linked marker like "AWS Internal" — preserve as-is.
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
    # Take the first 32 bits (two hextets) and mask the rest.
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _top_level_keys(value: Any) -> list[str]:
    """Return the sorted top-level keys of a dict (values NEVER captured)."""
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    return []


def _matches_event_pattern(
    event_source: str, event_name: str, pattern: dict[str, Any]
) -> bool:
    src_pat = str(pattern.get("event_source", ""))
    name_pat = str(pattern.get("event_name", ""))
    return (
        fnmatch.fnmatchcase(event_source, src_pat)
        and fnmatch.fnmatchcase(event_name, name_pat)
    )


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class AwsCloudTrailImporter:
    """Parse a CloudTrail export and convert each record to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_account_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Event patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("event_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._event_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._event_patterns = _DEFAULT_EVENT_PATTERNS
        # Error-code signal tables.
        meta_err = meta.get("error_code_signals")
        if isinstance(meta_err, dict) and meta_err:
            self._error_code_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_err.items()
                if isinstance(v, dict)
            }
        else:
            self._error_code_signals = dict(_DEFAULT_ERROR_CODE_SIGNALS)
        meta_err_pref = meta.get("error_code_prefix_signals")
        if isinstance(meta_err_pref, dict) and meta_err_pref:
            self._error_code_prefix_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_err_pref.items()
                if isinstance(v, dict)
            }
        else:
            self._error_code_prefix_signals = dict(_DEFAULT_ERROR_CODE_PREFIX_SIGNALS)
        # Privileged event sources (used for MFA flagging).
        meta_priv = meta.get("privileged_event_sources")
        if isinstance(meta_priv, list) and meta_priv:
            self._privileged_sources: frozenset[str] = frozenset(
                str(s) for s in meta_priv
            )
        else:
            self._privileged_sources = _DEFAULT_PRIVILEGED_EVENT_SOURCES
        # Cross-account threshold precedence: explicit arg > mapping metadata > default.
        if cross_account_threshold is not None:
            self.cross_account_threshold = int(cross_account_threshold)
        else:
            self.cross_account_threshold = int(
                meta.get("cross_account_threshold", _DEFAULT_CROSS_ACCOUNT_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a CloudTrail export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse CloudTrail export content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"Records": [...]}`` / ``{"data": [...]}`` / JSONL / single record."""
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
                if "Records" in doc and isinstance(doc["Records"], list):
                    return [r for r in doc["Records"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                # Single record.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-record EvaluationResults plus cross-account synthetic findings."""
        # First pass: aggregate accountIds per principalId for cross-account detection.
        principal_accounts: dict[str, set[str]] = {}
        for rec in records:
            ui = rec.get("userIdentity") or {}
            if not isinstance(ui, dict):
                continue
            pid = ui.get("principalId")
            acct = ui.get("accountId")
            if isinstance(pid, str) and pid and isinstance(acct, str) and acct:
                principal_accounts.setdefault(pid, set()).add(acct)

        cross_account_principals = {
            pid: sorted(accts)
            for pid, accts in principal_accounts.items()
            if len(accts) > self.cross_account_threshold
        }

        results = [
            self._parse_record(
                rec,
                file_sha256=file_sha256,
                cross_account_principals=cross_account_principals,
            )
            for rec in records
        ]

        # Synthetic per-principal cross-account pattern findings.
        for pid, accts in sorted(cross_account_principals.items()):
            results.append(
                self._synthetic_cross_account_result(
                    principal_id=pid,
                    account_ids=accts,
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
            "source_format": "aws_cloudtrail",
            "source_tool_name": "aws_cloudtrail",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_event(
        self, event_source: str, event_name: str
    ) -> dict[str, Any] | None:
        """Find the first event-pattern that matches; ``None`` if no match."""
        for pattern in self._event_patterns:
            if _matches_event_pattern(event_source, event_name, pattern):
                return pattern
        return None

    def _classify_error_code(self, error_code: str) -> dict[str, str] | None:
        """Resolve an error_code (exact match first, then prefix match)."""
        if error_code in self._error_code_signals:
            return self._error_code_signals[error_code]
        for prefix, signal in self._error_code_prefix_signals.items():
            if error_code.startswith(prefix):
                return signal
        return None

    # ------------------------------------------------------------------
    # Per-record parsing
    # ------------------------------------------------------------------

    def _parse_record(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_account_principals: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id = str(record.get("eventID") or uuid.uuid4())
        event_source = str(record.get("eventSource") or "").strip()
        event_name = str(record.get("eventName") or "").strip()
        event_time = str(
            record.get("eventTime") or datetime.now(timezone.utc).isoformat()
        )
        aws_region = str(record.get("awsRegion") or "")
        request_id = str(record.get("requestID") or "")
        event_type = str(record.get("eventType") or "")
        read_only_raw = record.get("readOnly")
        read_only: bool | None = (
            bool(read_only_raw) if isinstance(read_only_raw, bool) else None
        )
        error_code_raw = record.get("errorCode")
        error_code: str | None = (
            str(error_code_raw).strip()
            if isinstance(error_code_raw, str) and error_code_raw.strip()
            else None
        )
        error_message_raw = record.get("errorMessage")
        error_message: str | None = (
            str(error_message_raw)
            if isinstance(error_message_raw, str) and error_message_raw
            else None
        )

        # ---- userIdentity (sanitized) ----
        ui = record.get("userIdentity") or {}
        if not isinstance(ui, dict):
            ui = {}
        identity_type = str(ui.get("type") or "")
        principal_id_raw = ui.get("principalId")
        principal_id_redacted = _redact_principal_id(
            principal_id_raw if isinstance(principal_id_raw, str) else None
        )
        access_key_id_redacted = _redact_access_key_id(
            ui.get("accessKeyId") if isinstance(ui.get("accessKeyId"), str) else None
        )
        user_name = ui.get("userName") if isinstance(ui.get("userName"), str) else None
        account_id = ui.get("accountId") if isinstance(ui.get("accountId"), str) else None
        identity_arn = ui.get("arn") if isinstance(ui.get("arn"), str) else None
        session_context = ui.get("sessionContext") or {}
        if not isinstance(session_context, dict):
            session_context = {}
        session_attrs = session_context.get("attributes") or {}
        if not isinstance(session_attrs, dict):
            session_attrs = {}
        mfa_raw = session_attrs.get("mfaAuthenticated")
        # CloudTrail represents MFA as the string "true"/"false". Normalize.
        if isinstance(mfa_raw, bool):
            mfa_authenticated: bool | None = mfa_raw
        elif isinstance(mfa_raw, str):
            mfa_low = mfa_raw.strip().lower()
            if mfa_low == "true":
                mfa_authenticated = True
            elif mfa_low == "false":
                mfa_authenticated = False
            else:
                mfa_authenticated = None
        else:
            mfa_authenticated = None

        # ---- sourceIPAddress (privacy-normalized) ----
        source_ip = _classify_source_ip(record.get("sourceIPAddress"))

        # ---- requestParameters / responseElements (KEYS ONLY) ----
        request_param_keys = _top_level_keys(record.get("requestParameters"))
        response_element_keys = _top_level_keys(record.get("responseElements"))

        # ---- resources (ARNs are not secrets — capture intact) ----
        resources_raw = record.get("resources") or []
        resource_arns: list[str] = []
        if isinstance(resources_raw, list):
            for r in resources_raw:
                if isinstance(r, dict):
                    arn = r.get("ARN")
                    if isinstance(arn, str) and arn:
                        resource_arns.append(arn)

        common_evidence: dict[str, Any] = {
            "cloudtrail_event_id": event_id,
            "event_source": event_source,
            "event_name": event_name,
            "event_time": event_time,
            "aws_region": aws_region,
            "request_id": request_id,
            "event_type": event_type,
            "read_only": read_only,
            "error_code": error_code,
            "error_message": error_message,
            "user_identity_type": identity_type,
            "user_name": user_name,
            "account_id": account_id,
            "identity_arn": identity_arn,
            "principal_id_redacted": principal_id_redacted,
            "access_key_id_redacted": access_key_id_redacted,
            "mfa_authenticated": mfa_authenticated,
            "source_ip_redacted": source_ip,
            "request_parameter_keys": request_param_keys,
            "response_element_keys": response_element_keys,
            "resource_arns": resource_arns,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "aws_cloudtrail",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Root identity — critical compliance violation in most envs.
        # Evaluated first: a Root call is always a FAIL regardless of the
        # specific API. We still emit the per-event signal below for context.
        # ----------------------------------------------------------------
        if identity_type == "Root":
            signal = "root_identity"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"performed by Root user — root usage is a critical "
                        f"compliance violation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. errorCode signals — failures override the per-event PASS.
        # We surface the failure as the primary control result, plus the
        # per-event classification for context.
        # ----------------------------------------------------------------
        error_signal_meta = (
            self._classify_error_code(error_code) if error_code else None
        )
        pattern = self._classify_event(event_source, event_name)

        if error_signal_meta is not None:
            signal = error_signal_meta["signal"]
            control_id = _control_for(
                signal, self._mappings, error_signal_meta.get("control", "PR-02")
            )
            result = error_signal_meta.get("result", "FAIL")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"failed with errorCode={error_code!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif pattern is not None:
            signal = str(pattern.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(pattern.get("control", "PR-05"))
            )
            result = str(pattern.get("result", "PASS"))
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown event source / name — surface as PR-05 FLAG so it does
            # not silently pass. CloudTrail has thousands of API names; the
            # mapping table only covers the high-signal subset.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. STS AssumeRole — additive: capture role ARN.
        # The primary classification is already PR-01 PASS; this adds the
        # arn_to (resource ARN) for lineage analysis. Only fires on AssumeRole
        # patterns when the per-event classification matched.
        # ----------------------------------------------------------------
        if (
            event_source == "sts.amazonaws.com"
            and fnmatch.fnmatchcase(event_name, "AssumeRole*")
            and resource_arns
            and pattern is not None
        ):
            # Augment the existing PASS evidence with role ARN list.
            for cr in control_results:
                if cr.evidence_data.get("signal") == "sts_assume_role":
                    cr.evidence_data["assumed_role_arns"] = resource_arns

        # ----------------------------------------------------------------
        # 4. MFA on privileged operation — additive PR-01 FLAG.
        # Fires when the call hits a privileged service (IAM/KMS/Secrets) and
        # the session was not MFA-authenticated. Skipped when mfa is unknown
        # (some service-linked sessions don't carry sessionContext).
        # ----------------------------------------------------------------
        if (
            event_source in self._privileged_sources
            and mfa_authenticated is False
        ):
            signal = "no_mfa_on_privileged"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"performed without MFA authentication on a privileged service"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Console action — interactive console = needs human-trail.
        # ----------------------------------------------------------------
        if event_type == "AwsConsoleAction":
            signal = "console_action"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"CloudTrail event {event_id} {event_source}:{event_name} "
                        f"is an interactive console action — verify human trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 6. Cross-account pattern — informational per-event marker.
        # The synthetic per-principal finding is added separately in the
        # second pass.
        # ----------------------------------------------------------------
        if (
            isinstance(principal_id_raw, str)
            and principal_id_raw in cross_account_principals
        ):
            signal = "cross_account_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"CloudTrail event {event_id} principal {principal_id_redacted} "
                        f"is part of a cross-account pattern "
                        f"({len(cross_account_principals[principal_id_raw])} accounts > "
                        f"threshold {self.cross_account_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_account_account_ids": cross_account_principals[
                            principal_id_raw
                        ],
                        "cross_account_threshold": self.cross_account_threshold,
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
            f"Imported from AWS CloudTrail: event_source={event_source} "
            f"event_name={event_name} "
            f"identity_type={identity_type or 'unknown'} "
            f"error_code={error_code or 'none'} "
            f"region={aws_region or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"cloudtrail-{event_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="aws_cloudtrail_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=request_id or None,
        )

    def _synthetic_cross_account_result(
        self,
        *,
        principal_id: str,
        account_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-principal cross-account pattern finding.

        Captures the (redacted) principalId, the accountIds it touched, and
        the threshold used so downstream posture analysis can answer "which
        principals are crossing AWS account boundaries?".
        """
        signal = "cross_account_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"cloudtrail-cross-account-{principal_id}"
        principal_redacted = _redact_principal_id(principal_id) or principal_id
        evidence: dict[str, Any] = {
            "cloudtrail_event_id": synthetic_id,
            "principal_id_redacted": principal_redacted,
            "cross_account_account_ids": account_ids,
            "cross_account_account_count": len(account_ids),
            "cross_account_threshold": self.cross_account_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "aws_cloudtrail",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"CloudTrail synthetic finding: principal {principal_redacted} "
                f"touched {len(account_ids)} accounts in this export "
                f"({', '.join(account_ids)}) — exceeds cross-account threshold "
                f"{self.cross_account_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_cloudtrail_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from AWS CloudTrail: synthetic cross-account "
                f"pattern for principal={principal_redacted} "
                f"accounts={len(account_ids)}>threshold="
                f"{self.cross_account_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
