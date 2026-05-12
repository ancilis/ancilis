"""Tests for the AWS S3 server access log importer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ancilis.importers.aws_s3_access import AwsS3AccessImporter


# ---------------------------------------------------------------------------
# Fixtures — inline S3 access-log records (no boto3 required)
# ---------------------------------------------------------------------------


_BUCKET_OWNER = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
_DEFAULT_REQUESTER = "arn:aws:iam::123456789012:user/agent-svc"


def _record(
    *,
    request_id: str = "req-001",
    bucket: str = "agent-rag-corpus",
    bucket_owner: str = _BUCKET_OWNER,
    time: str = "[06/May/2026:12:00:00 +0000]",
    remote_ip: str = "203.0.113.42",
    requester: str = _DEFAULT_REQUESTER,
    operation: str = "REST.GET.OBJECT",
    key: str = "documents/report.pdf",
    request_uri: str | None = None,
    http_status: int | str = 200,
    error_code: str | None = None,
    bytes_sent: int | str = 12345,
    object_size: int | str = 12345,
    total_time_ms: int | str = 50,
    turn_around_time_ms: int | str = 12,
    referer: str = "-",
    user_agent: str = "aws-sdk-python/1.0",
    version_id: str = "-",
    host_id: str = "host-id-xyz",
    signature_version: str = "SigV4",
    cipher_suite: str = "TLS_AES_128_GCM_SHA256",
    auth_type: str = "AuthHeader",
    host_header: str = "agent-rag-corpus.s3.us-east-1.amazonaws.com",
    tls_version: str = "TLSv1.2",
    access_point_arn: str | None = None,
    acl_required: str = "-",
    copy_source: str | None = None,
) -> dict[str, Any]:
    if request_uri is None:
        request_uri = f"GET /{bucket}/{key} HTTP/1.1"
    rec: dict[str, Any] = {
        "bucket_owner": bucket_owner,
        "bucket": bucket,
        "time": time,
        "remote_ip": remote_ip,
        "requester": requester,
        "request_id": request_id,
        "operation": operation,
        "key": key,
        "request_uri": request_uri,
        "http_status": http_status,
        "error_code": error_code or "-",
        "bytes_sent": bytes_sent,
        "object_size": object_size,
        "total_time_ms": total_time_ms,
        "turn_around_time_ms": turn_around_time_ms,
        "referer": referer,
        "user_agent": user_agent,
        "version_id": version_id,
        "host_id": host_id,
        "signature_version": signature_version,
        "cipher_suite": cipher_suite,
        "auth_type": auth_type,
        "host_header": host_header,
        "tls_version": tls_version,
        "access_point_arn": access_point_arn or "-",
        "acl_required": acl_required,
    }
    if copy_source is not None:
        rec["copy_source"] = copy_source
    return rec


def _findings_for_request(results: list, request_id: str) -> list:
    return [r for r in results if r.action_id == f"s3access-{request_id}"]


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Per-record classification
# ---------------------------------------------------------------------------


def test_get_object_passes() -> None:
    """REST.GET.OBJECT 200 on a non-sensitive prefix → PR-04 PASS, ALLOW."""
    doc = json.dumps(
        {"records": [_record(request_id="evt-get", key="documents/report.pdf")]}
    )
    importer = AwsS3AccessImporter(agent_id="test")
    results = importer.parse_string(doc)
    findings = _findings_for_request(results, "evt-get")
    assert len(findings) == 1
    r = findings[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-04" and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "s3_object_read"
        for cr in r.control_results
    )


def test_sensitive_prefix_get_flags() -> None:
    """REST.GET.OBJECT on customers/* prefix → PR-04 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-sens-get",
                    key="customers/12345/ssn.pdf",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-sens-get")[0]
    assert r.decision == "FLAG"
    sigs = _signals(r)
    assert "sensitive_prefix_read" in sigs


def test_sensitive_prefix_put_flags() -> None:
    """REST.PUT.OBJECT on payroll/* → PR-04 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-sens-put",
                    operation="REST.PUT.OBJECT",
                    key="payroll/2026-05/may.csv",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-sens-put")[0]
    assert r.decision == "FLAG"
    assert "sensitive_prefix_write" in _signals(r)


def test_delete_audit() -> None:
    """REST.DELETE.OBJECT → PR-05 PASS (audit trail)."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-del",
                    operation="REST.DELETE.OBJECT",
                    key="staging/old-artifact.bin",
                    http_status=204,
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-del")[0]
    assert any(
        cr.control_id == "PR-05" and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "s3_object_delete"
        for cr in r.control_results
    )
    assert r.decision == "ALLOW"


def test_batch_delete_flags() -> None:
    """BATCH.DELETE.OBJECT → PR-02 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-batch",
                    operation="BATCH.DELETE.OBJECT",
                    key="logs/old.log",
                    http_status=200,
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-batch")[0]
    assert r.decision == "FLAG"
    assert "s3_batch_delete" in _signals(r)
    assert any(cr.control_id == "PR-02" for cr in r.control_results)


def test_list_buckets_flags_recon() -> None:
    """REST.LIST.BUCKETS → PR-04 FLAG (recon pattern)."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-list",
                    operation="REST.LIST.BUCKETS",
                    key="-",
                    bucket="-",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-list")[0]
    assert r.decision == "FLAG"
    assert "s3_list_buckets" in _signals(r)


def test_cross_bucket_copy_flags() -> None:
    """REST.COPY.OBJECT to a different bucket → PR-04 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-copy",
                    operation="REST.COPY.OBJECT",
                    bucket="agent-output-bucket",
                    key="copied/result.json",
                    copy_source="/agent-source-bucket/source/result.json",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-copy")[0]
    assert r.decision == "FLAG"
    assert "cross_bucket_copy" in _signals(r)


def test_put_acl_flags() -> None:
    """REST.PUT.ACL → PR-02 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-acl",
                    operation="REST.PUT.ACL",
                    key="-",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-acl")[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02" and cr.evidence_data.get("signal") == "s3_acl_change"
        for cr in r.control_results
    )


def test_anonymous_user_fails() -> None:
    """requester=AnonymousUser → PR-01 FAIL, decision=BLOCK."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-anon",
                    requester="AnonymousUser",
                    auth_type="AnonymousUser",
                    key="docs/public-readme.txt",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-anon")[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-01" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "anonymous_request"
        for cr in r.control_results
    )


def test_legacy_tls_fails() -> None:
    """tls_version=TLSv1.0 → PR-04 FAIL."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-tls",
                    tls_version="TLSv1.0",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-tls")[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "legacy_tls"
        for cr in r.control_results
    )


def test_sigv2_flags() -> None:
    """signature_version=SigV2 → PR-04 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-sigv2",
                    signature_version="SigV2",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-sigv2")[0]
    assert r.decision == "FLAG"
    assert "sigv2_deprecated" in _signals(r)


def test_large_egress_flags() -> None:
    """REST.GET.OBJECT with bytes_sent > threshold → PR-04 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-egress",
                    bytes_sent=200_000_000,
                    object_size=200_000_000,
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-egress")[0]
    assert r.decision == "FLAG"
    assert "large_egress" in _signals(r)


def test_mass_read_synthetic() -> None:
    """Many sensitive-prefix reads from one requester → synthetic mass_data_read."""
    base = datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(102):
        ts = (base + timedelta(seconds=i * 10)).strftime("[%d/%b/%Y:%H:%M:%S +0000]")
        records.append(
            _record(
                request_id=f"evt-mass-{i:03d}",
                time=ts,
                requester="arn:aws:iam::123456789012:role/agent-bulk-reader",
                key=f"customers/cust-{i}/file-{i}.pdf",
                bucket="agent-rag-corpus",
            )
        )
    doc = json.dumps({"records": records})
    importer = AwsS3AccessImporter(mass_read_threshold=100)
    results = importer.parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("s3access-mass-read-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("signal") == "mass_data_read"
    assert cr.evidence_data.get("mass_read_count") == 102

    # Per-record markers should also appear on each event.
    per_event = [
        r
        for r in results
        if r.action_id.startswith("s3access-evt-mass-")
    ]
    assert len(per_event) == 102
    for r in per_event:
        assert "mass_data_read" in _signals(r)


def test_cross_bucket_pattern_synthetic() -> None:
    """Same requester touching > 5 distinct buckets → synthetic broad_bucket_access FLAG."""
    requester = "arn:aws:iam::123456789012:role/agent-explorer"
    records = [
        _record(
            request_id=f"evt-xb-{i}",
            requester=requester,
            bucket=f"bucket-{i}",
            key="file.txt",
        )
        for i in range(7)
    ]
    importer = AwsS3AccessImporter(cross_bucket_threshold=5)
    results = importer.parse_string(json.dumps({"records": records}))
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("s3access-cross-bucket-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("broad_bucket_count") == 7


def test_failed_then_success_synthetic() -> None:
    """Same requester denied then allowed within 1h → synthetic failed_then_success FLAG."""
    requester = "arn:aws:iam::123456789012:user/escalator"
    base = datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)
    deny_ts = base.strftime("[%d/%b/%Y:%H:%M:%S +0000]")
    allow_ts = (base + timedelta(minutes=10)).strftime(
        "[%d/%b/%Y:%H:%M:%S +0000]"
    )
    records = [
        _record(
            request_id="evt-deny",
            time=deny_ts,
            requester=requester,
            key="secrets/db-creds.json",
            http_status=403,
            error_code="AccessDenied",
            bucket="agent-secrets",
        ),
        _record(
            request_id="evt-allow",
            time=allow_ts,
            requester=requester,
            key="secrets/db-creds.json",
            http_status=200,
            bucket="agent-secrets",
        ),
    ]
    results = AwsS3AccessImporter().parse_string(
        json.dumps({"records": records})
    )
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("s3access-failed-then-success-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("signal") == "failed_then_success"


def test_key_path_normalized() -> None:
    """Full key path is NEVER stored — only directory + extension."""
    raw_key = "customers/cust-zeta-9876/sensitive-ssn-document.pdf"
    doc = json.dumps(
        {
            "records": [
                _record(
                    request_id="evt-norm",
                    key=raw_key,
                    request_uri=(
                        "GET /agent-rag-corpus/"
                        "customers/cust-zeta-9876/sensitive-ssn-document.pdf "
                        "HTTP/1.1"
                    ),
                    requester="arn:aws:iam::000000000000:user/agent-svc",
                )
            ]
        }
    )
    results = AwsS3AccessImporter().parse_string(doc)
    r = _findings_for_request(results, "evt-norm")[0]
    for cr in r.control_results:
        ev = cr.evidence_data
        assert ev.get("key_directory") == "customers/"
        assert ev.get("key_extension") == ".pdf"
        # Hard guarantee: full key (including the customer ID and basename)
        # NEVER leaks anywhere in evidence_data. Iterate recursively.
        def _no_leak(value: Any) -> None:
            if isinstance(value, str):
                assert "cust-zeta-9876" not in value, (
                    f"customer-id token leaked into evidence: {value!r}"
                )
                assert "sensitive-ssn-document" not in value, (
                    f"basename leaked into evidence: {value!r}"
                )
            elif isinstance(value, dict):
                for v in value.values():
                    _no_leak(v)
            elif isinstance(value, list):
                for v in value:
                    _no_leak(v)
        _no_leak(ev)


def test_raw_log_text_format_supported() -> None:
    """Raw S3 server access log text (space-delimited) should be auto-detected and parsed."""
    raw = (
        f"{_BUCKET_OWNER} agent-rag-corpus "
        f"[06/May/2026:12:00:00 +0000] "
        f"203.0.113.42 "
        f'"arn:aws:iam::123456789012:user/agent-svc" '
        f"req-raw-001 "
        f"REST.GET.OBJECT "
        f"documents/report.pdf "
        f'"GET /agent-rag-corpus/documents/report.pdf HTTP/1.1" '
        f"200 - 12345 12345 50 12 "
        f'"-" "aws-sdk-python/1.0" - host-id-xyz SigV4 '
        f"TLS_AES_128_GCM_SHA256 AuthHeader "
        f"agent-rag-corpus.s3.us-east-1.amazonaws.com TLSv1.2 - -"
    )
    importer = AwsS3AccessImporter()
    results = importer.parse_string(raw)
    findings = _findings_for_request(results, "req-raw-001")
    assert len(findings) == 1, (
        f"expected 1 finding for raw log; got {len(findings)} "
        f"out of {[r.action_id for r in results]}"
    )
    r = findings[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.evidence_data.get("signal") == "s3_object_read"
        for cr in r.control_results
    )
    # Provenance should record source format.
    cr = r.control_results[0]
    assert cr.evidence_data["source_provenance"]["source_format"] == "aws_s3_access"
