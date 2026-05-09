"""Tests for the BigQuery audit-log importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.bigquery import BigQueryImporter


# ---------------------------------------------------------------------------
# Fixture builders — Cloud Audit AuditLog entries filtered to BigQuery
# ---------------------------------------------------------------------------


def _entry(
    *,
    insert_id: str = "bq-evt-0001",
    timestamp: str = "2026-04-01T12:00:00Z",
    severity: str = "INFO",
    method_name: str = "google.cloud.bigquery.v2.JobService.InsertJob",
    dataset_id: str = "prod_analytics",
    project_id: str = "my-proj",
    principal_email: str = "agent-svc@my-proj.iam.gserviceaccount.com",
    caller_ip: str = "203.0.113.7",
    statement_type: str | None = "SELECT",
    job_type: str | None = "QUERY",
    query_length: int = 1234,
    use_legacy_sql: bool = False,
    destination_table: Any = None,
    total_bytes_processed: int = 1024,
    total_billed_bytes: int = 2048,
    reservation: str | None = "projects/my-proj/locations/us/reservations/agentslot",
    job_state: str = "DONE",
    error_code: int | None = None,
    error_reason: str | None = None,
    table_data_read_fields: list[str] | None = None,
    has_dataset_change: bool = False,
    permission: str = "bigquery.tables.getData",
    granted: bool = True,
    resource_type: str = "bigquery_dataset",
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if statement_type is not None or job_type is not None:
        query_config: dict[str, Any] = {}
        if statement_type is not None:
            query_config["statementType"] = statement_type
        query_config["query_length"] = query_length
        query_config["useLegacySql"] = use_legacy_sql
        if destination_table is not None:
            query_config["destinationTable"] = destination_table
        job_config: dict[str, Any] = {"queryConfig": query_config}
        if job_type is not None:
            job_config["jobType"] = job_type
        job_stats: dict[str, Any] = {
            "startTime": "2026-04-01T12:00:00Z",
            "endTime": "2026-04-01T12:00:01Z",
            "totalBytesProcessed": total_bytes_processed,
            "totalBilledBytes": total_billed_bytes,
        }
        if reservation is not None:
            job_stats["reservation"] = reservation
        job_status: dict[str, Any] = {"state": job_state}
        if error_code is not None:
            job_status["error"] = {"code": error_code, "reason": error_reason}
        else:
            job_status["error"] = None
        metadata["jobChange"] = {
            "job": {
                "jobConfig": job_config,
                "jobStats": job_stats,
                "jobStatus": job_status,
            }
        }
    if table_data_read_fields is not None:
        metadata["tableDataRead"] = {
            "fields": table_data_read_fields,
            "reason": "JOB",
        }
    if has_dataset_change:
        metadata["datasetChange"] = {
            "access": {"role": "roles/bigquery.dataViewer"}
        }

    return {
        "insertId": insert_id,
        "timestamp": timestamp,
        "severity": severity,
        "resource": {
            "type": resource_type,
            "labels": {"dataset_id": dataset_id, "project_id": project_id},
        },
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "bigquery.googleapis.com",
            "methodName": method_name,
            "authenticationInfo": {"principalEmail": principal_email},
            "authorizationInfo": [
                {
                    "resource": (
                        f"projects/{project_id}/datasets/{dataset_id}"
                    ),
                    "permission": permission,
                    "granted": granted,
                }
            ],
            "requestMetadata": {"callerIp": caller_ip},
            "metadata": metadata,
        },
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _walk_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_values(v)
    else:
        yield obj


# ---------------------------------------------------------------------------
# 1. Plain SELECT on benign dataset → PASS
# ---------------------------------------------------------------------------


def test_select_passes() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-pass-0001",
                    dataset_id="ops_metrics",
                    statement_type="SELECT",
                    total_bytes_processed=1_000_000,
                    total_billed_bytes=10_000_000,
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "bq_select" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "bq_select")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 2. SELECT on sensitive dataset flags
# ---------------------------------------------------------------------------


def test_sensitive_dataset_flags() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-flag-0002",
                    dataset_id="prod_customer_data",
                    statement_type="SELECT",
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "bq_select_sensitive_dataset" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "bq_select_sensitive_dataset"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["sensitive_dataset_match"] is True


# ---------------------------------------------------------------------------
# 3. tableDataRead with sensitive fields → FAIL (and field values not stored)
# ---------------------------------------------------------------------------


def test_sensitive_field_fails() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-fail-0003",
                    statement_type="SELECT",
                    table_data_read_fields=["customer_id", "ssn", "email"],
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "bq_select_sensitive_field" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "bq_select_sensitive_field"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    classification = cr.evidence_data["table_data_read_classification"]
    assert classification["sensitive_field_match"] is True
    assert classification["sensitive_field_count"] == 2  # ssn + email
    assert classification["field_count"] == 3
    # Raw fields list must never appear under any guise.
    assert "fields" not in cr.evidence_data
    for v in _walk_values(cr.evidence_data):
        if isinstance(v, list):
            assert "customer_id" not in v
            assert "ssn" not in v
            assert "email" not in v


# ---------------------------------------------------------------------------
# 4. DROP_TABLE on sensitive dataset → FAIL
# ---------------------------------------------------------------------------


def test_drop_table_fails() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-drop-0004",
                    dataset_id="prod_customer_data",
                    statement_type="DROP_TABLE",
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "bq_schema_destruction" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "bq_schema_destruction"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 5. DROP_DATASET → FAIL (irreversible)
# ---------------------------------------------------------------------------


def test_drop_dataset_fails() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-dropds-0005",
                    dataset_id="ops_metrics",
                    statement_type="DROP_DATASET",
                    method_name="google.cloud.bigquery.v2.DatasetService.DeleteDataset",
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "bq_dataset_destruction" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "bq_dataset_destruction"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 6. EXTRACT job → FAIL (data exfiltration)
# ---------------------------------------------------------------------------


def test_extract_fails_exfil() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-extract-0006",
                    statement_type=None,
                    job_type="EXTRACT",
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "bq_job_extract" in _signals(r)
    cr = next(
        c for c in r.control_results if c.evidence_data.get("signal") == "bq_job_extract"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 7. Large scan flags
# ---------------------------------------------------------------------------


def test_large_scan_flags() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-scan-0007",
                    dataset_id="ops_metrics",
                    statement_type="SELECT",
                    total_bytes_processed=200_000_000_000,  # 200 GB > 100 GB
                    total_billed_bytes=200_000_000_000,
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "bq_large_scan" in _signals(r)
    cr = next(
        c for c in r.control_results if c.evidence_data.get("signal") == "bq_large_scan"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 8. Large billed bytes → FAIL (cost anomaly)
# ---------------------------------------------------------------------------


def test_large_billed_fails() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-billed-0008",
                    dataset_id="ops_metrics",
                    statement_type="SELECT",
                    total_bytes_processed=2_000_000_000_000,
                    total_billed_bytes=2_000_000_000_000,  # 2 TB > 1 TB
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "bq_cost_anomaly" in _signals(r)
    cr = next(
        c for c in r.control_results if c.evidence_data.get("signal") == "bq_cost_anomaly"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 9. PermissionDenied (error code 7) → PASS (correctly denied)
# ---------------------------------------------------------------------------


def test_permission_denied_passes() -> None:
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="bq-deny-0009",
                    statement_type="SELECT",
                    error_code=7,
                    error_reason="accessDenied",
                )
            ]
        }
    )
    [r] = BigQueryImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "bq_permission_denied" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "bq_permission_denied"
    )
    assert cr.result == "PASS"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 10. Sensitive-field-read burst → synthetic FAIL
# ---------------------------------------------------------------------------


def test_sensitive_field_burst_synthetic() -> None:
    # 3 sensitive-field reads in 1h, threshold lowered to 2 to avoid 50 fixtures.
    entries = [
        _entry(
            insert_id=f"bq-fb-{i:04d}",
            timestamp=f"2026-04-01T12:{i:02d}:00Z",
            principal_email="leaky-agent@my-proj.iam.gserviceaccount.com",
            statement_type="SELECT",
            table_data_read_fields=["ssn"],
        )
        for i in range(3)
    ]
    doc = json.dumps({"entries": entries})
    importer = BigQueryImporter(high_volume_sensitive_field_threshold=2)
    results = importer.parse_string(doc)

    synthetic = [
        r for r in results if r.action_id.startswith("bigquery-sensitive-field-burst-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "bq_high_volume_sensitive_field_read"
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["high_volume_count"] == 3


# ---------------------------------------------------------------------------
# 11. Cross-dataset synthetic finding
# ---------------------------------------------------------------------------


def test_cross_dataset_synthetic() -> None:
    entries = [
        _entry(
            insert_id=f"bq-cross-{i:04d}",
            dataset_id=f"ops_dataset_{i}",
            principal_email="wide-agent@my-proj.iam.gserviceaccount.com",
            statement_type="SELECT",
        )
        for i in range(4)  # 4 datasets > threshold 3
    ]
    doc = json.dumps({"entries": entries})
    importer = BigQueryImporter(cross_dataset_threshold=3)
    results = importer.parse_string(doc)

    synthetic = [
        r for r in results if r.action_id.startswith("bigquery-cross-dataset-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "bq_cross_dataset_pattern"
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["cross_dataset_dataset_count"] == 4


# ---------------------------------------------------------------------------
# 12. Query text is never stored
# ---------------------------------------------------------------------------


def test_query_text_not_stored() -> None:
    """An export that includes a literal query string must never surface it."""
    entry = _entry(
        insert_id="bq-noleak-0012",
        statement_type="SELECT",
        dataset_id="ops_metrics",
    )
    # Inject worst case: a queryConfig with full SQL text alongside query_length.
    entry["protoPayload"]["metadata"]["jobChange"]["job"]["jobConfig"]["queryConfig"][
        "query"
    ] = "SELECT secret_column FROM customers WHERE ssn='123-45-6789'"
    doc = json.dumps({"entries": [entry]})
    [r] = BigQueryImporter().parse_string(doc)
    for cr in r.control_results:
        assert "query" not in cr.evidence_data
        assert "QUERY" not in cr.evidence_data
        for v in _walk_values(cr.evidence_data):
            s = str(v)
            assert "secret_column" not in s
            assert "123-45-6789" not in s
    # Length is what we keep.
    cr0 = r.control_results[0]
    assert "query_length" in cr0.evidence_data
    assert cr0.evidence_data["query_length"] == 1234


# ---------------------------------------------------------------------------
# 13. tableDataRead.fields raw values are never stored — only counts
# ---------------------------------------------------------------------------


def test_field_values_not_stored() -> None:
    entry = _entry(
        insert_id="bq-fields-0013",
        statement_type="SELECT",
        table_data_read_fields=[
            "ssn_normalized",
            "internal_employee_id",
            "phone_canonical",
        ],
    )
    doc = json.dumps({"entries": [entry]})
    [r] = BigQueryImporter().parse_string(doc)
    for cr in r.control_results:
        # Raw fields list must not appear under any guise.
        assert "fields" not in cr.evidence_data
        for v in _walk_values(cr.evidence_data):
            s = str(v)
            assert "ssn_normalized" not in s
            assert "internal_employee_id" not in s
            assert "phone_canonical" not in s
    cr0 = r.control_results[0]
    classification = cr0.evidence_data["table_data_read_classification"]
    assert classification["field_count"] == 3
    assert classification["sensitive_field_match"] is True
    assert "field_count" in classification


# ---------------------------------------------------------------------------
# 14. callerIp is masked (not stored verbatim)
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    entry = _entry(
        insert_id="bq-ip-0014",
        statement_type="SELECT",
        caller_ip="93.184.216.34",  # public, RFC 5737 TEST-NET ranges are
                                     # flagged "private" by Python ipaddress
    )
    doc = json.dumps({"entries": [entry]})
    [r] = BigQueryImporter().parse_string(doc)
    cr0 = r.control_results[0]
    assert cr0.evidence_data["caller_ip_masked"] == "93.184.0.0/16"
    # The full IP must not appear anywhere.
    for v in _walk_values(cr0.evidence_data):
        assert str(v) != "93.184.216.34"


# ---------------------------------------------------------------------------
# 15. JSONL shape is supported
# ---------------------------------------------------------------------------


def test_jsonl_shape() -> None:
    e1 = _entry(insert_id="bq-jsonl-1", dataset_id="ops_metrics")
    e2 = _entry(
        insert_id="bq-jsonl-2", dataset_id="prod_customer_data", statement_type="SELECT"
    )
    content = "\n".join([json.dumps(e1), json.dumps(e2)])
    results = BigQueryImporter().parse_string(content)
    assert len(results) == 2
    # Mix of PASS + FLAG decisions surfaces correctly across JSONL records.
    decisions = sorted(r.decision for r in results)
    assert decisions == ["ALLOW", "FLAG"]
