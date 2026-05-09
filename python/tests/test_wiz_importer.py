"""Tests for WizImporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ancilis.importers.wiz import WizImporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue(**overrides):
    """Build a Wiz issue dict with sane defaults."""
    base = {
        "id": "wiz-issue-abcd1234",
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-15T00:00:00Z",
        "type": "MISCONFIGURATION",
        "status": "OPEN",
        "severity": "MEDIUM",
        "control_name": "Public S3 bucket without authentication",
        "control_category": "Storage",
        "framework_compliance_failed": [],
        "resource": {
            "id": "arn:aws:s3:::ancilis-prod-rag-corpus-99887766",
            "name": "ancilis-prod-rag-corpus",
            "type": "BUCKET",
            "cloud_provider": "AWS",
            "subscription_id": "111122223333",
            "region": "us-east-1",
            "tags": [
                {"key": "environment", "value": "production"},
                {"key": "customer-id", "value": "acme-corp-secret"},
            ],
        },
        "exposure": {
            "is_internet_facing": False,
            "is_publicly_accessible": False,
            "anonymous_access": False,
        },
        "data_classification": [],
        "kill_chain": None,
        "is_due_diligence_done": True,
        "ignore_reason": None,
        "ignored_until": None,
        "ai_recommendation": "Restrict bucket policy to authenticated users only",
        "auto_remediation_available": True,
        "is_attack_path_root": False,
        "linked_issues_count": 0,
        "first_seen": "2026-01-01T00:00:00Z",
        "due_date": "2026-12-31",
    }
    # Allow nested override by merging known sub-dicts.
    for k, v in overrides.items():
        if k in ("resource", "exposure") and isinstance(v, dict):
            merged = dict(base[k])
            merged.update(v)
            base[k] = merged
        else:
            base[k] = v
    return base


def _doc(*issues, envelope="issues"):
    return {envelope: list(issues)}


def _find_signal(results, signal):
    """Return the first ControlResult whose evidence_data['signal'] == signal."""
    for er in results:
        for cr in er.control_results:
            if cr.evidence_data.get("signal") == signal:
                return cr, er
    return None, None


def _all_signals(results):
    sigs = []
    for er in results:
        for cr in er.control_results:
            sig = cr.evidence_data.get("signal")
            if sig is not None:
                sigs.append(sig)
    return sigs


# ---------------------------------------------------------------------------
# Tests — primary mappings
# ---------------------------------------------------------------------------


def test_open_critical_fails():
    importer = WizImporter()
    doc = _doc(_issue(severity="CRITICAL"))
    results = importer.parse_string(json.dumps(doc))
    cr, er = _find_signal(results, "open_critical")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert er.decision == "FLAG"  # mode=audit


def test_open_high_publicly_accessible_fails():
    importer = WizImporter()
    doc = _doc(
        _issue(
            severity="HIGH",
            exposure={"is_publicly_accessible": True, "is_internet_facing": True},
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "open_high_publicly_accessible")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    # And the standard open_high should NOT also fire (the public-accessible
    # branch supersedes it for HIGH).
    assert "open_high" not in _all_signals(results)


def test_open_attack_path_fails():
    importer = WizImporter()
    doc = _doc(_issue(type="ATTACK_PATH", severity="HIGH"))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "type_attack_path")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_open_exposed_secret_fails():
    importer = WizImporter()
    doc = _doc(_issue(type="EXPOSED_SECRET", severity="HIGH"))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "type_exposed_secret")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_open_toxic_combination_fails():
    importer = WizImporter()
    doc = _doc(_issue(type="TOXIC_COMBINATION", severity="HIGH"))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "type_toxic_combination")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_anonymous_access_fails():
    importer = WizImporter()
    doc = _doc(
        _issue(
            severity="MEDIUM",
            exposure={"anonymous_access": True},
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "anonymous_access")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_pii_with_high_severity_fails():
    importer = WizImporter()
    doc = _doc(
        _issue(
            severity="HIGH",
            data_classification=["PII", "financial"],
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "sensitive_data_high_severity")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert "PII" in cr.evidence_data.get("sensitive_classifications_hit", [])


def test_rejected_no_reason_fails():
    importer = WizImporter()
    doc = _doc(_issue(status="REJECTED", ignore_reason=None))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "rejected_no_reason")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_rejected_false_positive_passes():
    importer = WizImporter()
    doc = _doc(_issue(status="REJECTED", ignore_reason="false_positive"))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "rejected_false_positive")
    assert cr is not None
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    # ignore_reason sentinel is captured verbatim (not hashed).
    assert cr.evidence_data["ignore_reason"]["sentinel"] == "false_positive"


def test_overdue_open_fails():
    # Set "now" to a fixed point AFTER the issue's due_date.
    fixed_now = datetime(2027, 6, 1, tzinfo=timezone.utc)
    importer = WizImporter(now=fixed_now)
    doc = _doc(_issue(status="OPEN", due_date="2026-12-31"))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "due_date_overdue")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["is_overdue"] is True


def test_compliance_relevant_flags():
    importer = WizImporter()
    doc = _doc(
        _issue(
            severity="HIGH",
            framework_compliance_failed=["SOC2", "PCI-DSS"],
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "compliance_relevant")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert "SOC2" in cr.evidence_data.get("compliance_frameworks_hit", [])


def test_attack_path_root_fails():
    importer = WizImporter()
    doc = _doc(_issue(is_attack_path_root=True))
    results = importer.parse_string(json.dumps(doc))
    cr, _ = _find_signal(results, "attack_path_root")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Tests — synthetics
# ---------------------------------------------------------------------------


def test_concentration_synthetic():
    # 6 OPEN+CRITICAL in same control_category — exceeds default threshold (5).
    importer = WizImporter()
    issues = [
        _issue(
            id=f"wiz-iam-{i}",
            severity="CRITICAL",
            control_category="IAM",
            resource={"id": f"arn:aws:iam::role/role-{i}-AAAA{i:04d}"},
        )
        for i in range(6)
    ]
    doc = _doc(*issues)
    results = importer.parse_string(json.dumps(doc))

    # Find the synthetic concentration result.
    synthetic = next(
        (
            er for er in results
            if any(cr.evidence_data.get("synthetic_kind") == "concentration"
                   for cr in er.control_results)
        ),
        None,
    )
    assert synthetic is not None
    cr = synthetic.control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["control_category"] == "IAM"
    assert cr.evidence_data["open_critical_count"] == 6


def test_resource_focus_synthetic():
    # 11 issues on the same resource id — exceeds default threshold (10).
    importer = WizImporter()
    same_resource = {
        "id": "arn:aws:s3:::shared-bucket-XYZ12345",
        "name": "shared-bucket",
        "type": "BUCKET",
        "cloud_provider": "AWS",
        "subscription_id": "111122223333",
        "region": "us-east-1",
        "tags": [],
    }
    issues = [
        _issue(id=f"wiz-mc-{i}", severity="LOW", resource=same_resource)
        for i in range(11)
    ]
    doc = _doc(*issues)
    results = importer.parse_string(json.dumps(doc))

    synthetic = next(
        (
            er for er in results
            if any(cr.evidence_data.get("synthetic_kind") == "resource_focus"
                   for cr in er.control_results)
        ),
        None,
    )
    assert synthetic is not None
    cr = synthetic.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["issue_count"] == 11


# ---------------------------------------------------------------------------
# Tests — sanitization
# ---------------------------------------------------------------------------


def test_resource_id_truncated():
    importer = WizImporter()
    raw_id = "arn:aws:s3:::ancilis-prod-rag-corpus-99887766"
    doc = _doc(_issue(resource={"id": raw_id}))
    results = importer.parse_string(json.dumps(doc))
    # Pick the first emitted control result with resource evidence.
    cr = results[0].control_results[0]
    truncated = cr.evidence_data["resource"]["id_truncated"]
    assert truncated == raw_id[-8:]
    assert truncated == "99887766"
    # Crucially: the full id is NOT serialized anywhere in the evidence data.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert raw_id not in serialized


def test_resource_name_redacted():
    importer = WizImporter()
    sensitive_name = "cust-acme-prod-rag-corpus"
    doc = _doc(
        _issue(
            resource={
                "id": "arn:aws:s3:::cust-acme-prod-rag-corpus-99887766",
                "name": sensitive_name,
            }
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    name_info = cr.evidence_data["resource"]["name_redacted"]
    assert name_info is not None
    assert name_info["length"] == len(sensitive_name)
    assert "sha256" in name_info and len(name_info["sha256"]) == 64
    # The raw name must NOT appear anywhere in the evidence data.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert sensitive_name not in serialized


# ---------------------------------------------------------------------------
# Tests — envelope handling and source provenance
# ---------------------------------------------------------------------------


def test_data_envelope_supported():
    importer = WizImporter()
    doc = {"data": [_issue(severity="CRITICAL")]}
    results = importer.parse_string(json.dumps(doc))
    assert len(results) >= 1
    assert any(
        cr.evidence_data.get("signal") == "open_critical"
        for er in results for cr in er.control_results
    )


def test_jsonl_supported():
    importer = WizImporter()
    lines = [
        json.dumps(_issue(id="iss-1", severity="CRITICAL")),
        json.dumps(_issue(id="iss-2", severity="LOW")),
    ]
    results = importer.parse_string("\n".join(lines))
    assert any(
        cr.evidence_data.get("signal") == "open_critical"
        for er in results for cr in er.control_results
    )
    assert any(
        cr.evidence_data.get("signal") == "open_low"
        for er in results for cr in er.control_results
    )


def test_single_object_supported():
    importer = WizImporter()
    obj = _issue(severity="CRITICAL")
    results = importer.parse_string(json.dumps(obj))
    assert any(
        cr.evidence_data.get("signal") == "open_critical"
        for er in results for cr in er.control_results
    )


def test_parse_file_records_source_hash(tmp_path: Path):
    importer = WizImporter()
    doc = _doc(_issue(severity="CRITICAL"))
    p = tmp_path / "wiz.json"
    p.write_text(json.dumps(doc))
    results = importer.parse(p)
    cr = results[0].control_results[0]
    assert "original_file_sha256" in cr.evidence_data["source_provenance"]
    assert len(cr.evidence_data["source_provenance"]["original_file_sha256"]) == 64
    assert cr.evidence_data["source_provenance"]["source_format"] == "wiz"
