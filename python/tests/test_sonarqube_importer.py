"""Tests for SonarQubeImporter."""

from __future__ import annotations

import json

from ancilis.importers.sonarqube import SonarQubeImporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue(**overrides):
    """Build a SonarQube issue with sane defaults."""
    base = {
        "key": "AY9-issue-001",
        "rule": "javascript:S2068",
        "component": "my-proj:src/auth/login.js",
        "project": "my-proj",
        "line": 42,
        "hash": "0123456789abcdef0123456789abcdef",
        "textRange": {"startLine": 42, "endLine": 42, "startOffset": 5, "endOffset": 30},
        "message_length": 80,
        "message": "Hardcoded credential found in source code",
        "severity": "MAJOR",
        "status": "OPEN",
        "resolution": None,
        "type": "VULNERABILITY",
        "tags": ["security"],
        "creationDate": "2026-01-15T10:00:00+0000",
        "updateDate": "2026-01-15T10:00:00+0000",
        "assignee": "agent-svc",
        "author_name": "agent-bot",
        "is_ai_generated": False,
        "confidence": "HIGH",
        "attribute": "TRUSTWORTHY",
        "impacts": [],
        "cwe": [],
        "owaspTop10": [],
        "sansTop25": [],
        "effort": "30min",
        "debt": "30min",
        "quality_gate_breached": False,
        "new_code": False,
        "is_security_hotspot": False,
        "hotspot_status": None,
    }
    base.update(overrides)
    return base


def _hotspot(**overrides):
    base = {
        "key": "AY9-hotspot-001",
        "rule": "javascript:S5547",
        "component": "my-proj:src/crypto/cipher.js",
        "project": "my-proj",
        "line": 15,
        "status": "TO_REVIEW",
        "resolution": None,
        "vulnerability_probability": "MEDIUM",
        "is_ai_generated": False,
        "creationDate": "2026-01-15T10:00:00+0000",
        "updateDate": "2026-01-15T10:00:00+0000",
        "message": "Review crypto usage",
    }
    base.update(overrides)
    return base


def _quality_gate(**overrides):
    base = {
        "status": "ERROR",
        "project": "my-proj",
        "conditions": [
            {
                "metric": "new_security_rating",
                "actual_value": "3",
                "status": "ERROR",
                "comparator": "GT",
                "error_threshold": "1",
            }
        ],
    }
    base.update(overrides)
    return base


def _doc_issues(*issues):
    return {"issues": list(issues)}


def _doc_hotspots(*hotspots):
    return {"hotspots": list(hotspots)}


def _doc_qg(qg):
    return {"quality_gate": qg}


def _first_real_cr(results, signal):
    """Return the ControlResult on the (non-synthetic) record with the given signal."""
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal and not cr.evidence_data.get("synthetic"):
                return cr
    raise AssertionError(f"No control_result found for signal={signal!r}")


def _first_synth(results, kind):
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("synthetic_kind") == kind:
                return r, cr
    raise AssertionError(f"No synthetic for kind={kind!r}")


# ---------------------------------------------------------------------------
# Issue mappings
# ---------------------------------------------------------------------------


def test_vulnerability_blocker_open_fails():
    importer = SonarQubeImporter()
    iss = _issue(type="VULNERABILITY", severity="BLOCKER", status="OPEN")
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_blocker_open")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert results[0].decision == "BLOCK"


def test_vulnerability_critical_fails():
    importer = SonarQubeImporter()
    iss = _issue(type="VULNERABILITY", severity="CRITICAL", status="OPEN")
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_critical_open")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


def test_bug_blocker_fails():
    importer = SonarQubeImporter()
    iss = _issue(type="BUG", severity="BLOCKER", status="OPEN")
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "bug_blocker")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


def test_code_smell_passes():
    importer = SonarQubeImporter()
    iss = _issue(type="CODE_SMELL", severity="MAJOR", status="OPEN")
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "code_smell_audit")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert results[0].decision == "ALLOW"


def test_critical_cwe_command_injection_fails():
    """CWE-78 (command injection) escalates to FAIL even at MINOR severity."""
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="MINOR",
        status="OPEN",
        cwe=["CWE-78"],
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "critical_cwe_command_injection")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


def test_hardcoded_credentials_cwe_798_fails_de01():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="MINOR",
        status="OPEN",
        cwe=["CWE-798"],
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "hardcoded_credentials")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_broken_crypto_cwe_327_fails_pr04():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="MAJOR",
        status="OPEN",
        cwe=["CWE-327"],
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "broken_crypto")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_wontfix_blocker_fails_governance():
    """RESOLVED+WONTFIX on critical/blocker = waiving without governance."""
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="RESOLVED",
        resolution="WONTFIX",
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "wontfix_blocker")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_false_positive_passes_audit():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="CRITICAL",
        status="RESOLVED",
        resolution="FALSE-POSITIVE",
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "false_positive_resolution")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_ai_generated_blocker_fails():
    """SonarQube AI CodeFix surfaces AI-introduced critical → PR-03 FAIL with ai_assisted=true."""
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="OPEN",
        is_ai_generated=True,
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "ai_generated_critical")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["ai_assisted"] is True
    assert cr.evidence_data["is_ai_generated"] is True


def test_low_confidence_critical_flags():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="CRITICAL",
        status="OPEN",
        confidence="LOW",
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "low_confidence_critical")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


def test_security_impact_high_fails_pr04():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="MAJOR",
        status="OPEN",
        impacts=[{"softwareQuality": "SECURITY", "severity": "HIGH"}],
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "security_impact_high")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_quality_gate_breached_on_issue_fails():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="MAJOR",
        status="OPEN",
        quality_gate_breached=True,
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "quality_gate_breached")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Hotspots
# ---------------------------------------------------------------------------


def test_hotspot_to_review_high_flags():
    importer = SonarQubeImporter()
    h = _hotspot(status="TO_REVIEW", vulnerability_probability="HIGH")
    results = importer.parse_string(json.dumps(_doc_hotspots(h)))
    cr = _first_real_cr(results, "hotspot_to_review_high")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_hotspot_reviewed_safe_passes():
    importer = SonarQubeImporter()
    h = _hotspot(status="REVIEWED", resolution="SAFE", vulnerability_probability="MEDIUM")
    results = importer.parse_string(json.dumps(_doc_hotspots(h)))
    cr = _first_real_cr(results, "hotspot_reviewed_safe")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_ai_hotspot_high_fails():
    importer = SonarQubeImporter()
    h = _hotspot(
        status="TO_REVIEW",
        vulnerability_probability="HIGH",
        is_ai_generated=True,
    )
    results = importer.parse_string(json.dumps(_doc_hotspots(h)))
    cr = _first_real_cr(results, "ai_hotspot_high")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["ai_assisted"] is True


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


def test_quality_gate_error_security_rating_fails():
    importer = SonarQubeImporter()
    qg = _quality_gate(
        status="ERROR",
        conditions=[
            {
                "metric": "new_security_rating",
                "actual_value": "4",
                "status": "ERROR",
                "comparator": "GT",
                "error_threshold": "1",
            }
        ],
    )
    results = importer.parse_string(json.dumps(_doc_qg(qg)))
    cr = _first_real_cr(results, "qg_error_security_rating")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_quality_gate_warn_flags():
    importer = SonarQubeImporter()
    qg = _quality_gate(
        status="WARN",
        conditions=[
            {"metric": "coverage", "actual_value": "75", "status": "WARN"}
        ],
    )
    results = importer.parse_string(json.dumps(_doc_qg(qg)))
    cr = _first_real_cr(results, "qg_warn")
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"


def test_quality_gate_multi_dimension_fails():
    """ERROR with > 3 conditions → multi-dimension quality breakdown."""
    importer = SonarQubeImporter()
    qg = _quality_gate(
        status="ERROR",
        conditions=[
            {"metric": "new_security_rating", "actual_value": "3", "status": "ERROR"},
            {"metric": "new_reliability_rating", "actual_value": "4", "status": "ERROR"},
            {"metric": "coverage", "actual_value": "60", "status": "ERROR"},
            {"metric": "duplicated_lines_density", "actual_value": "10", "status": "ERROR"},
            {"metric": "new_bugs", "actual_value": "5", "status": "ERROR"},
        ],
    )
    results = importer.parse_string(json.dumps(_doc_qg(qg)))
    cr = _first_real_cr(results, "qg_error_multi_dim")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Synthetics
# ---------------------------------------------------------------------------


def test_high_density_synthetic_fires():
    """> 5 OPEN BLOCKER vulns in same project → DE-01 FAIL synthetic."""
    importer = SonarQubeImporter(high_density_blocker_per_project=2)
    issues = [
        _issue(
            key=f"k-{i}",
            type="VULNERABILITY",
            severity="BLOCKER",
            status="OPEN",
            project="bad-proj",
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc_issues(*issues)))
    r, cr = _first_synth(results, "high_density_blocker_per_project")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["project"] == "bad-proj"
    assert cr.evidence_data["open_blocker_vuln_count"] == 3


def test_ai_concentration_synthetic_fires():
    importer = SonarQubeImporter(ai_generated_concentration=2)
    issues = [
        _issue(
            key=f"k-{i}",
            type="VULNERABILITY",
            severity="MAJOR",
            status="OPEN",
            is_ai_generated=True,
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc_issues(*issues)))
    r, cr = _first_synth(results, "ai_generated_concentration")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["ai_generated_count"] == 3


def test_cross_cwe_synthetic_fires():
    """Same CWE > 5 occurrences across distinct files → systemic issue."""
    importer = SonarQubeImporter(cross_cwe_threshold=2)
    issues = [
        _issue(
            key=f"k-{i}",
            type="VULNERABILITY",
            severity="MAJOR",
            status="OPEN",
            cwe=["CWE-200"],  # Information exposure (NOT in critical_cwes)
            component=f"my-proj:src/file{i}.js",
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc_issues(*issues)))
    r, cr = _first_synth(results, "cross_cwe_pattern")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["cwe"] == "CWE-200"
    assert cr.evidence_data["file_count"] == 3


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_message_not_stored_raw():
    """``message`` raw text must NEVER appear in evidence_data; only length+sha256."""
    importer = SonarQubeImporter()
    secret_message = "Hardcoded API key: sk_live_super_secret_key_12345"
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="OPEN",
        message=secret_message,
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_blocker_open")

    serialized = json.dumps(cr.evidence_data)
    assert "sk_live_super_secret_key_12345" not in serialized
    assert "Hardcoded API key" not in serialized
    # But length + sha256 should be captured.
    redacted = cr.evidence_data["message_redacted"]
    assert redacted["length"] == len(secret_message)
    assert len(redacted["sha256"]) == 64


def test_component_path_normalized():
    """component path must be reduced to directory/<.ext>; filename stem dropped."""
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="OPEN",
        component="tenant-acme:src/secrets/api-private-key.pem",
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_blocker_open")

    component_norm = cr.evidence_data["component_normalized"]
    assert component_norm == "src/secrets/<.pem>"
    serialized = json.dumps(cr.evidence_data)
    assert "tenant-acme" not in serialized
    assert "api-private-key" not in serialized


def test_assignee_and_author_redacted():
    importer = SonarQubeImporter()
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="OPEN",
        assignee="kevin.bauer@example.com",
        author_name="ai-agent-prod",
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_blocker_open")

    serialized = json.dumps(cr.evidence_data)
    assert "kevin.bauer@example.com" not in serialized
    assert "ai-agent-prod" not in serialized
    assert cr.evidence_data["assignee_redacted"]["length"] == len("kevin.bauer@example.com")
    assert cr.evidence_data["author_redacted"]["length"] == len("ai-agent-prod")


def test_hash_truncated_to_last_8():
    importer = SonarQubeImporter()
    full_hash = "0123456789abcdef0123456789abcdef"
    iss = _issue(
        type="VULNERABILITY",
        severity="BLOCKER",
        status="OPEN",
        hash=full_hash,
    )
    results = importer.parse_string(json.dumps(_doc_issues(iss)))
    cr = _first_real_cr(results, "vulnerability_blocker_open")
    assert cr.evidence_data["hash_truncated"] == full_hash[-8:]


# ---------------------------------------------------------------------------
# Envelopes / autodetect
# ---------------------------------------------------------------------------


def test_mixed_envelope_parses_all_kinds():
    """{"issues":[...], "hotspots":[...], "quality_gate":{...}} all parsed."""
    importer = SonarQubeImporter()
    payload = {
        "issues": [
            _issue(type="VULNERABILITY", severity="BLOCKER", status="OPEN"),
        ],
        "hotspots": [
            _hotspot(status="TO_REVIEW", vulnerability_probability="HIGH"),
        ],
        "quality_gate": _quality_gate(
            status="ERROR",
            conditions=[
                {"metric": "new_security_rating", "actual_value": "3", "status": "ERROR"}
            ],
        ),
    }
    results = importer.parse_string(json.dumps(payload))

    signals = {
        cr.evidence_data.get("signal")
        for r in results
        for cr in r.control_results
        if not cr.evidence_data.get("synthetic")
    }
    assert "vulnerability_blocker_open" in signals
    assert "hotspot_to_review_high" in signals
    assert "qg_error_security_rating" in signals


def test_jsonl_parses():
    importer = SonarQubeImporter()
    line1 = json.dumps(_issue(type="VULNERABILITY", severity="BLOCKER", status="OPEN"))
    line2 = json.dumps(_issue(key="k2", type="CODE_SMELL", severity="MINOR", status="OPEN"))
    content = f"{line1}\n{line2}\n"
    results = importer.parse_string(content)
    signals = {
        cr.evidence_data.get("signal")
        for r in results
        for cr in r.control_results
        if not cr.evidence_data.get("synthetic")
    }
    assert "vulnerability_blocker_open" in signals
    assert "code_smell_audit" in signals
