"""Tests for SnykImporter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.snyk import SnykImporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue(**attrs):
    """Build a Snyk REST issue object with sane defaults."""
    base = {
        "key": "SNYK-JS-LODASH-1234",
        "title": "Prototype Pollution",
        "type": "package_vulnerability",
        "severity": "high",
        "effective_severity_level": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit_maturity": None,
        "is_fixable": True,
        "is_patchable": False,
        "is_pinnable": False,
        "is_upgradable": True,
        "is_ignored": False,
        "ignored_reason": None,
        "is_disregarded": False,
        "status": "open",
        "first_introduced": "2026-01-01T00:00:00Z",
        "package_name": "lodash",
        "package_version": "4.17.20",
        "fixed_in_version": "4.17.21",
        "language": "javascript",
        "license": None,
        "license_severity": None,
        "code_file_path": None,
        "code_line": None,
        "scan_target_type": "git",
        "project_id": "proj-1",
        "project_name": "ancilis-svc",
        "org_id": "org-1",
        "ai_assisted": False,
    }
    base.update(attrs)
    return {"id": base["key"], "type": "issue", "attributes": base}


def _doc(*issues, envelope: str = "data"):
    return {envelope: list(issues)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_critical_open_fails():
    importer = SnykImporter()
    doc = _doc(_issue(severity="critical", effective_severity_level="critical"))
    results = importer.parse_string(json.dumps(doc))
    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "status_open_critical"
    assert results[0].decision == "BLOCK"


def test_high_open_fails():
    importer = SnykImporter()
    doc = _doc(_issue(severity="high", effective_severity_level="high"))
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "status_open_high"


def test_medium_with_mature_exploit_fails():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="medium",
            effective_severity_level="medium",
            exploit_maturity="mature",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "status_open_medium_mature"


def test_low_passes():
    importer = SnykImporter()
    doc = _doc(_issue(severity="low", effective_severity_level="low"))
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "status_open_low"
    assert results[0].decision == "ALLOW"


def test_resolved_audit():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="high",
            effective_severity_level="high",
            status="resolved",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "status_resolved"


def test_ignored_no_reason_fails():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="high",
            effective_severity_level="high",
            status="ignored",
            is_ignored=True,
            ignored_reason=None,
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "ignored_no_reason"


def test_ignored_with_reason_critical_flags():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="critical",
            effective_severity_level="critical",
            status="ignored",
            is_ignored=True,
            ignored_reason="known false positive — internal-only path",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "ignored_with_reason_high"


def test_license_high_fails():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            type="license",
            severity="high",
            effective_severity_level="high",
            status="open",
            license="GPL-3.0",
            license_severity="high",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "license_high"


def test_container_critical_fails():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            type="container",
            severity="critical",
            effective_severity_level="critical",
            status="open",
            scan_target_type="container",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "container_critical"


def test_unfixable_critical_flags():
    """A critical/high finding with is_fixable=False but status=ignored becomes unfixable_critical FLAG only when we route around the open path. With status=open + critical the FAIL still wins; verify the unfixable path with status=resolved-equivalent path: status absent."""
    importer = SnykImporter()
    # Use a non-"open" status (e.g. "needs-review") to fall through to unfixable.
    doc = _doc(
        _issue(
            severity="critical",
            effective_severity_level="critical",
            status="needs-review",
            is_fixable=False,
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "unfixable_critical"


def test_disregarded_fails():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="medium",
            effective_severity_level="medium",
            status="open",
            is_disregarded=True,
        )
    )
    results = importer.parse_string(json.dumps(doc))
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "disregarded"


def test_high_density_synthetic():
    importer = SnykImporter(high_density_threshold=2)
    issues = [
        _issue(
            key=f"SNYK-CRIT-{i}",
            severity="critical",
            effective_severity_level="critical",
            project_id="proj-A",
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc(*issues)))
    synth = [r for r in results if any(cr.evidence_data.get("synthetic_kind") == "high_density" for cr in r.control_results)]
    assert len(synth) == 1
    cr = synth[0].control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["project_id"] == "proj-A"
    assert cr.evidence_data["open_critical_high_count"] == 3


def test_ai_assisted_concentration_synthetic():
    importer = SnykImporter(ai_assisted_concentration_threshold=2)
    issues = [
        _issue(
            key=f"SNYK-AI-{i}",
            severity="high",
            effective_severity_level="high",
            project_id=f"proj-{i}",
            ai_assisted=True,
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc(*issues)))
    synth = [r for r in results if any(cr.evidence_data.get("synthetic_kind") == "ai_assisted_concentration" for cr in r.control_results)]
    assert len(synth) == 1
    cr = synth[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["ai_assisted_count"] == 3


def test_cross_project_pattern_synthetic():
    importer = SnykImporter(cross_project_threshold=1)
    issues = [
        _issue(
            key=f"SNYK-CRIT-{i}",
            severity="critical",
            effective_severity_level="critical",
            project_id=f"proj-{i}",
            package_name="lodash",
            package_version="4.17.20",
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc(*issues)))
    synth = [r for r in results if any(cr.evidence_data.get("synthetic_kind") == "cross_project_pattern" for cr in r.control_results)]
    assert len(synth) == 1
    cr = synth[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["package_name"] == "lodash"
    assert cr.evidence_data["package_version"] == "4.17.20"
    assert cr.evidence_data["project_count"] == 3


def test_code_file_path_normalized():
    importer = SnykImporter()
    doc = _doc(
        _issue(
            severity="high",
            effective_severity_level="high",
            type="code",
            code_file_path="src/secrets/private-key.pem",
        )
    )
    results = importer.parse_string(json.dumps(doc))
    ed = results[0].control_results[0].evidence_data
    norm = ed["code_file_path_normalized"]
    # The filename "private-key" must be dropped, only directory + ext remain.
    assert "private-key" not in norm
    assert norm == "src/secrets/<.pem>"


def test_ignored_reason_redacted():
    importer = SnykImporter()
    reason_text = "We accept this risk because secret key ABCD-1234 is rotated daily"
    doc = _doc(
        _issue(
            severity="high",
            effective_severity_level="high",
            status="ignored",
            is_ignored=True,
            ignored_reason=reason_text,
        )
    )
    results = importer.parse_string(json.dumps(doc))
    ed = results[0].control_results[0].evidence_data
    redacted = ed["ignored_reason_redacted"]
    # Raw reason MUST NOT appear anywhere in evidence_data.
    serialized = json.dumps(ed)
    assert "ABCD-1234" not in serialized
    assert reason_text not in serialized
    assert redacted["length"] == len(reason_text)
    assert redacted["sha256"] == hashlib.sha256(reason_text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Format-shape coverage (envelope variants)
# ---------------------------------------------------------------------------


def test_issues_envelope_supported():
    importer = SnykImporter()
    doc = _doc(_issue(severity="critical", effective_severity_level="critical"), envelope="issues")
    results = importer.parse_string(json.dumps(doc))
    assert len(results) == 1


def test_jsonl_supported(tmp_path: Path):
    importer = SnykImporter()
    issues = [
        _issue(key="SNYK-1", severity="critical", effective_severity_level="critical"),
        _issue(key="SNYK-2", severity="low", effective_severity_level="low"),
    ]
    jsonl = "\n".join(json.dumps(i) for i in issues)
    p = tmp_path / "snyk.jsonl"
    p.write_text(jsonl)
    results = importer.parse(p)
    assert len(results) == 2
    # File hash propagates into source_provenance.
    expected_hash = hashlib.sha256(p.read_bytes()).hexdigest()
    assert (
        results[0].control_results[0].evidence_data["source_provenance"]["original_file_sha256"]
        == expected_hash
    )


def test_single_object_supported():
    importer = SnykImporter()
    issue = _issue(severity="critical", effective_severity_level="critical")
    results = importer.parse_string(json.dumps(issue))
    assert len(results) == 1
    assert results[0].control_results[0].result == "FAIL"


def test_title_never_stored_raw():
    importer = SnykImporter()
    title = "leaked-credential-AKIAIOSFODNN7EXAMPLE"
    doc = _doc(_issue(title=title, severity="high", effective_severity_level="high"))
    results = importer.parse_string(json.dumps(doc))
    ed = results[0].control_results[0].evidence_data
    serialized = json.dumps(ed)
    # The full title may APPEAR within the prefix (since title is short), but the prefix length is bounded.
    assert ed["title"]["sha256"] == hashlib.sha256(title.encode("utf-8")).hexdigest()
    assert ed["title"]["length"] == len(title)
    assert len(ed["title"]["prefix"]) <= 80
    assert "title" in serialized  # sanity


# ---------------------------------------------------------------------------
# Importability — `from ancilis.importers import SnykImporter`
# ---------------------------------------------------------------------------


def test_importable_from_package():
    from ancilis.importers import SnykImporter as Exported

    assert Exported is SnykImporter


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
