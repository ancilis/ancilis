"""Tests for SemgrepImporter."""

from __future__ import annotations

import hashlib
import json

from ancilis.importers.semgrep import SemgrepImporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(**overrides):
    """Build a Semgrep CLI result with sane defaults."""
    extra = {
        "message": "Detected use of os.system with shell injection risk.",
        "severity": "WARNING",
        "metadata": {
            "category": "security",
            "cwe": [],
            "owasp": [],
            "confidence": "MEDIUM",
            "impact": "MEDIUM",
            "likelihood": "MEDIUM",
            "subcategory": ["audit"],
            "technology": ["python"],
            "references": [],
            "vulnerability_class": ["Command Injection"],
            "source-rule-url": "https://semgrep.dev/r/python.lang.security.audit.dangerous-system-call",
            "ai-generated": False,
            "shortlink": "https://sg.run/abc",
        },
        "fix": None,
        "fix_regex": None,
        "is_ignored": False,
        "validation_state": None,
        "rendered_fix": None,
        "metavars": {},
    }

    extra_overrides = overrides.pop("extra", None) or {}
    metadata_overrides = extra_overrides.pop("metadata", None) or {}
    extra["metadata"].update(metadata_overrides)
    extra.update(extra_overrides)

    base = {
        "check_id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
        "path": "src/api.py",
        "start": {"line": 42, "col": 5},
        "end": {"line": 45, "col": 30},
        "extra": extra,
        "fingerprint": "fp-" + hashlib.sha256(b"x").hexdigest()[:16],
        "syntactic_id": "sid-" + hashlib.sha256(b"y").hexdigest()[:16],
    }
    base.update(overrides)
    return base


def _doc(*findings, envelope: str = "results"):
    return {envelope: list(findings)}


def _first_real_cr(results, signal):
    """Return the ControlResult on the (non-synthetic) finding with the given signal."""
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal and not cr.evidence_data.get("synthetic"):
                return cr
    raise AssertionError(f"No control_result found for signal={signal!r}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_high_confidence_security_error_fails():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "metadata": {"confidence": "HIGH", "impact": "MEDIUM", "likelihood": "MEDIUM"},
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "security_error_high_confidence")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert results[0].decision == "BLOCK"


def test_low_confidence_security_error_flags():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "metadata": {"confidence": "LOW", "impact": "MEDIUM", "likelihood": "MEDIUM"},
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "security_error_low_confidence")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


def test_security_warning_flags():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "WARNING",
            "metadata": {"confidence": "MEDIUM", "impact": "MEDIUM", "likelihood": "MEDIUM"},
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "security_warning")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


def test_correctness_error_flags():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "metadata": {
                "category": "correctness",
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
                "vulnerability_class": ["Logic Bug"],
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "correctness_error")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


def test_performance_passes():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "WARNING",
            "metadata": {
                "category": "performance",
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
                "vulnerability_class": ["Slow Query"],
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "performance_any")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert results[0].decision == "ALLOW"


def test_critical_cwe_command_injection_fails():
    """CWE-78 should FAIL even with confidence=LOW + severity=INFO."""
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "INFO",
            "metadata": {
                "category": "security",
                "cwe": [
                    "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
                ],
                "confidence": "LOW",
                "impact": "LOW",
                "likelihood": "LOW",
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "critical_cwe_command_injection")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert "CWE-78" in cr.evidence_data["cwe"]


def test_hardcoded_credentials_fails_de01():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "WARNING",
            "metadata": {
                "category": "security",
                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "hardcoded_credentials")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_broken_crypto_fails_pr04():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "WARNING",
            "metadata": {
                "category": "security",
                "cwe": ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "broken_crypto")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_validated_secret_confirmed_fails():
    """Semgrep Pro CONFIRMED_VALID = real secret in repo → DE-01 FAIL."""
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "validation_state": "CONFIRMED_VALID",
            "metadata": {
                "category": "secrets",
                "confidence": "HIGH",
                "impact": "HIGH",
                "likelihood": "HIGH",
                "vulnerability_class": ["Secret"],
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "validated_secret_confirmed")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["validation_state"] == "CONFIRMED_VALID"


def test_validated_secret_invalid_passes_audit():
    """Semgrep Pro CONFIRMED_INVALID = false positive → PR-05 PASS audit trail."""
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "validation_state": "CONFIRMED_INVALID",
            "metadata": {
                "category": "secrets",
                "confidence": "HIGH",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
                "vulnerability_class": ["Secret"],
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "validated_secret_invalid")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_ignored_flags():
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "ERROR",
            "is_ignored": True,
            "metadata": {
                "category": "security",
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "likelihood": "MEDIUM",
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "is_ignored")
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["is_ignored"] is True


def test_ai_generated_concentration_synthetic():
    importer = SemgrepImporter(ai_assisted_concentration=2)
    findings = [
        _finding(
            check_id=f"rule-{i}",
            path=f"src/file_{i}.py",
            extra={
                "severity": "WARNING",
                "metadata": {
                    "category": "security",
                    "confidence": "MEDIUM",
                    "impact": "MEDIUM",
                    "likelihood": "MEDIUM",
                    "ai-generated": True,
                },
            },
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc(*findings)))
    synth = [
        r
        for r in results
        if any(
            cr.evidence_data.get("synthetic_kind") == "ai_assisted_concentration"
            for cr in r.control_results
        )
    ]
    assert len(synth) == 1
    cr = synth[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["ai_assisted_count"] == 3
    # All real findings should also have ai_assisted=True captured.
    real = [
        r
        for r in results
        if not any(cr.evidence_data.get("synthetic") for cr in r.control_results)
    ]
    assert all(r.control_results[0].evidence_data["ai_assisted"] is True for r in real)


def test_high_density_per_file_synthetic():
    importer = SemgrepImporter(high_density_per_file=2)
    findings = [
        _finding(
            check_id=f"rule-{i}",
            path="src/broken.py",
            extra={
                "severity": "ERROR",
                "metadata": {
                    "category": "security",
                    "confidence": "MEDIUM",
                    "impact": "MEDIUM",
                    "likelihood": "MEDIUM",
                },
            },
        )
        for i in range(3)
    ]
    results = importer.parse_string(json.dumps(_doc(*findings)))
    synth = [
        r
        for r in results
        if any(
            cr.evidence_data.get("synthetic_kind") == "high_density_per_file"
            for cr in r.control_results
        )
    ]
    assert len(synth) == 1
    cr = synth[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["error_count"] == 3
    # The synthetic should not leak the filename.
    assert cr.evidence_data["path_normalized"] == "src/<.py>"


def test_likelihood_impact_high_escalates_to_fail():
    """A WARNING finding with likelihood+impact=HIGH should escalate to FAIL."""
    importer = SemgrepImporter()
    f = _finding(
        extra={
            "severity": "WARNING",
            "metadata": {
                "category": "security",
                "cwe": [],
                "confidence": "MEDIUM",
                "impact": "HIGH",
                "likelihood": "HIGH",
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "likelihood_impact_high")
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert results[0].decision == "BLOCK"


def test_metavars_values_never_stored():
    """Metavars values contain literal user code — must NEVER appear in evidence_data."""
    importer = SemgrepImporter()
    secret_value = "AKIAIOSFODNN7EXAMPLEKEY"
    f = _finding(
        extra={
            "severity": "ERROR",
            "metadata": {
                "category": "security",
                "confidence": "HIGH",
                "impact": "HIGH",
                "likelihood": "HIGH",
                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
            },
            "metavars": {
                "$KEY": {"abstract_content": secret_value, "start": {"line": 5}},
                "$VAL": {"abstract_content": "another-secret-value-xyz"},
            },
        }
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    # Walk the entire result tree looking for any string containing the secret.
    blob = json.dumps(
        [
            {
                "decision": r.decision,
                "decision_reason": r.decision_reason,
                "control_results": [
                    {
                        "control_id": cr.control_id,
                        "detail": cr.detail,
                        "evidence_data": cr.evidence_data,
                    }
                    for cr in r.control_results
                ],
            }
            for r in results
        ]
    )
    assert secret_value not in blob
    assert "another-secret-value-xyz" not in blob
    assert "metavars" not in blob


def test_path_filename_normalized():
    """Path filename stems must be dropped — only directory + extension preserved."""
    importer = SemgrepImporter()
    f = _finding(
        path="src/secrets/aws-prod-creds.pem",
        extra={
            "severity": "ERROR",
            "metadata": {
                "category": "security",
                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                "confidence": "HIGH",
                "impact": "HIGH",
                "likelihood": "HIGH",
            },
        },
    )
    results = importer.parse_string(json.dumps(_doc(f)))
    cr = _first_real_cr(results, "hardcoded_credentials")
    # Filename "aws-prod-creds" must NOT appear; only directory + .pem extension.
    assert cr.evidence_data["path_normalized"] == "src/secrets/<.pem>"
    blob = json.dumps([cr.evidence_data, cr.detail])
    assert "aws-prod-creds" not in blob
    # But line numbers ARE preserved (safe + useful).
    assert cr.evidence_data["start_line"] == 42
    assert cr.evidence_data["end_line"] == 45
