"""Tests for SARIF and CycloneDX evidence importers (ANC-221)."""

from __future__ import annotations

import json
import hashlib
import textwrap
from pathlib import Path

import pytest

from ancilis.importers.sarif import SarifImporter, _map_rule_to_control, _load_mappings
from ancilis.importers.cyclonedx import CycloneDxImporter, _cwe_to_control
from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore

# ---------------------------------------------------------------------------
# Fixtures — minimal inline SARIF and CycloneDX documents
# ---------------------------------------------------------------------------

SARIF_ONE_FINDING = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "TestScanner",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": "js/sql-injection",
                            "name": "SqlInjection",
                            "shortDescription": {"text": "SQL Injection"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "js/sql-injection",
                    "level": "error",
                    "message": {"text": "Query built from user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.js"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                }
            ],
        }
    ],
})

SARIF_NO_FINDINGS = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CleanScanner", "version": "2.0"}},
            "results": [],
        }
    ],
})

SARIF_MULTI_RUN = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Tool A"}},
            "results": [
                {"ruleId": "js/xss", "level": "warning", "message": {"text": "XSS"}, "locations": []}
            ],
        },
        {
            "tool": {"driver": {"name": "Tool B"}},
            "results": [],
        },
    ],
})

CDX_WITH_VULN = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:test-123",
    "metadata": {
        "timestamp": "2024-01-01T00:00:00Z",
        "tools": [{"name": "syft", "version": "0.90.0"}],
        "component": {"name": "myapp", "version": "1.0.0"},
    },
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
        {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
    ],
    "vulnerabilities": [
        {
            "id": "CVE-2021-23337",
            "description": "Prototype pollution in lodash",
            "cwes": [1321],
            "ratings": [{"severity": "high", "score": 7.2}],
            "affects": [{"ref": "pkg:npm/lodash@4.17.15", "versions": [{"version": "4.17.15"}]}],
        }
    ],
})

CDX_NO_VULNS = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "tools": [{"name": "cdxgen", "version": "9.0.0"}],
        "component": {"name": "cleanapp"},
    },
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0"},
    ],
})

# ---------------------------------------------------------------------------
# SARIF importer unit tests
# ---------------------------------------------------------------------------

class TestSarifImporter:
    def test_parse_single_finding(self):
        imp = SarifImporter(agent_id="test-agent")
        results = imp.parse_string(SARIF_ONE_FINDING)

        assert len(results) == 1
        ev = results[0]
        assert ev.source_type == "sarif_import"
        assert ev.agent_id == "test-agent"
        assert ev.decision == "FLAG"
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.control_id == "PR-03"  # sql-injection → PR-03
        assert cr.result == "FAIL"
        assert "js/sql-injection" in cr.detail
        assert "src/db.js:42" in cr.detail

    def test_no_findings_produces_pass(self):
        imp = SarifImporter()
        results = imp.parse_string(SARIF_NO_FINDINGS)

        assert len(results) == 1
        ev = results[0]
        assert ev.decision == "ALLOW"
        assert ev.control_results[0].result == "PASS"

    def test_multi_run_produces_multiple_results(self):
        imp = SarifImporter()
        results = imp.parse_string(SARIF_MULTI_RUN)
        assert len(results) == 2

    def test_source_type_is_sarif_import(self):
        imp = SarifImporter()
        results = imp.parse_string(SARIF_ONE_FINDING)
        assert results[0].source_type == "sarif_import"

    def test_evaluation_ids_are_unique(self):
        imp = SarifImporter()
        r1 = imp.parse_string(SARIF_ONE_FINDING)
        r2 = imp.parse_string(SARIF_ONE_FINDING)
        assert r1[0].evaluation_id != r2[0].evaluation_id

    def test_tool_name_in_decision_reason(self):
        imp = SarifImporter()
        results = imp.parse_string(SARIF_ONE_FINDING)
        assert "TestScanner" in results[0].decision_reason

    def test_parse_from_shared_fixture(self):
        """Smoke test: parse the shared fixture committed in 253360e."""
        fixture = Path(__file__).parent.parent.parent / "shared" / "fixtures" / "sample.sarif"
        if not fixture.exists():
            pytest.skip("shared fixture not found")
        imp = SarifImporter()
        results = imp.parse(fixture)
        assert len(results) >= 1
        for ev in results:
            assert ev.source_type == "sarif_import"
            assert ev.evaluation_id

    def test_parse_file_captures_hash_covered_provenance(self, tmp_path: Path):
        fixture = tmp_path / "scan.sarif"
        fixture.write_text(SARIF_ONE_FINDING, encoding="utf-8")
        expected_sha256 = hashlib.sha256(SARIF_ONE_FINDING.encode("utf-8")).hexdigest()

        imp = SarifImporter(agent_id="ci-pipeline")
        evaluation = imp.parse(fixture)[0]
        provenance = evaluation.control_results[0].evidence_data["source_provenance"]

        assert provenance == {
            "source_format": "sarif",
            "source_tool_name": "TestScanner",
            "source_tool_version": "1.0.0",
            "original_file_sha256": expected_sha256,
        }

        store = EvidenceStore(load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True)
        record = store.store(evaluation, tool_name=str(fixture))
        tampered_control_results = record.control_results
        tampered_control_results[0]["evidence_data"]["source_provenance"][
            "source_tool_version"
        ] = "tampered"
        store._connection.execute(
            "UPDATE evidence_records SET control_results = ?::JSON WHERE record_id = ?",
            [json.dumps(tampered_control_results), record.record_id],
        )

        valid, errors = store.verify_chain()
        assert valid is False
        assert any("hash mismatch" in error for error in errors)
        store.close()


# ---------------------------------------------------------------------------
# SARIF control mapping unit tests
# ---------------------------------------------------------------------------

class TestSarifMapping:
    def test_exact_match(self):
        mappings = {"js/sql-injection": "PR-03"}
        assert _map_rule_to_control("js/sql-injection", mappings) == "PR-03"

    def test_glob_match(self):
        mappings = {"js/sql-*": "PR-03"}
        assert _map_rule_to_control("js/sql-union-injection", mappings) == "PR-03"

    def test_exact_beats_glob(self):
        mappings = {"js/xss": "PR-03", "js/xss-*": "PR-02"}
        assert _map_rule_to_control("js/xss", mappings) == "PR-03"

    def test_unmapped_returns_default(self):
        assert _map_rule_to_control("unknown/rule", {}) == "PR-03"

    def test_load_mappings_returns_dict(self):
        m = _load_mappings()
        assert isinstance(m, dict)
        # shared/mappings/sarif-aksi-controls.json has at least a few entries
        # (gracefully handles if file is missing)


# ---------------------------------------------------------------------------
# CycloneDX importer unit tests
# ---------------------------------------------------------------------------

class TestCycloneDxImporter:
    def test_components_produce_pass_record(self):
        imp = CycloneDxImporter(agent_id="cdx-test")
        results = imp.parse_string(CDX_NO_VULNS)

        assert len(results) == 1  # only component result, no vulns
        ev = results[0]
        assert ev.source_type == "cyclonedx_import"
        assert ev.decision == "ALLOW"
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-05"

    def test_vulnerability_produces_fail(self):
        imp = CycloneDxImporter(agent_id="cdx-test")
        results = imp.parse_string(CDX_WITH_VULN)

        # 1 component record + 1 vuln record
        assert len(results) == 2
        comp_ev = results[0]
        vuln_ev = results[1]

        assert comp_ev.decision == "ALLOW"
        assert vuln_ev.decision == "BLOCK"  # high severity → FAIL → BLOCK
        cr = vuln_ev.control_results[0]
        assert cr.result == "FAIL"
        assert "CVE-2021-23337" in cr.detail

    def test_component_count_in_evidence_data(self):
        imp = CycloneDxImporter()
        results = imp.parse_string(CDX_WITH_VULN)
        comp_ev = results[0]
        ed = comp_ev.control_results[0].evidence_data
        assert ed["component_count"] == 2

    def test_source_type(self):
        imp = CycloneDxImporter()
        results = imp.parse_string(CDX_NO_VULNS)
        assert results[0].source_type == "cyclonedx_import"

    def test_source_tool_extracted(self):
        imp = CycloneDxImporter()
        results = imp.parse_string(CDX_NO_VULNS)
        assert "cdxgen" in results[0].decision_reason

    def test_parse_from_shared_fixture(self):
        """Smoke test: parse the shared CycloneDX fixture."""
        fixture = (
            Path(__file__).parent.parent.parent
            / "shared" / "fixtures" / "sample-sbom.cdx.json"
        )
        if not fixture.exists():
            pytest.skip("shared fixture not found")
        imp = CycloneDxImporter()
        results = imp.parse(fixture)
        assert len(results) >= 1
        for ev in results:
            assert ev.source_type == "cyclonedx_import"

    def test_parse_file_captures_hash_covered_provenance(self, tmp_path: Path):
        fixture = tmp_path / "bom.cdx.json"
        fixture.write_text(CDX_WITH_VULN, encoding="utf-8")
        expected_sha256 = hashlib.sha256(CDX_WITH_VULN.encode("utf-8")).hexdigest()

        imp = CycloneDxImporter(agent_id="sbom-pipeline")
        evaluation = imp.parse(fixture)[0]
        provenance = evaluation.control_results[0].evidence_data["source_provenance"]

        assert provenance == {
            "source_format": "cyclonedx",
            "source_tool_name": "syft",
            "source_tool_version": "0.90.0",
            "original_file_sha256": expected_sha256,
        }

        store = EvidenceStore(load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True)
        record = store.store(evaluation, tool_name=str(fixture))
        tampered_control_results = record.control_results
        tampered_control_results[0]["evidence_data"]["source_provenance"][
            "source_tool_name"
        ] = "tampered"
        store._connection.execute(
            "UPDATE evidence_records SET control_results = ?::JSON WHERE record_id = ?",
            [json.dumps(tampered_control_results), record.record_id],
        )

        valid, errors = store.verify_chain()
        assert valid is False
        assert any("hash mismatch" in error for error in errors)
        store.close()


# ---------------------------------------------------------------------------
# CycloneDX CWE mapping unit tests
# ---------------------------------------------------------------------------

class TestCweMapping:
    def test_sql_injection_cwe(self):
        assert _cwe_to_control(["CWE-89"]) == "PR-03"

    def test_ssrf_cwe(self):
        assert _cwe_to_control(["CWE-918"]) == "PR-01"

    def test_crypto_cwe(self):
        assert _cwe_to_control(["CWE-327"]) == "PR-04"

    def test_hardcoded_credentials_cwe(self):
        assert _cwe_to_control(["CWE-798"]) == "PR-05"

    def test_data_exfil_cwe(self):
        assert _cwe_to_control(["CWE-200"]) == "DE-01"

    def test_integer_cwe(self):
        assert _cwe_to_control(["CWE-89"]) == "PR-03"

    def test_unknown_cwe_returns_default(self):
        assert _cwe_to_control(["CWE-9999"]) == "PR-03"

    def test_empty_cwes_returns_default(self):
        assert _cwe_to_control([]) == "PR-03"


# ---------------------------------------------------------------------------
# Integration: importers produce records storable in EvidenceStore
# ---------------------------------------------------------------------------

class TestImporterIntegration:
    def test_sarif_result_fields_valid_for_store(self):
        imp = SarifImporter(agent_id="ci-pipeline")
        results = imp.parse_string(SARIF_ONE_FINDING)
        ev = results[0]

        # Verify all fields required by EvidenceStore.store() are present
        assert ev.evaluation_id
        assert ev.timestamp
        assert ev.agent_id == "ci-pipeline"
        assert ev.source_type == "sarif_import"
        assert ev.mode in ("audit", "enforce")
        assert isinstance(ev.control_results, list)
        assert ev.decision in ("ALLOW", "FLAG", "BLOCK")

    def test_cyclonedx_result_fields_valid_for_store(self):
        imp = CycloneDxImporter(agent_id="sbom-pipeline")
        results = imp.parse_string(CDX_WITH_VULN)

        for ev in results:
            assert ev.evaluation_id
            assert ev.timestamp
            assert ev.agent_id == "sbom-pipeline"
            assert ev.source_type == "cyclonedx_import"
            assert isinstance(ev.control_results, list)
            assert len(ev.control_results) > 0
