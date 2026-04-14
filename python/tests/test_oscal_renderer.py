"""Tests for OSCAL report rendering."""

from __future__ import annotations

import json

from ancilis._shared import shared_path
from ancilis.evidence.record import EvidenceRecord
from ancilis.report.renderers.oscal import load_oscal_mapping, render_oscal


def _record(*, control_id: str, result: str) -> EvidenceRecord:
    return EvidenceRecord(
        record_id=f"record-{control_id.lower()}",
        evaluation_id=f"eval-{control_id.lower()}",
        timestamp="2026-04-14T00:00:00+00:00",
        agent_id="agent-1",
        source_type="agent",
        tool_name="read_file",
        decision="ALLOW" if result in {"PASS", "SKIP"} else "BLOCK",
        mode="audit",
        control_results=[
            {
                "control_id": control_id,
                "control_name": f"{control_id} control",
                "result": result,
                "detail": f"{control_id} detail",
                "evidence_data": {"example": True},
                "duration_ms": 1.0,
            }
        ],
        active_overlays=[],
        data_classifications=[],
        active_certifications=[],
        record_hash=f"hash-{control_id.lower()}",
        previous_hash="genesis",
    )


def test_load_oscal_mapping_covers_all_shared_controls() -> None:
    mapping = load_oscal_mapping()
    control_ids = {
        json.loads(path.read_text(encoding="utf-8"))["id"]
        for path in shared_path("controls").glob("*.json")
    }

    assert control_ids == set(mapping["mappings"])
    assert mapping["framework"] == "NIST SP 800-53 Rev 5"
    assert mapping["oscal_version"] == "1.1.2"


def test_render_oscal_maps_runtime_controls_to_observations() -> None:
    output = render_oscal([_record(control_id="PR-01", result="PASS")])
    payload = json.loads(output)

    result = payload["assessment-results"]["results"][0]
    assert len(result["observations"]) == 3
    assert result["findings"] == []

    observed_nist_controls = []
    for observation in result["observations"]:
        props = {prop["name"]: prop["value"] for prop in observation["props"]}
        assert props["aksi-control-id"] == "PR-01"
        assert props["evidence-record-id"] == "record-pr-01"
        assert props["assessment-state"] == "satisfied"
        observed_nist_controls.append(props["nist-sp800-53-control-id"])
    assert observed_nist_controls == ["ac-2", "ia-2", "ia-5"]

    reviewed = result["reviewed-controls"]["control-selections"][0]["include-controls"]
    assert [item["control-id"] for item in reviewed] == ["ac-2", "ia-2", "ia-5"]


def test_render_oscal_includes_integrity_metadata_props() -> None:
    record = _record(control_id="PR-01", result="PASS")
    record.session_id = "session-1"
    record.tenant_id = "tenant-1"
    record.detected_data_types = ["DC-PII"]
    record.sdk_version = "0.1.0"
    record.classification_context = {"llm_provider": "openai"}

    output = render_oscal([record])
    payload = json.loads(output)

    props = {
        prop["name"]: prop["value"]
        for prop in payload["assessment-results"]["results"][0]["observations"][0]["props"]
    }
    assert props["evidence-record-hash"] == "hash-pr-01"
    assert props["evidence-previous-hash"] == "genesis"
    assert props["evidence-session-id"] == "session-1"
    assert props["evidence-tenant-id"] == "tenant-1"
    assert props["detected-data-types"] == '["DC-PII"]'
    assert props["sdk-version"] == "0.1.0"
    assert props["classification-context"] == '{"llm_provider": "openai"}'


def test_render_oscal_maps_posture_controls_to_findings() -> None:
    output = render_oscal([_record(control_id="GOV-01", result="ERROR")])
    payload = json.loads(output)

    result = payload["assessment-results"]["results"][0]
    assert result["observations"] == []
    assert len(result["findings"]) == 2

    assert [finding["target"]["target-id"] for finding in result["findings"]] == ["pl-2", "pm-1"]
    for finding in result["findings"]:
        assert finding["target"]["status"]["state"] == "not-satisfied"
        assert finding["props"][0]["value"] == "GOV-01"
