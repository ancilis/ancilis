"""Tests for the discovery demo seed script and orchestration."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import ancilis.evidence.store as evidence_store_module

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
DISCOVERY_RUN_PATH = ROOT / "examples" / "demo" / "run-discovery.py"
DISCOVERY_RUN_ALL_PATH = ROOT / "examples" / "demo" / "run-discovery.sh"
DISCOVERY_ROOT = ROOT / "examples" / "demo" / "discovery"
DISCOVERY_MANIFEST_PATH = DISCOVERY_ROOT / "discovery-manifest.json"
DISCOVERY_AGENT_ROOT = DISCOVERY_ROOT / "agents"

EXPECTED_AGENTS = {
    "payments-processor": {
        "runtime_type": "bedrock",
        "data_types": ["credit_cards", "financial_records", "personal_info"],
        "detected_data_types": ["DC-CHD", "DC-PII"],
        "evidence_summary": {"allow": 5, "block": 1, "flag": 0},
    },
    "fraud-sentinel": {
        "runtime_type": "cli",
        "data_types": ["credit_cards", "financial_records", "personal_info"],
        "detected_data_types": ["DC-CHD", "DC-PII"],
        "evidence_summary": {"allow": 4, "block": 2, "flag": 0},
    },
    "compliance-auditor": {
        "runtime_type": "framework",
        "data_types": ["financial_records", "health_records", "personal_info"],
        "detected_data_types": ["DC-PHI", "DC-PII"],
        "evidence_summary": {"allow": 5, "block": 1, "flag": 0},
    },
    "invoice-extractor": {
        "runtime_type": "mcp",
        "data_types": ["financial_records", "personal_info"],
        "detected_data_types": ["DC-PII"],
        "evidence_summary": {"allow": 5, "block": 1, "flag": 1},
    },
    "customer-assist": {
        "runtime_type": "http",
        "data_types": ["credit_cards", "health_records", "personal_info"],
        "detected_data_types": ["DC-CHD", "DC-PHI", "DC-PII"],
        "evidence_summary": {"allow": 5, "block": 2, "flag": 0},
    },
}


def _load_discovery_module():
    assert DISCOVERY_RUN_PATH.exists(), f"Discovery demo script missing: {DISCOVERY_RUN_PATH}"
    spec = importlib.util.spec_from_file_location("examples.demo.run_discovery", DISCOVERY_RUN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_discovery(tmp_path: Path, monkeypatch):
    module = _load_discovery_module()
    monkeypatch.setattr(evidence_store_module, "DEFAULT_DB_DIR", tmp_path / ".ancilis")
    monkeypatch.chdir(tmp_path)
    stream = io.StringIO()
    output_dir = tmp_path / "discovery-output"

    result = module.main(output_dir=output_dir, stream=stream)

    return module, result, stream.getvalue()


def _posture_summary(records) -> dict[str, int]:
    summary = {"allow": 0, "block": 0, "flag": 0}
    for record in records:
        results = {item["result"] for item in record.control_results}
        if {"FAIL", "ERROR"} & results:
            summary["block"] += 1
        elif "FLAG" in results:
            summary["flag"] += 1
        else:
            summary["allow"] += 1
    return summary


def test_discovery_agent_configs_load_successfully() -> None:
    for agent_name, expected in EXPECTED_AGENTS.items():
        config_path = DISCOVERY_AGENT_ROOT / agent_name / "ancilis.yaml"
        assert config_path.exists(), f"Missing discovery config: {config_path}"

        config = load_config(path=config_path)

        assert config.agent_name == agent_name
        assert sorted(config.data_classifications) == expected["data_types"]


def test_run_discovery_generates_expected_evidence_and_manifest(tmp_path: Path, monkeypatch) -> None:
    _, result, output = _run_discovery(tmp_path, monkeypatch)

    assert len(result.agents) == 5
    assert result.total_evidence_records == 32
    assert Path(result.manifest_path).exists()
    assert "Discovery demo manifest:" in output

    agents_by_name = {agent.name: agent for agent in result.agents}
    assert set(agents_by_name) == set(EXPECTED_AGENTS)

    for agent_name, expected in EXPECTED_AGENTS.items():
        agent = agents_by_name[agent_name]
        assert agent.runtime_type == expected["runtime_type"]
        assert sorted(agent.data_types) == expected["data_types"]
        assert sorted(agent.detected_data_types) == expected["detected_data_types"]
        assert agent.evidence_summary == expected["evidence_summary"]
        assert agent.first_seen < agent.last_seen

        config = load_config(path=agent.config_path)
        store = EvidenceStore(config, db_path=agent.db_path)
        try:
            records = store.get_records(limit=None)
            assert len(records) == sum(expected["evidence_summary"].values())
            assert _posture_summary(records) == expected["evidence_summary"]
            assert sorted({record.source_type for record in records}) == [expected["runtime_type"]]
            assert sorted({dt for record in records for dt in record.detected_data_types}) == expected["detected_data_types"]
            assert records[0].timestamp < records[-1].timestamp
            valid, errors = store.verify_chain()
            assert valid, errors
        finally:
            store.close()


def test_run_discovery_manifest_has_expected_structure(tmp_path: Path, monkeypatch) -> None:
    _, result, _ = _run_discovery(tmp_path, monkeypatch)

    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))

    assert manifest["total_evidence_records"] == 32
    assert len(manifest["agents"]) == 5
    assert {agent["runtime_type"] for agent in manifest["agents"]} == {
        "mcp",
        "bedrock",
        "cli",
        "framework",
        "http",
    }
    assert manifest["sdk_direct_integration"]["source_type"] == "sdk_direct"
    assert manifest["sdk_direct_integration"]["config"]["transport"]["mode"] == "local_file"
    assert sorted(manifest["sdk_direct_integration"]["config"]["transport"]["paths"]) == sorted(
        agent["db_path"] for agent in manifest["agents"]
    )

    for item in manifest["agents"]:
        expected = EXPECTED_AGENTS[item["name"]]
        assert item["runtime_type"] == expected["runtime_type"]
        assert sorted(item["data_types"]) == expected["data_types"]
        assert sorted(item["detected_data_types"]) == expected["detected_data_types"]
        assert item["first_seen"] < item["last_seen"]
        assert item["evidence_summary"] == expected["evidence_summary"]
        assert item["classification_findings"]
        assert {finding["status"] for finding in item["classification_findings"]} == {
            "pending_confirmation"
        }
        assert Path(item["config_path"]).exists()
        assert Path(item["db_path"]).exists()
        assert item["tool_count"] >= 6


def test_run_discovery_shell_script_targets_platform_discovery_flow() -> None:
    assert DISCOVERY_RUN_ALL_PATH.exists(), f"Missing discovery orchestration script: {DISCOVERY_RUN_ALL_PATH}"
    script = DISCOVERY_RUN_ALL_PATH.read_text(encoding="utf-8")

    assert "python examples/demo/run-discovery.py" in script
    assert str(DISCOVERY_MANIFEST_PATH.relative_to(ROOT)) in script
    assert "/v1/discovery/sessions" in script
    assert "/agents" in script
    assert "/discovery" in script
