"""Smoke tests for the acquirer-demo scenario generator."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[3]
RUN_DEMO_PATH = ROOT / "examples" / "demo_scenarios" / "run_demo.py"

EXPECTED_AGENTS = {
    "patient_intake_agent",
    "payment_processor",
    "code_review_agent",
    "hr_onboarding_bot",
    "data_pipeline_agent",
}


def _load_demo_module():
    assert RUN_DEMO_PATH.exists(), f"Demo scenario runner missing: {RUN_DEMO_PATH}"
    spec = importlib.util.spec_from_file_location("examples.demo_scenarios.run_demo", RUN_DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _records(db_path: Path):
    config = load_config(raw={"agent": {"name": "demo-scenario-reader"}})
    store = EvidenceStore(config, db_path=db_path)
    try:
        return store.get_records(limit=None), store.verify_chain()
    finally:
        store.close()


def test_demo_scenarios_generate_five_agents_with_realistic_evidence(tmp_path: Path) -> None:
    module = _load_demo_module()
    db_path = tmp_path / "demo-scenarios.duckdb"
    ndjson_path = tmp_path / "evidence.ndjson"

    result = module.main(["--db", str(db_path), "--output", str(ndjson_path)])

    records, chain = _records(db_path)
    assert result.agent_count == 5
    assert result.evidence_count >= 15
    assert {record.agent_id for record in records} == EXPECTED_AGENTS
    assert {record.decision for record in records} >= {"ALLOW", "BLOCK", "FLAG"}
    assert chain == (True, [])

    overlays = {overlay for record in records for overlay in record.active_overlays}
    assert {"hipaa", "pci-dss-v4", "soc2", "gdpr", "ccpa", "glba", "cmmc-l2"} <= overlays

    data_types = {data_type for record in records for data_type in record.data_classifications}
    assert {"DC-PHI", "DC-PII", "DC-CHD", "DC-GEN", "DC-IP", "DC-CUI", "DC-FIN"} <= data_types

    exported = [json.loads(line) for line in ndjson_path.read_text().splitlines()]
    assert len(exported) == len(records)
    assert {item["agent_id"] for item in exported} == EXPECTED_AGENTS


def test_demo_scenarios_spread_timestamps_over_a_credible_timeline(tmp_path: Path) -> None:
    module = _load_demo_module()
    db_path = tmp_path / "timeline.duckdb"

    module.main(["--db", str(db_path)])

    records, _ = _records(db_path)
    timestamps = [datetime.fromisoformat(record.timestamp.replace("Z", "+00:00")) for record in records]

    assert max(timestamps) - min(timestamps) >= module.FULL_TIMELINE_SPAN
    assert timestamps == sorted(timestamps)


def test_demo_scenarios_fast_mode_keeps_one_call_per_agent(tmp_path: Path) -> None:
    module = _load_demo_module()
    db_path = tmp_path / "fast.duckdb"

    result = module.main(["--fast", "--db", str(db_path)])

    records, chain = _records(db_path)
    assert result.agent_count == 5
    assert result.evidence_count == 5
    assert {record.agent_id for record in records} == EXPECTED_AGENTS
    assert chain == (True, [])


def test_demo_scenarios_cli_outputs_recording_ready_summary(tmp_path: Path) -> None:
    db_path = tmp_path / "cli.duckdb"
    ndjson_path = tmp_path / "cli.ndjson"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "python" / "src")

    completed = subprocess.run(
        [
            sys.executable,
            str(RUN_DEMO_PATH),
            "--fast",
            "--db",
            str(db_path),
            "--output",
            str(ndjson_path),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=True,
        text=True,
    )

    assert "Generated 5 demo agents" in completed.stdout
    assert "patient_intake_agent" in completed.stdout
    assert "payment_processor" in completed.stdout
    assert "Push to platform" in completed.stdout
    assert ndjson_path.exists()
    assert len(ndjson_path.read_text().splitlines()) == 5
