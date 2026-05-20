"""Tests for deterministic Cover gap assessment."""

from __future__ import annotations

from pathlib import Path

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.mcp_server import MCPServerContext
from ancilis.mcp_server.cover.gap_assessment import assess_gap
from ancilis.producers.tool import ToolActionProducer


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _context(raw: dict) -> MCPServerContext:
    config = load_config(raw=raw)
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, evidence_store=store)
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=store,
        action_producer=ToolActionProducer(
            config,
            engine,
            registry=engine.registry,
            evidence_store=store,
        ),
    )


def test_assess_gap_reports_setup_gap_without_config(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", "[project]\ndependencies = ['openai']\n")

    result = assess_gap(
        root=tmp_path,
        business_context="We handle patient records and need HIPAA.",
    )

    assert result.mode == "setup_gap"
    assert result.target.my_agent_handles == ["health_records"]
    assert result.target.active_overlays == ["hipaa"]
    assert result.config_gap.missing_my_agent_handles == ["health_records"]
    assert result.config_gap.missing_overlays == ["hipaa"]
    assert "openai" in result.instrumentation_gap.missing_producers
    assert result.evidence_gap.session_id is None
    assert result.next_steps[0].startswith("Create ancilis.yaml")
    assert result.warnings == []


def test_assess_gap_reports_present_config_items(tmp_path: Path) -> None:
    _write(
        tmp_path / "ancilis.yaml",
        "agent:\n  name: therapy\nmy_agent_handles:\n  - health_records\ncompliance:\n  overlays:\n    - hipaa\n",
    )

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records and HIPAA.",
    )

    assert result.config_gap.present_my_agent_handles == ["health_records"]
    assert result.config_gap.missing_my_agent_handles == []
    assert result.config_gap.present_overlays == ["hipaa"]
    assert result.config_gap.missing_overlays == []


def test_assess_gap_does_not_fall_back_when_project_config_is_invalid(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "ancilis.yaml", "my_agent_handles:\n  - not_a_real_type\n")
    runtime_context = _context(
        {
            "agent": {"name": "runtime"},
            "my_agent_handles": ["health_records"],
            "compliance": {"overlays": ["hipaa"]},
        }
    )

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records and HIPAA.",
        runtime_context=runtime_context,
    )

    assert any(warning.startswith("config_load_error:") for warning in result.warnings)
    assert result.config_gap.missing_my_agent_handles == ["health_records"]
    assert result.config_gap.present_my_agent_handles == []
    assert result.config_gap.missing_overlays == ["hipaa"]
    assert result.config_gap.present_overlays == []


def test_assess_gap_reports_evidence_gap_from_runtime_context(tmp_path: Path) -> None:
    context = _context(
        {
            "agent": {"name": "therapy"},
            "my_agent_handles": ["health_records"],
            "compliance": {"overlays": ["hipaa"]},
        }
    )
    evaluation = EvaluationResult(
        evaluation_id="eval-1",
        action_id="action-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="agent-1",
        source_type="tool",
        mode="audit",
        control_results=[ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "ok")],
        decision="ALLOW",
        decision_reason="test",
        active_overlays=["hipaa"],
        data_classifications=["DC-PHI"],
        total_duration_ms=1.0,
        session_id="session-1",
    )
    context.evidence_store.store(evaluation, tool_name="agent")

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records need HIPAA.",
        runtime_context=context,
    )

    assert result.mode == "evidence_gap"
    assert result.evidence_gap.session_id == "session-1"
    assert result.evidence_gap.controls_total > 0
    assert "PR-01" in result.evidence_gap.evidenced_controls
    assert "PR-01" not in result.evidence_gap.missing_controls


def test_assess_gap_ignores_session_id_without_runtime_context(tmp_path: Path) -> None:
    result = assess_gap(
        root=tmp_path,
        business_context="Patient records need HIPAA.",
        session_id="session-1",
    )

    assert result.mode == "setup_gap"
    assert result.evidence_gap.session_id is None
    assert result.evidence_gap.controls_total > 0
    assert result.evidence_gap.missing_controls
    assert "Run ancilis doctor and ancilis scan after setup to collect evidence." in result.next_steps


def test_assess_gap_ignores_empty_explicit_evidence_session(tmp_path: Path) -> None:
    context = _context(
        {
            "agent": {"name": "therapy"},
            "my_agent_handles": ["health_records"],
            "compliance": {"overlays": ["hipaa"]},
        }
    )

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records need HIPAA.",
        runtime_context=context,
        session_id="missing-session",
    )

    assert result.mode == "setup_gap"
    assert result.evidence_gap.session_id is None
    assert result.evidence_gap.controls_with_evidence == 0
    assert result.evidence_gap.missing_controls
    assert "Run ancilis doctor and ancilis scan after setup to collect evidence." in result.next_steps
