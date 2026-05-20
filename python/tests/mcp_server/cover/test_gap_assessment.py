"""Tests for deterministic Cover gap assessment."""

from __future__ import annotations

from pathlib import Path

from ancilis.config import load_config
from ancilis.engine.engine import Engine
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
