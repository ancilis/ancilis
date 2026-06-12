"""Regression tests for control-scope honesty (audit findings F16, F17)."""

from __future__ import annotations

import json
from pathlib import Path

from ancilis.config import (
    load_config,
    load_control_definitions,
    load_overlay_definitions,
)
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.evaluators.gov01_identity_auth import GOV01IdentityAuthEvaluator
from ancilis.report.compliance import build_compliance_sections
from ancilis.report.renderer import _render_compliance_markdown

ROOT = Path(__file__).resolve().parents[2]


# --- F16: reports surface runtime-evidence vs organizational scope -----------


def test_compliance_sections_surface_runtime_vs_organizational() -> None:
    cfg = load_config(raw={"agent": {"name": "a"}, "my_agent_handles": ["personal_info"]})
    sections = build_compliance_sections(
        cfg, {"control_pass_rates": {}}, load_control_definitions(), load_overlay_definitions()
    )
    assert sections, "personal_info should activate at least one overlay"
    for s in sections:
        assert {"runtime_criteria", "total_criteria", "organizational_criteria", "scaffold"} <= s.keys()
        assert s["runtime_criteria"] + s["organizational_criteria"] == s["total_criteria"]
        for c in s["controls"]:
            assert "support_level" in c
            assert "runtime_testable" in c
        if not s["scaffold"]:
            lines: list[str] = []
            _render_compliance_markdown(lines, s)
            md = "\n".join(lines)
            assert "runtime evidence for" in md and "mapped criteria" in md
            assert "organizational controls it does not assess" in md
            # Per-control runtime/attestation Type column is present.
            assert "| Type |" in md


def test_scaffold_overlay_renders_caveat_not_false_coverage() -> None:
    section = {
        "overlay_name": "Agent Payments",
        "triggered_by": "",
        "strict_controls": [],
        "controls": [],
        "scaffold": True,
        "runtime_criteria": 0,
        "total_criteria": 0,
        "organizational_criteria": 0,
        "gaps": [],
    }
    lines: list[str] = []
    _render_compliance_markdown(lines, section)
    md = "\n".join(lines)
    assert "Scaffold mapping" in md
    assert "not yet verified" in md.lower()


def test_controls_have_support_level_distinguisher_on_disk() -> None:
    # The machine-readable runtime-vs-organizational field already exists as
    # support_level; confirm every control carries it with a known value.
    defs = load_control_definitions()
    assert len(defs) == 41
    levels = {c.get("support_level") for c in defs.values()}
    assert levels <= {"runtime_evaluator", "attestation"}
    runtime = sum(1 for c in defs.values() if c.get("support_level") == "runtime_evaluator")
    attestation = sum(1 for c in defs.values() if c.get("support_level") == "attestation")
    assert runtime + attestation == 41
    assert runtime > 0 and attestation > 0


# --- F17: GOV-01 is named/detailed for what it does (no authentication claim) -


def test_gov01_does_not_claim_authentication() -> None:
    ev = GOV01IdentityAuthEvaluator()
    assert ev.control_name == "Agent Identity Declaration and Match"
    assert "authentication" not in ev.control_name.lower()

    gov = json.loads((ROOT / "shared" / "controls" / "gov-01.json").read_text())
    assert "authentication" not in gov["display_name"].lower()
    assert "authentication" not in gov["name"].lower()
    # The description must explicitly disclaim credential authentication.
    assert "not credential authentication" in gov["description"].lower()


def test_gov01_pass_detail_says_match_not_verified() -> None:
    cfg = load_config(raw={"agent": {"name": "agentx"}})
    action = Action(
        action_id="a", timestamp="2026-06-06T00:00:00Z", agent_id="agentx",
        action_type="tool_call", tool=ToolInfo(name="x"), parameters=ActionParameters(raw={}),
    )
    res = GOV01IdentityAuthEvaluator().evaluate(action, cfg)
    assert res.result == "PASS"
    assert "matches configured declaration" in res.detail.lower()
    assert "verified" not in res.detail.lower()


def test_gov01_behavior_unchanged() -> None:
    cfg = load_config(raw={"agent": {"name": "agentx", "owner": "alice"}})
    ev = GOV01IdentityAuthEvaluator()

    def _act(agent_id: str, owner: str | None = None) -> Action:
        return Action(
            action_id="a", timestamp="2026-06-06T00:00:00Z", agent_id=agent_id,
            action_type="tool_call", tool=ToolInfo(name="x"),
            parameters=ActionParameters(raw={}), agent_owner=owner,
        )

    assert ev.evaluate(_act(""), cfg).result == "FAIL"          # missing identity
    assert ev.evaluate(_act("wrong"), cfg).result == "FAIL"     # mismatch
    assert ev.evaluate(_act("agentx", "bob"), cfg).result == "FAIL"   # owner mismatch
    assert ev.evaluate(_act("agentx", "alice"), cfg).result == "PASS"  # match
