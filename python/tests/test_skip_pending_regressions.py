"""Regression tests: SKIP results are pending, never passing.

Follow-ups to the "SKIP rendered as passing" fix — covers posture status,
compliance matrix/table rendering, pass-rate denominators, scan output,
OSCAL state mapping, and the demo dashboard.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.baselines.drift import _pass_rate
from ancilis.cli.main import cli
from ancilis.config import (
    load_config,
    load_control_definitions,
    load_overlay_definitions,
)
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.remediation import _stats_for
from ancilis.report.compliance import build_compliance_sections
from ancilis.report.generator import ReportData
from ancilis.report.renderer import (
    _build_posture_summary,
    _matrix_cell,
    _render_baseline_markdown,
)
from ancilis.report.renderers.oscal import render_oscal

ROOT = Path(__file__).resolve().parents[2]


def _control(
    *, total: int, passed: int, failed: int, skipped: int, pass_rate: float = 0.0
) -> dict[str, Any]:
    return {
        "control_id": "PR-01",
        "display_name": "PR-01 control",
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "evaluated": total - skipped,
        "pass_rate": pass_rate,
        "threshold": "standard",
    }


# --- 1. Posture status: nothing evaluated is PENDING, not HEALTHY ------------


def test_posture_pending_when_all_controls_skip_only() -> None:
    data = ReportData(
        baseline={"controls": [_control(total=4, passed=0, failed=0, skipped=4)]},
    )
    posture = _build_posture_summary(data)
    assert posture["passing_control_count"] == 0
    assert posture["pending_control_count"] == 1
    assert posture["status"] == "PENDING"
    assert posture["status_color"] != "green"


def test_posture_healthy_when_a_control_actually_passes() -> None:
    data = ReportData(
        baseline={
            "controls": [
                _control(total=4, passed=4, failed=0, skipped=0, pass_rate=100.0),
                _control(total=2, passed=0, failed=0, skipped=2),
            ]
        },
    )
    posture = _build_posture_summary(data)
    assert posture["status"] == "HEALTHY"
    assert posture["status_color"] == "green"


def test_posture_healthy_with_no_controls_at_all() -> None:
    posture = _build_posture_summary(ReportData(baseline={"controls": []}))
    assert posture["status"] == "HEALTHY"


# --- 2. Matrix cell and markdown table: SKIP-only is pending, not a pass -----


def test_matrix_cell_skip_only_renders_pending_dash() -> None:
    assert _matrix_cell(_control(total=3, passed=0, failed=0, skipped=3), False) == "-"


def test_matrix_cell_pass_and_fail_unchanged() -> None:
    assert _matrix_cell(_control(total=3, passed=3, failed=0, skipped=0), False) == "✓"
    assert "✗" in _matrix_cell(_control(total=3, passed=0, failed=2, skipped=1), False)


def test_baseline_markdown_table_skip_only_is_pending() -> None:
    lines: list[str] = []
    _render_baseline_markdown(
        lines,
        {
            "controls": [
                _control(total=3, passed=0, failed=0, skipped=3),
                _control(total=3, passed=3, failed=0, skipped=0, pass_rate=100.0),
            ]
        },
    )
    md = "\n".join(lines)
    assert "| Pending |" in md
    assert "| Pass |" in md


# --- 3. Compliance sections: pass rate over evaluated (non-SKIP) results -----


def test_compliance_pass_rate_excludes_skip_from_denominator() -> None:
    cfg = load_config(raw={"agent": {"name": "a"}, "my_agent_handles": ["personal_info"]})
    sections = build_compliance_sections(
        cfg,
        {"control_pass_rates": {"PR-01": {"PASS": 1, "SKIP": 3}}},
        load_control_definitions(),
        load_overlay_definitions(),
    )
    rows = [c for s in sections for c in s["controls"] if c["control_id"] == "PR-01"]
    assert rows, "PR-01 should appear in at least one active overlay"
    for row in rows:
        assert row["total"] == 4
        assert row["skipped"] == 3
        assert row["evaluated"] == 1
        assert row["pass_rate"] == 100.0


def test_compliance_pass_rate_skip_only_is_zero_not_divide_error() -> None:
    cfg = load_config(raw={"agent": {"name": "a"}, "my_agent_handles": ["personal_info"]})
    sections = build_compliance_sections(
        cfg,
        {"control_pass_rates": {"PR-01": {"SKIP": 5}}},
        load_control_definitions(),
        load_overlay_definitions(),
    )
    rows = [c for s in sections for c in s["controls"] if c["control_id"] == "PR-01"]
    assert rows
    for row in rows:
        assert row["pass_rate"] == 0.0


# --- 4. scan: SKIP-only controls report pending, pass_rate over evaluated ----


def _skip_only_evaluation(control_id: str = "PR-01") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id="skip-eval",
        action_id="skip-action",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="test-agent",
        mode="audit",
        control_results=[
            ControlResult(
                control_id=control_id,
                control_name=f"{control_id} control",
                result="SKIP",
                detail="no evaluator ran",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision="ALLOW",
        decision_reason="",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


def test_scan_ci_skip_only_control_is_pending_not_pass(tmp_path: Path) -> None:
    cfg_path = tmp_path / "ancilis.yaml"
    cfg_path.write_text(yaml.dump({"agent": {"name": "test-agent", "owner": "o"}}))
    db = tmp_path / "evidence.db"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db))
    store.store(_skip_only_evaluation(), tool_name="read_file")
    store.close()

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg_path), "--db", str(db)])
    assert result.exit_code == 0
    data = json.loads(result.output)

    pr01 = next(c for c in data["controls"] if c["id"] == "PR-01")
    assert pr01["status"] == "pending"
    assert pr01["evaluated"] == 0
    assert pr01["skips"] == 1
    assert data["summary"]["pending"] >= 1
    assert data["summary"]["evaluated_results"] == 0
    assert data["summary"]["pass_rate"] == 0.0
    # SKIP-only never counted as passing.
    passing = [c for c in data["controls"] if c["status"] == "pass"]
    assert all(c["id"] != "PR-01" for c in passing)


def test_scan_human_skip_only_control_shows_pending(tmp_path: Path) -> None:
    cfg_path = tmp_path / "ancilis.yaml"
    cfg_path.write_text(yaml.dump({"agent": {"name": "test-agent", "owner": "o"}}))
    db = tmp_path / "evidence.db"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db))
    store.store(_skip_only_evaluation(), tool_name="read_file")
    store.close()

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--config", str(cfg_path), "--db", str(db)])
    assert result.exit_code == 0
    assert "pending" in result.output
    assert "PR-01 control — pass" not in result.output


# --- 5. Denominators: remediation and baseline drift exclude SKIP ------------


def test_remediation_stats_pass_rate_over_evaluated_only() -> None:
    summary = {"control_pass_rates": {"PR-01": {"PASS": 1, "FAIL": 1, "SKIP": 2}}}
    total, failures, flags, pass_rate = _stats_for(summary, "PR-01")
    assert total == 4
    assert failures == 1
    assert pass_rate == 50.0  # 1 PASS / 2 evaluated, not 1/4


def test_remediation_stats_skip_only_rate_is_zero() -> None:
    summary = {"control_pass_rates": {"PR-01": {"SKIP": 3}}}
    total, failures, flags, pass_rate = _stats_for(summary, "PR-01")
    assert total == 3
    assert pass_rate == 0.0


def test_remediation_stats_unchanged_without_skips() -> None:
    summary = {"control_pass_rates": {"PR-01": {"PASS": 3, "FAIL": 1}}}
    total, failures, flags, pass_rate = _stats_for(summary, "PR-01")
    assert total == 4
    assert pass_rate == 75.0


def test_drift_pass_rate_excludes_skip() -> None:
    stats = {"total": 4, "pass": 1, "fail": 1, "flag": 0, "error": 0, "skip": 2}
    assert _pass_rate(stats) == 0.5  # 1/2 evaluated, not 1/4


def test_drift_pass_rate_skip_only_treated_as_no_evidence() -> None:
    stats = {"total": 3, "pass": 0, "fail": 0, "flag": 0, "error": 0, "skip": 3}
    assert _pass_rate(stats) == 1.0  # same as total == 0 (no evidence, no drift)


def test_drift_pass_rate_unchanged_without_skips() -> None:
    stats = {"total": 4, "pass": 3, "fail": 1, "flag": 0, "error": 0, "skip": 0}
    assert _pass_rate(stats) == 0.75


# --- 6. OSCAL: SKIP is not-satisfied (pending), never not-applicable ---------


def _oscal_record(*, control_id: str, result: str) -> EvidenceRecord:
    return EvidenceRecord(
        record_id=f"record-{control_id.lower()}",
        evaluation_id=f"eval-{control_id.lower()}",
        timestamp="2026-04-14T00:00:00+00:00",
        agent_id="agent-1",
        source_type="agent",
        tool_name="read_file",
        decision="ALLOW",
        mode="audit",
        control_results=[
            {
                "control_id": control_id,
                "control_name": f"{control_id} control",
                "result": result,
                "detail": f"{control_id} detail",
                "evidence_data": {},
                "duration_ms": 1.0,
            }
        ],
        active_overlays=[],
        data_classifications=[],
        active_certifications=[],
        record_hash=f"hash-{control_id.lower()}",
        previous_hash="genesis",
    )


def test_oscal_skip_finding_is_not_satisfied_with_pending_remark() -> None:
    output = render_oscal([_oscal_record(control_id="GOV-01", result="SKIP")])
    assert "not-applicable" not in output
    payload = json.loads(output)
    findings = payload["assessment-results"]["results"][0]["findings"]
    assert findings
    for finding in findings:
        status = finding["target"]["status"]
        assert status["state"] == "not-satisfied"
        assert status["reason"] == "SKIP"
        assert "pending" in status["remarks"]


def test_oscal_skip_observation_carries_pending_remark() -> None:
    output = render_oscal([_oscal_record(control_id="PR-01", result="SKIP")])
    assert "not-applicable" not in output
    payload = json.loads(output)
    observations = payload["assessment-results"]["results"][0]["observations"]
    assert observations
    for observation in observations:
        assert "pending" in observation["remarks"]
        states = [p["value"] for p in observation["props"] if p["name"] == "assessment-state"]
        assert states == ["not-satisfied"]


def test_oscal_pass_and_fail_states_unchanged() -> None:
    output = render_oscal(
        [
            _oscal_record(control_id="GOV-01", result="PASS"),
            _oscal_record(control_id="PR-01", result="PASS"),
        ]
    )
    payload = json.loads(output)
    result = payload["assessment-results"]["results"][0]
    for finding in result["findings"]:
        assert finding["target"]["status"]["state"] == "satisfied"
        assert "remarks" not in finding["target"]["status"]
    for observation in result["observations"]:
        assert "remarks" not in observation


# --- 7. Demo dashboard: pass rate computed from result counts, no NaN --------


def test_dashboard_rates_computed_over_evaluated_counts() -> None:
    html = (ROOT / "examples" / "demo" / "static" / "dashboard.html").read_text(
        encoding="utf-8"
    )
    # The old bug: multiplying the per-control status-count dict as a scalar.
    assert "Math.round(rate * 100)" not in html
    # The fix rates PASS over evaluated (non-SKIP) results and shows Pending
    # when nothing was evaluated.
    assert "counts.SKIP" in html
    assert "counts.PASS" in html
    assert "Pending" in html


# --- 8. Docs advertise the `pending` coverage_status --------------------------


def test_docs_include_pending_coverage_status() -> None:
    assert "`pending`" in (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
    assert "`pending`" in (ROOT / "docs" / "evidence-and-reporting.md").read_text(
        encoding="utf-8"
    )
    certify = (ROOT / "docs" / "cli" / "certify.mdx").read_text(encoding="utf-8")
    assert "`pending`" in certify and "collect evidence" in certify
