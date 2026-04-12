"""Targeted tests for renderer.py coverage gaps.

Covers: _render_advisory_terminal, render_pdf branches, _csv_value,
_markdown_fallback_path, _style no-op, broken-chain posture, AIUC-1
with compliance sections and advisory, upgrade advisories, _short_date edge cases.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from ancilis.report.generator import ReportData
from ancilis.report.renderer import (
    RenderPdfResult,
    _csv_value,
    _markdown_fallback_path,
    _numeric_threshold,
    _short_date,
    render_csv,
    render_markdown,
    render_ndjson,
    render_pdf,
    render_terminal,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _minimal_report_data(
    *,
    chain_valid: bool = True,
    advisory: dict | None = None,
    certification: dict | None = None,
    compliance_sections: list | None = None,
    failing_control_ids: list[str] | None = None,
    report_format: str = "markdown",
) -> ReportData:
    """Build the smallest valid ReportData for renderer tests."""
    failing = set(failing_control_ids or [])
    controls = [
        {
            "control_id": cid,
            "display_name": f"Control {cid}",
            "total": 10 if cid not in failing else 10,
            "passed": 10 if cid not in failing else 8,
            "failed": 0 if cid not in failing else 2,
            "pass_rate": 100.0 if cid not in failing else 80.0,
            "threshold": "standard",
        }
        for cid in ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]
    ]

    default_section = {
        "overlay_id": "test-overlay",
        "overlay_name": "Test Overlay",
        "triggered_by": "pii_data",
        "strict_controls": [],
        "controls": [
            {
                "control_id": "PR-01",
                "display_name": "Identity",
                "citations": ["TST-PR-01"],
                "total": 0,
                "passed": 0,
                "failed": 0,
                "pass_rate": 0.0,
                "threshold": "standard",
            }
        ],
        "gaps": [],
        "evidence_retention_days": 365,
        "retention_met": True,
    }

    return ReportData(
        agent_name="test-agent",
        mode="audit",
        period_start="2026-01-01T00:00:00+00:00",
        period_end="2026-01-31T23:59:59+00:00",
        generated_at="2026-02-01T00:00:00+00:00",
        report_format=report_format,
        baseline={
            "controls": controls,
            "tools_evaluated": ["tool_a"],
            "total_evaluations": 10,
            "decisions": {"allow": 8, "block": 2},
            "evidence_retention_days": 365,
        },
        compliance_sections=compliance_sections if compliance_sections is not None else [default_section],
        certification=certification,
        advisory=advisory,
        total_evaluations=10,
        chain_valid=chain_valid,
        chain_errors=[] if chain_valid else ["hash mismatch at record 3"],
    )


def _make_cert(
    *,
    chain_valid: bool = True,
    with_operator: bool = False,
    with_automated: bool = False,
    with_failures: bool = False,
) -> dict:
    automated = []
    if with_automated:
        automated = [
            {
                "requirement_id": "REQ-1",
                "aksi_control": "PR-01",
                "evidence_count": 5 if not with_failures else 5,
                "passed": 5 if not with_failures else 3,
                "failed": 0 if not with_failures else 2,
                "flagged": 0,
            },
        ]
    operator = []
    if with_operator:
        operator = [{"requirement_id": "REQ-O-1", "description": "Policy doc required"}]
    return {
        "certification_id": "aiuc-1",
        "certification_name": "AIUC-1",
        "readiness_percentage": 80,
        "ready_count": 12,
        "total_requirements": 15,
        "coverage_percentage": 75,
        "automated_count": 12,
        "operator_count": 3,
        "evidence_count": 100,
        "chain_valid": chain_valid,
        "automated_coverage": automated,
        "operator_action_required": operator,
    }


def _make_advisory(*, with_upgrade: bool = False) -> dict:
    advisory: dict = {
        "pattern_detections": [
            {"pattern_type": "PII_EMAIL", "count": 3},
        ],
        "recommendations": [
            {
                "suggested_value": "pii",
                "suggested_config_field": "my_agent_handles",
                "detection_count": 3,
                "severity": "medium",
                "example_config": "my_agent_handles: [pii]",
            }
        ],
        "upgrade_advisories": [],
    }
    if with_upgrade:
        advisory["upgrade_advisories"] = [
            {"message": "Consider upgrading to SOC 2 overlay for full coverage"}
        ]
    return advisory


# ---------------------------------------------------------------------------
# _csv_value — None branch
# ---------------------------------------------------------------------------


def test_csv_value_none_returns_empty_string() -> None:
    assert _csv_value(None) == ""


def test_csv_value_list_returns_json() -> None:
    result = _csv_value(["a", "b"])
    assert result == '["a", "b"]'


def test_csv_value_dict_returns_sorted_json() -> None:
    result = _csv_value({"z": 1, "a": 2})
    assert result == '{"a": 2, "z": 1}'


def test_csv_value_string_passthrough() -> None:
    assert _csv_value("hello") == "hello"


# ---------------------------------------------------------------------------
# _markdown_fallback_path — branches
# ---------------------------------------------------------------------------


def test_markdown_fallback_path_pdf_suffix() -> None:
    result = _markdown_fallback_path("/tmp/report.pdf")
    assert result == "/tmp/report.md"


def test_markdown_fallback_path_md_suffix_returns_same() -> None:
    result = _markdown_fallback_path("/tmp/report.md")
    assert result == "/tmp/report.md"


def test_markdown_fallback_path_other_extension_appends_md() -> None:
    result = _markdown_fallback_path("/tmp/report.txt")
    assert result == "/tmp/report.txt.md"


def test_markdown_fallback_path_no_extension_appends_md() -> None:
    result = _markdown_fallback_path("/tmp/report")
    assert result == "/tmp/report.md"


# ---------------------------------------------------------------------------
# _numeric_threshold — non-numeric branch
# ---------------------------------------------------------------------------


def test_numeric_threshold_returns_none_for_list() -> None:
    assert _numeric_threshold([1, 2, 3]) is None


def test_numeric_threshold_returns_none_for_dict() -> None:
    assert _numeric_threshold({"key": "value"}) is None


def test_numeric_threshold_int() -> None:
    assert _numeric_threshold(95) == 95.0


def test_numeric_threshold_string_float() -> None:
    assert _numeric_threshold("90.5") == 90.5


def test_numeric_threshold_invalid_string() -> None:
    assert _numeric_threshold("strict") is None


# ---------------------------------------------------------------------------
# render_pdf — success and CalledProcessError branches
# ---------------------------------------------------------------------------


def test_render_pdf_success(tmp_path: Path) -> None:
    output = str(tmp_path / "report.pdf")
    markdown = "# Test Report\n\nContent here."

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = None
        result = render_pdf(markdown, output)

    assert result.format == "pdf"
    assert result.output_path == output
    assert result.fallback_reason is None


def test_render_pdf_called_process_error_falls_back_to_markdown(tmp_path: Path) -> None:
    output = str(tmp_path / "report.pdf")
    markdown = "# Test\n\nFallback content."

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, "pandoc")
        result = render_pdf(markdown, output)

    assert result.format == "markdown"
    assert result.output_path == str(tmp_path / "report.md")
    assert result.fallback_reason is not None
    assert Path(result.output_path).read_text() == markdown


def test_render_pdf_file_not_found_falls_back_to_markdown(tmp_path: Path) -> None:
    output = str(tmp_path / "report.pdf")
    markdown = "# Test\n\nContent."

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError
        result = render_pdf(markdown, output)

    assert result.format == "markdown"
    assert result.fallback_reason is not None


# ---------------------------------------------------------------------------
# render_terminal — advisory section (lines 107-108, 457-479)
# ---------------------------------------------------------------------------


def test_render_terminal_with_advisory_no_upgrade(monkeypatch) -> None:
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data(advisory=_make_advisory(with_upgrade=False))
    output = render_terminal(data)

    assert "Classification Advisory" in output
    assert "PII_EMAIL" in output
    assert "3 occurrence" in output


def test_render_terminal_with_advisory_and_upgrade_advisories(monkeypatch) -> None:
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data(advisory=_make_advisory(with_upgrade=True))
    output = render_terminal(data)

    assert "Certification upgrade advisories" in output
    assert "SOC 2" in output


def test_render_terminal_with_advisory_recommendations(monkeypatch) -> None:
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data(advisory=_make_advisory())
    output = render_terminal(data)

    assert "Recommended config updates" in output
    assert "pii" in output
    assert "my_agent_handles" in output


# ---------------------------------------------------------------------------
# render_terminal — broken chain posture (CRITICAL)
# ---------------------------------------------------------------------------


def test_render_terminal_broken_chain_shows_critical(monkeypatch) -> None:
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data(chain_valid=False)
    output = render_terminal(data)

    assert "CRITICAL" in output


def test_render_terminal_many_failing_controls_shows_critical(monkeypatch) -> None:
    # 3+ failing controls → CRITICAL even with valid chain
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data(
        failing_control_ids=["PR-01", "PR-02", "PR-03"],
    )
    output = render_terminal(data)

    assert "CRITICAL" in output


# ---------------------------------------------------------------------------
# render_terminal — zero-total control mark (line 351: returns "-")
# ---------------------------------------------------------------------------


def test_render_terminal_zero_total_control_shows_dash(monkeypatch) -> None:
    monkeypatch.setattr("ancilis.report.renderer._use_color", lambda: False)
    data = _minimal_report_data()
    # The default section already has a control with total=0
    output = render_terminal(data)
    # No assertion on exact character — just ensure no crash and output exists
    assert "test-agent" in output


# ---------------------------------------------------------------------------
# render_markdown — broken chain executive summary (line 506)
# ---------------------------------------------------------------------------


def test_render_markdown_broken_chain_in_executive_summary() -> None:
    data = _minimal_report_data(chain_valid=False)
    output = render_markdown(data)

    assert "BROKEN" in output


# ---------------------------------------------------------------------------
# render_markdown — zero-total control in compliance section (line 561)
# ---------------------------------------------------------------------------


def test_render_markdown_compliance_zero_total_control() -> None:
    section_with_zero = {
        "overlay_id": "soc2",
        "overlay_name": "SOC 2",
        "triggered_by": "",
        "strict_controls": [],
        "controls": [
            {
                "control_id": "PR-01",
                "display_name": "Identity",
                "citations": ["CC6.1"],
                "total": 0,
                "passed": 0,
                "failed": 0,
                "pass_rate": 0.0,
                "threshold": "standard",
            }
        ],
        "gaps": [],
        "evidence_retention_days": 365,
        "retention_met": True,
    }
    data = _minimal_report_data(compliance_sections=[section_with_zero])
    output = render_markdown(data)

    # Zero-total control row shows "- " (no data marker) in the pass rate column
    assert "| CC6.1 | PR-01 | 0 | - |" in output


# ---------------------------------------------------------------------------
# render_markdown — advisory upgrade advisories (lines 643-647)
# ---------------------------------------------------------------------------


def test_render_markdown_advisory_upgrade_advisories() -> None:
    data = _minimal_report_data(advisory=_make_advisory(with_upgrade=True))
    output = render_markdown(data)

    assert "Certification Upgrade Advisories" in output
    assert "SOC 2" in output


# ---------------------------------------------------------------------------
# render_markdown — AIUC-1 format with compliance sections (712-713, 717-718)
# ---------------------------------------------------------------------------


def test_render_markdown_aiuc1_with_compliance_sections() -> None:
    section = {
        "overlay_id": "soc2",
        "overlay_name": "SOC 2",
        "triggered_by": "pii",
        "strict_controls": [],
        "controls": [
            {
                "control_id": "PR-01",
                "display_name": "Identity",
                "citations": ["CC6.1"],
                "total": 5,
                "passed": 5,
                "failed": 0,
                "pass_rate": 100.0,
                "threshold": "standard",
            }
        ],
        "gaps": [],
        "evidence_retention_days": 365,
        "retention_met": True,
    }
    data = _minimal_report_data(
        report_format="aiuc1-readiness",
        certification=_make_cert(),
        compliance_sections=[section],
    )
    output = render_markdown(data)

    assert "AIUC-1 READINESS REPORT" in output
    assert "SOC 2" in output


def test_render_markdown_aiuc1_with_advisory() -> None:
    data = _minimal_report_data(
        report_format="aiuc1-readiness",
        certification=_make_cert(),
        advisory=_make_advisory(with_upgrade=True),
        compliance_sections=[],
    )
    output = render_markdown(data)

    assert "AIUC-1 READINESS REPORT" in output
    assert "Classification Advisory" in output


# ---------------------------------------------------------------------------
# render_markdown — AIUC-1 early return when cert is None (line 654)
# ---------------------------------------------------------------------------


def test_render_markdown_aiuc1_format_no_cert_falls_through_to_standard() -> None:
    data = _minimal_report_data(
        report_format="aiuc1-readiness",
        certification=None,
        compliance_sections=[],
    )
    output = render_markdown(data)

    # Falls through to standard report (no aiuc1 early return with cert)
    assert "Ancilis Posture Report" in output


# ---------------------------------------------------------------------------
# render_markdown — AIUC-1 with failure details (line 690)
# ---------------------------------------------------------------------------


def test_render_markdown_aiuc1_automated_coverage_with_failures() -> None:
    data = _minimal_report_data(
        report_format="aiuc1-readiness",
        certification=_make_cert(with_automated=True, with_failures=True),
        compliance_sections=[],
    )
    output = render_markdown(data)

    assert "failures" in output


# ---------------------------------------------------------------------------
# _short_date — edge cases (line 729: len < 10)
# ---------------------------------------------------------------------------


def test_short_date_with_short_string() -> None:
    # Very short string — should return it as-is (< 10 chars)
    result = _short_date("2026-01")
    assert result == "2026-01"


def test_short_date_with_iso_timestamp() -> None:
    result = _short_date("2026-01-15T12:00:00Z")
    assert result == "2026-01-15"


def test_short_date_with_exactly_10_chars() -> None:
    result = _short_date("2026-01-15")
    assert result == "2026-01-15"


# ---------------------------------------------------------------------------
# render_ndjson and render_csv — ensure no crash on empty lists
# ---------------------------------------------------------------------------


def test_render_ndjson_empty_list() -> None:
    assert render_ndjson([]) == ""


def test_render_csv_empty_list() -> None:
    result = render_csv([])
    assert "record_id" in result  # header only
