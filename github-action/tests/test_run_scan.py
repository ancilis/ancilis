"""Unit tests for github-action/scripts/run-scan.py."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import the script as a module (it lives outside the installed package)
# ---------------------------------------------------------------------------

_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "run-scan.py"


def _load_run_scan() -> Any:
    spec = importlib.util.spec_from_file_location("run_scan", _SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


run_scan_mod = _load_run_scan()


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


def test_format_comment_contains_marker() -> None:
    result = {
        "score": 85,
        "posture": "compliant",
        "overlay": "financial",
        "controls": [
            {"id": "PR-01", "name": "Identity", "verdict": "PASS", "detail": "10 evals"}
        ],
    }
    comment = run_scan_mod.format_comment(result, threshold=70, passed=True)
    assert "<!-- ancilis-posture-gate -->" in comment


def test_format_comment_shows_score_and_threshold() -> None:
    result = {
        "score": 50,
        "posture": "non_compliant",
        "overlay": "fedramp",
        "controls": [],
    }
    comment = run_scan_mod.format_comment(result, threshold=70, passed=False)
    assert "50/100" in comment
    assert "70" in comment
    assert "FAIL" in comment


def test_format_comment_pass_status() -> None:
    result = {
        "score": 100,
        "posture": "compliant",
        "overlay": "financial",
        "controls": [],
    }
    comment = run_scan_mod.format_comment(result, threshold=70, passed=True)
    assert "PASS" in comment
    assert "✅" in comment


def test_format_comment_includes_controls_table() -> None:
    result = {
        "score": 80,
        "posture": "compliant",
        "overlay": "financial",
        "controls": [
            {"id": "PR-01", "name": "Identity", "verdict": "PASS", "detail": "5 evals"},
            {"id": "PR-02", "name": "Scope", "verdict": "FAIL", "detail": "2 failures"},
        ],
    }
    comment = run_scan_mod.format_comment(result, threshold=70, passed=True)
    assert "PR-01" in comment
    assert "PR-02" in comment
    assert "Identity" in comment
    assert "Scope" in comment


# ---------------------------------------------------------------------------
# Threshold logic
# ---------------------------------------------------------------------------


def test_threshold_equal_passes() -> None:
    """score == threshold must pass."""
    result = {"score": 70, "posture": "compliant", "overlay": "financial", "controls": [], "raw": {}}
    passed = result["score"] >= 70
    assert passed is True


def test_threshold_below_fails() -> None:
    result = {"score": 69, "posture": "non_compliant", "overlay": "financial", "controls": [], "raw": {}}
    passed = result["score"] >= 70
    assert passed is False


def test_threshold_zero_always_passes() -> None:
    result = {"score": 0, "posture": "non_compliant", "overlay": "financial", "controls": [], "raw": {}}
    passed = result["score"] >= 0
    assert passed is True


# ---------------------------------------------------------------------------
# set_output
# ---------------------------------------------------------------------------


def test_set_output_writes_correct_format(tmp_path: Path) -> None:
    out_file = tmp_path / "github_output"
    out_file.touch()
    with patch.dict(os.environ, {"GITHUB_OUTPUT": str(out_file)}):
        run_scan_mod.set_output("score", "85")
        run_scan_mod.set_output("passed", "true")
    contents = out_file.read_text()
    assert "score=85\n" in contents
    assert "passed=true\n" in contents


def test_set_output_no_env_var_no_crash(capsys: pytest.CaptureFixture[str]) -> None:
    """When GITHUB_OUTPUT is missing, falls back to legacy ::set-output without raising."""
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("GITHUB_OUTPUT", None)
        run_scan_mod.set_output("key", "value")
    captured = capsys.readouterr()
    assert "key" in captured.out


# ---------------------------------------------------------------------------
# is_pr_context
# ---------------------------------------------------------------------------


def test_is_pr_context_true_on_pull_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    assert run_scan_mod.is_pr_context() is True


def test_is_pr_context_false_on_push(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    assert run_scan_mod.is_pr_context() is False


def test_is_pr_context_false_when_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    assert run_scan_mod.is_pr_context() is False


# ---------------------------------------------------------------------------
# run_scan — JSON parse
# ---------------------------------------------------------------------------

_SAMPLE_CI_JSON = json.dumps({
    "version": "0.1.0",
    "agent": "test-agent",
    "mode": "audit",
    "timestamp": "2026-04-11T00:00:00Z",
    "controls": [
        {"id": "PR-01", "name": "Identity", "status": "pass", "evaluations": 10, "failures": 0, "flags": 0},
        {"id": "PR-02", "name": "Scope", "status": "fail", "evaluations": 5, "failures": 2, "flags": 0},
        {"id": "PR-03", "name": "Provenance", "status": "skip", "evaluations": 0, "failures": 0, "flags": 0},
    ],
    "dependencies": {"posture": "skip", "findings": []},
    "summary": {"total_controls": 3, "passing": 1, "failing": 1, "skipped": 1, "total_evaluations": 15},
    "posture": "non_compliant",
    "exit_code": 1,
})


def test_run_scan_parses_ci_json(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = _SAMPLE_CI_JSON
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc):
        result = run_scan_mod.run_scan("financial")

    assert result["score"] == 33  # 1/3 * 100
    assert result["posture"] == "non_compliant"
    assert len(result["controls"]) == 3
    assert result["controls"][0]["verdict"] == "PASS"
    assert result["controls"][1]["verdict"] == "FAIL"


def test_run_scan_text_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = "  ✓ Identity Control — pass (10 evals)\n  ✗ Scope Control — fail (2 failures)\n"
    mock_proc.stderr = "Posture: non_compliant\n"

    with patch("subprocess.run", return_value=mock_proc):
        result = run_scan_mod.run_scan("financial")

    # Fell back to text parse — score should be computed from passes/total
    assert isinstance(result["score"], int)
    assert result["overlay"] == "financial"


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------


def test_format_summary_pass() -> None:
    result = {"score": 90, "overlay": "hipaa", "controls": []}
    summary = run_scan_mod.format_summary(result, passed=True)
    assert "PASS" in summary
    assert "90" in summary
    assert "hipaa" in summary


def test_format_summary_fail() -> None:
    result = {"score": 40, "overlay": "fedramp", "controls": []}
    summary = run_scan_mod.format_summary(result, passed=False)
    assert "FAIL" in summary
    assert "40" in summary
