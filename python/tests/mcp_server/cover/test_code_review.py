"""Tests for deterministic Cover code review."""

from __future__ import annotations

from pathlib import Path

from ancilis.mcp_server.cover.code_review import review_code
from ancilis.mcp_server.cover.report import render_onboarding_report


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_review_code_rejects_paths_outside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    _write(outside, "print('outside')\n")

    result = review_code(tmp_path, paths=[outside])

    assert result.reviewed_files == []
    assert result.skipped_files[0].reason == "path_outside_root"


def test_review_code_skips_files_larger_than_limit(tmp_path: Path) -> None:
    path = tmp_path / "large.py"
    _write(path, "x" * 20)

    result = review_code(tmp_path, paths=[path], max_bytes_per_file=10)

    assert result.reviewed_files == []
    assert result.skipped_files[0].reason == "file_too_large"


def test_review_code_redacts_sensitive_patterns(tmp_path: Path) -> None:
    path = tmp_path / "agent.py"
    _write(path, "patient_email = 'jane@example.com'\nmrn = 'MRN-123456'\n")

    result = review_code(tmp_path, paths=[path])

    assert str(path.resolve()) in result.reviewed_files
    sensitive = [finding for finding in result.findings if finding.category == "sensitive_data"]
    assert sensitive
    assert all("jane@example.com" not in (finding.sample or "") for finding in sensitive)
    assert any(finding.sample == "j***@example.com" for finding in sensitive)


def test_review_code_detects_shell_and_http_surfaces(tmp_path: Path) -> None:
    path = tmp_path / "agent.py"
    _write(
        path,
        "\n".join(
            [
                "import subprocess",
                "import requests",
                "subprocess.run(['curl', 'https://api.example.com'])",
                "requests.post('https://api.example.com/upload')",
            ]
        ),
    )

    result = review_code(tmp_path, paths=[path])

    categories = {finding.category for finding in result.findings}
    assert {"shell_execution", "outbound_http"}.issubset(categories)
    assert {"cli", "http"}.issubset(set(result.producer_recommendations))


def test_review_code_accepts_named_snippets() -> None:
    result = review_code(
        snippets=[
            {
                "name": "tool.py",
                "text": "import os\nos.system('rm -rf /tmp/example')\n",
            }
        ]
    )

    assert result.reviewed_files == ["snippet:tool.py"]
    assert any(finding.category == "shell_execution" for finding in result.findings)


def test_render_onboarding_report_includes_next_steps() -> None:
    report = render_onboarding_report(
        summary="Patient portal likely handles health records.",
        next_steps=["Create ancilis.yaml", "Run ancilis doctor"],
        confidence="high",
    )

    assert "# Ancilis Cover Onboarding Report" in report
    assert "Patient portal likely handles health records." in report
    assert "- Create ancilis.yaml" in report
    assert "Confidence: high" in report
