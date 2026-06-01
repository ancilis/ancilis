"""Tests for deterministic Ancilis Cover project inspection."""

from __future__ import annotations

import json
from pathlib import Path

from ancilis.mcp_server.cover.project import inspect_project


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_inspect_project_detects_ai_frameworks_and_ancilis_config(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        "\n".join(
            [
                "[project]",
                'dependencies = ["langchain>=0.2", "openai==1.0.0", "mcp>=1.0"]',
                "",
            ]
        ),
    )
    _write(
        tmp_path / "package.json",
        json.dumps(
            {
                "dependencies": {
                    "@modelcontextprotocol/sdk": "^1.0.0",
                    "typescript": "^5.0.0",
                }
            }
        ),
    )
    _write(tmp_path / "ancilis.yaml", "agent:\n  name: cover-test\n")
    _write(tmp_path / "src" / "agent.py", "from langchain_openai import ChatOpenAI\n")
    _write(tmp_path / "src" / "agent.ts", "import OpenAI from 'openai';\n")

    result = inspect_project(tmp_path)

    assert result.root == str(tmp_path.resolve())
    assert result.ancilis_present is True
    assert result.config_path == str((tmp_path / "ancilis.yaml").resolve())
    assert {"python", "typescript"}.issubset(set(result.languages))
    assert {"langchain", "openai", "mcp"}.issubset(set(result.frameworks))
    assert {"langchain", "openai", "mcp"}.issubset(set(result.recommended_producers))
    assert "langchain" in result.dependencies
    assert "@modelcontextprotocol/sdk" in result.dependencies
    assert any(signal.rule_id == "config.ancilis_yaml" for signal in result.signals)
    assert any(signal.source == "dependency" and signal.value == "openai" for signal in result.signals)


def test_inspect_project_respects_file_limit(tmp_path: Path) -> None:
    for index in range(5):
        _write(tmp_path / f"file_{index}.py", "print('hello')\n")

    result = inspect_project(tmp_path, max_files=2)

    assert result.files_scanned == 2
    assert result.files_skipped == 3
    assert "python" in result.languages
    assert any("file limit" in warning for warning in result.warnings)


def test_inspect_project_skips_hidden_files_by_default(tmp_path: Path) -> None:
    _write(tmp_path / ".hidden" / "agent.py", "import anthropic\n")
    _write(tmp_path / "visible.py", "print('visible')\n")

    result = inspect_project(tmp_path)

    assert "anthropic" not in result.frameworks
    assert "python" in result.languages


def test_inspect_project_can_include_hidden_files(tmp_path: Path) -> None:
    _write(tmp_path / ".hidden" / "agent.py", "import anthropic\n")

    result = inspect_project(tmp_path, include_hidden=True)

    assert "anthropic" in result.frameworks
    assert "anthropic" in result.recommended_producers
