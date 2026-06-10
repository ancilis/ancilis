"""Tests for the ancilis init CLI command."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ancilis.cli.init import detect_framework, sanitize_name, Framework
from ancilis.cli.main import cli
from ancilis.config import load_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def invoke_init(args: list[str], input: str | None = None, tmp_path: Path | None = None) -> object:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["init"] + args, input=input, catch_exceptions=False)
    return result


# ---------------------------------------------------------------------------
# 1. Interactive happy path
# ---------------------------------------------------------------------------


def test_init_interactive_happy_path(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            ["init", "--dir", str(td_path)],
            input="generic\n\ntest-agent\n",  # framework, overlay (default soc2), agent name
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert (td_path / "ancilis.yaml").exists()
        assert (td_path / "ancilis_scan.py").exists()
        assert (td_path / ".env.example").exists()


# ---------------------------------------------------------------------------
# 2. Non-interactive mode — all flags skip prompts
# ---------------------------------------------------------------------------


def test_init_noninteractive(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework", "langchain",
                "--overlay", "soc2",
                "--agent-name", "my-agent",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert (td_path / "ancilis.yaml").exists()
        assert (td_path / "ancilis_scan.py").exists()
        assert (td_path / ".env.example").exists()
        # No prompts should appear
        assert "?" not in result.output or "Next steps" in result.output


# ---------------------------------------------------------------------------
# 3. Detection — LangChain via requirements.txt
# ---------------------------------------------------------------------------


def test_init_detect_langchain(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.1.0\nopenai>=1.0\n")
    detected = detect_framework(tmp_path)
    assert detected is not None
    assert detected.framework == Framework.LANGCHAIN
    assert detected.source == "requirements.txt"
    assert detected.confidence == "high"


# ---------------------------------------------------------------------------
# 4. Detection — CrewAI via pyproject.toml
# ---------------------------------------------------------------------------


def test_init_detect_crewai(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'my-agent'\ndependencies = ['crewai>=0.1']\n"
    )
    detected = detect_framework(tmp_path)
    assert detected is not None
    assert detected.framework == Framework.CREWAI


# ---------------------------------------------------------------------------
# 5. Detection — OpenAI only
# ---------------------------------------------------------------------------


def test_init_detect_openai(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("openai>=1.0\nrequests\n")
    detected = detect_framework(tmp_path)
    assert detected is not None
    assert detected.framework == Framework.OPENAI


# ---------------------------------------------------------------------------
# 6. Detection — nothing found → None
# ---------------------------------------------------------------------------


def test_init_detect_nothing(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests\nflask\n")
    detected = detect_framework(tmp_path)
    assert detected is None


# ---------------------------------------------------------------------------
# 7. Existing config — overwrite confirmed
# ---------------------------------------------------------------------------


def test_init_existing_config_overwrite(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        (td_path / "ancilis.yaml").write_text("agent:\n  name: old\n")
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", "soc2",
                "--agent-name", "new-agent",
                "--dir", str(td_path),
            ],
            input="y\n",  # confirm overwrite
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        content = (td_path / "ancilis.yaml").read_text()
        assert "new-agent" in content


# ---------------------------------------------------------------------------
# 8. Existing config — abort
# ---------------------------------------------------------------------------


def test_init_existing_config_abort(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        original = "agent:\n  name: old\n"
        (td_path / "ancilis.yaml").write_text(original)
        result = runner.invoke(
            cli,
            ["init", "--dir", str(td_path)],
            input="n\n",  # decline overwrite
        )
        # Should exit cleanly (exit code 0 or 1 is acceptable — SystemExit(0))
        assert (td_path / "ancilis.yaml").read_text() == original


# ---------------------------------------------------------------------------
# 9. .gitignore append
# ---------------------------------------------------------------------------


def test_init_gitignore_append(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        (td_path / ".gitignore").write_text("__pycache__/\n*.pyc\n")
        runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", "soc2",
                "--agent-name", "agent",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        content = (td_path / ".gitignore").read_text()
        assert ".ancilis/" in content


# ---------------------------------------------------------------------------
# 10. .gitignore already contains .ancilis/ — no duplicate
# ---------------------------------------------------------------------------


def test_init_gitignore_already_present(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        (td_path / ".gitignore").write_text("__pycache__/\n.ancilis/\n")
        runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", "soc2",
                "--agent-name", "agent",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        content = (td_path / ".gitignore").read_text()
        assert content.count(".ancilis/") == 1


# ---------------------------------------------------------------------------
# 10b. .gitignore output honesty — only claim "updated .gitignore" when true
# ---------------------------------------------------------------------------


def _run_init(td_path: Path):
    return CliRunner().invoke(
        cli,
        ["init", "--framework", "generic", "--overlay", "soc2",
         "--agent-name", "agent", "--dir", str(td_path)],
        catch_exceptions=False,
    )


def test_init_no_gitignore_does_not_claim_update(tmp_path: Path) -> None:
    """No .gitignore: init must NOT create one and must NOT claim it updated one."""
    with CliRunner().isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = _run_init(td_path)
        assert not (td_path / ".gitignore").exists()  # never created
        assert "updated .gitignore" not in result.output


def test_init_gitignore_append_reports_update(tmp_path: Path) -> None:
    """An actual append to an existing .gitignore IS reported."""
    with CliRunner().isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        (td_path / ".gitignore").write_text("__pycache__/\n")
        result = _run_init(td_path)
        assert "updated .gitignore" in result.output


def test_init_gitignore_already_present_does_not_claim_update(tmp_path: Path) -> None:
    """When .ancilis/ is already ignored, init makes no change and claims none."""
    with CliRunner().isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        (td_path / ".gitignore").write_text(".ancilis/\n")
        result = _run_init(td_path)
        assert "updated .gitignore" not in result.output


# ---------------------------------------------------------------------------
# 11. --no-sample skips scan script
# ---------------------------------------------------------------------------


def test_init_no_sample_flag(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", "soc2",
                "--agent-name", "agent",
                "--no-sample",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert not (td_path / "ancilis_scan.py").exists()
        assert (td_path / "ancilis.yaml").exists()


# ---------------------------------------------------------------------------
# 12. Generated YAML is valid via load_config()
# ---------------------------------------------------------------------------


def test_init_generated_yaml_valid(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", "soc2",
                "--agent-name", "my-agent",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        config = load_config(path=str(td_path / "ancilis.yaml"))
        assert config.agent_name == "my-agent"


# ---------------------------------------------------------------------------
# 13. All 10 overlay names generate valid YAML
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("overlay", [
    "soc2", "gdpr", "hipaa", "iso-42001", "eu-ai-act",
    "nist-csf", "pci-dss-v4", "cmmc-l2", "glba", "securities-mnpi",
])
def test_init_all_overlays_valid(overlay: str, tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework", "generic",
                "--overlay", overlay,
                "--agent-name", "agent",
                "--dir", str(td_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"Failed for overlay {overlay}: {result.output}"
        content = (td_path / "ancilis.yaml").read_text()
        assert overlay in content


def test_init_accepts_nist_csf_2_alias_as_canonical_overlay(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        td_path = Path(td)
        result = runner.invoke(
            cli,
            [
                "init",
                "--framework",
                "generic",
                "--overlay",
                "nist-csf-2",
                "--agent-name",
                "agent",
                "--dir",
                str(td_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        content = (td_path / "ancilis.yaml").read_text()
        assert "nist-csf" in content
        assert "nist-csf-2" not in content
        config = load_config(path=str(td_path / "ancilis.yaml"))
        assert list(config.active_overlays) == ["nist-csf"]


# ---------------------------------------------------------------------------
# 14. sanitize_agent_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("My Agent", "my-agent"),
    ("My  Agent!!", "my-agent"),
    ("already-fine", "already-fine"),
    ("UPPER CASE", "upper-case"),
    ("123 Numbers", "123-numbers"),
    ("---strip---", "strip"),
    ("", "my-agent"),
    ("special@#$chars", "special-chars"),
])
def test_init_sanitize_agent_name(raw: str, expected: str) -> None:
    assert sanitize_name(raw) == expected
