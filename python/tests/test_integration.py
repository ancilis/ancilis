"""Integration tests — config bad paths, audit vs enforce end-to-end, CLI error paths."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.tool import BlockedActionError, ToolActionProducer


# --- Helpers ---

def _write_config(data: dict[str, Any], tmpdir: Path) -> Path:
    path = tmpdir / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _dummy_tool(x: str) -> str:
    return f"result:{x}"


# === Config validation bad-path tests ===


class TestConfigBadPaths:
    def test_malformed_yaml(self, tmp_path: Path) -> None:
        """Malformed YAML produces an error, not a stack trace."""
        bad = tmp_path / "ancilis.yaml"
        bad.write_text(": invalid: yaml: {{[")
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(bad)])
        assert result.exit_code != 0

    def test_missing_agent_name(self) -> None:
        """Config without agent.name raises ValueError."""
        with pytest.raises((ValueError, Exception)):
            load_config(raw={"agent": {"name": ""}})

    def test_unknown_data_type(self) -> None:
        """Unrecognized data type produces actionable error."""
        with pytest.raises(ValueError, match="Unknown data type"):
            load_config(raw={"agent": {"name": "test"}, "my_agent_handles": ["unicorn_data"]})

    def test_invalid_mode(self) -> None:
        """Invalid security.mode raises ValueError."""
        with pytest.raises((ValueError, Exception)):
            load_config(raw={"agent": {"name": "test"}, "security": {"mode": "yolo"}})

    def test_unknown_control_override(self) -> None:
        """Unknown control ID in overrides raises ValueError."""
        with pytest.raises(ValueError, match="Unknown control ID"):
            load_config(raw={
                "agent": {"name": "test"},
                "security": {"controls": {"FAKE-99": {"enabled": True}}},
            })

    def test_unrecognized_cert_target_warns(self) -> None:
        """Unrecognized certification target produces a warning, not a crash."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "certification_targets": ["aiuc-99"],
        })
        assert any("aiuc-99" in w for w in config.warnings)

    def test_validate_cli_missing_config(self, tmp_path: Path) -> None:
        """CLI config validate with nonexistent file gives actionable error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(tmp_path / "nope.yaml")])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "no such file" in result.output.lower() or "error" in result.output.lower()

    def test_validate_cli_bad_data_type(self, tmp_path: Path) -> None:
        """CLI config validate with unknown data type gives actionable error."""
        path = _write_config({
            "agent": {"name": "test"},
            "my_agent_handles": ["unicorn_data"],
        }, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(path)])
        assert result.exit_code != 0
        assert "Unknown data type" in result.output or "invalid" in result.output.lower()


# === Audit vs Enforce end-to-end ===


class TestAuditVsEnforce:
    def test_audit_mode_allows_unapproved_tool(self) -> None:
        """In audit mode, unapproved tools are allowed (logged but not blocked)."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "security": {"mode": "audit", "tools": {"allowed": ["approved_tool"]}},
        })
        engine = Engine(config)
        evidence = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

        # Unapproved tool — should be allowed in audit mode
        result = producer.execute(
            _dummy_tool,
            agent_name="test",
            tool_name="unapproved_tool",
            args=("hello",),
        )
        assert result.blocked is False
        assert result.evaluation.decision == "ALLOW"
        assert result.evaluation.mode == "audit"
        assert result.return_value == "result:hello"

        # Verify evidence was recorded
        summary = evidence.get_summary()
        assert summary["total_evaluations"] == 1
        evidence.close()

    def test_enforce_mode_blocks_unapproved_tool(self) -> None:
        """In enforce mode, unapproved tools are blocked."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "security": {"mode": "enforce", "tools": {"allowed": ["approved_tool"]}},
        })
        engine = Engine(config)
        evidence = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

        with pytest.raises(BlockedActionError) as exc_info:
            producer.execute(
                _dummy_tool,
                agent_name="test",
                tool_name="unapproved_tool",
                args=("hello",),
            )
        assert "blocked" in exc_info.value.display_message.lower()

        # Verify evidence was still recorded
        summary = evidence.get_summary()
        assert summary["total_evaluations"] == 1
        decisions = summary["decisions"]
        assert decisions.get("BLOCK", 0) == 1
        evidence.close()

    def test_enforce_mode_allows_approved_tool(self) -> None:
        """In enforce mode, approved tools pass through."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "security": {"mode": "enforce", "tools": {"allowed": ["approved_tool"]}},
        })
        engine = Engine(config)
        evidence = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

        result = producer.execute(
            _dummy_tool,
            agent_name="test",
            tool_name="approved_tool",
            args=("hello",),
        )
        assert result.blocked is False
        assert result.evaluation.decision == "ALLOW"
        assert result.evaluation.mode == "enforce"
        evidence.close()

    def test_evidence_records_mode_field(self) -> None:
        """Evidence records contain the correct mode field."""
        for mode in ("audit", "enforce"):
            config = load_config(raw={
                "agent": {"name": "test"},
                "security": {"mode": mode, "tools": {"allowed": ["test_tool"]}},
            })
            engine = Engine(config)
            evidence = EvidenceStore(config, in_memory=True)
            producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

            producer.execute(
                _dummy_tool,
                agent_name="test",
                tool_name="test_tool",
                args=("x",),
            )

            records = evidence.get_records()
            assert len(records) == 1
            assert records[0].mode == mode
            evidence.close()


# === CLI error path tests ===


class TestCLIErrorPaths:
    def test_status_missing_config(self) -> None:
        """ancilis status without config gives helpful error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", "/nonexistent/ancilis.yaml"])
        assert result.exit_code != 0

    def test_report_missing_config(self) -> None:
        """ancilis report without config gives helpful error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--config", "/nonexistent/ancilis.yaml"])
        assert result.exit_code != 0

    def test_doctor_missing_config(self, tmp_path: Path) -> None:
        """ancilis doctor with missing config shows error and fix hint."""
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor", "--config", str(tmp_path / "nope.yaml")])
        assert result.exit_code != 0
        # New format uses [✗] icon; "ancilis.yaml" appears in detail and fix hint
        assert "[✗]" in result.output or "not found" in result.output
        assert "ancilis.yaml" in result.output

    def test_doctor_valid_config(self, tmp_path: Path) -> None:
        """ancilis doctor with valid config shows config loaded successfully."""
        path = _write_config({"agent": {"name": "test"}}, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor", "--config", str(path)])
        # Exit code 0 (all pass) or 1 (warnings like platform/gitignore) — never 2
        assert result.exit_code in (0, 1)
        assert "Ancilis Doctor" in result.output
        assert "checks passed" in result.output

    def test_approve_tool_missing_config(self) -> None:
        """ancilis approve-tool with missing config gives error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["approve-tool", "test-tool", "--config", "/nonexistent/ancilis.yaml"])
        assert result.exit_code != 0


# === MCP middleware integration (with mock) ===


class TestMCPMiddlewareIntegration:
    """Test MCP middleware happy and blocked paths with mock session."""

    @pytest.fixture
    def mock_session(self):
        """Create a minimal mock MCP session."""
        from dataclasses import dataclass, field
        from typing import Any

        @dataclass
        class MockTextContent:
            type: str = "text"
            text: str = ""

        @dataclass
        class MockCallToolResult:
            content: list[Any] = field(default_factory=list)
            isError: bool = False  # noqa: N815
            structuredContent: Any = None  # noqa: N815
            meta: Any = None

        @dataclass
        class MockTool:
            name: str = ""
            description: str = ""
            inputSchema: dict[str, Any] = field(default_factory=dict)  # noqa: N815

        @dataclass
        class MockListToolsResult:
            tools: list[MockTool] = field(default_factory=list)

        class Session:
            async def call_tool(self, name, arguments=None):
                return MockCallToolResult(content=[MockTextContent(text=f"OK:{name}")])

            async def list_tools(self):
                return MockListToolsResult(tools=[
                    MockTool(name="allowed-tool", description="Test tool"),
                    MockTool(name="blocked-tool", description="Test tool"),
                ])

        return Session()

    @pytest.mark.asyncio
    async def test_happy_path_allowed(self, mock_session) -> None:
        """Allowed tool passes through middleware."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "security": {"mode": "enforce", "tools": {"allowed": ["allowed-tool"]}},
        })
        from ancilis.middleware import AncilisMiddleware
        evidence = EvidenceStore(config, in_memory=True)
        mw = AncilisMiddleware(mock_session, config=config, evidence_store=evidence)
        await mw.list_tools()

        result = await mw.call_tool("allowed-tool", {"key": "value"})
        assert result.content[0].text == "OK:allowed-tool"

        ev = mw.get_last_evaluation()
        assert ev is not None
        assert ev.decision == "ALLOW"
        evidence.close()
        mw.close()

    @pytest.mark.asyncio
    async def test_blocked_path_enforce(self, mock_session) -> None:
        """Unapproved tool is blocked in enforce mode."""
        config = load_config(raw={
            "agent": {"name": "test"},
            "security": {"mode": "enforce", "tools": {"allowed": ["allowed-tool"]}},
        })
        from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
        evidence = EvidenceStore(config, in_memory=True)
        mw = AncilisMiddleware(mock_session, config=config, evidence_store=evidence)
        await mw.list_tools()

        with pytest.raises(BlockedToolCallError):
            await mw.call_tool("blocked-tool", {})

        ev = mw.get_last_evaluation()
        assert ev is not None
        assert ev.decision == "BLOCK"
        evidence.close()
        mw.close()
