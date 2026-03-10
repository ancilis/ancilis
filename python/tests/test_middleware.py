"""Tests for ancilis.middleware — Unit 3: MCP Middleware & Pattern Detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ancilis.config import load_config
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
from ancilis.middleware.response_scanner import scan_response


# --- Mock MCP Types ---


@dataclass
class MockTextContent:
    type: str = "text"
    text: str = ""
    annotations: Any = None
    meta: Any = None


@dataclass
class MockCallToolResult:
    content: list[Any] = field(default_factory=list)
    isError: bool = False
    structuredContent: Any = None
    meta: Any = None


@dataclass
class MockTool:
    name: str = ""
    description: str = ""
    inputSchema: dict[str, Any] = field(default_factory=dict)
    title: str | None = None
    outputSchema: Any = None
    icons: Any = None
    annotations: Any = None
    meta: Any = None
    execution: Any = None


@dataclass
class MockListToolsResult:
    tools: list[MockTool] = field(default_factory=list)


def _mock_session(
    call_tool_return: MockCallToolResult | None = None,
    tools: list[MockTool] | None = None,
) -> AsyncMock:
    session = AsyncMock()
    if call_tool_return is None:
        call_tool_return = MockCallToolResult(
            content=[MockTextContent(text="OK")]
        )
    session.call_tool.return_value = call_tool_return
    session.list_tools.return_value = MockListToolsResult(tools=tools or [])
    return session


def _config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


# --- Middleware Initialization ---


class TestMiddlewareInit:
    @pytest.mark.asyncio
    async def test_init_with_config_object(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        assert mw.config.agent_name == "test-agent"

    @pytest.mark.asyncio
    async def test_init_with_minimal_config(self):
        session = _mock_session()
        config = _config()
        mw = AncilisMiddleware(session, config=config)
        assert mw.config.mode == "audit"


# --- Tool Call Interception ---


class TestToolCallInterception:
    @pytest.mark.asyncio
    async def test_audit_mode_allows_and_forwards(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        # Register the tool so PR-03 passes
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        result = await mw.call_tool("my-tool", {"key": "value"})
        session.call_tool.assert_called_once_with("my-tool", {"key": "value"})
        assert result.content[0].text == "OK"

    @pytest.mark.asyncio
    async def test_enforce_all_pass_forwards(self):
        config = _config(security={"mode": "enforce"})
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        result = await mw.call_tool("my-tool", {"key": "value"})
        session.call_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_enforce_control_fails_blocks(self):
        config = _config(security={"mode": "enforce"})
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        # Don't register tool — PR-03 will fail

        with pytest.raises(BlockedToolCallError) as exc_info:
            await mw.call_tool("unknown-tool", {})

        session.call_tool.assert_not_called()
        assert "unknown-tool" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_blocked_call_has_evaluation(self):
        config = _config(security={"mode": "enforce"})
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)

        with pytest.raises(BlockedToolCallError) as exc_info:
            await mw.call_tool("unknown-tool", {})

        assert exc_info.value.evaluation.decision == "BLOCK"

    @pytest.mark.asyncio
    async def test_action_built_correctly(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool", version="1.0", description_hash="abc"))

        await mw.call_tool("my-tool", {"param": "val"})

        ev = mw.get_last_evaluation()
        assert ev is not None
        assert ev.agent_id == "test-agent"
        assert ev.mode == "audit"


# --- Auto-Discovery ---


class TestAutoDiscovery:
    @pytest.mark.asyncio
    async def test_list_tools_registers(self):
        tools = [
            MockTool(name="tool-a", description="Description A"),
            MockTool(name="tool-b", description="Description B"),
        ]
        session = _mock_session(tools=tools)
        mw = AncilisMiddleware(session, config=_config())

        await mw.list_tools()
        assert mw.registry.is_registered("tool-a")
        assert mw.registry.is_registered("tool-b")

    @pytest.mark.asyncio
    async def test_discovered_tool_passes_provenance(self):
        tools = [MockTool(name="tool-a", description="Desc A")]
        session = _mock_session(tools=tools)
        config = _config(security={"mode": "enforce"})
        mw = AncilisMiddleware(session, config=config)

        await mw.list_tools()
        result = await mw.call_tool("tool-a", {})
        session.call_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_description_drift_detected(self):
        tools_v1 = [MockTool(name="tool-a", description="Version 1")]
        tools_v2 = [MockTool(name="tool-a", description="Version 2 changed")]
        session = AsyncMock()
        session.list_tools.side_effect = [
            MockListToolsResult(tools=tools_v1),
            MockListToolsResult(tools=tools_v2),
        ]
        session.call_tool.return_value = MockCallToolResult(
            content=[MockTextContent(text="OK")]
        )

        mw = AncilisMiddleware(session, config=_config())
        await mw.list_tools()
        await mw.list_tools()

        assert len(mw.drift_events) == 1
        assert mw.drift_events[0].tool_name == "tool-a"


# --- Pattern Detection on Responses ---


class TestResponseScanning:
    @pytest.mark.asyncio
    async def test_ssn_in_response_generates_recommendation(self):
        response = MockCallToolResult(
            content=[MockTextContent(text="Patient SSN: 123-45-6789")]
        )
        session = _mock_session(call_tool_return=response)
        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="patient-lookup"))

        await mw.call_tool("patient-lookup", {})
        recs = mw.get_recommendations()
        assert any("personal_info" in r for r in recs)

    @pytest.mark.asyncio
    async def test_credit_card_in_response_detected(self):
        response = MockCallToolResult(
            content=[MockTextContent(text="Card: 4111 1111 1111 1111")]
        )
        session = _mock_session(call_tool_return=response)
        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="payment-tool"))

        await mw.call_tool("payment-tool", {})
        recs = mw.get_recommendations()
        assert any("credit_cards" in r for r in recs)

    @pytest.mark.asyncio
    async def test_high_entropy_flagged_as_encrypted(self):
        # A high-entropy string simulating encrypted data
        encrypted = "aK7xP9mQ2rT5wB8nY1cD4fG6hJ0kL3vE" * 2
        response = MockCallToolResult(
            content=[MockTextContent(text=f"Data: {encrypted}")]
        )
        session = _mock_session(call_tool_return=response)
        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="secure-tool"))

        await mw.call_tool("secure-tool", {})
        assert len(mw.scan_results) > 0
        findings = mw.scan_results[0].encryption_findings
        assert any(f.finding_type == "high_entropy" for f in findings)

    @pytest.mark.asyncio
    async def test_clean_response_no_recommendations(self):
        response = MockCallToolResult(
            content=[MockTextContent(text="Everything is fine. Status: OK")]
        )
        session = _mock_session(call_tool_return=response)
        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="status-tool"))

        await mw.call_tool("status-tool", {})
        assert len(mw.get_recommendations()) == 0

    @pytest.mark.asyncio
    async def test_recommendations_accumulate(self):
        r1 = MockCallToolResult(content=[MockTextContent(text="SSN: 123-45-6789")])
        r2 = MockCallToolResult(content=[MockTextContent(text="Card: 4111 1111 1111 1111")])
        session = AsyncMock()
        session.call_tool.side_effect = [r1, r2]

        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="tool-a"))
        mw.registry.register(ToolEntry(name="tool-b"))

        await mw.call_tool("tool-a", {})
        await mw.call_tool("tool-b", {})
        recs = mw.get_recommendations()
        assert len(recs) >= 2


# --- Enforcement ---


class TestEnforcement:
    @pytest.mark.asyncio
    async def test_audit_failure_allows_through(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        # Don't register — PR-03 fails, but audit mode allows

        result = await mw.call_tool("unregistered-tool", {})
        session.call_tool.assert_called_once()
        ev = mw.get_last_evaluation()
        assert ev is not None
        assert ev.decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_enforce_failure_blocks(self):
        config = _config(security={"mode": "enforce"})
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)

        with pytest.raises(BlockedToolCallError):
            await mw.call_tool("unregistered-tool", {})
        session.call_tool.assert_not_called()


# --- Integration with Engine ---


class TestEngineIntegration:
    @pytest.mark.asyncio
    async def test_evaluation_result_accessible(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        await mw.call_tool("my-tool", {"x": 1})
        ev = mw.get_last_evaluation()
        assert ev is not None
        assert len(ev.control_results) > 0

    @pytest.mark.asyncio
    async def test_evaluation_log_grows(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="tool-a"))

        await mw.call_tool("tool-a", {})
        await mw.call_tool("tool-a", {})
        assert len(mw.evaluation_log) == 2


# --- Edge Cases ---


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_parameters(self):
        config = _config()
        session = _mock_session()
        mw = AncilisMiddleware(session, config=config)
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        result = await mw.call_tool("my-tool")
        session.call_tool.assert_called_once_with("my-tool", None)

    @pytest.mark.asyncio
    async def test_mcp_server_error_handled(self):
        session = AsyncMock()
        session.call_tool.side_effect = RuntimeError("MCP server down")
        mw = AncilisMiddleware(session, config=_config())
        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        with pytest.raises(RuntimeError, match="MCP server down"):
            await mw.call_tool("my-tool", {})

        # Evaluation should still have been logged
        assert len(mw.evaluation_log) == 1


# --- Response Scanner Unit Tests ---


class TestResponseScanner:
    def test_scan_response_ssn(self):
        result = scan_response("test-tool", "SSN: 000-00-0000")
        assert any(p.pattern_type == "ssn" for p in result.patterns)
        assert any("personal_info" in r for r in result.recommendations)

    def test_scan_response_clean(self):
        result = scan_response("test-tool", "Everything is normal.")
        assert len(result.patterns) == 0
        assert len(result.recommendations) == 0

    def test_scan_response_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz"
        result = scan_response("test-tool", f"Token: {jwt}")
        assert any(f.finding_type == "jwt_token" for f in result.encryption_findings)
