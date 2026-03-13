"""Tests for ADR-005: Action Object Producer Protocol."""

from __future__ import annotations

import hashlib
import uuid
from unittest.mock import patch

import pytest

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation
from ancilis.producers.mcp import MCPActionProducer


# --- Helpers ---


def _config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _enforce_config(**overrides):
    raw = {"agent": {"name": "test-agent"}, "security": {"mode": "enforce"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _make_engine(config=None, registry=None):
    c = config or _config()
    return Engine(c, registry=registry)


# --- Protocol Compliance ---


class TestActionProducerProtocol:
    def test_cli_producer_satisfies_protocol(self):
        """CLIActionProducer satisfies ActionProducer protocol."""
        config = _config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine)
        assert isinstance(producer, ActionProducer)

    def test_mcp_producer_satisfies_protocol(self):
        """MCPActionProducer satisfies ActionProducer protocol."""
        config = _config()
        registry = ToolRegistry()
        producer = MCPActionProducer(config=config, registry=registry)
        assert isinstance(producer, ActionProducer)

    def test_producer_type_enum_values(self):
        assert ProducerType.MCP.value == "mcp"
        assert ProducerType.CLI.value == "cli"
        assert ProducerType.HTTP.value == "http"
        assert ProducerType.A2A.value == "a2a"
        assert ProducerType.FRAMEWORK.value == "framework"
        assert ProducerType.MANUAL.value == "manual"


# --- Action Object Extension ---


class TestActionProducerType:
    def test_action_default_producer_type(self):
        """Action defaults to producer_type='mcp' for backward compat."""
        action = Action(
            action_id=str(uuid.uuid4()),
            timestamp="2026-03-13T00:00:00Z",
            agent_id="test",
            action_type="tool_call",
            tool=ToolInfo(name="test-tool"),
            parameters=ActionParameters(),
        )
        assert action.producer_type == "mcp"
        assert action.producer_version == "0.1.0"

    def test_action_with_cli_producer_type(self):
        """Action can carry CLI producer type."""
        action = Action(
            action_id=str(uuid.uuid4()),
            timestamp="2026-03-13T00:00:00Z",
            agent_id="test",
            action_type="tool_call",
            tool=ToolInfo(name="cli:echo"),
            parameters=ActionParameters(),
            producer_type="cli",
        )
        assert action.producer_type == "cli"


# --- MCP Producer ---


class TestMCPActionProducer:
    def test_producer_type(self):
        config = _config()
        producer = MCPActionProducer(config=config, registry=ToolRegistry())
        assert producer.producer_type == ProducerType.MCP

    def test_producer_version(self):
        config = _config()
        producer = MCPActionProducer(config=config, registry=ToolRegistry())
        assert producer.producer_version == "0.1.0"

    def test_translate_sets_producer_type(self):
        config = _config()
        registry = ToolRegistry()
        producer = MCPActionProducer(config=config, registry=registry)
        action = producer.translate({"name": "read_file", "arguments": {"path": "/tmp/x"}})
        assert action.producer_type == "mcp"
        assert action.tool.name == "read_file"
        assert action.agent_id == "test-agent"

    def test_compute_tool_hash(self):
        config = _config()
        producer = MCPActionProducer(config=config, registry=ToolRegistry())
        h = producer.compute_tool_hash("Read a file from disk")
        expected = hashlib.sha256("Read a file from disk".encode()).hexdigest()
        assert h == expected

    def test_compute_tool_hash_deterministic(self):
        config = _config()
        producer = MCPActionProducer(config=config, registry=ToolRegistry())
        h1 = producer.compute_tool_hash("desc")
        h2 = producer.compute_tool_hash("desc")
        assert h1 == h2


# --- CLI Producer Translation ---


class TestCLITranslation:
    def _make_producer(self, config=None):
        c = config or _config()
        engine = _make_engine(c)
        return CLIActionProducer(config=c, engine=engine)

    def test_basic_command(self):
        producer = self._make_producer()
        invocation = CLIInvocation(
            command=["aws", "s3", "ls", "s3://my-bucket/"],
            agent_name="test-agent",
        )
        action = producer.translate(invocation)
        assert action.agent_id == "test-agent"
        assert action.tool.name == "cli:aws"
        assert action.parameters.raw["command"] == ["aws", "s3", "ls", "s3://my-bucket/"]
        assert action.parameters.raw["args"] == ["s3", "ls", "s3://my-bucket/"]
        assert action.producer_type == "cli"
        assert action.producer_version == "0.1.0"
        assert action.action_type == "tool_call"

    def test_absolute_path_command(self):
        producer = self._make_producer()
        invocation = CLIInvocation(
            command=["/usr/bin/python", "script.py"],
            agent_name="test-agent",
        )
        action = producer.translate(invocation)
        assert action.tool.name == "cli:python"

    def test_single_command_no_args(self):
        producer = self._make_producer()
        invocation = CLIInvocation(command=["ls"], agent_name="test-agent")
        action = producer.translate(invocation)
        assert action.tool.name == "cli:ls"
        assert action.parameters.raw["args"] == []

    def test_empty_command(self):
        producer = self._make_producer()
        invocation = CLIInvocation(command=[], agent_name="test-agent")
        action = producer.translate(invocation)
        assert action.tool.name == "cli:unknown"

    def test_working_directory_included(self):
        producer = self._make_producer()
        invocation = CLIInvocation(
            command=["ls"], agent_name="test-agent", working_directory="/tmp"
        )
        action = producer.translate(invocation)
        assert action.parameters.raw["working_directory"] == "/tmp"

    def test_parameter_hash_set(self):
        producer = self._make_producer()
        invocation = CLIInvocation(command=["echo", "hello"], agent_name="test-agent")
        action = producer.translate(invocation)
        assert len(action.parameters.parameter_hash) == 64  # SHA-256 hex

    def test_context_carries_dc_codes(self):
        config = _config(data_handling=["personal_info"])
        producer = self._make_producer(config)
        invocation = CLIInvocation(command=["echo"], agent_name="test-agent")
        action = producer.translate(invocation)
        assert len(action.context.data_classifications) > 0

    def test_registry_lookup_for_description_hash(self):
        config = _config()
        engine = _make_engine(config)
        registry = engine.registry
        registry.register(ToolEntry(
            name="cli:echo",
            description_hash="abc123hash",
            status=ToolStatus.APPROVED,
        ))
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)
        invocation = CLIInvocation(command=["echo", "hi"], agent_name="test-agent")
        action = producer.translate(invocation)
        assert action.tool.description_hash == "abc123hash"


# --- CLI Tool Hash ---


class TestCLIToolHash:
    def _make_producer(self):
        config = _config()
        return CLIActionProducer(config=config, engine=_make_engine(config))

    def test_deterministic(self):
        producer = self._make_producer()
        h1 = producer.compute_tool_hash("echo")
        h2 = producer.compute_tool_hash("echo")
        assert h1 == h2

    def test_differs_between_tools(self):
        producer = self._make_producer()
        h1 = producer.compute_tool_hash("echo")
        h2 = producer.compute_tool_hash("cat")
        assert h1 != h2

    def test_nonexistent_tool_still_produces_hash(self):
        producer = self._make_producer()
        h = producer.compute_tool_hash("nonexistent_tool_xyz_12345")
        assert len(h) == 64


# --- CLI Tool Registration ---


class TestCLIToolRegistration:
    def test_register_from_config_allowlist(self):
        config = _config(security={"tools": {"allowed": ["echo", "cat"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)
        registered = producer.register_tools(registry)
        assert "cli:echo" in registered
        assert "cli:cat" in registered

    def test_registered_as_observed(self):
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)
        producer.register_tools(registry)
        entry = registry.lookup("cli:echo")
        assert entry is not None
        assert entry.status == ToolStatus.OBSERVED

    def test_registered_with_hash(self):
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)
        producer.register_tools(registry)
        entry = registry.lookup("cli:echo")
        assert entry is not None
        assert entry.description_hash is not None
        assert len(entry.description_hash) == 64

    def test_empty_allowlist_registers_nothing(self):
        config = _config()
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)
        registered = producer.register_tools(registry)
        assert registered == []


# --- CLI Execute: Audit Mode ---


class TestCLIExecuteAudit:
    def _make_producer(self, config=None):
        c = config or _config()
        engine = _make_engine(c)
        return CLIActionProducer(config=c, engine=engine)

    def test_execute_allows_in_audit_mode(self):
        producer = self._make_producer()
        result = producer.execute(command=["echo", "hello"], agent_name="test-agent")
        assert not result.blocked
        assert result.stdout is not None
        assert result.stdout.strip() == "hello"
        assert result.evaluation is not None

    def test_execute_returns_evaluation(self):
        producer = self._make_producer()
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        assert result.evaluation.decision == "ALLOW"
        assert len(result.evaluation.control_results) > 0

    def test_execute_returns_return_code(self):
        producer = self._make_producer()
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        assert result.return_code == 0

    def test_execute_captures_stderr(self):
        producer = self._make_producer()
        result = producer.execute(
            command=["python3", "-c", "import sys; sys.stderr.write('err\\n')"],
            agent_name="test-agent",
        )
        assert not result.blocked
        assert result.stderr is not None
        assert "err" in result.stderr

    def test_execute_nonexistent_command(self):
        producer = self._make_producer()
        result = producer.execute(
            command=["nonexistent_command_xyz_99999"],
            agent_name="test-agent",
        )
        assert not result.blocked
        assert result.return_code == -1
        assert "not found" in result.stderr.lower()

    def test_execute_action_has_cli_producer_type(self):
        producer = self._make_producer()
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        assert result.action.producer_type == "cli"


# --- CLI Execute: Enforce Mode ---


class TestCLIExecuteEnforce:
    def test_blocks_unapproved_tool(self):
        """Enforce mode blocks execution of unapproved CLI tool."""
        config = _enforce_config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine)
        result = producer.execute(
            command=["echo", "should-not-run"], agent_name="test-agent"
        )
        assert result.blocked
        assert result.stdout is None
        assert result.return_code is None

    def test_allows_approved_tool(self):
        """Enforce mode allows approved tool with hash baseline."""
        config = _enforce_config()
        registry = ToolRegistry()
        # Pre-register and approve the tool
        registry.register(ToolEntry(
            name="cli:echo",
            description_hash=hashlib.sha256(b"echo-hash").hexdigest(),
            status=ToolStatus.APPROVED,
        ))
        engine = Engine(config, registry=registry)
        producer = CLIActionProducer(config=config, engine=engine, registry=registry)

        # Translate first to get the hash that PR-03 will see
        invocation = CLIInvocation(command=["echo", "hello"], agent_name="test-agent")
        action = producer.translate(invocation)
        # Update registry to match the action's description_hash (simulating discovery)
        if action.tool.description_hash:
            entry = registry.lookup("cli:echo")
            entry.description_hash = action.tool.description_hash

        result = producer.execute(command=["echo", "hello"], agent_name="test-agent")
        # In enforce mode with approved + hash-matching tool, should allow
        assert not result.blocked
        assert result.stdout.strip() == "hello"


# --- CLI Pattern Detection ---


class TestCLIPatternDetection:
    def _make_producer(self):
        config = _config()
        return CLIActionProducer(config=config, engine=_make_engine(config))

    def test_stdout_scanned_for_patterns(self):
        """CLI stdout containing sensitive patterns gets flagged."""
        producer = self._make_producer()
        result = producer.execute(
            command=["echo", "SSN: 123-45-6789"],
            agent_name="test-agent",
        )
        assert not result.blocked
        # The SSN pattern should be detected in stdout
        assert result.scan_result is not None
        pattern_types = [p.pattern_type for p in result.scan_result.patterns]
        assert "ssn" in pattern_types

    def test_no_scan_when_blocked(self):
        """Blocked execution does not scan (no output to scan)."""
        config = _enforce_config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine)
        result = producer.execute(
            command=["echo", "SSN: 123-45-6789"],
            agent_name="test-agent",
        )
        assert result.blocked
        assert result.scan_result is None

    def test_clean_stdout_no_scan_result(self):
        """Clean stdout produces no scan result."""
        producer = self._make_producer()
        result = producer.execute(
            command=["echo", "hello world"],
            agent_name="test-agent",
        )
        assert result.scan_result is None


# --- CLI Invocation Dataclass ---


class TestCLIInvocation:
    def test_basic_fields(self):
        inv = CLIInvocation(command=["echo", "hi"], agent_name="agent-1")
        assert inv.command == ["echo", "hi"]
        assert inv.agent_name == "agent-1"
        assert inv.working_directory is None
        assert inv.environment is None

    def test_with_all_fields(self):
        inv = CLIInvocation(
            command=["ls"],
            agent_name="agent-1",
            working_directory="/tmp",
            environment={"PATH": "/usr/bin"},
        )
        assert inv.working_directory == "/tmp"
        assert inv.environment == {"PATH": "/usr/bin"}


# --- Backward Compatibility ---


class TestBackwardCompatibility:
    def test_mcp_action_builder_still_works(self):
        """Existing MCP action builder produces actions with producer_type='mcp'."""
        from ancilis.middleware.action_builder import build_action

        config = _config()
        registry = ToolRegistry()
        action = build_action("test-tool", {"key": "val"}, config, registry)
        assert action.producer_type == "mcp"

    def test_existing_action_construction_unchanged(self):
        """Actions constructed without producer_type default to 'mcp'."""
        action = Action(
            action_id="id",
            timestamp="ts",
            agent_id="agent",
            action_type="tool_call",
            tool=ToolInfo(name="tool"),
            parameters=ActionParameters(),
        )
        assert action.producer_type == "mcp"
        assert action.producer_version == "0.1.0"

    def test_engine_evaluates_cli_actions(self):
        """Engine evaluates CLI-produced actions the same as MCP actions."""
        config = _config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine)
        invocation = CLIInvocation(command=["echo", "test"], agent_name="test-agent")
        action = producer.translate(invocation)
        evaluation = engine.evaluate(action)
        assert evaluation.decision in ("ALLOW", "BLOCK")
        assert len(evaluation.control_results) > 0

    def test_package_exports(self):
        """New types are importable from the ancilis package."""
        import ancilis

        assert hasattr(ancilis, "CLIActionProducer")
        assert hasattr(ancilis, "CLIInvocation")
        assert hasattr(ancilis, "CLIExecutionResult")
        assert hasattr(ancilis, "ActionProducer")
        assert hasattr(ancilis, "ProducerType")

    def test_mcp_producer_lazy_import(self):
        """MCPActionProducer is available via lazy import."""
        import ancilis

        # This should work via __getattr__
        assert "MCPActionProducer" in ancilis.__all__
