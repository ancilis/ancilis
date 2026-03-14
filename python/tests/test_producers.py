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
from ancilis.evidence.store import EvidenceStore


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


def _make_cli_producer(config=None, engine=None, registry=None, evidence_store=None):
    """Create a CLIActionProducer with in-memory evidence store for test isolation."""
    c = config or _config()
    e = engine or _make_engine(c, registry=registry)
    store = evidence_store or EvidenceStore(c, in_memory=True)
    return CLIActionProducer(config=c, engine=e, registry=registry, evidence_store=store)


# --- Protocol Compliance ---


class TestActionProducerProtocol:
    def test_cli_producer_satisfies_protocol(self):
        """CLIActionProducer satisfies ActionProducer protocol."""
        config = _config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
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
        return CLIActionProducer(config=c, engine=engine, evidence_store=EvidenceStore(c, in_memory=True))

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
        config = _config(my_agent_handles=["personal_info"])
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
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        invocation = CLIInvocation(command=["echo", "hi"], agent_name="test-agent")
        action = producer.translate(invocation)
        assert action.tool.description_hash == "abc123hash"


# --- CLI Tool Hash ---


class TestCLIToolHash:
    def _make_producer(self):
        config = _config()
        return CLIActionProducer(config=config, engine=_make_engine(config), evidence_store=EvidenceStore(config, in_memory=True))

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
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        registered = producer.register_tools(registry)
        assert "cli:echo" in registered
        assert "cli:cat" in registered

    def test_allowlisted_registered_as_approved(self):
        """Tools from config allowlist register as APPROVED."""
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        producer.register_tools(registry)
        entry = registry.lookup("cli:echo")
        assert entry is not None
        assert entry.status == ToolStatus.APPROVED
        assert entry.approved_by == "config"

    def test_registered_with_hash(self):
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        producer.register_tools(registry)
        entry = registry.lookup("cli:echo")
        assert entry is not None
        assert entry.description_hash is not None
        assert len(entry.description_hash) == 64

    def test_empty_allowlist_registers_nothing(self):
        config = _config()
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        registered = producer.register_tools(registry)
        assert registered == []


# --- CLI Execute: Audit Mode ---


class TestCLIExecuteAudit:
    def _make_producer(self, config=None):
        c = config or _config()
        engine = _make_engine(c)
        return CLIActionProducer(config=c, engine=engine, evidence_store=EvidenceStore(c, in_memory=True))

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
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
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
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))

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
        return CLIActionProducer(config=config, engine=_make_engine(config), evidence_store=EvidenceStore(config, in_memory=True))

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
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
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
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
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


# --- Fix 2: Double-Prefix Prevention ---


class TestCLIDoublePrefix:
    def test_no_double_prefix_bare_name(self):
        """Config with 'echo' produces 'cli:echo', not 'cli:cli:echo'."""
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        registered = producer.register_tools(registry)
        assert "cli:echo" in registered
        assert "cli:cli:echo" not in registered

    def test_no_double_prefix_already_prefixed(self):
        """Config with 'cli:echo' produces 'cli:echo', not 'cli:cli:echo'."""
        config = _config(security={"tools": {"allowed": ["cli:echo"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        registered = producer.register_tools(registry)
        assert "cli:echo" in registered
        assert "cli:cli:echo" not in registered


# --- Fix 2: Auto-Registration ---


class TestCLIAutoRegistration:
    def test_execute_auto_registers_unknown_tool_as_observed(self):
        """execute() registers unknown tool as OBSERVED."""
        config = _config()
        engine = _make_engine(config)
        registry = engine.registry
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        # Don't call register_tools()
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        entry = registry.lookup("cli:echo")
        assert entry is not None
        assert entry.status == ToolStatus.OBSERVED

    def test_auto_register_only_once(self):
        """Second execute() for same tool doesn't re-register."""
        config = _config()
        engine = _make_engine(config)
        registry = engine.registry
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        producer.execute(command=["echo", "first"], agent_name="test-agent")
        first_entry = registry.lookup("cli:echo")
        first_seen = first_entry.first_seen
        producer.execute(command=["echo", "second"], agent_name="test-agent")
        second_entry = registry.lookup("cli:echo")
        assert second_entry.first_seen == first_seen


# --- Fix 2: PR-02 Scope Prefix Awareness ---


class TestPR02PrefixAwareness:
    def test_bare_name_in_config_matches_prefixed_action(self):
        """tools_allowed: [echo] passes scope check for cli:echo action."""
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        # Find PR-02 result
        pr02 = next(
            (r for r in result.evaluation.control_results if r.control_id == "PR-02"),
            None,
        )
        assert pr02 is not None
        assert pr02.result == "PASS"

    def test_prefixed_name_in_config_matches(self):
        """tools_allowed: [cli:echo] passes scope check for cli:echo action."""
        config = _config(security={"tools": {"allowed": ["cli:echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        pr02 = next(
            (r for r in result.evaluation.control_results if r.control_id == "PR-02"),
            None,
        )
        assert pr02 is not None
        assert pr02.result == "PASS"

    def test_blocked_tool_with_prefix(self):
        """tools_blocked: [echo] blocks cli:echo action."""
        config = _config(security={"tools": {"blocked": ["echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        pr02 = next(
            (r for r in result.evaluation.control_results if r.control_id == "PR-02"),
            None,
        )
        assert pr02 is not None
        assert pr02.result == "FAIL"


# --- Fix 3: Evidence Persistence ---


class TestCLIEvidencePersistence:
    def test_execute_creates_evidence_record(self):
        """Every CLI execution produces a persistent evidence record."""
        from ancilis.evidence.store import EvidenceStore

        config = _config()
        engine = _make_engine(config)
        evidence_store = EvidenceStore(config, in_memory=True)
        producer = CLIActionProducer(
            config=config, engine=engine, evidence_store=evidence_store
        )
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        assert evidence_store.count() == 1

    def test_evidence_chain_integrity(self):
        """CLI evidence records participate in hash chain."""
        from ancilis.evidence.store import EvidenceStore

        config = _config()
        engine = _make_engine(config)
        evidence_store = EvidenceStore(config, in_memory=True)
        producer = CLIActionProducer(
            config=config, engine=engine, evidence_store=evidence_store
        )
        producer.execute(command=["echo", "first"], agent_name="test-agent")
        producer.execute(command=["echo", "second"], agent_name="test-agent")
        assert evidence_store.count() == 2
        valid, errors = evidence_store.verify_chain()
        assert valid, f"Chain errors: {errors}"

    def test_evidence_records_tool_name(self):
        """Evidence record contains the CLI tool name."""
        from ancilis.evidence.store import EvidenceStore

        config = _config()
        engine = _make_engine(config)
        evidence_store = EvidenceStore(config, in_memory=True)
        producer = CLIActionProducer(
            config=config, engine=engine, evidence_store=evidence_store
        )
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        records = evidence_store.get_records()
        assert len(records) == 1
        assert records[0].tool_name == "cli:echo"

    def test_default_constructor_produces_evidence(self):
        """CLI producer with default constructor produces evidence records."""
        config = _config()
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        result = producer.execute(command=["echo", "test"], agent_name="test-agent")
        assert not result.blocked
        assert result.stdout.strip() == "test"
        # Evidence store created by default, evidence recorded
        assert producer._evidence_store is not None
        assert producer._evidence_store.count() == 1

    def test_blocked_execution_still_produces_evidence(self):
        """Even blocked executions create evidence records."""
        from ancilis.evidence.store import EvidenceStore

        config = _enforce_config()
        engine = _make_engine(config)
        evidence_store = EvidenceStore(config, in_memory=True)
        producer = CLIActionProducer(
            config=config, engine=engine, evidence_store=evidence_store
        )
        result = producer.execute(command=["echo", "blocked"], agent_name="test-agent")
        assert result.blocked
        assert evidence_store.count() == 1
        records = evidence_store.get_records()
        assert records[0].decision == "BLOCK"


# --- Fix Pass #2: CLI Trust Lifecycle Parity ---


class TestCLITrustLifecycle:
    def test_allowlisted_tool_auto_registers_as_approved(self):
        """Auto-register honors config allowlist: echo in allowed -> APPROVED."""
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        entry = engine.registry.lookup("cli:echo")
        assert entry is not None
        assert entry.status == ToolStatus.APPROVED
        assert entry.approved_by == "config"

    def test_unknown_tool_auto_registers_as_observed(self):
        """Tool not in allowlist auto-registers as OBSERVED."""
        config = _config(security={"tools": {"allowed": ["cat"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        entry = engine.registry.lookup("cli:echo")
        assert entry is not None
        assert entry.status == ToolStatus.OBSERVED

    def test_bare_name_in_allowlist_matches_prefixed(self):
        """Config 'echo' matches auto-registered 'cli:echo'."""
        config = _config(security={"tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        entry = engine.registry.lookup("cli:echo")
        assert entry.status == ToolStatus.APPROVED

    def test_prefixed_name_in_allowlist_matches(self):
        """Config 'cli:echo' matches auto-registered 'cli:echo'."""
        config = _config(security={"tools": {"allowed": ["cli:echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        producer.execute(command=["echo", "test"], agent_name="test-agent")
        entry = engine.registry.lookup("cli:echo")
        assert entry.status == ToolStatus.APPROVED

    def test_enforce_mode_allows_allowlisted_cli_tool(self):
        """Enforce mode + allowlisted CLI tool -> not blocked (APPROVED status)."""
        config = _enforce_config(security={"mode": "enforce", "tools": {"allowed": ["echo"]}})
        engine = _make_engine(config)
        producer = CLIActionProducer(config=config, engine=engine, evidence_store=EvidenceStore(config, in_memory=True))
        result = producer.execute(command=["echo", "hello"], agent_name="test-agent")
        assert not result.blocked
        assert result.stdout.strip() == "hello"

    def test_register_tools_all_approved(self):
        """register_tools() marks all allowlisted tools as APPROVED."""
        config = _config(security={"tools": {"allowed": ["echo", "cat", "ls"]}})
        engine = _make_engine(config)
        registry = ToolRegistry()
        producer = CLIActionProducer(config=config, engine=engine, registry=registry, evidence_store=EvidenceStore(config, in_memory=True))
        producer.register_tools(registry)
        for name in ["cli:echo", "cli:cat", "cli:ls"]:
            entry = registry.lookup(name)
            assert entry is not None
            assert entry.status == ToolStatus.APPROVED
