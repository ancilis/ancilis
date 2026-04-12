"""Coverage baseline tests — exercises zero-coverage modules directly.

These tests ensure that all pure-dataclass, protocol, and __init__ re-export
modules are exercised by the test suite. They are intentionally lightweight;
the goal is coverage, not deep behaviour testing (other suites handle that).
"""

from __future__ import annotations

import importlib


# ---------------------------------------------------------------------------
# engine/__init__.py (re-exports)
# ---------------------------------------------------------------------------

def test_engine_init_exports():
    import ancilis.engine as eng
    from ancilis.engine import (
        Action,
        ActionContext,
        ActionParameters,
        ControlResult,
        Engine,
        EvaluationResult,
        ToolEntry,
        ToolInfo,
        ToolRegistry,
    )
    assert eng.Action is Action
    assert eng.Engine is Engine
    assert eng.ControlResult is ControlResult
    assert eng.EvaluationResult is EvaluationResult
    assert eng.ToolRegistry is ToolRegistry


# ---------------------------------------------------------------------------
# engine/action.py — dataclasses
# ---------------------------------------------------------------------------

def test_tool_info_defaults():
    from ancilis.engine.action import ToolInfo
    ti = ToolInfo(name="my_tool")
    assert ti.name == "my_tool"
    assert ti.version is None
    assert ti.server is None
    assert ti.description_hash is None


def test_tool_info_full():
    from ancilis.engine.action import ToolInfo
    ti = ToolInfo(name="t", version="1.0", server="srv", description_hash="abc")
    assert ti.version == "1.0"
    assert ti.server == "srv"
    assert ti.description_hash == "abc"


def test_action_parameters_defaults():
    from ancilis.engine.action import ActionParameters
    ap = ActionParameters()
    assert ap.raw == {}
    assert ap.parameter_hash == ""


def test_action_parameters_with_data():
    from ancilis.engine.action import ActionParameters
    ap = ActionParameters(raw={"key": "val"}, parameter_hash="deadbeef")
    assert ap.raw["key"] == "val"
    assert ap.parameter_hash == "deadbeef"


def test_action_context_defaults():
    from ancilis.engine.action import ActionContext
    ctx = ActionContext()
    assert ctx.session_id is None
    assert ctx.parent_action_id is None
    assert ctx.data_classifications == []
    assert ctx.active_overlays == []


def test_action_context_with_data():
    from ancilis.engine.action import ActionContext
    ctx = ActionContext(
        session_id="s1",
        parent_action_id="p1",
        data_classifications=["DC-01"],
        active_overlays=["financial"],
    )
    assert ctx.session_id == "s1"
    assert ctx.parent_action_id == "p1"
    assert "DC-01" in ctx.data_classifications
    assert "financial" in ctx.active_overlays


def test_action_full():
    from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
    action = Action(
        action_id="act-001",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-x",
        action_type="tool_call",
        tool=ToolInfo(name="read_file"),
        parameters=ActionParameters(raw={"path": "/tmp/x"}),
        agent_owner="alice",
        context=ActionContext(session_id="sess-42"),
        source_type="agent",
        producer_type="mcp",
        producer_version="0.1.0",
    )
    assert action.action_id == "act-001"
    assert action.agent_id == "agent-x"
    assert action.action_type == "tool_call"
    assert action.tool.name == "read_file"
    assert action.parameters.raw["path"] == "/tmp/x"
    assert action.agent_owner == "alice"
    assert action.context.session_id == "sess-42"
    assert action.source_type == "agent"
    assert action.producer_type == "mcp"
    assert action.producer_version == "0.1.0"


def test_action_defaults():
    from ancilis.engine.action import Action, ActionParameters, ToolInfo
    action = Action(
        action_id="act-002",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-y",
        action_type="tool_call",
        tool=ToolInfo(name="write_file"),
        parameters=ActionParameters(),
    )
    assert action.agent_owner is None
    assert action.source_type == "agent"
    assert action.producer_type == "mcp"
    assert action.producer_version == "0.1.0"


# ---------------------------------------------------------------------------
# engine/result.py — dataclasses
# ---------------------------------------------------------------------------

def test_control_result_required_fields():
    from ancilis.engine.result import ControlResult
    cr = ControlResult(
        control_id="PR-01",
        control_name="Agent Identity",
        result="PASS",
        detail="Verified",
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data == {}
    assert cr.duration_ms == 0.0
    assert cr.display_name == ""
    assert cr.display_detail == ""
    assert cr.remediation_hint == ""


def test_control_result_optional_fields():
    from ancilis.engine.result import ControlResult
    cr = ControlResult(
        control_id="PR-04",
        control_name="Exposure",
        result="FLAG",
        detail="PII detected",
        evidence_data={"pii": True},
        duration_ms=5.5,
        display_name="Exposure Control",
        display_detail="PII in output",
        remediation_hint="Redact PII",
    )
    assert cr.evidence_data == {"pii": True}
    assert cr.duration_ms == 5.5
    assert cr.display_name == "Exposure Control"
    assert cr.remediation_hint == "Redact PII"


def test_evaluation_result_required_fields():
    from ancilis.engine.result import EvaluationResult
    er = EvaluationResult(
        evaluation_id="ev-001",
        action_id="act-001",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-x",
    )
    assert er.evaluation_id == "ev-001"
    assert er.source_type == "agent"
    assert er.mode == "audit"
    assert er.control_results == []
    assert er.decision == "ALLOW"
    assert er.decision_reason == ""
    assert er.active_overlays == []
    assert er.data_classifications == []
    assert er.total_duration_ms == 0.0
    assert er.session_id is None


def test_evaluation_result_full():
    from ancilis.engine.result import ControlResult, EvaluationResult
    cr = ControlResult("PR-01", "Identity", "PASS", "ok")
    er = EvaluationResult(
        evaluation_id="ev-002",
        action_id="act-002",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-z",
        source_type="api",
        mode="enforce",
        control_results=[cr],
        decision="BLOCK",
        decision_reason="PR-01 failed",
        active_overlays=["financial"],
        data_classifications=["DC-01"],
        total_duration_ms=12.3,
        session_id="sess-99",
    )
    assert er.mode == "enforce"
    assert er.decision == "BLOCK"
    assert len(er.control_results) == 1
    assert er.session_id == "sess-99"
    assert er.total_duration_ms == 12.3


# ---------------------------------------------------------------------------
# engine/evaluators/__init__.py (re-exports)
# ---------------------------------------------------------------------------

def test_evaluators_init_exports():
    import ancilis.engine.evaluators as evs
    from ancilis.engine.evaluators import (
        PR01IdentityEvaluator,
        PR02ScopeEvaluator,
        PR03ProvenanceEvaluator,
        PR04ExposureEvaluator,
        PR05AuditEvaluator,
        PR06ConfigBaselineEvaluator,
        PR07TransportEvaluator,
        PR08InputEvaluator,
        DE01BaselineEvaluator,
        RateTracker,
        BaselineWindow,
        DeviationFlag,
    )
    assert evs.PR01IdentityEvaluator is PR01IdentityEvaluator
    assert evs.RateTracker is RateTracker
    assert evs.BaselineWindow is BaselineWindow


# ---------------------------------------------------------------------------
# engine/evaluators/base.py — Protocol
# ---------------------------------------------------------------------------

def test_control_evaluator_protocol_importable():
    from ancilis.engine.evaluators.base import ControlEvaluator
    # Protocol class is importable and runtime-checkable via structural subtyping
    assert hasattr(ControlEvaluator, 'evaluate')


def test_control_evaluator_structural_check():
    """Any class with the right shape satisfies ControlEvaluator."""
    from ancilis.engine.evaluators.base import ControlEvaluator
    from ancilis.engine.result import ControlResult

    class MyEvaluator:
        control_id = "MY-01"
        control_name = "My Control"

        def evaluate(self, action, config) -> ControlResult:
            return ControlResult("MY-01", "My Control", "PASS", "ok")

    ev = MyEvaluator()
    assert ev.control_id == "MY-01"
    result = ev.evaluate(None, None)
    assert result.result == "PASS"


# ---------------------------------------------------------------------------
# evidence/__init__.py (re-exports)
# ---------------------------------------------------------------------------

def test_evidence_init_exports():
    import ancilis.evidence as evi
    from ancilis.evidence import (
        GENESIS_SEED,
        EvidenceRecord,
        EvidenceStore,
        canonical_payload,
        compute_hash,
    )
    assert evi.GENESIS_SEED is GENESIS_SEED
    assert evi.EvidenceRecord is EvidenceRecord
    assert evi.EvidenceStore is EvidenceStore
    assert callable(evi.canonical_payload)
    assert callable(evi.compute_hash)


# ---------------------------------------------------------------------------
# evidence/record.py — dataclass
# ---------------------------------------------------------------------------

def test_evidence_record_required_fields():
    from ancilis.evidence.record import EvidenceRecord
    r = EvidenceRecord(
        record_id="rec-001",
        evaluation_id="ev-001",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-x",
        source_type="agent",
        tool_name="read_file",
        decision="ALLOW",
        mode="audit",
        control_results=[],
        active_overlays=[],
        data_classifications=[],
        active_certifications=[],
        record_hash="abc123",
        previous_hash="000000",
    )
    assert r.record_id == "rec-001"
    assert r.decision == "ALLOW"
    assert r.mode == "audit"
    assert r.control_results == []
    assert r.total_duration_ms == 0.0
    assert r.output_summary is None
    assert r.session_id is None
    assert r.tenant_id is None


def test_evidence_record_optional_fields():
    from ancilis.evidence.record import EvidenceRecord
    r = EvidenceRecord(
        record_id="rec-002",
        evaluation_id="ev-002",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-y",
        source_type="api",
        tool_name="write_file",
        decision="BLOCK",
        mode="enforce",
        control_results=[{"control_id": "PR-01", "result": "FAIL"}],
        active_overlays=["financial"],
        data_classifications=["DC-01"],
        active_certifications=["SOC2"],
        record_hash="deadbeef",
        previous_hash="cafebabe",
        total_duration_ms=7.5,
        output_summary="Wrote 100 bytes",
        session_id="sess-1",
        tenant_id="tenant-abc",
    )
    assert r.decision == "BLOCK"
    assert r.total_duration_ms == 7.5
    assert r.output_summary == "Wrote 100 bytes"
    assert r.session_id == "sess-1"
    assert r.tenant_id == "tenant-abc"
    assert r.active_certifications == ["SOC2"]


# ---------------------------------------------------------------------------
# middleware/__init__.py (re-exports)
# ---------------------------------------------------------------------------

def test_middleware_init_exports():
    import ancilis.middleware as mw
    from ancilis.middleware import AncilisMiddleware, BlockedToolCallError, ScanResult
    assert mw.AncilisMiddleware is AncilisMiddleware
    assert mw.BlockedToolCallError is BlockedToolCallError
    assert mw.ScanResult is ScanResult


# ---------------------------------------------------------------------------
# producers/protocol.py — Enum + Protocol
# ---------------------------------------------------------------------------

def test_producer_type_enum_values():
    from ancilis.producers.protocol import ProducerType
    assert ProducerType.MCP == "mcp"
    assert ProducerType.CLI == "cli"
    assert ProducerType.HTTP == "http"
    assert ProducerType.A2A == "a2a"
    assert ProducerType.FRAMEWORK == "framework"
    assert ProducerType.MANUAL == "manual"


def test_producer_type_is_str_enum():
    from ancilis.producers.protocol import ProducerType
    assert isinstance(ProducerType.MCP, str)
    assert ProducerType.MCP == "mcp"


def test_action_producer_protocol_importable():
    from ancilis.producers.protocol import ActionProducer
    assert hasattr(ActionProducer, 'translate')
    assert hasattr(ActionProducer, 'compute_tool_hash')
    assert hasattr(ActionProducer, 'register_tools')


def test_protocol_module_exports_action():
    """Protocol module re-imports Action and ToolRegistry."""
    from ancilis.producers.protocol import Action, ToolRegistry  # noqa: F401
    assert Action is not None
    assert ToolRegistry is not None


def test_action_producer_structural_check():
    """A concrete class satisfying ActionProducer protocol is runtime-checkable."""
    from ancilis.producers.protocol import ActionProducer, ProducerType
    from ancilis.engine.action import Action, ActionParameters, ToolInfo
    import uuid
    from datetime import datetime, timezone

    class MyProducer:
        @property
        def producer_type(self) -> ProducerType:
            return ProducerType.MANUAL

        @property
        def producer_version(self) -> str:
            return "1.0.0"

        def translate(self, raw_invocation) -> Action:
            return Action(
                action_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id="test",
                action_type="tool_call",
                tool=ToolInfo(name="test_tool"),
                parameters=ActionParameters(),
            )

        def compute_tool_hash(self, tool_identifier) -> str:
            return "hash"

        def register_tools(self, registry) -> list:
            return []

    p = MyProducer()
    assert isinstance(p, ActionProducer)
    assert p.producer_type == ProducerType.MANUAL
    assert p.producer_version == "1.0.0"
    action = p.translate({})
    assert action.agent_id == "test"
    assert p.compute_tool_hash("t") == "hash"
    assert p.register_tools(None) == []


# ---------------------------------------------------------------------------
# testing/__init__.py (re-exports)
# ---------------------------------------------------------------------------

def test_testing_init_exports():
    import ancilis.testing as t
    from ancilis.testing import (
        MockEvidenceStore,
        FakeProducer,
        ScanResult,
        ComplianceScenarios,
        assert_control_passes,
        assert_control_fails,
        assert_control_flags,
        assert_posture_above,
        assert_decision_allows,
        assert_decision_blocks,
        make_action,
        make_test_config,
    )
    assert t.MockEvidenceStore is MockEvidenceStore
    assert t.FakeProducer is FakeProducer
    assert t.ComplianceScenarios is ComplianceScenarios
    assert callable(t.assert_control_passes)
    assert callable(t.make_action)
    assert callable(t.make_test_config)


# ---------------------------------------------------------------------------
# testing/_helpers.py — make_action and make_test_config edge cases
# ---------------------------------------------------------------------------

def test_make_action_with_agent_owner():
    from ancilis.testing._helpers import make_action
    action = make_action(agent_owner="alice", agent_id="my-agent")
    assert action.agent_owner == "alice"
    assert action.agent_id == "my-agent"


def test_make_action_source_type():
    from ancilis.testing._helpers import make_action
    action = make_action(source_type="api")
    assert action.source_type == "api"


def test_make_test_config_with_no_overlay():
    from ancilis.testing._helpers import make_test_config
    config = make_test_config()
    assert config.agent_name == "test-agent"
    assert config.mode == "audit"


def test_make_test_config_enforce_mode():
    from ancilis.testing._helpers import make_test_config
    config = make_test_config(mode="enforce")
    assert config.mode == "enforce"


# ---------------------------------------------------------------------------
# testing/mock_store.py — MockEvidenceStore additional paths
# ---------------------------------------------------------------------------

def test_mock_store_get_records_filters():
    from ancilis.testing.mock_store import MockEvidenceStore
    from ancilis.engine.result import ControlResult, EvaluationResult

    store = MockEvidenceStore()
    cr = ControlResult("PR-01", "Identity", "PASS", "ok")
    ev = EvaluationResult(
        evaluation_id="ev-001",
        action_id="act-001",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="agent-x",
        control_results=[cr],
        decision="ALLOW",
    )
    store.store(ev, tool_name="read_file")

    # Filter by tool_name
    records = store.get_records(tool_name="read_file")
    assert len(records) == 1

    # Filter by non-matching tool_name
    records = store.get_records(tool_name="write_file")
    assert len(records) == 0

    store.close()


def test_mock_store_count_session():
    from ancilis.testing.mock_store import MockEvidenceStore
    from ancilis.engine.result import ControlResult, EvaluationResult

    store = MockEvidenceStore()
    cr = ControlResult("PR-01", "Identity", "PASS", "ok")
    ev = EvaluationResult(
        evaluation_id="ev-001",
        action_id="act-001",
        timestamp="2026-04-12T10:00:00Z",
        agent_id="test-agent",
        control_results=[cr],
        decision="ALLOW",
        session_id="sess-001",
    )
    store.store(ev, tool_name="tool_a")
    assert store.count() == 1
    store.close()


def test_mock_store_with_overlay():
    from ancilis.testing.mock_store import MockEvidenceStore
    store = MockEvidenceStore(agent_name="finance-agent", overlay="financial")
    assert store.count() == 0
    store.close()


# ---------------------------------------------------------------------------
# testing/fake_producer.py — FakeProducer edge cases
# ---------------------------------------------------------------------------

def test_fake_producer_data_classifications():
    from ancilis.testing.fake_producer import FakeProducer
    producer = FakeProducer("pii_tool", agent_id="my-agent")
    action = producer.make_action(data_classifications=["DC-01", "DC-02"])
    assert "DC-01" in action.context.data_classifications


def test_fake_producer_session_id():
    from ancilis.testing.fake_producer import FakeProducer
    producer = FakeProducer()
    action = producer.make_action(session_id="sess-xyz")
    assert action.context.session_id == "sess-xyz"


def test_fake_producer_source_type():
    from ancilis.testing.fake_producer import FakeProducer
    producer = FakeProducer()
    action = producer.make_action(source_type="api")
    assert action.source_type == "api"


def test_fake_producer_agent_owner():
    from ancilis.testing.fake_producer import FakeProducer
    producer = FakeProducer("t", agent_owner="bob")
    action = producer.make_action()
    assert action.agent_owner == "bob"


# ---------------------------------------------------------------------------
# testing/plugin.py — pytest plugin fixtures (direct test)
# ---------------------------------------------------------------------------

def test_plugin_ancilis_scan_fixture(ancilis_scan):
    """Exercises the ancilis_scan fixture path in plugin.py."""
    from ancilis.testing import ScanResult, assert_control_passes
    assert isinstance(ancilis_scan, ScanResult)
    assert_control_passes(ancilis_scan, "PR-01")


def test_plugin_ancilis_store_fixture(ancilis_store):
    """Exercises the ancilis_store fixture path in plugin.py."""
    from ancilis.testing import MockEvidenceStore
    assert isinstance(ancilis_store, MockEvidenceStore)
    assert ancilis_store.count() == 0


def test_plugin_ancilis_overlay_fixture(ancilis_overlay):
    """Exercises the ancilis_overlay fixture path in plugin.py."""
    # Default: no overlay configured
    assert ancilis_overlay is None


# ---------------------------------------------------------------------------
# engine/registry.py — full coverage of uncovered branches
# ---------------------------------------------------------------------------

def test_tool_registry_register_and_lookup():
    from ancilis.engine.registry import ToolEntry, ToolRegistry
    registry = ToolRegistry()
    entry = ToolEntry(name="my_tool")
    registry.register(entry)
    found = registry.lookup("my_tool")
    assert found is not None
    assert found.name == "my_tool"


def test_tool_registry_lookup_missing():
    from ancilis.engine.registry import ToolRegistry
    registry = ToolRegistry()
    assert registry.lookup("nonexistent") is None


def test_tool_registry_is_registered():
    from ancilis.engine.registry import ToolEntry, ToolRegistry
    registry = ToolRegistry()
    assert not registry.is_registered("t")
    registry.register(ToolEntry(name="t"))
    assert registry.is_registered("t")


def test_tool_registry_approve():
    from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
    registry = ToolRegistry()
    registry.register(ToolEntry(name="t"))
    result = registry.approve("t", approved_by="admin")
    assert result is True
    entry = registry.lookup("t")
    assert entry.status == ToolStatus.APPROVED
    assert entry.approved_by == "admin"
    assert entry.approved is True


def test_tool_registry_approve_missing():
    from ancilis.engine.registry import ToolRegistry
    registry = ToolRegistry()
    result = registry.approve("nonexistent")
    assert result is False


def test_tool_registry_get_all():
    from ancilis.engine.registry import ToolEntry, ToolRegistry
    registry = ToolRegistry()
    registry.register(ToolEntry(name="tool_a"))
    registry.register(ToolEntry(name="tool_b"))
    all_tools = registry.get_all()
    names = {t.name for t in all_tools}
    assert "tool_a" in names
    assert "tool_b" in names


def test_tool_entry_approved_property_observed():
    from ancilis.engine.registry import ToolEntry, ToolStatus
    entry = ToolEntry(name="t")
    assert entry.status == ToolStatus.OBSERVED
    assert entry.approved is False


def test_tool_entry_approved_property_blocked():
    from ancilis.engine.registry import ToolEntry, ToolStatus
    entry = ToolEntry(name="t", status=ToolStatus.BLOCKED)
    assert entry.approved is False


def test_tool_entry_fields():
    from ancilis.engine.registry import ToolEntry, ToolStatus
    entry = ToolEntry(
        name="my_tool",
        version="2.0",
        description_hash="abc",
        status=ToolStatus.APPROVED,
        approved_by="operator",
    )
    assert entry.version == "2.0"
    assert entry.description_hash == "abc"
    assert entry.approved_by == "operator"
    assert entry.first_seen is not None
    assert entry.status_changed is not None
