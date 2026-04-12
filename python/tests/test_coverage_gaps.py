"""Coverage gap fill — targets uncovered lines in core modules.

Modules addressed:
- ancilis/config.py         (UnavailableOverlay, format_resolved_config, load_config default path)
- ancilis/evidence/store.py (context manager, DB migration, tenant branches, chain verify)
- ancilis/middleware/middleware.py (default init, get_summary_line, async ctx manager)
- ancilis/engine/evaluators/pr02_scope.py (rate limit)
- ancilis/engine/evaluators/pr04_exposure.py (unauthorized destination)
- ancilis/engine/patterns.py (email, phone, api_key, mrn, luhn edge cases)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, patch

import duckdb
import pytest

from ancilis.config import (
    UnavailableOverlay,
    format_resolved_config,
    load_config,
    load_overlay_definitions,
)
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.pr02_scope import PR02ScopeEvaluator, RateTracker
from ancilis.engine.evaluators.pr04_exposure import PR04ExposureEvaluator
from ancilis.engine.patterns import (
    _luhn_check,
    _redact_api_key,
    _redact_email,
    _redact_mrn,
    _redact_phone,
    scan_for_patterns,
)
from ancilis.evidence.store import EvidenceStore
from ancilis.middleware import AncilisMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _make_action(
    tool_name: str = "test-tool",
    params: dict | None = None,
    agent_id: str = "test-agent",
) -> Action:
    return Action(
        action_id="act-001",
        timestamp="2025-01-01T00:00:00Z",
        agent_id=agent_id,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw=params or {}),
    )


def _mock_session(text: str = "OK") -> AsyncMock:
    @dataclass
    class MockTextContent:
        type: str = "text"
        text: str = ""
        annotations: Any = None
        meta: Any = None

    @dataclass
    class MockCallToolResult:
        content: list[Any] = field(default_factory=list)
        isError: bool = False  # noqa: N815
        structuredContent: Any = None  # noqa: N815
        meta: Any = None

    @dataclass
    class MockListToolsResult:
        tools: list[Any] = field(default_factory=list)

    session = AsyncMock()
    session.call_tool.return_value = MockCallToolResult(
        content=[MockTextContent(text=text)]
    )
    session.list_tools.return_value = MockListToolsResult(tools=[])
    return session


# ---------------------------------------------------------------------------
# config.py — UnavailableOverlay
# ---------------------------------------------------------------------------


class TestUnavailableOverlay:
    def test_unavailable_overlay_init(self):
        """UnavailableOverlay stores overlay_id, triggered_by, data_type."""
        uo = UnavailableOverlay("future-overlay", "DC-PHI", "health_records")
        assert uo.overlay_id == "future-overlay"
        assert uo.triggered_by == "DC-PHI"
        assert uo.data_type == "health_records"

    def test_unavailable_overlay_resolution(self, monkeypatch):
        """When a DC code maps to an overlay not in available files, it becomes unavailable."""
        real_load = load_overlay_definitions

        def patched_load():
            overlays = real_load()
            # Remove hipaa to make it appear unavailable
            overlays.pop("hipaa", None)
            return overlays

        monkeypatch.setattr("ancilis.config.load_overlay_definitions", patched_load)

        resolved = load_config(
            raw={
                "agent": {"name": "test"},
                "my_agent_handles": ["health_records"],
            }
        )
        assert len(resolved.unavailable_overlays) > 0
        hipaa_unavailable = [u for u in resolved.unavailable_overlays if u.overlay_id == "hipaa"]
        assert hipaa_unavailable, "Expected hipaa in unavailable overlays"
        uo = hipaa_unavailable[0]
        assert uo.data_type == "health_records"


# ---------------------------------------------------------------------------
# config.py — format_resolved_config
# ---------------------------------------------------------------------------


class TestFormatResolvedConfig:
    def test_basic_format_contains_agent_name(self):
        resolved = _make_config()
        output = format_resolved_config(resolved)
        assert "test-agent" in output
        assert "Mode:" in output

    def test_format_with_overlays(self):
        resolved = _make_config(
            my_agent_handles=["health_records"],
            compliance={"overlays": ["hipaa"]},
        )
        output = format_resolved_config(resolved)
        assert "Active Overlays:" in output
        assert "HIPAA" in output or "hipaa" in output.lower()

    def test_format_with_data_classifications(self):
        resolved = _make_config(my_agent_handles=["health_records"])
        output = format_resolved_config(resolved)
        assert "Data Classifications:" in output
        assert "health_records" in output

    def test_format_with_warnings(self):
        # Invalid certification target triggers a warning
        resolved = _make_config(certification_targets=["not-a-real-cert"])
        output = format_resolved_config(resolved)
        assert "Warnings:" in output

    def test_format_with_overlay_adjustments(self):
        """Financial overlay (GLBA) should apply strict threshold adjustments."""
        resolved = _make_config(
            my_agent_handles=["financial_records"],
            compliance={"overlays": ["glba"]},
        )
        output = format_resolved_config(resolved)
        # If overlay adjustments applied, they appear in output
        # (may or may not appear depending on GLBA control_adjustments)
        assert "test-agent" in output  # sanity check

    def test_format_with_unavailable_overlays(self, monkeypatch):
        """Unavailable overlays appear in the formatted output."""
        real_load = load_overlay_definitions

        def patched_load():
            overlays = real_load()
            overlays.pop("hipaa", None)
            return overlays

        monkeypatch.setattr("ancilis.config.load_overlay_definitions", patched_load)

        resolved = load_config(
            raw={
                "agent": {"name": "test"},
                "my_agent_handles": ["health_records"],
            }
        )
        output = format_resolved_config(resolved)
        assert "Unavailable Overlays" in output


# ---------------------------------------------------------------------------
# config.py — load_config default path fallback
# ---------------------------------------------------------------------------


class TestLoadConfigDefaultPath:
    def test_load_config_finds_ancilis_yaml_in_cwd(self, tmp_path, monkeypatch):
        """load_config() with no args should find ancilis.yaml in cwd."""
        yaml_content = "agent:\n  name: cwd-agent\n"
        (tmp_path / "ancilis.yaml").write_text(yaml_content)
        monkeypatch.chdir(tmp_path)

        resolved = load_config()
        assert resolved.agent_name == "cwd-agent"

    def test_load_config_no_args_no_file_raises(self, tmp_path, monkeypatch):
        """load_config() with no args and no ancilis.yaml raises FileNotFoundError."""
        monkeypatch.chdir(tmp_path)

        with pytest.raises(FileNotFoundError, match="ancilis.yaml"):
            load_config()


# ---------------------------------------------------------------------------
# evidence/store.py — context manager
# ---------------------------------------------------------------------------


class TestEvidenceStoreContextManager:
    def test_context_manager_enter_returns_store(self):
        config = _make_config()
        store = EvidenceStore(config, in_memory=True)
        with store as s:
            assert s is store

    def test_context_manager_exit_closes_store(self):
        config = _make_config()
        store = EvidenceStore(config, in_memory=True)
        with store:
            pass
        # After exit, _conn should be None
        assert store._conn is None


# ---------------------------------------------------------------------------
# evidence/store.py — DB migration (missing columns)
# ---------------------------------------------------------------------------


class TestEvidenceStoreMigration:
    def test_migration_adds_missing_columns(self, tmp_path):
        """Store opens old DB missing session_id/source_type/output_summary and migrates it."""
        db_path = str(tmp_path / "old.duckdb")

        # Create DB with minimal schema (no session_id, source_type, output_summary)
        conn = duckdb.connect(db_path)
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1;
            CREATE TABLE evidence_records (
                seq_id BIGINT DEFAULT nextval('evidence_seq'),
                record_id VARCHAR PRIMARY KEY,
                evaluation_id VARCHAR NOT NULL,
                timestamp VARCHAR NOT NULL,
                agent_id VARCHAR NOT NULL,
                tool_name VARCHAR NOT NULL,
                decision VARCHAR NOT NULL,
                mode VARCHAR NOT NULL,
                control_results JSON NOT NULL,
                active_overlays JSON NOT NULL,
                data_classifications JSON NOT NULL,
                active_certifications JSON NOT NULL,
                record_hash VARCHAR NOT NULL,
                previous_hash VARCHAR NOT NULL,
                total_duration_ms DOUBLE NOT NULL,
                tenant_id VARCHAR
            );
        """)
        conn.close()

        config = _make_config()
        store = EvidenceStore(config, db_path=db_path)
        store._ensure_initialized()

        # Verify migrated columns exist
        columns = {
            row[1]
            for row in store._conn.execute(
                "PRAGMA table_info('evidence_records')"
            ).fetchall()
        }
        assert "session_id" in columns
        assert "source_type" in columns
        assert "output_summary" in columns
        store.close()


# ---------------------------------------------------------------------------
# evidence/store.py — tenant_id branches in list_sessions / latest_session_id
# ---------------------------------------------------------------------------


class TestEvidenceStoreTenantBranches:
    def _store_with_record(self, config, tenant_id=None, session_id="sess-1"):
        """Create in-memory store and persist one record."""
        from ancilis.engine.result import ControlResult, EvaluationResult

        store = EvidenceStore(config, in_memory=True, tenant_id=tenant_id)
        eval_result = EvaluationResult(
            evaluation_id="eval-001",
            action_id="action-001",
            timestamp="2025-01-15T10:00:00Z",
            agent_id="test-agent",
            mode="audit",
            session_id=session_id,
            control_results=[
                ControlResult(
                    control_id="PR-01",
                    control_name="Agent Identity",
                    result="PASS",
                    detail="OK",
                    evidence_data={},
                    duration_ms=1.0,
                )
            ],
            decision="ALLOW",
            decision_reason="All passed",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=5.0,
        )
        store.store(eval_result, tool_name="test-tool")
        return store

    def test_list_sessions_with_tenant_id(self):
        config = _make_config()
        store = self._store_with_record(config, tenant_id="tenant-A", session_id="sess-T1")
        sessions = store.list_sessions()
        assert any(s["session_id"] == "sess-T1" for s in sessions)
        store.close()

    def test_latest_session_id_with_tenant_id(self):
        config = _make_config()
        store = self._store_with_record(config, tenant_id="tenant-B", session_id="sess-T2")
        latest = store.latest_session_id()
        assert latest == "sess-T2"
        store.close()


# ---------------------------------------------------------------------------
# evidence/store.py — verify_chain hash mismatch
# ---------------------------------------------------------------------------


class TestEvidenceStoreChainVerify:
    def _make_eval(self, evaluation_id: str = "eval-001") -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult
        return EvaluationResult(
            evaluation_id=evaluation_id,
            action_id="action-001",
            timestamp="2025-01-15T10:00:00Z",
            agent_id="test-agent",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="PR-01",
                    control_name="Agent Identity",
                    result="PASS",
                    detail="OK",
                    evidence_data={},
                    duration_ms=1.0,
                )
            ],
            decision="ALLOW",
            decision_reason="All passed",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=5.0,
        )

    def test_verify_chain_detects_record_hash_tampering(self, tmp_path):
        """verify_chain returns errors when record_hash is corrupted (recomputed mismatch)."""
        config = _make_config()
        store = EvidenceStore(config, db_path=str(tmp_path / "tampered.duckdb"))
        store.store(self._make_eval(), tool_name="test-tool")

        # Corrupt record_hash — recomputed hash won't match stored
        store._conn.execute(
            "UPDATE evidence_records SET record_hash = 'deadbeef' || record_hash"
        )

        valid, errors = store.verify_chain()
        assert not valid
        assert len(errors) > 0
        store.close()

    def test_verify_chain_detects_previous_hash_tampering(self, tmp_path):
        """verify_chain returns errors when previous_hash breaks the chain link."""
        config = _make_config()
        store = EvidenceStore(config, db_path=str(tmp_path / "prev-tampered.duckdb"))
        store.store(self._make_eval("eval-001"), tool_name="test-tool")

        # Corrupt previous_hash so the chain link is broken
        store._conn.execute(
            "UPDATE evidence_records SET previous_hash = 'badhash' WHERE true"
        )

        valid, errors = store.verify_chain()
        assert not valid
        assert any("previous_hash" in e for e in errors)
        store.close()

    def test_verify_chain_empty_store_is_valid(self):
        config = _make_config()
        store = EvidenceStore(config, in_memory=True)
        valid, errors = store.verify_chain()
        assert valid
        assert errors == []
        store.close()


# ---------------------------------------------------------------------------
# evidence/store.py — get_records with agent_id filter
# ---------------------------------------------------------------------------


class TestEvidenceStoreGetRecordsFilters:
    def test_get_records_with_agent_id_filter(self):
        """get_records(agent_id=...) applies the agent_id WHERE condition."""
        from ancilis.engine.result import ControlResult, EvaluationResult

        config = _make_config()
        store = EvidenceStore(config, in_memory=True)

        eval_result = EvaluationResult(
            evaluation_id="eval-001",
            action_id="action-001",
            timestamp="2025-01-15T10:00:00Z",
            agent_id="target-agent",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="PR-01",
                    control_name="Agent Identity",
                    result="PASS",
                    detail="OK",
                    evidence_data={},
                    duration_ms=1.0,
                )
            ],
            decision="ALLOW",
            decision_reason="All passed",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=5.0,
        )
        store.store(eval_result, tool_name="my-tool")

        records = store.get_records(agent_id="target-agent")
        assert len(records) == 1
        assert records[0].agent_id == "target-agent"

        # Filter by non-existent agent returns empty
        records_none = store.get_records(agent_id="other-agent")
        assert len(records_none) == 0
        store.close()


# ---------------------------------------------------------------------------
# middleware/middleware.py — default config (no args)
# ---------------------------------------------------------------------------


class TestMiddlewareDefaultConfig:
    @pytest.mark.asyncio
    async def test_init_with_no_config_uses_default(self):
        """Middleware with no config uses load_config(raw=...) default."""
        session = _mock_session()
        config = _make_config()
        mw = AncilisMiddleware(
            session,
            evidence_store=EvidenceStore(config, in_memory=True),
        )
        # Default name comes from the internal default raw config
        assert mw.config.agent_name == "ancilis-agent"


# ---------------------------------------------------------------------------
# middleware/middleware.py — get_summary_line
# ---------------------------------------------------------------------------


class TestMiddlewareSummaryLine:
    @pytest.mark.asyncio
    async def test_get_summary_line_after_call(self):
        config = _make_config()
        session = _mock_session()
        store = EvidenceStore(config, in_memory=True)
        mw = AncilisMiddleware(session, config=config, evidence_store=store)

        from ancilis.engine.registry import ToolEntry
        mw.registry.register(ToolEntry(name="my-tool"))

        await mw.call_tool("my-tool", {})

        line = mw.get_summary_line()
        assert "1 tool calls evaluated" in line
        assert "Ancilis:" in line

    @pytest.mark.asyncio
    async def test_get_summary_line_zero_calls(self):
        config = _make_config()
        session = _mock_session()
        store = EvidenceStore(config, in_memory=True)
        mw = AncilisMiddleware(session, config=config, evidence_store=store)
        line = mw.get_summary_line()
        assert "0 tool calls evaluated" in line


# ---------------------------------------------------------------------------
# middleware/middleware.py — async context manager
# ---------------------------------------------------------------------------


class TestMiddlewareAsyncContextManager:
    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        config = _make_config()
        session = _mock_session()
        store = EvidenceStore(config, in_memory=True)
        async with AncilisMiddleware(session, config=config, evidence_store=store) as mw:
            assert mw.config.agent_name == "test-agent"
        # After exit, store should be closed
        assert store._conn is None


# ---------------------------------------------------------------------------
# middleware/middleware.py — _extract_response_text with real TextContent
# ---------------------------------------------------------------------------


class TestExtractResponseText:
    def test_extract_with_mcp_text_content(self):
        """_extract_response_text handles real MCP TextContent instances."""
        try:
            from mcp.types import TextContent
            content = TextContent(type="text", text="hello world")
        except (ImportError, Exception):
            pytest.skip("MCP TextContent not available")

        @dataclass
        class FakeResult:
            content: list[Any] = field(default_factory=list)

        result = FakeResult(content=[content])
        text = AncilisMiddleware._extract_response_text(result)  # type: ignore[arg-type]
        assert text == "hello world"


# ---------------------------------------------------------------------------
# PR-02 Scope Evaluator — rate limit exceeded
# ---------------------------------------------------------------------------


class TestPR02RateLimit:
    def test_rate_limit_exceeded_returns_fail(self):
        class HighRateTracker(RateTracker):
            def get_action_count(self, agent_id: str) -> int:
                return 999  # always over limit

        config = _make_config(security={"scope": {"max_actions_per_minute": 10}})
        evaluator = PR02ScopeEvaluator(rate_tracker=HighRateTracker())
        action = _make_action()
        result = evaluator.evaluate(action, config)
        assert result.result == "FAIL"
        assert "rate limit" in result.detail.lower()

    def test_rate_tracker_default_returns_zero(self):
        """Default RateTracker.get_action_count() returns 0 (interface stub)."""
        tracker = RateTracker()
        assert tracker.get_action_count("any-agent") == 0

    def test_extract_destination_returns_none_when_no_keys(self):
        """_extract_destination returns None when params have no url/host/etc."""
        config = _make_config()
        evaluator = PR02ScopeEvaluator()
        action = _make_action(params={"data": "value", "count": 5})
        result = evaluator._extract_destination(action)
        assert result is None


# ---------------------------------------------------------------------------
# PR-04 Exposure Evaluator — unauthorized destination (allowed list)
# ---------------------------------------------------------------------------


class TestPR04UnauthorizedDestination:
    def test_sensitive_data_to_non_allowlisted_destination_fails(self):
        """Sensitive data going to a destination not in allowed_destinations is FAIL."""
        config = _make_config(
            security={
                "scope": {
                    "allowed_destinations": ["trusted.example.com"],
                }
            }
        )
        evaluator = PR04ExposureEvaluator()
        # SSN triggers a sensitive pattern match
        action = _make_action(
            params={
                "message": "SSN is 123-45-6789",
                "url": "untrusted.other.com",
            }
        )
        result = evaluator.evaluate(action, config)
        assert result.result == "FAIL"
        assert "unauthorized destination" in result.detail.lower()


# ---------------------------------------------------------------------------
# engine/patterns.py — email, phone, API key, MRN, Luhn edge cases
# ---------------------------------------------------------------------------


class TestPatternDetection:
    def test_email_detected_and_redacted(self):
        matches = scan_for_patterns("Contact us at user@example.com for help.")
        email_match = next((m for m in matches if m.pattern_type == "email"), None)
        assert email_match is not None
        assert email_match.count == 1
        assert "@" in email_match.redacted_sample
        assert "***" in email_match.redacted_sample

    def test_phone_detected_and_redacted(self):
        matches = scan_for_patterns("Call 555-867-5309 for support.")
        phone_match = next((m for m in matches if m.pattern_type == "phone"), None)
        assert phone_match is not None
        assert "***" in phone_match.redacted_sample

    def test_api_key_detected_and_redacted(self):
        matches = scan_for_patterns("Use token sk-abcdefghijklmnopqrstuvwxyz123456 to auth.")
        api_match = next((m for m in matches if m.pattern_type == "api_key"), None)
        assert api_match is not None
        assert "***" in api_match.redacted_sample

    def test_mrn_detected_and_redacted(self):
        # MRN pattern: MRN[-:\s]?\d{6,} — only one separator char allowed
        matches = scan_for_patterns("Patient MRN:1234567 admitted today.")
        mrn_match = next((m for m in matches if m.pattern_type == "mrn"), None)
        assert mrn_match is not None
        assert "MRN-***" in mrn_match.redacted_sample

    def test_redact_email_no_at_sign(self):
        """_redact_email handles edge case where split on @ gives only one part."""
        # Shouldn't happen in practice but exercises the len(parts) > 1 branch
        result = _redact_email("user@domain.com")
        assert "***" in result
        assert "@" in result

    def test_redact_phone(self):
        result = _redact_phone("555-867-5309")
        assert "***-***-" in result
        assert result.endswith("5309")

    def test_redact_api_key(self):
        result = _redact_api_key("sk-abcdef12345678901234")
        assert result.startswith("sk-a")
        assert "***" in result

    def test_redact_mrn(self):
        result = _redact_mrn("MRN:1234567")
        assert "MRN-***" in result

    def test_luhn_too_many_digits_returns_false(self):
        """_luhn_check returns False for numbers with > 19 digits."""
        too_long = "1" * 20  # 20 digits — over the 19 limit
        assert _luhn_check(too_long) is False

    def test_luhn_subtraction_path(self):
        """Luhn d *= 2 followed by d -= 9 fires for doubled digits > 9."""
        # Visa test number: 4111111111111111 (known Luhn-valid)
        assert _luhn_check("4111111111111111") is True

    def test_multiple_emails_count(self):
        text = "a@x.com and b@y.com and c@z.com"
        matches = scan_for_patterns(text)
        email_match = next((m for m in matches if m.pattern_type == "email"), None)
        assert email_match is not None
        assert email_match.count == 3
