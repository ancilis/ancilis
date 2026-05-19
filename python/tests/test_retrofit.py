"""Retrofit tests — Cert Declaration & Output Disclosure.

Verifies:
- certification_targets in ancilis.yaml drives targeted control activation
- Report includes a focused AIUC-1 readiness section when cert declared
- Tool response text is captured as output_summary in evidence records
- Output summary is truncated to 500 chars for large responses
- Blocked calls are stored with no output_summary
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
from ancilis.report.generator import ReportGenerator


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------


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


def _mock_session(response_text: str = "result-ok") -> AsyncMock:
    session = AsyncMock()
    session.call_tool.return_value = MockCallToolResult(
        content=[MockTextContent(text=response_text)]
    )
    return session


def _config_with_cert(**overrides):
    raw = {
        "agent": {"name": "test-cert-agent"},
        "certification_targets": ["aiuc-1"],
        **overrides,
    }
    return load_config(raw=raw)


# ---------------------------------------------------------------------------
# 1. Cert Declaration — control activation
# ---------------------------------------------------------------------------


class TestCertDeclaration:
    def test_aiuc1_target_populates_active_certifications(self):
        config = _config_with_cert()
        assert "aiuc-1" in config.active_certifications

    def test_aiuc1_activates_required_controls(self):
        """PR-01 through PR-05 must be enabled when aiuc-1 is declared."""
        config = _config_with_cert()
        required = {"PR-01", "PR-02", "PR-03", "PR-04", "PR-05"}
        enabled = {cid for cid, cs in config.controls.items() if cs.enabled}
        assert required.issubset(enabled), (
            f"Controls not activated: {required - enabled}"
        )

    def test_no_cert_target_leaves_active_certifications_empty(self):
        config = load_config(raw={"agent": {"name": "plain-agent"}})
        assert config.active_certifications == []

    def test_unknown_cert_target_produces_warning_not_error(self):
        config = load_config(raw={
            "agent": {"name": "test"},
            "certification_targets": ["nonexistent-cert"],
        })
        # Should not raise; unknown target adds a warning
        assert "nonexistent-cert" not in config.active_certifications
        assert any("nonexistent-cert" in w for w in config.warnings)


# ---------------------------------------------------------------------------
# 2. Cert Declaration → Focused readiness report
# ---------------------------------------------------------------------------


class TestCertReadinessReport:
    def test_cert_section_present_with_aiuc1_target(self):
        config = _config_with_cert()
        store = EvidenceStore(config, in_memory=True)
        try:
            gen = ReportGenerator(config, store)
            data = gen.generate(period="30d", report_format="aiuc1-readiness")
            assert data.certification is not None
            assert data.certification["certification_id"] == "aiuc-1"
        finally:
            store.close()

    def test_cert_section_absent_without_target(self):
        config = load_config(raw={"agent": {"name": "plain-agent"}})
        store = EvidenceStore(config, in_memory=True)
        try:
            gen = ReportGenerator(config, store)
            data = gen.generate(period="30d", report_format="terminal")
            assert data.certification is None
        finally:
            store.close()

    def test_cert_section_contains_readiness_percentage(self):
        config = _config_with_cert()
        store = EvidenceStore(config, in_memory=True)
        try:
            gen = ReportGenerator(config, store)
            data = gen.generate(period="30d", report_format="aiuc1-readiness")
            assert data.certification is not None
            assert "readiness_percentage" in data.certification
            assert isinstance(data.certification["readiness_percentage"], int)
        finally:
            store.close()

    def test_cert_section_present_with_terminal_format_too(self):
        """Cert section appears regardless of format when aiuc-1 is declared."""
        config = _config_with_cert()
        store = EvidenceStore(config, in_memory=True)
        try:
            gen = ReportGenerator(config, store)
            data = gen.generate(period="30d", report_format="terminal")
            assert data.certification is not None
        finally:
            store.close()


# ---------------------------------------------------------------------------
# 3. Output Disclosure — output_summary in evidence records
# ---------------------------------------------------------------------------


class TestOutputDisclosure:
    @pytest.mark.asyncio
    async def test_output_summary_stored_on_allow(self):
        """Tool response text must appear as output_summary in evidence record."""
        session = _mock_session(response_text="file contents here")
        store = EvidenceStore(
            load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True
        )
        mw = AncilisMiddleware(
            session,
            config=load_config(raw={
                "agent": {"name": "test-agent"},
                "security": {"tools": {"allowed": ["read_file"]}},
            }),
            evidence_store=store,
        )
        await mw.call_tool("read_file", {"path": "/tmp/a.txt"})

        records = store.get_records()
        assert len(records) == 1
        assert records[0].output_summary == "file contents here"
        store.close()

    @pytest.mark.asyncio
    async def test_output_summary_none_on_empty_response(self):
        """Empty response yields output_summary=None (not empty string)."""
        session = _mock_session(response_text="")
        store = EvidenceStore(
            load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True
        )
        mw = AncilisMiddleware(
            session,
            config=load_config(raw={
                "agent": {"name": "test-agent"},
                "security": {"tools": {"allowed": ["noop"]}},
            }),
            evidence_store=store,
        )
        await mw.call_tool("noop", {})

        records = store.get_records()
        assert records[0].output_summary is None
        store.close()

    @pytest.mark.asyncio
    async def test_output_summary_truncated_at_500_chars(self):
        """Output summaries longer than 500 chars must be truncated."""
        long_response = "X" * 1000
        session = _mock_session(response_text=long_response)
        store = EvidenceStore(
            load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True
        )
        mw = AncilisMiddleware(
            session,
            config=load_config(raw={
                "agent": {"name": "test-agent"},
                "security": {"tools": {"allowed": ["big_tool"]}},
            }),
            evidence_store=store,
        )
        await mw.call_tool("big_tool", {})

        records = store.get_records()
        assert len(records[0].output_summary) == 500
        store.close()

    @pytest.mark.asyncio
    async def test_output_summary_none_on_blocked_call(self):
        """Blocked calls store evidence with output_summary=None (no output produced)."""
        session = _mock_session()
        store = EvidenceStore(
            load_config(raw={"agent": {"name": "test-agent"}}), in_memory=True
        )
        mw = AncilisMiddleware(
            session,
            config=load_config(raw={
                "agent": {"name": "test-agent"},
                "security": {
                    "mode": "enforce",
                    "tools": {"blocked": ["dangerous_tool"]},
                },
            }),
            evidence_store=store,
        )
        with pytest.raises(BlockedToolCallError):
            await mw.call_tool("dangerous_tool", {})

        records = store.get_records()
        assert len(records) == 1
        assert records[0].output_summary is None
        store.close()

    @pytest.mark.asyncio
    async def test_output_summary_in_hash_chain(self):
        """Evidence record hash must reflect output_summary (chain integrity)."""
        import json
        from ancilis.evidence.chain import canonical_payload, compute_hash

        session = _mock_session(response_text="important output")
        config = load_config(raw={
            "agent": {"name": "test-agent"},
            "security": {"tools": {"allowed": ["summarize"]}},
        })
        store = EvidenceStore(config, in_memory=True)
        mw = AncilisMiddleware(session, config=config, evidence_store=store)
        await mw.call_tool("summarize", {"text": "hello"})

        records = store.get_records()
        rec = records[0]
        assert rec.output_summary == "important output"

        # Recompute hash and verify it differs from a null-output hash
        payload_with_output = canonical_payload(
            evaluation_id=rec.evaluation_id,
            timestamp=rec.timestamp,
            agent_id=rec.agent_id,
            source_type=rec.source_type,
            tool_name=rec.tool_name,
            decision=rec.decision,
            mode=rec.mode,
            control_results=rec.control_results,
            active_overlays=rec.active_overlays,
            data_classifications=rec.data_classifications,
            active_certifications=rec.active_certifications,
            total_duration_ms=rec.total_duration_ms,
            previous_hash=rec.previous_hash,
            output_summary="important output",
            session_id=rec.session_id,
            detected_data_types=rec.detected_data_types,
            sdk_version=rec.sdk_version,
            framework_version=rec.framework_version,
            classification_context=rec.classification_context,
        )
        payload_without_output = canonical_payload(
            evaluation_id=rec.evaluation_id,
            timestamp=rec.timestamp,
            agent_id=rec.agent_id,
            source_type=rec.source_type,
            tool_name=rec.tool_name,
            decision=rec.decision,
            mode=rec.mode,
            control_results=rec.control_results,
            active_overlays=rec.active_overlays,
            data_classifications=rec.data_classifications,
            active_certifications=rec.active_certifications,
            total_duration_ms=rec.total_duration_ms,
            previous_hash=rec.previous_hash,
            output_summary=None,
            session_id=rec.session_id,
            detected_data_types=rec.detected_data_types,
            sdk_version=rec.sdk_version,
            framework_version=rec.framework_version,
            classification_context=rec.classification_context,
        )
        assert compute_hash(payload_with_output) != compute_hash(payload_without_output)
        assert rec.record_hash == compute_hash(payload_with_output)
        store.close()
