"""Tests for DE-04, GOV-02, ID-01 evaluators (ANC-507)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.de04_integrity import DE04IntegrityEvaluator
from ancilis.engine.evaluators.gov02_ownership import GOV02OwnershipEvaluator
from ancilis.engine.evaluators.id01_inventory import ID01InventoryEvaluator


# --- Helpers ---


def _make_action() -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(name="test-tool"),
        parameters=ActionParameters(raw={}, parameter_hash="abc"),
        context=ActionContext(),
    )


def _make_config(**agent_overrides):
    agent = {"name": "test-agent"}
    agent.update(agent_overrides)
    return load_config(raw={"agent": agent})


def _make_store(total: int = 0, chain_valid: bool = True, errors: list[str] | None = None) -> MagicMock:
    store = MagicMock()
    store.count.return_value = total
    store.verify_chain.return_value = (chain_valid, errors or [])
    return store


# --- DE-04 Evidence Integrity ---


class TestDE04Integrity:
    def test_valid_chain_passes(self):
        store = _make_store(total=5, chain_valid=True)
        ev = DE04IntegrityEvaluator(evidence_store=store)
        result = ev.evaluate(_make_action(), _make_config())
        assert result.result == "PASS"
        assert result.control_id == "DE-04"
        assert result.evidence_data["chain_valid"] is True
        assert result.evidence_data["total_records"] == 5
        assert result.evidence_data["errors"] == []

    def test_empty_store_flags(self):
        store = _make_store(total=0, chain_valid=True)
        ev = DE04IntegrityEvaluator(evidence_store=store)
        result = ev.evaluate(_make_action(), _make_config())
        assert result.result == "FLAG"
        assert result.evidence_data["total_records"] == 0

    def test_broken_chain_fails(self):
        errors = ["Record abc123: hash mismatch. Expected aabbcc..., got 112233..."]
        store = _make_store(total=3, chain_valid=False, errors=errors)
        ev = DE04IntegrityEvaluator(evidence_store=store)
        result = ev.evaluate(_make_action(), _make_config())
        assert result.result == "FAIL"
        assert result.evidence_data["chain_valid"] is False
        assert len(result.evidence_data["errors"]) == 1

    def test_no_store_configured_flags(self):
        ev = DE04IntegrityEvaluator(evidence_store=None)
        result = ev.evaluate(_make_action(), _make_config())
        assert result.result == "FLAG"
        assert "No evidence store" in result.detail

    def test_evidence_structure(self):
        store = _make_store(total=2, chain_valid=True)
        ev = DE04IntegrityEvaluator(evidence_store=store)
        result = ev.evaluate(_make_action(), _make_config())
        assert "chain_valid" in result.evidence_data
        assert "total_records" in result.evidence_data
        assert "errors" in result.evidence_data
        assert result.duration_ms >= 0


# --- GOV-02 Agent Ownership ---


class TestGOV02Ownership:
    eval = GOV02OwnershipEvaluator()

    def test_owner_set_passes(self):
        config = _make_config(owner="alice@example.com")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "PASS"
        assert result.control_id == "GOV-02"
        assert result.evidence_data["owner_declared"] is True
        assert result.evidence_data["owner_value"] == "alice@example.com"

    def test_owner_placeholder_todo_flags(self):
        config = _make_config(owner="TODO")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FLAG"
        assert result.evidence_data["owner_declared"] is True

    def test_owner_placeholder_unknown_flags(self):
        config = _make_config(owner="unknown")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FLAG"

    def test_owner_placeholder_changeme_flags(self):
        config = _make_config(owner="changeme")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FLAG"

    def test_no_owner_fails(self):
        config = _make_config()  # no owner field → defaults to ""
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FAIL"
        assert result.evidence_data["owner_declared"] is False
        assert result.evidence_data["owner_value"] is None

    def test_evidence_structure(self):
        config = _make_config(owner="bob@corp.com")
        result = self.eval.evaluate(_make_action(), config)
        assert "owner_declared" in result.evidence_data
        assert "owner_value" in result.evidence_data
        assert "source_field" in result.evidence_data
        assert result.duration_ms >= 0

    def test_placeholder_case_insensitive(self):
        config = _make_config(owner="TBD")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FLAG"


# --- ID-01 Agent Inventory ---


class TestID01Inventory:
    eval = ID01InventoryEvaluator()

    def test_name_and_id_passes(self):
        config = _make_config(name="my-agent", agent_id="agt-1234")
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "PASS"
        assert result.control_id == "ID-01"
        assert result.evidence_data["inventory_status"] == "registered"
        assert result.evidence_data["fields"]["name"] == "my-agent"
        assert result.evidence_data["fields"]["id"] == "agt-1234"

    def test_name_only_flags(self):
        config = _make_config(name="my-agent")  # no agent_id
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FLAG"
        assert result.evidence_data["inventory_status"] == "partial"
        assert result.evidence_data["fields"]["id"] is None

    def test_neither_fails(self):
        # agent.name is required by schema, so we can't truly have neither.
        # Simulate by patching config directly.
        config = _make_config(name="placeholder")
        config.agent_name = ""  # override to simulate missing name
        result = self.eval.evaluate(_make_action(), config)
        assert result.result == "FAIL"
        assert result.evidence_data["inventory_status"] == "unregistered"

    def test_evidence_structure(self):
        config = _make_config(name="my-agent", agent_id="agt-001")
        result = self.eval.evaluate(_make_action(), config)
        assert "inventory_status" in result.evidence_data
        assert "fields" in result.evidence_data
        assert "name" in result.evidence_data["fields"]
        assert "id" in result.evidence_data["fields"]
        assert result.duration_ms >= 0
