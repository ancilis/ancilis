"""pytest plugin — provides ancilis_scan, ancilis_store, ancilis_overlay fixtures."""

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

import pytest

from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry
from ancilis.testing._helpers import make_action, make_test_config
from ancilis.testing.mock_store import MockEvidenceStore
from ancilis.testing.scan_result import ScanResult

if TYPE_CHECKING:
    pass


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register ancilis ini options."""
    parser.addini(
        "ancilis_overlay",
        help="Ancilis overlay to activate in tests (e.g. 'financial')",
        default=None,
    )
    parser.addini(
        "ancilis_agent_name",
        help="Agent name used in ancilis test config",
        default="test-agent",
    )
    parser.addini(
        "ancilis_mode",
        help="Ancilis security mode for tests: 'audit' or 'enforce'",
        default="audit",
    )


@pytest.fixture
def ancilis_overlay(request: pytest.FixtureRequest) -> str | None:
    """Pytest fixture: active overlay name from ini config or None.

    Configure in pytest.ini::

        [pytest]
        ancilis_overlay = financial
    """
    value = request.config.getini("ancilis_overlay")
    return value if value else None


@pytest.fixture
def ancilis_store(ancilis_overlay: str | None) -> Generator[MockEvidenceStore, None, None]:
    """Pytest fixture: provides an in-memory MockEvidenceStore.

    The store is closed and discarded after each test.

    Usage::

        def test_evidence_persisted(ancilis_store):
            ancilis_store.store(evaluation, tool_name="my_tool")
            assert ancilis_store.count() == 1
    """
    agent_name = "test-agent"
    store = MockEvidenceStore(agent_name=agent_name, overlay=ancilis_overlay)
    yield store
    store.close()


@pytest.fixture
def ancilis_scan(
    request: pytest.FixtureRequest,
    ancilis_overlay: str | None,
) -> ScanResult:
    """Pytest fixture: evaluates a default action and returns a ScanResult.

    The evaluation uses a minimal in-memory config (no ancilis.yaml required).
    The agent_name matches the configured name so PR-01 passes by default.

    Configure via ini options::

        [pytest]
        ancilis_agent_name = my-agent
        ancilis_mode = audit
        ancilis_overlay = financial

    Usage::

        from ancilis.testing import assert_control_passes, assert_posture_above

        def test_my_agent(ancilis_scan):
            assert_control_passes(ancilis_scan, "PR-01")
            assert_posture_above(ancilis_scan, 0.75)
            assert ancilis_scan.score > 0.75
    """
    agent_name = request.config.getini("ancilis_agent_name") or "test-agent"
    mode = request.config.getini("ancilis_mode") or "audit"

    config = make_test_config(agent_name=agent_name, mode=mode, overlay=ancilis_overlay)

    registry = ToolRegistry()
    registry.register(ToolEntry(name="test_tool"))
    registry.approve("test_tool", approved_by="pytest")

    engine = Engine(config, registry=registry)

    action = make_action(
        tool_name="test_tool",
        agent_id=agent_name,
    )
    evaluation = engine.evaluate(action)
    return ScanResult([evaluation])
