"""ancilis.testing — test utilities for agent compliance testing.

Provides mocks, fixtures, assertion helpers, and pre-built scenarios so
developers can write unit tests for their agent code against compliance
requirements — without hitting the platform API or running a full scan.

Quick start::

    pip install ancilis[testing]

Usage in tests::

    from ancilis.testing import (
        MockEvidenceStore,
        FakeProducer,
        ComplianceScenarios,
        assert_control_passes,
        assert_control_fails,
        assert_posture_above,
    )

    def test_identity_control():
        store = MockEvidenceStore()
        scenario = ComplianceScenarios.financial_compliant()
        assert_control_passes(scenario, "PR-01")
        assert_posture_above(scenario, 0.80)

pytest fixtures (auto-registered via entry_points)::

    ancilis_scan     — ScanResult from a default evaluation
    ancilis_store    — MockEvidenceStore (in-memory, closed after test)
    ancilis_overlay  — active overlay name from pytest.ini
"""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ancilis.testing._helpers import make_action, make_test_config
    from ancilis.testing.assertions import (
        assert_control_fails,
        assert_control_flags,
        assert_control_passes,
        assert_decision_allows,
        assert_decision_blocks,
        assert_posture_above,
    )
    from ancilis.testing.fake_producer import FakeProducer
    from ancilis.testing.mock_store import MockEvidenceStore
    from ancilis.testing.scan_result import ScanResult
    from ancilis.testing.scenarios import ComplianceScenarios

_EXPORTS: dict[str, tuple[str, str]] = {
    "MockEvidenceStore": ("ancilis.testing.mock_store", "MockEvidenceStore"),
    "FakeProducer": ("ancilis.testing.fake_producer", "FakeProducer"),
    "ScanResult": ("ancilis.testing.scan_result", "ScanResult"),
    "ComplianceScenarios": ("ancilis.testing.scenarios", "ComplianceScenarios"),
    "assert_control_passes": ("ancilis.testing.assertions", "assert_control_passes"),
    "assert_control_fails": ("ancilis.testing.assertions", "assert_control_fails"),
    "assert_control_flags": ("ancilis.testing.assertions", "assert_control_flags"),
    "assert_posture_above": ("ancilis.testing.assertions", "assert_posture_above"),
    "assert_decision_allows": ("ancilis.testing.assertions", "assert_decision_allows"),
    "assert_decision_blocks": ("ancilis.testing.assertions", "assert_decision_blocks"),
    "make_action": ("ancilis.testing._helpers", "make_action"),
    "make_test_config": ("ancilis.testing._helpers", "make_test_config"),
}


def __getattr__(name: str) -> object:
    if name in _EXPORTS:
        module_name, attr_name = _EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_EXPORTS)
