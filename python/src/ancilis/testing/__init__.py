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
from ancilis.testing._helpers import make_action, make_test_config

__all__ = [
    # Core utilities
    "MockEvidenceStore",
    "FakeProducer",
    "ScanResult",
    "ComplianceScenarios",
    # Assertion helpers
    "assert_control_passes",
    "assert_control_fails",
    "assert_control_flags",
    "assert_posture_above",
    "assert_decision_allows",
    "assert_decision_blocks",
    # Helpers
    "make_action",
    "make_test_config",
]
