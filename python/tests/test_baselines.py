"""Tests for ancilis baseline management and drift detection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from ancilis.baselines.drift import (
    DriftDetector,
    _classify_severity,
    _compute_control_stats,
    _dominant_result,
    _pass_rate,
)
from ancilis.baselines.manager import BaselineManager
from ancilis.baselines.models import (
    Baseline,
    ControlDrift,
    ControlSnapshot,
    DriftReport,
)
from ancilis.config import load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(agent_name: str = "test-agent") -> Any:
    return load_config(raw={"agent": {"name": agent_name}})


def make_store(config=None) -> EvidenceStore:
    if config is None:
        config = make_config()
    return EvidenceStore(config, in_memory=True)


def make_evaluation(
    control_id: str = "PR-01",
    control_name: str = "Agent Identity",
    result: str = "PASS",
    agent_id: str = "test-agent",
    decision: str = "ALLOW",
    active_overlays: list[str] | None = None,
    timestamp: str | None = None,
) -> EvaluationResult:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return EvaluationResult(
        evaluation_id="eval-001",
        action_id="action-001",
        timestamp=timestamp,
        agent_id=agent_id,
        mode="audit",
        control_results=[
            ControlResult(
                control_id=control_id,
                control_name=control_name,
                result=result,
                detail="test detail",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision=decision,
        decision_reason="test",
        active_overlays=active_overlays or [],
        data_classifications=[],
        total_duration_ms=2.0,
    )


def make_snapshot(
    control_id: str = "PR-01",
    result: str = "PASS",
    pass_rate: float = 1.0,
    total_evaluations: int = 10,
) -> ControlSnapshot:
    return ControlSnapshot(
        control_id=control_id,
        result=result,
        pass_rate=pass_rate,
        total_evaluations=total_evaluations,
        evidence_window_start="2025-01-01T00:00:00+00:00",
        evidence_window_end="2025-01-08T00:00:00+00:00",
    )


def make_baseline(snapshots: list[ControlSnapshot] | None = None) -> Baseline:
    return Baseline(
        baseline_id="baseline-001",
        created_at="2025-01-01T00:00:00+00:00",
        agent_id="test-agent",
        label="test-baseline",
        control_snapshots=snapshots or [make_snapshot()],
        overlay_id=None,
        metadata=None,
        is_active=True,
    )


# ---------------------------------------------------------------------------
# Unit: _compute_control_stats
# ---------------------------------------------------------------------------


class TestComputeControlStats:
    def test_empty_rows(self):
        assert _compute_control_stats([]) == {}

    def test_single_pass(self):
        rows = [('[ {"control_id": "PR-01", "control_name": "Identity", "result": "PASS"} ]',)]
        stats = _compute_control_stats(rows)
        assert "PR-01" in stats
        assert stats["PR-01"]["pass"] == 1
        assert stats["PR-01"]["total"] == 1

    def test_mixed_results_aggregated(self):
        rows = [
            ('[ {"control_id": "PR-01", "control_name": "ID", "result": "PASS"} ]',),
            ('[ {"control_id": "PR-01", "control_name": "ID", "result": "FAIL"} ]',),
            ('[ {"control_id": "PR-01", "control_name": "ID", "result": "PASS"} ]',),
        ]
        stats = _compute_control_stats(rows)
        assert stats["PR-01"]["pass"] == 2
        assert stats["PR-01"]["fail"] == 1
        assert stats["PR-01"]["total"] == 3

    def test_multiple_controls_in_one_row(self):
        rows = [
            ('[ {"control_id": "PR-01", "control_name": "ID", "result": "PASS"},'
             '  {"control_id": "DE-01", "control_name": "Data", "result": "FAIL"} ]',),
        ]
        stats = _compute_control_stats(rows)
        assert "PR-01" in stats
        assert "DE-01" in stats
        assert stats["PR-01"]["pass"] == 1
        assert stats["DE-01"]["fail"] == 1


# ---------------------------------------------------------------------------
# Unit: _pass_rate and _dominant_result
# ---------------------------------------------------------------------------


class TestPassRateAndDominantResult:
    def test_pass_rate_all_pass(self):
        stats = {"pass": 10, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 10}
        assert _pass_rate(stats) == 1.0

    def test_pass_rate_half(self):
        stats = {"pass": 5, "fail": 5, "flag": 0, "skip": 0, "error": 0, "total": 10}
        assert _pass_rate(stats) == 0.5

    def test_pass_rate_zero_total(self):
        stats = {"pass": 0, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 0}
        assert _pass_rate(stats) == 1.0

    def test_dominant_result_all_same(self):
        stats = {"pass": 5, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 5}
        assert _dominant_result(stats) == "PASS"

    def test_dominant_result_mixed_picks_highest(self):
        stats = {"pass": 3, "fail": 7, "flag": 0, "skip": 0, "error": 0, "total": 10}
        assert _dominant_result(stats) == "FAIL"

    def test_dominant_result_zero_total(self):
        stats = {"pass": 0, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 0}
        assert _dominant_result(stats) == "SKIP"


# ---------------------------------------------------------------------------
# Unit: _classify_severity — all four levels
# ---------------------------------------------------------------------------


class TestClassifySeverity:
    def _snap(self, result: str, pass_rate: float) -> ControlSnapshot:
        return ControlSnapshot(
            control_id="PR-01",
            result=result,
            pass_rate=pass_rate,
            total_evaluations=10,
            evidence_window_start="",
            evidence_window_end="",
        )

    def test_pass_to_fail_is_high(self):
        # Use sub-100% baseline so CRITICAL path doesn't fire; PASS→FAIL is HIGH
        snap = self._snap("PASS", 0.9)
        assert _classify_severity(snap, 0.0, "FAIL") == "HIGH"

    def test_pass_to_flag_is_high(self):
        # Use sub-100% baseline so CRITICAL path doesn't fire; PASS→FLAG is HIGH
        snap = self._snap("PASS", 0.9)
        assert _classify_severity(snap, 0.5, "FLAG") == "HIGH"

    def test_perfect_baseline_degraded_to_fail_is_critical(self):
        snap = self._snap("PASS", 1.0)
        # pass_rate drops but baseline was 100% — triggers CRITICAL
        assert _classify_severity(snap, 0.8, "FAIL") == "CRITICAL"

    def test_major_degradation_is_medium(self):
        snap = self._snap("PASS", 0.9)
        # drop of 0.21 >= MAJOR threshold (0.20) — MEDIUM
        assert _classify_severity(snap, 0.69, "PASS") == "MEDIUM"

    def test_minor_degradation_is_low(self):
        snap = self._snap("PASS", 0.9)
        # drop of 0.15 >= DEGRADATION threshold (0.10) — LOW
        assert _classify_severity(snap, 0.75, "PASS") == "LOW"

    def test_no_degradation_returns_none(self):
        snap = self._snap("PASS", 0.8)
        assert _classify_severity(snap, 0.9, "PASS") is None

    def test_improvement_returns_none(self):
        snap = self._snap("PASS", 0.5)
        assert _classify_severity(snap, 1.0, "PASS") is None


# ---------------------------------------------------------------------------
# Unit: DriftDetector.detect()
# ---------------------------------------------------------------------------


class TestDriftDetector:
    def test_stable_when_all_pass(self):
        baseline = make_baseline([make_snapshot("PR-01", "PASS", 1.0, 5)])
        current_stats = {
            "PR-01": {"control_name": "ID", "pass": 5, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 5}
        }
        report = DriftDetector().detect(baseline, current_stats, {})
        assert report.overall_status == "STABLE"
        assert report.control_drifts == []

    def test_pass_to_fail_detected(self):
        baseline = make_baseline([make_snapshot("PR-01", "PASS", 1.0, 5)])
        current_stats = {
            "PR-01": {"control_name": "ID", "pass": 0, "fail": 5, "flag": 0, "skip": 0, "error": 0, "total": 5}
        }
        report = DriftDetector().detect(baseline, current_stats, {"PR-01": "2025-01-09T00:00:00"})
        assert report.overall_status == "DRIFTED"
        assert len(report.control_drifts) == 1
        drift = report.control_drifts[0]
        assert drift.control_id == "PR-01"
        assert drift.severity in ("HIGH", "CRITICAL")

    def test_missing_control_that_was_passing(self):
        baseline = make_baseline([make_snapshot("PR-01", "PASS", 1.0, 5)])
        report = DriftDetector().detect(baseline, {}, {})
        assert report.overall_status == "DRIFTED"
        assert report.control_drifts[0].current_result == "SKIP"
        assert report.control_drifts[0].severity == "HIGH"

    def test_missing_control_that_was_skipping(self):
        baseline = make_baseline([make_snapshot("PR-01", "SKIP", 0.0, 0)])
        report = DriftDetector().detect(baseline, {}, {})
        # SKIP with pass_rate=0 — not a regression
        assert report.overall_status == "STABLE"

    def test_multiple_drifts_summary_shows_top_severity(self):
        baseline = make_baseline([
            make_snapshot("PR-01", "PASS", 1.0, 10),
            make_snapshot("PR-02", "PASS", 0.9, 10),
        ])
        current_stats = {
            "PR-01": {"control_name": "ID", "pass": 0, "fail": 10, "flag": 0, "skip": 0, "error": 0, "total": 10},
            "PR-02": {"control_name": "DE", "pass": 8, "fail": 2, "flag": 0, "skip": 0, "error": 0, "total": 10},
        }
        report = DriftDetector().detect(baseline, current_stats, {})
        assert report.overall_status == "DRIFTED"
        assert "CRITICAL" in report.summary or "HIGH" in report.summary

    def test_report_fields_populated(self):
        baseline = make_baseline()
        current_stats = {
            "PR-01": {"control_name": "ID", "pass": 10, "fail": 0, "flag": 0, "skip": 0, "error": 0, "total": 10}
        }
        report = DriftDetector().detect(baseline, current_stats, {}, checked_at="2025-01-10T00:00:00+00:00")
        assert report.baseline_id == "baseline-001"
        assert report.baseline_label == "test-baseline"
        assert report.checked_at == "2025-01-10T00:00:00+00:00"
        assert report.agent_id == "test-agent"
        assert report.drift_report_id  # non-empty UUID


# ---------------------------------------------------------------------------
# Integration: BaselineManager via in-memory EvidenceStore
# ---------------------------------------------------------------------------


class TestBaselineManager:
    def _make_mgr(self, agent_name: str = "test-agent"):
        cfg = make_config(agent_name)
        store = make_store(cfg)
        mgr = BaselineManager(evidence_store=store, config=cfg)
        return mgr, store

    def _store_eval(self, store: EvidenceStore, result: str = "PASS", control_id: str = "PR-01"):
        eval_ = make_evaluation(control_id=control_id, result=result)
        store.store(eval_, tool_name="test_tool")

    # --- create ---

    def test_create_with_no_evidence(self):
        mgr, store = self._make_mgr()
        b = mgr.create(label="empty-baseline")
        assert b.label == "empty-baseline"
        assert b.is_active is True
        assert b.control_snapshots == []
        store.close()

    def test_create_snapshots_evidence(self):
        mgr, store = self._make_mgr()
        self._store_eval(store, "PASS", "PR-01")
        self._store_eval(store, "PASS", "PR-01")
        self._store_eval(store, "FAIL", "PR-01")
        b = mgr.create(label="v1")
        assert len(b.control_snapshots) == 1
        snap = b.control_snapshots[0]
        assert snap.control_id == "PR-01"
        assert snap.pass_rate == pytest.approx(2 / 3, rel=1e-3)
        store.close()

    def test_create_deactivates_previous_baseline(self):
        mgr, store = self._make_mgr()
        b1 = mgr.create(label="first")
        b2 = mgr.create(label="second")
        assert b1.is_active is True  # local object unchanged
        # Fetch from DB to verify deactivation
        refreshed_b1 = mgr.get_baseline(b1.baseline_id)
        assert refreshed_b1.is_active is False
        assert b2.is_active is True
        store.close()

    def test_create_with_metadata(self):
        mgr, store = self._make_mgr()
        b = mgr.create(label="meta-baseline", metadata={"version": "1.0", "env": "prod"})
        assert b.metadata == {"version": "1.0", "env": "prod"}
        store.close()

    # --- list and get ---

    def test_list_empty(self):
        mgr, store = self._make_mgr()
        assert mgr.list_baselines() == []
        store.close()

    def test_list_returns_all(self):
        mgr, store = self._make_mgr()
        mgr.create(label="a")
        mgr.create(label="b")
        mgr.create(label="c")
        baselines = mgr.list_baselines()
        assert len(baselines) == 3
        store.close()

    def test_get_baseline_found(self):
        mgr, store = self._make_mgr()
        created = mgr.create(label="get-test")
        fetched = mgr.get_baseline(created.baseline_id)
        assert fetched.baseline_id == created.baseline_id
        assert fetched.label == "get-test"
        store.close()

    def test_get_baseline_not_found(self):
        mgr, store = self._make_mgr()
        with pytest.raises(KeyError):
            mgr.get_baseline("nonexistent-id")
        store.close()

    # --- deactivate ---

    def test_deactivate(self):
        mgr, store = self._make_mgr()
        b = mgr.create(label="to-deactivate")
        mgr.deactivate(b.baseline_id)
        refreshed = mgr.get_baseline(b.baseline_id)
        assert refreshed.is_active is False
        store.close()

    # --- check_drift ---

    def test_check_drift_stable(self):
        mgr, store = self._make_mgr()
        self._store_eval(store, "PASS", "PR-01")
        mgr.create(label="stable-v1")
        self._store_eval(store, "PASS", "PR-01")
        report = mgr.check_drift()
        assert report.overall_status == "STABLE"
        store.close()

    def test_check_drift_detects_regression(self):
        mgr, store = self._make_mgr()
        # Baseline: PR-01 passing 100%
        self._store_eval(store, "PASS", "PR-01")
        self._store_eval(store, "PASS", "PR-01")
        mgr.create(label="pre-regression")
        # After baseline: PR-01 starts failing
        self._store_eval(store, "FAIL", "PR-01")
        self._store_eval(store, "FAIL", "PR-01")
        report = mgr.check_drift()
        assert report.overall_status == "DRIFTED"
        assert any(d.control_id == "PR-01" for d in report.control_drifts)
        store.close()

    def test_check_drift_no_baseline_raises(self):
        mgr, store = self._make_mgr()
        with pytest.raises(KeyError, match="No active baseline"):
            mgr.check_drift()
        store.close()

    def test_check_drift_by_baseline_id(self):
        mgr, store = self._make_mgr()
        self._store_eval(store, "PASS", "PR-01")
        b = mgr.create(label="explicit-id")
        self._store_eval(store, "FAIL", "PR-01")
        report = mgr.check_drift(baseline_id=b.baseline_id)
        assert report.baseline_id == b.baseline_id
        store.close()

    # --- overlay scoping ---

    def test_overlay_scoped_baselines_are_independent(self):
        mgr, store = self._make_mgr()
        b_glba = mgr.create(label="glba-baseline", overlay_id="financial")
        b_none = mgr.create(label="no-overlay-baseline", overlay_id=None)
        # Both should be active independently
        r_glba = mgr.get_baseline(b_glba.baseline_id)
        r_none = mgr.get_baseline(b_none.baseline_id)
        assert r_glba.is_active is True
        assert r_none.is_active is True
        store.close()

    def test_overlay_alias_is_canonicalized_for_baseline_api(self):
        mgr, store = self._make_mgr()
        store.store(
            make_evaluation(active_overlays=["nist-csf"]),
            tool_name="test_tool",
        )

        baseline = mgr.create(label="nist-baseline", overlay_id="nist-csf-2")

        assert baseline.overlay_id == "nist-csf"
        assert len(baseline.control_snapshots) == 1
        assert len(mgr.list_baselines(overlay_id="nist-csf-2")) == 1
        report = mgr.check_drift(overlay_id="nist-csf-2")
        assert report.baseline_id == baseline.baseline_id
        assert report.overlay_id == "nist-csf"
        store.close()


# ---------------------------------------------------------------------------
# Integration: on_drift callback
# ---------------------------------------------------------------------------


class TestOnDriftCallback:
    def test_callback_not_fired_without_baseline(self):
        cfg = make_config()
        fired = []
        store = EvidenceStore(cfg, in_memory=True, on_drift=lambda r: fired.append(r))
        eval_ = make_evaluation()
        store.store(eval_, tool_name="test")
        assert fired == []
        store.close()

    def test_callback_fired_when_active_baseline_exists(self):
        cfg = make_config()
        fired = []
        store = EvidenceStore(cfg, in_memory=True, on_drift=lambda r: fired.append(r))

        # Seed evidence and create baseline via manager
        mgr = BaselineManager(evidence_store=store, config=cfg)
        eval_pass = make_evaluation(result="PASS")
        store.store(eval_pass, tool_name="test")
        mgr.create(label="callback-test")

        # Store a failing record — should trigger callback
        eval_fail = make_evaluation(result="FAIL")
        store.store(eval_fail, tool_name="test")

        assert len(fired) >= 1
        assert isinstance(fired[0], DriftReport)
        store.close()

    def test_callback_not_fired_when_none(self):
        cfg = make_config()
        store = EvidenceStore(cfg, in_memory=True, on_drift=None)
        mgr = BaselineManager(evidence_store=store, config=cfg)
        store.store(make_evaluation("PR-01", result="PASS"), tool_name="test")
        mgr.create(label="no-callback")
        store.store(make_evaluation("PR-01", result="FAIL"), tool_name="test")
        # Should not raise
        store.close()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_baseline_stores_and_retrieves_empty_snapshots(self):
        cfg = make_config()
        store = make_store(cfg)
        mgr = BaselineManager(evidence_store=store, config=cfg)
        b = mgr.create(label="empty")
        fetched = mgr.get_baseline(b.baseline_id)
        assert fetched.control_snapshots == []
        store.close()

    def test_baseline_metadata_roundtrip(self):
        cfg = make_config()
        store = make_store(cfg)
        mgr = BaselineManager(evidence_store=store, config=cfg)
        meta = {"env": "staging", "version": 42, "tags": ["a", "b"]}
        b = mgr.create(label="meta-test", metadata=meta)
        fetched = mgr.get_baseline(b.baseline_id)
        assert fetched.metadata == meta
        store.close()

    def test_drift_report_is_stable_with_no_current_evidence(self):
        cfg = make_config()
        store = make_store(cfg)
        mgr = BaselineManager(evidence_store=store, config=cfg)
        # Create baseline with no evidence (no snapshots)
        mgr.create(label="empty-baseline")
        # check_drift against empty evidence = STABLE (nothing to compare)
        report = mgr.check_drift()
        assert report.overall_status == "STABLE"
        store.close()

    def test_control_drift_evidence_delta(self):
        baseline = make_baseline([make_snapshot("PR-01", "PASS", 1.0, 5)])
        current_stats = {
            "PR-01": {"control_name": "ID", "pass": 0, "fail": 10, "flag": 0, "skip": 0, "error": 0, "total": 10}
        }
        report = DriftDetector().detect(baseline, current_stats, {})
        assert report.control_drifts[0].evidence_delta == 5  # 10 - 5
