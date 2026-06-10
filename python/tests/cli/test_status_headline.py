"""Regression tests for the honest status headline (audit findings F1, F3).

The one-line "Controls: N active, ..." headline must never report "all passing"
while any control is failing, flagged, or not actually evaluated (SKIP /
never-evaluated / never-attested), and must distinguish runtime-verified from
attestation-passing controls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ancilis.cli import status as status_mod


def _control(cid: str, name: str):
    c = MagicMock()
    c.control_id = cid
    c.name = name
    c.enabled = True
    return c


def _config(controls):
    cfg = MagicMock()
    cfg.agent_name = "test-agent"
    cfg.mode = "audit"
    cfg.controls = {c.control_id: c for c in controls}
    cfg.active_certifications = []
    cfg.active_overlays = {}
    return cfg


def _store(pass_rates, total):
    store = MagicMock()
    store.get_summary.return_value = {
        "total_evaluations": total,
        "decisions": {"ALLOW": total},
        "control_pass_rates": pass_rates,
    }
    sync = MagicMock(pending_count=0, failed_count=0, last_sync_at=None, last_error=None)
    store.get_sync_summary.return_value = sync
    return store


_CONTROL_DEFS = {
    "PR-04": {"display_name": "Data Exposure Prevention", "support_level": "runtime_evaluator"},
    "PR-01": {"display_name": "Identity", "support_level": "runtime_evaluator"},
    "GOV-04": {"display_name": "Governance Attestation", "support_level": "attestation"},
}


def _render(cfg, store):
    with patch.object(status_mod, "load_control_definitions", return_value=_CONTROL_DEFS):
        return status_mod._format_status(cfg, store, verbose=False)


def test_flag_never_reports_all_passing():
    cfg = _config([_control("PR-04", "Data Exposure"), _control("PR-01", "Identity")])
    store = _store(
        {
            "PR-04": {"FLAG": 1, "PASS": 2, "FAIL": 0, "ERROR": 0, "SKIP": 0},
            "PR-01": {"PASS": 3, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0},
        },
        total=3,
    )
    out = _render(cfg, store)
    assert "all passing" not in out
    assert "flagged" in out
    assert "runtime-verified" in out


def test_never_evaluated_control_is_pending_not_passing():
    cfg = _config([_control("PR-04", "Data Exposure"), _control("PR-01", "Identity")])
    # Only PR-01 evaluated (PASS); PR-04 has no records at all.
    store = _store({"PR-01": {"PASS": 2, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}}, total=2)
    out = _render(cfg, store)
    assert "all passing" not in out
    assert "pending" in out


def test_skip_only_attestation_is_pending_not_passing():
    cfg = _config([_control("PR-01", "Identity"), _control("GOV-04", "Gov Attestation")])
    store = _store(
        {
            "PR-01": {"PASS": 2, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0},
            "GOV-04": {"PASS": 0, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 2},
        },
        total=4,
    )
    out = _render(cfg, store)
    assert "all passing" not in out
    assert "pending" in out


def test_fresh_attestation_is_attestation_passing():
    cfg = _config([_control("GOV-04", "Gov Attestation")])
    store = _store({"GOV-04": {"PASS": 2, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}}, total=2)
    out = _render(cfg, store)
    assert "attestation-passing" in out


def test_all_runtime_pass_reads_all_passing():
    cfg = _config([_control("PR-04", "Data Exposure"), _control("PR-01", "Identity")])
    store = _store(
        {
            "PR-04": {"PASS": 2, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0},
            "PR-01": {"PASS": 2, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0},
        },
        total=4,
    )
    out = _render(cfg, store)
    assert "all passing" in out
    assert "2 runtime-verified" in out


def test_failing_control_reports_failing():
    cfg = _config([_control("PR-01", "Identity")])
    store = _store({"PR-01": {"PASS": 0, "FLAG": 0, "FAIL": 1, "ERROR": 0, "SKIP": 0}}, total=1)
    out = _render(cfg, store)
    assert "all passing" not in out
    assert "failing" in out


def test_verbose_skip_only_control_is_pending_not_passing():
    # A SKIP-only attestation control must render as pending in the verbose
    # per-control view, never "passing" (the F3 dishonesty must not survive
    # into --verbose either).
    cfg = _config([_control("GOV-04", "Gov Attestation"), _control("PR-04", "Data Exposure")])
    store = _store(
        {
            "GOV-04": {"PASS": 0, "FLAG": 0, "FAIL": 0, "ERROR": 0, "SKIP": 3},
            "PR-04": {"PASS": 0, "FLAG": 2, "FAIL": 0, "ERROR": 0, "SKIP": 0},
        },
        total=5,
    )
    with patch.object(status_mod, "load_control_definitions", return_value=_CONTROL_DEFS):
        out = status_mod._format_status(cfg, store, verbose=True)
    lines = out.splitlines()
    gov_line = next(ln for ln in lines if "Governance Attestation" in ln)
    pr04_line = next(ln for ln in lines if "Data Exposure Prevention" in ln)
    assert "pending" in gov_line and "passing" not in gov_line
    assert "flagged" in pr04_line and "passing" not in pr04_line
