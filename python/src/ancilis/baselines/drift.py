from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ancilis.baselines.models import Baseline, ControlDrift, ControlSnapshot, DriftReport

# Severity thresholds
DEGRADATION_THRESHOLD = 0.10
MAJOR_DEGRADATION_THRESHOLD = 0.20


def _compute_control_stats(
    control_results_rows: list[tuple[Any, ...]],
) -> dict[str, dict[str, Any]]:
    """Aggregate pass rates per control_id from raw DB rows."""
    stats: dict[str, dict[str, Any]] = {}
    for (cr_json,) in control_results_rows:
        results = json.loads(cr_json) if isinstance(cr_json, str) else cr_json
        for cr in results:
            cid = cr["control_id"]
            if cid not in stats:
                stats[cid] = {
                    "control_name": cr.get("control_name", cid),
                    "pass": 0,
                    "fail": 0,
                    "flag": 0,
                    "skip": 0,
                    "error": 0,
                    "total": 0,
                    "first_failure_at": None,
                }
            result = cr.get("result", "SKIP").upper()
            key = result.lower() if result.lower() in stats[cid] else "skip"
            stats[cid][key] += 1
            stats[cid]["total"] += 1
    return stats


def _pass_rate(stats: dict[str, Any]) -> float:
    # SKIP means "no evaluator ran", not "passed" — rate only evaluated results.
    evaluated = stats["total"] - stats.get("skip", 0)
    if evaluated == 0:
        return 1.0
    return float(stats["pass"]) / float(evaluated)


def _dominant_result(stats: dict[str, Any]) -> str:
    total = stats["total"]
    if total == 0:
        return "SKIP"
    for key in ("pass", "fail", "flag", "error", "skip"):
        if stats[key] == total:
            return key.upper()
    # Mixed — pick whichever is most common
    best = max(("pass", "fail", "flag", "error", "skip"), key=lambda k: stats[k])
    return best.upper()


def _classify_severity(
    baseline_snapshot: ControlSnapshot,
    current_pass_rate: float,
    current_result: str,
) -> str | None:
    """Return severity string, or None if no drift detected."""
    b_result = baseline_snapshot.result.upper()
    c_result = current_result.upper()
    b_rate = baseline_snapshot.pass_rate

    drop = b_rate - current_pass_rate
    if drop <= 0:
        return None  # improved or unchanged

    # 100% pass rate that now fails/flags is CRITICAL (check before HIGH)
    if b_rate >= 1.0 and current_pass_rate < 1.0 and c_result in ("FAIL", "FLAG"):
        return "CRITICAL"

    # PASS → FAIL or PASS → FLAG is HIGH
    if b_result == "PASS" and c_result in ("FAIL", "FLAG"):
        return "HIGH"

    if drop >= MAJOR_DEGRADATION_THRESHOLD:
        return "MEDIUM"

    if drop >= DEGRADATION_THRESHOLD:
        return "LOW"

    return None


class DriftDetector:
    """Deterministic, threshold-based drift comparison."""

    def detect(
        self,
        baseline: Baseline,
        current_stats: dict[str, dict[str, Any]],
        current_first_failures: dict[str, str | None],
        checked_at: str | None = None,
    ) -> DriftReport:
        """Compare baseline snapshots against current stats and emit a DriftReport."""
        if checked_at is None:
            checked_at = datetime.now(timezone.utc).isoformat()

        drifts: list[ControlDrift] = []

        for snap in baseline.control_snapshots:
            cid = snap.control_id
            if cid not in current_stats:
                # Control disappeared — treat as drift if it was passing
                if snap.result == "PASS" and snap.pass_rate > 0:
                    drifts.append(
                        ControlDrift(
                            control_id=cid,
                            control_name=cid,
                            baseline_result=snap.result,
                            baseline_pass_rate=snap.pass_rate,
                            current_result="SKIP",
                            current_pass_rate=0.0,
                            severity="HIGH",
                            first_failure_at=None,
                            failure_count=0,
                            evidence_delta=-snap.total_evaluations,
                        )
                    )
                continue

            cur = current_stats[cid]
            c_rate = _pass_rate(cur)
            c_result = _dominant_result(cur)

            severity = _classify_severity(snap, c_rate, c_result)
            if severity is None:
                continue

            drifts.append(
                ControlDrift(
                    control_id=cid,
                    control_name=cur.get("control_name", cid),
                    baseline_result=snap.result,
                    baseline_pass_rate=snap.pass_rate,
                    current_result=c_result,
                    current_pass_rate=c_rate,
                    severity=severity,
                    first_failure_at=current_first_failures.get(cid),
                    failure_count=cur.get("fail", 0),
                    evidence_delta=cur["total"] - snap.total_evaluations,
                )
            )

        overall = "DRIFTED" if drifts else "STABLE"
        if drifts:
            severities = [d.severity for d in drifts]
            top = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in severities), "LOW")
            summary = f"{len(drifts)} control(s) drifted; top severity: {top}"
        else:
            summary = "All controls stable"

        return DriftReport(
            drift_report_id=str(uuid.uuid4()),
            baseline_id=baseline.baseline_id,
            baseline_label=baseline.label,
            checked_at=checked_at,
            agent_id=baseline.agent_id,
            overlay_id=baseline.overlay_id,
            overall_status=overall,
            summary=summary,
            control_drifts=drifts,
        )
