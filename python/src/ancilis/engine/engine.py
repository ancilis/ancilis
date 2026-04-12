"""Decision engine — orchestrates control evaluation."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from ancilis.config import ResolvedConfig, load_control_definitions
from ancilis.engine.action import Action
from ancilis.engine.evaluators.base import ControlEvaluator
from ancilis.engine.evaluators.pr01_identity import PR01IdentityEvaluator
from ancilis.engine.evaluators.pr02_scope import PR02ScopeEvaluator, RateTracker
from ancilis.engine.evaluators.pr03_provenance import PR03ProvenanceEvaluator
from ancilis.engine.evaluators.pr04_exposure import PR04ExposureEvaluator
from ancilis.engine.registry import ToolRegistry
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.controls.pr05_audit import PR05AuditEvaluator
from ancilis.controls.de01_baseline import DE01BaselineEvaluator, BaselineWindow
from ancilis.engine.evaluators.pr06_config_baseline import PR06ConfigBaselineEvaluator
from ancilis.engine.evaluators.pr07_transport import PR07TransportEvaluator
from ancilis.engine.evaluators.pr08_input import PR08InputEvaluator

# Controls that have evaluators
EVALUATOR_CONTROL_IDS = {"PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08", "DE-01"}


class Engine:
    """Control evaluation engine. Evaluates actions against active controls."""

    def __init__(
        self,
        config: ResolvedConfig,
        registry: ToolRegistry | None = None,
        rate_tracker: RateTracker | None = None,
        baseline_window: BaselineWindow | None = None,
    ) -> None:
        self.config = config
        self.registry = registry or ToolRegistry()
        self._control_defs = load_control_definitions()
        self._evaluators: dict[str, ControlEvaluator] = {
            "PR-01": PR01IdentityEvaluator(),
            "PR-02": PR02ScopeEvaluator(rate_tracker=rate_tracker),
            "PR-03": PR03ProvenanceEvaluator(registry=self.registry),
            "PR-04": PR04ExposureEvaluator(),
            "PR-05": PR05AuditEvaluator(),
            "PR-06": PR06ConfigBaselineEvaluator(),
            "PR-07": PR07TransportEvaluator(),
            "PR-08": PR08InputEvaluator(),
            "DE-01": DE01BaselineEvaluator(baseline_window=baseline_window),
        }

    def evaluate(self, action: Action) -> EvaluationResult:
        """Evaluate an action against all active controls."""
        start = time.perf_counter()
        control_results: list[ControlResult] = []

        for control_id, control_status in sorted(self.config.controls.items()):
            if not control_status.enabled:
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=control_status.name,
                        result="SKIP",
                        detail="Control is disabled.",
                        evidence_data={},
                        duration_ms=0.0,
                    )
                )
                continue

            evaluator = self._evaluators.get(control_id)
            if evaluator is None:
                # No evaluator for this control yet (PR-05, DE-01 are future units)
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=control_status.name,
                        result="SKIP",
                        detail="No evaluator implemented for this control.",
                        evidence_data={},
                        duration_ms=0.0,
                    )
                )
                continue

            try:
                result = evaluator.evaluate(action, self.config)
                control_results.append(result)
            except Exception as e:
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=control_status.name,
                        result="ERROR",
                        detail=f"Evaluator error: {e}",
                        evidence_data={"error": str(e)},
                        duration_ms=0.0,
                    )
                )

        # Post-process: fill display fields from control definitions
        for cr in control_results:
            cdef = self._control_defs.get(cr.control_id)
            if cdef and not cr.display_name:
                cr.display_name = cdef.get("display_name", cr.control_name)
                cr.display_detail = cdef.get("display_detail", "")
                cr.remediation_hint = cdef.get("remediation_hint_template", "")

        # Decision logic
        has_failure = any(r.result in ("FAIL", "ERROR") for r in control_results)

        if self.config.mode == "enforce" and has_failure:
            failed = [r.control_id for r in control_results if r.result in ("FAIL", "ERROR")]
            decision = "BLOCK"
            decision_reason = f"Blocked by: {', '.join(failed)}"
        else:
            decision = "ALLOW"
            if has_failure and self.config.mode == "audit":
                failed = [r.control_id for r in control_results if r.result in ("FAIL", "ERROR")]
                decision_reason = f"Audit mode — failures logged but allowed: {', '.join(failed)}"
            else:
                decision_reason = "All controls passed."

        total_ms = (time.perf_counter() - start) * 1000

        # Collect active overlay/classification info from config
        active_overlays = list(self.config.active_overlays.keys())
        data_classifications: list[str] = []
        for codes in self.config.data_classifications.values():
            for code in codes:
                if code not in data_classifications:
                    data_classifications.append(code)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action.action_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=action.agent_id,
            source_type=action.source_type,
            mode=self.config.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=active_overlays,
            data_classifications=data_classifications,
            total_duration_ms=total_ms,
            session_id=action.context.session_id,
        )
