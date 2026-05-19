"""Decision engine — orchestrates control evaluation."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Protocol

from ancilis.aksi.version import AKSI_FRAMEWORK_VERSION
from ancilis.config import ResolvedConfig, load_control_definitions
from ancilis.controls.custom import CustomControlEvaluator
from ancilis.engine.action import Action
from ancilis.engine.evaluators.de02_classification_drift import DE02ClassificationDriftEvaluator
from ancilis.engine.evaluators.de03_config_drift import DE03ConfigDriftEvaluator
from ancilis.engine.evaluators.de04_integrity import DE04IntegrityEvaluator
from ancilis.engine.evaluators.base import ControlEvaluator
from ancilis.engine.evaluators.gov01_identity_auth import GOV01IdentityAuthEvaluator
from ancilis.engine.evaluators.gov02_ownership import GOV02OwnershipEvaluator
from ancilis.engine.evaluators.gov03_risk_tolerance import GOV03RiskToleranceEvaluator
from ancilis.engine.evaluators.id01_inventory import ID01InventoryEvaluator
from ancilis.engine.evaluators.pr01_action_auth import PR01ActionAuthorizationEvaluator
from ancilis.engine.evaluators.pr02_scope import PR02ScopeEvaluator, RateTracker
from ancilis.engine.evaluators.pr03_provenance import PR03ProvenanceEvaluator
from ancilis.engine.evaluators.pr04_exposure import PR04ExposureEvaluator
from ancilis.engine.evaluators.pr05_isolation import PR05IsolationEvaluator
from ancilis.engine.registry import ToolRegistry
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.controls.de01_baseline import DE01BaselineEvaluator, BaselineWindow
from ancilis.engine.evaluators.pr06_audit_trail import PR06AuditTrailEvaluator
from ancilis.engine.evaluators.pr07_transport import PR07TransportEvaluator
from ancilis.engine.evaluators.pr08_input import PR08InputEvaluator

# Controls that have evaluators
EVALUATOR_CONTROL_IDS = {
    "DE-01",
    "DE-02",
    "DE-03",
    "DE-04",
    "GOV-01",
    "GOV-02",
    "GOV-03",
    "ID-01",
    "PR-01",
    "PR-02",
    "PR-03",
    "PR-04",
    "PR-05",
    "PR-06",
    "PR-07",
    "PR-08",
}

POLICY_SENSITIVE_EVALUATOR_CONTROL_IDS = {
    "DE-04",
    "GOV-01",
    "GOV-02",
    "GOV-03",
    "ID-01",
}
RUNTIME_POLICY_GATE_SOURCES = (
    "explicit:security.controls",
    "certification_targets:",
)
POST_EVALUATION_CONTROL_IDS = {"PR-06"}

# Maps PR-04 pattern types to data classification DC codes
PATTERN_TO_DC: dict[str, str] = {
    "ssn": "DC-PII",
    "email": "DC-PII",
    "phone": "DC-PII",
    "credit_card": "DC-CHD",
    "mrn": "DC-PHI",
    "api_key": "DC-IP",
}


class EvidenceIntegrityStore(Protocol):
    def count(self) -> int: ...

    def verify_chain(self) -> tuple[bool, list[str]]: ...


class Engine:
    """Control evaluation engine. Evaluates actions against active controls."""

    def __init__(
        self,
        config: ResolvedConfig,
        registry: ToolRegistry | None = None,
        rate_tracker: RateTracker | None = None,
        baseline_window: BaselineWindow | None = None,
        evidence_store: EvidenceIntegrityStore | None = None,
    ) -> None:
        self.config = config
        self.registry = registry or ToolRegistry()
        self._evidence_store = evidence_store
        self._control_defs = load_control_definitions()
        self._evaluators: dict[str, ControlEvaluator] = {
            "GOV-01": GOV01IdentityAuthEvaluator(),
            "GOV-03": GOV03RiskToleranceEvaluator(),
            "ID-01": ID01InventoryEvaluator(),
            "PR-01": PR01ActionAuthorizationEvaluator(),
            "PR-02": PR02ScopeEvaluator(rate_tracker=rate_tracker),
            "PR-03": PR03ProvenanceEvaluator(registry=self.registry),
            "PR-04": PR04ExposureEvaluator(),
            "PR-05": PR05IsolationEvaluator(),
            "PR-06": PR06AuditTrailEvaluator(),
            "PR-07": PR07TransportEvaluator(),
            "PR-08": PR08InputEvaluator(),
            "DE-01": DE01BaselineEvaluator(baseline_window=baseline_window),
            "DE-02": DE02ClassificationDriftEvaluator(),
            "DE-03": DE03ConfigDriftEvaluator(),
            "DE-04": DE04IntegrityEvaluator(evidence_store=evidence_store),
            "GOV-02": GOV02OwnershipEvaluator(),
        }
        for control_id, definition in getattr(self.config, "custom_controls", {}).items():
            self._evaluators[control_id] = CustomControlEvaluator(definition)

    def evaluate(self, action: Action) -> EvaluationResult:
        """Evaluate an action against all active controls."""
        start = time.perf_counter()
        control_results: list[ControlResult] = []
        post_controls: list[tuple[str, object]] = []

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

            if control_id in POST_EVALUATION_CONTROL_IDS:
                post_controls.append((control_id, control_status))
                continue

            if self._is_policy_gated(control_id):
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=control_status.name,
                        result="SKIP",
                        detail=(
                            "Control is not runtime-active under the explicit/certification "
                            "policy gate."
                        ),
                        evidence_data={
                            "activation_sources": sorted(
                                self.config.control_activation_sources.get(control_id, set())
                            ),
                            "required_activation_sources": list(RUNTIME_POLICY_GATE_SOURCES),
                        },
                        duration_ms=0.0,
                    )
                )
                continue

            evaluator = self._evaluators.get(control_id)
            if evaluator is None:
                # No runtime evaluator is active for this control yet.
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

        for control_id, control_status in post_controls:
            if self._is_policy_gated(control_id):
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=control_status.name,
                        result="SKIP",
                        detail=(
                            "Control is not runtime-active under the explicit/certification "
                            "policy gate."
                        ),
                        evidence_data={
                            "activation_sources": sorted(
                                self.config.control_activation_sources.get(control_id, set())
                            ),
                            "required_activation_sources": list(RUNTIME_POLICY_GATE_SOURCES),
                        },
                        duration_ms=0.0,
                    )
                )
                continue

            evaluator = self._evaluators.get(control_id)
            if evaluator is None:
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
                evaluate_with_context = getattr(evaluator, "evaluate")
                result = evaluate_with_context(
                    action,
                    self.config,
                    prior_results=control_results,
                    evidence_store=self._evidence_store,
                )
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

        # Extract detected DC codes from PR-04 pattern scan results
        detected_data_types: list[str] = []
        for cr in control_results:
            if cr.control_id == "PR-04":
                for pattern in cr.evidence_data.get("patterns_detected", []):
                    dc_code = PATTERN_TO_DC.get(pattern.get("type", ""))
                    if dc_code and dc_code not in detected_data_types:
                        detected_data_types.append(dc_code)
                break

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action.action_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=action.agent_id,
            source_type=action.source_type,
            framework_version=getattr(action, "framework_version", None) or AKSI_FRAMEWORK_VERSION,
            mode=self.config.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=active_overlays,
            data_classifications=data_classifications,
            detected_data_types=detected_data_types,
            total_duration_ms=total_ms,
            session_id=action.context.session_id,
        )

    def _is_policy_gated(self, control_id: str) -> bool:
        if control_id not in POLICY_SENSITIVE_EVALUATOR_CONTROL_IDS:
            return False
        return not self.config.control_has_activation_source(
            control_id,
            *RUNTIME_POLICY_GATE_SOURCES,
        )
