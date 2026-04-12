"""DE-04: Evidence Integrity Verification evaluator."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult

if TYPE_CHECKING:
    from ancilis.evidence.store import EvidenceStore


class DE04IntegrityEvaluator:
    """Verifies cryptographic hash chain integrity of the evidence store.

    DE-04 wraps EvidenceStore.verify_chain() into the standard ControlResult interface.
    Requires an EvidenceStore reference — pass via constructor like DE-01/BaselineWindow.
    """

    control_id = "DE-04"
    control_name = "Evidence Integrity Verification"

    def __init__(self, evidence_store: EvidenceStore | None = None) -> None:
        self._store = evidence_store

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        evidence: dict[str, Any] = {
            "chain_valid": False,
            "total_records": 0,
            "errors": [],
        }

        if self._store is None:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail="No evidence store configured — cannot verify chain integrity.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        total = self._store.count()
        evidence["total_records"] = total

        if total == 0:
            evidence["chain_valid"] = True
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail="Evidence store is empty — no chain to verify.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        chain_valid, errors = self._store.verify_chain()
        evidence["chain_valid"] = chain_valid
        evidence["errors"] = errors

        if not chain_valid:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Evidence chain integrity failure — {len(errors)} error(s) detected.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Evidence chain integrity verified — {total} record(s), no tampering detected.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
