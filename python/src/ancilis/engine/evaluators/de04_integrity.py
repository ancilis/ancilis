"""DE-04: Evidence Integrity Verification evaluator."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult

if TYPE_CHECKING:
    from ancilis.engine.engine import EvidenceIntegrityStore


class DE04IntegrityEvaluator:
    """Verifies cryptographic hash chain integrity of the evidence store.

    DE-04 wraps EvidenceStore.verify_chain() into the standard ControlResult interface.
    Requires an EvidenceStore reference — pass via constructor like DE-01/BaselineWindow.
    """

    control_id = "DE-04"
    control_name = "Evidence Integrity Verification"

    def __init__(self, evidence_store: EvidenceIntegrityStore | None = None) -> None:
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

        # Prefer the structured report so legacy (v1) records are surfaced as
        # legacy-unverified rather than silently passed. Fall back to the basic
        # tuple contract for stores that don't expose a real report (e.g. mocks).
        from ancilis.evidence.store import ChainVerificationReport

        report = None
        get_report = getattr(self._store, "verify_chain_report", None)
        candidate = get_report() if callable(get_report) else None
        if isinstance(candidate, ChainVerificationReport):
            report = candidate
            chain_valid, errors = report.valid, report.errors
        else:
            chain_valid, errors = self._store.verify_chain()
        evidence["chain_valid"] = chain_valid
        evidence["errors"] = errors
        if report is not None:
            evidence["chain_status"] = report.status
            evidence["verified"] = report.verified_count
            evidence["legacy_unverified"] = report.legacy_unverified_count

        if not chain_valid:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Evidence chain integrity failure — {len(errors)} error(s) detected.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if report is not None and report.legacy_unverified_count:
            if report.verified_count:
                detail = (
                    f"Mixed chain: {report.verified_count} record(s) HMAC-verified, "
                    f"{report.legacy_unverified_count} legacy (v1) record(s) intact but not "
                    f"cryptographically attestable. Set ANCILIS_CHAIN_KEY to key new writes."
                )
            else:
                detail = (
                    f"{report.legacy_unverified_count} legacy (v1) record(s) are intact but "
                    f"not cryptographically attestable without a protected key. Set "
                    f"ANCILIS_CHAIN_KEY to enable keyed (HMAC) integrity verification."
                )
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=detail,
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        verified_note = (
            f"{total} record(s) HMAC-verified, no tampering detected."
            if report is not None
            else f"{total} record(s), no tampering detected."
        )
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Evidence chain integrity verified — {verified_note}",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
