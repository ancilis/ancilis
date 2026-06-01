"""DE-03: Configuration/Dependency Drift Monitoring evaluator."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class DE03ConfigDriftEvaluator:
    """Establishes and monitors configuration baselines for agent tools.

    On first evaluation for a given tool, records the tool's configuration hash
    as the baseline and returns PASS (baseline established). On subsequent
    evaluations, compares against the stored baseline — PASS if unchanged,
    FAIL if drift is detected.
    """

    control_id = "DE-03"
    control_name = "Configuration/Dependency Drift Monitoring"

    def __init__(self) -> None:
        # In-memory baseline store: tool_name -> baseline_hash
        self._baselines: dict[str, str] = {}

    def _compute_hash(self, action: Action) -> str | None:
        """Compute a config hash from tool description_hash.

        Returns None if description_hash is not available — the evaluator
        skips rather than building an unreliable baseline from the tool name
        alone (which cannot detect semantic supply-chain changes).
        """
        tool = action.tool
        if not tool or not tool.description_hash:
            return None

        raw = ":".join([tool.name, tool.description_hash, tool.version or "", tool.server or ""])
        return hashlib.sha256(raw.encode()).hexdigest()

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        tool = action.tool
        if not tool or not tool.name:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail="No tool information available — cannot establish configuration baseline.",
                evidence_data={"tool_name": None, "baseline_established": False},
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        tool_name = tool.name
        current_hash = self._compute_hash(action)

        if current_hash is None:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail=f"Cannot compute configuration hash for tool '{tool_name}'.",
                evidence_data={"tool_name": tool_name, "baseline_established": False},
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence: dict[str, Any] = {
            "tool_name": tool_name,
            "current_hash": current_hash[:16] + "...",
            "baseline_established": False,
            "hash_match": None,
        }

        stored_baseline = self._baselines.get(tool_name)

        if stored_baseline is None:
            # First observation — establish baseline
            self._baselines[tool_name] = current_hash
            evidence["baseline_established"] = True
            evidence["hash_match"] = True
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"Configuration baseline established for tool '{tool_name}'.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["baseline_established"] = True

        if current_hash == stored_baseline:
            evidence["hash_match"] = True
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"Configuration integrity verified for tool '{tool_name}' — matches baseline.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Hash mismatch — drift detected
        evidence["hash_match"] = False
        evidence["baseline_hash"] = stored_baseline[:16] + "..."
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail=(
                f"Configuration drift detected for tool '{tool_name}' — "
                "current hash does not match established baseline."
            ),
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
