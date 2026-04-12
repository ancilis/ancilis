"""DE-02: Configuration Drift Monitoring evaluator."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class DE02ConfigDriftEvaluator:
    """Detects unauthorized changes to tool configurations between evaluations.

    On each evaluation, computes a fingerprint for the tool being invoked and
    compares it against the fingerprint recorded in the current session. If the
    fingerprint changes between evaluations for the same tool, drift is detected.

    Unlike PR-06 (which establishes a persistent baseline), DE-02 focuses on
    detecting intra-session configuration changes that may indicate a semantic
    supply-chain attack or misconfiguration.
    """

    control_id = "DE-02"
    control_name = "Configuration Drift Monitoring"

    def __init__(self) -> None:
        # Session-scoped fingerprints: tool_name -> last-seen fingerprint
        self._fingerprints: dict[str, str] = {}

    def _compute_fingerprint(self, action: Action) -> str | None:
        """Compute a fingerprint from tool metadata available in the action.

        Requires description_hash — returns None if absent so that pre-registry
        calls (before list_tools()) are skipped rather than establishing an
        unreliable baseline that would trigger false-positive drift on the
        first post-discovery call.
        """
        tool = action.tool
        if not tool or not tool.name or not tool.description_hash:
            return None

        parts = [tool.name, tool.description_hash, tool.version or "", tool.server or ""]
        raw = ":".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        tool = action.tool
        if not tool or not tool.name:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail="No tool information available — cannot monitor configuration drift.",
                evidence_data={"tool_name": None, "drift_detected": False},
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        tool_name = tool.name
        fingerprint = self._compute_fingerprint(action)

        if fingerprint is None:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail=f"Cannot compute fingerprint for tool '{tool_name}'.",
                evidence_data={"tool_name": tool_name, "drift_detected": False},
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence: dict[str, Any] = {
            "tool_name": tool_name,
            "fingerprint": fingerprint[:16] + "...",
            "drift_detected": False,
            "first_observation": False,
        }

        previous = self._fingerprints.get(tool_name)

        if previous is None:
            # First time this tool is seen in this session
            self._fingerprints[tool_name] = fingerprint
            evidence["first_observation"] = True
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"Configuration fingerprint recorded for tool '{tool_name}' — first observation in session.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if fingerprint == previous:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"No configuration drift detected for tool '{tool_name}' — fingerprint unchanged.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Fingerprint changed — drift detected
        evidence["drift_detected"] = True
        evidence["previous_fingerprint"] = previous[:16] + "..."
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail=(
                f"Configuration drift detected for tool '{tool_name}' — "
                "configuration changed since last evaluation in this session."
            ),
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
