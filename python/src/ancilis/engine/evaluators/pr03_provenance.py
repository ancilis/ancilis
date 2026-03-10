"""PR-03: Tool Provenance Verification evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.registry import ToolRegistry
from ancilis.engine.result import ControlResult


class PR03ProvenanceEvaluator:
    control_id = "PR-03"
    control_name = "Tool Provenance Verification"

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        tool_name = action.tool.name

        evidence: dict[str, Any] = {
            "tool_name": tool_name,
            "tool_version": action.tool.version,
        }

        entry = self.registry.lookup(tool_name)

        if entry is None:
            evidence["registered"] = False
            evidence["hash_match"] = "no_hash"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Tool '{tool_name}' is not registered.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["registered"] = True
        evidence["registry_entry"] = {
            "name": entry.name,
            "version": entry.version,
            "approved": entry.approved,
        }

        # Check version
        if action.tool.version and entry.version and action.tool.version != entry.version:
            evidence["hash_match"] = "no_hash"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Tool version mismatch: action has '{action.tool.version}', registry has '{entry.version}'.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Check description hash
        if action.tool.description_hash and entry.description_hash:
            if action.tool.description_hash != entry.description_hash:
                evidence["hash_match"] = False
                return ControlResult(
                    control_id=self.control_id,
                    control_name=self.control_name,
                    result="FAIL",
                    detail="Description hash drift detected — possible tampering.",
                    evidence_data=evidence,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            evidence["hash_match"] = True
        else:
            evidence["hash_match"] = "no_hash"

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Tool provenance verified.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
