/** GOV-02: Agent Ownership & Accountability evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

const PLACEHOLDER_VALUES = new Set([
  "todo", "unknown", "changeme", "tbd", "n/a", "none", "placeholder", "example",
]);

export class GOV02OwnershipEvaluator implements ControlEvaluator {
  controlId = "GOV-02";
  controlName = "Agent Ownership & Accountability";

  evaluate(_action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const ownerValue = (config.agentOwner ?? "").trim();

    const evidence: Record<string, unknown> = {
      owner_declared: false,
      owner_value: ownerValue || null,
      source_field: "agent.owner",
    };

    if (!ownerValue) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: "No agent owner configured. Add agent.owner in ancilis.yaml.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence["owner_declared"] = true;

    if (PLACEHOLDER_VALUES.has(ownerValue.toLowerCase())) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Agent owner appears to be a placeholder value: '${ownerValue}'. Replace with a contactable individual.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: `Agent owner declared: '${ownerValue}'.`,
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
