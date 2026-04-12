/** GOV-01: Governance Policy evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

export class GOV01PolicyEvaluator implements ControlEvaluator {
  controlId = "GOV-01";
  controlName = "Governance Policy";

  evaluate(_action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const fieldsPresent: string[] = [];
    const fieldsMissing: string[] = [];

    // 1. agent_name must be set (non-empty)
    if (config.agentName?.trim()) {
      fieldsPresent.push("agent_name");
    } else {
      fieldsMissing.push("agent_name");
    }

    // 2. mode must be explicitly set
    if (config.mode?.trim()) {
      fieldsPresent.push("mode");
    } else {
      fieldsMissing.push("mode");
    }

    // 3. data_classifications must have at least one entry
    if (config.dataClassifications.size > 0) {
      fieldsPresent.push("data_classifications");
    } else {
      fieldsMissing.push("data_classifications");
    }

    // 4. scope constraints — tools_allowed or tools_blocked must be set
    const hasScope = config.toolsAllowed.length > 0 || config.toolsBlocked.length > 0;
    if (hasScope) {
      fieldsPresent.push("scope_constraints");
    } else {
      fieldsMissing.push("scope_constraints");
    }

    const presentCount = fieldsPresent.length;
    const total = fieldsPresent.length + fieldsMissing.length;

    let completeness: string;
    if (presentCount === total) {
      completeness = "complete";
    } else if (presentCount >= 2) {
      completeness = "partial";
    } else {
      completeness = "insufficient";
    }

    const evidence: Record<string, unknown> = {
      policy_completeness: completeness,
      fields_present: fieldsPresent,
      fields_missing: fieldsMissing,
    };

    const durationMs = performance.now() - start;

    if (completeness === "complete") {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: "Complete governance policy: all required fields are configured.",
        evidenceData: evidence,
        durationMs,
      };
    }

    if (completeness === "partial") {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Partial governance policy: missing ${fieldsMissing.join(", ")}.`,
        evidenceData: evidence,
        durationMs,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FAIL",
      detail: `Insufficient governance policy: ${fieldsMissing.length} of ${total} required fields are missing.`,
      evidenceData: evidence,
      durationMs,
    };
  }
}
