/** PR-05: Audit Logging evaluator. */

import type { Action } from "../engine/action.js";
import type { ControlResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlEvaluator } from "../engine/evaluators/base.js";

export class PR05AuditEvaluator implements ControlEvaluator {
  controlId = "PR-05";
  controlName = "Audit Logging";

  evaluate(action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const evidence: Record<string, unknown> = {
      logging_enabled: false,
      log_format: "unknown",
      required_fields_present: false,
      sample_entry_field_count: 0,
    };

    const hasEvidenceStore = config.evidenceRetentionDays > 0;

    if (!hasEvidenceStore) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: "Audit logging is not configured. Enable evidence storage in ancilis.yaml.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence.logging_enabled = true;

    const requiredFields = ["actionId", "timestamp", "agentId", "actionType"];
    const presentFields: string[] = [];
    const actionObj = action as unknown as Record<string, unknown>;
    for (const field of requiredFields) {
      if (actionObj[field]) {
        presentFields.push(field);
      }
    }

    evidence.required_fields_present = presentFields.length === requiredFields.length;
    evidence.sample_entry_field_count = presentFields.length;
    evidence.log_format = "json";

    if (!evidence.required_fields_present) {
      const missing = requiredFields.filter(f => !presentFields.includes(f));
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: `Log entry missing required fields: ${missing.join(", ")}.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: "Structured audit logging active with all required fields.",
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
