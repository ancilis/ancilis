/** Decision engine — orchestrates control evaluation. */

import { randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "./action.js";
import type { ControlEvaluator } from "./evaluators/base.js";
import { PR01IdentityEvaluator } from "./evaluators/pr01-identity.js";
import { PR02ScopeEvaluator } from "./evaluators/pr02-scope.js";
import type { RateTracker } from "./evaluators/pr02-scope.js";
import { PR03ProvenanceEvaluator } from "./evaluators/pr03-provenance.js";
import { PR04ExposureEvaluator } from "./evaluators/pr04-exposure.js";
import { PR05AuditEvaluator } from "../controls/pr05Audit.js";
import { DE01BaselineEvaluator } from "../controls/de01Baseline.js";
import type { BaselineWindow } from "../controls/de01Baseline.js";
import { ToolRegistry } from "./registry.js";
import type { ControlResult, EvaluationResult } from "./result.js";

export class Engine {
  private config: ResolvedConfig;
  readonly registry: ToolRegistry;
  private evaluators: Map<string, ControlEvaluator>;

  constructor(
    config: ResolvedConfig,
    options?: { registry?: ToolRegistry; rateTracker?: RateTracker; baselineWindow?: BaselineWindow },
  ) {
    this.config = config;
    this.registry = options?.registry ?? new ToolRegistry();
    this.evaluators = new Map<string, ControlEvaluator>([
      ["PR-01", new PR01IdentityEvaluator()],
      ["PR-02", new PR02ScopeEvaluator(options?.rateTracker)],
      ["PR-03", new PR03ProvenanceEvaluator(this.registry)],
      ["PR-04", new PR04ExposureEvaluator()],
      ["PR-05", new PR05AuditEvaluator()],
      ["DE-01", new DE01BaselineEvaluator(options?.baselineWindow)],
    ]);
  }

  evaluate(action: Action): EvaluationResult {
    const start = performance.now();
    const controlResults: ControlResult[] = [];

    for (const [controlId, controlStatus] of [...this.config.controls.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      if (!controlStatus.enabled) {
        controlResults.push({
          controlId,
          controlName: controlStatus.name,
          result: "SKIP",
          detail: "Control is disabled.",
          evidenceData: {},
          durationMs: 0,
        });
        continue;
      }

      const evaluator = this.evaluators.get(controlId);
      if (!evaluator) {
        controlResults.push({
          controlId,
          controlName: controlStatus.name,
          result: "SKIP",
          detail: "No evaluator implemented for this control.",
          evidenceData: {},
          durationMs: 0,
        });
        continue;
      }

      try {
        const result = evaluator.evaluate(action, this.config);
        controlResults.push(result);
      } catch (e) {
        controlResults.push({
          controlId,
          controlName: controlStatus.name,
          result: "ERROR",
          detail: `Evaluator error: ${e instanceof Error ? e.message : String(e)}`,
          evidenceData: { error: String(e) },
          durationMs: 0,
        });
      }
    }

    // Decision logic
    const hasFailure = controlResults.some(r => r.result === "FAIL" || r.result === "ERROR");

    let decision: "ALLOW" | "BLOCK" | "FLAG";
    let decisionReason: string;

    if (this.config.mode === "enforce" && hasFailure) {
      const failed = controlResults
        .filter(r => r.result === "FAIL" || r.result === "ERROR")
        .map(r => r.controlId);
      decision = "BLOCK";
      decisionReason = `Blocked by: ${failed.join(", ")}`;
    } else {
      decision = "ALLOW";
      if (hasFailure && this.config.mode === "audit") {
        const failed = controlResults
          .filter(r => r.result === "FAIL" || r.result === "ERROR")
          .map(r => r.controlId);
        decisionReason = `Audit mode — failures logged but allowed: ${failed.join(", ")}`;
      } else {
        decisionReason = "All controls passed.";
      }
    }

    const activeOverlays = [...this.config.activeOverlays.keys()];
    const dataClassifications: string[] = [];
    for (const codes of this.config.dataClassifications.values()) {
      for (const code of codes) {
        if (!dataClassifications.includes(code)) {
          dataClassifications.push(code);
        }
      }
    }

    return {
      evaluationId: randomUUID(),
      actionId: action.actionId,
      timestamp: new Date().toISOString(),
      agentId: action.agentId,
      mode: this.config.mode as "audit" | "enforce",
      controlResults,
      decision,
      decisionReason,
      activeOverlays,
      dataClassifications,
      totalDurationMs: performance.now() - start,
    };
  }

  /** Expose evaluators for testing (e.g., to inject a broken evaluator). */
  _setEvaluator(controlId: string, evaluator: ControlEvaluator): void {
    this.evaluators.set(controlId, evaluator);
  }
}
