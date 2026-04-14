/** Decision engine — orchestrates control evaluation. */

import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { ResolvedConfig } from "../config/index.js";
import { sharedPathFrom } from "../shared-path.js";
import type { Action } from "./action.js";
import type { ControlEvaluator } from "./evaluators/base.js";
import { PR01IdentityEvaluator } from "./evaluators/pr01-identity.js";
import { PR02ScopeEvaluator } from "./evaluators/pr02-scope.js";
import type { RateTracker } from "./evaluators/pr02-scope.js";
import { PR03ProvenanceEvaluator } from "./evaluators/pr03-provenance.js";
import { PR04ExposureEvaluator } from "./evaluators/pr04-exposure.js";
import { PR05AuditEvaluator } from "../controls/pr05Audit.js";
import { PR06ConfigBaselineEvaluator } from "../controls/pr06ConfigBaseline.js";
import { PR07TransportEvaluator } from "../controls/pr07Transport.js";
import { PR08InputEvaluator } from "../controls/pr08Input.js";
import { DE01BaselineEvaluator } from "../controls/de01Baseline.js";
import type { BaselineWindow } from "../controls/de01Baseline.js";
import { DE02ConfigDriftEvaluator } from "./evaluators/de02-config-drift.js";
import { DE04IntegrityEvaluator } from "./evaluators/de04-integrity.js";
import type { DE04StoreAdapter } from "./evaluators/de04-integrity.js";
import { ToolRegistry } from "./registry.js";
import type { ControlResult, EvaluationResult } from "./result.js";

const CONTROLS_DIR = sharedPathFrom(import.meta.url, "controls");
const POLICY_SENSITIVE_EVALUATOR_CONTROL_IDS = new Set(["DE-04", "GOV-01", "GOV-02", "GOV-03", "ID-01"]);
const RUNTIME_POLICY_GATE_SOURCES = ["explicit:security.controls", "certification_targets:"];

function loadControlDefs(): Map<string, Record<string, unknown>> {
  const controls = new Map<string, Record<string, unknown>>();
  try {
    const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8"));
      controls.set(data.id, data);
    }
  } catch { /* shared dir may not exist in tests */ }
  return controls;
}

export class Engine {
  private config: ResolvedConfig;
  readonly registry: ToolRegistry;
  private evaluators: Map<string, ControlEvaluator>;
  private controlDefs: Map<string, Record<string, unknown>>;

  constructor(
    config: ResolvedConfig,
    options?: {
      registry?: ToolRegistry;
      rateTracker?: RateTracker;
      baselineWindow?: BaselineWindow;
      evidenceStore?: DE04StoreAdapter | null;
    },
  ) {
    this.config = config;
    this.registry = options?.registry ?? new ToolRegistry();
    this.controlDefs = loadControlDefs();
    this.evaluators = new Map<string, ControlEvaluator>([
      ["PR-01", new PR01IdentityEvaluator()],
      ["PR-02", new PR02ScopeEvaluator(options?.rateTracker)],
      ["PR-03", new PR03ProvenanceEvaluator(this.registry)],
      ["PR-04", new PR04ExposureEvaluator()],
      ["PR-05", new PR05AuditEvaluator()],
      ["PR-06", new PR06ConfigBaselineEvaluator()],
      ["PR-07", new PR07TransportEvaluator()],
      ["PR-08", new PR08InputEvaluator()],
      ["DE-01", new DE01BaselineEvaluator(options?.baselineWindow)],
      ["DE-02", new DE02ConfigDriftEvaluator()],
      ["DE-04", new DE04IntegrityEvaluator(options?.evidenceStore ?? null)],
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

      if (this.isPolicyGated(controlId)) {
        controlResults.push({
          controlId,
          controlName: controlStatus.name,
          result: "SKIP",
          detail: "Control is not runtime-active under the explicit/certification policy gate.",
          evidenceData: {
            activation_sources: [...(this.config.controlActivationSources.get(controlId) ?? new Set<string>())].sort(),
            required_activation_sources: RUNTIME_POLICY_GATE_SOURCES,
          },
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

    // Post-process: fill display fields from control definitions
    for (const cr of controlResults) {
      const cdef = this.controlDefs.get(cr.controlId);
      if (cdef && !cr.displayName) {
        cr.displayName = (cdef.display_name as string) ?? cr.controlName;
        cr.displayDetail = (cdef.display_detail as string) ?? "";
        cr.remediationHint = (cdef.remediation_hint_template as string) ?? "";
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
      sourceType: action.sourceType ?? "agent",
      mode: this.config.mode as "audit" | "enforce",
      controlResults,
      decision,
      decisionReason,
      activeOverlays,
      dataClassifications,
      totalDurationMs: performance.now() - start,
      context: { sessionId: action.context?.sessionId ?? undefined },
    };
  }

  /** Expose evaluators for testing (e.g., to inject a broken evaluator). */
  _setEvaluator(controlId: string, evaluator: ControlEvaluator): void {
    this.evaluators.set(controlId, evaluator);
  }

  private isPolicyGated(controlId: string): boolean {
    if (!POLICY_SENSITIVE_EVALUATOR_CONTROL_IDS.has(controlId)) return false;
    return !this.config.controlHasActivationSource(controlId, ...RUNTIME_POLICY_GATE_SOURCES);
  }
}
