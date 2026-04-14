/** PR-06: Configuration Integrity Baseline evaluator. */

import { createHash } from "node:crypto";
import type { Action } from "../engine/action.js";
import type { ControlResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlEvaluator } from "../engine/evaluators/base.js";

export class PR06ConfigBaselineEvaluator implements ControlEvaluator {
  controlId = "PR-06";
  controlName = "Configuration Integrity Baseline";

  /** In-memory baseline store: toolName -> baselineHash */
  private _baselines = new Map<string, string>();

  private _computeHash(action: Action): string | null {
    const tool = action.tool;
    if (!tool || !tool.descriptionHash) return null;
    return createHash("sha256")
      .update(`${tool.name}:${tool.descriptionHash}`)
      .digest("hex");
  }

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const tool = action.tool;
    if (!tool?.name) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "SKIP",
        detail: "No tool information available — cannot establish configuration baseline.",
        evidenceData: { tool_name: null, baseline_established: false },
        durationMs: performance.now() - start,
      };
    }

    const toolName = tool.name;
    const currentHash = this._computeHash(action);

    if (currentHash === null) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "SKIP",
        detail: `Cannot compute configuration hash for tool '${toolName}'.`,
        evidenceData: { tool_name: toolName, baseline_established: false },
        durationMs: performance.now() - start,
      };
    }

    const evidence: Record<string, unknown> = {
      tool_name: toolName,
      current_hash: currentHash.slice(0, 16) + "...",
      baseline_established: false,
      hash_match: null,
    };

    const stored = this._baselines.get(toolName);

    if (stored === undefined) {
      this._baselines.set(toolName, currentHash);
      evidence.baseline_established = true;
      evidence.hash_match = true;
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `Configuration baseline established for tool '${toolName}'.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence.baseline_established = true;

    if (currentHash === stored) {
      evidence.hash_match = true;
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `Configuration integrity verified for tool '${toolName}' — matches baseline.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence.hash_match = false;
    evidence.baseline_hash = stored.slice(0, 16) + "...";
    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FAIL",
      detail: `Configuration drift detected for tool '${toolName}' — current hash does not match established baseline.`,
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
