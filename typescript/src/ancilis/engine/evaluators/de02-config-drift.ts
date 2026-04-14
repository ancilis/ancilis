/** DE-02: Configuration Drift Monitoring evaluator. */

import { createHash } from "node:crypto";
import type { ResolvedConfig } from "../../config/index.js";
import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ControlEvaluator } from "./base.js";

export class DE02ConfigDriftEvaluator implements ControlEvaluator {
  controlId = "DE-02";
  controlName = "Configuration Drift Monitoring";

  private readonly fingerprints = new Map<string, string>();

  private computeFingerprint(action: Action): string | null {
    const tool = action.tool;
    if (!tool?.name || !tool.descriptionHash) {
      return null;
    }

    const raw = [
      tool.name,
      tool.descriptionHash,
      tool.version ?? "",
      tool.server ?? "",
    ].join(":");
    return createHash("sha256").update(raw).digest("hex");
  }

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const tool = action.tool;
    if (!tool?.name) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "SKIP",
        detail: "No tool information available - cannot monitor configuration drift.",
        evidenceData: { tool_name: null, drift_detected: false },
        durationMs: performance.now() - start,
      };
    }

    const toolName = tool.name;
    const fingerprint = this.computeFingerprint(action);
    if (fingerprint === null) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "SKIP",
        detail: `Cannot compute fingerprint for tool '${toolName}'.`,
        evidenceData: { tool_name: toolName, drift_detected: false },
        durationMs: performance.now() - start,
      };
    }

    const evidence: Record<string, unknown> = {
      tool_name: toolName,
      fingerprint: fingerprint.slice(0, 16) + "...",
      drift_detected: false,
      first_observation: false,
    };

    const previous = this.fingerprints.get(toolName);
    if (previous === undefined) {
      this.fingerprints.set(toolName, fingerprint);
      evidence.first_observation = true;
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `Configuration fingerprint recorded for tool '${toolName}' - first observation in session.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    if (fingerprint === previous) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `No configuration drift detected for tool '${toolName}' - fingerprint unchanged.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence.drift_detected = true;
    evidence.previous_fingerprint = previous.slice(0, 16) + "...";
    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FAIL",
      detail: (
        `Configuration drift detected for tool '${toolName}' - ` +
        "configuration changed since last evaluation in this session."
      ),
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
