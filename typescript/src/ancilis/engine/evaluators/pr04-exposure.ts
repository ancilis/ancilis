/** PR-04: Data Exposure Prevention evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";
import { scanParameters } from "../patterns.js";

export class PR04ExposureEvaluator implements ControlEvaluator {
  controlId = "PR-04";
  controlName = "Data Exposure Prevention";

  evaluate(action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const evidence: Record<string, unknown> = {
      scan_result: "clean",
      patterns_detected: [],
      destination: null,
      destination_authorized: true,
    };

    const matches = scanParameters(action.parameters.raw);

    if (matches.length === 0) {
      evidence.scan_result = "clean";
      let detail = "No sensitive data detected in outbound parameters.";
      if (config.dataClassifications.size === 0) {
        detail += " No data classifications declared.";
      }
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "PASS", detail, evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    // Patterns found
    evidence.scan_result = "patterns_found";
    evidence.patterns_detected = matches.map(m => ({
      type: m.patternType, count: m.count, redacted_sample: m.redactedSample,
    }));

    const destination = this.extractDestination(action);
    evidence.destination = destination;

    if (destination && config.scopeBlockedDestinations.length > 0) {
      if (config.scopeBlockedDestinations.includes(destination)) {
        evidence.destination_authorized = false;
        evidence.scan_result = "blocked";
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FAIL",
          detail: `Sensitive data detected going to blocked destination '${destination}'.`,
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
    }

    if (destination && config.scopeAllowedDestinations.length > 0) {
      if (!config.scopeAllowedDestinations.includes(destination)) {
        evidence.destination_authorized = false;
        evidence.scan_result = "blocked";
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FAIL",
          detail: `Sensitive data detected going to unauthorized destination '${destination}'.`,
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
    }

    const patternTypes = matches.map(m => m.patternType).join(", ");
    return {
      controlId: this.controlId, controlName: this.controlName,
      result: "PASS",
      detail: `Sensitive data patterns detected (${patternTypes}) but no destination restrictions configured.`,
      evidenceData: evidence, durationMs: performance.now() - start,
    };
  }

  private extractDestination(action: Action): string | null {
    const raw = action.parameters.raw;
    for (const key of ["url", "destination", "endpoint", "host", "server"]) {
      if (key in raw) {
        const val = raw[key];
        if (typeof val === "string") return val;
      }
    }
    return null;
  }
}
