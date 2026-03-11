/** DE-01: Behavioral Baseline Monitoring evaluator. */

import type { Action } from "../engine/action.js";
import type { ControlResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlEvaluator } from "../engine/evaluators/base.js";

export interface DeviationFlag {
  type: string;
  displayMessage: string;
  severity: string;
}

export interface BaselineWindow {
  toolCalls: string[];
  callCount: number;
  windowMinutes: number;
}

function uniqueTools(window: BaselineWindow): Set<string> {
  return new Set(window.toolCalls);
}

function callsPerMinute(window: BaselineWindow): number {
  if (window.windowMinutes <= 0) return 0;
  return window.callCount / window.windowMinutes;
}

export class DE01BaselineEvaluator implements ControlEvaluator {
  controlId = "DE-01";
  controlName = "Behavioral Anomaly Detection";

  static readonly FREQUENCY_SPIKE_MULTIPLIER = 3.0;

  private _baseline: BaselineWindow;

  constructor(baselineWindow?: BaselineWindow) {
    this._baseline = baselineWindow ?? { toolCalls: [], callCount: 0, windowMinutes: 0 };
  }

  get baseline(): BaselineWindow { return this._baseline; }

  setBaseline(window: BaselineWindow): void {
    this._baseline = window;
  }

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const evidence: Record<string, unknown> = {
      baseline_established: false,
      baseline_window_calls: 0,
      current_rate_vs_baseline: 0.0,
      deviation_flags: [],
      new_tools_detected: [],
    };

    const toolName = action.tool.name;

    if (this._baseline.callCount === 0) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: "Baseline not yet established — monitoring started.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    evidence.baseline_established = true;
    evidence.baseline_window_calls = this._baseline.callCount;

    const deviationFlags: DeviationFlag[] = [];
    const newTools: string[] = [];

    if (!uniqueTools(this._baseline).has(toolName)) {
      newTools.push(toolName);
      deviationFlags.push({
        type: "new_tool",
        displayMessage: `Tool '${toolName}' not seen in baseline window`,
        severity: "warning",
      });
    }

    const baselineRate = callsPerMinute(this._baseline);
    if (baselineRate > 0) {
      evidence.current_rate_vs_baseline = 1.0;
    }

    evidence.deviation_flags = deviationFlags;
    evidence.new_tools_detected = newTools;

    if (deviationFlags.length > 0) {
      const flagSummary = deviationFlags.map(f => f.displayMessage).join("; ");
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Behavioral deviation detected: ${flagSummary}`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: "Agent behavior within established baseline parameters.",
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }

  evaluateWithRate(action: Action, _config: ResolvedConfig, currentRate: number): ControlResult {
    const start = performance.now();

    const evidence: Record<string, unknown> = {
      baseline_established: true,
      baseline_window_calls: this._baseline.callCount,
      current_rate_vs_baseline: 0.0,
      deviation_flags: [],
      new_tools_detected: [],
    };

    if (this._baseline.callCount === 0) {
      evidence.baseline_established = false;
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: "Baseline not yet established — monitoring started.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    const toolName = action.tool.name;
    const deviationFlags: DeviationFlag[] = [];
    const newTools: string[] = [];

    if (!uniqueTools(this._baseline).has(toolName)) {
      newTools.push(toolName);
      deviationFlags.push({
        type: "new_tool",
        displayMessage: `Tool '${toolName}' not seen in baseline window`,
        severity: "warning",
      });
    }

    const baselineRate = callsPerMinute(this._baseline);
    if (baselineRate > 0) {
      const ratio = currentRate / baselineRate;
      evidence.current_rate_vs_baseline = Math.round(ratio * 100) / 100;
      if (ratio > DE01BaselineEvaluator.FREQUENCY_SPIKE_MULTIPLIER) {
        deviationFlags.push({
          type: "frequency_spike",
          displayMessage: `Tool call frequency is ${ratio.toFixed(1)}x above baseline average`,
          severity: "warning",
        });
      }
    }

    evidence.deviation_flags = deviationFlags;
    evidence.new_tools_detected = newTools;

    if (deviationFlags.length > 0) {
      const flagSummary = deviationFlags.map(f => f.displayMessage).join("; ");
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Behavioral deviation detected: ${flagSummary}`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: "Agent behavior within established baseline parameters.",
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
