/** PR-08: Input Validation evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

interface InjectionPattern {
  name: string;
  pattern: RegExp;
  suspicious?: boolean;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // SQL injection
  { name: "sql_or_injection", pattern: /'\s*OR\s+1\s*=\s*1/i },
  { name: "sql_drop_table", pattern: /;\s*DROP\s+TABLE/i },
  { name: "sql_union_select", pattern: /\bUNION\s+SELECT\b/i },
  { name: "sql_comment_injection", pattern: /'[^']*--/, suspicious: true },
  // Command injection
  { name: "cmd_rm", pattern: /;\s*rm\s+/ },
  { name: "cmd_pipe_cat", pattern: /\|\s*cat\s+/ },
  { name: "cmd_subshell", pattern: /\$\([^)]+\)/ },
  { name: "cmd_backtick", pattern: /`[^`]+`/ },
  // Path traversal
  { name: "path_traversal_unix", pattern: /\.\.\// },
  { name: "path_traversal_win", pattern: /\.\.[/\\]/ },
  { name: "path_etc_passwd", pattern: /\/etc\/passwd/i },
  { name: "path_traversal_encoded", pattern: /%2e%2e/i },
];

function flattenValues(params: Record<string, unknown>, depth = 3): string[] {
  if (depth <= 0) return [];
  const results: string[] = [];
  for (const val of Object.values(params)) {
    if (typeof val === "string") {
      results.push(val);
    } else if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string") results.push(item);
        else if (item !== null && typeof item === "object") {
          results.push(...flattenValues(item as Record<string, unknown>, depth - 1));
        }
      }
    } else if (val !== null && typeof val === "object") {
      results.push(...flattenValues(val as Record<string, unknown>, depth - 1));
    }
  }
  return results;
}

export class PR08InputEvaluator implements ControlEvaluator {
  controlId = "PR-08";
  controlName = "Input Validation";

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const params = action.parameters.raw as Record<string, unknown>;
    const parameterKeys = Object.keys(params);
    const values = flattenValues(params);

    const patternsFound: string[] = [];
    let isSuspiciousOnly = true;

    for (const { name, pattern, suspicious } of INJECTION_PATTERNS) {
      for (const value of values) {
        if (pattern.test(value)) {
          patternsFound.push(name);
          if (!suspicious) isSuspiciousOnly = false;
          break; // one match per pattern is enough
        }
      }
    }

    const evidence: Record<string, unknown> = {
      scan_result: "clean",
      patterns_found: patternsFound,
      parameter_keys: parameterKeys,
    };

    const durationMs = performance.now() - start;

    if (patternsFound.length === 0) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: "No injection patterns detected in action parameters.",
        evidenceData: evidence,
        durationMs,
      };
    }

    if (isSuspiciousOnly) {
      evidence.scan_result = "suspicious";
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Suspicious patterns detected (may be false positive): ${patternsFound.join(", ")}.`,
        evidenceData: evidence,
        durationMs,
      };
    }

    evidence.scan_result = "injection_detected";
    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FAIL",
      detail: `Injection patterns detected: ${patternsFound.join(", ")}.`,
      evidenceData: evidence,
      durationMs,
    };
  }
}
