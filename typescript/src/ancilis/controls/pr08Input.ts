/** PR-08: Input Validation evaluator. */

import type { Action } from "../engine/action.js";
import type { ControlResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlEvaluator } from "../engine/evaluators/base.js";

const INJECTION_PATTERNS: Record<string, RegExp> = {
  // SQL injection
  sql_or_injection: /'\s*OR\s+1\s*=\s*1/i,
  sql_drop_table: /;\s*DROP\s+TABLE/i,
  sql_union_select: /\bUNION\s+SELECT\b/i,
  sql_comment_injection: /'[^']*--/,
  // Command injection
  cmd_rm: /;\s*rm\s+/,
  cmd_pipe_cat: /\|\s*cat\s+/,
  cmd_subshell: /\$\([^)]+\)/,
  cmd_backtick: /`[^`]+`/,
  // Path traversal
  path_traversal_unix: /\.\.\//,
  path_traversal_win: /\.\.[\\/]/,
  path_etc_passwd: /\/etc\/passwd/i,
  path_traversal_encoded: /%2e%2e/i,
};

/** Patterns that are suspicious but not definitive — produce FLAG instead of FAIL. */
const SUSPICIOUS_PATTERNS = new Set(["sql_comment_injection"]);

function flattenValues(params: Record<string, unknown>, depth = 3): string[] {
  const results: string[] = [];
  if (depth <= 0) return results;
  for (const val of Object.values(params)) {
    if (typeof val === "string") {
      results.push(val);
    } else if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      results.push(...flattenValues(val as Record<string, unknown>, depth - 1));
    } else if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string") {
          results.push(item);
        } else if (item !== null && typeof item === "object") {
          results.push(...flattenValues(item as Record<string, unknown>, depth - 1));
        }
      }
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

    for (const [patternName, pattern] of Object.entries(INJECTION_PATTERNS)) {
      for (const value of values) {
        if (pattern.test(value)) {
          patternsFound.push(patternName);
          if (!SUSPICIOUS_PATTERNS.has(patternName)) {
            isSuspiciousOnly = false;
          }
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
