import type { FailOn } from "./inputs.js";
import type { ScanResult } from "./scanner.js";

export interface ThresholdResult {
  shouldFail: boolean;
  reason: string;
}

export function applyThreshold(scan: ScanResult, failOn: FailOn): ThresholdResult {
  if (failOn === "none") {
    return { shouldFail: false, reason: "fail-on is none — check always passes" };
  }

  const hasBlocks = scan.controls.some(
    (c) => c.status === "fail" && c.failures > 0
  );
  const hasFailures = scan.controls.some((c) => c.status === "fail");
  const hasFlags = scan.controls.some((c) => c.flags > 0);
  // "pending" (SKIP-only) and "skip" (never evaluated) both count as non-pass:
  // a control without verifying evidence must never satisfy a threshold as
  // if it were passing.
  const hasNonPass = scan.controls.some((c) => c.status !== "pass");

  // Detect BLOCK decisions: only in enforce mode when posture is non_compliant
  // In audit mode, failures are logged but never blocked — critical threshold ignores them
  const hasBlocking = scan.mode === "enforce" && scan.posture === "non_compliant" && scan.exit_code === 1;

  switch (failOn) {
    case "critical":
      // Fail only on BLOCK decisions (enforce mode blocks)
      if (hasBlocking && hasBlocks) {
        return { shouldFail: true, reason: "BLOCK decisions present" };
      }
      return { shouldFail: false, reason: "No BLOCK decisions — check passes at critical threshold" };

    case "high":
      // Fail on any control failure
      if (hasFailures) {
        return { shouldFail: true, reason: "One or more controls are failing" };
      }
      return { shouldFail: false, reason: "No control failures — check passes at high threshold" };

    case "medium":
      // Fail on failures or flags
      if (hasFailures) {
        return { shouldFail: true, reason: "One or more controls are failing" };
      }
      if (hasFlags) {
        return { shouldFail: true, reason: "One or more controls have flagged evaluations" };
      }
      return { shouldFail: false, reason: "No failures or flags — check passes at medium threshold" };

    case "low":
      // Fail on any non-pass status (includes skip)
      if (hasNonPass) {
        return { shouldFail: true, reason: "One or more controls are not passing (fail, pending, or skip)" };
      }
      return { shouldFail: false, reason: "All controls passing — check passes at low threshold" };
  }
}
