import * as core from "@actions/core";
import type { ScanResult } from "./scanner.js";

export function createAnnotations(scan: ScanResult): void {
  for (const control of scan.controls) {
    if (control.status === "fail") {
      core.error(
        `Control ${control.id} (${control.name}) failed: ${control.failures} failure(s) in ${control.evaluations} evaluation(s)`
      );
    } else if (control.flags > 0) {
      core.warning(
        `Control ${control.id} (${control.name}) flagged: ${control.flags} flag(s) in ${control.evaluations} evaluation(s)`
      );
    }
  }
}
