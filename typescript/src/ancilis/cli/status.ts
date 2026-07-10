/** ancilis status — developer's primary interaction point. */

import type { ResolvedConfig } from "../config/index.js";
import type { EvidenceSummary } from "../report/generator.js";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { sharedPathFrom } from "../shared-path.js";

const CONTROLS_DIR = sharedPathFrom(import.meta.url, "controls");

function normalizedDecisions(summary: EvidenceSummary): Record<string, number> {
  const normalized: Record<string, number> = {};
  for (const [key, value] of Object.entries(summary.decisions ?? {})) {
    normalized[key.trim().toUpperCase()] = value;
  }
  return normalized;
}

function loadControlDefs(): Map<string, Record<string, unknown>> {
  const controls = new Map<string, Record<string, unknown>>();
  try {
    const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8"));
      controls.set(data.id, data);
    }
  } catch { /* ok */ }
  return controls;
}

export function formatStatus(config: ResolvedConfig, summary: EvidenceSummary, verbose = false): string {
  const lines: string[] = [];
  const controlDefs = loadControlDefs();

  lines.push(`Ancilis — ${config.agentName}`);
  lines.push(`  Mode: ${config.mode}`);

  const enabled = [...config.controls.values()].filter(c => c.enabled);
  const controlStats = summary.control_pass_rates ?? {};

  // Honest per-control bucketing (mirrors Python status). The headline must
  // never report "all passing" while a control is failing, flagged, or has
  // not actually been evaluated (never evaluated, or only SKIP results).
  let verified = 0;
  let attested = 0;
  let pendingCount = 0;
  let flaggedCount = 0;
  let failingCount = 0;
  for (const cs of enabled) {
    const stats = controlStats[cs.controlId] ?? {};
    const cdef = controlDefs.get(cs.controlId) ?? {};
    const supportLevel = (cdef.support_level as string | undefined) ?? "runtime_evaluator";
    const failCount = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
    const flagCount = stats.FLAG ?? 0;
    const passCount = stats.PASS ?? 0;
    if (failCount > 0) {
      failingCount += 1;
    } else if (flagCount > 0) {
      flaggedCount += 1;
    } else if (passCount > 0) {
      if (supportLevel === "attestation") attested += 1;
      else verified += 1;
    } else {
      // No PASS/FAIL/FLAG: never evaluated, or only SKIP (e.g. an
      // attestation control awaiting its first attestation).
      pendingCount += 1;
    }
  }

  const totalEvals = summary.total_evaluations;
  let controlSuffix: string;
  if (totalEvals === 0) {
    controlSuffix = "not yet evaluated";
  } else {
    const parts: string[] = [];
    if (verified) parts.push(`${verified} runtime-verified`);
    if (attested) parts.push(`${attested} attestation-passing`);
    if (pendingCount) parts.push(`${pendingCount} pending`);
    if (flaggedCount) parts.push(`${flaggedCount} flagged`);
    if (failingCount) parts.push(`${failingCount} failing`);
    controlSuffix = parts.length > 0 ? parts.join(", ") : "not yet evaluated";
    // Only an unqualified clean state earns the "all passing" affirmation.
    if (!pendingCount && !flaggedCount && !failingCount && (verified || attested)) {
      controlSuffix += " — all passing";
    }
  }
  lines.push(`  Controls: ${enabled.length} active, ${controlSuffix}`);

  // Certification one-liners
  for (const certId of config.activeCertifications) {
    lines.push(`  ${certId.toUpperCase()}: active`);
  }

  // Overlay one-liners
  for (const [, oa] of [...config.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    let trigger = "";
    if (oa.triggeredBy.length > 0) {
      const first = oa.triggeredBy[0];
      if (first !== undefined && first.includes(" via ")) {
        trigger = ` — triggered by ${first.split(" via ")[1]} declaration`;
      }
    }
    lines.push(`  ${oa.name}: active${trigger}`);
  }

  // Evaluation counts
  const total = summary.total_evaluations;
  const blocked = normalizedDecisions(summary).BLOCK ?? 0;
  if (total > 0) {
    lines.push(`  Tool calls: ${total.toLocaleString()} evaluated, ${blocked} blocked`);
  } else {
    lines.push("  No evaluations recorded yet. Middleware is collecting data.");
  }

  // Verbose detail
  if (verbose) {
    lines.push("");
    lines.push("  Controls:");
    for (const cs of [...enabled].sort((a, b) => a.controlId.localeCompare(b.controlId))) {
      const cdef = controlDefs.get(cs.controlId) ?? {};
      const displayName = (cdef.display_name as string) ?? cs.name;
      const stats = controlStats[cs.controlId] ?? {};
      const failCount = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
      const flagCount = stats.FLAG ?? 0;

      const passCount = stats.PASS ?? 0;
      const totalCount = Object.values(stats).reduce((a, b) => a + b, 0);

      let mark: string, statusStr: string;
      if (totalCount === 0) {
        mark = "\u2013";
        statusStr = "not yet evaluated";
      } else if (failCount > 0) {
        mark = "\u2717";
        statusStr = `failing (${failCount} failures)`;
      } else if (flagCount > 0) {
        // A flag is a deviation for review \u2014 not a pass.
        mark = "!";
        statusStr = `flagged (${flagCount} flag${flagCount !== 1 ? "s" : ""})`;
      } else if (passCount > 0) {
        mark = "\u2713";
        statusStr = "passing";
      } else {
        // Evaluated only as SKIP (e.g. an attestation control not yet
        // attested) \u2014 pending, not passing.
        mark = "\u25cb";
        statusStr = "pending (attestation required)";
      }
      lines.push(`    ${mark} ${displayName} — ${statusStr}`);
    }

    if (config.activeCertifications.length > 0 || config.activeOverlays.size > 0) {
      lines.push("");
      lines.push("  Activation:");
      for (const certId of config.activeCertifications) {
        lines.push(`    ${certId.toUpperCase()} certification active — ${enabled.length} controls enforcing`);
      }
      for (const [, oa] of [...config.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
        let trigger = "";
        if (oa.triggeredBy.length > 0) {
          const first = oa.triggeredBy[0];
          if (first !== undefined && first.includes(" via ")) {
            trigger = ` — triggered by ${first.split(" via ")[1]} declaration`;
          }
        }
        lines.push(`    ${oa.name} overlay active${trigger}`);
      }
    }

    if (total > 0) {
      const chainStatus = summary.chain_valid ? "intact" : "BROKEN";
      lines.push(`  Evidence records: ${total.toLocaleString()} stored, hash chain ${chainStatus}`);
    }
  }

  return lines.join("\n");
}
