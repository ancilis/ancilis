/** ancilis status — developer's primary interaction point. */

import type { ResolvedConfig } from "../config/index.js";
import type { EvidenceSummary } from "../report/generator.js";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __statusFilename = fileURLToPath(import.meta.url);
const CONTROLS_DIR = resolve(__statusFilename, "..", "..", "..", "..", "..", "shared", "controls");

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

  let allPassing = true;
  for (const cs of enabled) {
    const stats = controlStats[cs.controlId] ?? {};
    if ((stats.FAIL ?? 0) > 0 || (stats.ERROR ?? 0) > 0) allPassing = false;
  }

  const passingStr = allPassing ? "all passing" : "issues detected";
  lines.push(`  Controls: ${enabled.length} active, ${passingStr}`);

  // Certification one-liners
  for (const certId of config.activeCertifications) {
    lines.push(`  ${certId.toUpperCase()}: active`);
  }

  // Overlay one-liners
  for (const [, oa] of [...config.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    let trigger = "";
    if (oa.triggeredBy.length > 0) {
      const first = oa.triggeredBy[0];
      if (first.includes(" via ")) {
        trigger = ` — triggered by ${first.split(" via ")[1]} declaration`;
      }
    }
    lines.push(`  ${oa.name}: active${trigger}`);
  }

  // Evaluation counts
  const total = summary.total_evaluations;
  const blocked = summary.decisions.BLOCK ?? 0;
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

      let mark: string, suffix: string;
      if (failCount > 0) {
        mark = "\u2717";
        suffix = ` (${failCount} failures)`;
      } else if (flagCount > 0) {
        mark = "\u2713";
        suffix = ` (${flagCount} flags)`;
      } else {
        mark = "\u2713";
        suffix = "";
      }
      lines.push(`    ${mark} ${displayName} — passing${suffix}`);
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
          if (first.includes(" via ")) {
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
