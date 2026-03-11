/** ancilis config validate — config validation with actionable errors. */

import { loadConfig } from "../config/index.js";

export function validateAndFormat(configPath?: string): { valid: boolean; message: string } {
  const lines: string[] = [];

  try {
    const raw = configPath ? { path: configPath } : undefined;
    const resolved = loadConfig(raw ?? {});

    lines.push("\u2713 Config valid");
    lines.push(`  Agent: ${resolved.agentName}`);
    lines.push(`  Mode: ${resolved.mode}`);

    // Activation summary
    const activationLines: string[] = [];
    for (const certId of resolved.activeCertifications) {
      const enabledCount = [...resolved.controls.values()].filter(c => c.enabled).length;
      activationLines.push(`    certification_targets: [${certId}] \u2192 ${certId.toUpperCase()} active, ${enabledCount} controls`);
    }
    for (const [, oa] of [...resolved.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const trigger = oa.triggeredBy.length > 0 ? oa.triggeredBy.join(", ") : "explicit";
      activationLines.push(`    ${oa.name} overlay active (triggered by ${trigger})`);
    }

    if (activationLines.length > 0) {
      lines.push("  Activation:");
      lines.push(...activationLines);
    }

    const enabled = [...resolved.controls.values()].filter(c => c.enabled).length;
    lines.push(`  Controls: ${enabled} active`);

    return { valid: true, message: lines.join("\n") };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    lines.push("\u2717 Config invalid");
    lines.push(`  ${msg}`);
    return { valid: false, message: lines.join("\n") };
  }
}
