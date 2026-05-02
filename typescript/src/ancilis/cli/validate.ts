/** ancilis config validate — config validation with actionable errors. */

import { inspectConfigFileMigration, loadConfig, migrateConfigFile } from "../config/index.js";

export interface ConfigValidateOptions {
  verbose?: boolean;
}

export interface ConfigMigrateOptions {
  apply?: boolean;
}

export function validateAndFormat(configPath?: string, options: ConfigValidateOptions = {}): { valid: boolean; message: string } {
  const lines: string[] = [];

  try {
    const migration = configPath ? inspectConfigFileMigration(configPath) : null;
    const raw = configPath ? { path: configPath } : undefined;
    const resolved = loadConfig(raw ?? {});

    lines.push("\u2713 Config valid");
    lines.push(`  Config version: ${resolved.configVersion ?? "unknown"}`);
    lines.push(`  Agent: ${resolved.agentName}`);
    lines.push(`  Mode: ${resolved.mode}`);

    if (migration?.changed) {
      lines.push(`  Migration available: v${migration.originalVersion} -> v${migration.currentVersion}`);
      for (const change of migration.changes) {
        lines.push(`    - ${change}`);
      }
      lines.push("    Run `ancilis config migrate --apply` to write the migrated config and backup.");
    }

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

    if (resolved.warnings.length > 0) {
      lines.push("  Warnings:");
      for (const warning of resolved.warnings) {
        lines.push(`    - ${warning}`);
      }
    }

    if (options.verbose) {
      lines.push("  Schema:");
      lines.push("    shared/schemas/config.schema.json");
      lines.push("  Active overlays:");
      if (resolved.activeOverlays.size === 0) {
        lines.push("    - none");
      } else {
        for (const [overlayId, overlay] of [...resolved.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
          const trigger = overlay.triggeredBy.length > 0 ? overlay.triggeredBy.join(", ") : "manual";
          lines.push(`    - ${overlayId}: ${overlay.name} (${trigger})`);
        }
      }
      lines.push("  Enabled controls:");
      for (const control of enabledControls(resolved)) {
        lines.push(`    - ${control.controlId}: ${control.name}`);
      }
    }

    return { valid: true, message: lines.join("\n") };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    lines.push("\u2717 Config invalid");
    lines.push(`  ${msg}`);
    return { valid: false, message: lines.join("\n") };
  }
}

function enabledControls(resolved: ReturnType<typeof loadConfig>): Array<{ controlId: string; name: string }> {
  return [...resolved.controls.values()]
    .filter(control => control.enabled)
    .sort((a, b) => a.controlId.localeCompare(b.controlId))
    .map(control => ({ controlId: control.controlId, name: control.name }));
}

export function migrateAndFormat(configPath: string, options: ConfigMigrateOptions = {}): { ok: boolean; message: string } {
  const lines: string[] = [];

  try {
    const result = migrateConfigFile(configPath, { apply: options.apply });
    if (!result.changed) {
      return {
        ok: true,
        message: `Config already at version ${result.currentVersion}; no migration needed.`,
      };
    }

    lines.push(
      options.apply
        ? `Migrated ${configPath} from v${result.originalVersion} to v${result.currentVersion}.`
        : `Preview migration for ${configPath}: v${result.originalVersion} -> v${result.currentVersion}.`,
    );
    for (const change of result.changes) {
      lines.push(`  - ${change}`);
    }
    if (options.apply) {
      lines.push(`Backup written to ${result.backupPath}`);
    } else {
      lines.push("Run `ancilis config migrate --apply` to write these changes.");
    }

    return { ok: true, message: lines.join("\n") };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, message: `Config migration failed\n  ${msg}` };
  }
}
