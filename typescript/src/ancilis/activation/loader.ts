/** Loads overlay profiles and certification profiles from shared JSON data files. */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { sharedPathFrom } from "../shared-path.js";
import { type PluginContext, PluginRegistry } from "../plugins/index.js";

const SHARED_DIR = sharedPathFrom(import.meta.url);
const OVERLAYS_DIR = join(SHARED_DIR, "overlays");
const CERTIFICATIONS_DIR = join(OVERLAYS_DIR, "certifications");
const CONTROLS_DIR = join(SHARED_DIR, "controls");
const CLASSIFICATIONS_FILE = join(SHARED_DIR, "classifications", "taxonomy.json");

export interface LoadOverlayProfilesOptions {
  readonly pluginRegistry?: PluginRegistry;
  readonly pluginConfigs?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly warnings?: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function warnOverlay(pluginName: string, detail: string, warnings?: string[]): void {
  const message = `Skipping Ancilis plugin overlay ${pluginName}: ${detail}`;
  warnings?.push(message);
}

function validatedPluginOverlayProfile(
  pluginName: string,
  rawProfile: unknown,
  warnings?: string[],
): Record<string, unknown> | null {
  if (!isRecord(rawProfile)) {
    warnOverlay(pluginName, "overlay profile must be a mapping", warnings);
    return null;
  }

  const overlayId = rawProfile.id;
  if (
    typeof overlayId !== "string"
    || !overlayId.startsWith("plugin:")
    || overlayId.slice("plugin:".length).trim().length === 0
  ) {
    warnOverlay(pluginName, "overlay id must be explicit and namespaced as plugin:<name>", warnings);
    return null;
  }

  for (const fieldName of ["name", "trigger_type"] as const) {
    const value = rawProfile[fieldName];
    if (typeof value !== "string" || value.trim().length === 0) {
      warnOverlay(pluginName, `overlay profile missing required '${fieldName}' field`, warnings);
      return null;
    }
  }

  for (const fieldName of ["triggered_by", "applicable_data_types"] as const) {
    const value = rawProfile[fieldName];
    if (value !== undefined && value !== null && !isStringList(value)) {
      warnOverlay(pluginName, `overlay profile field '${fieldName}' must be a list of strings`, warnings);
      return null;
    }
  }

  for (const fieldName of ["control_adjustments", "evidence_requirements", "controls"] as const) {
    const value = rawProfile[fieldName];
    if (value !== undefined && value !== null && !isRecord(value)) {
      warnOverlay(pluginName, `overlay profile field '${fieldName}' must be a mapping`, warnings);
      return null;
    }
  }

  const controlAdjustments = rawProfile.control_adjustments;
  if (isRecord(controlAdjustments)) {
    for (const [controlId, adjustment] of Object.entries(controlAdjustments)) {
      if (!isRecord(adjustment)) {
        warnOverlay(pluginName, `overlay profile field 'control_adjustments.${controlId}' must be a mapping`, warnings);
        return null;
      }
    }
  }

  const evidenceRequirements = rawProfile.evidence_requirements;
  if (isRecord(evidenceRequirements)) {
    for (const [controlId, requirements] of Object.entries(evidenceRequirements)) {
      if (!isStringList(requirements)) {
        warnOverlay(pluginName, `overlay profile field 'evidence_requirements.${controlId}' must be a list of strings`, warnings);
        return null;
      }
    }
  }

  const controls = rawProfile.controls;
  if (isRecord(controls)) {
    for (const [controlId, controlData] of Object.entries(controls)) {
      if (!isRecord(controlData)) {
        warnOverlay(pluginName, `overlay profile field 'controls.${controlId}' must be a mapping`, warnings);
        return null;
      }
      const controlRequirements = controlData.evidence_requirements;
      if (controlRequirements !== undefined && controlRequirements !== null && !isStringList(controlRequirements)) {
        warnOverlay(pluginName, `overlay profile field 'controls.${controlId}.evidence_requirements' must be a list of strings`, warnings);
        return null;
      }
    }
  }

  const retentionDays = rawProfile.evidence_retention_minimum_days;
  if (retentionDays !== undefined && (!Number.isInteger(retentionDays) || typeof retentionDays !== "number")) {
    warnOverlay(pluginName, "overlay profile field 'evidence_retention_minimum_days' must be an integer", warnings);
    return null;
  }

  const humanOversightRequired = rawProfile.human_oversight_required;
  if (humanOversightRequired !== undefined && typeof humanOversightRequired !== "boolean") {
    warnOverlay(pluginName, "overlay profile field 'human_oversight_required' must be a boolean", warnings);
    return null;
  }

  return { ...rawProfile };
}

function mergePluginOverlayProfiles(
  profiles: Map<string, Record<string, unknown>>,
  options: LoadOverlayProfilesOptions,
): void {
  const pluginRegistry = options.pluginRegistry;
  if (!pluginRegistry) return;

  for (const record of pluginRegistry.compatible("overlay")) {
    const pluginName = record.name;
    const loadedPlugin = record.plugin;
    if (!isRecord(loadedPlugin)) {
      warnOverlay(pluginName, "has no plugin object and was skipped", options.warnings);
      continue;
    }
    if (typeof loadedPlugin.loadOverlayProfile !== "function") {
      warnOverlay(pluginName, "does not implement the overlay plugin contract", options.warnings);
      continue;
    }

    const context: PluginContext = {
      sdkVersion: pluginRegistry.sdkVersion,
      config: options.pluginConfigs?.[pluginName] ?? {},
    };

    let rawProfile: unknown;
    try {
      rawProfile = loadedPlugin.loadOverlayProfile(context);
    } catch (error: unknown) {
      warnOverlay(
        pluginName,
        `failed to load overlay profile: ${(error as Error).message ?? String(error)}`,
        options.warnings,
      );
      continue;
    }

    const profile = validatedPluginOverlayProfile(pluginName, rawProfile, options.warnings);
    if (!profile) continue;

    const overlayId = profile.id as string;
    if (profiles.has(overlayId)) {
      warnOverlay(
        pluginName,
        `overlay id '${overlayId}' collides with an existing overlay and was skipped`,
        options.warnings,
      );
      continue;
    }
    profiles.set(overlayId, profile);
  }
}

export function loadOverlayProfiles(options: LoadOverlayProfilesOptions = {}): Map<string, Record<string, unknown>> {
  const profiles = new Map<string, Record<string, unknown>>();
  const files = readdirSync(OVERLAYS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(OVERLAYS_DIR, file), "utf-8"));
    profiles.set(data.id, data);
  }
  mergePluginOverlayProfiles(profiles, options);
  return profiles;
}

export function loadCertificationProfile(certId: string): Record<string, unknown> | null {
  const path = join(CERTIFICATIONS_DIR, `${certId}.json`);
  if (!existsSync(path)) {
    return null;
  }
  const data = JSON.parse(readFileSync(path, "utf-8"));
  if (!("version" in data)) {
    return null;
  }
  return data;
}

export function loadCertificationProfiles(certIds: string[]): Map<string, Record<string, unknown>> {
  const profiles = new Map<string, Record<string, unknown>>();
  for (const cid of certIds) {
    const profile = loadCertificationProfile(cid);
    if (profile !== null) {
      profiles.set(cid, profile);
    }
  }
  return profiles;
}

export function loadControlDefinitions(): Map<string, Record<string, unknown>> {
  const controls = new Map<string, Record<string, unknown>>();
  const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8"));
    controls.set(data.id, data);
  }
  return controls;
}

export function loadTaxonomy(): Record<string, unknown> {
  return JSON.parse(readFileSync(CLASSIFICATIONS_FILE, "utf-8"));
}
