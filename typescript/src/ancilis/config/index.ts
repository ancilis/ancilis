/**
 * Ancilis configuration parser — loads, validates, and resolves ancilis.yaml configs.
 */

import { z } from "zod";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { sharedPathFrom } from "../shared-path.js";

// Resolve shared/ directory relative to the installed package root
const SHARED_DIR = sharedPathFrom(import.meta.url);
const CONTROLS_DIR = join(SHARED_DIR, "controls");
const OVERLAYS_DIR = join(SHARED_DIR, "overlays");
const CERTIFICATIONS_DIR = join(OVERLAYS_DIR, "certifications");
const CLASSIFICATIONS_FILE = join(SHARED_DIR, "classifications", "taxonomy.json");

// --- Zod Schemas ---

const VALID_CONTROL_IDS = ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"] as const;

const ControlOverrideSchema = z.object({
  enabled: z.boolean().default(true),
});

const ToolsConfigSchema = z.object({
  allowed: z.array(z.string()).default([]),
  blocked: z.array(z.string()).default([]),
}).default({});

const ScopeConfigSchema = z.object({
  max_actions_per_minute: z.number().int().nullable().default(null),
  allowed_destinations: z.array(z.string()).default([]),
  blocked_destinations: z.array(z.string()).default([]),
}).default({});

const SecurityConfigSchema = z.object({
  mode: z.enum(["audit", "enforce"]).default("audit"),
  controls: z.record(z.string(), ControlOverrideSchema).default({}),
  tools: ToolsConfigSchema,
  scope: ScopeConfigSchema,
}).default({});

const EvidenceConfigSchema = z.object({
  storage: z.enum(["local"]).default("local"),
  retention_days: z.number().int().min(1).default(365),
}).default({});

const ComplianceConfigSchema = z.object({
  overlays: z.array(z.string()).nullable().default(null),
  evidence: EvidenceConfigSchema,
}).default({});

const ScanDependenciesConfigSchema = z.object({
  enabled: z.boolean().default(true),
  severity_threshold: z.enum(["critical", "high", "medium", "low"]).default("high"),
  ignore: z.array(z.string()).default([]),
}).default({});

const ScanConfigSchema = z.object({
  dependencies: ScanDependenciesConfigSchema,
}).default({});

const AncilisConfigSchema = z.object({
  agent: z.object({
    name: z.string().min(1, "agent.name must be a non-empty string"),
    description: z.string().default(""),
    owner: z.string().default(""),
    llm_provider: z.string().nullable().default(null),
  }),
  security: SecurityConfigSchema,
  my_agent_handles: z.array(z.string()).default([]),
  certification_targets: z.array(z.string()).default([]),
  compliance: ComplianceConfigSchema,
  scan: ScanConfigSchema,
});

type AncilisConfig = z.infer<typeof AncilisConfigSchema>;

// --- Shared JSON Loaders ---

interface ControlDefinition {
  id: string;
  name: string;
  function: string;
  csf_mapping: string;
  description: string;
  default_enabled: boolean;
  baseline: boolean;
  [key: string]: unknown;
}

interface OverlayDefinition {
  id: string;
  name: string;
  triggered_by_classifications: string[];
  control_adjustments: Record<string, {
    threshold_adjustment: string;
    additional_evidence_fields: string[];
    regulatory_citation: string;
  }>;
  evidence_retention_minimum_days: number;
  human_oversight_required: boolean;
  [key: string]: unknown;
}

interface ClassificationEntry {
  code: string;
  name: string;
  description: string;
  overlays: string[];
}

interface Taxonomy {
  version: string;
  classifications: ClassificationEntry[];
  developer_type_mapping: Record<string, string[]>;
}

function loadControlDefinitions(): Map<string, ControlDefinition> {
  const controls = new Map<string, ControlDefinition>();
  const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8")) as ControlDefinition;
    controls.set(data.id, data);
  }
  return controls;
}

function loadOverlayDefinitions(): Map<string, OverlayDefinition> {
  const overlays = new Map<string, OverlayDefinition>();
  const files = readdirSync(OVERLAYS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(OVERLAYS_DIR, file), "utf-8")) as OverlayDefinition;
    overlays.set(data.id, data);
  }
  return overlays;
}

function loadTaxonomy(): Taxonomy {
  return JSON.parse(readFileSync(CLASSIFICATIONS_FILE, "utf-8")) as Taxonomy;
}

function loadValidCertTargets(): Set<string> {
  const targets = new Set<string>();
  try {
    const files = readdirSync(CERTIFICATIONS_DIR).filter(f => f.endsWith(".json"));
    for (const file of files) {
      targets.add(file.replace(".json", ""));
    }
  } catch { /* dir may not exist */ }
  return targets;
}

// --- Resolution Result ---

export interface ControlStatus {
  controlId: string;
  name: string;
  enabled: boolean;
  threshold: string;
  overlayCitations: string[];
}

export interface OverlayActivation {
  overlayId: string;
  name: string;
  triggeredBy: string[];
}

export interface UnavailableOverlay {
  overlayId: string;
  triggeredBy: string;
  dataType: string;
}

export interface ResolvedConfig {
  agentName: string;
  agentOwner: string;
  mode: string;
  controls: Map<string, ControlStatus>;
  dataClassifications: Map<string, string[]>;
  activeOverlays: Map<string, OverlayActivation>;
  unavailableOverlays: UnavailableOverlay[];
  overlayAdjustments: string[];
  evidenceRetentionDays: number;
  humanOversightRequired: boolean;
  warnings: string[];
  toolsAllowed: string[];
  toolsBlocked: string[];
  scopeMaxActionsPerMinute: number | null;
  scopeAllowedDestinations: string[];
  scopeBlockedDestinations: string[];
  activeCertifications: string[];
  llmProvider: string | null;
  scanDependenciesEnabled: boolean;
  scanDependenciesSeverityThreshold: "critical" | "high" | "medium" | "low";
  scanDependenciesIgnore: string[];
}

// --- Validation ---

function validateConfig(raw: Record<string, unknown>): { config: AncilisConfig; warnings: string[] } {
  const warnings: string[] = [];

  // Check for unknown top-level keys
  const knownKeys = new Set(["agent", "security", "my_agent_handles", "certification_targets", "compliance", "scan"]);
  for (const key of Object.keys(raw)) {
    if (!knownKeys.has(key)) {
      warnings.push(`Unknown top-level key: '${key}'`);
    }
  }

  // Validate control IDs in overrides
  const security = raw.security as Record<string, unknown> | undefined;
  if (security && typeof security === "object") {
    const controls = security.controls as Record<string, unknown> | undefined;
    if (controls && typeof controls === "object") {
      const validIds = new Set<string>(VALID_CONTROL_IDS);
      for (const key of Object.keys(controls)) {
        if (!validIds.has(key)) {
          throw new Error(`Unknown control ID in security.controls: '${key}'`);
        }
      }
    }
  }

  // Validate my_agent_handles types
  const taxonomy = loadTaxonomy();
  const validTypes = new Set(Object.keys(taxonomy.developer_type_mapping));
  const dataHandling = raw.my_agent_handles as string[] | undefined;
  if (Array.isArray(dataHandling)) {
    for (const dt of dataHandling) {
      if (!validTypes.has(dt)) {
        throw new Error(
          `Unknown data type in my_agent_handles: '${dt}'. ` +
          `Valid types: ${[...validTypes].sort().join(", ")}`
        );
      }
    }
  }

  // Validate certification_targets
  const certTargets = raw.certification_targets as string[] | undefined;
  if (Array.isArray(certTargets)) {
    const validCerts = loadValidCertTargets();
    for (const ct of certTargets) {
      if (!validCerts.has(ct)) {
        const available = validCerts.size > 0 ? [...validCerts].sort().join(", ") : "none available";
        warnings.push(
          `certification_targets contains unrecognized value '${ct}'. ` +
          `Available targets: ${available}`
        );
      }
    }
  }

  const config = AncilisConfigSchema.parse(raw);
  return { config, warnings };
}

// --- Config Resolution ---

function resolveConfig(config: AncilisConfig, warnings: string[]): ResolvedConfig {
  const result: ResolvedConfig = {
    agentName: config.agent.name,
    agentOwner: config.agent.owner,
    mode: config.security.mode,
    controls: new Map(),
    dataClassifications: new Map(),
    activeOverlays: new Map(),
    unavailableOverlays: [],
    overlayAdjustments: [],
    evidenceRetentionDays: config.compliance.evidence.retention_days,
    humanOversightRequired: false,
    warnings,
    toolsAllowed: [...config.security.tools.allowed],
    toolsBlocked: [...config.security.tools.blocked],
    scopeMaxActionsPerMinute: config.security.scope.max_actions_per_minute,
    scopeAllowedDestinations: [...config.security.scope.allowed_destinations],
    scopeBlockedDestinations: [...config.security.scope.blocked_destinations],
    activeCertifications: [],
    llmProvider: config.agent.llm_provider,
    scanDependenciesEnabled: config.scan.dependencies.enabled,
    scanDependenciesSeverityThreshold: config.scan.dependencies.severity_threshold,
    scanDependenciesIgnore: [...config.scan.dependencies.ignore],
  };

  const controlDefs = loadControlDefinitions();
  const overlayDefs = loadOverlayDefinitions();
  const taxonomy = loadTaxonomy();

  // Resolve controls
  for (const [cid, cdef] of [...controlDefs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const override = config.security.controls[cid];
    const enabled = override ? override.enabled : (cdef.default_enabled ?? true);
    result.controls.set(cid, {
      controlId: cid,
      name: cdef.name,
      enabled,
      threshold: "standard",
      overlayCitations: [],
    });
  }

  // Resolve data classifications
  for (const dataType of config.my_agent_handles) {
    const dcCodes = taxonomy.developer_type_mapping[dataType] ?? [];
    result.dataClassifications.set(dataType, dcCodes);
  }

  // Collect all DC codes
  const allDcCodes = new Set<string>();
  for (const codes of result.dataClassifications.values()) {
    for (const code of codes) {
      allDcCodes.add(code);
    }
  }

  // Build classification-to-overlay lookup
  const classificationLookup = new Map<string, string[]>();
  for (const entry of taxonomy.classifications) {
    classificationLookup.set(entry.code, entry.overlays);
  }

  // Determine which overlays should activate
  const overlayTriggers = new Map<string, string[]>();
  for (const [dataType, dcCodes] of result.dataClassifications) {
    for (const dcCode of dcCodes) {
      const overlayIds = classificationLookup.get(dcCode) ?? [];
      for (const oid of overlayIds) {
        if (!overlayTriggers.has(oid)) {
          overlayTriggers.set(oid, []);
        }
        const triggerStr = `${dcCode} via ${dataType}`;
        const triggers = overlayTriggers.get(oid)!;
        if (!triggers.includes(triggerStr)) {
          triggers.push(triggerStr);
        }
      }
    }
  }

  // If compliance.overlays is set, filter
  let filteredTriggers: Map<string, string[]>;
  if (config.compliance.overlays !== null) {
    const explicitOverlays = new Set(config.compliance.overlays);
    filteredTriggers = new Map<string, string[]>();
    for (const [k, v] of overlayTriggers) {
      if (explicitOverlays.has(k)) {
        filteredTriggers.set(k, v);
      }
    }
    for (const oid of explicitOverlays) {
      if (!filteredTriggers.has(oid)) {
        filteredTriggers.set(oid, []);
      }
    }
  } else {
    filteredTriggers = overlayTriggers;
  }

  // Activate overlays
  const availableOverlayIds = new Set(overlayDefs.keys());
  for (const [oid, triggers] of [...filteredTriggers.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (availableOverlayIds.has(oid)) {
      const odef = overlayDefs.get(oid)!;
      result.activeOverlays.set(oid, {
        overlayId: oid,
        name: odef.name,
        triggeredBy: triggers,
      });
    } else {
      for (const trigger of triggers) {
        const parts = trigger.split(" via ");
        const dcCode = parts[0]!;
        const dataType = parts.length > 1 ? parts[1]! : "unknown";
        result.unavailableOverlays.push({
          overlayId: oid,
          triggeredBy: dcCode,
          dataType,
        });
      }
    }
  }

  // Apply overlay adjustments
  let maxRetention = config.compliance.evidence.retention_days;
  for (const [oid] of result.activeOverlays) {
    const odef = overlayDefs.get(oid)!;
    const adjustments = odef.control_adjustments ?? {};
    for (const [cid, adj] of Object.entries(adjustments)) {
      const control = result.controls.get(cid);
      if (control && control.enabled) {
        const threshold = adj.threshold_adjustment ?? "standard";
        const citation = adj.regulatory_citation ?? "";
        if (threshold === "strict" && control.threshold !== "strict") {
          control.threshold = "strict";
        }
        control.overlayCitations.push(citation);
        if (threshold === "strict") {
          result.overlayAdjustments.push(`${cid}: threshold -> strict (${citation})`);
        }
      }
    }

    const retention = odef.evidence_retention_minimum_days ?? 365;
    if (retention > maxRetention) {
      maxRetention = retention;
    }

    if (odef.human_oversight_required) {
      result.humanOversightRequired = true;
    }
  }
  result.evidenceRetentionDays = maxRetention;

  // Resolve certification targets
  const validCerts = loadValidCertTargets();
  for (const ct of config.certification_targets) {
    if (validCerts.has(ct)) {
      result.activeCertifications.push(ct);
    }
  }

  return result;
}

// --- Public API ---

export interface LoadConfigOptions {
  path?: string;
  raw?: Record<string, unknown>;
}

export function loadConfig(options: LoadConfigOptions = {}): ResolvedConfig {
  let configDict: Record<string, unknown>;

  if (options.raw !== undefined) {
    configDict = { ...options.raw };
  } else if (options.path !== undefined) {
    const content = readFileSync(options.path, "utf-8");
    configDict = (parseYaml(content) ?? {}) as Record<string, unknown>;
  } else {
    throw new Error("No config path or raw config provided");
  }

  const { config, warnings } = validateConfig(configDict);
  return resolveConfig(config, warnings);
}

export function formatResolvedConfig(resolved: ResolvedConfig): string {
  const lines: string[] = [];
  lines.push("Ancilis Configuration Loaded");
  lines.push("-".repeat(32));
  lines.push(`Agent: ${resolved.agentName}`);
  lines.push(`Mode: ${resolved.mode}`);
  lines.push("");

  const active = [...resolved.controls.values()].filter(c => c.enabled).length;
  const total = resolved.controls.size;
  lines.push(`Baseline Controls (${active}/${total} active):`);
  for (const [, cs] of [...resolved.controls.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const mark = cs.enabled ? "+" : "-";
    lines.push(`  ${mark} ${cs.controlId}  ${cs.name}`);
  }
  lines.push("");

  if (resolved.dataClassifications.size > 0) {
    lines.push("Data Classifications:");
    for (const [dt, codes] of [...resolved.dataClassifications.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`  ${dt} -> ${codes.join(", ")}`);
    }
    lines.push("");
  }

  if (resolved.activeOverlays.size > 0) {
    lines.push("Active Overlays:");
    for (const [, oa] of [...resolved.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const triggers = oa.triggeredBy.length > 0 ? oa.triggeredBy.join(", ") : "explicit";
      lines.push(`  + ${oa.name} (triggered by ${triggers})`);
    }
    lines.push("");
  }

  if (resolved.unavailableOverlays.length > 0) {
    lines.push("Unavailable Overlays (roadmap):");
    for (const uo of resolved.unavailableOverlays) {
      lines.push(`  ? ${uo.overlayId} would be activated by ${uo.triggeredBy} via ${uo.dataType} but is not yet available`);
    }
    lines.push("");
  }

  if (resolved.overlayAdjustments.length > 0) {
    lines.push("Overlay Adjustments Applied:");
    for (const adj of resolved.overlayAdjustments) {
      lines.push(`  ${adj}`);
    }
    lines.push(`  Evidence retention: ${resolved.evidenceRetentionDays} days`);
    if (resolved.humanOversightRequired) {
      lines.push("  Human oversight: REQUIRED");
    }
    lines.push("");
  }

  if (resolved.warnings.length > 0) {
    lines.push("Warnings:");
    for (const w of resolved.warnings) {
      lines.push(`  ! ${w}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
