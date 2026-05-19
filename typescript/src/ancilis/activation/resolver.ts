/** Activation resolver — reads config, handles both paths, produces unified ActivationSpec. */

import {
  loadCertificationProfiles,
  loadControlDefinitions,
  loadOverlayProfiles,
  loadTaxonomy,
} from "./loader.js";
import { normalizeOverlayIds } from "../overlays/index.js";

export const COMMON_AKSI_CONTROLS = new Set([
  "GOV-01", "GOV-02", "GOV-03", "GOV-04", "GOV-05", "GOV-06", "GOV-07",
  "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
  "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
  "PR-09", "PR-10", "PR-11", "PR-12",
  "DE-01", "DE-02", "DE-03", "DE-04", "DE-05", "DE-06",
  "RS-01", "RS-02", "RS-03", "RS-04", "RS-05", "RS-06",
  "RC-01", "RC-02", "RC-03",
]);
export const EXTENDED_CONTROLS = new Set(["PAY-01", "PAY-02"]);
export const ALL_AKSI_CONTROLS = new Set([...COMMON_AKSI_CONTROLS, ...EXTENDED_CONTROLS]);
export const BASELINE_CONTROLS = COMMON_AKSI_CONTROLS;

export interface ActivationSpec {
  activeControls: string[];
  activeOverlays: string[];
  activeCertifications: string[];
  dataClassifications: string[];
  controlThresholds: Record<string, string>;
  evidenceRequirements: Record<string, string[]>;
  activationSource: Record<string, string>;
  activationSummary: string[];
  evidenceRetentionDays: number;
  humanOversightRequired: boolean;
}

export class ActivationResolver {
  private overlayProfiles: Map<string, Record<string, unknown>>;
  private controlDefs: Map<string, Record<string, unknown>>;
  private taxonomy: Record<string, unknown>;

  constructor() {
    this.overlayProfiles = loadOverlayProfiles();
    this.controlDefs = loadControlDefinitions();
    this.taxonomy = loadTaxonomy();
  }

  resolve(options?: {
    dataHandling?: string[];
    certificationTargets?: string[];
  }): ActivationSpec {
    const spec: ActivationSpec = {
      activeControls: [],
      activeOverlays: [],
      activeCertifications: [],
      dataClassifications: [],
      controlThresholds: {},
      evidenceRequirements: {},
      activationSource: {},
      activationSummary: [],
      evidenceRetentionDays: 365,
      humanOversightRequired: false,
    };

    // 1. AKSI v0.6 common controls are baseline.
    for (const cid of [...COMMON_AKSI_CONTROLS].sort()) {
      spec.activeControls.push(cid);
      spec.controlThresholds[cid] = "standard";
      spec.activationSource[cid] = "baseline";
    }

    // 2. NIST CSF baseline overlay is always active
    const nistCsf = this.overlayProfiles.get("nist-csf");
    if (nistCsf?.trigger_type === "baseline") {
      spec.activeOverlays.push("nist-csf");
      spec.activationSource["nist-csf"] = "baseline";
    }

    // 3. Path 1 — data classification
    if (options?.dataHandling && options.dataHandling.length > 0) {
      this.resolveDataPath(spec, options.dataHandling);
    }

    // 4. Path 2 — certification intent
    if (options?.certificationTargets && options.certificationTargets.length > 0) {
      this.resolveCertificationPath(spec, options.certificationTargets);
    }

    this.activateExtensionControls(spec, {
      classifications: new Set(spec.dataClassifications),
      certificationTargets: new Set(options?.certificationTargets ?? []),
    });

    spec.activeControls = [...new Set(spec.activeControls)].sort();
    spec.activationSummary = this.buildSummary(spec);

    return spec;
  }

  private resolveDataPath(spec: ActivationSpec, dataHandling: string[]): void {
    const typeMapping = (this.taxonomy as Record<string, Record<string, string[]>>).developer_type_mapping ?? {};
    const classificationLookup = new Map<string, string[]>();
    for (const entry of ((this.taxonomy as Record<string, Array<Record<string, unknown>>>).classifications ?? [])) {
      classificationLookup.set(entry.code as string, normalizeOverlayIds((entry.overlays ?? []) as string[]));
    }

    const allDcCodes = new Set<string>();
    for (const dataType of dataHandling) {
      const dcCodes = typeMapping[dataType] ?? [];
      for (const dc of dcCodes) allDcCodes.add(dc);

      for (const dcCode of dcCodes) {
        const overlayIds = classificationLookup.get(dcCode) ?? [];
        for (const oid of overlayIds) {
          const profile = this.overlayProfiles.get(oid);
          if (profile?.trigger_type === "baseline") {
            continue;
          }

          if (profile && !spec.activeOverlays.includes(oid)) {
            spec.activeOverlays.push(oid);
            spec.activationSource[oid] = `my_agent_handles:${dataType}`;
          }
        }
      }
    }

    spec.dataClassifications = [...allDcCodes].sort();

    let maxRetention = spec.evidenceRetentionDays;
    for (const oid of spec.activeOverlays) {
      const profile = this.overlayProfiles.get(oid)!;
      this.applyOverlay(spec, profile, `overlay:${oid}`);

      const retention = (profile.evidence_retention_minimum_days as number) ?? 365;
      if (retention > maxRetention) maxRetention = retention;

      if (profile.human_oversight_required === true) {
        spec.humanOversightRequired = true;
      }
    }
    spec.evidenceRetentionDays = maxRetention;
  }

  private resolveCertificationPath(spec: ActivationSpec, certTargets: string[]): void {
    const certProfiles = loadCertificationProfiles(certTargets);
    const extensionTargets = this.extensionCertificationTargets();

    for (const cidTarget of certTargets) {
      const profile = certProfiles.get(cidTarget);
      if (!profile) {
        if (!extensionTargets.has(normalizeCertificationTarget(cidTarget))) {
          continue;
        }
        continue;
      }

      spec.activeCertifications.push(cidTarget);

      const required = (profile.required_aksi_controls ?? []) as string[];
      for (const controlId of required) {
        if (!spec.activeControls.includes(controlId)) {
          spec.activeControls.push(controlId);
        }
        if (!spec.activationSource[controlId] || spec.activationSource[controlId] === "baseline") {
          spec.activationSource[controlId] = `certification_targets:${cidTarget}`;
        }
        spec.controlThresholds[controlId] ??= "standard";
      }

      const evidencePackaging = (profile.evidence_packaging ?? {}) as Record<string, unknown>;
      const retention = (evidencePackaging.retention_days as number) ?? 365;
      if (retention > spec.evidenceRetentionDays) {
        spec.evidenceRetentionDays = retention;
      }
    }
  }

  private extensionCertificationTargets(): Set<string> {
    const targets = new Set<string>();
    for (const controlDef of this.controlDefs.values()) {
      if (controlDef.common !== false) continue;
      for (const target of ((controlDef.trigger_certification_targets as string[] | undefined) ?? [])) {
        targets.add(target);
      }
    }
    return targets;
  }

  private activateExtensionControls(
    spec: ActivationSpec,
    scope: { classifications: Set<string>; certificationTargets: Set<string> },
  ): void {
    const normalizedTargets = new Set([...scope.certificationTargets].map(normalizeCertificationTarget));
    for (const [controlId, controlDef] of [...this.controlDefs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      if (controlDef.common !== false) continue;
      const triggerClasses = new Set((controlDef.trigger_classifications as string[] | undefined) ?? []);
      const triggerTargets = new Set((controlDef.trigger_certification_targets as string[] | undefined) ?? []);
      const classMatches = [...triggerClasses].filter(code => scope.classifications.has(code)).sort();
      const targetMatches = [...triggerTargets].filter(target => normalizedTargets.has(target)).sort();
      if (classMatches.length === 0 && targetMatches.length === 0) continue;
      if (!spec.activeControls.includes(controlId)) {
        spec.activeControls.push(controlId);
      }
      spec.controlThresholds[controlId] ??= "standard";
      if (classMatches.length > 0) {
        spec.activationSource[controlId] = `classification:${classMatches[0]}`;
      } else if (targetMatches.length > 0) {
        spec.activationSource[controlId] = `certification_targets:${firstOriginalCertificationTarget(scope.certificationTargets, targetMatches[0]!)}`;
      }
    }
  }

  private applyOverlay(spec: ActivationSpec, profile: Record<string, unknown>, source: string): void {
    const adjustments = (profile.control_adjustments ?? {}) as Record<string, Record<string, unknown>>;
    for (const [controlId, adj] of Object.entries(adjustments)) {
      const threshold = (adj.threshold_adjustment as string) ?? "standard";
      const current = spec.controlThresholds[controlId] ?? "standard";
      if (threshold === "strict" && current !== "strict") {
        spec.controlThresholds[controlId] = "strict";
        spec.activationSource[`${controlId}_threshold`] = source;
      }
      if (!spec.activeControls.includes(controlId)) {
        spec.activeControls.push(controlId);
      }
    }

    const evidenceReqs = (profile.evidence_requirements ?? {}) as Record<string, string[]>;
    for (const [controlId, reqs] of Object.entries(evidenceReqs)) {
      const existing = spec.evidenceRequirements[controlId] ?? [];
      const merged = [...existing];
      for (const req of reqs) {
        if (!merged.includes(req)) merged.push(req);
      }
      spec.evidenceRequirements[controlId] = merged;
    }
  }

  private buildSummary(spec: ActivationSpec): string[] {
    const summary: string[] = [];

    for (const certId of spec.activeCertifications) {
      const count = spec.activeControls.length;
      summary.push(`${certId.toUpperCase()} certification active — ${count} controls enforcing`);
    }

    for (const oid of spec.activeOverlays) {
      const profile = this.overlayProfiles.get(oid);
      const name = (profile?.name as string) ?? oid;
      const sourceKey = spec.activationSource[oid] ?? "";
      if (profile?.trigger_type === "baseline") {
        continue;
      }
      let triggered = "";
      if (sourceKey.includes("my_agent_handles:")) {
        const dataType = sourceKey.split(":")[1];
        triggered = ` — triggered by ${dataType} declaration`;
      }
      summary.push(`${name} overlay active${triggered}`);
    }

    if (summary.length === 0) {
      summary.push(`Baseline security active — ${spec.activeControls.length} controls enforcing`);
    }

    return summary;
  }
}

function normalizeCertificationTarget(target: string): string {
  return target.toUpperCase().replaceAll("-", "_");
}

function firstOriginalCertificationTarget(
  targets: Set<string>,
  normalizedTarget: string,
): string {
  for (const target of targets) {
    if (normalizeCertificationTarget(target) === normalizedTarget) {
      return target;
    }
  }
  return normalizedTarget;
}
