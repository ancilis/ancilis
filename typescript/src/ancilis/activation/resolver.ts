/** Activation resolver — reads config, handles both paths, produces unified ActivationSpec. */

import {
  loadCertificationProfiles,
  loadOverlayProfiles,
  loadTaxonomy,
} from "./loader.js";
import type { LoadOverlayProfilesOptions } from "./loader.js";
import { normalizeOverlayIds } from "../overlays/index.js";

export const ALL_AKSI_CONTROLS = new Set([
  "GOV-01", "GOV-02", "GOV-03", "GOV-04",
  "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
  "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
  "DE-01", "DE-02", "DE-03", "DE-04",
  "RS-01", "RS-02", "RS-03",
  "RC-01", "RC-02",
]);
export const BASELINE_CONTROLS = ALL_AKSI_CONTROLS;
export const EXTENDED_CONTROLS = new Set<string>();

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

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export class ActivationResolver {
  private overlayProfiles: Map<string, Record<string, unknown>>;
  private taxonomy: Record<string, unknown>;

  constructor(options: LoadOverlayProfilesOptions = {}) {
    this.overlayProfiles = loadOverlayProfiles(options);
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

    // 1. All 26 AKSI controls are baseline
    for (const cid of [...ALL_AKSI_CONTROLS].sort()) {
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

    for (const [overlayId, profile] of this.overlayProfiles.entries()) {
      const triggerType = profile.trigger_type;
      if (triggerType !== "data_classification") continue;
      const triggeredBy = stringList(profile.triggered_by ?? profile.triggered_by_classifications);
      for (const classification of triggeredBy) {
        const overlayIds = classificationLookup.get(classification) ?? [];
        if (!overlayIds.includes(overlayId)) {
          overlayIds.push(overlayId);
          classificationLookup.set(classification, overlayIds);
        }
      }
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

    for (const cidTarget of certTargets) {
      const profile = certProfiles.get(cidTarget);
      if (!profile) continue;

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

    for (const [overlayId, profile] of this.overlayProfiles.entries()) {
      if (profile.trigger_type !== "certification_target") continue;
      const triggeredBy = stringList(profile.triggered_by);
      for (const target of certTargets) {
        if (!triggeredBy.includes(target)) continue;
        if (!spec.activeOverlays.includes(overlayId)) {
          spec.activeOverlays.push(overlayId);
          spec.activationSource[overlayId] = `certification_targets:${target}`;
        }
        this.applyOverlay(spec, profile, `overlay:${overlayId}`);
        const retention = (profile.evidence_retention_minimum_days as number) ?? 365;
        if (retention > spec.evidenceRetentionDays) {
          spec.evidenceRetentionDays = retention;
        }
        if (profile.human_oversight_required === true) {
          spec.humanOversightRequired = true;
        }
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
