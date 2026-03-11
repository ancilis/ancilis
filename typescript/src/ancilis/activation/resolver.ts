/** Activation resolver — reads config, handles both paths, produces unified ActivationSpec. */

import {
  loadCertificationProfiles,
  loadOverlayProfiles,
  loadTaxonomy,
} from "./loader.js";

export const BASELINE_CONTROLS = new Set(["PR-01", "PR-02", "PR-03", "PR-04"]);
export const EXTENDED_CONTROLS = new Set(["PR-05", "DE-01"]);

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
  private taxonomy: Record<string, unknown>;

  constructor() {
    this.overlayProfiles = loadOverlayProfiles();
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

    // 1. Baseline controls
    for (const cid of [...BASELINE_CONTROLS].sort()) {
      spec.activeControls.push(cid);
      spec.controlThresholds[cid] = "standard";
      spec.activationSource[cid] = "baseline";
    }

    // 2. Path 1 — data classification
    if (options?.dataHandling && options.dataHandling.length > 0) {
      this.resolveDataPath(spec, options.dataHandling);
    }

    // 3. Path 2 — certification intent
    if (options?.certificationTargets && options.certificationTargets.length > 0) {
      this.resolveCertificationPath(spec, options.certificationTargets);
    }

    // 4. Activate extended controls if overlay or certification active
    if (spec.activeOverlays.length > 0 || spec.activeCertifications.length > 0) {
      for (const cid of [...EXTENDED_CONTROLS].sort()) {
        if (!spec.activeControls.includes(cid)) {
          spec.activeControls.push(cid);
          spec.controlThresholds[cid] ??= "standard";
          if (!spec.activationSource[cid]) {
            const sources: string[] = [];
            if (spec.activeOverlays.length > 0) sources.push(`overlay:${spec.activeOverlays[0]}`);
            if (spec.activeCertifications.length > 0) sources.push(`certification_targets:${spec.activeCertifications[0]}`);
            spec.activationSource[cid] = sources[0] ?? "extended";
          }
        }
      }
    }

    spec.activeControls = [...new Set(spec.activeControls)].sort();
    spec.activationSummary = this.buildSummary(spec);

    return spec;
  }

  private resolveDataPath(spec: ActivationSpec, dataHandling: string[]): void {
    const typeMapping = (this.taxonomy as Record<string, Record<string, string[]>>).developer_type_mapping ?? {};
    const classificationLookup = new Map<string, string[]>();
    for (const entry of ((this.taxonomy as Record<string, Array<Record<string, unknown>>>).classifications ?? [])) {
      classificationLookup.set(entry.code as string, (entry.overlays ?? []) as string[]);
    }

    const allDcCodes = new Set<string>();
    for (const dataType of dataHandling) {
      const dcCodes = typeMapping[dataType] ?? [];
      for (const dc of dcCodes) allDcCodes.add(dc);

      for (const dcCode of dcCodes) {
        const overlayIds = classificationLookup.get(dcCode) ?? [];
        for (const oid of overlayIds) {
          if (this.overlayProfiles.has(oid) && !spec.activeOverlays.includes(oid)) {
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
