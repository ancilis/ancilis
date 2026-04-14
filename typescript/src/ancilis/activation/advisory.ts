/** Classification advisory and certification upgrade advisory. */

import { loadOverlayProfiles, loadTaxonomy } from "./loader.js";
import { normalizeOverlayIds } from "../overlays/index.js";

export interface ClassificationRecommendation {
  detectedPattern: string;
  suggestedConfigField: string;
  suggestedValue: string;
  projectedOverlays: string[];
  projectedControls: string[];
  detectionCount: number;
  confidence: string;
  severity: string;
  exampleConfig: string;
}

export interface CertificationUpgradeAdvisory {
  certificationId: string;
  message: string;
  suggestedConfigAddition: Record<string, unknown>;
  aiuc1DomainsStrengthened: string[];
  severity: string;
}

export interface PatternDetection {
  patternType: string;
  count: number;
}

const PATTERN_TO_DATA_TYPE: Record<string, string> = {
  ssn: "personal_info",
  credit_card: "credit_cards",
  email: "personal_info",
  phone: "personal_info",
  api_key: "trade_secrets",
  mrn: "health_records",
};

const PATTERN_SEVERITY: Record<string, string> = {
  ssn: "alert",
  credit_card: "alert",
  mrn: "alert",
  api_key: "warning",
  email: "info",
  phone: "info",
};

const DATA_TYPE_TO_AIUC1_DOMAIN: Record<string, string[]> = {
  health_records: ["A"],
  personal_info: ["A"],
  credit_cards: ["A"],
  financial_records: ["A"],
  ai_training_data: ["D"],
  biometric_data: ["A", "D"],
};

export class ClassificationAdvisory {
  private taxonomy: Record<string, unknown>;
  private overlayProfiles: Map<string, Record<string, unknown>>;

  constructor() {
    this.taxonomy = loadTaxonomy();
    this.overlayProfiles = loadOverlayProfiles();
  }

  generate(
    patternDetections: PatternDetection[],
    options?: {
      activeDataHandling?: string[];
      activeCertifications?: string[];
    },
  ): { recommendations: ClassificationRecommendation[]; upgradeAdvisories: CertificationUpgradeAdvisory[] } {
    const current = new Set(options?.activeDataHandling ?? []);
    const recommendations: ClassificationRecommendation[] = [];
    const upgradeAdvisories: CertificationUpgradeAdvisory[] = [];

    const typeDetections = new Map<string, number>();
    const typePatterns = new Map<string, string[]>();

    for (const detection of patternDetections) {
      const dataType = PATTERN_TO_DATA_TYPE[detection.patternType];
      if (dataType && !current.has(dataType)) {
        typeDetections.set(dataType, (typeDetections.get(dataType) ?? 0) + detection.count);
        const patterns = typePatterns.get(dataType) ?? [];
        patterns.push(detection.patternType);
        typePatterns.set(dataType, patterns);
      }
    }

    for (const [dataType, count] of typeDetections) {
      const patterns = typePatterns.get(dataType)!;
      const projectedOverlays = this.projectOverlays(dataType);
      const projectedControls = this.projectControls(projectedOverlays);

      const severityOrder: Record<string, number> = { info: 0, warning: 1, alert: 2 };
      let maxSev = "info";
      for (const p of patterns) {
        const s = PATTERN_SEVERITY[p] ?? "info";
        if (severityOrder[s]! > severityOrder[maxSev]!) maxSev = s;
      }

      const confidence = count >= 5 ? "high" : count >= 2 ? "medium" : "low";

      recommendations.push({
        detectedPattern: patterns[0]!,
        suggestedConfigField: "my_agent_handles",
        suggestedValue: dataType,
        projectedOverlays,
        projectedControls,
        detectionCount: count,
        confidence,
        severity: maxSev,
        exampleConfig: `my_agent_handles:\n  - ${dataType}`,
      });
    }

    if (options?.activeCertifications?.includes("aiuc-1")) {
      for (const rec of recommendations) {
        const domains = DATA_TYPE_TO_AIUC1_DOMAIN[rec.suggestedValue] ?? [];
        if (domains.length > 0) {
          upgradeAdvisories.push({
            certificationId: "aiuc-1",
            message: `${rec.suggestedValue} patterns detected in tool calls. Adding 'my_agent_handles: [${rec.suggestedValue}]' would activate ${rec.projectedOverlays.join(", ")} controls and strengthen your AIUC-1 posture under domain ${domains.join(", ")}.`,
            suggestedConfigAddition: { my_agent_handles: [rec.suggestedValue] },
            aiuc1DomainsStrengthened: domains,
            severity: "info",
          });
        }
      }
    }

    return { recommendations, upgradeAdvisories };
  }

  private projectOverlays(dataType: string): string[] {
    const typeMapping = (this.taxonomy as Record<string, Record<string, string[]>>).developer_type_mapping ?? {};
    const dcCodes = typeMapping[dataType] ?? [];

    const classificationLookup = new Map<string, string[]>();
    for (const entry of ((this.taxonomy as Record<string, Array<Record<string, unknown>>>).classifications ?? [])) {
      classificationLookup.set(entry.code as string, normalizeOverlayIds((entry.overlays ?? []) as string[]));
    }

    const overlays: string[] = [];
    for (const dcCode of dcCodes) {
      for (const oid of classificationLookup.get(dcCode) ?? []) {
        if (this.overlayProfiles.has(oid) && !overlays.includes(oid)) {
          overlays.push(oid);
        }
      }
    }
    return overlays;
  }

  private projectControls(overlayIds: string[]): string[] {
    const controls = new Set<string>();
    for (const oid of overlayIds) {
      const profile = this.overlayProfiles.get(oid);
      if (profile) {
        for (const cid of Object.keys((profile.control_adjustments ?? {}) as Record<string, unknown>)) {
          controls.add(cid);
        }
      }
    }
    return [...controls].sort();
  }
}
