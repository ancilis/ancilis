import { assessEpisodeClassifications, TrustedClassificationAdapter, ClassificationHistory } from "../../src/ancilis/index.js";
import type { ClassificationRequest, ClassificationResponse, EpisodeClassificationReport, EpisodeTrustPolicy } from "../../src/ancilis/index.js";
export function resolve(request: ClassificationRequest, body: Uint8Array): ClassificationResponse {
    const digest: string = request.request_sha256;
    const artifact: string = request.reference.artifact;
    // @ts-expect-error immutable authorization context
    request.reference.access_scope = "changed";
    return { schema: "ancilis-classification-response/1", request_sha256: digest, outcome: "UNKNOWN", classification: null, evidence_refs: [], reasons: [artifact && body.length ? "UNRESOLVED" : "MISSING"] };
}
export async function assess(wire: string, trust: EpisodeTrustPolicy, adapter: TrustedClassificationAdapter): Promise<EpisodeClassificationReport> {
    return assessEpisodeClassifications(wire, { trust, adapter });
}
export function history(history: ClassificationHistory, report: EpisodeClassificationReport): string | null {
    history.append(report);
    return report.toJSON().classifications[0]!.classification;
}
