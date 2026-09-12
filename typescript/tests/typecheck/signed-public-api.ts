import { EpisodeSigner, EpisodeTrustPolicy, signEpisodeSnapshot, verifySignedEpisode } from "../../src/ancilis/index.js";
import type { EpisodeSnapshot, EpisodeTrustPolicyDocument, ProtectedBodyRequest, SignedEpisodeVerification } from "../../src/ancilis/index.js";

export async function publicApi(snapshot: EpisodeSnapshot, policy: EpisodeTrustPolicyDocument, signer: EpisodeSigner): Promise<boolean> {
  const exported: string = signEpisodeSnapshot(snapshot, signer);
  const result = await verifySignedEpisode(exported, { trust: new EpisodeTrustPolicy(policy), bodyResolver: (request: ProtectedBodyRequest) => {
    const digest: string = request.reference.sha256;
    const length: number = request.reference.byte_length;
    // @ts-expect-error authorization context is immutable
    request.reference.access_scope = "other";
    return digest && length ? null : new Uint8Array();
  } });
  return result.envelope_authenticated;
}
export function immutableResult(result: SignedEpisodeVerification): void {
  // @ts-expect-error verifier result is immutable
  result.envelope_authenticated = true;
  // @ts-expect-error reason history is immutable
  result.reasons.push("forged");
}

export function narrowedSurface(result: SignedEpisodeVerification, policy: EpisodeTrustPolicy, signer: EpisodeSigner): void {
  // @ts-expect-error result policy binding is immutable
  result.policy_sha256 = "changed";
  // @ts-expect-error result export binding is immutable
  result.export_sha256 = "changed";
  // @ts-expect-error low-level verification is module-private
  policy.verifySignature;
  // @ts-expect-error signing uses the designed standalone/episode entry points
  signer.signSnapshot;
}

import type { EpisodeHandle } from "../../src/ancilis/index.js";
export function episodeSignedExport(handle: EpisodeHandle, signer: EpisodeSigner): string {
  return handle.exportSigned(signer);
}
