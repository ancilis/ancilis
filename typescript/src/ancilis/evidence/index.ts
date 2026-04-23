/** Evidence generation and storage (Unit 4). */

export { GENESIS_SEED, canonicalPayload, computeHash } from "./chain.js";
export type { EvidenceRecord } from "./record.js";
export { resolveEvidenceAdapter } from "./adapter.js";
export type {
  EvidenceAdapter,
  EvidenceAdapterExport,
  EvidenceAdapterPayload,
  EvidenceAdapterQuery,
  EvidenceAdapterSelection,
  ResolveEvidenceAdapterOptions,
} from "./adapter.js";
export { EvidenceStore } from "./store.js";
