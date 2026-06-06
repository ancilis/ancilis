"""Evidence generation and storage (Unit 4)."""

from ancilis.evidence.adapter import (
    EvidenceAdapter,
    EvidenceAdapterExport,
    EvidenceAdapterPayload,
    EvidenceAdapterQuery,
    EvidenceAdapterSelection,
    resolve_evidence_adapter,
)
from ancilis.evidence.chain import (
    CHAIN_FORMAT_V1,
    CHAIN_FORMAT_V2,
    CURRENT_CHAIN_FORMAT,
    GENESIS_SEED,
    ChainKeyError,
    canonical_payload,
    compute_hash,
    compute_keyed_hash,
    resolve_chain_key,
)
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.evidence.sync import SyncEngine, SyncResult

__all__ = [
    "EvidenceAdapter",
    "EvidenceAdapterExport",
    "EvidenceAdapterPayload",
    "EvidenceAdapterQuery",
    "EvidenceAdapterSelection",
    "CHAIN_FORMAT_V1",
    "CHAIN_FORMAT_V2",
    "CURRENT_CHAIN_FORMAT",
    "ChainKeyError",
    "GENESIS_SEED",
    "EvidenceRecord",
    "EvidenceStore",
    "SyncEngine",
    "SyncResult",
    "canonical_payload",
    "compute_hash",
    "compute_keyed_hash",
    "resolve_chain_key",
    "resolve_evidence_adapter",
]
