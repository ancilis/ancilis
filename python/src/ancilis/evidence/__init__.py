"""Evidence generation and storage (Unit 4)."""

from ancilis.evidence.adapter import (
    EvidenceAdapter,
    EvidenceAdapterExport,
    EvidenceAdapterPayload,
    EvidenceAdapterQuery,
    EvidenceAdapterSelection,
    resolve_evidence_adapter,
)
from ancilis.evidence.chain import GENESIS_SEED, canonical_payload, compute_hash
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.evidence.sync import SyncEngine, SyncResult

__all__ = [
    "EvidenceAdapter",
    "EvidenceAdapterExport",
    "EvidenceAdapterPayload",
    "EvidenceAdapterQuery",
    "EvidenceAdapterSelection",
    "GENESIS_SEED",
    "EvidenceRecord",
    "EvidenceStore",
    "SyncEngine",
    "SyncResult",
    "canonical_payload",
    "compute_hash",
    "resolve_evidence_adapter",
]
