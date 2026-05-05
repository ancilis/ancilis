from __future__ import annotations

from pathlib import Path

from ancilis.evidence.chain import GENESIS_SEED, canonical_payload, compute_hash
from ancilis.evidence.store import EvidenceStore

from .helpers import make_store_evaluation

BATCH_SIZE = 250


def _insert_batch(benchmark_config, tmp_path: Path) -> int:
    db_path = tmp_path / "evidence-throughput.duckdb"
    db_path.unlink(missing_ok=True)
    with EvidenceStore(benchmark_config, db_path=db_path) as store:
        for index in range(BATCH_SIZE):
            store.store(
                make_store_evaluation(
                    Path(f"tool-{index:04d}.py"),
                    index,
                    session_id="bench-throughput",
                ),
                tool_name="bench-throughput",
            )
        return store.count(session_id="bench-throughput")


def _hash_chain_batch() -> str:
    previous_hash = GENESIS_SEED
    for index in range(1000):
        payload = canonical_payload(
            evaluation_id=f"hash-bench-{index:04d}",
            timestamp="2026-01-01T00:00:00+00:00",
            agent_id="benchmark-agent",
            source_type="agent",
            tool_name="synthetic-tool",
            decision="ALLOW",
            mode="audit",
            control_results=[
                {
                    "control_id": "PR-05",
                    "control_name": "Audit Logging",
                    "result": "PASS",
                    "detail": "Synthetic benchmark evidence recorded.",
                    "evidence_data": {"batch_index": index},
                    "duration_ms": 0.365,
                }
            ],
            active_overlays=[],
            data_classifications=[],
            active_certifications=[],
            total_duration_ms=1.25,
            previous_hash=previous_hash,
        )
        previous_hash = compute_hash(payload)
    return previous_hash


def test_temp_duckdb_evidence_insert_throughput(benchmark, benchmark_config, tmp_path: Path) -> None:
    inserted = benchmark.pedantic(_insert_batch, args=(benchmark_config, tmp_path), rounds=3, iterations=1)
    assert inserted == BATCH_SIZE


def test_sha256_hash_chain_ops_per_second(benchmark) -> None:
    final_hash = benchmark.pedantic(_hash_chain_batch, rounds=5, iterations=1)
    assert len(final_hash) == 64
