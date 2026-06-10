"""Regression tests for evidence-chain integrity (audit findings F13, F14, F15).

F13: HMAC-keyed (v2) chaining with a chain-format version field and a migration
     path; verify_chain requires the key; a forged record fails verification.
F14: reset()/purge_before() emit signed checkpoints; an emptied chain is reported
     as reset-or-purged, not a pristine empty chain; the ANC-922 narrower-payload
     path cannot be used to forge keyed records.
F15: docs state per-record forgery is possible without a protected key.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.evidence.chain import CHAIN_FORMAT_V1, CHAIN_FORMAT_V2
from ancilis.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
KEY = b"unit-test-chain-key"


def _config():
    return load_config(raw={"agent": {"name": "chain-test"}})


def _action(i: int) -> Action:
    return Action(
        action_id=f"a{i}",
        timestamp=f"2026-06-06T00:00:0{i}Z",
        agent_id="chain-test",
        action_type="tool_call",
        tool=ToolInfo(name="x"),
        parameters=ActionParameters(raw={"q": "clean"}),
    )


def _seed(store: EvidenceStore, n: int = 3) -> None:
    engine = Engine(_config())
    for i in range(n):
        store.store(engine.evaluate(_action(i)), tool_name="x")


# --- F13 -------------------------------------------------------------------


def test_keyed_v2_chain_verifies(tmp_path) -> None:
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=KEY)
    _seed(store)
    report = store.verify_chain_report()
    assert report.valid
    assert report.status == "verified"
    assert report.verified_count == 3
    assert report.legacy_unverified_count == 0
    # Persisted records carry chain_format_version = 2.
    versions = {r[0] for r in store._connection.execute(
        "SELECT DISTINCT chain_format_version FROM evidence_records"
    ).fetchall()}
    assert versions == {CHAIN_FORMAT_V2}
    store.close()


def test_unkeyed_records_are_legacy_unverified(tmp_path) -> None:
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=None)
    _seed(store)
    report = store.verify_chain_report()
    # Intact but NOT silently "verified".
    assert report.valid
    assert report.status == "legacy-unverified"
    assert report.verified_count == 0
    assert report.legacy_unverified_count == 3
    versions = {r[0] for r in store._connection.execute(
        "SELECT DISTINCT chain_format_version FROM evidence_records"
    ).fetchall()}
    assert versions == {CHAIN_FORMAT_V1}
    store.close()


def test_verify_requires_key_for_v2_records(tmp_path) -> None:
    db = str(tmp_path / "e.duckdb")
    keyed = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(keyed)
    keyed.close()
    # A verifier without the key cannot attest v2 records.
    nokey = EvidenceStore(_config(), db_path=db, chain_key=None)
    report = nokey.verify_chain_report()
    assert not report.valid
    assert any("key required" in e.lower() for e in report.errors)
    nokey.close()
    # With the key, it verifies.
    withkey = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    assert withkey.verify_chain_report().valid
    withkey.close()


def test_forged_v2_record_fails_verification(tmp_path) -> None:
    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store)
    store.close()
    # Attacker with DB write access (no key) rewrites a record + its hash.
    conn = duckdb.connect(db)
    conn.execute("UPDATE evidence_records SET decision = 'ALLOW', record_hash = 'forged' WHERE seq_id = 2")
    conn.close()
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    report = store.verify_chain_report()
    assert not report.valid
    assert report.status == "broken"
    store.close()


# --- F14 -------------------------------------------------------------------


def test_downgrade_v2_to_v1_is_detected(tmp_path) -> None:
    """An attacker (no key) flips a v2 record to v1 + recomputes the unkeyed
    SHA-256 hash. The signed migration boundary must catch this HMAC bypass."""
    import json as _json

    from ancilis.evidence.chain import canonical_payload, compute_hash

    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store, n=4)
    store.close()

    conn = duckdb.connect(db)
    cols = (
        "evaluation_id,timestamp,agent_id,source_type,tool_name,decision,mode,"
        "control_results,active_overlays,data_classifications,active_certifications,"
        "total_duration_ms,previous_hash,output_summary,session_id,tenant_id,"
        "detected_data_types,sdk_version,framework_version,classification_context"
    )
    r = conn.execute(f"SELECT {cols} FROM evidence_records WHERE seq_id = 3").fetchone()
    canon = canonical_payload(
        evaluation_id=r[0], timestamp=r[1], agent_id=r[2], source_type=r[3],
        tool_name=r[4], decision="ALLOW", mode=r[6],
        control_results=_json.loads(r[7]), active_overlays=_json.loads(r[8]),
        data_classifications=_json.loads(r[9]), active_certifications=_json.loads(r[10]),
        total_duration_ms=r[11], previous_hash=r[12], output_summary=r[13],
        session_id=r[14], tenant_id=r[15], detected_data_types=_json.loads(r[16]),
        sdk_version=r[17], framework_version=r[18], classification_context=_json.loads(r[19]),
    )
    conn.execute(
        "UPDATE evidence_records SET decision='ALLOW', record_hash=?, chain_format_version=1 WHERE seq_id=3",
        [compute_hash(canon)],
    )
    conn.close()

    report = EvidenceStore(_config(), db_path=db, chain_key=KEY).verify_chain_report()
    assert not report.valid
    assert any("downgrade" in e.lower() for e in report.errors)


def test_partial_downgrade_with_surviving_v2_is_detected(tmp_path) -> None:
    """Flipping ONE v2 record to v1 (others remain v2) must trip the keyed
    migration boundary, not pass as legacy-unverified."""
    import json as _json

    from ancilis.evidence.chain import canonical_payload, compute_hash

    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store, n=4)
    store.close()
    conn = duckdb.connect(db)
    cols = (
        "evaluation_id,timestamp,agent_id,source_type,tool_name,decision,mode,"
        "control_results,active_overlays,data_classifications,active_certifications,"
        "total_duration_ms,previous_hash,output_summary,session_id,tenant_id,"
        "detected_data_types,sdk_version,framework_version,classification_context"
    )
    r = conn.execute(f"SELECT {cols} FROM evidence_records WHERE seq_id = 4").fetchone()
    canon = canonical_payload(
        evaluation_id=r[0], timestamp=r[1], agent_id=r[2], source_type=r[3], tool_name=r[4],
        decision="ALLOW", mode=r[6], control_results=_json.loads(r[7]),
        active_overlays=_json.loads(r[8]), data_classifications=_json.loads(r[9]),
        active_certifications=_json.loads(r[10]), total_duration_ms=r[11], previous_hash=r[12],
        output_summary=r[13], session_id=r[14], tenant_id=r[15],
        detected_data_types=_json.loads(r[16]), sdk_version=r[17], framework_version=r[18],
        classification_context=_json.loads(r[19]),
    )
    conn.execute(
        "UPDATE evidence_records SET decision='ALLOW', record_hash=?, chain_format_version=1 WHERE seq_id=4",
        [compute_hash(canon)],
    )
    conn.close()
    assert not EvidenceStore(_config(), db_path=db, chain_key=KEY).verify_chain_report().valid


def test_forged_unkeyed_purge_event_is_not_trusted_on_keyed_chain(tmp_path) -> None:
    """An attacker without the key cannot authorize a pruned gap with a forged
    UNKEYED purge checkpoint on a keyed chain."""
    import uuid as _uuid

    from ancilis.evidence.chain import compute_hash
    from ancilis.evidence.store import _chain_event_canonical

    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store, n=4)
    store.close()
    conn = duckdb.connect(db)
    survivor_prev = conn.execute(
        "SELECT previous_hash FROM evidence_records WHERE seq_id = 3"
    ).fetchone()[0]
    conn.execute("DELETE FROM evidence_records WHERE seq_id <= 2")
    conn.execute("DELETE FROM evidence_chain_events")
    eid = str(_uuid.uuid4())
    canonical = _chain_event_canonical(eid, "purge", "2026-06-09T00:00:00Z", 2, "x", 2, survivor_prev)
    conn.execute(
        "INSERT INTO evidence_chain_events "
        "(event_id,event_type,created_at,hwm_seq,hwm_hash,record_count,keyed,boundary_hash,signature) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        [eid, "purge", "2026-06-09T00:00:00Z", 2, "x", 2, False, survivor_prev, compute_hash(canonical)],
    )
    conn.close()
    # The forged unkeyed checkpoint must NOT authorize the gap on a keyed chain.
    assert not EvidenceStore(_config(), db_path=db, chain_key=KEY).verify_chain_report().valid


def test_partial_prune_keeps_surviving_chain_valid(tmp_path) -> None:
    """A legitimate prefix prune must NOT make the surviving chain read as broken
    (that would invalidate retained data — forbidden by the hard constraint)."""
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=KEY)
    engine = Engine(_config())
    for i in range(4):
        ev = engine.evaluate(_action(i))
        ev.timestamp = f"2026-06-0{i + 1}T00:00:00Z"
        store.store(ev, tool_name="x")
    removed = store.purge_before("2026-06-03T00:00:00Z")
    assert removed == 2
    report = store.verify_chain_report()
    assert report.valid  # surviving chain still verifies
    assert report.purge_events == 1
    store.close()


def test_keyed_checkpoint_requires_key_at_verify(tmp_path) -> None:
    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store)
    store.reset()
    store.close()
    report = EvidenceStore(_config(), db_path=db, chain_key=None).verify_chain_report()
    assert not report.valid
    assert any("key required" in e.lower() for e in report.errors)


def test_reset_emits_checkpoint_and_is_not_silently_clean(tmp_path) -> None:
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=KEY)
    _seed(store)
    assert store.reset() == 3
    report = store.verify_chain_report()
    # Empty AND auditable: reported as reset-or-purged, not a pristine empty chain.
    assert report.status == "reset-or-purged"
    assert report.reset_events == 1
    store.close()


def test_purge_emits_checkpoint(tmp_path) -> None:
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=KEY)
    _seed(store, n=3)
    # All three timestamps are < this cutoff, so all are purged.
    removed = store.purge_before("2027-01-01T00:00:00Z")
    assert removed == 3
    report = store.verify_chain_report()
    assert report.purge_events == 1
    assert report.status == "reset-or-purged"
    store.close()


def test_tampered_audit_log_is_detected(tmp_path) -> None:
    db = str(tmp_path / "e.duckdb")
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    _seed(store)
    store.reset()
    store.close()
    # Tamper the signed checkpoint.
    conn = duckdb.connect(db)
    conn.execute("UPDATE evidence_chain_events SET record_count = 999")
    conn.close()
    store = EvidenceStore(_config(), db_path=db, chain_key=KEY)
    report = store.verify_chain_report()
    assert not report.valid
    assert any("audit log tampered" in e.lower() for e in report.errors)
    store.close()


def test_empty_never_used_chain_is_distinguishable_from_reset(tmp_path) -> None:
    store = EvidenceStore(_config(), db_path=str(tmp_path / "e.duckdb"), chain_key=KEY)
    report = store.verify_chain_report()
    assert report.status == "empty"
    assert report.reset_events == 0 and report.purge_events == 0
    store.close()


# --- F15 -------------------------------------------------------------------


def test_docs_state_per_record_forgery_without_key() -> None:
    for rel in ("README.md", "docs/limitations.md", "docs/evidence-and-reporting.md"):
        text = (ROOT / rel).read_text(encoding="utf-8").lower()
        assert "hmac" in text, rel
        assert "legacy-unverified" in text, rel
    # limitations must spell out per-record forgery, not just whole-DB replacement.
    lim = (ROOT / "docs" / "limitations.md").read_text(encoding="utf-8").lower()
    assert "per-record forgery" in lim
    assert "ancilis_chain_key" in lim
