"""Golden-vector coverage for bounded native episode capture."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import jsonschema

from ancilis.episodes import Ancilis, ObservationInput, canonical_json, verify_episode_snapshot


VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "tests/fixtures/episodes/native-vectors.json"
    ).read_text()
)


def test_native_policy_open_event_and_v2_chain_match_golden_vectors() -> None:
    vector = VECTORS
    sdk = Ancilis(
        vector["open"]["tenant"],
        vector["open"]["owner_source"],
        source_instance="synthetic-instance",
        _clock=lambda: vector["open"]["created_at"],
        _nonce_factory=lambda: vector["open"]["open_nonce"],
    )

    assert sdk.policy.to_dict() == vector["policy"]
    assert sdk.policy.sha256 == vector["policy_sha256"]

    episode = sdk.episode(
        vector["open"]["episode"], expected_surfaces=vector["open"]["expected_surfaces"]
    )
    initial = episode.inspect().to_dict()
    assert initial["open"] == vector["open"]
    assert initial["open_sha256"] == vector["open_sha256"]
    assert initial["revision_id"] == vector["revision_id"]
    assert initial["revision_method"] == vector["revision_method"]
    assert initial["observation_chain_sha256"] == vector["genesis_chain"]

    observation = episode.observe(ObservationInput(**vector["manual_input"]))
    assert observation.to_dict() == vector["observation"]
    after = episode.inspect().to_dict()
    assert after["observation_chain_sha256"] == vector["first_observation_chain"]
    assert after["revision_id"] != initial["revision_id"]
    assert verify_episode_snapshot(after, assessed_at=vector["open"]["created_at"]).to_dict() == {
        "schema": "ancilis-verification/1",
        "status": "UNVERIFIED",
        "envelope_authenticated": False,
        "protected_bodies": "NOT_REQUESTED",
        "reconstruction": "UNSUPPORTED",
        "policy_sha256": vector["policy_sha256"],
        "assessed_at": vector["open"]["created_at"],
        "reasons": ["NATIVE_CHAIN_MATCH"],
        "verified_claim_refs": [],
    }


def test_golden_v2_revision_hash_uses_the_shared_canonical_preimage() -> None:
    assert (
        canonical_json(VECTORS["canonical_nonbmp"]["value"]).hex()
        == VECTORS["canonical_nonbmp"]["utf8_hex"]
    )
    digest = hashlib.sha256(
        b"ancilis-native-revision/2\n" + canonical_json(VECTORS["partial_revision_preimage"])
    ).hexdigest()
    assert digest == VECTORS["partial_revision_id"]


def test_real_native_snapshot_and_unsigned_verdict_validate_against_shared_schemas() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    episode = sdk.episode("episode", expected_surfaces=("tool",))
    episode.observe(ObservationInput("call", "2026-09-10T00:00:00.000000Z", "tool", "EXECUTE", "START", None, "STARTED"))
    root = Path(__file__).resolve().parents[2] / "shared/episodes/v1"
    jsonschema.validate(episode.inspect().to_dict(), json.loads((root / "episode.schema.json").read_text()))
    jsonschema.validate(verify_episode_snapshot(episode.inspect()).to_dict(), json.loads((root / "verification.schema.json").read_text()))
