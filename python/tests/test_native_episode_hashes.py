"""Golden-vector coverage for bounded native episode capture."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from ancilis.episodes import Ancilis, ObservationInput, canonical_json


VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "tests/fixtures/episodes/native-vectors.json"
    ).read_text()
)


def test_native_policy_open_event_and_initial_revision_match_golden_vectors() -> None:
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

    observation = episode.observe(ObservationInput(**vector["manual_input"]))
    assert observation.to_dict() == vector["observation"]


def test_golden_partial_revision_hash_uses_the_shared_canonical_preimage() -> None:
    assert (
        canonical_json(VECTORS["canonical_nonbmp"]["value"]).hex()
        == VECTORS["canonical_nonbmp"]["utf8_hex"]
    )
    digest = hashlib.sha256(
        b"ancilis-native-revision/1\n" + canonical_json(VECTORS["partial_revision_preimage"])
    ).hexdigest()
    assert digest == VECTORS["partial_revision_id"]
