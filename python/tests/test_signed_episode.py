"""Public synthetic vectors and adversarial signed-episode verification."""

import asyncio
import copy
import json
from pathlib import Path

import pytest

import ancilis as sdk
from ancilis.episodes import canonical_json

VECTOR = json.loads(
    (Path(__file__).parents[2] / "tests/fixtures/episodes/signed-vectors.json").read_text()
)
BODY = bytes.fromhex(VECTOR["body_hex"])


def api(name):
    value = getattr(sdk, name, None)
    assert callable(value), f"missing public signed-episode API: {name}"
    return value


def trust(**changes):
    document = copy.deepcopy(VECTOR["trust_policy"])
    document.update(changes)
    return api("EpisodeTrustPolicy")(document)


def verify(wire=None, policy=None, resolver=None, assessed_at=None):
    return api("verify_signed_episode")(
        VECTOR["export"] if wire is None else wire,
        trust() if policy is None else policy,
        assessed_at=assessed_at or VECTOR["assessed_at"],
        body_resolver=resolver,
    ).to_dict()


def test_sign_and_verify_exact_cross_language_primitive_vector():
    signer = api("EpisodeSigner").from_seed(
        "tenant", "source", "key-1", seed=bytes.fromhex(VECTOR["seed_hex"])
    )
    assert api("sign_episode_snapshot")(VECTOR["snapshot"], signer) == VECTOR["export"]
    assert verify(resolver=lambda request: BODY) == VECTOR["expected"]
    assert VECTOR["seed_hex"] not in repr(signer)


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("schema", "ancilis-signed-episode/0", "INVALID_SIGNED_EXPORT"),
        ("algorithm", "none", "INVALID_SIGNED_EXPORT"),
        ("key_id", "unknown", "UNTRUSTED_KEY"),
        ("signature", "00" * 64, "INVALID_SIGNATURE"),
        ("signature", "00" * 64 + "\n", "INVALID_SIGNED_EXPORT"),
        ("extra", "field", "INVALID_SIGNED_EXPORT"),
    ],
)
def test_envelope_failures_never_invoke_resolver(field, value, reason):
    envelope = json.loads(VECTOR["export"])
    envelope[field] = value
    called = []
    result = verify(canonical_json(envelope), resolver=lambda request: called.append(request))
    assert result["reasons"] == [reason]
    assert result["envelope_authenticated"] is False
    assert called == []


@pytest.mark.parametrize(
    "wire",
    [
        " " + VECTOR["export"],
        "\ufeff" + VECTOR["export"],
        "\ud800",
        b"\xff",
        b"\xef\xbb\xbf" + VECTOR["export"].encode(),
        '{"schema":"a","schema":"b"}',
        "[" * 80 + "0" + "]" * 80,
    ],
)
def test_malformed_encoding_and_noncanonical_wire_are_rejected(wire):
    result = verify(wire)
    assert result["status"] == "REJECTED"
    assert result["reasons"] == ["INVALID_SIGNED_EXPORT"]
    assert result["export_sha256"] is None


def test_native_tampering_is_not_promoted_by_a_signature():
    envelope = json.loads(VECTOR["export"])
    envelope["snapshot"]["observations"][1]["artifacts"][0]["sha256"] = "00" * 32
    assert verify(canonical_json(envelope))["reasons"] == ["INVALID_NATIVE_SNAPSHOT"]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"tenant": "other"}, "SCOPE_MISMATCH"),
        ({"source": "other"}, "SCOPE_MISMATCH"),
        ({"keys": []}, "UNTRUSTED_KEY"),
    ],
)
def test_trust_is_external_and_scope_bound(change, reason):
    called = []
    result = verify(policy=trust(**change), resolver=lambda request: called.append(request))
    assert result["reasons"] == [reason]
    assert called == []


def test_key_validity_boundaries_and_revocation_precedence():
    key = copy.deepcopy(VECTOR["trust_policy"]["keys"][0])
    assert verify(assessed_at=key["not_before"])["envelope_authenticated"] is True
    assert verify(assessed_at=key["not_after"])["reasons"] == ["KEY_NOT_CURRENT"]
    key["revoked"] = True
    assert verify(policy=trust(keys=[key]), assessed_at=key["not_after"])["reasons"] == [
        "REVOKED_KEY"
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"max_body_bytes": True},
        {"max_body_requests": 0},
        {"body_mode": "TRUST_ALL"},
        {"unknown": 1},
        {"keys": VECTOR["trust_policy"]["keys"] * 2},
    ],
)
def test_invalid_policy_is_configuration_error(change):
    api("EpisodeTrustPolicy")
    with pytest.raises(ValueError, match="INVALID_TRUST_POLICY"):
        trust(**change)


def test_policy_and_request_are_detached_from_caller_mutations():
    original = copy.deepcopy(VECTOR["trust_policy"])
    policy = api("EpisodeTrustPolicy")(original)
    original["keys"].clear()
    policy.to_dict()["keys"].clear()

    def resolver(request):
        assert request.tenant == "tenant" and request.reference.access_scope == "scope"
        assert request.event_id == VECTOR["snapshot"]["observations"][1]["event_id"]
        with pytest.raises(AttributeError):
            request.reference.sha256 = "00" * 32
        return BODY

    assert verify(policy=policy, resolver=resolver) == VECTOR["expected"]


@pytest.mark.parametrize(
    "body,state,status",
    [
        (None, "UNAVAILABLE", "UNVERIFIED"),
        (b"wrong", "MISMATCH", "REJECTED"),
        ("private bad type", "ERROR", "ERROR"),
    ],
)
def test_body_requirement_failures_preserve_authentication_only(body, state, status):
    result = verify(resolver=lambda request: body)
    assert result["envelope_authenticated"] is True
    assert result["protected_bodies"] == state and result["status"] == status
    assert result["verified_body_count"] == 0 and result["verified_claim_refs"] == []
    assert "private" not in str(result)


def test_budget_refusal_and_none_mode_make_no_resolver_calls():
    called = []
    result = verify(policy=trust(max_total_body_bytes=1), resolver=lambda r: called.append(r))
    assert result["protected_bodies"] == "LIMIT_EXCEEDED" and called == []
    result = verify(policy=trust(body_mode="NONE"), resolver=lambda r: called.append(r))
    assert result["status"] == "AUTHENTICATED" and result["protected_bodies"] == "NOT_REQUESTED"
    assert result["reconstruction"] == "UNSUPPORTED" and called == []


def test_episode_method_and_no_references_do_not_claim_body_verification():
    owner = sdk.Ancilis("tenant", "source")
    episode = owner.episode("empty", expected_surfaces=("tool",))
    signer = api("EpisodeSigner").from_seed(
        "tenant", "source", "key-1", seed=bytes.fromhex(VECTOR["seed_hex"])
    )
    result = verify(episode.export_signed(signer))
    assert result["protected_bodies"] == "NO_REFERENCES" and result["status"] == "UNVERIFIED"


def test_wrong_signer_scope_and_discarded_snapshots_are_refused():
    signer = api("EpisodeSigner").from_seed(
        "other", "source", "key-1", seed=bytes.fromhex(VECTOR["seed_hex"])
    )
    with pytest.raises(ValueError, match="SCOPE_MISMATCH"):
        api("sign_episode_snapshot")(VECTOR["snapshot"], signer)
    owner = sdk.Ancilis("tenant", "source")
    episode = owner.episode("empty", expected_surfaces=("tool",))
    owner.discard_episode("empty")
    signer = api("EpisodeSigner").from_seed(
        "tenant", "source", "key-1", seed=bytes.fromhex(VECTOR["seed_hex"])
    )
    with pytest.raises(ValueError, match="NATIVE_HISTORY_DISCARDED"):
        episode.export_signed(signer)


@pytest.mark.asyncio
async def test_async_resolver_and_cancellation():
    async def resolver(request):
        await asyncio.sleep(0)
        return BODY

    result = await api("averify_signed_episode")(
        VECTOR["export"], trust(), assessed_at=VECTOR["assessed_at"], body_resolver=resolver
    )
    assert result.to_dict() == VECTOR["expected"]
    with pytest.raises(ValueError, match="INVALID_BODY_RESOLVER"):
        verify(resolver=resolver)

    async def cancelled(request):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await api("averify_signed_episode")(
            VECTOR["export"], trust(), assessed_at=VECTOR["assessed_at"], body_resolver=cancelled
        )


def test_body_request_reuses_typed_immutable_content_evidence():
    def resolver(request):
        assert isinstance(request.reference, sdk.ContentEvidence)
        assert (
            request.reference.sha256
            == VECTOR["snapshot"]["observations"][1]["artifacts"][0]["sha256"]
        )
        return BODY

    assert verify(resolver=resolver) == VECTOR["expected"]


def test_shared_wire_policy_and_result_schemas():
    import jsonschema

    root = Path(__file__).parents[2] / "shared/episodes/v1"
    for filename, value in (
        ("signed-episode.schema.json", json.loads(VECTOR["export"])),
        ("trust-policy.schema.json", trust().to_dict()),
        ("signed-verification.schema.json", verify(resolver=lambda request: BODY)),
    ):
        schema = json.loads((root / filename).read_text())
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        validator.validate(value)
        value["unexpected"] = "field"
        assert not validator.is_valid(value)


def test_wire_size_is_capped_before_parsing_or_callbacks():
    result = verify(b" " * (32 * 1024 * 1024 + 1))
    assert result["reasons"] == ["EXPORT_TOO_LARGE"]
    assert result["export_sha256"] is None


def test_resolver_exception_is_sanitized_and_not_retried():
    calls = []

    def resolver(request):
        calls.append(request)
        raise RuntimeError("private-body-or-secret")

    result = verify(resolver=resolver)
    assert result["reasons"] == ["ENVELOPE_AUTHENTICATED", "BODY_RESOLVER_ERROR"]
    assert len(calls) == 1 and "private-body-or-secret" not in str(result)


def test_invalid_signer_and_unsorted_or_malformed_policy_keys():
    with pytest.raises(ValueError, match="INVALID_SIGNER"):
        api("EpisodeSigner").from_seed("tenant", "source", "key-1", seed=b"bad")
    key = copy.deepcopy(VECTOR["trust_policy"]["keys"][0])
    later = {**key, "key_id": "key-2"}
    for keys in ([later, key], [{**key, "public_key": "00"}], [{**key, "not_before": "invalid"}]):
        with pytest.raises(ValueError, match="INVALID_TRUST_POLICY"):
            trust(keys=keys)


@pytest.mark.parametrize("field", ["schema", "algorithm", "key_id", "snapshot", "signature"])
def test_every_envelope_field_is_required(field):
    envelope = json.loads(VECTOR["export"])
    del envelope[field]
    assert verify(canonical_json(envelope))["reasons"] == ["INVALID_SIGNED_EXPORT"]


def test_resolver_cannot_rebind_expected_bytes_by_bypassing_dataclass_freeze():
    import hashlib

    def resolver(request):
        changed = b"changed bytes"
        object.__setattr__(request.reference, "byte_length", len(changed))
        object.__setattr__(request.reference, "sha256", hashlib.sha256(changed).hexdigest())
        return changed

    result = verify(resolver=resolver)
    assert result["status"] == "REJECTED"
    assert result["protected_bodies"] == "MISMATCH"


@pytest.mark.asyncio
async def test_async_resolver_cannot_rebind_expected_bytes():
    import hashlib

    async def resolver(request):
        await asyncio.sleep(0)
        changed = b"changed bytes"
        object.__setattr__(request.reference, "byte_length", len(changed))
        object.__setattr__(request.reference, "sha256", hashlib.sha256(changed).hexdigest())
        return changed

    result = await api("averify_signed_episode")(
        VECTOR["export"], trust(), assessed_at=VECTOR["assessed_at"], body_resolver=resolver
    )
    assert result.to_dict()["protected_bodies"] == "MISMATCH"


def test_direct_signature_preimage_and_ordered_occurrences():
    envelope = json.loads(VECTOR["export"])
    del envelope["signature"]
    assert (b"ancilis-signed-episode/1\n" + canonical_json(envelope)).hex() == VECTOR[
        "signing_preimage_hex"
    ]
    calls = []

    def resolver(request):
        calls.append((request.event_id, request.reference.access_scope, request.reference.role))
        return BODY

    result = verify(VECTOR["multiple_export"], resolver=resolver)
    rows = VECTOR["multiple_snapshot"]["observations"]
    assert calls == [
        (rows[1]["event_id"], "scope-one", "INPUT"),
        (rows[1]["event_id"], "scope-two", "OUTPUT"),
        (rows[3]["event_id"], "scope-three", "INPUT"),
    ]
    assert result["status"] == "AUTHENTICATED" and result["verified_body_count"] == 3


@pytest.mark.parametrize(
    "change",
    [
        {"max_body_bytes": len(BODY) - 1},
        {"max_body_requests": 2},
        {"max_total_body_bytes": len(BODY) * 3 - 1},
    ],
)
def test_every_body_budget_is_preflighted(change):
    calls = []
    result = verify(
        VECTOR["multiple_export"], policy=trust(**change), resolver=lambda r: calls.append(r)
    )
    assert result["protected_bodies"] == "LIMIT_EXCEEDED" and calls == []


def test_exact_budgets_and_partial_verification_count():
    policy = trust(
        max_body_bytes=len(BODY), max_total_body_bytes=len(BODY) * 3, max_body_requests=3
    )
    assert (
        verify(VECTOR["multiple_export"], policy=policy, resolver=lambda r: BODY)[
            "verified_body_count"
        ]
        == 3
    )
    calls = []

    def resolver(request):
        calls.append(request)
        return BODY if len(calls) == 1 else None

    result = verify(VECTOR["multiple_export"], policy=policy, resolver=resolver)
    assert len(calls) == 2 and result["verified_body_count"] == 1
    assert result["protected_bodies"] == "UNAVAILABLE"


def test_embedded_native_schema_matches_its_source():
    root = Path(__file__).parents[2] / "shared/episodes/v1"
    native = json.loads((root / "episode.schema.json").read_text())
    signed = json.loads((root / "signed-episode.schema.json").read_text())
    assert signed["$defs"]["native_snapshot"] == {
        k: v for k, v in native.items() if k not in ("$schema", "$id", "$defs", "title")
    }
    for name, definition in signed["$defs"].items():
        if name != "native_snapshot":
            assert definition == native["$defs"][name]
