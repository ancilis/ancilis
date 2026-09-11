"""Synthetic orchestration tests; adapters here are not GE verification."""

import asyncio
import copy
import hashlib
import json
from pathlib import Path

import pytest
import ancilis as sdk

V = json.loads(
    (Path(__file__).parents[2] / "tests/fixtures/episodes/classification-vectors.json").read_text()
)
S = json.loads(
    (Path(__file__).parents[2] / "tests/fixtures/episodes/signed-vectors.json").read_text()
)
BODY = bytes.fromhex(V["body_hex"])


def api(name):
    result = getattr(sdk, name, None)
    assert callable(result), f"Missing public API {name}"
    return result


def adapter(resolve=None):
    return api("TrustedClassificationAdapter")(
        **V["adapter"], resolve=resolve or (lambda request, body: copy.deepcopy(V["response"]))
    )


def semantic(propose):
    return api("ExperimentalSemanticProvider")(
        provider_id="demo", method_id="demo/1", runtime_id="synthetic", propose=propose
    )


def assess(**changes):
    args = dict(
        trust=sdk.EpisodeTrustPolicy(V["trust_policy"]),
        adapter=adapter(),
        body_resolver=lambda r: BODY,
        assessed_at=V["assessed_at"],
    )
    args.update(changes)
    return api("assess_episode_classifications")(args.pop("export", V["export"]), **args)


def unknown(request, body):
    return dict(
        schema="ancilis-classification-response/1",
        request_sha256=request.request_sha256,
        outcome="UNKNOWN",
        classification=None,
        evidence_refs=[],
        reasons=["STALE_LABEL"],
    )


def proposal(request, body):
    return dict(
        schema="ancilis-semantic-proposal/1",
        request_sha256=request.request_sha256,
        status="PROPOSED",
        proposed_classification="DEMO-SENSITIVE",
        evidence_refs=["bc" * 32],
        reasons=[],
    )


def test_exact_vector_and_trusted_bypass():
    calls = []

    def resolve(request, body):
        assert request.to_dict() == V["request"] and body == BODY
        calls.append(request)
        return copy.deepcopy(V["response"])

    report = assess(adapter=adapter(resolve))
    assert report.to_dict() == V["report"] and report.origin == "LOCAL_ASSESSMENT"
    report = assess(
        adapter=adapter(resolve),
        experimental_semantic=semantic(lambda *a: pytest.fail("must bypass")),
    )
    assert report.to_dict()["classifications"][0]["semantic"]["state"] == "NOT_REQUESTED"
    assert len(calls) == 2


@pytest.mark.parametrize("body", [None, b"wrong"])
def test_body_gate_prevents_all_classification_callbacks(body):
    report = assess(
        body_resolver=lambda r: body, adapter=adapter(lambda *a: pytest.fail("body gate"))
    )
    assert report.to_dict()["classifications"] == []
    assert report.to_dict()["verification"]["protected_bodies"] in ("UNAVAILABLE", "MISMATCH")


def test_no_adapter_and_semantic_requires_real_trusted_attempt():
    report = assess(adapter=None).to_dict()
    assert report["classifications"][0]["sdk_reason"] == "CLASSIFICATION_PROVIDER_UNAVAILABLE"
    assert report["classifications"][0]["response"] is None
    with pytest.raises(ValueError, match="SEMANTIC_REQUIRES_TRUSTED_ADAPTER"):
        assess(adapter=None, experimental_semantic=semantic(proposal))
    with pytest.raises(ValueError, match="BODY_VERIFICATION_REQUIRED"):
        assess(trust=sdk.EpisodeTrustPolicy({**V["trust_policy"], "body_mode": "NONE"}))


@pytest.mark.parametrize(
    "change",
    [
        {"request_sha256": "00" * 32},
        {"extra": True},
        {"classification": None},
        {"evidence_refs": []},
        {"classification": "UNSUPPORTED-CLASS"},
        {"outcome": "SUPPORTED_NEGATIVE"},
        {"verified": True},
    ],
)
def test_bad_adapter_response_is_distinct_error(change):
    report = assess(adapter=adapter(lambda *a: {**V["response"], **change})).to_dict()
    row = report["classifications"][0]
    assert (
        row["outcome"] == "ERROR"
        and row["response"] is None
        and row["sdk_reason"] == "INVALID_ADAPTER_RESPONSE"
    )


@pytest.mark.parametrize("outcome", ["UNKNOWN", "ABSTAIN", "ERROR", "UNSUPPORTED"])
def test_distinct_provider_outcomes_and_semantic_opt_in(outcome):
    def resolve(request, body):
        return {**unknown(request, body), "outcome": outcome}

    calls = []

    def propose(request, body):
        calls.append(request)
        return proposal(request, body)

    row = assess(adapter=adapter(resolve), experimental_semantic=semantic(propose)).to_dict()[
        "classifications"
    ][0]
    assert row["outcome"] == outcome and row["classification"] is None
    assert len(calls) == (1 if outcome == "UNKNOWN" else 0)
    if calls:
        assert (
            row["semantic"]["response"]["status"] == "PROPOSED"
            and row["semantic"]["state"] == "UNQUALIFIED"
        )


def test_exception_sanitized_and_later_occurrences_continue():
    calls = []

    def resolve(request, body):
        calls.append(request.request_sha256)
        if len(calls) == 1:
            raise RuntimeError("private-secret")
        return unknown(request, body)

    report = assess(export=S["multiple_export"], adapter=adapter(resolve)).to_dict()
    assert len(calls) == 3 and [r["outcome"] for r in report["classifications"]] == [
        "ERROR",
        "UNKNOWN",
        "UNKNOWN",
    ]
    assert "private-secret" not in str(report)
    assert report["classifications"][0]["sdk_reason"] == "ADAPTER_CALL_FAILED"


def test_request_mutation_cannot_rebind_response_or_later_body():
    def resolve(request, body):
        document = request.to_dict()
        document["reference"]["artifact"] = "forged"
        object.__setattr__(request, "_document", document)
        return {**V["response"], "request_sha256": "00" * 32}

    row = assess(adapter=adapter(resolve)).to_dict()["classifications"][0]
    assert row["request"] == V["request"] and row["sdk_reason"] == "INVALID_ADAPTER_RESPONSE"


def test_semantic_self_qualification_and_exceptions_do_not_promote():
    for cb in (
        lambda r, b: {**proposal(r, b), "qualification": "QUALIFIED"},
        lambda r, b: {**proposal(r, b), "request_sha256": "00" * 32},
    ):
        row = assess(adapter=adapter(unknown), experimental_semantic=semantic(cb)).to_dict()[
            "classifications"
        ][0]
        assert (
            row["outcome"] == "UNKNOWN"
            and row["semantic"]["sdk_reason"] == "INVALID_SEMANTIC_RESPONSE"
        )

    def failure(*a):
        raise RuntimeError("private")

    row = assess(adapter=adapter(unknown), experimental_semantic=semantic(failure)).to_dict()[
        "classifications"
    ][0]
    assert (
        row["semantic"]["sdk_reason"] == "SEMANTIC_PROVIDER_ERROR" and row["outcome"] == "UNKNOWN"
    )


def test_history_preserves_reassessment_and_origin_and_refuses_tamper_or_overflow():
    report = assess()
    d = report.to_dict()
    history = api("ClassificationHistory")(
        d["tenant"], d["episode"], d["open_sha256"], max_reports=2
    )
    assert history.append(report) is True and history.append(report) is False
    later = assess(assessed_at="2026-09-11T01:00:00.000000Z", adapter=adapter(unknown))
    assert history.append(later) is True
    assert [e["report"]["classifications"][0]["outcome"] for e in history.inspect()] == [
        "SUPPORTED_POSITIVE",
        "UNKNOWN",
    ]
    parsed = api("EpisodeClassificationReport")(d)
    assert parsed.origin == "PARSED_UNAUTHENTICATED"
    other = api("ClassificationHistory")(d["tenant"], d["episode"], d["open_sha256"])
    other.append(parsed)
    assert other.inspect()[0]["origin"] == "PARSED_UNAUTHENTICATED"
    with pytest.raises(ValueError, match="HISTORY_LIMIT"):
        history.append(assess(assessed_at="2026-09-11T02:00:00.000000Z", adapter=adapter(unknown)))
    assert len(history.inspect()) == 2
    d["classifications"][0]["classification"] = "forged"
    with pytest.raises(ValueError, match="INVALID_CLASSIFICATION_REPORT"):
        api("EpisodeClassificationReport")(d)


@pytest.mark.asyncio
async def test_async_callbacks_cancellation_and_no_sync_implicit_run():
    async def resolve(request, body):
        await asyncio.sleep(0)
        return unknown(request, body)

    async def body(request):
        await asyncio.sleep(0)
        return BODY

    result = await api("aassess_episode_classifications")(
        V["export"],
        trust=sdk.EpisodeTrustPolicy(V["trust_policy"]),
        adapter=adapter(resolve),
        body_resolver=body,
        assessed_at=V["assessed_at"],
    )
    assert result.to_dict()["classifications"][0]["outcome"] == "UNKNOWN"
    with pytest.raises(ValueError, match="ASYNC_CALLBACK_IN_SYNC_API"):
        assess(adapter=adapter(resolve))

    async def cancelled(*a):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await api("aassess_episode_classifications")(
            V["export"],
            trust=sdk.EpisodeTrustPolicy(V["trust_policy"]),
            adapter=adapter(cancelled),
            body_resolver=body,
            assessed_at=V["assessed_at"],
        )


def test_shared_schemas_validate_real_outputs():
    import jsonschema

    report = assess().to_dict()
    for name, value in [
        ("classification-request", report["classifications"][0]["request"]),
        ("classification-response", report["classifications"][0]["response"]),
        ("classification-report", report),
    ]:
        schema = json.loads(
            (Path(__file__).parents[2] / f"shared/episodes/v1/{name}.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            value
        )


def test_full_semantic_vector_and_schema():
    import jsonschema

    report = assess(adapter=adapter(unknown), experimental_semantic=semantic(proposal)).to_dict()
    assert report == V["semantic_report"]
    for name, value in [
        ("semantic-request", report["classifications"][0]["semantic"]["request"]),
        ("semantic-proposal", report["classifications"][0]["semantic"]["response"]),
        ("classification-report", report),
    ]:
        schema = json.loads(
            (Path(__file__).parents[2] / f"shared/episodes/v1/{name}.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            value
        )


def test_empty_episode_and_invalid_signature_reports_do_not_fabricate_scope():
    owner = sdk.Ancilis("tenant", "source")
    with owner.episode("empty-classification", expected_surfaces=("tool",)) as episode:
        pass
    signer = sdk.EpisodeSigner.from_seed(
        "tenant", "source", "key-1", seed=bytes.fromhex(S["seed_hex"])
    )
    empty = assess(export=episode.export_signed(signer)).to_dict()
    assert empty["classifications"] == [] and empty["tenant"] == "tenant"
    assert empty["verification"]["protected_bodies"] == "NO_REFERENCES"
    envelope = json.loads(V["export"])
    envelope["signature"] = "00" * 64
    invalid = assess(export=sdk.episodes.canonical_json(envelope)).to_dict()
    assert (
        invalid["tenant"] is None
        and invalid["revision_id"] is None
        and invalid["classifications"] == []
    )


def test_history_byte_limit_scope_and_detached_inspection():
    r = assess()
    d = r.to_dict()
    history = api("ClassificationHistory")(d["tenant"], d["episode"], d["open_sha256"], max_bytes=1)
    with pytest.raises(ValueError, match="HISTORY_LIMIT"):
        history.append(r)
    assert history.inspect() == ()
    wrong = api("ClassificationHistory")("other", d["episode"], d["open_sha256"])
    with pytest.raises(ValueError, match="HISTORY_SCOPE_MISMATCH"):
        wrong.append(r)
    history = api("ClassificationHistory")(d["tenant"], d["episode"], d["open_sha256"])
    history.append(r)
    view = history.inspect()
    view[0]["report"]["classifications"][0]["outcome"] = "ERROR"
    assert history.inspect()[0]["report"]["classifications"][0]["outcome"] == "SUPPORTED_POSITIVE"


def test_positive_cannot_omit_selected_receipts_and_parsed_origins_do_not_upgrade():
    row = assess(
        adapter=adapter(lambda *a: {**V["response"], "evidence_refs": ["cd" * 32]})
    ).to_dict()["classifications"][0]
    assert row["sdk_reason"] == "INVALID_ADAPTER_RESPONSE"
    r = assess()
    d = r.to_dict()
    history = api("ClassificationHistory")(d["tenant"], d["episode"], d["open_sha256"])
    history.append(api("EpisodeClassificationReport")(d))
    assert history.append(r) is False
    assert history.inspect()[0]["origin"] == "PARSED_UNAUTHENTICATED"
