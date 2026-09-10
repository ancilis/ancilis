"""Behavioral regressions for the volatile native Python episode ledger."""

from __future__ import annotations

import asyncio
import copy
import inspect

import pytest

from ancilis.episodes import (
    Ancilis,
    CaptureResult,
    ContentEvidence,
    EpisodeCapacityError,
    EpisodeError,
    EpisodeLifecycleError,
    ObservationConflict,
    ObservationInput,
    Relationship,
    verify_episode_snapshot,
    canonical_json,
)


def _input(
    call_id: str, *, phase: str = "START", outcome: str = "STARTED", chunk_index=None, **extra
):
    operation = extra.pop("operation", "EXECUTE")
    return ObservationInput(
        call_id=call_id,
        occurred_at="2026-09-10T00:00:00.000000Z",
        surface="tool",
        operation=operation,
        phase=phase,
        chunk_index=chunk_index,
        outcome=outcome,
        **extra,
    )


def test_manual_duplicate_is_noop_but_changed_input_is_conflict() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    episode = sdk.episode("episode", expected_surfaces=("tool",))
    first = episode.observe(_input("call"))
    assert episode.observe(_input("call")) is first
    with pytest.raises(ObservationConflict):
        episode.observe(_input("call", operation="READ"))
    snapshot = episode.inspect().to_dict()
    assert snapshot["coverage"]["reasons"] == ["EVENT_CONFLICT"]
    assert len(snapshot["observations"]) == 1


def test_content_evidence_retains_no_body_and_artifact_cannot_rebind() -> None:
    evidence = ContentEvidence.from_bytes("a", b"sensitive")
    assert not hasattr(evidence, "data")
    sdk = Ancilis("tenant", "source", source_instance="instance")
    episode = sdk.episode("episode", expected_surfaces=("tool",))
    episode.observe(_input("one", artifacts=(evidence,)))
    with pytest.raises(ValueError, match="ARTIFACT_REBIND"):
        episode.observe(_input("two", artifacts=(ContentEvidence.from_bytes("a", b"other"),)))


def test_five_operation_capture_keeps_both_artifacts_without_raw_body() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    secret = b"SYNTHETIC PAN 4111111111111111"
    memory = {}

    read = sdk.attach_tool(
        lambda: secret,
        name="read",
        surface="document",
        operation="READ",
        capture=lambda frame: (
            CaptureResult((ContentEvidence.from_bytes("doc", frame.result),))
            if frame.phase == "END"
            else None
        ),
    )
    execute = sdk.attach_tool(
        lambda value: len(value), name="execute", surface="execution", operation="EXECUTE"
    )
    write = sdk.attach_tool(
        lambda value: memory.setdefault("doc", value),
        name="write",
        surface="memory",
        operation="WRITE",
    )
    recall = sdk.attach_tool(
        lambda: memory["doc"], name="recall", surface="memory", operation="READ"
    )
    output = sdk.attach_tool(
        lambda: "Processed synthetic request.",
        name="output",
        surface="output",
        operation="WRITE",
        capture=lambda frame: (
            CaptureResult((ContentEvidence.from_bytes("final", frame.result.encode()),))
            if frame.phase == "END"
            else None
        ),
    )

    with sdk.episode(
        "five", expected_surfaces=("document", "tool", "execution", "memory", "output")
    ) as episode:
        value = read()
        assert execute(value) == len(secret)
        assert write(value) == secret
        assert recall() == secret
        assert output() == "Processed synthetic request."

    snapshot = episode.inspect().to_dict()
    assert len(snapshot["observations"]) == 10
    assert [
        artifact["artifact"] for row in snapshot["observations"] for artifact in row["artifacts"]
    ] == [
        "doc",
        "final",
    ]
    assert snapshot["coverage"]["missing_surfaces"] == ["tool"]
    assert secret.decode() not in str(snapshot)


def test_event_cap_is_sdk_global_and_discard_reclaims_exact_reservation() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance", max_events=2)
    first = sdk.episode("first", expected_surfaces=("tool",))
    second = sdk.episode("second", expected_surfaces=("tool",))
    first.observe(_input("first"))
    first.observe(_input("first", phase="END", outcome="SUCCEEDED"))
    assert second.observe(_input("second-start")) is None
    assert sdk.discard_episode("first") is True
    assert second.observe(_input("second-start")) is not None


def test_generator_throw_is_observed_once_and_preserves_stop_value() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")

    def stream():
        try:
            yield 1
        except ValueError:
            yield 2
        return 9

    wrapped = sdk.attach_tool(stream, name="stream", surface="tool", operation="EXECUTE")
    with sdk.episode("stream", expected_surfaces=("tool",)) as episode:
        iterator = wrapped()
        assert next(iterator) == 1
        assert iterator.throw(ValueError("cancel")) == 2
        with pytest.raises(StopIteration) as stopped:
            next(iterator)
        assert stopped.value.value == 9
    rows = episode.inspect().to_dict()["observations"]
    assert [row["phase"] for row in rows] == ["START", "CHUNK", "CHUNK", "END"]
    assert [row["outcome"] for row in rows][-1] == "SUCCEEDED"


def test_detached_wrapper_cannot_capture_and_closed_sdk_rejects_attach() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    wrapped = sdk.attach_tool(lambda: 1, name="tool", surface="tool", operation="EXECUTE")
    sdk.detach(wrapped)
    with sdk.episode("detached", expected_surfaces=("tool",)) as episode:
        assert wrapped() == 1
    assert episode.inspect().to_dict()["observations"] == []
    sdk.close()
    with pytest.raises(EpisodeLifecycleError, match="SDK_CLOSED"):
        sdk.attach_tool(lambda: 2, name="other", surface="tool", operation="EXECUTE")


def test_mcp_attachment_is_deduplicated_and_preserves_caller_method_binding() -> None:
    class Client:
        owned = True

        def __init__(self):
            self.calls = 0

        async def call_tool(self, request):
            assert self.owned is True
            self.calls += 1
            return request

    sdk = Ancilis("tenant", "source", source_instance="instance")
    client = Client()
    surfaces = {"read": {"surface": "document", "operation": "READ"}}
    adapter = sdk.attach_mcp(client, surfaces=surfaces)
    assert sdk.attach_mcp(client, surfaces=surfaces) is adapter

    async def exercise():
        request = {"name": "read"}
        with sdk.episode("mcp", expected_surfaces=("document",)) as episode:
            assert await adapter.call_tool(request) is request
        assert len(episode.inspect().to_dict()["observations"]) == 2

    asyncio.run(exercise())
    assert client.calls == 1


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Ancilis("tenant", "source", source_instance=""),
        lambda: ContentEvidence("artifact", "g" * 64, 1),
        lambda: ContentEvidence("artifact", "0" * 64, True),
        lambda: Relationship("NOT_A_RELATIONSHIP", "a", "b"),
        lambda: ObservationInput(
            "call", "2026-99-99T00:00:00.000000Z", "tool", "EXECUTE", "START", None, "STARTED"
        ),
        lambda: ObservationInput(
            "call", "2026-09-10T00:00:00.000000Z", "tool", "EXECUTE", "CHUNK", True, "OBSERVED"
        ),
        lambda: Ancilis("tenant", "source", source_instance="instance", max_events=True),
        lambda: Ancilis("tenant", "source", source_instance="instance", strict_capture=1),
    ],
)
def test_public_dataclass_and_policy_constructors_reject_invalid_contract_values(factory) -> None:
    with pytest.raises((EpisodeError, ValueError)):
        factory()


def test_advisory_episode_cap_returns_saturated_handle_and_strict_raises() -> None:
    sdk = Ancilis("tenant", "source", max_episodes=1)
    sdk.episode("one", expected_surfaces=("tool",))
    saturated = sdk.episode("two", expected_surfaces=("tool",))
    assert saturated.inspect().to_dict()["coverage"]["reasons"] == ["LEDGER_EPISODE_CAP"]
    strict = Ancilis("tenant", "source", max_episodes=1, strict_capture=True)
    strict.episode("one", expected_surfaces=("tool",))
    with pytest.raises(EpisodeCapacityError):
        strict.episode("two", expected_surfaces=("tool",))


def test_sync_async_task_and_generator_wrappers_preserve_application_protocols() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")

    def sync(value):
        return value

    async def coro(value):
        return value

    def stream():
        received = yield "one"
        yield received

    wrapped_sync = sdk.attach_tool(sync, name="sync", surface="tool", operation="EXECUTE")
    wrapped_coro = sdk.attach_tool(coro, name="coro", surface="tool", operation="EXECUTE")
    wrapped_stream = sdk.attach_tool(stream, name="stream", surface="tool", operation="EXECUTE")
    assert wrapped_sync(object()) is not None
    assert inspect.iscoroutinefunction(wrapped_coro)
    assert asyncio.run(wrapped_coro("value")) == "value"
    iterator = wrapped_stream()
    assert next(iterator) == "one"
    assert iterator.send("two") == "two"


def test_active_episode_capture_is_metadata_only_by_default_and_callback_returns_refs() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")

    def callback(frame):
        if frame.phase == "END":
            return CaptureResult((ContentEvidence.from_bytes("out", b"body"),))
        return None

    wrapped = sdk.attach_tool(
        lambda: "result", name="tool", surface="tool", operation="EXECUTE", capture=callback
    )
    with sdk.episode("episode", expected_surfaces=("tool",)) as episode:
        assert wrapped() == "result"
    data = episode.inspect().to_dict()
    assert data["coverage"]["observed_surfaces"] == ["tool"]
    assert data["observations"][-1]["artifacts"][0]["sha256"]


def test_async_generator_wrapper_is_lazy_and_forwards_send_close() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")

    async def stream():
        received = yield "one"
        yield received

    wrapped = sdk.attach_tool(stream, name="stream", surface="tool", operation="EXECUTE")
    assert inspect.isasyncgenfunction(wrapped)

    async def consume():
        iterator = wrapped()
        assert await anext(iterator) == "one"
        assert await iterator.asend("two") == "two"
        await iterator.aclose()

    asyncio.run(consume())


def test_closed_sdk_wrapper_still_calls_application_without_admitting_new_events() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    wrapped = sdk.attach_tool(lambda: "value", name="tool", surface="tool", operation="EXECUTE")
    with sdk.episode("episode", expected_surfaces=("tool",)) as episode:
        sdk.close()
        assert wrapped() == "value"
    assert episode.inspect().to_dict()["observations"] == []
    assert sdk.diagnostics().to_dict()["reasons"] == {"SDK_CLOSED": 1}


def test_public_projections_are_typed_and_tombstone_resets_to_episode_genesis() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    episode = sdk.episode("episode", expected_surfaces=("tool",))
    observation = episode.observe(_input("call"))
    assert observation.event_id == observation.to_dict()["event_id"]
    before = episode.inspect()
    assert before.observation_chain_sha256 != before.open_sha256
    assert sdk.discard_episode("episode") is True
    snapshot = episode.inspect()
    assert snapshot.observations == ()
    assert snapshot.coverage.observed_surfaces == ()
    assert snapshot.coverage.incomplete_calls == 0
    assert snapshot.coverage.reasons[-1] == "DISCARDED_EPISODE"
    assert (
        snapshot.observation_chain_sha256
        == __import__("hashlib")
        .sha256(
            b"ancilis-native-observation-chain/1\n"
            + canonical_json({"open_sha256": snapshot.open_sha256})
        )
        .hexdigest()
    )
    verdict = verify_episode_snapshot(snapshot)
    assert verdict.status == "UNVERIFIED"
    assert verdict.reasons == ("NATIVE_HISTORY_DISCARDED",)


def test_unsigned_verifier_rejects_payload_reorder_duplicate_and_foreign_scope() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    episode = sdk.episode("episode", expected_surfaces=("tool",))
    episode.observe(_input("call"))
    episode.observe(_input("call", phase="END", outcome="SUCCEEDED"))
    valid = episode.inspect().to_dict()
    assert verify_episode_snapshot(valid).reasons == ("NATIVE_CHAIN_MATCH",)
    for mutate in (
        lambda value: value["observations"].__setitem__(
            0, {**value["observations"][0], "outcome": "OBSERVED"}
        ),
        lambda value: value["observations"].reverse(),
        lambda value: value["observations"].append(copy.deepcopy(value["observations"][0])),
        lambda value: value["observations"].__setitem__(
            0, {**value["observations"][0], "tenant": "foreign"}
        ),
    ):
        invalid = copy.deepcopy(valid)
        mutate(invalid)
        result = verify_episode_snapshot(invalid).to_dict()
        assert result["status"] == "REJECTED"
        assert result["reasons"] in (["NATIVE_CHAIN_MISMATCH"], ["INVALID_NATIVE_SNAPSHOT"])


def test_ordinary_callable_returning_coroutine_or_async_generator_is_lazy() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    started = []

    async def coroutine():
        started.append("coroutine")
        return object()

    async def async_stream():
        started.append("stream")
        yield "one"

    wrapped_coroutine = sdk.attach_tool(
        lambda: coroutine(), name="coro", surface="tool", operation="EXECUTE"
    )
    wrapped_stream = sdk.attach_tool(
        lambda: async_stream(), name="stream", surface="tool", operation="EXECUTE"
    )

    async def exercise():
        with sdk.episode("lazy", expected_surfaces=("tool",)) as episode:
            pending = wrapped_coroutine()
            iterator = wrapped_stream()
            assert started == []
            assert await pending is not None
            assert await anext(iterator) == "one"
        assert [row["phase"] for row in episode.inspect().to_dict()["observations"]] == [
            "START",
            "START",
            "END",
            "CHUNK",
        ]

    asyncio.run(exercise())


def test_custom_awaitable_is_returned_unchanged_without_telemetry_execution() -> None:
    class Custom:
        executed = False

        def __await__(self):
            self.executed = True
            yield
            return "value"

    sdk = Ancilis("tenant", "source", source_instance="instance")
    custom = Custom()
    wrapped = sdk.attach_tool(lambda: custom, name="custom", surface="tool", operation="EXECUTE")
    with sdk.episode("custom", expected_surfaces=("tool",)) as episode:
        assert wrapped() is custom
        assert not custom.executed
    assert episode.inspect().coverage.reasons == ("UNSUPPORTED_RETURN_PROTOCOL",)


def test_nested_same_episode_context_restores_outer_binding() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    wrapped = sdk.attach_tool(lambda: "value", name="tool", surface="tool", operation="EXECUTE")
    with sdk.episode("nested", expected_surfaces=("tool",)) as episode:
        wrapped()
        with episode:
            wrapped()
        wrapped()
    assert len(episode.inspect().observations) == 6
