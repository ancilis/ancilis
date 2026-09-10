"""Behavioral regressions for the volatile native Python episode ledger."""

from __future__ import annotations

import asyncio
import inspect

import pytest

from ancilis.episodes import (
    Ancilis,
    CaptureResult,
    ContentEvidence,
    EpisodeCapacityError,
    ObservationConflict,
    ObservationInput,
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
    assert sdk.diagnostics().to_dict()["reasons"] == [{"reason": "SDK_CLOSED", "count": 1}]
