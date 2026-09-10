"""Public native API parity and application-transparency regressions."""

import asyncio
import copy
import gc
import inspect
import weakref
import json
from pathlib import Path

import pytest

from ancilis import (
    Ancilis,
    CaptureResult,
    ContentEvidence,
    ObservationInput,
    verify_episode_snapshot,
)


def sdk(**kw):
    return Ancilis("tenant-a", "app", **kw)


def observe(call="c1", **kw):
    data = dict(
        call_id=call,
        occurred_at="2026-09-10T00:00:00.000000Z",
        surface="tool",
        operation="EXECUTE",
        phase="START",
        chunk_index=None,
        outcome="STARTED",
    )
    data.update(kw)
    return ObservationInput(**data)


def attach(owner, fn, **kw):
    return owner.attach_tool(
        fn, name=kw.pop("name", "tool"), surface="tool", operation="EXECUTE", **kw
    )


@pytest.mark.parametrize("fixture", json.loads((Path(__file__).resolve().parents[2] / "tests/fixtures/episodes/native-cross-language.json").read_text())["cases"], ids=lambda f: f["name"])
def test_cross_language_snapshots(fixture):
    assert verify_episode_snapshot(fixture["snapshot"], assessed_at="2026-09-10T00:00:00.000000Z").to_dict() == fixture["expected"]


def test_partial_call_capture_preserves_rows_and_reports_gaps():
    owner = sdk()
    ep = owner.episode("one", expected_surfaces=("tool",))
    ep.observe(observe(phase="CHUNK", chunk_index=2, outcome="OBSERVED"))
    ep.observe(observe(phase="END", outcome="SUCCEEDED"))
    snap = ep.inspect().to_dict()
    assert len(snap["observations"]) == 2
    assert snap["coverage"]["incomplete_calls"] == 1
    assert set(snap["coverage"]["reasons"]) == {"MISSING_START", "CHUNK_GAP"}
    assert verify_episode_snapshot(snap).status == "UNVERIFIED"


def test_empty_diagnostics_is_object_and_attached_capture_is_visible():
    owner = sdk()
    assert owner.diagnostics().to_dict()["reasons"] == {}
    fn = attach(owner, lambda: 42)
    with owner.episode("one", expected_surfaces=("tool",)):
        assert fn() == 42
    d = owner.diagnostics().to_dict()
    assert d["attachments"][0]["started"] == 1
    assert d["attachments"][0]["completed"] == 1
    assert d["attachments"][0]["events_admitted"] == 2


def test_callback_frames_cover_start_end_and_capture_failures_do_not_escape():
    owner = sdk()
    phases = []

    def capture(frame):
        phases.append(frame.phase)
        raise ValueError("SENSITIVE")

    fn = attach(owner, lambda: 42, capture=capture)
    with owner.episode("one", expected_surfaces=("tool",)):
        assert fn() == 42
    assert phases == ["START", "END"]
    assert owner.diagnostics().to_dict()["reasons"]["CAPTURE_CALLBACK_FAILED"] == 2
    assert "SENSITIVE" not in str(owner.diagnostics().to_dict())


def test_generator_kind_forwarding_and_final_value():
    owner = sdk()

    def stream():
        value = yield 1
        try:
            yield value
        except ValueError as error:
            yield error
        return 9

    wrapped = attach(owner, stream)
    assert inspect.isgeneratorfunction(wrapped)
    with owner.episode("one", expected_surfaces=("tool",)) as ep:
        iterator = wrapped()
        assert next(iterator) == 1
        assert iterator.send(7) == 7
        error = ValueError("original")
        assert iterator.throw(error) is error
        with pytest.raises(StopIteration) as stopped:
            next(iterator)
        assert stopped.value.value == 9
        iterator.close()
        iterator.close()
        assert [o.phase for o in ep.inspect().observations] == [
            "START",
            "CHUNK",
            "CHUNK",
            "CHUNK",
            "END",
        ]


@pytest.mark.asyncio
async def test_async_generator_asend_athrow_close_and_chunk_before_return():
    owner = sdk()
    final = []

    async def stream():
        try:
            value = yield 1
            try:
                yield value
            except ValueError as error:
                yield error
        finally:
            final.append(True)

    wrapped = attach(owner, stream)
    assert inspect.isasyncgenfunction(wrapped)
    with owner.episode("one", expected_surfaces=("tool",)) as ep:
        iterator = wrapped()
        assert await iterator.__anext__() == 1
        assert ep.inspect().observations[-1].phase == "CHUNK"
        assert await iterator.asend(7) == 7
        error = ValueError("original")
        assert await iterator.athrow(error) is error
        await iterator.aclose()
        await iterator.aclose()
        assert len(final) == 1
        rows = ep.inspect().to_dict()["observations"]
        assert [o["phase"] for o in rows] == ["START", "CHUNK", "CHUNK", "CHUNK", "END"]
        assert rows[-1]["outcome"] == "CLOSED_EARLY"


@pytest.mark.asyncio
async def test_async_bound_context_survives_await_and_concurrent_same_episode():
    owner = sdk()
    fn = attach(owner, lambda: 42)
    episode = owner.episode("shared", expected_surfaces=("tool",))

    async def work():
        await asyncio.sleep(0)
        return fn()

    bound = owner.bind_episode(work, episode)
    assert await bound() == 42

    async def nested():
        with episode:
            await asyncio.sleep(0)
            assert fn() == 42

    await asyncio.gather(nested(), nested())
    assert len(episode.inspect().observations) == 6
    assert "CONTEXT_EXIT_MISMATCH" not in owner.diagnostics().to_dict()["reasons"]


def test_task_identity_custom_iterator_and_metadata_ownership():
    owner = sdk()

    class Iterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise AssertionError("SDK consumed iterator")

    value = Iterator()
    fn = attach(owner, lambda: value)
    with owner.episode("one", expected_surfaces=("tool",)) as ep:
        assert fn() is value
    assert "UNSUPPORTED_RETURN_PROTOCOL" in ep.inspect().coverage.reasons


@pytest.mark.asyncio
async def test_task_retains_cancel_and_original_exception_identity():
    owner = sdk()
    task = asyncio.create_task(asyncio.sleep(100))
    fn = attach(owner, lambda: task)
    with owner.episode("one", expected_surfaces=("tool",)) as ep:
        assert fn() is task
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
    assert ep.inspect().to_dict()["observations"][-1]["outcome"] == "CANCELLED"


def test_discard_frees_slot_is_single_use_and_preserves_loss_totals():
    owner = sdk(max_episodes=1, max_events=1)
    fn = attach(owner, lambda: 42)
    with owner.episode("one", expected_surfaces=("tool",)) as ep:
        fn()
    assert owner.flush()["lost"] > 0
    # Lost END is not an in-flight operation once the actual call returned.
    assert owner.discard_episode("one") is True
    assert owner.discard_episode("one") is False
    assert owner.flush()["lost"] > 0
    with owner.episode("one", expected_surfaces=("tool",)) as new:
        assert new is not ep
        assert new.inspect().open_sha256 != ep.inspect().open_sha256
    assert owner.diagnostics().to_dict()["events"] == 0


def test_repeated_expected_surface_and_closed_manual_admission_rejected():
    owner = sdk()
    with pytest.raises(ValueError):
        owner.episode("bad", expected_surfaces=("tool", "tool"))
    ep = owner.episode("one", expected_surfaces=("tool",))
    owner.close()
    with pytest.raises(ValueError, match="SDK_CLOSED"):
        ep.observe(observe())


def test_arguments_and_results_are_not_retained_after_a_completed_call():
    owner = sdk()

    class Value:
        pass

    value = Value()
    reference = weakref.ref(value)
    fn = attach(owner, lambda arg: arg, capture=lambda frame: None)
    with owner.episode("one", expected_surfaces=("tool",)):
        assert fn(value) is value
    del value
    gc.collect()
    assert reference() is None


@pytest.mark.asyncio
async def test_mcp_keeps_python_call_signature_arguments_and_caller_ownership():
    owner = sdk()
    calls = []

    class Client:
        async def call_tool(self, name, arguments=None, **kw):
            calls.append((name, arguments, kw))
            return arguments

        async def close(self):
            raise AssertionError("caller owned")

    client = Client()
    options = {"read": {"surface": "document", "operation": "READ"}}
    attached = owner.attach_mcp(client, surfaces=options)
    assert owner.attach_mcp(client, surfaces=options) is attached
    args = {"synthetic": True}
    with owner.episode("one", expected_surfaces=("document",)):
        assert await attached.call_tool("read", args, meta="assertion") is args
    assert calls == [("read", args, {"meta": "assertion"})]
    await owner.aclose()


def test_verifier_rejects_extra_fields_invalid_tombstone_and_schema_invalid_claims():
    owner = sdk()
    ep = owner.episode("one", expected_surfaces=("tool",))
    ep.observe(observe())
    ep.observe(observe(phase="END", outcome="SUCCEEDED"))
    snapshot = ep.inspect().to_dict()
    assert verify_episode_snapshot(snapshot).status == "UNVERIFIED"
    extra = copy.deepcopy(snapshot)
    extra["trusted"] = True
    assert verify_episode_snapshot(extra).status == "REJECTED"
    assert verify_episode_snapshot({}).to_dict()["policy_sha256"]
    owner.discard_episode("one")
    tombstone = ep.inspect().to_dict()
    tombstone["revision_id"] = "f" * 64
    assert verify_episode_snapshot(tombstone).status == "REJECTED"


def test_verifier_assessment_policy_and_expected_tenant_are_explicit():
    owner = sdk()
    ep = owner.episode("one", expected_surfaces=("tool",))
    result = verify_episode_snapshot(ep.inspect(), expected_tenant="other").to_dict()
    assert result["status"] == "REJECTED"
    assert result["policy_sha256"] != ep.inspect().to_dict()["open"]["policy_sha256"]
