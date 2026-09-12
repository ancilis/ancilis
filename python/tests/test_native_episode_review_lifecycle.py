"""Regressions from the corrected native batch's independent review."""

import asyncio
import gc

import pytest

from ancilis import Ancilis, verify_episode_snapshot


def attach(owner, fn, **options):
    return owner.attach_tool(
        fn, name="stream", surface="tool", operation="EXECUTE", **options
    )


def test_abandoned_generator_releases_capture_without_inventing_an_end():
    owner = Ancilis("tenant", "source", max_episodes=1)
    frames = []

    def stream():
        yield 1
        yield 2

    wrapped = attach(owner, lambda: stream(), capture=lambda frame: frames.append(frame.phase))
    with owner.episode("one", expected_surfaces=("tool",)) as episode:
        iterator = wrapped()
        assert next(iterator) == 1
        del iterator
        gc.collect()
        snapshot = episode.inspect().to_dict()
        assert "MISSING_END" in snapshot["coverage"]["reasons"]
        assert snapshot["coverage"]["incomplete_calls"] == 1
        assert snapshot["coverage"]["lost_events"] == 1
        assert frames == ["START", "CHUNK"]
        assert verify_episode_snapshot(snapshot).status == "UNVERIFIED"
    assert owner.discard_episode("one") is True
    with owner.episode("two", expected_surfaces=("tool",)) as next_episode:
        assert next_episode.inspect().to_dict()["coverage"]["lost_events"] == 0


@pytest.mark.asyncio
async def test_abandoned_async_generator_releases_capture_without_calling_callback():
    owner = Ancilis("tenant", "source", max_episodes=1)
    frames = []

    async def stream():
        yield 1
        yield 2

    wrapped = attach(owner, lambda: stream(), capture=lambda frame: frames.append(frame.phase))
    with owner.episode("one", expected_surfaces=("tool",)) as episode:
        iterator = wrapped()
        assert await anext(iterator) == 1
        del iterator
        gc.collect()
        await asyncio.sleep(0)
        assert "MISSING_END" in episode.inspect().to_dict()["coverage"]["reasons"]
        assert frames == ["START", "CHUNK"]
    assert owner.discard_episode("one") is True


def test_generator_argument_error_preserves_error_and_releases_episode():
    owner = Ancilis("tenant", "source")

    def stream(required):
        yield required

    wrapped = attach(owner, stream)
    with owner.episode("one", expected_surfaces=("tool",)) as episode:
        with pytest.raises(TypeError, match="required"):
            next(wrapped())
        assert episode.inspect().to_dict()["observations"][-1]["outcome"] == "FAILED"
    assert owner.discard_episode("one") is True


@pytest.mark.asyncio
async def test_async_generator_argument_error_preserves_error_and_releases_episode():
    owner = Ancilis("tenant", "source")

    async def stream(required):
        yield required

    wrapped = attach(owner, stream)
    with owner.episode("one", expected_surfaces=("tool",)) as episode:
        with pytest.raises(TypeError, match="required"):
            await anext(wrapped())
        assert episode.inspect().to_dict()["observations"][-1]["outcome"] == "FAILED"
    assert owner.discard_episode("one") is True


@pytest.mark.parametrize("caps,count", [({"max_attachments": 3}, 3), ({"max_diagnostic_keys": 2}, 2)])
def test_mcp_capacity_refusal_does_not_leave_partial_attachments(caps, count):
    owner = Ancilis("tenant", "source", **caps)
    attach(owner, lambda: 42)

    class Client:
        def call_tool(self, name):
            return name

    before = owner.diagnostics().to_dict()["attachments"]
    surfaces = {str(i): {"surface": "tool", "operation": "EXECUTE"} for i in range(count)}
    with pytest.raises(ValueError, match="ATTACHMENT_CAP"):
        owner.attach_mcp(Client(), surfaces=surfaces)
    assert owner.diagnostics().to_dict()["attachments"] == before


def test_mcp_invalid_later_name_does_not_leave_partial_attachments():
    owner = Ancilis("tenant", "source")

    class Client:
        def call_tool(self, name):
            return name

    surfaces = {
        "a": {"surface": "tool", "operation": "EXECUTE"},
        "z\n": {"surface": "tool", "operation": "EXECUTE"},
    }
    with pytest.raises(ValueError, match="INVALID_ID"):
        owner.attach_mcp(Client(), surfaces=surfaces)
    assert owner.diagnostics().to_dict()["attachments"] == []
