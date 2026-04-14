"""Tests for patch_openai / unpatch_openai."""

from __future__ import annotations

import sys
import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def test_patch_wraps_create(openai_stub, response_dict):
    """After patch_openai(), calling create() still returns the original response."""
    openai_stub.chat.completions.create = MagicMock(return_value=response_dict)

    with patch("ancilis_openai.patch._submit"):
        from ancilis_openai.patch import patch_openai
        patch_openai(agent_id="test")

        result = openai_stub.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
        )

    assert result == response_dict


def test_unpatch_restores_original(openai_stub, response_dict):
    """unpatch_openai() restores the original create function."""
    original_create = MagicMock(return_value=response_dict)
    openai_stub.chat.completions.create = original_create

    with patch("ancilis_openai.patch._submit"):
        from ancilis_openai.patch import patch_openai, unpatch_openai

        patch_openai()
        assert openai_stub.chat.completions.create is not original_create

        unpatch_openai()
        assert openai_stub.chat.completions.create is original_create


def test_patch_only_once(openai_stub, response_dict):
    """Calling patch_openai() twice is idempotent — create wrapped only once."""
    original_create = MagicMock(return_value=response_dict)
    openai_stub.chat.completions.create = original_create

    with patch("ancilis_openai.patch._submit"):
        from ancilis_openai.patch import patch_openai, unpatch_openai

        patch_openai()
        once_wrapped = openai_stub.chat.completions.create

        patch_openai()  # second call — should be no-op
        assert openai_stub.chat.completions.create is once_wrapped

        unpatch_openai()
        assert openai_stub.chat.completions.create is original_create


def test_unpatch_when_not_patched(openai_stub):
    """unpatch_openai() is safe to call even if not patched."""
    from ancilis_openai.patch import unpatch_openai
    # Should not raise
    unpatch_openai()


def test_patch_emits_evidence(openai_stub, response_dict):
    """patch_openai() causes _emit to be called with correct model."""
    original_create = MagicMock(return_value=response_dict)
    openai_stub.chat.completions.create = original_create
    captured: list[Any] = []

    def fake_emit(producer, model, request, response, event="response"):
        captured.append({"model": model, "event": event})

    with patch("ancilis_openai.patch._emit", side_effect=fake_emit):
        from ancilis_openai.patch import patch_openai
        patch_openai(agent_id="test")

        openai_stub.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
        )

    assert len(captured) == 1
    assert captured[0]["model"] == "gpt-4o"
    assert captured[0]["event"] == "response"


def test_stream_evidence_emitted_on_completion(openai_stub, stream_chunks):
    """Streaming: evidence emitted after all chunks consumed, event=stream_complete."""
    openai_stub.chat.completions.create = MagicMock(return_value=iter(stream_chunks))
    captured: list[Any] = []

    def fake_emit(producer, model, request, response, event="response"):
        captured.append({"model": model, "event": event, "response": response})

    with patch("ancilis_openai.patch._emit", side_effect=fake_emit):
        from ancilis_openai.patch import patch_openai
        patch_openai()

        result = openai_stub.chat.completions.create(
            model="gpt-4o", messages=[], stream=True
        )
        # Evidence NOT emitted yet — must consume stream
        assert len(captured) == 0

        chunks = list(result)  # consume
        assert len(chunks) == len(stream_chunks)

    assert len(captured) == 1
    assert captured[0]["event"] == "stream_complete"


def test_stream_content_reconstructed(openai_stub, stream_chunks):
    """Reconstructed content from stream chunks is correct."""
    openai_stub.chat.completions.create = MagicMock(return_value=iter(stream_chunks))
    captured: list[Any] = []

    def fake_emit(producer, model, request, response, event="response"):
        captured.append(response)

    with patch("ancilis_openai.patch._emit", side_effect=fake_emit):
        from ancilis_openai.patch import patch_openai
        patch_openai()

        result = openai_stub.chat.completions.create(model="gpt-4o", messages=[], stream=True)
        list(result)

    assert len(captured) == 1
    content = captured[0]["choices"][0]["message"]["content"]
    assert content == "Hello world"


def test_thread_safety(openai_stub, response_dict):
    """Concurrent calls don't cross-contaminate evidence."""
    results: list[str] = []
    lock = threading.Lock()
    errors: list[Exception] = []

    def make_response(model: str) -> dict:
        r = dict(response_dict)
        r["model"] = model
        return r

    call_count = [0]

    def fake_create(**kwargs: Any) -> dict:
        model = kwargs.get("model", "unknown")
        return make_response(model)

    openai_stub.chat.completions.create = MagicMock(side_effect=fake_create)

    emitted_models: list[str] = []

    def fake_emit(producer, model, request, response, event="response"):
        with lock:
            emitted_models.append(model)

    with patch("ancilis_openai.patch._emit", side_effect=fake_emit):
        from ancilis_openai.patch import patch_openai
        patch_openai()

        def call(model: str) -> None:
            try:
                openai_stub.chat.completions.create(model=model, messages=[])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call, args=(f"model-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert not errors
    assert len(emitted_models) == 10
    assert sorted(emitted_models) == sorted(f"model-{i}" for i in range(10))


def test_response_to_dict_passthrough(response_dict):
    """_response_to_dict returns dict as-is."""
    from ancilis_openai.patch import _response_to_dict

    assert _response_to_dict(response_dict) is response_dict


def test_response_to_dict_model_dump():
    """_response_to_dict calls model_dump() if available."""
    from ancilis_openai.patch import _response_to_dict

    obj = MagicMock()
    obj.model_dump.return_value = {"model": "gpt-4o", "choices": []}
    result = _response_to_dict(obj)
    assert result == {"model": "gpt-4o", "choices": []}


def test_submit_never_raises(openai_stub, response_dict):
    """Engine errors in _submit must not propagate."""
    openai_stub.chat.completions.create = MagicMock(return_value=response_dict)

    with patch("ancilis_openai.patch._submit", side_effect=RuntimeError("boom")):
        from ancilis_openai.patch import patch_openai
        # Should not raise
        patch_openai()
        openai_stub.chat.completions.create(model="gpt-4o", messages=[])
