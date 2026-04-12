"""patch_openai / unpatch_openai — monkey-patch OpenAI SDK for zero-config evidence capture."""

from __future__ import annotations

import functools
import threading
from typing import Any, Generator, Iterator

from ancilis_openai._producer import OpenAIProducer

_lock = threading.Lock()
_patched = False
_originals: dict[str, Any] = {}
_thread_local = threading.local()


def patch_openai(
    agent_id: str = "openai-agent",
    session_id: str | None = None,
) -> None:
    """Monkey-patch openai.chat.completions.create (sync + async) to capture evidence.

    Safe to call multiple times — only patches once.
    Call `unpatch_openai()` to restore original behaviour.
    """
    global _patched

    try:
        import openai
    except ImportError as exc:
        raise ImportError(
            "openai package is required. Install it with: pip install openai>=1.0.0"
        ) from exc

    with _lock:
        if _patched:
            return

        producer = OpenAIProducer(agent_id=agent_id, session_id=session_id)

        # --- sync create ---
        original_create = openai.chat.completions.create
        _originals["chat.completions.create"] = original_create

        @functools.wraps(original_create)
        def patched_create(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", "unknown")
            stream = kwargs.get("stream", False)

            if stream:
                return _wrap_stream(
                    original_create(*args, **kwargs),
                    producer=producer,
                    model=model,
                    request=kwargs,
                )

            response = original_create(*args, **kwargs)
            _emit(producer, model, kwargs, _response_to_dict(response))
            return response

        openai.chat.completions.create = patched_create  # type: ignore[method-assign]

        # --- async create ---
        try:
            original_acreate = openai.chat.completions.acreate
            _originals["chat.completions.acreate"] = original_acreate

            @functools.wraps(original_acreate)
            async def patched_acreate(*args: Any, **kwargs: Any) -> Any:
                model = kwargs.get("model", "unknown")
                response = await original_acreate(*args, **kwargs)
                _emit(producer, model, kwargs, _response_to_dict(response))
                return response

            openai.chat.completions.acreate = patched_acreate  # type: ignore[method-assign]
        except AttributeError:
            # Some openai versions don't expose acreate at top level
            pass

        _patched = True


def unpatch_openai() -> None:
    """Restore original openai methods. Safe to call even if not patched."""
    global _patched

    try:
        import openai
    except ImportError:
        return

    with _lock:
        if not _patched:
            return

        if "chat.completions.create" in _originals:
            openai.chat.completions.create = _originals.pop("chat.completions.create")  # type: ignore[method-assign]
        if "chat.completions.acreate" in _originals:
            openai.chat.completions.acreate = _originals.pop("chat.completions.acreate")  # type: ignore[method-assign]

        _originals.clear()
        _patched = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _emit(
    producer: OpenAIProducer,
    model: str,
    request: dict[str, Any],
    response: dict[str, Any],
    event: str = "response",
) -> None:
    """Build and submit an Action to the Ancilis engine. Never raises."""
    try:
        raw = {
            "event": event,
            "model": model,
            "request": request,
            "response": response,
        }
        action = producer.translate(raw)
        _submit(action)
    except Exception:  # noqa: BLE001
        pass


def _submit(action: Any) -> None:
    """Submit to Ancilis engine. Never raises."""
    try:
        from ancilis.config import load_config
        from ancilis.engine.engine import ControlEngine

        config = load_config()
        engine = ControlEngine(config)
        engine.evaluate(action)
    except Exception:  # noqa: BLE001
        pass


def _response_to_dict(response: Any) -> dict[str, Any]:
    """Convert an openai response object to a plain dict for the producer."""
    if isinstance(response, dict):
        return response
    try:
        return response.model_dump()
    except AttributeError:
        pass
    # Fallback: extract common fields
    result: dict[str, Any] = {}
    if hasattr(response, "model"):
        result["model"] = response.model
    if hasattr(response, "usage") and response.usage:
        usage = response.usage
        result["usage"] = {
            "prompt_tokens": getattr(usage, "prompt_tokens", 0),
            "completion_tokens": getattr(usage, "completion_tokens", 0),
            "total_tokens": getattr(usage, "total_tokens", 0),
        }
    if hasattr(response, "choices") and response.choices:
        choices = []
        for ch in response.choices:
            choice_dict: dict[str, Any] = {}
            if hasattr(ch, "finish_reason"):
                choice_dict["finish_reason"] = ch.finish_reason
            if hasattr(ch, "message") and ch.message:
                msg = ch.message
                choice_dict["message"] = {
                    "content": getattr(msg, "content", None),
                    "tool_calls": _tool_calls_to_list(getattr(msg, "tool_calls", None)),
                }
            choices.append(choice_dict)
        result["choices"] = choices
    return result


def _tool_calls_to_list(tool_calls: Any) -> list[dict[str, Any]]:
    if not tool_calls:
        return []
    result = []
    for tc in tool_calls:
        entry: dict[str, Any] = {}
        if hasattr(tc, "function"):
            entry["function"] = {
                "name": getattr(tc.function, "name", ""),
                "arguments": getattr(tc.function, "arguments", ""),
            }
        result.append(entry)
    return result


class _StreamWrapper:
    """Wraps a streaming response to collect chunks and emit evidence on completion."""

    def __init__(
        self,
        stream: Any,
        producer: OpenAIProducer,
        model: str,
        request: dict[str, Any],
    ) -> None:
        self._stream = stream
        self._producer = producer
        self._model = model
        self._request = request
        self._chunks: list[Any] = []

    def __iter__(self) -> Iterator[Any]:
        try:
            for chunk in self._stream:
                self._chunks.append(chunk)
                yield chunk
        finally:
            self._emit_evidence()

    def __enter__(self) -> "_StreamWrapper":
        return self

    def __exit__(self, *args: Any) -> None:
        if hasattr(self._stream, "__exit__"):
            self._stream.__exit__(*args)

    def _emit_evidence(self) -> None:
        """Emit evidence after stream is exhausted."""
        response = _reconstruct_stream_response(self._chunks, self._model)
        _emit(self._producer, self._model, self._request, response, event="stream_complete")


def _wrap_stream(
    stream: Any,
    producer: OpenAIProducer,
    model: str,
    request: dict[str, Any],
) -> _StreamWrapper:
    return _StreamWrapper(stream, producer, model, request)


def _reconstruct_stream_response(chunks: list[Any], model: str) -> dict[str, Any]:
    """Reconstruct a response-like dict from stream chunks."""
    content_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    finish_reason: str | None = None

    for chunk in chunks:
        choices = getattr(chunk, "choices", []) or []
        for choice in choices:
            delta = getattr(choice, "delta", None)
            if delta:
                content = getattr(delta, "content", None)
                if content:
                    content_parts.append(content)
                tc_list = getattr(delta, "tool_calls", None)
                if tc_list:
                    tool_calls.extend(_tool_calls_to_list(tc_list))
            fr = getattr(choice, "finish_reason", None)
            if fr:
                finish_reason = fr

    full_content = "".join(content_parts)
    return {
        "model": model,
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {
                    "content": full_content,
                    "tool_calls": tool_calls,
                },
            }
        ],
        # Usage not available from streaming by default
        "usage": {},
    }
