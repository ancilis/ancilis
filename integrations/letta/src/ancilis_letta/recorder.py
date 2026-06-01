"""record_response — standalone evidence recorder for ``LettaResponse`` payloads.

When you don't want to wrap the client (for example, you're replaying responses
from a fixture, processing async webhooks, or already have ``LettaResponse``
objects from another code path), call ``record_response`` to translate every
message in the response into Ancilis evidence.

The function is duck-typed: ``response`` may be a real ``LettaResponse``, a
plain dict, or any object exposing a ``messages`` attribute / item.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any
from collections.abc import Iterable

from ancilis_letta._producer import LettaProducer

logger = logging.getLogger(__name__)


def record_response(
    response: Any,
    *,
    agent_id: str,
    engine: Any = None,
    evidence_store: Any = None,
    session_id: str | None = None,
) -> list[Any]:
    """Translate every message in ``response`` and submit it as evidence.

    Parameters
    ----------
    response:
        A ``LettaResponse``-like object or dict with a ``messages`` field, or a
        plain list of message-like objects.
    agent_id:
        Identifier recorded on every Action.
    engine:
        Optional Ancilis Engine. When provided, ``engine.evaluate(action)`` is
        called for every translated Action. Errors are swallowed.
    evidence_store:
        Optional Ancilis EvidenceStore. When provided, ``store.append(action)``
        is called for every translated Action. Errors are swallowed.
    session_id:
        Optional session correlator. If omitted, a uuid4 is generated.

    Returns
    -------
    list[Action]
        The translated Action objects, in input order.
    """
    producer = LettaProducer(
        agent_id=agent_id,
        session_id=session_id or str(uuid.uuid4()),
    )

    actions: list[Any] = []
    for raw in _iter_messages(response):
        try:
            normalised = _normalise_message(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: failed to normalise message: %s", exc)
            continue
        if normalised is None:
            continue
        try:
            action = producer.translate(normalised)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: failed to translate message: %s", exc)
            continue
        actions.append(action)
        _submit(action, engine, evidence_store)

    # Capture any usage_statistics tail attached to the response.
    usage = _extract_usage(response)
    if usage is not None:
        try:
            usage_action = producer.translate(
                {"kind": "usage_statistics", "usage_statistics": usage}
            )
            actions.append(usage_action)
            _submit(usage_action, engine, evidence_store)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: failed to record usage_statistics: %s", exc)

    return actions


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _iter_messages(response: Any) -> Iterable[Any]:
    """Yield message-like objects from a duck-typed response container."""
    if response is None:
        return []
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        msgs = response.get("messages")
        if msgs is None:
            return []
        return msgs
    msgs = getattr(response, "messages", None)
    if msgs is None:
        return []
    return msgs


def _normalise_message(msg: Any) -> dict[str, Any] | None:
    """Convert a Letta message subtype (or dict) into the producer's raw shape."""
    if msg is None:
        return None
    out = dict(msg) if isinstance(msg, dict) else _attrs_to_dict(msg)

    # The producer keys on ``kind``. Letta SDK exposes ``message_type`` on each
    # message subtype; if it's missing, derive from class name.
    if "kind" not in out:
        kind = out.get("message_type")
        if kind is None:
            cls = getattr(msg, "__class__", None)
            cls_name = cls.__name__ if cls is not None else "UnknownMessage"
            kind = _classname_to_kind(cls_name)
        if kind is not None:
            out["kind"] = kind

    # Convert nested tool_call object into a plain dict the producer can read.
    tc = out.get("tool_call")
    if tc is not None and not isinstance(tc, dict):
        out["tool_call"] = {
            "name": getattr(tc, "name", None),
            "arguments": getattr(tc, "arguments", None),
            "tool_call_id": getattr(tc, "tool_call_id", None),
        }
    return out


def _attrs_to_dict(obj: Any) -> dict[str, Any]:
    """Best-effort projection of a pydantic / dataclass / vanilla object to dict."""
    # pydantic v2
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:  # noqa: BLE001
            pass
    # pydantic v1
    dict_method = getattr(obj, "dict", None)
    if callable(dict_method):
        try:
            return dict_method()
        except Exception:  # noqa: BLE001
            pass
    # Walk MRO so class-level attrs (e.g. ``message_type = "user_message"``)
    # are included alongside instance attrs.
    out: dict[str, Any] = {}
    seen: set[str] = set()
    cls = getattr(obj, "__class__", None)
    classes = list(getattr(cls, "__mro__", [cls])) if cls is not None else []
    for klass in classes:
        for name in vars(klass):
            if name.startswith("_") or name in seen:
                continue
            value = getattr(obj, name, None)
            if callable(value):
                continue
            out[name] = value
            seen.add(name)
    inst_dict = getattr(obj, "__dict__", None)
    if isinstance(inst_dict, dict):
        for k, v in inst_dict.items():
            if not k.startswith("_") and not callable(v):
                out[k] = v
    return out


def _classname_to_kind(name: str) -> str | None:
    mapping = {
        "SystemMessage": "system_message",
        "UserMessage": "user_message",
        "AssistantMessage": "assistant_message",
        "ToolCallMessage": "tool_call_message",
        "ToolReturnMessage": "tool_return_message",
        "ReasoningMessage": "reasoning_message",
    }
    return mapping.get(name)


def _extract_usage(response: Any) -> Any:
    """Pull a ``usage`` / ``usage_statistics`` payload off the response container."""
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("usage") or response.get("usage_statistics")
    return getattr(response, "usage", None) or getattr(response, "usage_statistics", None)


def _submit(action: Any, engine: Any, evidence_store: Any) -> None:
    """Forward action to engine + evidence store. Errors are swallowed."""
    if engine is not None:
        try:
            engine.evaluate(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: engine.evaluate failed: %s", exc)
    if evidence_store is not None:
        try:
            evidence_store.append(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: evidence_store.append failed: %s", exc)
