"""wrap_client() — proxy around a Letta client for Ancilis evidence capture.

The wrapper forwards all attribute access to the underlying client via
``__getattr__``, but intercepts the calls that touch evidence-relevant
surfaces:

* ``client.agents.messages.create`` — every returned message is recorded
* ``client.agents.messages.create_stream`` — every SSE event is recorded
* ``client.agents.archival_memory.create`` / ``update`` / ``search`` / ``delete``
* ``client.agents.core_memory.update``

letta-client is not imported at module load time — the wrapper is duck-typed
and only relies on the client exposing the documented method shape.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from ancilis_letta._producer import LettaProducer
from ancilis_letta.recorder import _normalise_message, _submit  # type: ignore[attr-defined]

logger = logging.getLogger(__name__)


def wrap_client(
    client: Any,
    *,
    agent_id: str,
    session_id: str | None = None,
    engine: Any = None,
    evidence_store: Any = None,
) -> _AncilisWrappedClient:
    """Return a proxy around ``client`` that records each call as Ancilis evidence.

    Parameters
    ----------
    client:
        A ``letta_client.Letta`` instance (or any duck-compatible object exposing
        ``agents.messages``, ``agents.archival_memory``, ``agents.core_memory``).
    agent_id:
        Identifier recorded on every Action. Required because Letta agents are
        identified by stable IDs across sessions.
    session_id:
        Optional session correlator. If omitted, a uuid4 is generated.
    engine:
        Optional Ancilis Engine. When provided, ``engine.evaluate(action)`` is
        called for every translated Action. Errors are swallowed.
    evidence_store:
        Optional Ancilis EvidenceStore. When provided, ``store.append(action)``
        is called for every translated Action. Errors are swallowed.
    """
    producer = LettaProducer(
        agent_id=agent_id,
        session_id=session_id or str(uuid.uuid4()),
    )
    return _AncilisWrappedClient(
        client,
        producer=producer,
        engine=engine,
        evidence_store=evidence_store,
        agent_id=agent_id,
    )


class _AncilisWrappedClient:
    """Proxy around a Letta client that records evidence on each call."""

    __slots__ = (
        "_client",
        "_producer",
        "_engine",
        "_store",
        "_agent_id",
        "_actions",
        "_agents_proxy",
    )

    def __init__(
        self,
        client: Any,
        *,
        producer: LettaProducer,
        engine: Any,
        evidence_store: Any,
        agent_id: str,
    ) -> None:
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_producer", producer)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_store", evidence_store)
        object.__setattr__(self, "_agent_id", agent_id)
        object.__setattr__(self, "_actions", [])
        object.__setattr__(self, "_agents_proxy", _AgentsProxy(self, client.agents))

    def __getattr__(self, name: str) -> Any:
        if name == "agents":
            return self._agents_proxy
        return getattr(self._client, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._client, name, value)

    @property
    def captured_actions(self) -> list[Any]:
        """Snapshot of every Action this wrapper has recorded (test hook)."""
        return list(self._actions)

    # Internal: shared record path used by all proxies below.
    def _record(self, raw: dict[str, Any]) -> Any:
        try:
            normalised = _normalise_message(raw)
            if normalised is None:
                return None
            action = self._producer.translate(normalised)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-letta: failed to translate event: %s", exc)
            return None
        self._actions.append(action)
        _submit(action, self._engine, self._store)
        return action


class _AgentsProxy:
    """Wraps ``client.agents`` to insert messages / memory proxies."""

    __slots__ = ("_owner", "_inner", "_messages_proxy", "_archival_proxy", "_core_proxy")

    def __init__(self, owner: _AncilisWrappedClient, inner: Any) -> None:
        self._owner = owner
        self._inner = inner
        self._messages_proxy = _MessagesProxy(owner, getattr(inner, "messages", None))
        self._archival_proxy = _ArchivalMemoryProxy(
            owner, getattr(inner, "archival_memory", None)
        )
        self._core_proxy = _CoreMemoryProxy(owner, getattr(inner, "core_memory", None))

    def __getattr__(self, name: str) -> Any:
        if name == "messages":
            return self._messages_proxy
        if name == "archival_memory":
            return self._archival_proxy
        if name == "core_memory":
            return self._core_proxy
        return getattr(self._inner, name)


class _MessagesProxy:
    """Wraps ``agents.messages`` — records each message in the response."""

    __slots__ = ("_owner", "_inner")

    def __init__(self, owner: _AncilisWrappedClient, inner: Any) -> None:
        self._owner = owner
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        try:
            response = self._inner.create(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "tool_return_message",
                    "agent_id": agent_id,
                    "error": exc,
                    "tool_name": "agents.messages.create",
                }
            )
            raise
        self._record_response(response, agent_id=agent_id)
        return response

    def create_stream(self, *args: Any, **kwargs: Any) -> _StreamProxy:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        try:
            stream = self._inner.create_stream(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "tool_return_message",
                    "agent_id": agent_id,
                    "error": exc,
                    "tool_name": "agents.messages.create_stream",
                }
            )
            raise
        return _StreamProxy(self._owner, stream, agent_id=agent_id)

    def list(self, *args: Any, **kwargs: Any) -> Any:
        # Listing existing messages is a read-only data access; we do not
        # record a per-message Action because no agent action is being taken.
        return self._inner.list(*args, **kwargs)

    def _record_response(self, response: Any, *, agent_id: str) -> None:
        messages = _messages_of(response)
        for msg in messages:
            raw = _normalise_message(msg) or {}
            raw.setdefault("agent_id", agent_id)
            self._owner._record(raw)
        usage = _usage_of(response)
        if usage is not None:
            self._owner._record(
                {
                    "kind": "usage_statistics",
                    "agent_id": agent_id,
                    "usage_statistics": usage,
                }
            )


class _StreamProxy:
    """Iterator wrapper that records each SSE event."""

    __slots__ = ("_owner", "_inner", "_agent_id", "_iter")

    def __init__(self, owner: _AncilisWrappedClient, inner: Any, *, agent_id: str) -> None:
        self._owner = owner
        self._inner = inner
        self._agent_id = agent_id
        self._iter = None

    def __iter__(self) -> _StreamProxy:
        self._iter = iter(self._inner)
        return self

    def __next__(self) -> Any:
        assert self._iter is not None
        event = next(self._iter)
        self._record_event(event)
        return event

    def __aiter__(self) -> _StreamProxy:
        self._iter = self._inner.__aiter__()
        return self

    async def __anext__(self) -> Any:
        assert self._iter is not None
        event = await self._iter.__anext__()
        self._record_event(event)
        return event

    def _record_event(self, event: Any) -> None:
        raw = _normalise_message(event) or {}
        raw.setdefault("agent_id", self._agent_id)
        self._owner._record(raw)


class _ArchivalMemoryProxy:
    """Wraps ``agents.archival_memory`` — records every memory operation."""

    __slots__ = ("_owner", "_inner")

    def __init__(self, owner: _AncilisWrappedClient, inner: Any) -> None:
        self._owner = owner
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        return self._wrap("archival_memory_create", args, kwargs, text_kw="text")

    def update(self, *args: Any, **kwargs: Any) -> Any:
        return self._wrap("archival_memory_update", args, kwargs, text_kw="text")

    def search(self, *args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        try:
            result = self._inner.search(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "archival_memory_search",
                    "agent_id": agent_id,
                    "query": kwargs.get("query") or (args[0] if args else None),
                    "error": exc,
                }
            )
            raise
        results = _list_of(result)
        self._owner._record(
            {
                "kind": "archival_memory_search",
                "agent_id": agent_id,
                "query": kwargs.get("query") or (args[0] if args else None),
                "results": results if isinstance(results, list) else None,
                "count": len(results) if isinstance(results, list) else None,
            }
        )
        return result

    def list(self, *args: Any, **kwargs: Any) -> Any:
        # Pure read of existing memory — record as a search-style data_access
        # with no query.
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        result = self._inner.list(*args, **kwargs)
        results = _list_of(result)
        self._owner._record(
            {
                "kind": "archival_memory_search",
                "agent_id": agent_id,
                "results": results if isinstance(results, list) else None,
                "count": len(results) if isinstance(results, list) else None,
            }
        )
        return result

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        memory_id = kwargs.get("memory_id") or (args[1] if len(args) > 1 else None)
        try:
            result = self._inner.delete(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "archival_memory_delete",
                    "agent_id": agent_id,
                    "memory_id": memory_id,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "archival_memory_delete",
                "agent_id": agent_id,
                "memory_id": memory_id,
            }
        )
        return result

    def _wrap(
        self,
        kind: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        text_kw: str,
    ) -> Any:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        text = kwargs.get(text_kw) or kwargs.get("content")
        method = getattr(self._inner, kind.split("_")[-1])  # create / update
        try:
            result = method(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": kind,
                    "agent_id": agent_id,
                    "text": text,
                    "error": exc,
                }
            )
            raise
        memory_id = (
            getattr(result, "id", None)
            or (result.get("id") if isinstance(result, dict) else None)
        )
        self._owner._record(
            {
                "kind": kind,
                "agent_id": agent_id,
                "text": text,
                "memory_id": memory_id,
            }
        )
        return result


class _CoreMemoryProxy:
    """Wraps ``agents.core_memory`` — records core_memory.update operations."""

    __slots__ = ("_owner", "_inner")

    def __init__(self, owner: _AncilisWrappedClient, inner: Any) -> None:
        self._owner = owner
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def update(self, *args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id") or self._owner._agent_id
        block_label = kwargs.get("block_label") or kwargs.get("label")
        new_value = kwargs.get("new_value") or kwargs.get("value")
        try:
            result = self._inner.update(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "core_memory_update",
                    "agent_id": agent_id,
                    "block_label": block_label,
                    "new_value": new_value,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "core_memory_update",
                "agent_id": agent_id,
                "block_label": block_label,
                "new_value": new_value,
            }
        )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _messages_of(response: Any) -> list[Any]:
    if response is None:
        return []
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        msgs = response.get("messages")
        return list(msgs) if msgs else []
    msgs = getattr(response, "messages", None)
    return list(msgs) if msgs else []


def _usage_of(response: Any) -> Any:
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("usage") or response.get("usage_statistics")
    return getattr(response, "usage", None) or getattr(response, "usage_statistics", None)


def _list_of(value: Any) -> Any:
    """Coerce a possibly-iterable result to a list, leave others untouched."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return value.get("results") or value.get("items") or value
    return value
