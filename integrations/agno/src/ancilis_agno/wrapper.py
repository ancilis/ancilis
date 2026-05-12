"""wrap_agent / wrap_team — proxies around Agno objects for Ancilis evidence capture.

The wrappers forward all attribute access to the underlying Agent / Team via
``__getattr__``, but intercept the calls that touch evidence-relevant
surfaces:

* ``Agent.run`` / ``Agent.arun`` / ``Agent.run_stream``
* ``Agent.memory.add_user_memory`` / ``update_session_summary`` / ``search_user_memories``
* ``Agent.knowledge.search`` / ``add`` / ``update``
* ``Team.run`` — each member's RunResponse becomes a separate Action

agno is not imported at module load time — the wrappers are duck-typed.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any
from collections.abc import AsyncIterator, Iterator

from ancilis_agno._producer import AgnoProducer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public factories
# ---------------------------------------------------------------------------


def wrap_agent(
    agent: Any,
    *,
    agent_id: str,
    session_id: str | None = None,
    engine: Any = None,
    evidence_store: Any = None,
) -> _AncilisWrappedAgent:
    """Return a proxy around ``agent`` that records each run as Ancilis evidence.

    Parameters
    ----------
    agent:
        An ``agno.agent.Agent`` (or any duck-compatible object exposing
        ``run`` / ``arun`` / ``run_stream``, plus optional ``memory`` and
        ``knowledge`` attributes).
    agent_id:
        Identifier recorded on every Action.
    session_id:
        Optional session correlator. If omitted, a uuid4 is generated.
    engine:
        Optional Ancilis Engine. When provided, ``engine.evaluate(action)`` is
        called for every translated Action. Errors are swallowed.
    evidence_store:
        Optional Ancilis EvidenceStore. When provided, ``store.append(action)``
        is called for every translated Action. Errors are swallowed.
    """
    producer = AgnoProducer(
        agent_id=agent_id,
        session_id=session_id or str(uuid.uuid4()),
    )
    return _AncilisWrappedAgent(
        agent,
        producer=producer,
        engine=engine,
        evidence_store=evidence_store,
        agent_id=agent_id,
    )


def wrap_team(
    team: Any,
    *,
    agent_id: str,
    session_id: str | None = None,
    engine: Any = None,
    evidence_store: Any = None,
) -> _AncilisWrappedTeam:
    """Return a proxy around ``team`` that records every member delegation.

    Each ``MemberRunStarted`` / ``MemberRunCompleted`` event in the team's
    response stream is recorded as a separate Action with ``member_name`` set
    in evidence_data, alongside the team-level RunResponse events.
    """
    producer = AgnoProducer(
        agent_id=agent_id,
        session_id=session_id or str(uuid.uuid4()),
    )
    return _AncilisWrappedTeam(
        team,
        producer=producer,
        engine=engine,
        evidence_store=evidence_store,
        agent_id=agent_id,
    )


# ---------------------------------------------------------------------------
# Wrapped agent
# ---------------------------------------------------------------------------


class _AncilisWrappedAgent:
    """Proxy around an Agno Agent that records evidence on each run."""

    __slots__ = (
        "_agent",
        "_producer",
        "_engine",
        "_store",
        "_agent_id",
        "_actions",
        "_memory_proxy",
        "_knowledge_proxy",
    )

    def __init__(
        self,
        agent: Any,
        *,
        producer: AgnoProducer,
        engine: Any,
        evidence_store: Any,
        agent_id: str,
    ) -> None:
        object.__setattr__(self, "_agent", agent)
        object.__setattr__(self, "_producer", producer)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_store", evidence_store)
        object.__setattr__(self, "_agent_id", agent_id)
        object.__setattr__(self, "_actions", [])

        memory = getattr(agent, "memory", None)
        knowledge = getattr(agent, "knowledge", None)
        object.__setattr__(
            self,
            "_memory_proxy",
            _MemoryProxy(self, memory) if memory is not None else None,
        )
        object.__setattr__(
            self,
            "_knowledge_proxy",
            _KnowledgeProxy(self, knowledge) if knowledge is not None else None,
        )

    # ---- attribute proxying ----

    def __getattr__(self, name: str) -> Any:
        if name == "memory":
            if self._memory_proxy is not None:
                return self._memory_proxy
            return getattr(self._agent, "memory", None)
        if name == "knowledge":
            if self._knowledge_proxy is not None:
                return self._knowledge_proxy
            return getattr(self._agent, "knowledge", None)
        return getattr(self._agent, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._agent, name, value)

    @property
    def captured_actions(self) -> list[Any]:
        """Snapshot of every Action this wrapper has recorded (test hook)."""
        return list(self._actions)

    # ---- run methods ----

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync run — record evidence around ``agent.run``."""
        try:
            response = self._agent.run(*args, **kwargs)
        except BaseException as exc:
            self._record({"kind": "RunCompleted", "agent_id": self._agent_id, "error": exc})
            raise
        self._record_run_response(response)
        return response

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async run — record evidence around ``agent.arun``."""
        try:
            response = await self._agent.arun(*args, **kwargs)
        except BaseException as exc:
            self._record({"kind": "RunCompleted", "agent_id": self._agent_id, "error": exc})
            raise
        self._record_run_response(response)
        return response

    def run_stream(self, *args: Any, **kwargs: Any) -> _StreamProxy:
        """Streaming run — wrap each yielded RunResponse / event as an Action."""
        try:
            stream = self._agent.run_stream(*args, **kwargs)
        except BaseException as exc:
            self._record(
                {"kind": "RunCompleted", "agent_id": self._agent_id, "error": exc}
            )
            raise
        return _StreamProxy(self, stream, agent_id=self._agent_id)

    # ---- internal: translate / evaluate / store / capture ----

    def _record(self, raw: dict[str, Any]) -> Any:
        try:
            action = self._producer.translate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-agno: failed to translate event: %s", exc)
            return None
        self._actions.append(action)
        _submit(action, self._engine, self._store)
        return action

    def _record_run_response(self, response: Any) -> None:
        """Record a non-streaming RunResponse — both the run-level event and any
        embedded ToolCall events."""
        raw = _run_response_to_dict(response, default_kind="RunResponse")
        if raw is None:
            return
        raw.setdefault("agent_id", self._agent_id)
        self._record(raw)
        # Emit a synthetic ToolCallCompleted Action for each tool used.
        for tc in _tool_calls_of(response):
            tc_raw = _tool_call_to_dict(tc)
            tc_raw.setdefault("agent_id", self._agent_id)
            self._record(tc_raw)


# ---------------------------------------------------------------------------
# Wrapped team
# ---------------------------------------------------------------------------


class _AncilisWrappedTeam:
    """Proxy around an Agno Team — records team + per-member run events."""

    __slots__ = (
        "_team",
        "_producer",
        "_engine",
        "_store",
        "_agent_id",
        "_actions",
    )

    def __init__(
        self,
        team: Any,
        *,
        producer: AgnoProducer,
        engine: Any,
        evidence_store: Any,
        agent_id: str,
    ) -> None:
        object.__setattr__(self, "_team", team)
        object.__setattr__(self, "_producer", producer)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_store", evidence_store)
        object.__setattr__(self, "_agent_id", agent_id)
        object.__setattr__(self, "_actions", [])

    def __getattr__(self, name: str) -> Any:
        return getattr(self._team, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._team, name, value)

    @property
    def captured_actions(self) -> list[Any]:
        return list(self._actions)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync team run — record team-level + per-member events."""
        try:
            response = self._team.run(*args, **kwargs)
        except BaseException as exc:
            self._record({"kind": "RunCompleted", "agent_id": self._agent_id, "error": exc})
            raise
        # Team-level run-completed event
        team_raw = _run_response_to_dict(response, default_kind="RunResponse")
        if team_raw is not None:
            team_raw.setdefault("agent_id", self._agent_id)
            self._record(team_raw)
        # Per-member events: each member.RunResponse → MemberRunCompleted Action
        for member_resp in _member_responses_of(response):
            member_raw = _run_response_to_dict(
                member_resp, default_kind="MemberRunCompleted"
            )
            if member_raw is None:
                continue
            member_name = (
                getattr(member_resp, "member_name", None)
                or getattr(member_resp, "name", None)
                or getattr(member_resp, "agent_name", None)
            )
            if member_name is not None:
                member_raw["member_name"] = str(member_name)
            member_agent_id = getattr(member_resp, "agent_id", None)
            if member_agent_id is not None:
                member_raw["member_agent_id"] = str(member_agent_id)
            member_raw["kind"] = "MemberRunCompleted"
            member_raw.setdefault("agent_id", self._agent_id)
            self._record(member_raw)
        return response

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async team run — same recording semantics as ``run``."""
        try:
            response = await self._team.arun(*args, **kwargs)
        except BaseException as exc:
            self._record({"kind": "RunCompleted", "agent_id": self._agent_id, "error": exc})
            raise
        team_raw = _run_response_to_dict(response, default_kind="RunResponse")
        if team_raw is not None:
            team_raw.setdefault("agent_id", self._agent_id)
            self._record(team_raw)
        for member_resp in _member_responses_of(response):
            member_raw = _run_response_to_dict(
                member_resp, default_kind="MemberRunCompleted"
            )
            if member_raw is None:
                continue
            member_name = (
                getattr(member_resp, "member_name", None)
                or getattr(member_resp, "name", None)
                or getattr(member_resp, "agent_name", None)
            )
            if member_name is not None:
                member_raw["member_name"] = str(member_name)
            member_agent_id = getattr(member_resp, "agent_id", None)
            if member_agent_id is not None:
                member_raw["member_agent_id"] = str(member_agent_id)
            member_raw["kind"] = "MemberRunCompleted"
            member_raw.setdefault("agent_id", self._agent_id)
            self._record(member_raw)
        return response

    def _record(self, raw: dict[str, Any]) -> Any:
        try:
            action = self._producer.translate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-agno: failed to translate event: %s", exc)
            return None
        self._actions.append(action)
        _submit(action, self._engine, self._store)
        return action


# ---------------------------------------------------------------------------
# Memory + knowledge proxies
# ---------------------------------------------------------------------------


class _MemoryProxy:
    """Wraps ``Agent.memory`` — records every persistent-memory operation."""

    __slots__ = ("_owner", "_inner")

    def __init__(self, owner: _AncilisWrappedAgent, inner: Any) -> None:
        self._owner = owner
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def add_user_memory(self, *args: Any, **kwargs: Any) -> Any:
        text = kwargs.get("memory") or kwargs.get("memory_text") or (
            args[0] if args else None
        )
        try:
            result = self._inner.add_user_memory(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "add_user_memory",
                    "agent_id": self._owner._agent_id,
                    "memory_text": text,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "add_user_memory",
                "agent_id": self._owner._agent_id,
                "memory_text": text,
            }
        )
        return result

    def update_session_summary(self, *args: Any, **kwargs: Any) -> Any:
        text = kwargs.get("summary") or kwargs.get("text") or (
            args[0] if args else None
        )
        session_id = kwargs.get("session_id")
        try:
            result = self._inner.update_session_summary(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "update_session_summary",
                    "agent_id": self._owner._agent_id,
                    "memory_text": text,
                    "session_id": session_id,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "update_session_summary",
                "agent_id": self._owner._agent_id,
                "memory_text": text,
                "session_id": session_id,
            }
        )
        return result

    def search_user_memories(self, *args: Any, **kwargs: Any) -> Any:
        query = kwargs.get("query") or (args[0] if args else None)
        try:
            result = self._inner.search_user_memories(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "search_user_memories",
                    "agent_id": self._owner._agent_id,
                    "query": query,
                    "error": exc,
                }
            )
            raise
        results = list(result) if isinstance(result, (list, tuple)) else None
        self._owner._record(
            {
                "kind": "search_user_memories",
                "agent_id": self._owner._agent_id,
                "query": query,
                "results": results,
                "count": len(results) if results is not None else None,
            }
        )
        return result

    def get_session_summary(self, *args: Any, **kwargs: Any) -> Any:
        try:
            result = self._inner.get_session_summary(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "get_session_summary",
                    "agent_id": self._owner._agent_id,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "get_session_summary",
                "agent_id": self._owner._agent_id,
            }
        )
        return result


class _KnowledgeProxy:
    """Wraps ``Agent.knowledge`` — records every knowledge-base operation."""

    __slots__ = ("_owner", "_inner")

    def __init__(self, owner: _AncilisWrappedAgent, inner: Any) -> None:
        self._owner = owner
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def search(self, *args: Any, **kwargs: Any) -> Any:
        query = kwargs.get("query") or (args[0] if args else None)
        limit = kwargs.get("limit")
        filters = kwargs.get("filters")
        try:
            result = self._inner.search(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "knowledge_search",
                    "agent_id": self._owner._agent_id,
                    "query": query,
                    "limit": limit,
                    "filters": filters,
                    "error": exc,
                }
            )
            raise
        results = list(result) if isinstance(result, (list, tuple)) else None
        self._owner._record(
            {
                "kind": "knowledge_search",
                "agent_id": self._owner._agent_id,
                "query": query,
                "limit": limit,
                "filters": filters,
                "results": results,
                "count": len(results) if results is not None else None,
            }
        )
        return result

    def add(self, *args: Any, **kwargs: Any) -> Any:
        documents = kwargs.get("documents") or (args[0] if args else None)
        try:
            result = self._inner.add(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "knowledge_add",
                    "agent_id": self._owner._agent_id,
                    "documents": documents if isinstance(documents, list) else None,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "knowledge_add",
                "agent_id": self._owner._agent_id,
                "documents": documents if isinstance(documents, list) else None,
            }
        )
        return result

    def update(self, *args: Any, **kwargs: Any) -> Any:
        documents = kwargs.get("documents") or (args[0] if args else None)
        try:
            result = self._inner.update(*args, **kwargs)
        except BaseException as exc:
            self._owner._record(
                {
                    "kind": "knowledge_update",
                    "agent_id": self._owner._agent_id,
                    "documents": documents if isinstance(documents, list) else None,
                    "error": exc,
                }
            )
            raise
        self._owner._record(
            {
                "kind": "knowledge_update",
                "agent_id": self._owner._agent_id,
                "documents": documents if isinstance(documents, list) else None,
            }
        )
        return result


# ---------------------------------------------------------------------------
# Stream proxy — wraps Agent.run_stream output.
# ---------------------------------------------------------------------------


class _StreamProxy:
    """Iterator wrapper that records each streamed RunResponse event."""

    __slots__ = ("_owner", "_inner", "_agent_id", "_iter")

    def __init__(
        self,
        owner: _AncilisWrappedAgent,
        inner: Any,
        *,
        agent_id: str,
    ) -> None:
        self._owner = owner
        self._inner = inner
        self._agent_id = agent_id
        self._iter: Any = None

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
        # Stream events have an ``event`` field per Agno docs:
        # "RunStarted", "RunResponse", "ToolCallStarted", "ToolCallCompleted",
        # "RunCompleted", "MemberRunStarted", "MemberRunCompleted".
        raw = _run_response_to_dict(event, default_kind=None)
        if raw is None:
            return
        raw.setdefault("agent_id", self._agent_id)
        self._owner._record(raw)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_response_to_dict(
    response: Any, *, default_kind: str | None
) -> dict[str, Any] | None:
    """Project a duck-typed RunResponse (or stream event) onto our raw dict shape."""
    if response is None:
        return None
    if isinstance(response, dict):
        out = dict(response)
        if "kind" not in out and "event" not in out and default_kind is not None:
            out["kind"] = default_kind
        return out
    out: dict[str, Any] = {}
    # Prefer the ``event`` attribute (streaming) over default_kind.
    event = getattr(response, "event", None)
    if event is not None:
        out["kind"] = str(event)
    elif default_kind is not None:
        out["kind"] = default_kind
    for attr in (
        "id",
        "event_id",
        "run_id",
        "agent_id",
        "session_id",
        "model",
        "content",
        "metrics",
        "tool_call_id",
        "tool_name",
        "tool_args",
        "tool_call",
        "tools",
        "parent_id",
    ):
        if hasattr(response, attr):
            value = getattr(response, attr)
            if value is not None:
                out[attr] = value
    err = getattr(response, "error", None)
    if err is not None:
        out["error"] = err
    return out


def _tool_call_to_dict(tc: Any) -> dict[str, Any]:
    """Project a ToolCall-like object into a ToolCallCompleted raw dict."""
    if isinstance(tc, dict):
        return {
            "kind": "ToolCallCompleted",
            "tool_name": tc.get("tool_name") or tc.get("name"),
            "tool_args": tc.get("tool_args") or tc.get("arguments"),
            "tool_call_id": tc.get("tool_call_id"),
            "result": tc.get("result"),
            "error": tc.get("error"),
        }
    return {
        "kind": "ToolCallCompleted",
        "tool_name": getattr(tc, "tool_name", None) or getattr(tc, "name", None),
        "tool_args": getattr(tc, "tool_args", None) or getattr(tc, "arguments", None),
        "tool_call_id": getattr(tc, "tool_call_id", None),
        "result": getattr(tc, "result", None),
        "error": getattr(tc, "error", None),
    }


def _tool_calls_of(response: Any) -> list[Any]:
    if response is None:
        return []
    if isinstance(response, dict):
        tools = response.get("tools")
        return list(tools) if isinstance(tools, list) else []
    tools = getattr(response, "tools", None)
    return list(tools) if isinstance(tools, list) else []


def _member_responses_of(response: Any) -> list[Any]:
    """Pull per-member RunResponse objects off a Team response.

    Agno teams expose the per-member responses under different attributes
    across versions: ``member_responses``, ``members``, or ``member_runs``.
    """
    if response is None:
        return []
    for attr in ("member_responses", "member_runs", "members"):
        value = (
            response.get(attr)
            if isinstance(response, dict)
            else getattr(response, attr, None)
        )
        if isinstance(value, list) and value:
            return list(value)
    return []


def _submit(action: Any, engine: Any, evidence_store: Any) -> None:
    """Forward action to engine + evidence store. Errors are swallowed."""
    if engine is not None:
        try:
            engine.evaluate(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-agno: engine.evaluate failed: %s", exc)
    if evidence_store is not None:
        try:
            evidence_store.append(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-agno: evidence_store.append failed: %s", exc)


# Silence unused-import warnings.
_ = AsyncIterator
_ = Iterator
