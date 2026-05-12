"""wrap_agent() — proxy wrapper around a Pydantic-AI Agent for Ancilis evidence capture.

The wrapper forwards all attribute access to the underlying Agent via
``__getattr__``, but overrides ``run`` (async), ``run_sync`` (sync), and
``iter`` (async streaming) to translate each invocation into an Ancilis Action,
optionally evaluate it through an Engine, and persist it to an EvidenceStore.

Pydantic-AI is not imported at module load time — the wrapper is duck-typed and
only relies on the Agent exposing a callable ``run``/``run_sync``/``iter``.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any, AsyncIterator

from ancilis_pydantic_ai._producer import PydanticAIProducer


def wrap_agent(
    agent: Any,
    *,
    agent_id: str = "pydantic-ai-agent",
    session_id: str | None = None,
    engine: Any = None,
    evidence_store: Any = None,
) -> "_AncilisWrappedAgent":
    """Return a proxy around ``agent`` that records each run as Ancilis evidence.

    Parameters
    ----------
    agent:
        A Pydantic-AI ``Agent`` (or any duck-compatible object exposing
        ``run`` / ``run_sync`` / ``iter``).
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
    return _AncilisWrappedAgent(
        agent,
        producer=PydanticAIProducer(
            agent_id=agent_id,
            session_id=session_id or str(uuid.uuid4()),
        ),
        engine=engine,
        evidence_store=evidence_store,
    )


class _AncilisWrappedAgent:
    """Proxy around a Pydantic-AI Agent that records evidence on each run."""

    __slots__ = (
        "_agent",
        "_producer",
        "_engine",
        "_store",
        "_actions",
    )

    def __init__(
        self,
        agent: Any,
        *,
        producer: PydanticAIProducer,
        engine: Any = None,
        evidence_store: Any = None,
    ) -> None:
        # Use object.__setattr__ to bypass our own __setattr__ proxy.
        object.__setattr__(self, "_agent", agent)
        object.__setattr__(self, "_producer", producer)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_store", evidence_store)
        object.__setattr__(self, "_actions", [])

    # ------------------------------------------------------------------
    # Attribute proxying
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        # __getattr__ is only invoked when the attribute is not found
        # through the normal lookup, so this only proxies un-overridden attrs.
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

    # ------------------------------------------------------------------
    # Overridden run methods
    # ------------------------------------------------------------------

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Async run — record evidence around the underlying ``agent.run``.

        On exception, an additional ``run_result`` Action is recorded with
        ``error_type`` set before the exception is re-raised.
        """
        prompt = args[0] if args else kwargs.get("user_prompt")
        try:
            result = await self._agent.run(*args, **kwargs)
        except BaseException as exc:
            self._record_run_event(prompt=prompt, result=None, error=exc)
            raise
        self._record_run_event(prompt=prompt, result=result, error=None)
        return result

    def run_sync(self, *args: Any, **kwargs: Any) -> Any:
        """Sync run — record evidence around the underlying ``agent.run_sync``.

        On exception, an additional ``run_result`` Action is recorded with
        ``error_type`` set before the exception is re-raised.
        """
        prompt = args[0] if args else kwargs.get("user_prompt")
        try:
            result = self._agent.run_sync(*args, **kwargs)
        except BaseException as exc:
            self._record_run_event(prompt=prompt, result=None, error=exc)
            raise
        self._record_run_event(prompt=prompt, result=result, error=None)
        return result

    def iter(self, *args: Any, **kwargs: Any) -> "_StreamingProxy":
        """Async-iter wrapper — each yielded event becomes one Action observation.

        ``Agent.iter`` may be either an async iterator directly, or an async
        context manager yielding a stream handle. We accept either and re-emit
        each event after recording it as evidence.
        """
        return _StreamingProxy(self, self._agent.iter(*args, **kwargs))

    # ------------------------------------------------------------------
    # Internal: translate / evaluate / store / capture
    # ------------------------------------------------------------------

    def _emit(self, raw: dict[str, Any]) -> Any:
        """Translate ``raw`` to an Action; evaluate (if engine); store (if store)."""
        try:
            action = self._producer.translate(raw)
        except Exception:  # noqa: BLE001 — evidence must never break the host
            return None
        self._actions.append(action)
        if self._engine is not None:
            try:
                self._engine.evaluate(action)
            except Exception:  # noqa: BLE001
                pass
        if self._store is not None:
            try:
                self._store.append(action)
            except Exception:  # noqa: BLE001
                pass
        return action

    def _record_run_event(
        self,
        *,
        prompt: Any,
        result: Any,
        error: BaseException | None,
    ) -> None:
        raw: dict[str, Any] = {
            "kind": "run_result",
            "event_id": str(uuid.uuid4()),
        }
        # Best-effort field extraction from a duck-typed RunResult.
        if result is not None:
            usage = _safe_call(result, "usage")
            if usage is not None:
                raw["usage"] = usage
            data = getattr(result, "data", None)
            if data is None:
                data = getattr(result, "output", None)
            if data is not None:
                raw["output"] = data
            model = getattr(result, "model", None)
            if model is not None:
                raw["model"] = str(model)
        if error is not None:
            raw["error"] = error
        self._emit(raw)


def _safe_call(obj: Any, method_name: str) -> Any:
    """Call ``obj.method_name()`` if available; otherwise return the attr or None."""
    attr = getattr(obj, method_name, None)
    if attr is None:
        return None
    if callable(attr):
        try:
            return attr()
        except Exception:  # noqa: BLE001
            return None
    return attr


class _StreamingProxy:
    """Wrap the value returned by ``Agent.iter`` so each yielded event is recorded.

    Pydantic-AI ``Agent.iter`` is documented as an async context manager whose
    ``__aenter__`` returns an async iterator. We support both the context-manager
    form and a plain async iterator, since tests use the simpler shape.
    """

    def __init__(self, owner: _AncilisWrappedAgent, inner: Any) -> None:
        self._owner = owner
        self._inner = inner
        self._iterator: AsyncIterator[Any] | None = None

    # ---- async-iterator form ----

    def __aiter__(self) -> "_StreamingProxy":
        self._iterator = self._inner.__aiter__()
        return self

    async def __anext__(self) -> Any:
        assert self._iterator is not None
        event = await self._iterator.__anext__()
        self._record(event)
        return event

    # ---- async-context-manager form ----

    async def __aenter__(self) -> "_StreamingProxy":
        if hasattr(self._inner, "__aenter__"):
            entered = await self._inner.__aenter__()
            self._iterator = entered.__aiter__() if hasattr(entered, "__aiter__") else entered
        else:
            self._iterator = self._inner.__aiter__()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        if hasattr(self._inner, "__aexit__"):
            return await self._inner.__aexit__(exc_type, exc, tb)
        return None

    # ---- internal ----

    def _record(self, event: Any) -> None:
        raw = _stream_event_to_dict(event)
        if raw is not None:
            self._owner._emit(raw)


def _stream_event_to_dict(event: Any) -> dict[str, Any] | None:
    """Best-effort projection of a Pydantic-AI stream event onto our raw dict shape."""
    if event is None:
        return None
    if isinstance(event, dict):
        return event
    kind = getattr(event, "kind", None) or _infer_kind_from_classname(event)
    if kind is None:
        return None
    raw: dict[str, Any] = {"kind": kind}
    for attr in ("event_id", "parent_event_id", "tool_name", "model", "output"):
        if hasattr(event, attr):
            value = getattr(event, attr)
            if value is not None:
                raw[attr] = value
    if hasattr(event, "tool_args"):
        args_val = getattr(event, "tool_args")
        if args_val is not None:
            raw["tool_args"] = args_val
    if hasattr(event, "usage"):
        usage = getattr(event, "usage")
        if usage is not None:
            raw["usage"] = usage
    if hasattr(event, "error"):
        err = getattr(event, "error")
        if err is not None:
            raw["error"] = err
    return raw


def _infer_kind_from_classname(event: Any) -> str | None:
    """Map Pydantic-AI stream event class names to our canonical ``kind`` strings."""
    name = type(event).__name__
    mapping = {
        "ModelResponseStreamEvent": "model_response",
        "ModelResponse": "model_response",
        "FunctionToolCallEvent": "function_tool_call",
        "FunctionToolResultEvent": "function_tool_result",
        "FinalResultEvent": "final_result",
        "RunResultEvent": "run_result",
    }
    return mapping.get(name)


# Silence unused-import warnings (kept for IDE auto-import friendliness).
_ = inspect
