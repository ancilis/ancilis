"""wrap_lm — proxy around a ``dspy.LM`` for Ancilis evidence capture.

The wrapper forwards all attribute access to the underlying LM via
``__getattr__``, but intercepts the calls that touch the LM surface
(``__call__`` and ``request``) so every Predict invocation is translated
to an Action and submitted to the optional engine + evidence store.

dspy is not imported at module load time — the wrapper is duck-typed.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from ancilis_dspy._producer import DSPyProducer

logger = logging.getLogger(__name__)


def wrap_lm(
    lm: Any,
    *,
    agent_id: str,
    session_id: str | None = None,
    engine: Any = None,
    evidence_store: Any = None,
) -> _AncilisWrappedLM:
    """Return a proxy around ``lm`` that records each call as Ancilis evidence.

    Parameters
    ----------
    lm:
        A ``dspy.LM`` (or any duck-compatible object exposing ``__call__``
        and / or ``request``).
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
    producer = DSPyProducer(
        agent_id=agent_id,
        session_id=session_id or str(uuid.uuid4()),
    )
    return _AncilisWrappedLM(
        lm,
        producer=producer,
        engine=engine,
        evidence_store=evidence_store,
        agent_id=agent_id,
    )


class _AncilisWrappedLM:
    """Proxy around a dspy.LM that records evidence on each call."""

    __slots__ = (
        "_lm",
        "_producer",
        "_engine",
        "_store",
        "_agent_id",
        "_actions",
    )

    def __init__(
        self,
        lm: Any,
        *,
        producer: DSPyProducer,
        engine: Any,
        evidence_store: Any,
        agent_id: str,
    ) -> None:
        object.__setattr__(self, "_lm", lm)
        object.__setattr__(self, "_producer", producer)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_store", evidence_store)
        object.__setattr__(self, "_agent_id", agent_id)
        object.__setattr__(self, "_actions", [])

    # ---- attribute proxying ----

    def __getattr__(self, name: str) -> Any:
        return getattr(self._lm, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._lm, name, value)

    @property
    def captured_actions(self) -> list[Any]:
        """Snapshot of every Action this wrapper has recorded (test hook)."""
        return list(self._actions)

    # ---- intercepted call surfaces ----

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Primary LM call surface — DSPy's Predict invokes ``lm(...)`` here."""
        return self._invoke("__call__", args, kwargs)

    def request(self, *args: Any, **kwargs: Any) -> Any:
        """Alternate LM call surface — older / custom dspy.LM subclasses."""
        return self._invoke("request", args, kwargs)

    # ---- internal: dispatch + record ----

    def _invoke(
        self,
        method: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        prompt = _extract_prompt(args, kwargs)
        lm_name = _lm_name(self._lm)
        model = getattr(self._lm, "model", None) or lm_name

        target = getattr(self._lm, method, None)
        if target is None or not callable(target):
            raise AttributeError(
                f"wrapped LM does not expose a callable {method!r}"
            )
        try:
            response = target(*args, **kwargs)
        except BaseException as exc:
            self._record(
                {
                    "kind": "lm_call",
                    "agent_id": self._agent_id,
                    "lm_name": lm_name,
                    "model": model,
                    "prompt": prompt,
                    "error": exc,
                }
            )
            raise

        completion = _extract_completion(response)
        usage = _extract_usage(response)
        self._record(
            {
                "kind": "lm_call",
                "agent_id": self._agent_id,
                "lm_name": lm_name,
                "model": model,
                "prompt": prompt,
                "completion": completion,
                "usage": usage,
            }
        )
        return response

    def _record(self, raw: dict[str, Any]) -> Any:
        try:
            action = self._producer.translate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-dspy: failed to translate event: %s", exc)
            return None
        self._actions.append(action)
        _submit(action, self._engine, self._store)
        return action


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lm_name(lm: Any) -> str:
    """Pick a stable identifier for the wrapped LM."""
    for attr in ("model", "name", "model_name"):
        value = getattr(lm, attr, None)
        if value:
            return str(value)
    return type(lm).__name__


def _extract_prompt(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Pull the prompt off the call's positional/keyword args.

    DSPy's LM interface accepts either ``prompt=`` (legacy completion-style)
    or ``messages=`` (chat-style); the first positional arg is also commonly
    the prompt.
    """
    if "messages" in kwargs:
        return kwargs["messages"]
    if "prompt" in kwargs:
        return kwargs["prompt"]
    if args:
        return args[0]
    return None


def _extract_completion(response: Any) -> Any:
    """Pull the completion text off a dspy.LM response.

    dspy.LM responses are typically a list of strings (one per ``n`` sampled
    completion) but may also be a single string, a dict with ``choices``, or
    an arbitrary object exposing ``text``/``content``.
    """
    if response is None:
        return None
    if isinstance(response, str):
        return response
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        choices = response.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                return (
                    first.get("text")
                    or (first.get("message") or {}).get("content")
                )
        return response.get("text") or response.get("content")
    text = getattr(response, "text", None) or getattr(response, "content", None)
    return text


def _extract_usage(response: Any) -> Any:
    """Pull a usage payload off a dspy.LM response."""
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("usage") or response.get("token_usage")
    return getattr(response, "usage", None) or getattr(
        response, "token_usage", None
    )


def _submit(action: Any, engine: Any, evidence_store: Any) -> None:
    """Forward action to engine + evidence store. Errors are swallowed."""
    if engine is not None:
        try:
            engine.evaluate(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-dspy: engine.evaluate failed: %s", exc)
    if evidence_store is not None:
        try:
            evidence_store.append(action)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-dspy: evidence_store.append failed: %s", exc)
