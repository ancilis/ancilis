"""AncilisEventHandler — LlamaIndex BaseEventHandler for automatic evidence capture."""

from __future__ import annotations

import logging
import threading
import uuid
from typing import Any

from ancilis_llamaindex._producer import LlamaIndexProducer

logger = logging.getLogger(__name__)


# LlamaIndex's BaseEventHandler is optional at import time. We provide a
# duck-typed fallback so users can import and instantiate ``AncilisEventHandler``
# in tests / observe-only contexts even when llama-index-core isn't installed —
# but registering it via ``dispatcher.add_event_handler(...)`` is what surfaces
# the real ImportError to the user (because the dispatcher itself ships with
# llama_index).
try:
    from llama_index.core.instrumentation.event_handlers import (  # type: ignore[import-not-found]
        BaseEventHandler as _LIBaseEventHandler,
    )

    _LLAMA_INDEX_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without llama-index
    _LLAMA_INDEX_AVAILABLE = False

    class _LIBaseEventHandler:  # type: ignore[no-redef]
        """Minimal duck-typed fallback matching llama_index's BaseEventHandler.

        Subclasses must implement ``handle(event)`` and ``class_name()``. This
        stub lets ``AncilisEventHandler`` be importable without the framework
        installed; users still need llama-index-core to register against a
        dispatcher.
        """

        @classmethod
        def class_name(cls) -> str:  # pragma: no cover - overridden
            return cls.__name__


class AncilisEventHandler(_LIBaseEventHandler):  # type: ignore[misc,valid-type]
    """LlamaIndex event handler that captures evidence via the Ancilis SDK.

    Usage::

        from llama_index.core.instrumentation import get_dispatcher
        from ancilis_llamaindex import AncilisEventHandler

        handler = AncilisEventHandler(agent_id="my-agent")
        get_dispatcher().add_event_handler(handler)

    The handler is observe-only when ``engine`` and ``evidence_store`` are
    ``None`` — captured actions are still kept on ``captured_actions`` for
    inspection, but nothing is evaluated or persisted.
    """

    def __init__(
        self,
        agent_id: str = "llamaindex-agent",
        session_id: str | None = None,
        engine: Any = None,
        evidence_store: Any = None,
    ) -> None:
        # Don't call super().__init__() — llama_index's BaseEventHandler is a
        # pydantic model and would reject our extra kwargs. The fallback class
        # has no __init__ either. Initialise our own state directly.
        self._session_id = session_id or str(uuid.uuid4())
        self._producer = LlamaIndexProducer(
            agent_id=agent_id, session_id=self._session_id
        )
        self._engine = engine
        self._evidence_store = evidence_store
        self._lock = threading.Lock()
        self._actions: list[Any] = []

    # ------------------------------------------------------------------
    # BaseEventHandler protocol
    # ------------------------------------------------------------------

    @classmethod
    def class_name(cls) -> str:
        """Identifier expected by llama_index's BaseEventHandler protocol."""
        return "AncilisEventHandler"

    def handle(self, event: Any) -> None:
        """Translate a LlamaIndex event into an Action and submit it.

        Instrumentation handlers must never raise — a buggy handler must not
        crash user code. All exceptions are logged at WARNING and swallowed.
        """
        try:
            raw = _event_to_dict(event)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-llamaindex: failed to serialise event: %s", exc)
            return

        try:
            action = self._producer.translate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-llamaindex: failed to translate event: %s", exc)
            return

        with self._lock:
            self._actions.append(action)

        self._submit(action)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def _submit(self, action: Any) -> None:
        """Forward action to engine + evidence store. Errors are swallowed."""
        evaluation: Any = None
        if self._engine is not None:
            try:
                evaluation = self._engine.evaluate(action)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ancilis-llamaindex: engine.evaluate failed: %s", exc)
                return

        if self._evidence_store is not None and evaluation is not None:
            try:
                self._evidence_store.store(evaluation, action.tool.name)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ancilis-llamaindex: evidence_store.store failed: %s", exc
                )

    @property
    def captured_actions(self) -> list[Any]:
        """Return a copy of captured Action objects (useful for testing)."""
        with self._lock:
            return list(self._actions)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event_to_dict(event: Any) -> dict[str, Any]:
    """Convert a llama_index event (pydantic-like) into a plain dict.

    LlamaIndex events expose ``.dict()`` (pydantic v1) or ``.model_dump()``
    (pydantic v2). Falls back to ``vars()`` and finally to a single ``value``
    field — never raises for arbitrary inputs.
    """
    if isinstance(event, dict):
        out = dict(event)
    elif hasattr(event, "model_dump") and callable(event.model_dump):
        out = event.model_dump()  # type: ignore[no-any-return]
    elif hasattr(event, "dict") and callable(event.dict):
        try:
            out = event.dict()  # type: ignore[no-any-return]
        except TypeError:
            out = _attrs_to_dict(event)
    else:
        out = _attrs_to_dict(event)

    # Make sure class_name is populated — llama_index events expose it as a
    # classmethod, not as a field, so .dict() may omit it.
    if "class_name" not in out:
        cls = getattr(event, "__class__", None)
        cls_method = getattr(event, "class_name", None)
        if callable(cls_method):
            try:
                out["class_name"] = cls_method()
            except Exception:  # noqa: BLE001
                out["class_name"] = cls.__name__ if cls else "UnknownEvent"
        elif cls is not None:
            out["class_name"] = cls.__name__

    return out


def _attrs_to_dict(event: Any) -> dict[str, Any]:
    """Collect public attributes from an object — including class-level ones."""
    out: dict[str, Any] = {}
    # Walk MRO so class-level attributes are included (instance __dict__ alone
    # misses bare ``class _Event: id_ = "x"`` style payloads).
    seen: set[str] = set()
    classes = []
    cls = getattr(event, "__class__", None)
    if cls is not None:
        classes = list(getattr(cls, "__mro__", [cls]))
    for klass in classes:
        for name in vars(klass):
            if name.startswith("_") or name in seen:
                continue
            value = getattr(event, name, None)
            if callable(value):
                continue
            out[name] = value
            seen.add(name)
    # Then overlay anything on the instance dict.
    inst_dict = getattr(event, "__dict__", None)
    if isinstance(inst_dict, dict):
        for name, value in inst_dict.items():
            if name.startswith("_") or callable(value):
                continue
            out[name] = value
    return out
