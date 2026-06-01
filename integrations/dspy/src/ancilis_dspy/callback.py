"""AncilisCallback — DSPy callback adapter for automatic evidence capture.

DSPy 2.5+ exposes a callback protocol via ``dspy.utils.callback.BaseCallback``
with paired ``on_<surface>_start`` / ``on_<surface>_end`` hooks across modules,
LMs, and the evaluation loop. ``AncilisCallback`` implements that protocol via
duck-typing — we never import ``dspy`` at module load, so the package is
importable in test contexts without DSPy installed.

Each hook translates the raw call into an Action and submits it to the
optional engine + evidence store. Internal errors are swallowed and logged
at WARNING — a buggy callback must never crash a user's DSPy program.

Call-id correlation: DSPy's callback runtime assigns a ``call_id`` per
top-level invocation and threads it through nested calls. ``AncilisCallback``
maintains a parent-stack so ``on_lm_start`` calls emitted inside an
``on_module_start`` are tagged with the module's ``call_id`` as their
``parent_call_id``.
"""

from __future__ import annotations

import logging
import threading
import uuid
from typing import Any

from ancilis_dspy._producer import DSPyProducer

logger = logging.getLogger(__name__)


class AncilisCallback:
    """DSPy ``BaseCallback``-compatible adapter that records Ancilis evidence.

    Usage::

        import dspy
        from ancilis_dspy import AncilisCallback

        dspy.settings.configure(
            callbacks=[AncilisCallback(agent_id="research-agent")]
        )

    The callback is observe-only when ``engine`` and ``evidence_store`` are
    ``None`` — captured actions are still kept on ``captured_actions`` for
    inspection, but nothing is evaluated or persisted.
    """

    def __init__(
        self,
        agent_id: str = "dspy-agent",
        session_id: str | None = None,
        engine: Any = None,
        evidence_store: Any = None,
    ) -> None:
        self._session_id = session_id or str(uuid.uuid4())
        self._producer = DSPyProducer(
            agent_id=agent_id, session_id=self._session_id
        )
        self._engine = engine
        self._evidence_store = evidence_store
        self._agent_id = agent_id
        self._lock = threading.Lock()
        self._actions: list[Any] = []
        # Parent-call stack for correlating nested events (lm inside module).
        self._parent_stack: list[str] = []

    # ------------------------------------------------------------------
    # BaseCallback protocol — module surface
    # ------------------------------------------------------------------

    def on_module_start(
        self,
        call_id: str,
        instance: Any,
        inputs: Any,
    ) -> None:
        """Record entry into a custom ``dspy.Module.__call__``."""
        self._safe_record(
            {
                "kind": "module_start",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "module_name": _instance_name(instance),
                "inputs": inputs,
                "parent_call_id": self._current_parent(),
            }
        )
        self._push_parent(str(call_id))

    def on_module_end(
        self,
        call_id: str,
        outputs: Any = None,
        exception: BaseException | None = None,
    ) -> None:
        """Record exit from a custom ``dspy.Module.__call__``."""
        self._pop_parent(str(call_id))
        self._safe_record(
            {
                "kind": "module_end",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "outputs": outputs,
                "error": exception,
                "parent_call_id": self._current_parent(),
            }
        )

    # ------------------------------------------------------------------
    # BaseCallback protocol — LM surface
    # ------------------------------------------------------------------

    def on_lm_start(
        self,
        call_id: str,
        instance: Any,
        inputs: Any,
    ) -> None:
        """Record entry into ``dspy.LM.__call__``."""
        prompt = inputs.get("prompt") if isinstance(inputs, dict) else inputs
        if isinstance(inputs, dict) and "messages" in inputs and prompt is None:
            prompt = inputs.get("messages")
        self._safe_record(
            {
                "kind": "lm_start",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "lm_name": _instance_name(instance),
                "model": getattr(instance, "model", None),
                "prompt": prompt,
                "parent_call_id": self._current_parent(),
            }
        )
        self._push_parent(str(call_id))

    def on_lm_end(
        self,
        call_id: str,
        outputs: Any = None,
        exception: BaseException | None = None,
    ) -> None:
        """Record exit from ``dspy.LM.__call__``."""
        self._pop_parent(str(call_id))
        completion = _completion_of(outputs)
        usage = _usage_of(outputs)
        self._safe_record(
            {
                "kind": "lm_end",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "completion": completion,
                "usage": usage,
                "error": exception,
                "parent_call_id": self._current_parent(),
            }
        )

    # ------------------------------------------------------------------
    # BaseCallback protocol — evaluation surface
    # ------------------------------------------------------------------

    def on_evaluate_start(
        self,
        call_id: str,
        instance: Any,
        inputs: Any,
    ) -> None:
        """Record start of a ``dspy.evaluate.Evaluate`` iteration."""
        metric_name = _evaluate_metric_name(instance)
        dataset_size = _evaluate_dataset_size(instance, inputs)
        self._safe_record(
            {
                "kind": "evaluate_start",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "metric_name": metric_name,
                "dataset_size": dataset_size,
                "parent_call_id": self._current_parent(),
            }
        )
        self._push_parent(str(call_id))

    def on_evaluate_end(
        self,
        call_id: str,
        outputs: Any = None,
        exception: BaseException | None = None,
    ) -> None:
        """Record completion of a ``dspy.evaluate.Evaluate`` iteration."""
        self._pop_parent(str(call_id))
        score = _score_of(outputs)
        self._safe_record(
            {
                "kind": "evaluate_end",
                "call_id": str(call_id),
                "agent_id": self._agent_id,
                "score": score,
                "error": exception,
                "parent_call_id": self._current_parent(),
            }
        )

    # ------------------------------------------------------------------
    # Public test hook
    # ------------------------------------------------------------------

    @property
    def captured_actions(self) -> list[Any]:
        """Return a copy of captured Action objects (useful for testing)."""
        with self._lock:
            return list(self._actions)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _safe_record(self, raw: dict[str, Any]) -> None:
        """Translate + submit, swallowing any internal errors."""
        try:
            action = self._producer.translate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ancilis-dspy: failed to translate event: %s", exc)
            return
        with self._lock:
            self._actions.append(action)
        self._submit(action)

    def _submit(self, action: Any) -> None:
        if self._engine is not None:
            try:
                self._engine.evaluate(action)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ancilis-dspy: engine.evaluate failed: %s", exc)
        if self._evidence_store is not None:
            try:
                self._evidence_store.append(action)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ancilis-dspy: evidence_store.append failed: %s", exc
                )

    def _current_parent(self) -> str | None:
        with self._lock:
            return self._parent_stack[-1] if self._parent_stack else None

    def _push_parent(self, call_id: str) -> None:
        with self._lock:
            self._parent_stack.append(call_id)

    def _pop_parent(self, call_id: str) -> None:
        with self._lock:
            # Pop our id if it's on top — robust to out-of-order completion.
            if self._parent_stack and self._parent_stack[-1] == call_id:
                self._parent_stack.pop()
            elif call_id in self._parent_stack:
                self._parent_stack.remove(call_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _instance_name(instance: Any) -> str:
    """Pick a stable identifier for a dspy.Module / dspy.LM instance."""
    if instance is None:
        return "unknown"
    for attr in ("__name__", "name", "model", "model_name"):
        value = getattr(instance, attr, None)
        if value:
            return str(value)
    cls = getattr(instance, "__class__", None)
    return cls.__name__ if cls is not None else "unknown"


def _completion_of(outputs: Any) -> Any:
    if outputs is None:
        return None
    if isinstance(outputs, (str, list)):
        return outputs
    if isinstance(outputs, dict):
        return (
            outputs.get("text")
            or outputs.get("content")
            or outputs.get("completion")
        )
    return getattr(outputs, "text", None) or getattr(outputs, "content", None)


def _usage_of(outputs: Any) -> Any:
    if outputs is None:
        return None
    if isinstance(outputs, dict):
        return outputs.get("usage") or outputs.get("token_usage")
    return getattr(outputs, "usage", None) or getattr(
        outputs, "token_usage", None
    )


def _evaluate_metric_name(instance: Any) -> str | None:
    if instance is None:
        return None
    metric = getattr(instance, "metric", None)
    if metric is None:
        return None
    return getattr(metric, "__name__", None) or type(metric).__name__


def _evaluate_dataset_size(instance: Any, inputs: Any) -> int | None:
    """Try to recover the dev/eval set size from the Evaluate instance or call."""
    if isinstance(inputs, dict):
        devset = inputs.get("devset") or inputs.get("dataset")
        if isinstance(devset, list):
            return len(devset)
    if instance is not None:
        devset = getattr(instance, "devset", None) or getattr(
            instance, "dataset", None
        )
        if isinstance(devset, list):
            return len(devset)
    return None


def _score_of(outputs: Any) -> float | None:
    if outputs is None:
        return None
    if isinstance(outputs, (int, float)) and not isinstance(outputs, bool):
        return float(outputs)
    if isinstance(outputs, dict):
        score = outputs.get("score") or outputs.get("metric_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            return float(score)
    score = getattr(outputs, "score", None)
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return float(score)
    return None
