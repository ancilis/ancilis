"""AncilisCallbackHandler — LangChain BaseCallbackHandler for automatic evidence capture."""

from __future__ import annotations

import threading
import uuid
from typing import Any, Sequence, Union

from ancilis_langchain._producer import LangChainProducer

# LangChain imports — optional at import time so the package can be imported
# even when langchain-core is not installed (fail fast at instantiation instead).
try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.outputs import LLMResult

    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object  # type: ignore[assignment,misc]
    LLMResult = Any  # type: ignore[assignment,misc]


class AncilisCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that captures evidence via the Ancilis SDK.

    Usage::

        from ancilis_langchain import AncilisCallbackHandler
        handler = AncilisCallbackHandler(agent_id="my-agent")
        chain.invoke(input, config={"callbacks": [handler]})
    """

    def __init__(
        self,
        *,
        agent_id: str = "langchain-agent",
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(
                "langchain-core is required. Install it with: pip install langchain-core>=0.2.0"
            )
        super().__init__()
        self._session_id = session_id or str(uuid.uuid4())
        self._metadata = metadata or {}
        self._producer = LangChainProducer(agent_id=agent_id, session_id=self._session_id)
        self._lock = threading.Lock()
        self._engine: Any = None  # Lazy-loaded Ancilis engine
        self._actions: list[Any] = []  # captured actions (for testing)

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "llm_start",
            "serialized": serialized,
            "prompts": prompts,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "llm_end",
            "response": _llm_result_to_dict(response),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "llm_error",
            "error": str(error),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "tool_start",
            "serialized": serialized,
            "input_str": input_str,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "tool_end",
            "output": output,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "tool_error",
            "error": str(error),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    # ------------------------------------------------------------------
    # Chain callbacks
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "chain_start",
            "serialized": serialized,
            "inputs": inputs,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "chain_end",
            "outputs": outputs,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "chain_error",
            "error": str(error),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    # ------------------------------------------------------------------
    # Retriever callbacks
    # ------------------------------------------------------------------

    def on_retriever_start(
        self,
        serialized: dict[str, Any],
        query: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "retriever_start",
            "serialized": serialized,
            "query": query,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_retriever_end(
        self,
        documents: Sequence[Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "retriever_end",
            "documents": list(documents),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    def on_retriever_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._capture({
            "event_type": "retriever_error",
            "error": str(error),
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        })

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _capture(self, raw: dict[str, Any]) -> None:
        """Translate raw callback data to Action and submit to Ancilis engine."""
        action = self._producer.translate(raw)
        with self._lock:
            self._actions.append(action)
        self._submit(action)

    def _submit(self, action: Any) -> None:
        """Submit action to Ancilis engine. No-op if engine not configured."""
        try:
            engine = self._get_engine()
            if engine is not None:
                engine.evaluate(action)
        except Exception:  # noqa: BLE001
            # Never let evidence capture break the application
            pass

    def _get_engine(self) -> Any:
        """Lazy-load the Ancilis engine from config."""
        if self._engine is not None:
            return self._engine
        try:
            from ancilis.config import load_config
            from ancilis.engine.engine import Engine

            config = load_config()
            self._engine = Engine(config)
        except Exception:  # noqa: BLE001
            pass
        return self._engine

    @property
    def captured_actions(self) -> list[Any]:
        """Return list of captured Action objects (useful for testing)."""
        with self._lock:
            return list(self._actions)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _llm_result_to_dict(response: Any) -> dict[str, Any]:
    """Convert LLMResult to a plain dict for serialisation."""
    if isinstance(response, dict):
        return response
    result: dict[str, Any] = {}
    if hasattr(response, "llm_output"):
        result["llm_output"] = response.llm_output or {}
    if hasattr(response, "generations"):
        gens = response.generations or []
        result["generations"] = [[_generation_to_dict(g) for g in row] for row in gens]
    return result


def _generation_to_dict(gen: Any) -> dict[str, Any]:
    if isinstance(gen, dict):
        return gen
    return {
        "text": getattr(gen, "text", ""),
        "generation_info": getattr(gen, "generation_info", None),
    }
