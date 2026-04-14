"""LangChainProducer — translates raw LangChain callback data into Ancilis Action objects."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


class LangChainProducer:
    """Translates raw LangChain callback payloads into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(self, agent_id: str = "langchain-agent", session_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw LangChain callback event dict into an Action."""
        event_type = raw.get("event_type", "unknown")
        run_id = str(raw.get("run_id", ""))
        parent_run_id = raw.get("parent_run_id")

        # Determine action_type and tool info
        if event_type in ("llm_start", "llm_end", "llm_error"):
            action_type = "tool_call"
            tool_name = _extract_model_name(raw)
            tool_version = None
        elif event_type in ("tool_start", "tool_end", "tool_error"):
            action_type = "tool_call"
            tool_name = _extract_tool_name(raw)
            tool_version = None
        elif event_type in ("chain_start", "chain_end", "chain_error"):
            action_type = "tool_call"
            tool_name = _extract_chain_name(raw)
            tool_version = None
        elif event_type in ("retriever_start", "retriever_end", "retriever_error"):
            action_type = "data_access"
            tool_name = _extract_retriever_name(raw)
            tool_version = None
        else:
            action_type = "tool_call"
            tool_name = event_type
            tool_version = None

        # Build parameter payload — capture input/output but not raw doc content
        params = _build_params(raw, event_type)
        param_hash = hashlib.sha256(str(sorted(params.items())).encode()).hexdigest()[:16]

        tool_desc = f"{event_type}:{tool_name}"
        desc_hash = hashlib.sha256(tool_desc.encode()).hexdigest()[:16]

        return Action(
            action_id=run_id or f"lc-{int(time.time() * 1000)}",
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=tool_version,
                server="langchain",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(
                session_id=self.session_id,
                parent_action_id=str(parent_run_id) if parent_run_id else None,
            ),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_model_name(raw: dict[str, Any]) -> str:
    serialized = raw.get("serialized", {}) or {}
    # langchain-core serialized format: kwargs.model_name or kwargs.model
    kwargs = serialized.get("kwargs", {}) or {}
    return (
        kwargs.get("model_name")
        or kwargs.get("model")
        or serialized.get("name")
        or "llm"
    )


def _extract_tool_name(raw: dict[str, Any]) -> str:
    serialized = raw.get("serialized", {}) or {}
    return serialized.get("name") or raw.get("tool_name") or "tool"


def _extract_chain_name(raw: dict[str, Any]) -> str:
    serialized = raw.get("serialized", {}) or {}
    ids = serialized.get("id", [])
    if ids:
        return ids[-1]
    return serialized.get("name") or "chain"


def _extract_retriever_name(raw: dict[str, Any]) -> str:
    serialized = raw.get("serialized", {}) or {}
    return serialized.get("name") or "retriever"


def _build_params(raw: dict[str, Any], event_type: str) -> dict[str, Any]:
    """Extract evidence-relevant fields — no raw document content (privacy)."""
    params: dict[str, Any] = {"event_type": event_type}

    if event_type == "llm_start":
        prompts = raw.get("prompts", [])
        params["prompt_count"] = len(prompts)
        # Capture token count estimate only, not content
        params["total_prompt_chars"] = sum(len(p) for p in prompts if isinstance(p, str))

    elif event_type == "llm_end":
        response = raw.get("response", {}) or {}
        llm_output = response.get("llm_output", {}) or {}
        token_usage = llm_output.get("token_usage", {}) or {}
        params["token_usage"] = token_usage
        params["model_name"] = llm_output.get("model_name", "")
        generations = response.get("generations", [])
        params["generation_count"] = len(generations)

    elif event_type == "tool_start":
        params["input_str"] = raw.get("input_str", "")[:512]  # cap at 512 chars

    elif event_type == "tool_end":
        output = raw.get("output", "")
        params["output_length"] = len(str(output))

    elif event_type == "chain_start":
        inputs = raw.get("inputs", {}) or {}
        params["input_keys"] = list(inputs.keys())

    elif event_type == "chain_end":
        outputs = raw.get("outputs", {}) or {}
        params["output_keys"] = list(outputs.keys())

    elif event_type == "retriever_start":
        params["query"] = raw.get("query", "")[:512]

    elif event_type == "retriever_end":
        documents = raw.get("documents", []) or []
        # Store metadata only — no document content (privacy)
        params["document_count"] = len(documents)
        params["document_sources"] = [
            _safe_doc_meta(d) for d in documents[:20]
        ]

    # Always capture run correlation
    if "run_id" in raw:
        params["run_id"] = str(raw["run_id"])
    if "parent_run_id" in raw and raw["parent_run_id"] is not None:
        params["parent_run_id"] = str(raw["parent_run_id"])

    return params


def _safe_doc_meta(doc: Any) -> dict[str, Any]:
    """Extract only metadata from a document — no content."""
    if hasattr(doc, "metadata"):
        meta = doc.metadata or {}
        return {k: v for k, v in meta.items() if k in ("source", "page", "chunk_id", "doc_id")}
    if isinstance(doc, dict):
        meta = doc.get("metadata", {}) or {}
        return {k: v for k, v in meta.items() if k in ("source", "page", "chunk_id", "doc_id")}
    return {}


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
