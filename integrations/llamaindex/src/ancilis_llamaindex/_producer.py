"""LlamaIndexProducer — translates raw LlamaIndex instrumentation events into Ancilis Action objects."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


# Event class_name → (event_kind, action_type, lifecycle)
# event_kind is the semantic category surfaced in the tool name; lifecycle is "start" | "end" | "event".
_EVENT_MAP: dict[str, tuple[str, str, str]] = {
    "LLMCompletionStartEvent": ("llm", "tool_call", "start"),
    "LLMCompletionEndEvent": ("llm", "tool_call", "end"),
    "LLMChatStartEvent": ("llm", "tool_call", "start"),
    "LLMChatEndEvent": ("llm", "tool_call", "end"),
    "EmbeddingStartEvent": ("embedding", "data_access", "start"),
    "EmbeddingEndEvent": ("embedding", "data_access", "end"),
    "RetrievalStartEvent": ("retrieval", "data_access", "start"),
    "RetrievalEndEvent": ("retrieval", "data_access", "end"),
    "AgentToolCallEvent": ("tool", "tool_call", "event"),
    "AgentRunStepStartEvent": ("agent_step", "tool_call", "start"),
    "AgentRunStepEndEvent": ("agent_step", "tool_call", "end"),
    "QueryStartEvent": ("query", "tool_call", "start"),
    "QueryEndEvent": ("query", "tool_call", "end"),
}


class LlamaIndexProducer:
    """Translates raw LlamaIndex instrumentation event dicts into Ancilis Action objects.

    The producer is duck-typed against the event protocol — it never imports
    ``llama_index`` so the package can be used in observe-only / test contexts
    even when the framework isn't installed.
    """

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(
        self,
        agent_id: str = "llamaindex-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw LlamaIndex event dict into an Action."""
        class_name = str(raw.get("class_name") or raw.get("event_type") or "UnknownEvent")
        event_id = str(raw.get("id_") or raw.get("event_id") or "")
        parent_id = raw.get("parent_id") or raw.get("parent_span_id")

        event_kind, action_type, lifecycle = _EVENT_MAP.get(
            class_name, ("unknown", "tool_call", "event")
        )

        target_name = _extract_target_name(raw, event_kind)
        tool_name = f"llama_index:{event_kind}:{target_name}"

        params = _build_params(raw, class_name, event_kind, lifecycle)
        param_hash = hashlib.sha256(
            str(sorted(params.items(), key=lambda kv: kv[0])).encode()
        ).hexdigest()[:16]

        desc = f"{class_name}:{tool_name}"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]

        return Action(
            action_id=event_id or f"li-{int(time.time() * 1000)}",
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="llama_index",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(
                session_id=self.session_id,
                parent_action_id=str(parent_id) if parent_id else None,
            ),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_target_name(raw: dict[str, Any], event_kind: str) -> str:
    """Pick the most informative identifier for the event subject."""
    if event_kind in ("llm", "embedding"):
        model = (
            raw.get("model")
            or raw.get("model_name")
            or _from_serialized(raw, "model_name")
            or _from_serialized(raw, "model")
        )
        if model:
            return str(model)
        return "llm" if event_kind == "llm" else "embedding"

    if event_kind == "tool":
        return str(raw.get("tool_name") or raw.get("name") or "tool")

    if event_kind == "retrieval":
        return str(raw.get("retriever_name") or raw.get("name") or "retriever")

    if event_kind == "query":
        return str(raw.get("query_engine_name") or raw.get("name") or "query")

    if event_kind == "agent_step":
        return str(raw.get("agent_name") or raw.get("step_name") or "agent_step")

    return str(raw.get("name") or event_kind)


def _from_serialized(raw: dict[str, Any], key: str) -> Any:
    serialized = raw.get("serialized") or {}
    if isinstance(serialized, dict):
        return serialized.get(key) or (serialized.get("kwargs", {}) or {}).get(key)
    return None


def _build_params(
    raw: dict[str, Any], class_name: str, event_kind: str, lifecycle: str
) -> dict[str, Any]:
    """Extract evidence-relevant fields. Never capture raw response/document content."""
    params: dict[str, Any] = {
        "class_name": class_name,
        "event_kind": event_kind,
        "lifecycle": lifecycle,
    }

    timestamp = raw.get("timestamp")
    if timestamp is not None:
        params["timestamp"] = str(timestamp)

    span_id = raw.get("span_id")
    if span_id is not None:
        params["span_id"] = str(span_id)

    if event_kind == "llm":
        model = raw.get("model") or raw.get("model_name")
        if model:
            params["model"] = str(model)
        if lifecycle == "start":
            messages = raw.get("messages")
            prompt = raw.get("prompt")
            if isinstance(messages, list):
                params["message_count"] = len(messages)
            if isinstance(prompt, str):
                params["prompt_chars"] = len(prompt)
        else:  # end
            response = raw.get("response", {}) or {}
            token_usage = _extract_token_usage(response)
            if token_usage:
                params["token_usage"] = token_usage
            response_model = _from_response(response, "model")
            if response_model:
                params.setdefault("model", str(response_model))

    elif event_kind == "embedding":
        model = raw.get("model") or raw.get("model_name")
        if model:
            params["model"] = str(model)
        if lifecycle == "start":
            chunks = raw.get("chunks") or raw.get("texts")
            if isinstance(chunks, list):
                params["chunk_count"] = len(chunks)
        else:  # end
            embeddings = raw.get("embeddings")
            if isinstance(embeddings, list):
                params["embedding_count"] = len(embeddings)

    elif event_kind == "retrieval":
        if lifecycle == "start":
            query = raw.get("str_or_query_bundle") or raw.get("query")
            if query is not None:
                params["query"] = str(query)[:512]
        else:  # end
            nodes = raw.get("nodes") or raw.get("retrieved_nodes") or []
            if isinstance(nodes, list):
                params["node_count"] = len(nodes)
                params["node_sources"] = [
                    _safe_node_meta(n) for n in nodes[:20]
                ]

    elif event_kind == "tool":
        tool_name = raw.get("tool_name") or raw.get("name")
        if tool_name:
            params["tool_name"] = str(tool_name)
        # arguments may be dict or string — capture preview only
        args = raw.get("arguments") or raw.get("tool_kwargs") or raw.get("input")
        if args is not None:
            args_str = str(args)
            params["arguments_preview"] = args_str[:512]
            params["arguments_length"] = len(args_str)

    elif event_kind == "query":
        if lifecycle == "start":
            query = raw.get("query") or raw.get("str_or_query_bundle")
            if query is not None:
                params["query"] = str(query)[:512]
        else:  # end
            response = raw.get("response")
            if response is not None:
                params["response_length"] = len(str(response))

    elif event_kind == "agent_step":
        step = raw.get("step") or raw.get("step_id")
        if step is not None:
            params["step"] = str(step)

    # Error capture — applies to any *_End or AgentToolCall event
    error = raw.get("error")
    if error is not None:
        params["error"] = str(error)[:512]
        # error.type — when caller passes an Exception or a dict with .type
        err_type = (
            getattr(error, "__class__", None).__name__
            if isinstance(error, BaseException)
            else (error.get("type") if isinstance(error, dict) else None)
        )
        if err_type:
            params["error_type"] = str(err_type)

    if "id_" in raw:
        params["event_id"] = str(raw["id_"])
    parent_id = raw.get("parent_id") or raw.get("parent_span_id")
    if parent_id:
        params["parent_id"] = str(parent_id)

    return params


def _extract_token_usage(response: Any) -> dict[str, Any]:
    """Pull token usage out of a response payload's ``raw`` field if present."""
    if not isinstance(response, dict):
        return {}
    raw_field = response.get("raw")
    if not isinstance(raw_field, dict):
        return {}
    usage = raw_field.get("usage")
    if isinstance(usage, dict):
        return {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
        }
    # Some providers expose token counts at the top of ``raw``
    if any(
        k in raw_field for k in ("prompt_tokens", "completion_tokens", "total_tokens")
    ):
        return {
            "prompt_tokens": raw_field.get("prompt_tokens"),
            "completion_tokens": raw_field.get("completion_tokens"),
            "total_tokens": raw_field.get("total_tokens"),
        }
    return {}


def _from_response(response: Any, key: str) -> Any:
    if not isinstance(response, dict):
        return None
    raw_field = response.get("raw")
    if isinstance(raw_field, dict) and key in raw_field:
        return raw_field[key]
    return response.get(key)


def _safe_node_meta(node: Any) -> dict[str, Any]:
    """Extract only safe metadata fields from a NodeWithScore-like object."""
    allowed = ("source", "page", "chunk_id", "doc_id", "node_id", "score")
    if hasattr(node, "metadata") or hasattr(node, "node"):
        meta: dict[str, Any] = {}
        inner = getattr(node, "node", node)
        node_meta = getattr(inner, "metadata", None) or {}
        if isinstance(node_meta, dict):
            for k in ("source", "page", "chunk_id", "doc_id"):
                if k in node_meta:
                    meta[k] = node_meta[k]
        for k in ("node_id", "id_"):
            v = getattr(inner, k, None)
            if v is not None:
                meta["node_id"] = str(v)
                break
        score = getattr(node, "score", None)
        if score is not None:
            meta["score"] = score
        return meta
    if isinstance(node, dict):
        meta_field = node.get("metadata") or {}
        out = {k: v for k, v in meta_field.items() if k in allowed}
        for k in ("node_id", "id_"):
            if k in node:
                out["node_id"] = str(node[k])
                break
        if "score" in node:
            out["score"] = node["score"]
        return out
    return {}


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
