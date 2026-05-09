"""DSPyProducer — translates raw DSPy events into Ancilis Action objects.

This module never imports ``dspy`` at module load. The producer is duck-typed —
callers pass plain dict events extracted from ``dspy.LM`` calls, ``dspy.Module``
invocations, retriever (``dspy.Retrieve``) hits, ``dspy.evaluate.Evaluate``
loops, and ``dspy.teleprompt`` compile passes. This keeps the Ancilis evidence
path independent of the DSPy version installed (or absent) at runtime.

Security-critical guarantees:

1. **dspy.Example field VALUES are never stored raw.** Only the list of
   field names, the count, and a sha256 digest of the joined values.
2. **dspy.Prediction field VALUES are never stored raw.** Same treatment.
3. **Teleprompt training sets are never stored raw.** Only size + sha256.
4. **Prompt and completion text are never stored raw.** Only length + sha256.
5. **Numeric optimization scores ARE captured** — these are posture-relevant,
   not PII.
6. **Token usage is captured normally.**
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


# Map raw DSPy event ``kind`` strings to Ancilis (action_type, semantic_kind)
# pairs. ``semantic_kind`` is the second segment in the tool name pattern
# ``dspy:{kind}:{name}`` and lets evaluators bucket events without parsing
# action_type back out.
_EVENT_MAP: dict[str, tuple[str, str]] = {
    # Single LM invocation (a Predict / ChainOfThought / ReAct internal call).
    "lm_call": ("tool_call", "lm"),
    "lm_start": ("tool_call", "lm"),
    "lm_end": ("tool_call", "lm"),
    # Custom dspy.Module.__call__ — top-level user-program entry/exit.
    "module_call": ("tool_call", "module"),
    "module_start": ("tool_call", "module"),
    "module_end": ("tool_call", "module"),
    # Retriever model — RAG lookup, always data_access.
    "retrieve": ("data_access", "retrieve"),
    # Evaluate.evaluate iteration over a dev set.
    "evaluate": ("tool_call", "evaluate"),
    "evaluate_start": ("tool_call", "evaluate"),
    "evaluate_end": ("tool_call", "evaluate"),
    # Teleprompt optimization steps (BootstrapFewShot, MIPROv2, SIMBA, ...).
    "compile": ("tool_call", "compile"),
    "compile_start": ("tool_call", "compile"),
    "compile_end": ("tool_call", "compile"),
}


class DSPyProducer:
    """Translates raw DSPy event dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(
        self,
        agent_id: str = "dspy-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw DSPy event dict into an Action.

        Expected keys (all optional except ``kind``):
          - kind: one of the keys in ``_EVENT_MAP``
          - id / call_id / event_id: per-event identifier
          - agent_id: overrides the producer's default
          - module_name / lm_name / optimizer / metric_name: target name
          - inputs: dspy.Example-like (sanitized — names + sha256 only)
          - outputs: dspy.Prediction-like (sanitized — names + sha256 only)
          - prompt: prompt string (sanitized — length + sha256 only)
          - completion: completion string (sanitized — length + sha256 only)
          - usage: dict of token counts
          - query: retriever query (sanitized — length + sha256 only)
          - results: retriever result list (count only)
          - trainset / trainset_size: teleprompt training set (sanitized)
          - score: numeric optimization score (captured raw — posture useful)
          - dataset_size: evaluate dataset size
          - error / exception: exception captured as error_type
          - parent_call_id / parent_id: parent action correlator
        """
        kind = str(raw.get("kind") or raw.get("event") or "unknown")
        action_type, semantic_kind = _EVENT_MAP.get(
            _normalise_kind(kind), ("tool_call", "unknown")
        )

        target_name = _extract_target_name(kind, semantic_kind, raw)
        tool_name = f"dspy:{semantic_kind}:{target_name}"

        params = _build_params(kind, semantic_kind, raw)
        param_hash = hashlib.sha256(
            json.dumps(_sortable(params), sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        desc = f"{kind}:{target_name}"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]

        action_id = str(
            raw.get("id")
            or raw.get("call_id")
            or raw.get("event_id")
            or f"dspy-{int(time.time() * 1_000_000)}"
        )
        parent_id = (
            raw.get("parent_call_id")
            or raw.get("parent_id")
            or raw.get("parent_action_id")
        )
        agent_id = str(raw.get("agent_id") or self.agent_id)

        return Action(
            action_id=action_id,
            timestamp=_iso_now(),
            agent_id=agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="dspy",
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


def _normalise_kind(kind: str) -> str:
    """Collapse start/end variants to the lookup key.

    The event map keys both the canonical name (``lm_call``) and its
    start/end variants (``lm_start`` / ``lm_end``) so callers can pass
    whichever they emit.
    """
    return kind


def _extract_target_name(
    kind: str, semantic_kind: str, raw: dict[str, Any]
) -> str:
    """Pick the most informative identifier for the event subject."""
    if semantic_kind == "lm":
        return str(
            raw.get("lm_name")
            or raw.get("model")
            or raw.get("name")
            or "lm"
        )
    if semantic_kind == "module":
        return str(
            raw.get("module_name")
            or raw.get("name")
            or "module"
        )
    if semantic_kind == "retrieve":
        return str(
            raw.get("rm_name")
            or raw.get("retriever")
            or raw.get("name")
            or "retrieve"
        )
    if semantic_kind == "evaluate":
        return str(
            raw.get("metric_name")
            or raw.get("metric")
            or raw.get("name")
            or "evaluate"
        )
    if semantic_kind == "compile":
        return str(
            raw.get("optimizer")
            or raw.get("teleprompter")
            or raw.get("name")
            or "compile"
        )
    return str(raw.get("name") or kind)


def _build_params(
    kind: str, semantic_kind: str, raw: dict[str, Any]
) -> dict[str, Any]:
    """Extract evidence-relevant fields. Never capture raw text or example values."""
    params: dict[str, Any] = {"kind": kind, "semantic_kind": semantic_kind}

    # Universal correlation fields
    for src, dst in (
        ("id", "event_id"),
        ("call_id", "call_id"),
        ("event_id", "event_id"),
        ("agent_id", "agent_id"),
        ("session_id", "session_id"),
    ):
        value = raw.get(src)
        if value is not None:
            params[dst] = str(value)

    parent_id = (
        raw.get("parent_call_id")
        or raw.get("parent_id")
        or raw.get("parent_action_id")
    )
    if parent_id is not None:
        params["parent_call_id"] = str(parent_id)

    # ----- LM call surface -----
    if semantic_kind == "lm":
        if raw.get("model") is not None:
            params["model"] = str(raw["model"])
        if raw.get("lm_name") is not None:
            params["lm_name"] = str(raw["lm_name"])
        prompt = raw.get("prompt") or raw.get("messages")
        if prompt is not None:
            text = _flatten_prompt(prompt)
            params["prompt_length"] = len(text)
            params["prompt_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        completion = raw.get("completion") or raw.get("response") or raw.get(
            "output"
        )
        if completion is not None:
            text = _flatten_prompt(completion)
            params["completion_length"] = len(text)
            params["completion_sha256"] = hashlib.sha256(
                text.encode()
            ).hexdigest()

    # ----- Module call surface -----
    elif semantic_kind == "module":
        if raw.get("module_name") is not None:
            params["module_name"] = str(raw["module_name"])
        inputs = raw.get("inputs")
        if inputs is not None:
            params["inputs"] = _sanitize_example(inputs)
        outputs = raw.get("outputs") or raw.get("prediction")
        if outputs is not None:
            params["outputs"] = _sanitize_example(outputs)

    # ----- Retrieve surface -----
    elif semantic_kind == "retrieve":
        if raw.get("rm_name") is not None:
            params["rm_name"] = str(raw["rm_name"])
        query = raw.get("query") or raw.get("queries")
        if query is not None:
            text = _flatten_prompt(query)
            params["query_length"] = len(text)
            params["query_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        if isinstance(raw.get("k"), int):
            params["k"] = int(raw["k"])
        results = raw.get("results") or raw.get("passages")
        if isinstance(results, list):
            params["result_count"] = len(results)
        elif isinstance(raw.get("count"), int):
            params["result_count"] = int(raw["count"])

    # ----- Evaluate surface -----
    elif semantic_kind == "evaluate":
        if raw.get("metric_name") is not None:
            params["metric_name"] = str(raw["metric_name"])
        if isinstance(raw.get("dataset_size"), int):
            params["dataset_size"] = int(raw["dataset_size"])
        elif isinstance(raw.get("devset"), list):
            params["dataset_size"] = len(raw["devset"])
        score = raw.get("score") or raw.get("metric_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            params["score"] = float(score)

    # ----- Compile (teleprompt) surface -----
    elif semantic_kind == "compile":
        if raw.get("optimizer") is not None:
            params["optimizer"] = str(raw["optimizer"])
        # Training set: capture size + sha256 ONLY. The trainset is the
        # highest-PII surface in DSPy — it's typically real user data the
        # programmer wants to optimize against.
        trainset = raw.get("trainset")
        if trainset is not None:
            sanitized = _sanitize_trainset(trainset)
            params["trainset_size"] = sanitized["size"]
            params["trainset_sha256"] = sanitized["sha256"]
        elif isinstance(raw.get("trainset_size"), int):
            params["trainset_size"] = int(raw["trainset_size"])
        score = raw.get("score") or raw.get("metric_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            params["score"] = float(score)
        if isinstance(raw.get("step"), int):
            params["step"] = int(raw["step"])

    # Token usage capture (any event that carries it).
    usage = _normalise_usage(raw.get("usage") or raw.get("token_usage"))
    if usage:
        params["usage"] = usage

    # Generic error capture.
    err_type = _extract_error_type(raw.get("error") or raw.get("exception"))
    if err_type is not None:
        params["error_type"] = err_type

    return params


def _flatten_prompt(prompt: Any) -> str:
    """Flatten a prompt — may be a string, a list of {role, content} dicts, etc."""
    if prompt is None:
        return ""
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, list):
        parts: list[str] = []
        for item in prompt:
            if isinstance(item, dict):
                content = item.get("content") or item.get("text")
                if content is not None:
                    parts.append(str(content))
                else:
                    parts.append(repr(item))
            elif isinstance(item, str):
                parts.append(item)
            else:
                content = (
                    getattr(item, "content", None)
                    or getattr(item, "text", None)
                )
                parts.append(str(content) if content is not None else repr(item))
        return "\n".join(parts)
    return str(prompt)


def _sanitize_example(example: Any) -> dict[str, Any]:
    """Sanitize a dspy.Example or dspy.Prediction.

    DSPy ``Example`` and ``Prediction`` objects are field-value containers
    that frequently hold real user input or model output. We capture:

      * the sorted list of field names
      * the field count
      * a sha256 digest of the joined values (for change-detection)

    We NEVER capture the raw values themselves.
    """
    fields = _example_fields(example)
    if not fields:
        return {"field_names": [], "field_count": 0, "values_sha256": None}
    keys = sorted(str(k) for k in fields)
    # Concatenate values in sorted-key order so the digest is stable.
    joined = "\x1f".join(repr(fields[k]) for k in keys)
    values_sha256 = hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()
    return {
        "field_names": keys,
        "field_count": len(keys),
        "values_sha256": values_sha256,
    }


def _example_fields(example: Any) -> dict[str, Any]:
    """Pull the field-value mapping off a duck-typed Example / Prediction."""
    if example is None:
        return {}
    if isinstance(example, dict):
        return {str(k): v for k, v in example.items() if not str(k).startswith("_")}
    # dspy.Example / dspy.Prediction expose ``_store`` (a dict-like) under the
    # hood. Fall back to ``items`` (callable) → ``__dict__`` → ``vars``.
    store = getattr(example, "_store", None)
    if isinstance(store, dict):
        return {str(k): v for k, v in store.items() if not str(k).startswith("_")}
    items_method = getattr(example, "items", None)
    if callable(items_method):
        try:
            collected = dict(items_method())
            return {
                str(k): v
                for k, v in collected.items()
                if not str(k).startswith("_")
            }
        except Exception:  # noqa: BLE001
            pass
    inst_dict = getattr(example, "__dict__", None)
    if isinstance(inst_dict, dict):
        return {
            str(k): v
            for k, v in inst_dict.items()
            if not str(k).startswith("_") and not callable(v)
        }
    return {}


def _sanitize_trainset(trainset: Any) -> dict[str, Any]:
    """Sanitize a teleprompt training set.

    Training sets are sequences of ``dspy.Example`` objects. We capture only:

      * size (count of examples)
      * sha256 of the joined per-example digest list

    The actual examples are NEVER materialised into evidence.
    """
    if trainset is None:
        return {"size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    try:
        items = list(trainset)
    except TypeError:
        return {"size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    digests: list[str] = []
    for ex in items:
        sanitized = _sanitize_example(ex)
        digests.append(sanitized.get("values_sha256") or "")
    joined = "\x1e".join(digests)
    return {
        "size": len(items),
        "sha256": hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest(),
    }


def _normalise_usage(usage: Any) -> dict[str, Any] | None:
    """Coerce a usage object/dict to a plain dict of integer/float scalars.

    Captures the canonical fields where present:
    ``prompt_tokens``, ``completion_tokens``, ``total_tokens``, ``input_tokens``,
    ``output_tokens``.
    """
    if usage is None:
        return None
    if isinstance(usage, dict):
        source = usage
    else:
        source = {}
        for attr in (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "input_tokens",
            "output_tokens",
        ):
            if hasattr(usage, attr):
                source[attr] = getattr(usage, attr)
    out: dict[str, Any] = {}
    for key, value in source.items():
        if value is None:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out[str(key)] = value
            continue
        try:
            out[str(key)] = float(value)
        except (TypeError, ValueError):
            try:
                out[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
    return out or None


def _extract_error_type(error: Any) -> str | None:
    """Return a short error.type string, or None if no error is present."""
    if error is None:
        return None
    if isinstance(error, BaseException):
        return type(error).__name__
    if isinstance(error, dict):
        t = error.get("type") or error.get("error_type")
        return str(t) if t else None
    if isinstance(error, str):
        return error or None
    return type(error).__name__


def _sortable(value: Any) -> Any:
    """Normalise a params dict into a JSON-serialisable, sortable structure."""
    if isinstance(value, dict):
        return {str(k): _sortable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sortable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
