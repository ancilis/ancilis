"""OpenAI Chat Completions + Ancilis SOC 2 / HIPAA compliance monitoring.

Demonstrates ``OpenAIActionProducer.wrap_create`` — wrap the OpenAI client's
``chat.completions.create`` (or ``responses.create``) once and every model
invocation becomes an evaluated, evidence-recorded Action with the model
captured as the tool name (``llm:openai:gpt-4o-mini``, etc.).

Works without an OPENAI_API_KEY: the producer is duck-typed against the
upstream SDK and we drive a fake transport here. Set ``OPENAI_API_KEY`` in
``.env`` to swap the fake transport for a real one.

Overlay activation:
  health_records → HIPAA overlay (HIPAA §164.312 audit controls)
  personal_info  → GDPR, CCPA overlays

Run from this directory:

    python main.py
    ancilis status            # see HIPAA + SOC 2 + GDPR posture

Prerequisites:

    pip install -r requirements.txt
    cp .env.example .env  # optional — only needed for live API calls
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.producers import OpenAIActionProducer

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run.
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = OpenAIActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Agent:     {config.agent_name}")
print(f"Mode:      {config.mode}")
print(f"HIPAA:     {'hipaa' in (config.active_overlays or {})}")
print(f"SOC 2:     {'soc2' in (config.active_overlays or {})}")
print(f"GDPR:      {'gdpr' in (config.active_overlays or {})}")
print()


# ---------------------------------------------------------------------------
# Transport — fake or real depending on OPENAI_API_KEY
# ---------------------------------------------------------------------------
#
# The producer doesn't care whether the transport is the real OpenAI SDK or a
# stub — it observes the kwargs and emits an Action before the transport
# fires. ``wrap_create`` just calls whatever you pass in.

def _fake_chat_create(**kwargs: Any) -> dict[str, Any]:
    """Stand-in for ``client.chat.completions.create`` for offline runs."""
    last_user = next(
        (m.get("content", "") for m in reversed(kwargs.get("messages", [])) if m.get("role") == "user"),
        "",
    )
    canned: dict[str, str] = {
        "What was the patient's last HbA1c reading?": (
            "Last HbA1c was 6.2% (within normal range). Audit logged per HIPAA §164.312(b)."
        ),
        "When is the next check-up?": (
            "Recommended in 6 months. Reminder will be sent via the patient portal."
        ),
        "Summarize the audit trail": (
            "All access events have been recorded with hash-chained evidence. SOC 2 CC6.1 satisfied."
        ),
    }
    text = canned.get(last_user, "Simulated response — set OPENAI_API_KEY for real completions.")
    return {
        "id": "chatcmpl-sim-001",
        "model": kwargs.get("model"),
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {"prompt_tokens": 24, "completion_tokens": 18, "total_tokens": 42},
    }


def _resolve_transport() -> Any:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key or api_key.startswith("sk-..."):
        return _fake_chat_create
    try:
        import openai  # noqa: PLC0415
    except ImportError:
        return _fake_chat_create
    client = openai.OpenAI(api_key=api_key)
    return lambda **kwargs: client.chat.completions.create(**kwargs).model_dump()


transport = _resolve_transport()
wrapped = producer.wrap_create(transport, agent_name=config.agent_name)

print("=== OpenAI chat completions (observed) ===\n")

CONVERSATION = [
    "What was the patient's last HbA1c reading?",
    "When is the next check-up?",
    "Summarize the audit trail",
]

for question in CONVERSATION:
    print(f"[user] {question}")
    result = wrapped(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a HIPAA-compliant health records assistant."},
            {"role": "user", "content": question},
        ],
    )
    answer = result.response["choices"][0]["message"]["content"]
    print(f"[assistant] {answer}")
    print(f"  decision={result.evaluation.decision} tool={result.action.tool.name}")
    print()


# --- Evidence summary (filtered to this producer's run) ---
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Each call is attributed via the tool name `llm:openai:{model}` — match it in `ancilis.yaml`.")
print("Run `ancilis status` to see HIPAA / SOC 2 / GDPR posture.")

evidence.close()
