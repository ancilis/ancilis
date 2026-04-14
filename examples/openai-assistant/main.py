"""OpenAI Assistants API + Ancilis SOC 2 / HIPAA Compliance Monitoring.

Demonstrates wrapping raw OpenAI Assistants API calls with HTTPActionProducer
to capture compliance evidence for every API interaction — no framework needed.

The example simulates an assistant that handles health-record queries. It
works without an OpenAI API key (simulation mode). Set OPENAI_API_KEY in .env
to enable live Assistants API calls.

Overlay activation:
  health_records → HIPAA overlay (HIPAA §164.312 audit controls)
  personal_info  → GDPR, CCPA overlays

Run from this directory:
    python main.py
    ancilis scan

Prerequisites:
    pip install -r requirements.txt
    cp .env.example .env  # optional — only needed for live API calls
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.producers.http import HTTPActionProducer, HTTPRequest

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = HTTPActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Agent:     {config.agent_name}")
print(f"Mode:      {config.mode}")
print(f"HIPAA:     {'hipaa' in (config.active_overlays or {})}")
print(f"SOC 2:     {'soc2' in (config.active_overlays or {})}")
print(f"GDPR:      {'gdpr' in (config.active_overlays or {})}")
print()


# ---------------------------------------------------------------------------
# Simulated Assistants API responses (used when OPENAI_API_KEY is not set)
# ---------------------------------------------------------------------------

_BASE_URL = "https://api.openai.com/v1"
_THREAD_ID = "thread_sim_abc123"
_ASSISTANT_ID = "asst_sim_healthrecords"

_SIM_RESPONSES: dict[str, Any] = {
    "create_assistant": {
        "id": _ASSISTANT_ID,
        "object": "assistant",
        "name": "Health Records Assistant",
        "model": "gpt-4o",
        "tools": [{"type": "code_interpreter"}, {"type": "file_search"}],
    },
    "create_thread": {
        "id": _THREAD_ID,
        "object": "thread",
    },
    "create_message": {
        "id": "msg_sim_001",
        "object": "thread.message",
        "thread_id": _THREAD_ID,
        "role": "user",
    },
    "create_run": {
        "id": "run_sim_001",
        "object": "thread.run",
        "thread_id": _THREAD_ID,
        "assistant_id": _ASSISTANT_ID,
        "status": "completed",
    },
    "list_messages": {
        "object": "list",
        "data": [
            {
                "id": "msg_sim_002",
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": {
                            "value": (
                                "Based on the patient record, the last HbA1c reading was 6.2% "
                                "(within normal range). Next check-up is recommended in 6 months. "
                                "All data access has been logged per HIPAA §164.312(b)."
                            )
                        },
                    }
                ],
            }
        ],
    },
}


def _record_and_call(
    endpoint: str,
    method: str,
    body: dict[str, Any],
    sim_key: str,
) -> dict[str, Any]:
    """Record the HTTP action via Ancilis, then return simulated or live response."""
    api_key = os.getenv("OPENAI_API_KEY", "")
    url = f"{_BASE_URL}/{endpoint}"

    sim_response = _SIM_RESPONSES[sim_key]

    # Always record the action — Ancilis captures intent regardless of live/sim
    producer.observe(
        HTTPRequest(
            method=method,
            url=url,
            agent_name=config.agent_name,
            body=body if body else None,
            service_name="api.openai.com",
        )
    )

    if not api_key or api_key.startswith("sk-..."):
        return sim_response

    # Live path (requires a real API key)
    try:
        import openai  # noqa: PLC0415

        client = openai.OpenAI(api_key=api_key)
        if sim_key == "create_assistant":
            return client.beta.assistants.create(**body).model_dump()
        if sim_key == "create_thread":
            return client.beta.threads.create().model_dump()
        if sim_key == "create_message":
            return client.beta.threads.messages.create(**body).model_dump()
        if sim_key == "create_run":
            return client.beta.threads.runs.create_and_poll(**body).model_dump()
        if sim_key == "list_messages":
            thread_id = body.get("thread_id", _THREAD_ID)
            return client.beta.threads.messages.list(thread_id=thread_id).model_dump()
    except Exception as exc:  # noqa: BLE001
        print(f"  [live call failed: {exc}] — using simulation")

    return sim_response


# ---------------------------------------------------------------------------
# Assistants API workflow
# ---------------------------------------------------------------------------

print("=== OpenAI Assistants API Workflow ===")
print()

# Step 1: Create an Assistant with health-record tools
print("[1] Creating assistant...")
asst = _record_and_call(
    endpoint="assistants",
    method="POST",
    body={
        "name": "Health Records Assistant",
        "model": "gpt-4o",
        "tools": [{"type": "code_interpreter"}, {"type": "file_search"}],
        "instructions": "You assist with patient health record queries. Follow HIPAA guidelines.",
    },
    sim_key="create_assistant",
)
print(f"    id={asst['id']}  name={asst.get('name', 'n/a')}")
print()

# Step 2: Create a conversation thread
print("[2] Creating thread...")
thread = _record_and_call(
    endpoint="threads",
    method="POST",
    body={},
    sim_key="create_thread",
)
print(f"    id={thread['id']}")
print()

# Step 3: Add a user message
print("[3] Adding user message...")
msg = _record_and_call(
    endpoint=f"threads/{thread['id']}/messages",
    method="POST",
    body={
        "role": "user",
        "content": "What was the patient's last HbA1c reading and when is their next check-up?",
    },
    sim_key="create_message",
)
print(f"    id={msg['id']}  role={msg.get('role')}")
print()

# Step 4: Run the assistant
print("[4] Running assistant...")
run = _record_and_call(
    endpoint=f"threads/{thread['id']}/runs",
    method="POST",
    body={"thread_id": thread["id"], "assistant_id": asst["id"]},
    sim_key="create_run",
)
print(f"    id={run['id']}  status={run.get('status')}")
print()

# Step 5: Retrieve the response
print("[5] Retrieving response messages...")
messages = _record_and_call(
    endpoint=f"threads/{thread['id']}/messages",
    method="GET",
    body={"thread_id": thread["id"]},
    sim_key="list_messages",
)
assistant_msgs = [m for m in messages.get("data", []) if m.get("role") == "assistant"]
if assistant_msgs:
    content = assistant_msgs[0].get("content", [])
    if content and content[0].get("type") == "text":
        reply = content[0]["text"]["value"]
        print(f"    Assistant: {reply[:120]}{'...' if len(reply) > 120 else ''}")
print()

# ---------------------------------------------------------------------------
# Evidence summary
# ---------------------------------------------------------------------------
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence Summary ===")
print(f"  API calls recorded: {summary['total_evaluations']}")
print(f"  Decisions:          {summary['decisions']}")
print(f"  Hash chain:         {'intact' if summary['chain_valid'] else 'BROKEN'}")
print()
print("Run `ancilis scan` to see HIPAA + SOC 2 posture.")

evidence.close()
