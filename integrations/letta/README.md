# ancilis-letta

[Letta](https://letta.com) integration for [Ancilis](https://ancilis.ai) — automatic evidence capture for stateful, memory-persistent agents.

Letta agents (formerly MemGPT) maintain durable memory blocks across conversations. That makes their memory operations a primary security boundary: archival writes, core-memory updates, and retrievals all touch user-supplied content that frequently contains PII, credentials, or org-internal context. Ancilis records these operations as cryptographically chained evidence — without ever storing the raw memory text.

## Install

```bash
pip install ancilis-letta
```

## Quickstart — wrap_client

```python
from letta_client import Letta
from ancilis_letta import wrap_client

client = wrap_client(Letta(token="..."), agent_id="agent-abc")
response = client.agents.messages.create(
    agent_id="agent-abc",
    messages=[{"role": "user", "content": "remember my name is Kevin"}],
)
```

## Quickstart — record_response (no-wrap path)

If you already have a `LettaResponse` (e.g. from a fixture or replay), record it after the fact:

```python
from ancilis_letta import record_response

record_response(
    response,
    agent_id="agent-abc",
    engine=engine,
    evidence_store=store,
)
```

## What gets captured

| Letta message subtype | action_type | Captured |
|-----------------------|-------------|----------|
| `tool_call_message` | `tool_call` | tool name, sanitized arg keys + sha256 of arg values |
| `tool_return_message` | `tool_call` | tool name, return length, error.type if present |
| `assistant_message` / `reasoning_message` | `tool_call` | role, content length + sha256 |
| `archival_memory_create` / `archival_memory_update` | `data_access` | block label, content length + sha256 |
| `archival_memory_search` | `data_access` | query length + sha256, result count |
| `core_memory_update` | `data_access` | block label, new-value length + sha256 |

## Privacy

**Memory-block content is never stored raw.** Letta agents persist user-supplied memory across sessions — this is the most sensitive surface in any stateful-agent stack. Ancilis records only:

- Length of every text payload (message content, memory blocks, queries)
- A sha256 digest of the content (for change-detection / chain-of-custody)
- Tool argument *keys* and a sha256 digest of each value

Raw text, raw tool-arg values, and raw memory contents never enter the evidence store.

## Configuration

`wrap_client` accepts optional `engine=` and `evidence_store=` for direct injection. By default, the wrapped client observes operations without forwarding — wire up your `Engine` and `EvidenceStore` to enforce or persist.

## Compatibility

- letta-client: `>=0.1.0` (loose; producer is duck-typed and never imports letta_client at module load)
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
