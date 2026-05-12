# ancilis-agno

[Agno](https://github.com/agno-agi/agno) integration for [Ancilis](https://ancilis.ai) — automatic evidence capture for team-of-agents, knowledge-base, and memory-aware agentic systems.

Agno (formerly Phidata) is a fast, modular agentic framework with first-class primitives for memory, knowledge bases, and teams of cooperating agents. Each of those surfaces touches user-supplied content that frequently contains PII or org-internal context — Ancilis records every run, tool call, memory write, knowledge query, and team delegation as cryptographically chained evidence, without ever storing the raw values.

## Install

```bash
pip install ancilis-agno
```

## Quickstart — wrap_agent

```python
from agno.agent import Agent
from ancilis_agno import wrap_agent

agent = wrap_agent(Agent(model=..., memory=..., knowledge=...), agent_id="research-agent")
response = agent.run("summarize last quarter's sales")
```

## Quickstart — wrap_team

```python
from agno.team import Team
from ancilis_agno import wrap_team

team = wrap_team(Team(members=[a1, a2, a3]), agent_id="research-team")
response = team.run("draft the Q3 board memo")
```

## What gets captured

| Agno event / op | action_type | Captured |
|-----------------|-------------|----------|
| `RunStarted` / `RunResponse` / `RunCompleted` | `tool_call` | model, content length + sha256, token metrics |
| `ToolCallStarted` / `ToolCallCompleted` | `tool_call` | tool name, sanitized arg keys + sha256 of arg values, `tool_call_id` |
| `MemberRunStarted` / `MemberRunCompleted` | `tool_call` | member name + agent id, member-level metrics |
| `Memory.add_user_memory` / `update_session_summary` | `data_access` | content length + sha256 |
| `Knowledge.search` / `add` / `update` | `data_access` | query length + sha256, document count |

## Privacy

**Memory and knowledge content are never stored raw.** Agno teams persist user memory across sessions, and knowledge bases ingest user-supplied documents. Ancilis records only:

- Length of every text payload (memory text, knowledge query, tool args)
- A sha256 digest of the content (for change-detection / chain-of-custody)
- Tool argument *keys* and a sha256 digest of each value
- Token metrics (`time_to_first_token`, `total_tokens`, `tokens_per_second`)

Raw memory text, raw knowledge queries, and raw tool-arg values never enter the evidence store.

## Compatibility

- agno: `>=1.0.0` (loose; producer is duck-typed and never imports `agno` at module load)
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
