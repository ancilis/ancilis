# CrewAI Research Crew + Ancilis Multi-Agent Compliance

A simulated CrewAI multi-agent research crew with Ancilis SDK for compliance monitoring. Demonstrates per-agent evidence attribution — each crew member's tool calls are recorded under its own identity.

## What this demonstrates

1. A three-agent crew: **Researcher** (web search) → **Analyst** (findings processing) → **Reporter** (report generation)
2. Per-agent evidence attribution via `agent_name=` in `wrap_tool()`
3. SOC 2 overlay activates from `my_agent_handles: [personal_info]`
4. Shared evidence store across all agents — single DuckDB file

When `ancilis-crewai` ships, the `wrap_tool()` calls can be replaced with native CrewAI decorators. The TODO markers in `main.py` show where to migrate.

## Prerequisites

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set OPENAI_API_KEY
```

Or:

```bash
make setup
```

## Run

```bash
make run    # executes main.py (simulated crew, no API key needed)
make scan   # shows compliance posture
```

The example uses simulated tools and does **not** require an OpenAI API key for the compliance demonstration. Set `OPENAI_API_KEY` to connect a real CrewAI crew.

## Config

```yaml
agent:
  name: crewai-research-crew
my_agent_handles:
  - personal_info
mode: audit
```

## Expected output

```
Crew: crewai-research-crew
Mode: audit
SOC 2 overlay: True

=== CrewAI Research Crew Execution ===

[Researcher] Gathering intelligence...
  search_web → 3 results
  ...

=== Evidence Summary ===
  Records:    6
  Decisions:  {'ALLOW': 6}
  Hash chain: intact
  Tools:      ['analyze_findings', 'generate_report', 'search_web']
```

## Per-agent attribution pattern

```python
from ancilis import ToolActionProducer

# Single producer, per-call agent attribution
search_web = producer.wrap_tool(search_impl, tool_name="search_web", agent_name="researcher")
analyze = producer.wrap_tool(analyze_impl, tool_name="analyze", agent_name="analyst")
report = producer.wrap_tool(report_impl, tool_name="generate_report", agent_name="reporter")

# TODO: use ancilis-crewai for native CrewAI integration (ANC-568)
```

## Next steps

- See [langchain-chatbot](../langchain-chatbot/) for a single-agent LangChain integration
- See [certification-driven](../certification-driven/) for AIUC-1 targeting
