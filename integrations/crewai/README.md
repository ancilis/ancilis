# ancilis-crewai

CrewAI integration for [Ancilis](https://ancilis.ai) — zero-config evidence capture via `@ancilis_crew` decorator.

## Install

```bash
pip install ancilis-crewai
```

## Quickstart

```python
from ancilis_crewai import ancilis_crew
from crewai import Crew, Agent, Task

@ancilis_crew
class ResearchCrew(Crew):
    ...
```

That's it. All `kickoff()` calls now automatically capture:
- Crew start/end (agent/task counts, output length)
- Per-task start/end (agent role, task description length, output length)

## With options

```python
@ancilis_crew(agent_id="my-pipeline", session_id="run-42")
class ResearchCrew(Crew):
    ...
```

## What gets captured

| Event | Evidence |
|-------|----------|
| `crew_start` | crew name, agent count, task count |
| `crew_end` | output length (not content), agent/task counts |
| `task_start` | agent role, task description length, expected output length |
| `task_end` | agent role, output length |
| `tool_use` | tool name, input preview (512 chars max), input length |
| `delegation` | from_agent, to_agent, delegated task length |

Output content is never stored — only lengths. Tool inputs are truncated at 512 chars.

## Compatibility

- crewai: `>=0.40.0`
- Python: `>=3.10`
- Ancilis: `>=0.1.0`

## Safety

- Evidence capture errors never propagate — your crew runs unaffected
- No LLM content stored in evidence (only lengths)
- Compatible with `ancilis-langchain` if both installed (no double-capture — different event sources)
