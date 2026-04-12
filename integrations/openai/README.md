# ancilis-openai

OpenAI SDK integration for [Ancilis](https://ancilis.ai) — zero-config evidence capture via monkey-patch.

## Install

```bash
pip install ancilis-openai
```

## Quickstart

```python
from ancilis_openai import patch_openai
import openai

patch_openai(agent_id="my-agent")

# All subsequent openai.chat.completions.create calls are automatically captured
response = openai.chat.completions.create(model="gpt-4o", messages=[...])
```

## What gets captured

| Field | Evidence |
|-------|----------|
| `model` | model name (request + response) |
| `usage.prompt_tokens` | prompt token count |
| `usage.completion_tokens` | completion token count |
| `usage.total_tokens` | total tokens |
| `choices[0].message.tool_calls` | tool call names (not arguments) |
| `choices[0].finish_reason` | stop reason |
| `choices[0].message.content` | output length (not content itself) |
| `temperature`, `max_tokens` | request parameters |

For streaming, evidence is emitted after all chunks are consumed (`event=stream_complete`). Content is reconstructed from delta chunks.

## Cleanup

```python
from ancilis_openai import unpatch_openai

unpatch_openai()  # Restores original openai.chat.completions.create
```

## Safety

- Engine errors never propagate — evidence capture can never break your application
- No API keys or credentials are stored in evidence
- Output content is not stored — only `output_length`

## Compatibility

- openai: `>=1.0.0`
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
