# ancilis-autogen

AutoGen integration for [Ancilis](https://ancilis.ai) — zero-config conversation evidence capture.

## Version Support

Targets **pyautogen >= 0.2.0** (the `pyautogen` package). Uses `register_reply()` hooks for non-intrusive instrumentation.

AutoGen 0.4+ (`autogen-agentchat`) has a different API. Support for 0.4+ will be added in a future release.

## Install

```bash
pip install ancilis-autogen
```

## Quickstart

```python
from ancilis_autogen import AncilisConversationLogger

logger = AncilisConversationLogger(agent_id="my-pipeline")

# Single agent
logger.attach(assistant)

# All agents in a GroupChatManager
logger.attach_all(groupchat_manager)

# Optional: emit final summary
logger.log_conversation_end(turn_count=10, reason="task_complete")
```

## What gets captured

| Event | Evidence |
|-------|----------|
| `message` | sender, recipient, role, content length (not content), message_index |
| `function_call` | function name, args preview (512 chars), args length |
| `function_result` | function name, result length |
| `conversation_end` | turn count, termination reason |

Content is never stored — only `content_length`. Function args truncated at 512 chars.

## How it works

`attach(agent)` calls `agent.register_reply()` with a logging hook at position 0. The hook:
1. Observes the latest message
2. Emits evidence via Ancilis
3. Returns `(False, None)` — never intercepts the normal reply pipeline

The agent behaves exactly as before.

## Safety

- Evidence capture errors never propagate
- No message content stored (only lengths)
- Compatible with `ancilis-langchain` if both installed

## Compatibility

- pyautogen: `>=0.2.0`
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
