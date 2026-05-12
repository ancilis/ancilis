# ancilis-llamaindex

LlamaIndex integration for [Ancilis](https://ancilis.ai) — automatic evidence capture via the instrumentation event handler protocol.

## Install

```bash
pip install ancilis-llamaindex
```

## Quickstart

```python
from llama_index.core.instrumentation import get_dispatcher
from ancilis_llamaindex import AncilisEventHandler

handler = AncilisEventHandler(agent_id="my-agent")
get_dispatcher().add_event_handler(handler)
# All LLM, embedding, retrieval, agent-tool and query events are now captured.
```

## What gets captured

| Event class | Action type | Tool name |
|-------------|-------------|-----------|
| `LLMCompletionStart/EndEvent`, `LLMChatStart/EndEvent` | `tool_call` | `llama_index:llm:<model>` |
| `EmbeddingStart/EndEvent` | `data_access` | `llama_index:embedding:<model>` |
| `RetrievalStart/EndEvent` | `data_access` | `llama_index:retrieval:<name>` |
| `AgentToolCallEvent` | `tool_call` | `llama_index:tool:<tool_name>` |
| `QueryStart/EndEvent` | `tool_call` | `llama_index:query:<name>` |

Token usage (from `response.raw`), model name and error type are captured when present. Span/parent IDs are propagated as `parent_action_id`.

## Configuration

`AncilisEventHandler` accepts optional `engine` and `evidence_store`. If both are `None`, the handler runs in observe-only mode (`captured_actions` available for inspection).

## Compatibility

- LlamaIndex: `llama-index-core>=0.11.0`
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
