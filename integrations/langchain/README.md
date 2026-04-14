# ancilis-langchain

LangChain integration for [Ancilis](https://ancilis.ai) — automatic evidence capture via `CallbackHandler`.

## Install

```bash
pip install ancilis-langchain
```

## Quickstart

```python
from ancilis_langchain import AncilisCallbackHandler

handler = AncilisCallbackHandler(agent_id="my-agent")
result = chain.invoke({"question": "..."}, config={"callbacks": [handler]})
```

That's it. Ancilis automatically captures LLM calls, tool invocations, chain I/O, and retriever queries as cryptographically chained evidence.

## What gets captured

| Callback | Evidence |
|----------|----------|
| `on_llm_start` | model name, prompt count, char count |
| `on_llm_end` | token usage (prompt/completion/total), model name |
| `on_tool_start` | tool name, input (capped at 512 chars) |
| `on_tool_end` | output length |
| `on_chain_start` | chain type, input key names |
| `on_chain_end` | output key names |
| `on_retriever_start` | query (capped at 512 chars) |
| `on_retriever_end` | document count, source/page metadata (no content) |
| Error callbacks | event type, error message |

Parent/child run IDs are preserved across all events, allowing full chain run tree reconstruction.

## Privacy

Retriever document **content** is never stored in evidence — only `source`, `page`, `chunk_id`, and `doc_id` metadata fields are captured.

## Configuration

`AncilisCallbackHandler` reads config from `ancilis.yaml` / `ANCILIS_*` env vars automatically. No new config format.

## Compatibility

- LangChain: `langchain-core>=0.2.0` (LCEL, agents, retrieval chains, v0.2.x and v0.3.x)
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
