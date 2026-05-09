"""LangChain Chatbot + Ancilis SOC 2 compliance monitoring.

Demonstrates the LangChain-native callback handler. Drop a
``LangChainCallbackHandler`` into the ``callbacks=[]`` array of any LangChain
Runnable, Chain, or LLM and every llm/chat_model/tool/chain start emits an
evaluated, evidence-recorded Action. The same handler covers LangGraph
because it forwards through the shared LangChain callback bus.

This example does not require ``langchain`` to be installed — the handler
is duck-typed against ``BaseCallbackHandler`` and we drive it directly with
LangChain-shape arguments. Add ``callbacks=[handler]`` to a real LangChain
construct and the same observations are produced for free.

Run from this directory:

    python main.py
    ancilis status            # see SOC 2 posture

Prerequisites:

    pip install -r requirements.txt
"""

from pathlib import Path
from uuid import uuid4

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers import LangChainActionProducer, LangChainCallbackHandler

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config)

producer = LangChainActionProducer(config=config, engine=engine, evidence_store=evidence)
handler = LangChainCallbackHandler(producer, agent_name=config.agent_name)

print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"Active overlays: {sorted((config.active_overlays or {}).keys())}")
print()

# --- How you'd wire this with real LangChain ---
#
#     from langchain_openai import ChatOpenAI
#     from langchain_core.tools import tool
#
#     @tool
#     def search_web(query: str) -> dict:
#         ...
#
#     llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
#     # llm.invoke(...) → handler.on_chat_model_start fires → Action recorded
#
# Below we drive the handler directly so the example runs without an LLM
# key. The shape of arguments matches what LangChain passes its callbacks.

CONVERSATIONS = [
    {
        "user": "What are the SOC 2 monitoring requirements for AI agents?",
        "kind": "chat_model",
        "name": "ChatOpenAI",
        "messages": [["HumanMessage(content='What are the SOC 2 monitoring requirements for AI agents?')"]],
    },
    {
        "user": "Search the web for SOC 2 audit log requirements.",
        "kind": "tool",
        "name": "search_web",
        "input": "SOC 2 audit log requirements",
    },
    {
        "user": "If we need 99.9% uptime, how many minutes of downtime per year?",
        "kind": "tool",
        "name": "calculator",
        "input": "365 * 24 * 60 * (1 - 0.999)",
    },
    {
        "user": "Summarize the findings.",
        "kind": "chain",
        "name": "RunnableSequence",
        "inputs": {"question": "Summarize the findings."},
    },
    {
        "user": "What does NIST AI RMF say about runtime policy?",
        "kind": "chat_model",
        "name": "ChatOpenAI",
        "messages": [["HumanMessage(content='What does NIST AI RMF say about runtime policy?')"]],
    },
]

print("=== Simulated LangChain agent conversation (driving handler directly) ===\n")

for i, turn in enumerate(CONVERSATIONS, 1):
    print(f"[Turn {i}] User: {turn['user']}")
    run_id = uuid4()
    if turn["kind"] == "chat_model":
        handler.on_chat_model_start({"name": turn["name"]}, turn["messages"], run_id=run_id)
        print(f"  → on_chat_model_start({turn['name']!r})")
    elif turn["kind"] == "tool":
        handler.on_tool_start({"name": turn["name"]}, turn["input"], run_id=run_id)
        print(f"  → on_tool_start({turn['name']!r}, {turn['input']!r})")
    elif turn["kind"] == "chain":
        handler.on_chain_start({"name": turn["name"]}, turn["inputs"], run_id=run_id)
        print(f"  → on_chain_start({turn['name']!r})")
    print()

# --- Evidence summary (filtered to this producer's run) ---
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Run `ancilis status` to see SOC 2 posture.")

evidence.close()
