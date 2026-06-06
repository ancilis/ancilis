"""Sample scan script templates per agent framework.

Every template renders to a script that runs end-to-end against the real SDK
API: it loads ancilis.yaml, wraps a sample tool with ``ToolActionProducer``,
evaluates one call, and prints the evidence summary. Mirrors the known-good
examples/minimal-quickstart/main.py pattern so `ancilis init` never emits a
script that crashes on import.
"""

from __future__ import annotations

# Plain (non-f) string template with sentinel tokens so the embedded Python —
# which legitimately uses {} and f-strings — needs no brace escaping.
_TEMPLATE = '''\
"""Sample Ancilis scan for __FRAMEWORK_LABEL__.

Run from this directory (after `ancilis init` created ancilis.yaml):
    python ancilis_scan.py

This wraps a sample tool with Ancilis, evaluates one call, and prints the
resulting evidence summary. Replace `lookup` with your agent's real tools and
wrap each one with `producer.wrap_tool(...)`.
"""
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config()
engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)


# __FRAMEWORK_COMMENT__
def lookup(query: str) -> dict:
    """A sample tool. Replace with your agent's real tool."""
    return {"results": ["result for " + query]}


lookup = producer.wrap_tool(lookup, tool_name="lookup")

print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print()

result = lookup("example query")
print(f"lookup -> {result}")

summary = evidence.get_summary(session_id=producer.session_id)
print(
    f"\\nEvidence: {summary['total_evaluations']} record(s) this run, "
    f"chain {'intact' if summary['chain_valid'] else 'BROKEN'}"
)
print("\\nRun `ancilis status` to see your full compliance posture.")

evidence.close()
'''


_FRAMEWORK_COMMENTS: dict[str, tuple[str, str]] = {
    "langchain": (
        "a LangChain agent",
        "Wrap each tool function your LangChain agent calls with producer.wrap_tool "
        "so Ancilis evaluates and records every call.",
    ),
    "crewai": (
        "a CrewAI agent",
        "Wrap the tools your CrewAI crew members call so Ancilis evaluates each "
        "tool call.",
    ),
    "autogen": (
        "an AutoGen agent",
        "Wrap the tools registered with your AutoGen agents so Ancilis evaluates "
        "each call in the conversation loop.",
    ),
    "openai": (
        "an OpenAI agent",
        "Wrap the Python functions backing your OpenAI function/tool calls so "
        "Ancilis evaluates each invocation.",
    ),
    "generic": (
        "a custom agent",
        "Wrap any Python callable your agent uses so Ancilis evaluates and records "
        "each call.",
    ),
}


def _render(framework: str) -> str:
    label, comment = _FRAMEWORK_COMMENTS[framework]
    return _TEMPLATE.replace("__FRAMEWORK_LABEL__", label).replace(
        "__FRAMEWORK_COMMENT__", comment
    )


_TEMPLATES: dict[str, str] = {fw: _render(fw) for fw in _FRAMEWORK_COMMENTS}


def get_scan_script(framework: str) -> str:
    """Return the sample scan script for the given framework name."""
    return _TEMPLATES.get(framework, _TEMPLATES["generic"])
