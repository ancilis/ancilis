# Cover MCP gap assessment demo

This demo exercises the unified `ancilis-cover` MCP server without requiring an MCP host. It creates the real FastMCP server, lists its tools, and calls `ancilis_assess_gap` against a small sample healthcare agent project.

Run from the repository root:

```bash
PYTHONPATH=python/src python examples/cover-mcp-gap-assessment/run.py
```

Recorded output is available in `docs/demo-recordings/cover-mcp-gap-assessment.mp4`, with `.cast` and `.txt` variants beside it. The recording reflects the pre-v0.3 AKSI catalog state; rerun this demo after the v0.3 catalog migration to refresh displayed control counts.

Expected result:

- `ancilis_assess_gap` maps "patient records" and "HIPAA" to Ancilis targets.
- The sample project is flagged as missing `health_records` and `hipaa` config entries.
- The sample project is flagged as needing OpenAI producer instrumentation.
- Evidence coverage is reported as a setup gap because no runtime evidence session exists yet.
