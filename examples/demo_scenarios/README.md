# Demo Scenarios

Generate five realistic AI agent evidence streams for the acquirer demo.

```bash
python examples/demo_scenarios/run_demo.py
python examples/demo_scenarios/run_demo.py --fast
```

The script writes a local DuckDB evidence store and an NDJSON export using the same local export path as:

```bash
ancilis export --format ndjson --since 2026-04-15T09:00:00Z --db ~/.ancilis/demo-scenarios/evidence.duckdb
```

To sync into the Platform through the SDK Direct integration path:

```bash
export ANCILIS_PLATFORM_URL=https://ancilis-one-shot-production.up.railway.app
export ANCILIS_API_KEY=<platform bearer token or API key>
python examples/demo_scenarios/run_demo.py --push
```

Included agents:

- `patient_intake_agent`: MCP, PHI and PII, HIPAA/GDPR/CCPA/SOC 2
- `payment_processor`: Bedrock-style HTTP, cardholder data and PII, PCI-DSS/GDPR/CCPA/SOC 2
- `code_review_agent`: framework tool calls, general business data and trade secrets, SOC 2
- `hr_onboarding_bot`: HTTP workflow, PII, GDPR/CCPA/SOC 2
- `data_pipeline_agent`: CLI workflow, CUI and financial records, CMMC/GLBA/SOC 2
