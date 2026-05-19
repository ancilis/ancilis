# Ancilis SDK E2E Demo

This demo records a deterministic LangChain-core agent using the Ancilis Python
SDK production path:

1. `LangChainCallbackHandler`
2. `LangChainActionProducer`
3. `Engine`
4. PR-04 runtime classification
5. DuckDB `EvidenceStore`
6. `ancilis evidence` and `ancilis certify` CLI inspection

The LLM is a local stub that emits LangChain callback events. The Ancilis
middleware, engine, classification, controls, and evidence store are not mocked.

## Run

```bash
cd python/examples/demo_sdk_e2e
./record.sh
```

The script writes:

- `/tmp/ancilis_sdk_demo.cast`
- `/tmp/ancilis_sdk_demo.gif`
- `/tmp/ancilis_sdk_demo.mp4`

The local demo evidence database is regenerated on each run:

```bash
python run_demo.py
ancilis evidence list --limit 10 --db ./demo_evidence.duckdb
ancilis certify --target soc2 --db ./demo_evidence.duckdb
```

## Scenarios

- Benign customer record: no runtime classification.
- PII customer record: detects `DC-PII`.
- Cardholder-data customer record: detects `DC-CHD`, the AKSI class that places
  card data in PCI-DSS scope.
