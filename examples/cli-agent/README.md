# CLI Agent Example

Evaluate shell commands before execution. Block dangerous operations.

## What this demonstrates

Your agent runs shell commands — kubectl, curl, file operations. The CLIActionProducer wraps subprocess execution with the same policy evaluation that MCP middleware uses.

1. Allowed commands (`echo`, `date`, `ls`) execute normally
2. Blocked commands (`rm`, `curl`) are intercepted before execution
3. Every evaluation produces a hash-chained evidence record
4. Output scanning detects sensitive patterns in command output

## Prerequisites

```bash
pip install ancilis
```

## Run

```bash
cd examples/cli-agent
python run.py
```

## Config

```yaml
agent:
  name: ops-agent
security:
  mode: enforce
  tools:
    allowed:
      - echo
      - date
      - ls
      - cat
    blocked:
      - rm
      - curl
```

## Expected output

```
=== CLI Agent Example ===
Agent: ops-agent
Mode: enforce
Allowed: ['echo', 'date', 'ls', 'cat']
Blocked: ['rm', 'curl']

1. Running 'echo hello world' (allowed)...
   stdout: hello world
   Decision: ALLOW
   Blocked: False

2. Running 'date' (allowed)...
   stdout: Sat Mar 21 00:38:37 UTC 2026
   Decision: ALLOW

3. Running 'ls -la' (allowed)...
   stdout (first 3 lines):
     total 16
     ...
   Decision: ALLOW

4. Running 'rm -rf /tmp/test' (blocked)...
   Blocked: True
   Decision: BLOCK
   stdout: None

5. Running 'curl https://example.com' (blocked)...
   Blocked: True
   Decision: BLOCK

=== Evidence Summary ===
  Records: 5
  Decisions: {'ALLOW': 3, 'BLOCK': 2}
  Tools: ['cli:curl', 'cli:date', 'cli:echo', 'cli:ls', 'cli:rm']
  Hash chain: intact

Done. Shell commands evaluated against policy. Blocked before execution.
```

## What happened

- CLIActionProducer translates shell commands to Action objects
- Tool names are prefixed with `cli:` (e.g., `cli:echo`, `cli:rm`)
- Scope matching handles the prefix — bare `echo` in config matches `cli:echo`
- Blocked commands never execute — the subprocess is never called
- Tool provenance hashes include the resolved binary path and version
