#!/bin/sh
# compliance-check.sh — Generic Ancilis compliance scan for any CI/CD platform
#
# Usage:
#   ./compliance-check.sh [OPTIONS]
#
# Options (override via environment variables):
#   ANCILIS_CONFIG   Path to ancilis.yaml  (default: ./ancilis.yaml)
#   ANCILIS_DB       Path to evidence DB   (default: ./ancilis-evidence.duckdb)
#   ANCILIS_PERIOD   Evidence window        (default: 24h)
#   ANCILIS_SESSION  Scope to session ID    (default: unset — all sessions)
#   ANCILIS_OUTPUT   JSON output file       (default: ancilis-scan.json)
#
# Exit codes (propagated from ancilis scan):
#   0 = compliant
#   1 = non-compliant (violations found)
#   2 = configuration error
#
# POSIX-compatible: runs under both sh and bash.
# Verified with shellcheck (shellcheck compliance-check.sh).

set -e

# ── Configuration ─────────────────────────────────────────────────────────────
ANCILIS_CONFIG="${ANCILIS_CONFIG:-./ancilis.yaml}"
ANCILIS_DB="${ANCILIS_DB:-./ancilis-evidence.duckdb}"
ANCILIS_PERIOD="${ANCILIS_PERIOD:-24h}"
ANCILIS_OUTPUT="${ANCILIS_OUTPUT:-ancilis-scan.json}"

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { printf '[ancilis] %s\n' "$*" >&2; }
fail() { printf '[ancilis] ERROR: %s\n' "$*" >&2; exit 2; }

# ── Verify or install ancilis ─────────────────────────────────────────────────
if ! command -v ancilis >/dev/null 2>&1; then
    log "ancilis not found — installing via pip..."
    if ! command -v pip >/dev/null 2>&1 && ! command -v pip3 >/dev/null 2>&1; then
        fail "pip is not available. Install Python 3.10+ and pip first."
    fi
    PIP=$(command -v pip3 || command -v pip)
    "$PIP" install --quiet ancilis || fail "pip install ancilis failed."
    log "ancilis installed successfully."
fi

ANCILIS_VERSION=$(ancilis --version 2>&1 || echo "unknown")
log "Using $ANCILIS_VERSION"

# ── Validate config ───────────────────────────────────────────────────────────
if [ ! -f "$ANCILIS_CONFIG" ]; then
    fail "Config file not found: $ANCILIS_CONFIG (set ANCILIS_CONFIG to override)"
fi

# ── Build scan arguments ──────────────────────────────────────────────────────
SCAN_ARGS="--ci --config $ANCILIS_CONFIG --db $ANCILIS_DB --period $ANCILIS_PERIOD"

if [ -n "${ANCILIS_SESSION:-}" ]; then
    SCAN_ARGS="$SCAN_ARGS --session $ANCILIS_SESSION"
fi

# ── Run scan ──────────────────────────────────────────────────────────────────
log "Running: ancilis scan $SCAN_ARGS"
log "Output file: $ANCILIS_OUTPUT"

# Capture both the JSON output and the exit code.
# `set -e` is intentionally bypassed here so we can inspect the exit code.
set +e
# shellcheck disable=SC2086
ancilis scan $SCAN_ARGS > "$ANCILIS_OUTPUT" 2>&1
SCAN_EXIT=$?
set -e

# ── Parse and display results ─────────────────────────────────────────────────
if [ -f "$ANCILIS_OUTPUT" ] && command -v python3 >/dev/null 2>&1; then
    python3 - "$ANCILIS_OUTPUT" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception as e:
    print(f"[ancilis] Could not parse {path}: {e}", file=sys.stderr)
    sys.exit(0)

s = d.get("summary", {})
posture = d.get("posture", "unknown").upper()
icon = "PASS" if posture == "COMPLIANT" else "FAIL"

print(f"\n{'='*60}")
print(f"  Ancilis Compliance Scan — {icon}")
print(f"{'='*60}")
print(f"  Agent  : {d.get('agent', 'n/a')}")
print(f"  Mode   : {d.get('mode', 'n/a')}")
print(f"  Posture: {posture}")
print(f"  Time   : {d.get('timestamp', 'n/a')}")
print(f"{'='*60}")
print(f"  Controls: {s.get('passing',0)} pass  {s.get('failing',0)} fail  {s.get('skipped',0)} skip")
print(f"  Evaluations: {s.get('total_evaluations',0)} total")
print()

for c in d.get("controls", []):
    marker = "✓" if c["status"] == "pass" else ("✗" if c["status"] == "fail" else "–")
    line = f"  {marker}  {c['id']:<8}  {c['name']:<40}"
    if c["evaluations"] > 0:
        line += f"  evals={c['evaluations']}  fail={c['failures']}"
        if c["flags"] > 0:
            line += f"  flags={c['flags']}"
    else:
        line += "  (no evidence)"
    print(line)

print(f"{'='*60}\n")
PYEOF
else
    # Minimal fallback if python3 is unavailable
    log "Scan complete. Results in $ANCILIS_OUTPUT"
fi

# ── Handle exit codes ─────────────────────────────────────────────────────────
case $SCAN_EXIT in
    0)
        log "Result: COMPLIANT — all controls pass."
        ;;
    1)
        log "Result: NON-COMPLIANT — violations detected. See $ANCILIS_OUTPUT for details."
        ;;
    2)
        log "Result: CONFIG ERROR — check $ANCILIS_CONFIG and $ANCILIS_DB paths."
        ;;
    *)
        log "Result: unexpected exit code $SCAN_EXIT"
        ;;
esac

exit $SCAN_EXIT
