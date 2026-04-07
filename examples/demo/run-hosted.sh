#!/usr/bin/env bash
# Hosted demo: SDK evidence → Railway platform → dashboard
#
# Runs the financial demo agent locally, authenticates with the hosted
# Ancilis Platform, uploads the evidence records, and opens the dashboard.
# No Docker required.
#
# Usage:
#   bash examples/demo/run-hosted.sh
#   # or
#   make demo-hosted
#
# Environment variables (all optional):
#   ANCILIS_HOSTED_URL    Platform base URL (default: production Railway URL)
#   ANCILIS_DEMO_EMAIL    Login email       (default: demo@ancilis.dev)
#   ANCILIS_DEMO_PASSWORD Login password    (default: demo123)
#   ANCILIS_DEMO_OPEN_BROWSER  Set to 0 to skip opening the browser (default: 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

HOSTED_URL="${ANCILIS_HOSTED_URL:-https://ancilis-one-shot-production.up.railway.app}"
DEMO_EMAIL="${ANCILIS_DEMO_EMAIL:-demo@ancilis.dev}"
DEMO_PASSWORD="${ANCILIS_DEMO_PASSWORD:-demo123}"

_START_TS="$(date +%s)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '%s\n' "$*"; }
step() { printf '\n[%s] %s\n' "$1" "$2"; }
fail() { printf '\033[31mError: %s\033[0m\n' "$*" >&2; exit 1; }

extract_json_field() {
    python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"
}

maybe_open_browser() {
    [ "${ANCILIS_DEMO_OPEN_BROWSER:-1}" = "1" ] || return 0
    if command -v open >/dev/null 2>&1; then
        open "${HOSTED_URL}" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${HOSTED_URL}" >/dev/null 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

step "preflight" "Checking dependencies"

# Reuse shared checks (Python version, curl) — skip Docker
# shellcheck source=preflight.sh
source "${SCRIPT_DIR}/preflight.sh"
check_python_version
check_command curl

# ancilis importable?
python3 -c "import ancilis" 2>/dev/null \
    || fail "ancilis not found. Run: pip install ancilis  (or: pip install -e .)"

# Hosted URL reachable?
if ! curl -fsS --max-time 10 "${HOSTED_URL}/health" >/dev/null 2>&1; then
    fail "Hosted platform unreachable at ${HOSTED_URL}. Check ANCILIS_HOSTED_URL or network."
fi
log "  Platform reachable: ${HOSTED_URL}"

# ---------------------------------------------------------------------------
# Step 1: Run the financial demo
# ---------------------------------------------------------------------------

step "1/3" "Running the financial demo agent"

cd "${SDK_ROOT}"

DEMO_LOG="$(mktemp)"
trap 'rm -f "${DEMO_LOG}"' EXIT

python3 examples/demo/run.py | tee "${DEMO_LOG}"

DB_PATH="$(grep -o 'Evidence stored at: .*' "${DEMO_LOG}" | tail -1 | sed 's/Evidence stored at: //')"
[ -n "${DB_PATH}" ] || fail "Could not determine evidence DB path from run.py output."
[ -f "${DB_PATH}" ]  || fail "Expected evidence DB not found at: ${DB_PATH}"

log "  Evidence DB: ${DB_PATH}"

# ---------------------------------------------------------------------------
# Step 2: Authenticate with the hosted platform
# ---------------------------------------------------------------------------

step "2/3" "Authenticating with hosted platform"

LOGIN_BODY="$(python3 -c "
import json, sys
print(json.dumps({'email': sys.argv[1], 'password': sys.argv[2]}))
" "${DEMO_EMAIL}" "${DEMO_PASSWORD}")"

LOGIN_RESPONSE="$(
    curl -fsS \
        -X POST \
        -H "Content-Type: application/json" \
        -d "${LOGIN_BODY}" \
        "${HOSTED_URL}/v1/auth/login" 2>&1
)" || fail "Login request failed. Check ANCILIS_DEMO_EMAIL / ANCILIS_DEMO_PASSWORD."

AUTH_TOKEN="$(printf '%s' "${LOGIN_RESPONSE}" | extract_json_field access_token)"
[ -n "${AUTH_TOKEN}" ] || fail "Login succeeded but no access_token returned. Response: ${LOGIN_RESPONSE}"

log "  Authenticated as ${DEMO_EMAIL}"

# ---------------------------------------------------------------------------
# Step 3: Upload evidence records
# ---------------------------------------------------------------------------

step "3/3" "Uploading evidence to hosted platform"

python3 "${SCRIPT_DIR}/upload_evidence.py" \
    --db-path "${DB_PATH}" \
    --api-url "${HOSTED_URL}" \
    --auth-token "${AUTH_TOKEN}"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

_END_TS="$(date +%s)"
_ELAPSED=$(( _END_TS - _START_TS ))

log
log "╔══════════════════════════════════════════════════════╗"
log "║              Ancilis Hosted Demo — Done             ║"
log "╚══════════════════════════════════════════════════════╝"
log "  Dashboard : ${HOSTED_URL}"
log "  Elapsed   : ${_ELAPSED}s"
log

maybe_open_browser
