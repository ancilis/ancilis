#!/usr/bin/env bash
# Local demo: SDK scan → DuckDB evidence → embedded evidence viewer
#
# Runs the financial demo agent, then serves the evidence via a lightweight
# local HTTP server with a single-page dashboard. No Docker, no PostgreSQL,
# no external services required.
#
# Usage:
#   bash examples/demo/run-local.sh
#   # or
#   make demo-local
#
# Environment variables (all optional):
#   ANCILIS_DEMO_PORT          Port for the local evidence server (default: 8100)
#   ANCILIS_DEMO_OPEN_BROWSER  Set to 0 to skip opening the browser (default: 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DEMO_PORT="${ANCILIS_DEMO_PORT:-8100}"
VENV_DIR="${SCRIPT_DIR}/.demo-venv"

_START_TS="$(date +%s)"
_SERVER_PID=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '%s\n' "$*"; }
step() { printf '\n[%s] %s\n' "$1" "$2"; }
fail() { printf '\033[31mError: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
    if [ -n "${_SERVER_PID}" ] && kill -0 "${_SERVER_PID}" 2>/dev/null; then
        kill "${_SERVER_PID}" 2>/dev/null || true
        wait "${_SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

maybe_open_browser() {
    [ "${ANCILIS_DEMO_OPEN_BROWSER:-1}" = "1" ] || return 0
    local url="http://127.0.0.1:${DEMO_PORT}"
    if command -v open >/dev/null 2>&1; then
        open "${url}" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${url}" >/dev/null 2>&1 || true
    fi
}

wait_for_health() {
    local url="http://127.0.0.1:${DEMO_PORT}/health"
    local attempts=20
    local i=0
    while [ $i -lt $attempts ]; do
        if python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('${url}', timeout=1)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        i=$(( i + 1 ))
    done
    fail "Server did not start within 10 seconds."
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

step "preflight" "Checking dependencies"

# shellcheck source=preflight.sh
source "${SCRIPT_DIR}/preflight.sh"
check_python_version

# Ensure ancilis is importable; install into a demo venv if needed
if ! python3 -c "import ancilis" 2>/dev/null; then
    log "  ancilis not found — installing into ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"
    pip install -q -e "${SDK_ROOT}[dev]"
    log "  ancilis installed"
elif [ -f "${VENV_DIR}/bin/activate" ]; then
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"
fi

python3 -c "import ancilis; print(f'  ancilis {ancilis.__version__}')" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 1: Run the demo agent (generates evidence)
# ---------------------------------------------------------------------------

step "1/3" "Running the Ancilis demo agent"

cd "${SDK_ROOT}"

DEMO_LOG="$(mktemp /tmp/ancilis-demo-run.XXXXXX)"

# Run the demo; tee output so user can see it, capture for DB path extraction
python3 examples/demo/run.py 2>&1 | tee "${DEMO_LOG}"

DB_PATH="$(grep -o 'Evidence stored at: .*' "${DEMO_LOG}" | tail -1 | sed 's/Evidence stored at: //')"
[ -n "${DB_PATH}" ] || fail "Could not determine evidence DB path from run.py output."
[ -f "${DB_PATH}" ]  || fail "Expected evidence DB not found at: ${DB_PATH}"
rm -f "${DEMO_LOG}"

log "  Evidence DB: ${DB_PATH}"

# ---------------------------------------------------------------------------
# Step 2: Start the local evidence server
# ---------------------------------------------------------------------------

step "2/3" "Starting local evidence server on port ${DEMO_PORT}"

# Kill anything already on the port (makes re-runs idempotent)
if python3 -c "
import socket
s = socket.socket()
s.settimeout(0.5)
r = s.connect_ex(('127.0.0.1', ${DEMO_PORT}))
s.close()
exit(0 if r == 0 else 1)
" 2>/dev/null; then
    log "  Port ${DEMO_PORT} already in use — freeing it"
    lsof -ti tcp:"${DEMO_PORT}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 1
fi

python3 "${SCRIPT_DIR}/local_server.py" \
    --db-path "${DB_PATH}" \
    --port "${DEMO_PORT}" \
    > /tmp/ancilis-server.log 2>&1 &
_SERVER_PID=$!

wait_for_health
log "  Server running at http://127.0.0.1:${DEMO_PORT} (PID ${_SERVER_PID})"

# ---------------------------------------------------------------------------
# Step 3: Open browser, print summary, wait
# ---------------------------------------------------------------------------

step "3/3" "Opening dashboard"

maybe_open_browser

_END_TS="$(date +%s)"
_ELAPSED=$(( _END_TS - _START_TS ))

log
log "╔══════════════════════════════════════════════════════╗"
log "║            Ancilis Local Demo — Running             ║"
log "╚══════════════════════════════════════════════════════╝"
log "  Dashboard    : http://127.0.0.1:${DEMO_PORT}"
log "  Evidence DB  : ${DB_PATH}"
log "  Elapsed      : ${_ELAPSED}s"
log
log "  Press Ctrl+C to stop the server."
log

# Keep server alive until user interrupts
wait "${_SERVER_PID}" || true
