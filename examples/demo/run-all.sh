#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKEND_URL="${ANCILIS_DEMO_BACKEND_URL:-http://localhost:8000}"
DASHBOARD_URL="${ANCILIS_DEMO_DASHBOARD_URL:-http://localhost:3000}"
SKIP_STACK_START="${ANCILIS_DEMO_SKIP_STACK_START:-0}"
KEEP_RUNNING=true
STACK_STARTED=false

log() {
    printf '%s\n' "$*"
}

step() {
    printf '\n[%s] %s\n' "$1" "$2"
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

require_docker_daemon() {
    python3 -c 'import subprocess, sys
try:
    subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=True,
    )
except Exception:
    sys.exit(1)
'
}

cleanup() {
    if [ "${STACK_STARTED}" = true ]; then
        log
        log "Stopping demo stack..."
        (
            cd "${PLATFORM_DIR}"
            docker compose down >/dev/null 2>&1 || true
        )
    fi
}

on_interrupt() {
    KEEP_RUNNING=false
}

trap on_interrupt INT TERM
trap cleanup EXIT

resolve_platform_dir() {
    if [ -n "${ANCILIS_PLATFORM_DIR:-}" ]; then
        if [ -f "${ANCILIS_PLATFORM_DIR}/docker-compose.yml" ]; then
            printf '%s\n' "${ANCILIS_PLATFORM_DIR}"
            return
        fi
        if [ -f "${ANCILIS_PLATFORM_DIR}/platform/docker-compose.yml" ]; then
            printf '%s\n' "${ANCILIS_PLATFORM_DIR}/platform"
            return
        fi
        fail "ANCILIS_PLATFORM_DIR must point to the platform directory or its repo root."
    fi

    if [ -f "${SDK_ROOT}/platform/docker-compose.yml" ]; then
        printf '%s\n' "${SDK_ROOT}/platform"
        return
    fi

    if [ -f "${SDK_ROOT}/../ancilis-one-shot/platform/docker-compose.yml" ]; then
        printf '%s\n' "${SDK_ROOT}/../ancilis-one-shot/platform"
        return
    fi

    fail "Could not find the Platform checkout. Set ANCILIS_PLATFORM_DIR to the platform directory."
}

wait_for_url() {
    local url="$1"
    local label="$2"
    local attempts="${3:-120}"
    local delay="${4:-2}"
    local count=1

    until curl -fsS "${url}" >/dev/null 2>&1; do
        if [ "${count}" -ge "${attempts}" ]; then
            fail "${label} did not become ready at ${url}"
        fi
        sleep "${delay}"
        count=$((count + 1))
    done
}

extract_json_field() {
    local field="$1"
    python3 -c 'import json, sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "${field}"
}

build_demo_db_path() {
    python3 - <<'PY'
from pathlib import Path

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore

config = load_config(path=Path("examples/demo/ancilis.yaml"))
store = EvidenceStore(config, in_memory=False)
print(store.db_path)
PY
}

find_existing_integration_id() {
    python3 -c '
import json
import sys

target = sys.argv[1]
payload = json.load(sys.stdin)
for item in payload.get("items", []):
    if item.get("name") == target:
        print(item["id"])
        break
' "$1"
}

build_demo_integration_name() {
    local db_path="$1"
    python3 -c '
import sys

from ancilis.demo_orchestration import build_demo_integration_name

print(build_demo_integration_name(sys.argv[1]))
' "${db_path}"
}

build_integration_payload() {
    local db_path="$1"
    python3 -c '
import json
import sys

from ancilis.demo_orchestration import build_demo_integration_payload

payload = build_demo_integration_payload(sys.argv[1])
print(json.dumps(payload, separators=(",", ":")))
' "${db_path}"
}

maybe_open_browser() {
    if [ "${ANCILIS_DEMO_OPEN_BROWSER:-1}" != "1" ]; then
        return
    fi

    if command -v open >/dev/null 2>&1; then
        open "${DASHBOARD_URL}" >/dev/null 2>&1 || true
        return
    fi

    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${DASHBOARD_URL}" >/dev/null 2>&1 || true
    fi
}

# --- Pre-flight checks ---
# shellcheck source=preflight.sh
source "${SCRIPT_DIR}/preflight.sh"
check_python_version
check_command curl
if [ "${SKIP_STACK_START}" != "1" ]; then
    check_docker_running
    check_platform_checkout "${SDK_ROOT}"
    PLATFORM_DIR="$(resolve_platform_dir)"
fi

log "╔══════════════════════════════════════════════════════╗"
log "║              Ancilis End-to-End Demo                ║"
log "║        SDK -> Evidence -> Platform -> Dashboard     ║"
log "╚══════════════════════════════════════════════════════╝"

step "1/4" "Preparing the SDK demo environment"
cd "${SDK_ROOT}"
export TMPDIR="${SCRIPT_DIR}"
export TMP="${TMPDIR}"
export TEMP="${TMPDIR}"

if [ ! -d ".demo-venv" ]; then
    python3 -m venv .demo-venv
fi

# shellcheck disable=SC1091
source .demo-venv/bin/activate
python -m pip install -e ".[dev]" --quiet
log "  Python environment ready"

DEMO_DB_PATH="$(build_demo_db_path)"
rm -f "${DEMO_DB_PATH}"

step "2/4" "Running the financial demo agent"
DEMO_LOG="$(mktemp)"
python examples/demo/run.py | tee "${DEMO_LOG}"
DEMO_DB_PATH="$(sed -n 's/^Evidence stored at: //p' "${DEMO_LOG}" | tail -n 1)"
rm -f "${DEMO_LOG}"
[ -n "${DEMO_DB_PATH}" ] || fail "Could not determine the generated evidence database path."
[ -f "${DEMO_DB_PATH}" ] || fail "Expected evidence database was not created at ${DEMO_DB_PATH}"
DEMO_NAME="$(build_demo_integration_name "${DEMO_DB_PATH}")"
log "  Evidence generated at ${DEMO_DB_PATH}"
log "  Integration name: ${DEMO_NAME}"

if [ "${SKIP_STACK_START}" = "1" ]; then
    step "3/4" "Reusing an existing Platform stack"
    log "  Reusing existing Platform stack at ${BACKEND_URL} / ${DASHBOARD_URL}"
else
    step "3/4" "Starting the Platform stack"
    (
        cd "${PLATFORM_DIR}"
        docker compose up --build -d
    )
    STACK_STARTED=true
fi
wait_for_url "${BACKEND_URL}/health" "Backend API"
wait_for_url "${DASHBOARD_URL}" "Dashboard"
log "  Platform API ready at ${BACKEND_URL}"
log "  Dashboard ready at ${DASHBOARD_URL}"

step "4/4" "Registering the SDK evidence source and syncing it into the Platform"
LOGIN_RESPONSE="$(
    curl -fsS \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"org_slug":"ancilis-demo","email":"admin@ancilis.demo","password":"AncilisDemo123!"}' \
        "${BACKEND_URL}/v1/auth/login"
)"
AUTH_TOKEN="$(printf '%s' "${LOGIN_RESPONSE}" | extract_json_field access_token)"
[ -n "${AUTH_TOKEN}" ] || fail "Platform login did not return an access token."

INTEGRATIONS_RESPONSE="$(
    curl -fsS \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        "${BACKEND_URL}/v1/integrations"
)"
INTEGRATION_ID="$(printf '%s' "${INTEGRATIONS_RESPONSE}" | find_existing_integration_id "${DEMO_NAME}")"

if [ -z "${INTEGRATION_ID}" ]; then
    CREATE_PAYLOAD="$(build_integration_payload "${DEMO_DB_PATH}")"
    CREATE_RESPONSE="$(
        curl -fsS \
            -X POST \
            -H "Authorization: Bearer ${AUTH_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${CREATE_PAYLOAD}" \
            "${BACKEND_URL}/v1/integrations"
    )"
    INTEGRATION_ID="$(printf '%s' "${CREATE_RESPONSE}" | extract_json_field id)"
fi

[ -n "${INTEGRATION_ID}" ] || fail "Could not determine the demo integration id."

SYNC_RESPONSE="$(
    curl -fsS \
        -X POST \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        "${BACKEND_URL}/v1/integrations/${INTEGRATION_ID}/sync"
)"
SYNC_CREATED="$(printf '%s' "${SYNC_RESPONSE}" | extract_json_field evidence_created)"
SYNC_DEDUPED="$(printf '%s' "${SYNC_RESPONSE}" | extract_json_field evidence_deduplicated)"
log "  Synced integration ${INTEGRATION_ID}"
log "  Evidence created: ${SYNC_CREATED:-0}"
log "  Evidence deduplicated: ${SYNC_DEDUPED:-0}"

log
log "Demo is live."
log "  Dashboard: ${DASHBOARD_URL}"
log "  Backend docs: ${BACKEND_URL}/docs"
log "  Login: admin@ancilis.demo / AncilisDemo123!"
log "  Integration: ${DEMO_NAME}"
if [ "${STACK_STARTED}" = true ]; then
    log "Press Ctrl+C to stop the Platform stack."
else
    log "Press Ctrl+C to exit without stopping the reused Platform stack."
fi

maybe_open_browser

while [ "${KEEP_RUNNING}" = true ]; do
    sleep 1
done
