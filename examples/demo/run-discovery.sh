#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFEST_PATH="${SDK_ROOT}/examples/demo/discovery/discovery-manifest.json"
BACKEND_URL="${ANCILIS_DEMO_BACKEND_URL:-http://localhost:8000}"
DASHBOARD_URL="${ANCILIS_DEMO_DASHBOARD_URL:-http://localhost:3000}"
DISCOVERY_URL="${DASHBOARD_URL}/discovery"
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
        log "Stopping discovery demo stack..."
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

manifest_agents() {
    python3 - <<'PY' "${MANIFEST_PATH}"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

for agent in manifest.get("agents", []):
    print(json.dumps(agent, separators=(",", ":")))
PY
}

agent_field() {
    local field="$1"
    python3 -c 'import json, sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "${field}"
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

build_discovery_integration_name() {
    local agent_name="$1"
    local db_path="$2"
    python3 -c '
import sys

from ancilis.demo_orchestration import build_demo_integration_name

print(
    build_demo_integration_name(
        sys.argv[2],
        base_name=f"Discovery Demo SDK - {sys.argv[1]}",
    )
)
' "${agent_name}" "${db_path}"
}

build_discovery_integration_payload() {
    local agent_name="$1"
    local db_path="$2"
    python3 -c '
import json
import sys

from ancilis.demo_orchestration import build_demo_integration_payload

name = f"Discovery Demo SDK - {sys.argv[1]}"
payload = build_demo_integration_payload(
    sys.argv[2],
    name=name,
)
print(json.dumps(payload, separators=(",", ":")))
' "${agent_name}" "${db_path}"
}

build_discovery_agent_payload() {
    local integration_id="$1"
    python3 -c '
import json
import sys

agent = json.load(sys.stdin)
payload = {
    "agent_name": agent["name"],
    "runtime_type": agent["runtime_type"],
    "description": agent.get("description", ""),
    "tool_count": agent["tool_count"],
    "data_types": agent.get("data_types", []),
    "classifications": agent.get("classifications", []),
    "active_overlays": agent.get("active_overlays", []),
    "active_certifications": agent.get("active_certifications", []),
    "posture_summary": agent["evidence_summary"],
    "config_path": agent["config_path"],
    "db_path": agent["db_path"],
    "evidence_source_id": sys.argv[1],
}
print(json.dumps(payload, separators=(",", ":")))
' "${integration_id}"
}

maybe_open_browser() {
    if [ "${ANCILIS_DEMO_OPEN_BROWSER:-1}" != "1" ]; then
        return
    fi

    if command -v open >/dev/null 2>&1; then
        open "${DISCOVERY_URL}" >/dev/null 2>&1 || true
        return
    fi

    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${DISCOVERY_URL}" >/dev/null 2>&1 || true
    fi
}

require_cmd python3
require_cmd curl
if [ "${SKIP_STACK_START}" != "1" ]; then
    require_cmd docker
    require_docker_daemon || fail "Docker daemon is not reachable. Start Docker Desktop or your local Docker service."
    PLATFORM_DIR="$(resolve_platform_dir)"
fi

log "╔══════════════════════════════════════════════════════╗"
log "║            Ancilis Discovery Demo Orchestration     ║"
log "║     SDK -> Multi-Agent Evidence -> Discovery UI     ║"
log "╚══════════════════════════════════════════════════════╝"

step "1/5" "Preparing the SDK demo environment"
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

step "2/5" "Generating discovery evidence stores"
python examples/demo/run-discovery.py
[ -f "${MANIFEST_PATH}" ] || fail "Expected discovery manifest was not created at ${MANIFEST_PATH}"
log "  Discovery manifest: ${MANIFEST_PATH}"

if [ "${SKIP_STACK_START}" = "1" ]; then
    step "3/5" "Reusing an existing Platform stack"
    log "  Reusing existing Platform stack at ${BACKEND_URL} / ${DASHBOARD_URL}"
else
    step "3/5" "Starting the Platform stack"
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

step "4/5" "Registering discovery demo integrations and syncing evidence"
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

DISCOVERY_SESSION_RESPONSE="$(
    curl -fsS \
        -X POST \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"name":"Ancilis Discovery Demo","source":"sdk_demo"}' \
        "${BACKEND_URL}/v1/discovery/sessions"
)"
DISCOVERY_SESSION_ID="$(printf '%s' "${DISCOVERY_SESSION_RESPONSE}" | extract_json_field id)"
[ -n "${DISCOVERY_SESSION_ID}" ] || fail "Discovery session creation did not return an id."

while IFS= read -r agent_json; do
    [ -n "${agent_json}" ] || continue

    agent_name="$(printf '%s' "${agent_json}" | agent_field name)"
    db_path="$(printf '%s' "${agent_json}" | agent_field db_path)"
    integration_name="$(build_discovery_integration_name "${agent_name}" "${db_path}")"
    integration_id="$(printf '%s' "${INTEGRATIONS_RESPONSE}" | find_existing_integration_id "${integration_name}")"

    if [ -z "${integration_id}" ]; then
        create_payload="$(build_discovery_integration_payload "${agent_name}" "${db_path}")"
        create_response="$(
            curl -fsS \
                -X POST \
                -H "Authorization: Bearer ${AUTH_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "${create_payload}" \
                "${BACKEND_URL}/v1/integrations"
        )"
        integration_id="$(printf '%s' "${create_response}" | extract_json_field id)"
    fi

    [ -n "${integration_id}" ] || fail "Could not determine the integration id for ${agent_name}."

    sync_response="$(
        curl -fsS \
            -X POST \
            -H "Authorization: Bearer ${AUTH_TOKEN}" \
            "${BACKEND_URL}/v1/integrations/${integration_id}/sync"
    )"
    sync_created="$(printf '%s' "${sync_response}" | extract_json_field evidence_created)"
    sync_deduped="$(printf '%s' "${sync_response}" | extract_json_field evidence_deduplicated)"

    register_payload="$(printf '%s' "${agent_json}" | build_discovery_agent_payload "${integration_id}")"
    curl -fsS \
        -X POST \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${register_payload}" \
        "${BACKEND_URL}/v1/discovery/sessions/${DISCOVERY_SESSION_ID}/agents" \
        >/dev/null

    log "  ${agent_name}: synced integration ${integration_id} (created=${sync_created:-0}, deduped=${sync_deduped:-0})"
done < <(manifest_agents)

step "5/5" "Opening the discovery dashboard"
log "  Discovery session: ${DISCOVERY_SESSION_ID}"
log "  Dashboard: ${DISCOVERY_URL}"
log "  Backend docs: ${BACKEND_URL}/docs"
log "  Login: admin@ancilis.demo / AncilisDemo123!"
if [ "${STACK_STARTED}" = true ]; then
    log "Press Ctrl+C to stop the Platform stack."
else
    log "Press Ctrl+C to exit without stopping the reused Platform stack."
fi

maybe_open_browser

while [ "${KEEP_RUNNING}" = true ]; do
    sleep 1
done
