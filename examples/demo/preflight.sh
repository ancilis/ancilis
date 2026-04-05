#!/usr/bin/env bash
# Shared pre-flight validation for Ancilis demo scripts.
# Source this file; then call the check_* functions you need.

_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[0;33m'
_NC='\033[0m'

_pass() { printf "${_GREEN}✓ %s${_NC}\n" "$*"; }
_fail() { printf "${_RED}✗ %s${_NC}\n" "$*"; }
_hint() { printf "  ${_YELLOW}→ %s${_NC}\n" "$*"; }

check_python_version() {
    local required_major=3
    local required_minor=10

    if ! command -v python3 >/dev/null 2>&1; then
        _fail "Python 3 not found"
        _hint "Install Python 3.10+: https://www.python.org/downloads/"
        exit 1
    fi

    local version
    version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    local major minor
    major="${version%%.*}"
    minor="${version#*.}"

    if [ "${major}" -lt "${required_major}" ] || { [ "${major}" -eq "${required_major}" ] && [ "${minor}" -lt "${required_minor}" ]; }; then
        _fail "Python ${version} found — 3.10+ required"
        _hint "Install Python 3.10+: https://www.python.org/downloads/"
        exit 1
    fi

    _pass "Python ${version}"
}

check_docker_running() {
    if ! command -v docker >/dev/null 2>&1; then
        _fail "Docker not found"
        _hint "Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
        exit 1
    fi

    if ! python3 -c '
import subprocess, sys
try:
    subprocess.run(["docker","info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
except Exception:
    sys.exit(1)
' 2>/dev/null; then
        _fail "Docker daemon is not running"
        _hint "Start Docker Desktop and wait for it to finish loading, then re-run this script."
        exit 1
    fi

    _pass "Docker is running"
}

check_platform_checkout() {
    local sdk_root="${1:?sdk_root required}"

    if [ -n "${ANCILIS_PLATFORM_DIR:-}" ]; then
        if [ -f "${ANCILIS_PLATFORM_DIR}/docker-compose.yml" ] || [ -f "${ANCILIS_PLATFORM_DIR}/platform/docker-compose.yml" ]; then
            _pass "Platform checkout (ANCILIS_PLATFORM_DIR)"
            return
        fi
        _fail "ANCILIS_PLATFORM_DIR is set but no docker-compose.yml found"
        _hint "Set ANCILIS_PLATFORM_DIR to the platform directory containing docker-compose.yml."
        exit 1
    fi

    if [ -f "${sdk_root}/platform/docker-compose.yml" ]; then
        _pass "Platform checkout (${sdk_root}/platform)"
        return
    fi

    if [ -f "${sdk_root}/../ancilis-one-shot/platform/docker-compose.yml" ]; then
        _pass "Platform checkout (ancilis-one-shot/platform)"
        return
    fi

    _fail "Platform checkout not found"
    _hint "Clone the platform repo next to the SDK, or set ANCILIS_PLATFORM_DIR."
    _hint "  git clone <platform-repo> ../ancilis-one-shot   # or"
    _hint "  export ANCILIS_PLATFORM_DIR=/path/to/platform"
    exit 1
}

check_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        _fail "${cmd} not found"
        _hint "Install ${cmd} and make sure it is on your PATH."
        exit 1
    fi
    _pass "${cmd} available"
}
