#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

export PATH="$REPO_ROOT/.venv/bin:$PATH"
export PYTHONPATH="$REPO_ROOT/python/src:${PYTHONPATH:-}"
export ANCILIS_TELEMETRY_DISABLE_PROMPT=1
export DO_NOT_TRACK=1

for bin in asciinema agg ffmpeg ffprobe python ancilis; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing required command: $bin" >&2
    exit 1
  fi
done

cd "$SCRIPT_DIR"
rm -f /tmp/ancilis_sdk_demo.cast /tmp/ancilis_sdk_demo.gif /tmp/ancilis_sdk_demo.mp4

asciinema rec /tmp/ancilis_sdk_demo.cast -c "python run_demo.py" --overwrite
agg /tmp/ancilis_sdk_demo.cast /tmp/ancilis_sdk_demo.gif --font-size 14
ffmpeg -i /tmp/ancilis_sdk_demo.gif \
  -movflags faststart -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  /tmp/ancilis_sdk_demo.mp4 -y

ffprobe -v error -show_entries format=duration,format_name,size \
  -of default=noprint_wrappers=1 /tmp/ancilis_sdk_demo.mp4
