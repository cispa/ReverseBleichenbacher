#!/bin/bash
set -euo pipefail

# Validate required environment variables
: "${TARGET_RANGE:?TARGET_RANGE must be specified}"
: "${SCAN_PORT:?SCAN_PORT must be specified}"
: "${SCAN_RATE:?SCAN_RATE must be specified}"
: "${RESULTS_FILE:?RESULTS_FILE must be specified}"

# BANDWIDTH is optional
BANDWIDTH="${BANDWIDTH:-}"

mkdir -p "$(dirname "$RESULTS_FILE")"

cmd=(zmap -p "$SCAN_PORT" --rate "$SCAN_RATE" --output-fields=saddr --output-module=csv)
if [[ -n "$BANDWIDTH" ]]; then
  cmd+=("--bandwidth" "$BANDWIDTH")
fi
cmd+=("$TARGET_RANGE")

echo "[zmap-scanner] Running: ${cmd[*]}"

"${cmd[@]}" | ztee "$RESULTS_FILE" | python /app/push_to_redis.py
