#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/../reproduced/quick}"
BOOTSTRAP_ROUNDS="${BOOTSTRAP_ROUNDS:-20000}"
RUN_SIGNIFICANCE="${RUN_SIGNIFICANCE:-0}"

args=(--claim all --output-dir "$OUTPUT_DIR")
if [[ "$RUN_SIGNIFICANCE" == "1" ]]; then
  args+=(--full-statistics --bootstrap-rounds "$BOOTSTRAP_ROUNDS")
fi

exec python3 "$SCRIPT_DIR/verify_paper_claims.py" "${args[@]}"
