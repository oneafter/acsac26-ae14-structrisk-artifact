#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
claim="${1:-all}"
if [[ $# -gt 0 ]]; then
  shift
fi

exec python3 "$SCRIPT_DIR/verify_paper_claims.py" --claim "$claim" "$@"
