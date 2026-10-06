#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
claim="${1:-all}"
if [[ $# -gt 0 ]]; then
  shift
fi

exec bash "$ROOT/artifact/StructRisk/artifact_2026/verify_paper_claims.sh" \
  "$claim" \
  --output-dir "$ROOT/reproduced/$claim" \
  "$@"
