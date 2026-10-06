#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import sys
major, minor = sys.version_info[:2]
if (major, minor) < (3, 10):
    raise SystemExit(f"Python >= 3.10 required, found {major}.{minor}")
print(f"Python OK: {major}.{minor}")
PY

test -d artifact/StructRisk/generated
test -f artifact/StructRisk/artifact_2026/run_quick_check.sh
test -f artifact/StructRisk/artifact_2026/verify_paper_claims.py
test -f artifact/StructRisk/artifact_2026/PAPER_CLAIMS.json
test -f artifact/StructRisk/generated/phase1_offline_manual_ranked.jsonl
test -f artifact/StructRisk/generated/magma_unified_crash_backed_findings.jsonl
test -f verify_paper_claims.sh
test -f ARTIFACT_VERSION.txt

echo "StructRisk artifact environment check passed."
echo "No network access, API keys, Docker, or LaTeX are required for quick checks."
