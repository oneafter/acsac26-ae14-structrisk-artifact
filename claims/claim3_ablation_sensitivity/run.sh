#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
bash "$ROOT/verify_paper_claims.sh" ablation
# Signal-constant perturbation audit (rebuttal addition): perturbs every
# hand-set signal-extraction constant by +/-20% with theta fixed; recomputes
# StructRisk/generated/phase1_signal_constant_sensitivity.{json,md} and checks
# the within-project envelope stated in the author response.
cd "$ROOT/artifact"
python3 StructRisk/scripts/phase1_signal_constant_sensitivity.py
python3 - <<'PYEOF'
import json
payload = json.load(open('StructRisk/generated/phase1_signal_constant_sensitivity.json'))
env = payload['envelope']
assert payload['variant_count'] == 58, payload['variant_count']
assert env['wp_NDCG@5']['min'] >= 0.8473 and env['wp_NDCG@5']['max'] <= 0.8622, env['wp_NDCG@5']
assert env['wp_MAP']['min'] >= 0.8012 and env['wp_MAP']['max'] <= 0.8250, env['wp_MAP']
assert env['global_NDCG@10']['min'] >= 0.6988 and env['global_NDCG@10']['max'] <= 0.8572, env['global_NDCG@10']
print('PASS: signal-constant audit envelope matches the author-response statement')
PYEOF
