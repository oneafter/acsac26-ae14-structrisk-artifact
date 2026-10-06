#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BOOTSTRAP_ROUNDS="${BOOTSTRAP_ROUNDS:-20000}"
SEED="${SEED:-1337}"
RUN_CASR="${RUN_CASR:-0}"
RUN_SIGNIFICANCE="${RUN_SIGNIFICANCE:-0}"
RUN_WEIGHT_SENSITIVITY="${RUN_WEIGHT_SENSITIVITY:-0}"
REBUILD_PHASE1_SPLIT="${REBUILD_PHASE1_SPLIT:-0}"

echo "[1/11] Rebuilding processed phase-1 findings"
if [[ "$REBUILD_PHASE1_SPLIT" == "1" ]]; then
  python3 StructRisk/scripts/phase1_offline_experiment.py
else
  test -f StructRisk/generated/phase1_offline_eval.jsonl
  test -f StructRisk/generated/phase1_offline_dev.jsonl
  echo "Using shipped canonical phase-1 split (set REBUILD_PHASE1_SPLIT=1 to rebuild from the artifact index)."
fi

echo "[2/11] Rebuilding public and crash-side baselines"
python3 StructRisk/scripts/phase1_public_baseline.py
python3 StructRisk/scripts/phase1_artifact_baseline.py
python3 StructRisk/scripts/phase1_crash_baselines.py
python3 StructRisk/scripts/phase1_report_knn_baseline.py
python3 StructRisk/scripts/phase1_support_count_baseline.py

echo "[3/11] Rebuilding StructRisk fixed ranking"
python3 StructRisk/scripts/structrisk_rank.py \
  --mode manual \
  --input StructRisk/generated/phase1_offline_eval.jsonl \
  --output StructRisk/generated/phase1_offline_manual_ranked.jsonl \
  --weights-out StructRisk/generated/phase1_offline_manual_weights.json \
  --metrics-out StructRisk/generated/phase1_offline_manual_metrics.json

echo "[4/11] Rebuilding LLM-CardScore from shipped responses"
python3 StructRisk/scripts/phase1_llm_card_baseline.py \
  --mode responses \
  --eval StructRisk/generated/phase1_offline_eval.jsonl \
  --responses StructRisk/generated/phase1_llm_card_responses_clean.jsonl \
  --ranked-out StructRisk/generated/phase1_offline_llm_card_ranked.jsonl \
  --metrics-out StructRisk/generated/phase1_offline_llm_card_metrics.json \
  --summary-out StructRisk/generated/phase1_offline_llm_card_summary.md

echo "[5/11] Rebuilding StructRisk+LLM-LCR"
python3 StructRisk/scripts/phase1_local_tie_resolution.py \
  --base StructRisk/generated/phase1_offline_manual_ranked.jsonl \
  --llm-card StructRisk/generated/phase1_offline_llm_card_ranked.jsonl \
  --output StructRisk/generated/phase1_offline_llm_lcr_ranked.jsonl \
  --metrics-out StructRisk/generated/phase1_offline_llm_lcr_metrics.json \
  --summary-out StructRisk/generated/phase1_offline_llm_lcr_summary.md

echo "[6/11] Rebuilding ablation and sensitivity outputs"
python3 StructRisk/scripts/phase1_ablation.py \
  --eval StructRisk/generated/phase1_offline_eval.jsonl \
  --weights StructRisk/generated/phase1_offline_manual_weights.json \
  --json-out StructRisk/generated/phase1_ablation.json \
  --md-out StructRisk/generated/phase1_ablation.md
if [[ "$RUN_WEIGHT_SENSITIVITY" == "1" ]]; then
  python3 StructRisk/scripts/phase1_weight_sensitivity.py
else
  test -f StructRisk/generated/phase1_weight_sensitivity.json
  test -f StructRisk/generated/phase1_weight_sensitivity.md
  echo "Using shipped weight-sensitivity envelope (set RUN_WEIGHT_SENSITIVITY=1 to recompute)."
fi

echo "[7/11] Rebuilding within-project summary"
python3 StructRisk/scripts/phase1_local_tie_resolution.py \
  --base StructRisk/generated/phase1_within10_manual_ranked.jsonl \
  --llm-card StructRisk/generated/phase1_within10_llm_card_ranked.jsonl \
  --output StructRisk/generated/phase1_within10_llm_lcr_ranked.jsonl \
  --metrics-out StructRisk/generated/phase1_within10_llm_lcr_metrics.json \
  --summary-out StructRisk/generated/phase1_within10_llm_lcr_summary.md
python3 StructRisk/scripts/phase1_within_project_eval.py
python3 StructRisk/scripts/phase1_within_project_eval.py \
  --project binaryen \
  --project openbabel \
  --project squirrel \
  --project wabt \
  --project xlnt \
  --json-out StructRisk/generated/phase1_within_evalonly_metrics.json \
  --csv-out StructRisk/generated/phase1_within_evalonly_metrics.csv \
  --md-out StructRisk/generated/phase1_within_evalonly_metrics.md

echo "[8/11] Rebuilding significance summary"
if [[ "$RUN_SIGNIFICANCE" == "1" ]]; then
  python3 StructRisk/scripts/phase1_significance.py --bootstrap-rounds "$BOOTSTRAP_ROUNDS" --seed "$SEED"
  python3 StructRisk/scripts/phase1_within_project_significance.py --bootstrap-rounds "$BOOTSTRAP_ROUNDS" --seed "$SEED"
  python3 StructRisk/scripts/phase1_within_project_significance.py \
    --project binaryen \
    --project openbabel \
    --project squirrel \
    --project wabt \
    --project xlnt \
    --bootstrap-rounds "$BOOTSTRAP_ROUNDS" \
    --seed "$SEED" \
    --json-out StructRisk/generated/phase1_within_evalonly_significance.json \
    --md-out StructRisk/generated/phase1_within_evalonly_significance.md
else
  test -f StructRisk/generated/phase1_offline_significance.json
  test -f StructRisk/generated/phase1_offline_significance.md
  test -f StructRisk/generated/phase1_within_project_significance.json
  test -f StructRisk/generated/phase1_within_project_significance.md
  test -f StructRisk/generated/phase1_within_evalonly_significance.json
  test -f StructRisk/generated/phase1_within_evalonly_significance.md
  echo "Using shipped significance outputs (set RUN_SIGNIFICANCE=1 to recompute)."
fi

echo "[9/11] Rebuilding MAGMA crash-backed validation"
if [[ -f StructRisk/generated/magma_local_crash_backed_enriched_artifacts.jsonl && \
      -f StructRisk/generated/magma_poc49_crash_backed_enriched_artifacts.jsonl ]]; then
  python3 StructRisk/scripts/magma_unified_crash_backed_slice.py
else
  test -f StructRisk/generated/magma_unified_crash_backed_findings.jsonl
  echo "Using shipped unified MAGMA evidence-card slice (component replay artifacts not bundled)."
fi
python3 StructRisk/scripts/magma_crash_backed_benchmark.py \
  --input StructRisk/generated/magma_unified_crash_backed_findings.jsonl \
  --out-prefix StructRisk/generated/magma_unified_crash_backed_external
python3 StructRisk/scripts/magma_inventory_audit.py

echo "[10/11] Optionally rebuilding CASR-Severity baseline"
if [[ "$RUN_CASR" == "1" && -d "StructRisk/StructRisk_src_full/src" ]]; then
  python3 StructRisk/scripts/phase1_casr_baseline.py
else
  echo "Skipping CASR rerun (set RUN_CASR=1 and provide StructRisk/StructRisk_src_full/src to enable)."
fi

echo "[11/11] Checking canonical outputs"
test -f StructRisk/generated/phase1_offline_significance.md
test -f StructRisk/generated/phase1_within_project_metrics.md
test -f StructRisk/generated/phase1_ablation.md
test -f StructRisk/generated/phase1_weight_sensitivity.md
test -f StructRisk/generated/magma_unified_crash_backed_external_summary.md
test -f StructRisk/generated/magma_inventory_audit.md

echo "Full offline reproduction completed. Key outputs:"
echo "  StructRisk/generated/phase1_offline_significance.md"
echo "  StructRisk/generated/phase1_within_project_metrics.md"
echo "  StructRisk/generated/phase1_ablation.md"
echo "  StructRisk/generated/phase1_weight_sensitivity.md"
echo "  StructRisk/generated/magma_unified_crash_backed_external_summary.md"
echo "  StructRisk/generated/magma_inventory_audit.md"
