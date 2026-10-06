# Anonymous Artifact Package for `StructRisk`

This directory provides reviewer-facing scripts for exercising the `StructRisk` artifact for ACSAC 2026 submission #154. The maintenance version is recorded in `ARTIFACT_VERSION.txt`; `PAPER_CLAIMS.json` contains the expected values transcribed from the submitted PDF.

## Scope

The package is designed to support four reproducibility goals without requiring network access or live LLM/API calls:

- Rebuild the paper's main evaluation tables from prepared ranked outputs.
- Re-run the offline ranking pipeline from the prepared main-evaluation artifact index and shipped responses.
- Audit the anonymized LLM prompts/responses and the replay-based CASR comparator reports.
- Re-run the MAGMA crash-backed validation from shipped finding-level MAGMA slices and cached CVSS records.

The full repository additionally contains broader MAGMA reconstruction utilities, but the anonymous reviewer package is centered on the shipped unified crash-backed MAGMA slice over 49 deduplicated findings across nine projects. The shipped MAGMA inventory audit covers 138 bug records and 125 distinct CVEs, with 84 HIGH-or-CRITICAL CVEs under the preferred NVD CVSS, plus a project-level inventory-versus-slice coverage table for the unified crash-backed slice.

The anonymous package is centered on processed main-evaluation artifacts rather than on re-fuzzing third-party projects from scratch.

## What Is Included

- `StructRisk/scripts/`: all ranking, baseline, significance, and helper scripts used in the paper.
- `StructRisk/generated/phase1_artifact_index.jsonl`: processed main-evaluation artifact index. The `phase1_*` prefix is an internal historical name.
- `StructRisk/generated/phase1_offline_*.jsonl|json|md`: ranked outputs, metrics, and summaries for the reported baselines.
- `StructRisk/generated/phase1_within_project_metrics.*`: within-project evaluation outputs.
- `StructRisk/generated/phase1_within_evalonly_metrics.*` and `StructRisk/generated/phase1_within_evalonly_significance.*`: held-out Eval-only within-project sanity-check outputs over the five positive multi-finding evaluation projects.
- `StructRisk/generated/phase1_offline_significance.*`: bootstrap/permutation significance outputs.
- `StructRisk/generated/phase1_ablation.*`: feature ablation outputs.
- `StructRisk/artifact_2026/verify_paper_claims.py`: non-destructive Table 3--6 verifier that writes regenerated outputs under `StructRisk/reproduced/`.
- `StructRisk/artifact_2026/PAPER_CLAIMS.json`: exact submitted-PDF values used as verification expectations.
- `StructRisk/artifact_2026/REPRODUCIBILITY_STATUS.md`: recomputed-versus-cached scope matrix.
- `StructRisk/generated/phase1_llm_card_*.jsonl`, `StructRisk/generated/phase1_offline_llm_lcr_*`, and `StructRisk/generated/phase1_within10_llm_lcr_*`: anonymized LLM-card prompts/responses plus deterministic local tie-resolution audit outputs.
- `StructRisk/generated/phase1_casr_reports/`: CASR reports, stderr logs, and timeout records for the replay-based comparator.
- `StructRisk/user75_cve_summary.csv` and `StructRisk/user75_cve_tables.md`: anonymized CVE provenance tables covering CVE IDs, projects, CVSS/CNA/NVD status, and disclosure status.
- `StructRisk/generated/high_risk_disclosure_alignment.*` and `StructRisk/generated/high_risk_disclosures_summary.md`: alignment summaries for the disclosure-backed HIGH cases; direct public issue/advisory URLs are redacted in the double-blind package and can be restored for the non-anonymous release.
- `StructRisk/external/magma/` and `StructRisk/generated/magma*_*.{json,jsonl,csv,md}`: the MAGMA inventory audit inputs plus crash-backed MAGMA findings, ranked outputs, summaries, and project-level coverage tables.
The package includes processed data and cached outputs rather than raw fuzzing
campaigns or full third-party corpora.

## What Is Not Included

- The full third-party source mirror under `StructRisk/StructRisk_src_full/`.
- Raw fuzzing campaigns and original third-party corpora.
- The larger MAGMA rebuild-and-replay environments and the 1.9GB public PoC archives.
- Any live API keys, model credentials, or author-identifying metadata.

This omission is intentional for compactness, licensing hygiene, and anonymous review. The shipped processed benchmark, ranked outputs, prompts/responses, CASR reports, and MAGMA evidence-card slices are sufficient to audit the reported results.

## Requirements

Core reproduction uses only the Python standard library.

- `Python >= 3.10`
- `bash`

Optional dependencies:

- Docker is only relevant if you attempt to re-run replay-based CASR or MAGMA rebuild steps from original environments; it is not required for the shipped anonymous package quick check.

## Quick Start

From the artifact directory, run the non-destructive verifier:

```bash
bash StructRisk/artifact_2026/run_quick_check.sh
```

This quick path writes only under `StructRisk/reproduced/quick/`; it does not overwrite shipped canonical outputs. It:

- recomputes the global rankings from the shipped Eval findings (except cached CASR replay),
- recomputes the within-project metrics and exact project-block p-values,
- recomputes the ablation summary,
- rebuilds LLM-CardScore from shipped anonymized responses and then deterministically derives LLM-LCR with source-site novelty for tied card scores,
- rebuilds the unified crash-backed MAGMA validation summary from shipped findings,
- checks all regenerated values against Tables 3--6 of the submitted PDF.

`run_quick_check.sh` defaults to a reviewer-friendly check and therefore uses the canonical global significance output while independently recomputing the faster within-project exact tests. Set `RUN_SIGNIFICANCE=1` for the full global permutation/bootstrap rerun.

The shipped LLM-CardScore responses were generated with a fixed `gpt-5.4` configuration using the `xhigh` reasoning setting. The anonymous artifact supports deterministic replay from these cached responses rather than live regeneration against a future closed-model version.

To force a significance rerun from the shipped ranked outputs, use:

```bash
RUN_SIGNIFICANCE=1 BOOTSTRAP_ROUNDS=20000 bash StructRisk/artifact_2026/run_quick_check.sh
```

For the complete end-to-end offline rerun, use `run_full_offline.sh`.

Individual claim scopes are also available:

```bash
bash StructRisk/artifact_2026/verify_paper_claims.sh global
bash StructRisk/artifact_2026/verify_paper_claims.sh within
bash StructRisk/artifact_2026/verify_paper_claims.sh ablation
bash StructRisk/artifact_2026/verify_paper_claims.sh magma
```

## Full Offline Reproduction

To rerun the non-network pipeline from the shipped canonical main-evaluation split:

```bash
BOOTSTRAP_ROUNDS=20000 bash StructRisk/artifact_2026/run_full_offline.sh
```

This script performs the following steps:

1. Verifies the shipped canonical main-evaluation split by default; set `REBUILD_PHASE1_SPLIT=1` only if you want to regenerate exploratory split files from `phase1_artifact_index.jsonl`.
2. Re-runs the public, artifact, support-count, crash-state, report-kNN, CASR, and StructRisk baselines.
3. Re-runs the LLM baselines from shipped anonymized responses and the cached LCR base ranking.
4. Recomputes ablations, within-project evaluation, and the crash-backed MAGMA validation outputs; shipped significance outputs are reused unless `RUN_SIGNIFICANCE=1` is set.

The CASR replay baseline is skipped by default because the anonymous package does not bundle the full third-party source mirror. To force a CASR rerun in a local environment that has the required source tree and replay dependencies, set:

```bash
RUN_CASR=1 bash StructRisk/artifact_2026/run_full_offline.sh
```

## Signal-Constant Perturbation Audit (author-response addition)

`StructRisk/scripts/phase1_signal_constant_sensitivity.py` complements the
77-variant theta perturbation study by perturbing every hand-set constant of
the signal-extraction rules themselves (base replay/locality/sanitizer/weak
rules one-at-a-time and at all 16 corners; every derived-rule constant of
EvidenceUniq, FailureSem, the weak gate, and the support-stability bonus) by
+/-20%, with theta fixed at the shipped prior. It recomputes global metrics on
the held-out split and tie-aware within-project metrics over the ten positive
multi-finding projects, and reports stability envelopes only — no variant is
selected against any label. Run:

```bash
python3 StructRisk/scripts/phase1_signal_constant_sensitivity.py
```

Outputs: `StructRisk/generated/phase1_signal_constant_sensitivity.{json,md}`.
The maintenance packaging removes the unused experimental `--mode calibrated`
option from `structrisk_rank.py`; no reported number ever used it. The shipped
`phase1_offline_manual_weights.json` records `mode: "frozen"` with a
provenance note: the three-tier structure and sign constraints are
domain-informed, and the tier weights theta were set manually from domain
experience; the signal-rule constants were calibrated by scripted search on
the 5-project development split (its artifacts and labels); every value was
frozen before any evaluation project was scored. The weight values themselves
are unchanged.

## Theta Optimality Check (author-response addition)

`StructRisk/scripts/phase1_theta_optimality.py` grid-searches 31,104
sign-preserving theta assignments and shows the paper theta is the grid
optimum on no slice: 7,944 grid points beat it on the Dev within-project
objective (74.5th percentile), 7,098 on the Eval within-project objective
(77.2nd), and 8,776 on the combined within-project objective over all ten
positive multi-finding projects, the Table 4 slice (71.8th). The Dev-optimal
theta degrades on Eval (global NDCG@10 0.8522 -> 0.6969), illustrating why
theta was not fitted. Output:
`StructRisk/generated/phase1_theta_optimality.json`.

## Constant Provenance Check (author-response addition)

`StructRisk/scripts/phase1_constant_eval_tuning_check.py` runs a two-sided
unclaimed-headroom check over the 17 hand-tunable signal-rule constants: the
same kind of scripted coordinate search as the original calibration, once
against the Dev objective (the disclosed calibration target) and once against
the Eval objectives, starting from the shipped constants. Against Dev the
search finds zero headroom (no constant moves -- the shipped constants are a
converged point of their own calibration target); against Eval it immediately
finds headroom (within-project NDCG@5 0.8981 -> 0.9104, global NDCG@10 0.8522
-> 0.8553, by moving 2 constants) that an Eval calibration would have
captured. Together: calibrated on Dev, not tuned on Eval. The check is a
like-for-like reconstruction for auditing; the original calibration script is
not part of this reviewer package. Output:
`StructRisk/generated/phase1_constant_eval_tuning_check.json`.

## Constant LOPO Check (author-response addition)

`StructRisk/scripts/phase1_constant_lopo_check.py` applies to the signal-rule
constants the same leave-one-project-out discipline the paper applies to
StackDedup-kNN: for each Dev project, the like-for-like calibration search is
rerun on the remaining Dev projects and the held-out project is scored under
the fold's constants. Every fold moves zero constants, so LOPO scoring equals
shipped scoring on all ten within-project targets and the macro metrics
(NDCG@5 0.8561, MAP 0.8167) and exact tests vs Public-Severity are unchanged.
Output: `StructRisk/generated/phase1_constant_lopo_check.json`.

## Evidence-View Sensitivity Analysis (author-response addition, for Reviewer C)

`StructRisk/scripts/phase1_view_ablation.py` runs a deterministic
post-consolidation sensitivity analysis over the five card views: true
leave-one-view-out (masking a view's fields and recomputing every affected
base and derived signal), single-view cards, and coarse two-group cards, with
findings, labels, split, and the frozen scorer fixed. Before evaluating any
variant it asserts the unmasked ranking is byte-identical to the canonical
StructRisk order. Headline results: among the tested single-view and coarse-group
alternatives, the full card is strongest across all three scopes (global,
ten-project within-project, Eval-only), while leave-one-view-out effects are
heterogeneous (removing Code raises the within-project point estimates);
removing Replay collapses global NDCG@10 0.8522 -> 0.3254;
removing Input/provenance causes the largest within-project loss
(0.8561/0.8167 -> 0.7897/0.7451 NDCG@5/MAP); Sanitizer is the strongest
single-view local proxy (0.8174/0.7801); Stack has zero marginal ranking
effect after consolidation. Outputs:
`StructRisk/generated/phase1_view_ablation.{json,md}`; the full analysis
report is `StructRisk/generated/phase1_view_ablation_report.md`.

## Main Claims Covered

The package is intended to support reviewer verification of the following paper claims:

- Global ranking results in the primary held-out evaluation table.
- Within-project ranking results and the associated macro metrics.
- Bootstrap/permutation significance summary.
- Fixed-scorer ablation study.
- Leakage-controlled LLM evaluation using anonymous prompts, manifests, and shipped responses.
- Replay-based CASR comparator auditability through ranked outputs and released CASR reports.
- MAGMA crash-backed validation and full-inventory MAGMA severity audit.

## Key Output Files

After running the scripts above, the main files to inspect are:

- `StructRisk/generated/phase1_offline_significance.md`
- `StructRisk/generated/phase1_within_project_metrics.md`
- `StructRisk/generated/phase1_within_core_significance.md` (structured core vs baselines, no LLM)
- `StructRisk/generated/phase1_ablation.md` (structured-core ablation)
- `StructRisk/generated/phase1_signal_constant_sensitivity.md` (signal-constant perturbation audit)
- `StructRisk/generated/phase1_offline_manual_metrics.json`
- `StructRisk/generated/phase1_offline_llm_card_metrics.json`
- `StructRisk/generated/phase1_offline_llm_lcr_metrics.json`
- `StructRisk/generated/phase1_offline_casr_summary.md`
- `StructRisk/generated/magma_unified_crash_backed_external_summary.md`
- `StructRisk/generated/magma_unified_crash_backed_external_casr_summary.md`
- `StructRisk/generated/magma_inventory_audit.md`
- `StructRisk/generated/magma_inventory_project_coverage.csv`
