# Reviewer C Supplement: Evidence-View Sensitivity Analysis

## Purpose

Reviewer C asked whether StructRisk's observed ranking quality is sensitive to the design of the evidence card, whether alternative representations or groupings were considered, and whether performance is driven primarily by particular evidence views.

We therefore ran a new, deterministic post-submission sensitivity analysis over the five evidence-card views: **Sanitizer**, **Stack**, **Replay**, **Input/provenance**, and **Code**. The analysis isolates the structured StructRisk core; it does not use LLM-LCR. This distinction matters because the paper's StructRisk+LLM-LCR result is 0.9023/0.8750 NDCG@5/MAP, whereas the fixed structured core evaluated here is 0.8561/0.8167.

The main result is that the full evidence card outperforms every tested single-view and coarse two-group representation across the global, within-project, and project-disjoint Eval-only evaluations (leave-one-view-out effects are heterogeneous: removing Code raises the within-project point estimates). The contribution of individual views is task dependent: Replay is most important for the global queue, Input/provenance has the largest local leave-one-view-out effect, Sanitizer is the strongest single-view local proxy, and Stack is redundant for ranking after finding consolidation on this dataset. These results support complementary multi-view evidence, but they do not establish that the current five-view grouping is uniquely optimal.

## 1. Experimental Question

The experiment addresses two related questions:

1. **Marginal view sensitivity:** How does ranking change when one evidence view is removed while all other views and the frozen scorer remain available?
2. **Alternative representation sensitivity:** How well can a single view or a coarser evidence grouping rank findings without the complete card?

The experiment is intentionally descriptive. It identifies which views affect the observed rankings and where their effects appear; it does not introduce new statistical-significance claims.

## 2. Scope and Controls

### 2.1 Fixed components

The following components are held fixed in every variant:

- the released finding identities and project membership;
- the external HIGH-CVE labels;
- the Dev/Eval project split;
- the structured scorer and its original weights;
- the ranking metrics and tie-aware within-project evaluation;
- the deterministic secondary identifier tie-breaker.

The fixed scorer is:

| Signal | Weight |
| --- | ---: |
| Replay | 2.00 |
| Locality | 1.00 |
| EvidenceUniq (weak-gated) | 1.00 |
| FailureSem (weak-gated) | 1.00 |
| Sanitizer | 2.00 |
| Weak | -3.00 |
| Bias | 0.00 |

No weight, threshold, extraction constant, or representation choice is tuned against the results of this sensitivity analysis.

### 2.2 Post-consolidation scope

This is a **ranking-stage, post-consolidation** analysis. It fixes the 78 held-out global findings and the 82 findings in the ten positive multi-finding projects, then masks evidence views and recomputes all affected base and derived signals.

It does **not** rerun raw-crash consolidation. Sanitizer class, source location, and stack signatures contributed to the original finding boundaries, so a fully end-to-end view-removal experiment could produce a different number of findings. The present experiment answers the narrower question relevant to the ranker: given the consolidated findings available to an analyst, how sensitive is their ordering to each card view?

### 2.3 Why the structured core is isolated

LLM-LCR is excluded because it is a downstream local tie resolver rather than part of the five-view structured representation. Including it would confound evidence-card sensitivity with model-generated semantic scores. All reported variants therefore use the same transparent structured scorer.

## 3. View-Masking Procedure

For each variant, the implementation removes the selected view's fields and reverses the exact view-specific increments used by the released extractor. It then recomputes EvidenceUniq, support stability, FailureSem, weak gating, scores, and rankings from the retained evidence.

| Removed view | Fields or cues masked | Affected ranking signals recomputed |
| --- | --- | --- |
| Sanitizer | Canonical sanitizer class, summary, assertion/failure class | Sanitizer, Locality, Weak, FailureSem, both weak-gated derived signals |
| Stack | Stable multi-frame contribution | Locality and downstream score |
| Replay | Command-line availability, matched report section, command/report cues | Replay, Weak, FailureSem, weak-gated signals |
| Input/provenance | Support count, retained samples, campaigns, aligned targets, target name | Replay support bonus, Weak support adjustment, EvidenceUniq, support stability, target-dependent signature |
| Code | Matched project/summary locations and location-bearing signature | Locality, Weak, EvidenceUniq, FailureSem, support stability |

The implementation uses the same clamping bounds as the released extractor. It also asserts that the unmasked full-view ranking exactly matches the canonical StructRisk ranking before evaluating any variant.

## 4. Variants

### 4.1 Leave-one-view-out variants

- Full card
- Without Sanitizer
- Without Stack
- Without Replay
- Without Input/provenance
- Without Code
- Without both Stack and Code

The last variant tests whether Stack and Code jointly provide location information that is partly interchangeable after consolidation.

### 4.2 Alternative representations

- Sanitizer only
- Stack only
- Replay only
- Input/provenance only
- Code only
- Crash-report group: Sanitizer + Stack + Code
- Operational group: Replay + Input/provenance

These variants test concrete alternative representations without fitting a new model. They are intentionally conservative proxies: the same frozen scorer remains in place, and unavailable signals become zero or are recomputed from the retained fields.

## 5. Evaluation Scopes and Metrics

### 5.1 Global held-out queue

The global evaluation contains 78 findings from 18 held-out projects and 13 HIGH-CVE positives. We report HighRisk@5, HighRisk@10, NDCG@5, and NDCG@10. The headline sensitivity metric is NDCG@10 because it captures both retrieval and ordering at the paper's main global review depth.

### 5.2 Ten-project within-project evaluation

The within-project evaluation contains 82 findings and 19 positives across ten positive multi-finding projects. We report tie-aware macro Hits@1, Hits@3, NDCG@5, MRR, and MAP. Expected metric credit is used when a representation assigns equal scores to findings in the same project.

### 5.3 Project-disjoint Eval-only check

The Eval-only check contains the five positive multi-finding held-out projects: `binaryen`, `openbabel`, `squirrel`, `wabt`, and `xlnt`. It is project disjoint from Dev and is reported separately to show whether the local sensitivity pattern persists outside the development projects. Because only five project blocks are available, these values are descriptive point estimates.

## 6. Results

### 6.1 Leave-one-view-out sensitivity

| Variant | Global HR@5 | Global HR@10 | Global NDCG@5 | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Full card** | **5** | **8** | **1.0000** | **0.8522** | 0.8561 | 0.8167 | 0.8981 | 0.8417 |
| Without Sanitizer | 3 | 6 | 0.7227 | 0.6773 | 0.8661 | 0.8058 | 0.8874 | 0.8283 |
| Without Stack | 5 | 8 | 1.0000 | 0.8522 | 0.8561 | 0.8167 | 0.8981 | 0.8417 |
| Without Replay | 1 | 4 | 0.1696 | 0.3254 | 0.8534 | 0.8117 | 0.8927 | 0.8317 |
| Without Input/provenance | 4 | 6 | 0.8539 | 0.6938 | 0.7897 | 0.7451 | 0.8017 | 0.7478 |
| Without Code | 5 | 7 | 1.0000 | 0.7885 | 0.8736 | 0.8319 | 0.9330 | 0.8833 |
| Without Stack and Code | 5 | 7 | 1.0000 | 0.7885 | 0.8582 | 0.8153 | 0.9330 | 0.8833 |

Changes relative to the full card are:

| Variant | Delta global NDCG@10 | Delta WP NDCG@5 | Delta WP MAP | Delta Eval-only NDCG@5 | Delta Eval-only MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| Without Sanitizer | -0.1749 | +0.0100 | -0.0108 | -0.0107 | -0.0133 |
| Without Stack | +0.0000 | +0.0000 | +0.0000 | +0.0000 | +0.0000 |
| Without Replay | -0.5267 | -0.0027 | -0.0050 | -0.0054 | -0.0100 |
| Without Input/provenance | -0.1584 | -0.0664 | -0.0715 | -0.0964 | -0.0939 |
| Without Code | -0.0636 | +0.0175 | +0.0153 | +0.0349 | +0.0417 |
| Without Stack and Code | -0.0636 | +0.0021 | -0.0014 | +0.0349 | +0.0417 |

### 6.2 Single-view and grouped alternatives

| Representation | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Full card** | **0.8522** | **0.8561** | **0.8167** | **0.8981** | **0.8417** |
| Sanitizer only | 0.1389 | 0.8174 | 0.7801 | 0.8571 | 0.8072 |
| Stack only | 0.1100 | 0.6771 | 0.6307 | 0.6652 | 0.6372 |
| Replay only | 0.3590 | 0.4991 | 0.4636 | 0.5016 | 0.4463 |
| Input/provenance only | 0.2240 | 0.6140 | 0.5568 | 0.7036 | 0.6131 |
| Code only | 0.4042 | 0.8023 | 0.7580 | 0.8366 | 0.7894 |
| Crash-report group | 0.4858 | 0.8117 | 0.7638 | 0.8366 | 0.7894 |
| Operational group | 0.5523 | 0.6619 | 0.6142 | 0.7353 | 0.6520 |

The full card exceeds the strongest tested alternative by:

- **Global NDCG@10:** +0.2999 over the operational group (0.8522 vs. 0.5523), and +0.4479 over the best single view, Code (0.8522 vs. 0.4042).
- **Within-project NDCG@5/MAP:** +0.0387/+0.0366 over the best single view, Sanitizer (0.8561/0.8167 vs. 0.8174/0.7801).
- **Eval-only NDCG@5/MAP:** +0.0410/+0.0345 over the best single view, Sanitizer (0.8981/0.8417 vs. 0.8571/0.8072).

Thus, no tested single view or coarse grouping reproduces the full card's performance across all three evaluation scopes.

### 6.3 Per-project leave-one-view-out results

Each cell reports NDCG@5/MAP. A dagger marks the five project-disjoint Eval-only projects.

| Project | Full | -Sanitizer | -Stack | -Replay | -Input | -Code | -Stack-Code |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `binaryen` (dagger) | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 |
| `lily` | 0.5706/0.4167 | 0.5706/0.4167 | 0.5706/0.4167 | 0.5706/0.4167 | 1.0000/1.0000 | 0.5706/0.4167 | 0.5706/0.4167 |
| `openbabel` (dagger) | 0.9599/0.9167 | 0.9599/0.9167 | 0.9599/0.9167 | 0.9599/0.9167 | 0.9599/0.9167 | 0.9599/0.9167 | 0.9599/0.9167 |
| `raylib` | 1.0000/1.0000 | 0.6934/0.5833 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 |
| `sokol` | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 |
| `soloud` | 0.5000/0.5417 | 0.9599/0.9167 | 0.5000/0.5417 | 0.5000/0.5417 | 0.2506/0.2125 | 0.5000/0.4861 | 0.3467/0.3194 |
| `squirrel` (dagger) | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 |
| `wabt` (dagger) | 0.9197/0.8333 | 0.9197/0.8333 | 0.9197/0.8333 | 0.9197/0.8333 | 0.6108/0.4583 | 0.9197/0.8333 | 0.9197/0.8333 |
| `wren` | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 1.0000/1.0000 | 0.6383/0.5000 | 1.0000/1.0000 | 1.0000/1.0000 |
| `xlnt` (dagger) | 0.6108/0.4583 | 0.5572/0.3917 | 0.6108/0.4583 | 0.5839/0.4083 | 0.4378/0.3639 | 0.7853/0.6667 | 0.7853/0.6667 |

The per-project table explains why some macro averages improve when a view is removed. Sanitizer is decisive for `raylib` but its removal happens to improve `soloud`; Input/provenance is important for `soloud`, `wabt`, `wren`, and `xlnt`, but its removal improves `lily`; and removing Code improves `xlnt`. These heterogeneous effects argue against a universal single-view explanation and also caution against claiming that every existing view is beneficial for every project.

## 7. Interpretation

### 7.1 Replay drives global early retrieval

Removing Replay produces the largest global degradation: HighRisk@10 falls from 8 to 4 and NDCG@10 falls from 0.8522 to 0.3254. Replay availability and report consistency therefore provide strong cross-project calibration: findings supported by usable commands and matching reports rise above globally incomparable crash classes.

Replay alone is not sufficient, however. Its single-view NDCG@10 is only 0.3590, far below the full card. The strong leave-one-out effect and weak single-view result together indicate complementarity: Replay is valuable when combined with impact, provenance, and location evidence, rather than acting as a standalone severity proxy.

### 7.2 Input/provenance drives local discrimination

Removing Input/provenance produces the largest within-project loss: NDCG@5/MAP falls from 0.8561/0.8167 to 0.7897/0.7451. The project-disjoint Eval-only slice shows a larger reduction, from 0.8981/0.8417 to 0.8017/0.7478. Within a project, crash class and source location are often shared or closely related; bounded support, campaign spread, target provenance, and retained-sample evidence help distinguish findings that otherwise look similar.

Input/provenance alone remains insufficient (0.6140/0.5568 within-project NDCG@5/MAP), showing that its local value depends on being combined with failure semantics and impact evidence.

### 7.3 Sanitizer is the strongest single-view local proxy

Sanitizer alone achieves the strongest single-view within-project result, 0.8174/0.7801 NDCG@5/MAP, and the strongest Eval-only result, 0.8571/0.8072. This is expected for a sanitizer-rich C/C++ benchmark: memory-error classes encode meaningful local impact differences.

Its marginal effect is not uniform. Removing Sanitizer reduces global NDCG@10 by 0.1749 and lowers local MAP, but local NDCG@5 slightly increases because a small number of project-specific reorderings improve. The correct conclusion is that Sanitizer is a strong but non-dominant view, not that the full result is simply ASan severity under another name.

### 7.4 Stack is redundant after consolidation on this slice

Removing Stack does not change any reported ranking metric. The original consolidation has already grouped findings using source location, sanitizer class, and top-frame signatures, while the retained Code view preserves location evidence. Consequently, normalized stack depth and multi-frame stability have no independent marginal ranking effect after consolidation in the current data.

This zero effect should be reported directly. It does not imply that stacks are unnecessary end to end: they remain useful for grouping crashes without ASan reports and for constructing stable finding identities. It only shows that, conditional on the released consolidated findings and retained Code fields, Stack does not further reorder this ranking slice.

### 7.5 Code helps globally but is not uniformly beneficial locally

Removing Code lowers global NDCG@10 from 0.8522 to 0.7885, indicating that source-site evidence helps compare findings across projects. In contrast, the within-project point estimates increase to 0.8736/0.8319, primarily because `xlnt` is reordered favorably. Removing Stack and Code together largely preserves this pattern.

This is evidence of overlap and small-sample heterogeneity, not a basis for deleting the Code view. Code alone is the best single global view (0.4042), and bounded source location is also important for auditability, consolidation, and analyst interpretation even where its marginal ranking contribution is redundant.

### 7.6 The full card is more stable across tasks than any alternative

Different reduced representations perform best in different settings: the operational group is strongest among alternatives globally, while Sanitizer is strongest locally. Among the tested single-view and coarse-group alternatives, the full card is the only representation that remains strongest across the global queue, the ten-project local evaluation, and the project-disjoint Eval-only check; individual leave-one-view-out variants can exceed it on single scopes. The evidence therefore supports **task-dependent view complementarity** and cross-setting robustness rather than equal importance of all views.

## 8. Direct Answer to Reviewer C

We considered two concrete classes of alternative representation: leave-one-view-out cards and reduced single-view/coarse-group cards. The observed performance is not driven by one universal view. Replay has the largest effect on global NDCG@10, Input/provenance has the largest effect on within-project ranking, and Sanitizer is the strongest single-view local proxy. No single-view or coarse-group variant matches the full card across all evaluated scopes. Stack has no independent post-consolidation ranking effect, and Code is partially redundant locally, so the experiment does not support a claim that every view is necessary or that the present grouping is uniquely optimal. Instead, it supports the narrower conclusion that the views provide complementary, task-dependent evidence and that the complete card is the most stable tested representation.

## 9. Limitations

1. **No reconsolidation.** The analysis fixes finding boundaries and therefore cannot measure how removing Sanitizer, Stack, or Code would affect upstream deduplication and grouping.
2. **Derived-signal coupling.** Evidence views are not orthogonal. For example, Sanitizer and Code also affect FailureSem and Weak, while Input/provenance affects EvidenceUniq and support stability. This coupling is part of the implemented card-to-signal mapping, but it prevents interpreting each delta as a pure causal effect.
3. **Small project count.** The local analysis has ten project blocks, and the project-disjoint check has five. We therefore report descriptive effect sizes rather than new significance claims.
4. **Single workflow and domain.** The benchmark is sanitizer-rich C/C++ data from one fuzzing-and-disclosure workflow. Other workflows may assign more importance to stack, input grammar, kernel state, or domain-specific views.
5. **Frozen scorer favors comparability.** Keeping the original scorer fixed isolates representation sensitivity, but a model separately optimized for each reduced representation might produce different absolute values. Such retraining would answer a different question and would be difficult to justify with the available sample size.

## 10. Reproduction

From the repository root:

```bash
python3 StructRisk/scripts/phase1_view_ablation.py
```

Inputs:

- `StructRisk/generated/phase1_offline_eval.jsonl`
- `StructRisk/generated/phase1_within10_eval.jsonl`
- `StructRisk/generated/phase1_offline_enriched_artifacts.jsonl`
- `StructRisk/generated/phase1_offline_manual_ranked.jsonl`
- `StructRisk/generated/phase1_within10_manual_ranked.jsonl`

Outputs:

- `StructRisk/generated/phase1_view_ablation.json`
- `StructRisk/generated/phase1_view_ablation.md`

The script uses only the Python standard library and released StructRisk helpers. Before running variants, it verifies that the full-view global and within-project finding order exactly matches the canonical ranked outputs. Repeated executions produce byte-identical outputs.

Current SHA-256 values:

```text
642419ea60ed61f886a8cc55400dc559fba7488b2d69adb16d775d7a32eb4e10  StructRisk/scripts/phase1_view_ablation.py
1d67fb84c3ce9992594874815386f5a9789c82a8a535d03cead1c525c46b51ea  StructRisk/generated/phase1_view_ablation.json
4aff891e395aff4c6627f775ae2205e4a73f310d5bd335ee551785b6e67c26d9  StructRisk/generated/phase1_view_ablation.md
```

## 11. Concise Rebuttal Version

> We additionally ran a post-consolidation evidence-view sensitivity analysis with findings, labels, and the structured scorer fixed. The full card outperforms every tested single-view and coarse-group representation on global NDCG@10, within-project NDCG@5/MAP, and the project-disjoint Eval-only check (leave-one-view-out effects are heterogeneous). The views serve different roles: removing Replay reduces global NDCG@10 from 0.8522 to 0.3254, whereas removing Input/provenance reduces within-project NDCG@5/MAP from 0.8561/0.8167 to 0.7897/0.7451; the Eval-only slice shows the same local pattern. Sanitizer is the strongest single-view local proxy. Stack has no independent ranking effect after consolidation, indicating redundancy with retained location evidence. These descriptive results support task-dependent view complementarity, but do not claim that every view is necessary or that the current grouping is uniquely optimal.

## 12. Bottom Line

This experiment is favorable for the rebuttal because it directly answers Reviewer C with new, reproducible evidence and does not rely on the Public-Severity comparison. Its strongest defensible message is not that all five views are individually essential. Rather, the complete evidence card is the only tested representation that performs consistently across global and local ranking, while individual views contribute differently by task and project.
