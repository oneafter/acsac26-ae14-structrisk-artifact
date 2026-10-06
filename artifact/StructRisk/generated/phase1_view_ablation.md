# Evidence-View Sensitivity

This post-consolidation analysis fixes the released findings, labels, and StructRisk weights. It removes card views before signal extraction; it does not rerun finding consolidation.

## Leave-One-View-Out

| Variant | Global HR@10 | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full | 8 | 0.8522 | 0.8561 | 0.8167 | 0.8981 | 0.8417 |
| without_sanitizer | 6 | 0.6773 | 0.8661 | 0.8058 | 0.8874 | 0.8283 |
| without_stack | 8 | 0.8522 | 0.8561 | 0.8167 | 0.8981 | 0.8417 |
| without_replay | 4 | 0.3254 | 0.8534 | 0.8117 | 0.8927 | 0.8317 |
| without_input | 6 | 0.6938 | 0.7897 | 0.7451 | 0.8017 | 0.7478 |
| without_code | 7 | 0.7885 | 0.8736 | 0.8319 | 0.9330 | 0.8833 |
| without_stack_code | 7 | 0.7885 | 0.8582 | 0.8153 | 0.9330 | 0.8833 |

## Alternative Representations

| Variant | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| full | 0.8522 | 0.8561 | 0.8167 | 0.8981 | 0.8417 |
| only_sanitizer | 0.1389 | 0.8174 | 0.7801 | 0.8571 | 0.8072 |
| only_stack | 0.1100 | 0.6771 | 0.6307 | 0.6652 | 0.6372 |
| only_replay | 0.3590 | 0.4991 | 0.4636 | 0.5016 | 0.4463 |
| only_input | 0.2240 | 0.6140 | 0.5568 | 0.7036 | 0.6131 |
| only_code | 0.4042 | 0.8023 | 0.7580 | 0.8366 | 0.7894 |
| crash_report_only | 0.4858 | 0.8117 | 0.7638 | 0.8366 | 0.7894 |
| operational_only | 0.5523 | 0.6619 | 0.6142 | 0.7353 | 0.6520 |

## Descriptive Interpretation

- The full card exceeds every single-view proxy on global NDCG@10, within-project NDCG@5/MAP, and the project-disjoint Eval-only check.
- Sanitizer is the strongest single-view local proxy (NDCG@5/MAP 0.8174/0.7801), but its leave-one-out effect is partly absorbed by overlapping failure-semantics and weak-evidence cues.
- Replay is most important for the global queue; removing it lowers global NDCG@10 from 0.8522 to 0.3254, while its within-project effect is small.
- Input/provenance has the largest local leave-one-out effect, reducing NDCG@5/MAP from 0.8561/0.8167 to 0.7897/0.7451; the Eval-only pattern is similar (0.8981/0.8417 to 0.8017/0.7478).
- Stack has no independent ranking effect after consolidation, and Code helps globally but not on the current within-project slice. These are descriptive point estimates, not evidence that the current grouping is uniquely optimal.
