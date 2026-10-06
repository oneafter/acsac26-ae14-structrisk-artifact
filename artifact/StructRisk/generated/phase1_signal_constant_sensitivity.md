# Signal-Constant Perturbation Audit

This audit complements the theta-level perturbation study: it perturbs every hand-set constant of the signal-extraction rules by +/-20% (base rules one-at-a-time and at all 16 corners; every derived-rule constant one-at-a-time), with theta fixed at the shipped prior. No variant is selected against any label.

- Variants: `58` (+ base)
- Global metrics: deterministic held-out ordering (78 findings).
- Within-project metrics: tie-aware expected metrics over the ten positive multi-finding projects.

## Envelope

| Metric | Base | Min | Max |
| --- | ---: | ---: | ---: |
| global_NDCG@10 | 0.8522 | 0.6988 | 0.8572 |
| global_HR@10 | 8 | 6 | 8 |
| global_HR@5 | 5 | 3 | 5 |
| wp_NDCG@5 | 0.8561 | 0.8473 | 0.8622 |
| wp_MAP | 0.8167 | 0.8012 | 0.825 |

## Variants

| Variant | global NDCG@10 | global HR@10 | global HR@5 | wp NDCG@5 | wp MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| base | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| rule_replay_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| rule_replay_x120 | 0.7624 | 7 | 4 | 0.8473 | 0.8054 |
| rule_locality_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| rule_locality_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| rule_sanitizer_x80 | 0.8572 | 8 | 5 | 0.8561 | 0.8167 |
| rule_sanitizer_x120 | 0.8482 | 8 | 5 | 0.8561 | 0.8167 |
| rule_weak_x80 | 0.6988 | 6 | 4 | 0.8534 | 0.8093 |
| rule_weak_x120 | 0.7818 | 7 | 4 | 0.8622 | 0.825 |
| corner_LLLL | 0.7722 | 7 | 4 | 0.8534 | 0.8117 |
| corner_LLLH | 0.7885 | 7 | 5 | 0.8622 | 0.825 |
| corner_LLHL | 0.7656 | 7 | 4 | 0.8534 | 0.8075 |
| corner_LLHH | 0.7885 | 7 | 5 | 0.8622 | 0.825 |
| corner_LHLL | 0.7722 | 7 | 4 | 0.8534 | 0.8117 |
| corner_LHLH | 0.7885 | 7 | 5 | 0.8622 | 0.825 |
| corner_LHHL | 0.7656 | 7 | 4 | 0.8534 | 0.8117 |
| corner_LHHH | 0.7885 | 7 | 5 | 0.8622 | 0.825 |
| corner_HLLL | 0.7538 | 7 | 3 | 0.8473 | 0.8054 |
| corner_HLLH | 0.782 | 7 | 5 | 0.8534 | 0.8117 |
| corner_HLHL | 0.7506 | 7 | 3 | 0.8473 | 0.8012 |
| corner_HLHH | 0.782 | 7 | 5 | 0.8534 | 0.8117 |
| corner_HHLL | 0.7538 | 7 | 3 | 0.8473 | 0.8054 |
| corner_HHLH | 0.782 | 7 | 5 | 0.8534 | 0.8117 |
| corner_HHHL | 0.7506 | 7 | 3 | 0.8473 | 0.8054 |
| corner_HHHH | 0.782 | 7 | 5 | 0.8534 | 0.8117 |
| const_eu_support_x80 | 0.7846 | 7 | 5 | 0.8561 | 0.8167 |
| const_eu_support_x120 | 0.839 | 8 | 4 | 0.8509 | 0.8125 |
| const_eu_site_x80 | 0.8486 | 8 | 4 | 0.8622 | 0.825 |
| const_eu_site_x120 | 0.7885 | 7 | 5 | 0.8534 | 0.8117 |
| const_eu_spread_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_eu_spread_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_base_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_base_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_strong_x80 | 0.8572 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_strong_x120 | 0.7846 | 7 | 5 | 0.8561 | 0.8167 |
| const_fs_deadly_x80 | 0.7846 | 7 | 5 | 0.8561 | 0.8167 |
| const_fs_deadly_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_site_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_site_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_exact_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_exact_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_exit_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_exit_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_assert_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_assert_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_weakpat_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_weakpat_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_san_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_fs_san_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_gate_slope_x80 | 0.8486 | 8 | 4 | 0.8622 | 0.825 |
| const_gate_slope_x120 | 0.6988 | 6 | 4 | 0.8534 | 0.8093 |
| const_gate_floor_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_gate_floor_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_ss_bonus_x80 | 0.7846 | 7 | 5 | 0.8561 | 0.8167 |
| const_ss_bonus_x120 | 0.8572 | 8 | 5 | 0.8561 | 0.8167 |
| const_ss_min_count_x80 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_ss_min_count_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
| const_ss_weak_max_x80 | 0.7846 | 7 | 5 | 0.8561 | 0.8167 |
| const_ss_weak_max_x120 | 0.8522 | 8 | 5 | 0.8561 | 0.8167 |
