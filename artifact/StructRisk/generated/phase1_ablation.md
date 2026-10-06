# Phase-1 Ablation Summary

| Variant | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR | WP NDCG@5 | WP MRR | WP MAP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Full | 5 | 8 | 1.0000 | 0.8522 | 1 | 0.8561 | 0.8500 | 0.8167 |
| -replay | 4 | 7 | 0.8539 | 0.7624 | 1 | 0.8473 | 0.8375 | 0.8054 |
| -locality | 5 | 8 | 1.0000 | 0.8522 | 1 | 0.8561 | 0.8500 | 0.8111 |
| -evidence_uniqueness_gated | 5 | 7 | 1.0000 | 0.7885 | 1 | 0.8558 | 0.8500 | 0.8129 |
| -failure_semantics_gated | 5 | 7 | 1.0000 | 0.7910 | 1 | 0.8481 | 0.8500 | 0.8000 |
| -sanitizer | 4 | 7 | 0.8539 | 0.7695 | 1 | 0.8779 | 0.8375 | 0.8221 |
| -weak | 3 | 5 | 0.6992 | 0.5965 | 1 | 0.8473 | 0.8375 | 0.7999 |

Ablation is implemented by setting the corresponding fixed-prior weight to zero while leaving the other weights unchanged.
