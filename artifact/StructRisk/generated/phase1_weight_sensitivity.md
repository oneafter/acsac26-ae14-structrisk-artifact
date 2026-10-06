# StructRisk Weight Sensitivity

This experiment perturbs the fixed StructRisk prior weights without using Eval/MAGMA labels to select a replacement. It reports stability envelopes; the manuscript primary scorer remains the shipped fixed prior.

## Perturbation Design

- Features: `replay, locality, evidence_uniqueness_gated, failure_semantics_gated, sanitizer, weak`
- One-at-a-time perturbations: each weight scaled by 0.8 or 1.2.
- Full-corner perturbations: all six weights independently scaled by 0.8 or 1.2.
- LCR checks reuse cached LLM-CardScore outputs for deterministic same-project score-band and weak-bucket tie resolution with greedy source-site novelty.

## Envelope Summary

| Slice | Metric | Base | Min | Max | Spread | Variants |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| phase_global | HR@5 | 5 | 4 | 5 | 1 | 77 |
| phase_global | HR@10 | 8 | 6 | 8 | 2 | 77 |
| phase_global | NDCG@5 | 1.0 | 0.8539 | 1.0 | 0.1461 | 77 |
| phase_global | NDCG@10 | 0.8522 | 0.6988 | 0.8572 | 0.15839999999999999 | 77 |
| within_project | NDCG@5 | 0.8561004227058827 | 0.8534133817255534 | 0.8622396569389803 | 0.008826275213426937 | 77 |
| within_project | MAP | 0.8166666666666667 | 0.8074999999999999 | 0.825 | 0.01750000000000007 | 77 |
| within_project | MRR | 0.85 | 0.85 | 0.8583333333333334 | 0.008333333333333415 | 77 |
| phase_lcr_global | HR@5 | 5 | 4 | 5 | 1 | 77 |
| phase_lcr_global | HR@10 | 8 | 6 | 8 | 2 | 77 |
| phase_lcr_global | NDCG@5 | 1.0 | 0.8539 | 1.0 | 0.1461 | 77 |
| phase_lcr_global | NDCG@10 | 0.8522 | 0.6988 | 0.8572 | 0.15839999999999999 | 77 |
| within_lcr_project | NDCG@5 | 0.9023230490017153 | 0.8716656893634424 | 0.9023230490017153 | 0.030657359638272985 | 77 |
| within_lcr_project | MAP | 0.875 | 0.8333333333333333 | 0.875 | 0.04166666666666674 | 77 |
| within_lcr_project | MRR | 0.9333333333333333 | 0.8833333333333334 | 0.9333333333333333 | 0.04999999999999993 | 77 |

## Interpretation

- Small spreads indicate that the result is not tied to a single numerically precise fixed-prior weight vector.
- Variants are not used to choose a replacement scorer; they are reported only as robustness checks against post-hoc tuning concerns.
