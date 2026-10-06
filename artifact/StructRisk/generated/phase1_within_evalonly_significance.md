# Phase-1 Within-Project Significance Summary

- Multi-finding positive eval projects: `5` (binaryen, openbabel, squirrel, wabt, xlnt)
- Bootstrap: `20000` project-level resamples
- Exact test: project-block sign-flip randomization over all label-preserving swap patterns

## Macro Metrics

| Method | HR@1 | HR@3 | NDCG@5 | MRR | MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| Public-Severity | 0.3086 | 0.9257 | 0.5236 | 0.5210 | 0.4834 |
| ASan-Severity | 0.7467 | 1.4400 | 0.8571 | 0.8443 | 0.8072 |
| Crash-State | 0.9000 | 1.7000 | 0.9330 | 0.9500 | 0.8833 |
| LLM-CardScore | 0.9000 | 1.7000 | 0.9490 | 0.9500 | 0.9167 |
| StructRisk+LLM-LCR | 1.0000 | 1.8000 | 0.9679 | 1.0000 | 0.9333 |

## StructRisk+LLM-LCR Comparisons

| Comparison | Metric | Diff | 95% CI | Exact $p$ |
| --- | --- | ---: | --- | ---: |
| StructRisk+LLM-LCR vs Public-Severity | HR@1 | 0.6914 | [0.4933, 0.8495] | 0.0909 |
| StructRisk+LLM-LCR vs Public-Severity | HR@3 | 0.8743 | [0.3886, 1.3600] | 0.1515 |
| StructRisk+LLM-LCR vs Public-Severity | NDCG@5 | 0.4443 | [0.2123, 0.6426] | 0.0909 |
| StructRisk+LLM-LCR vs Public-Severity | MRR | 0.4790 | [0.2976, 0.6336] | 0.0909 |
| StructRisk+LLM-LCR vs Public-Severity | MAP | 0.4500 | [0.2241, 0.6145] | 0.0909 |
| StructRisk+LLM-LCR vs ASan-Severity | HR@1 | 0.2533 | [0.0000, 0.5200] | 0.5152 |
| StructRisk+LLM-LCR vs ASan-Severity | HR@3 | 0.3600 | [0.0000, 0.7600] | 0.5152 |
| StructRisk+LLM-LCR vs ASan-Severity | NDCG@5 | 0.1108 | [-0.0161, 0.2456] | 0.5152 |
| StructRisk+LLM-LCR vs ASan-Severity | MRR | 0.1557 | [0.0000, 0.3237] | 0.5152 |
| StructRisk+LLM-LCR vs ASan-Severity | MAP | 0.1262 | [-0.0333, 0.3058] | 0.5152 |
| StructRisk+LLM-LCR vs Crash-State | HR@1 | 0.1000 | [0.0000, 0.3000] | 1.0000 |
| StructRisk+LLM-LCR vs Crash-State | HR@3 | 0.1000 | [0.0000, 0.3000] | 1.0000 |
| StructRisk+LLM-LCR vs Crash-State | NDCG@5 | 0.0349 | [-0.0161, 0.0911] | 0.5152 |
| StructRisk+LLM-LCR vs Crash-State | MRR | 0.0500 | [0.0000, 0.1500] | 1.0000 |
| StructRisk+LLM-LCR vs Crash-State | MAP | 0.0500 | [-0.0333, 0.1333] | 0.5152 |
| StructRisk+LLM-LCR vs LLM-CardScore | HR@1 | 0.1000 | [0.0000, 0.3000] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | HR@3 | 0.1000 | [0.0000, 0.3000] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | NDCG@5 | 0.0189 | [-0.0241, 0.0806] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | MRR | 0.0500 | [0.0000, 0.1500] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | MAP | 0.0167 | [-0.0500, 0.1000] | 1.0000 |
