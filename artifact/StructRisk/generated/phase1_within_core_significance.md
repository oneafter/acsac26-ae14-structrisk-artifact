# Phase-1 Within-Project Significance Summary

- Multi-finding positive eval projects: `10` (binaryen, lily, openbabel, raylib, sokol, soloud, squirrel, wabt, wren, xlnt)
- Bootstrap: `20000` project-level resamples
- Exact test: project-block sign-flip randomization over all label-preserving swap patterns

## Macro Metrics

| Method | HR@1 | HR@3 | NDCG@5 | MRR | MAP |
| --- | ---: | ---: | ---: | ---: | ---: |
| Public-Severity | 0.2930 | 0.8790 | 0.5126 | 0.5153 | 0.4696 |
| ASan-Severity | 0.6067 | 1.4200 | 0.7699 | 0.7510 | 0.7197 |
| Crash-State | 0.6500 | 1.5500 | 0.8193 | 0.8000 | 0.7569 |
| LLM-CardScore | 0.8500 | 1.6500 | 0.8849 | 0.9083 | 0.8444 |
| StructRisk | 0.7500 | 1.6000 | 0.8561 | 0.8500 | 0.8167 |

## StructRisk Comparisons

| Comparison | Metric | Diff | 95% CI | Exact $p$ |
| --- | --- | ---: | --- | ---: |
| StructRisk vs Public-Severity | HR@1 | 0.4570 | [0.1990, 0.6770] | 0.0146 |
| StructRisk vs Public-Severity | HR@3 | 0.7210 | [0.4210, 1.0215] | 0.0088 |
| StructRisk vs Public-Severity | NDCG@5 | 0.3435 | [0.2010, 0.4889] | 0.0049 |
| StructRisk vs Public-Severity | MRR | 0.3347 | [0.1647, 0.4838] | 0.0088 |
| StructRisk vs Public-Severity | MAP | 0.3470 | [0.1909, 0.4977] | 0.0049 |
| StructRisk vs ASan-Severity | HR@1 | 0.1433 | [-0.2000, 0.4500] | 0.4849 |
| StructRisk vs ASan-Severity | HR@3 | 0.1800 | [-0.1000, 0.4733] | 0.3756 |
| StructRisk vs ASan-Severity | NDCG@5 | 0.0862 | [-0.0449, 0.2083] | 0.2507 |
| StructRisk vs ASan-Severity | MRR | 0.0990 | [-0.1249, 0.2983] | 0.3912 |
| StructRisk vs ASan-Severity | MAP | 0.0969 | [-0.0637, 0.2436] | 0.2976 |
| StructRisk vs Crash-State | HR@1 | 0.1000 | [-0.2500, 0.4500] | 0.8127 |
| StructRisk vs Crash-State | HR@3 | 0.0500 | [-0.1500, 0.3000] | 1.0000 |
| StructRisk vs Crash-State | NDCG@5 | 0.0368 | [-0.0788, 0.1524] | 0.6254 |
| StructRisk vs Crash-State | MRR | 0.0500 | [-0.1833, 0.2667] | 0.8127 |
| StructRisk vs Crash-State | MAP | 0.0597 | [-0.0861, 0.2083] | 0.5005 |
| StructRisk vs LLM-CardScore | HR@1 | -0.1000 | [-0.2500, 0.0000] | 0.5005 |
| StructRisk vs LLM-CardScore | HR@3 | -0.0500 | [-0.1500, 0.0000] | 1.0000 |
| StructRisk vs LLM-CardScore | NDCG@5 | -0.0288 | [-0.0736, 0.0114] | 0.3756 |
| StructRisk vs LLM-CardScore | MRR | -0.0583 | [-0.1417, 0.0000] | 0.5005 |
| StructRisk vs LLM-CardScore | MAP | -0.0278 | [-0.0889, 0.0333] | 0.5005 |
