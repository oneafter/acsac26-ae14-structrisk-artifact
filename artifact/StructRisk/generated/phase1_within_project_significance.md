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
| StructRisk+LLM-LCR | 0.9000 | 1.7000 | 0.9023 | 0.9333 | 0.8750 |

## StructRisk+LLM-LCR Comparisons

| Comparison | Metric | Diff | 95% CI | Exact $p$ |
| --- | --- | ---: | --- | ---: |
| StructRisk+LLM-LCR vs Public-Severity | HR@1 | 0.6070 | [0.3648, 0.7860] | 0.0049 |
| StructRisk+LLM-LCR vs Public-Severity | HR@3 | 0.8210 | [0.4838, 1.1571] | 0.0088 |
| StructRisk+LLM-LCR vs Public-Severity | NDCG@5 | 0.3897 | [0.2337, 0.5397] | 0.0049 |
| StructRisk+LLM-LCR vs Public-Severity | MRR | 0.4181 | [0.2362, 0.5642] | 0.0068 |
| StructRisk+LLM-LCR vs Public-Severity | MAP | 0.4054 | [0.2415, 0.5472] | 0.0068 |
| StructRisk+LLM-LCR vs ASan-Severity | HR@1 | 0.2933 | [-0.0733, 0.6200] | 0.2039 |
| StructRisk+LLM-LCR vs ASan-Severity | HR@3 | 0.2800 | [-0.0333, 0.6067] | 0.1883 |
| StructRisk+LLM-LCR vs ASan-Severity | NDCG@5 | 0.1325 | [-0.0185, 0.2722] | 0.1259 |
| StructRisk+LLM-LCR vs ASan-Severity | MRR | 0.1824 | [-0.0635, 0.4061] | 0.1883 |
| StructRisk+LLM-LCR vs ASan-Severity | MAP | 0.1553 | [-0.0249, 0.3180] | 0.1415 |
| StructRisk+LLM-LCR vs Crash-State | HR@1 | 0.2500 | [-0.1500, 0.6000] | 0.3756 |
| StructRisk+LLM-LCR vs Crash-State | HR@3 | 0.1500 | [0.0000, 0.3500] | 0.5005 |
| StructRisk+LLM-LCR vs Crash-State | NDCG@5 | 0.0830 | [-0.0370, 0.1967] | 0.2195 |
| StructRisk+LLM-LCR vs Crash-State | MRR | 0.1333 | [-0.1000, 0.3500] | 0.3132 |
| StructRisk+LLM-LCR vs Crash-State | MAP | 0.1181 | [-0.0319, 0.2611] | 0.1883 |
| StructRisk+LLM-LCR vs LLM-CardScore | HR@1 | 0.0500 | [0.0000, 0.1500] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | HR@3 | 0.0500 | [0.0000, 0.1500] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | NDCG@5 | 0.0175 | [-0.0080, 0.0510] | 0.5005 |
| StructRisk+LLM-LCR vs LLM-CardScore | MRR | 0.0250 | [0.0000, 0.0750] | 1.0000 |
| StructRisk+LLM-LCR vs LLM-CardScore | MAP | 0.0306 | [-0.0111, 0.0806] | 0.3756 |
