# Phase-1 Significance Summary

- Eval projects: `18` (ChaiScript, LIEF, OpenCC, berry, binaryen, ettercap, janet, libfastcommon, lobster, mapnik, micropython, minisat, mruby, openbabel, squirrel, wabt, wasm3, xlnt)
- Bootstrap: `20000` project-level resamples
- Exact test: project-block sign-flip randomization over all label-preserving swap patterns

## Primary Metrics with 95% Bootstrap CIs

| Method | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR Rank |
| --- | --- | --- | --- | --- | --- |
| Public-Severity | 4 [2, 5] | 7 [3, 9] | 0.7860 [0.5531, 1.0000] | 0.7281 [0.4846, 0.9196] | 1 [1, 1] |
| Artifact-Completeness | 2 [0, 3] | 3 [0, 6] | 0.3008 [0.0000, 0.7227] | 0.2614 [0.0000, 0.6780] | 3 [1, 17] |
| Support-Count | 1 [0, 3] | 1 [0, 4] | 0.3392 [0.0000, 0.7227] | 0.2201 [0.0000, 0.5533] | 1 [1, 19] |
| ASan-Severity | 1 [0, 4] | 1 [0, 7] | 0.1696 [0.0000, 0.6608] | 0.1100 [0.0000, 0.6500] | 3 [1, 75] |
| Crash-State | 2 [0, 4] | 4 [0, 7] | 0.3836 [0.0000, 0.8688] | 0.3885 [0.0000, 0.7722] | 2 [1, 26] |
| StackDedup-kNN | 3 [0, 5] | 4 [1, 7] | 0.5296 [0.0000, 1.0000] | 0.4171 [0.1175, 0.7682] | 2 [1, 6] |
| CASR-Severity | 1 [0, 4] | 4 [0, 6] | 0.3392 [0.0000, 0.8539] | 0.4233 [0.0000, 0.6653] | 1 [1, 12] |
| LLM-CardScore | 4 [2, 5] | 5 [3, 9] | 0.8539 [0.4704, 1.0000] | 0.6275 [0.4131, 0.9337] | 1 [1, 2] |
| StructRisk | 5 [2, 5] | 8 [3, 10] | 1.0000 [0.5148, 1.0000] | 0.8522 [0.4483, 1.0000] | 1 [1, 1] |

## StructRisk Comparisons

| Comparison | Metric | Diff | 95% CI | Exact $p$ |
| --- | --- | ---: | --- | ---: |
| StructRisk vs Public-Severity | HighRisk@5 | 1 | [-2, 2] | 0.7490 |
| StructRisk vs Public-Severity | HighRisk@10 | 1 | [-4, 4] | 0.7513 |
| StructRisk vs Public-Severity | NDCG@5 | 0.2140 | [-0.3156, 0.3156] | 0.5949 |
| StructRisk vs Public-Severity | NDCG@10 | 0.1241 | [-0.3274, 0.3012] | 0.7132 |
| StructRisk vs Public-Severity | Rank-to-First-HighRisk | 0 | [0, 0] | 1.0000 |
| StructRisk vs ASan-Severity | HighRisk@5 | 4 | [1, 5] | 0.1094 |
| StructRisk vs ASan-Severity | HighRisk@10 | 7 | [0, 9] | 0.0527 |
| StructRisk vs ASan-Severity | NDCG@5 | 0.8304 | [0.2080, 1.0000] | 0.0430 |
| StructRisk vs ASan-Severity | NDCG@10 | 0.7421 | [0.1565, 0.8900] | 0.0254 |
| StructRisk vs ASan-Severity | Rank-to-First-HighRisk | 2 | [0, 74] | 0.7090 |
| StructRisk vs Crash-State | HighRisk@5 | 3 | [0, 4] | 0.1484 |
| StructRisk vs Crash-State | HighRisk@10 | 4 | [0, 6] | 0.2422 |
| StructRisk vs Crash-State | NDCG@5 | 0.6164 | [0.0000, 0.8688] | 0.1113 |
| StructRisk vs Crash-State | NDCG@10 | 0.4636 | [0.0533, 0.6489] | 0.1514 |
| StructRisk vs Crash-State | Rank-to-First-HighRisk | 1 | [0, 9] | 0.9297 |
| StructRisk vs StackDedup-kNN | HighRisk@5 | 2 | [0, 3] | 0.4995 |
| StructRisk vs StackDedup-kNN | HighRisk@10 | 4 | [0, 5] | 0.2842 |
| StructRisk vs StackDedup-kNN | NDCG@5 | 0.4704 | [0.0000, 0.7227] | 0.1875 |
| StructRisk vs StackDedup-kNN | NDCG@10 | 0.4351 | [0.0734, 0.5970] | 0.1311 |
| StructRisk vs StackDedup-kNN | Rank-to-First-HighRisk | 1 | [0, 4] | 0.0935 |
| StructRisk vs CASR-Severity | HighRisk@5 | 4 | [0, 5] | 0.0620 |
| StructRisk vs CASR-Severity | HighRisk@10 | 4 | [-1, 9] | 0.2159 |
| StructRisk vs CASR-Severity | NDCG@5 | 0.6608 | [-0.0633, 1.0000] | 0.0933 |
| StructRisk vs CASR-Severity | NDCG@10 | 0.4288 | [-0.0164, 0.8701] | 0.1254 |
| StructRisk vs CASR-Severity | Rank-to-First-HighRisk | 0 | [0, 11] | 1.0000 |
| StructRisk vs LLM-CardScore | HighRisk@5 | 1 | [-1, 2] | 0.7559 |
| StructRisk vs LLM-CardScore | HighRisk@10 | 3 | [-2, 3] | 0.1885 |
| StructRisk vs LLM-CardScore | NDCG@5 | 0.1461 | [-0.2375, 0.4071] | 0.7168 |
| StructRisk vs LLM-CardScore | NDCG@10 | 0.2247 | [-0.1420, 0.3031] | 0.2666 |
| StructRisk vs LLM-CardScore | Rank-to-First-HighRisk | 0 | [0, 1] | 1.0000 |
