# Within-Project Ranking Summary

Tie-aware expectations are used when a method assigns the same score to multiple findings within a project.

## Macro Averages

| Scope | Method | Projects | HR@1 | HR@3 | NDCG@3 | NDCG@5 | MRR | MAP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| all-positive-projects | Public-Severity | 5 | 0.3086 | 0.9257 | 0.4267 | 0.5236 | 0.5210 | 0.4834 |
| multi-finding-projects | Public-Severity | 5 | 0.3086 | 0.9257 | 0.4267 | 0.5236 | 0.5210 | 0.4834 |
| all-positive-projects | Support-Count | 5 | 0.5333 | 1.2333 | 0.5577 | 0.7036 | 0.6750 | 0.6131 |
| multi-finding-projects | Support-Count | 5 | 0.5333 | 1.2333 | 0.5577 | 0.7036 | 0.6750 | 0.6131 |
| all-positive-projects | Artifact-Completeness | 5 | 0.6000 | 1.2333 | 0.5754 | 0.6353 | 0.6869 | 0.6139 |
| multi-finding-projects | Artifact-Completeness | 5 | 0.6000 | 1.2333 | 0.5754 | 0.6353 | 0.6869 | 0.6139 |
| all-positive-projects | ASan-Severity | 5 | 0.6800 | 1.4400 | 0.7578 | 0.8313 | 0.8110 | 0.7683 |
| multi-finding-projects | ASan-Severity | 5 | 0.6800 | 1.4400 | 0.7578 | 0.8313 | 0.8110 | 0.7683 |
| all-positive-projects | Crash-State | 5 | 0.9000 | 1.7000 | 0.9066 | 0.9330 | 0.9500 | 0.8833 |
| multi-finding-projects | Crash-State | 5 | 0.9000 | 1.7000 | 0.9066 | 0.9330 | 0.9500 | 0.8833 |
| all-positive-projects | StackDedup-kNN | 5 | 0.8800 | 1.5400 | 0.8538 | 0.9190 | 0.9283 | 0.8660 |
| multi-finding-projects | StackDedup-kNN | 5 | 0.8800 | 1.5400 | 0.8538 | 0.9190 | 0.9283 | 0.8660 |
| all-positive-projects | CASR-Severity | 5 | 0.4000 | 1.0000 | 0.4759 | 0.5621 | 0.5643 | 0.5123 |
| multi-finding-projects | CASR-Severity | 5 | 0.4000 | 1.0000 | 0.4759 | 0.5621 | 0.5643 | 0.5123 |
| all-positive-projects | LLM-CardScore | 5 | 0.9000 | 1.7000 | 0.9226 | 0.9490 | 0.9500 | 0.9167 |
| multi-finding-projects | LLM-CardScore | 5 | 0.9000 | 1.7000 | 0.9226 | 0.9490 | 0.9500 | 0.9167 |
| all-positive-projects | StructRisk | 5 | 0.8000 | 1.6000 | 0.8453 | 0.8981 | 0.8833 | 0.8417 |
| multi-finding-projects | StructRisk | 5 | 0.8000 | 1.6000 | 0.8453 | 0.8981 | 0.8833 | 0.8417 |
| all-positive-projects | StructRisk+LLM-LCR | 5 | 1.0000 | 1.8000 | 0.9679 | 0.9679 | 1.0000 | 0.9333 |
| multi-finding-projects | StructRisk+LLM-LCR | 5 | 1.0000 | 1.8000 | 0.9679 | 0.9679 | 1.0000 | 0.9333 |

## Per-Project Rows

| Method | Project | Findings | Positives | HR@1 | HR@3 | NDCG@5 | MRR | MAP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Public-Severity | binaryen | 7 | 1 | 0.1429 | 0.4286 | 0.4212 | 0.3704 | 0.3704 |
| Public-Severity | openbabel | 3 | 2 | 0.6667 | 2.0000 | 0.8710 | 0.8333 | 0.8056 |
| Public-Severity | squirrel | 10 | 2 | 0.2000 | 0.6000 | 0.3616 | 0.4287 | 0.3715 |
| Public-Severity | wabt | 5 | 2 | 0.4000 | 1.2000 | 0.7231 | 0.6417 | 0.5925 |
| Public-Severity | xlnt | 15 | 2 | 0.1333 | 0.4000 | 0.2410 | 0.3312 | 0.2768 |
| Support-Count | binaryen | 7 | 1 | 0.0000 | 0.0000 | 0.4307 | 0.2500 | 0.2500 |
| Support-Count | openbabel | 3 | 2 | 0.6667 | 2.0000 | 0.8710 | 0.8333 | 0.8056 |
| Support-Count | squirrel | 10 | 2 | 1.0000 | 1.6667 | 0.9323 | 1.0000 | 0.8611 |
| Support-Count | wabt | 5 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
| Support-Count | xlnt | 15 | 2 | 0.0000 | 0.5000 | 0.3644 | 0.2917 | 0.3157 |
| Artifact-Completeness | binaryen | 7 | 1 | 0.0000 | 0.0000 | 0.0000 | 0.1429 | 0.1429 |
| Artifact-Completeness | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| Artifact-Completeness | squirrel | 10 | 2 | 1.0000 | 1.6667 | 0.9323 | 1.0000 | 0.8611 |
| Artifact-Completeness | wabt | 5 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
| Artifact-Completeness | xlnt | 15 | 2 | 0.0000 | 0.5000 | 0.3644 | 0.2917 | 0.3157 |
| ASan-Severity | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| ASan-Severity | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| ASan-Severity | squirrel | 10 | 2 | 0.6667 | 2.0000 | 0.8710 | 0.8333 | 0.8056 |
| ASan-Severity | wabt | 5 | 2 | 0.4000 | 1.2000 | 0.7231 | 0.6417 | 0.5925 |
| ASan-Severity | xlnt | 15 | 2 | 0.3333 | 1.0000 | 0.6026 | 0.5800 | 0.5267 |
| Crash-State | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Crash-State | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| Crash-State | squirrel | 10 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| Crash-State | wabt | 5 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
| Crash-State | xlnt | 15 | 2 | 0.5000 | 1.5000 | 0.7853 | 0.7500 | 0.6667 |
| StackDedup-kNN | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| StackDedup-kNN | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| StackDedup-kNN | squirrel | 10 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| StackDedup-kNN | wabt | 5 | 2 | 0.4000 | 1.2000 | 0.7231 | 0.6417 | 0.5925 |
| StackDedup-kNN | xlnt | 15 | 2 | 1.0000 | 1.5000 | 0.9118 | 1.0000 | 0.8208 |
| CASR-Severity | binaryen | 7 | 1 | 0.0000 | 1.0000 | 0.5000 | 0.3333 | 0.3333 |
| CASR-Severity | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| CASR-Severity | squirrel | 10 | 2 | 0.0000 | 1.0000 | 0.4737 | 0.3333 | 0.3722 |
| CASR-Severity | wabt | 5 | 2 | 1.0000 | 1.0000 | 0.8772 | 1.0000 | 0.7500 |
| CASR-Severity | xlnt | 15 | 2 | 0.0000 | 0.0000 | 0.0000 | 0.1548 | 0.1894 |
| LLM-CardScore | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| LLM-CardScore | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| LLM-CardScore | squirrel | 10 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| LLM-CardScore | wabt | 5 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| LLM-CardScore | xlnt | 15 | 2 | 0.5000 | 1.5000 | 0.7853 | 0.7500 | 0.6667 |
| StructRisk | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| StructRisk | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9599 | 1.0000 | 0.9167 |
| StructRisk | squirrel | 10 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| StructRisk | wabt | 5 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
| StructRisk | xlnt | 15 | 2 | 0.0000 | 1.0000 | 0.6108 | 0.4167 | 0.4583 |
| StructRisk+LLM-LCR | binaryen | 7 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| StructRisk+LLM-LCR | openbabel | 3 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
| StructRisk+LLM-LCR | squirrel | 10 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| StructRisk+LLM-LCR | wabt | 5 | 2 | 1.0000 | 2.0000 | 1.0000 | 1.0000 | 1.0000 |
| StructRisk+LLM-LCR | xlnt | 15 | 2 | 1.0000 | 2.0000 | 0.9197 | 1.0000 | 0.8333 |
