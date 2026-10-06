# MAGMA Component Replay Diagnostic Summary

- Input: `StructRisk/generated/magma_poc49_crash_backed_findings.jsonl`
- Train: `StructRisk/generated/phase1_offline_dev.jsonl`
- Findings: `46`
- Projects: `7`
- HIGH-or-CRITICAL positives: `30`
- Multi-finding projects: `7`

This component replay diagnostic reuses the same frozen StructRisk scorer, but it is not the submitted MAGMA validation table. The submitted paper reports the unified crash-backed slice that deduplicates exact local replays and public-PoC replays.

## Diagnostic Global Ranking

| Method | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Oracle-CVSS | 5 | 10 | 1.0000 | 1.0000 | 1 |
| Support-Count | 2 | 5 | 0.4953 | 0.5909 | 4 |
| Artifact-Completeness | 3 | 4 | 0.7790 | 0.6625 | 1 |
| ASan-Severity | 2 | 4 | 0.4953 | 0.5586 | 4 |
| Crash-State | 2 | 5 | 0.4953 | 0.5909 | 4 |
| StackDedup-kNN | 2 | 4 | 0.4953 | 0.5586 | 4 |
| StructRisk | 3 | 5 | 0.7853 | 0.7343 | 1 |

## Diagnostic Within-Project Ranking

| Method | Projects | HR@1 | HR@3 | NDCG@5 | MRR | MAP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Oracle-CVSS | 7 | 1.0000 | 2.7143 | 1.0000 | 1.0000 | 1.0000 |
| Support-Count | 7 | 0.7143 | 2.0000 | 0.8428 | 0.8214 | 0.7226 |
| Artifact-Completeness | 7 | 0.7143 | 2.0000 | 0.8531 | 0.8214 | 0.7321 |
| ASan-Severity | 7 | 0.7143 | 2.2857 | 0.8739 | 0.8214 | 0.7875 |
| Crash-State | 7 | 0.7143 | 2.0000 | 0.8428 | 0.8214 | 0.7226 |
| StackDedup-kNN | 7 | 0.7143 | 2.2857 | 0.8739 | 0.8214 | 0.7875 |
| StructRisk | 7 | 0.7143 | 1.8571 | 0.8427 | 0.8214 | 0.7292 |

## Notes

- `Oracle-CVSS` is a label-aware upper bound using public CVSS only for evaluation-oriented ordering.
- `Support-Count` is a transparent occurrence-count control; `StackDedup-kNN` is trained only on the paper's internal phase-1 development split.
- This file is a component replay diagnostic retained for coverage auditing; the submitted MAGMA result is the unified crash-backed validation summary.

## Diagnostic StructRisk Per-Project Rows

| Project | Findings | Positives | NDCG@5 | MAP |
| --- | ---: | ---: | ---: | ---: |
| libpng | 4 | 1 | 0.6165 | 0.2500 |
| libtiff | 9 | 6 | 0.7808 | 0.6913 |
| libxml2 | 6 | 5 | 0.8062 | 0.7100 |
| openssl | 4 | 3 | 0.9506 | 0.8056 |
| php | 3 | 3 | 1.0000 | 1.0000 |
| poppler | 12 | 5 | 0.7447 | 0.6857 |
| sqlite3 | 8 | 7 | 1.0000 | 0.9617 |
