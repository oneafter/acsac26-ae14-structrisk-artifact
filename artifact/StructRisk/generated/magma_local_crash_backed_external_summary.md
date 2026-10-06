# MAGMA Component Replay Diagnostic Summary

- Input: `StructRisk/generated/magma_local_crash_backed_findings.jsonl`
- Train: `StructRisk/generated/phase1_offline_dev.jsonl`
- Findings: `23`
- Projects: `9`
- HIGH-or-CRITICAL positives: `12`
- Multi-finding projects: `5`

This component replay diagnostic reuses the same frozen StructRisk scorer, but it is not the submitted MAGMA validation table. The submitted paper reports the unified crash-backed slice that deduplicates exact local replays and public-PoC replays.

## Diagnostic Global Ranking

| Method | HR@10 | NDCG@10 |
| --- | ---: | ---: |
| Oracle-CVSS | 10 | 1.0000 |
| Support-Count | 7 | 0.8588 |
| Artifact-Completeness | 7 | 0.8301 |
| ASan-Severity | 4 | 0.5098 |
| Crash-State | 7 | 0.7960 |
| StructRisk | 8 | 0.8923 |

## Notes

- `Oracle-CVSS` is a label-aware upper bound using public CVSS only for evaluation-oriented ordering.
- `Support-Count` is a transparent occurrence-count control.
- The generated metrics JSON also retains auxiliary HR@5/First-HR, StackDedup-kNN, and per-project diagnostics for audit; they are not separate main-text claims.
- This file is a component replay diagnostic retained for coverage auditing; the submitted MAGMA result is the unified crash-backed validation summary.

## Diagnostic StructRisk Per-Project Rows

| Project | Findings | Positives | NDCG@5 | MAP |
| --- | ---: | ---: | ---: | ---: |
| libpng | 4 | 1 | 0.9800 | 1.0000 |
| libtiff | 4 | 2 | 1.0000 | 1.0000 |
| openssl | 5 | 4 | 1.0000 | 1.0000 |
| sqlite3 | 3 | 3 | 1.0000 | 1.0000 |
