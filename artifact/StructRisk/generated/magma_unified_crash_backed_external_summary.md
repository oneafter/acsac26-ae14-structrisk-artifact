# MAGMA Crash-Backed Validation Summary

- Input: `StructRisk/generated/magma_unified_crash_backed_findings.jsonl`
- Train: `StructRisk/generated/phase1_offline_dev.jsonl`
- Findings: `49`
- Projects: `9`
- HIGH-or-CRITICAL positives: `31`
- Multi-finding projects: `7`

The structured `StructRisk` scores use the same frozen sign-constrained weights as the main phase-1 evaluation. The main-text MAGMA table uses Oracle-CVSS as a label-aware ceiling plus fixed crash-side baselines and CASR-Severity; auxiliary learned-comparator diagnostics are retained only in the metrics JSON.

## Main-Text Global Ranking

| Method | HR@10 | NDCG@10 |
| --- | ---: | ---: |
| Oracle-CVSS | 10 | 1.0000 |
| Support-Count | 7 | 0.8588 |
| Artifact-Completeness | 7 | 0.8301 |
| ASan-Severity | 4 | 0.5131 |
| Crash-State | 7 | 0.7960 |
| CASR-Severity | 7 | 0.8588 |
| StructRisk | 8 | 0.8923 |

## Notes

- `Oracle-CVSS` is a label-aware upper bound using public CVSS only for evaluation-oriented ordering.
- `Support-Count` is a transparent occurrence-count control.
- The generated metrics JSON also retains auxiliary HR@5/First-HR, StackDedup-kNN, and per-project diagnostics for audit; they are not separate main-text claims.
- `CASR-Severity` replays one representative crash per finding inside the corresponding MAGMA ASAN image; cached reports can be reused without MAGMA-side tuning.

## Diagnostic StructRisk Per-Project Rows

| Project | Findings | Positives | NDCG@5 | MAP |
| --- | ---: | ---: | ---: | ---: |
| libpng | 4 | 1 | 0.9800 | 1.0000 |
| libtiff | 9 | 6 | 0.8196 | 0.7885 |
| libxml2 | 6 | 5 | 0.8777 | 0.8100 |
| openssl | 5 | 4 | 1.0000 | 1.0000 |
| php | 3 | 3 | 1.0000 | 1.0000 |
| poppler | 12 | 5 | 0.6478 | 0.5190 |
| sqlite3 | 8 | 7 | 1.0000 | 0.9821 |
