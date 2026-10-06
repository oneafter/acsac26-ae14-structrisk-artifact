# MAGMA Coverage Audit

This audit characterizes the full MAGMA bug inventory alongside the crash-backed validation slice used in the paper.

## Full Inventory

- Bug records: `138`
- Distinct CVEs: `125`
- HIGH or CRITICAL CVEs under preferred NVD CVSS: `84`
- Severity counts: CRITICAL=21, HIGH=63, LOW=1, MEDIUM=40
- Projects: `9`

## Unified Crash-Backed Evidence-Card Slice

- Input crash-backed artifacts: `1190`
- Deduplicated artifacts: `1154`
- Duplicate artifacts removed: `36`
- Deduplicated findings: `49`
- Projects: `9`
- HIGH-or-CRITICAL positives: `31`
- Distinct MAGMA bug IDs: `48`
- Distinct CVEs: `43`
- CVE coverage vs full inventory: `43/125` (34.4%)
- HIGH-or-CRITICAL CVE coverage vs full inventory: `29/84` (34.5%)

## Unified Crash-Backed Ranking

| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |
| --- | ---: | ---: | ---: | ---: |
| Oracle-CVSS | 10 | 1.0000 | 1.0000 | 1.0000 |
| Support-Count | 7 | 0.8588 | 0.8996 | 0.8673 |
| Artifact-Completeness | 7 | 0.8301 | 0.8803 | 0.8006 |
| ASan-Severity | 4 | 0.5131 | 0.8739 | 0.7875 |
| Crash-State | 7 | 0.7960 | 0.8793 | 0.7959 |
| StructRisk | 8 | 0.8923 | 0.9036 | 0.8714 |
| CASR-Severity | 7 | 0.8588 | 0.8996 | 0.8673 |

StackDedup-kNN is retained in the metrics JSON as an auxiliary learned-comparator diagnostic, but is omitted from the Markdown ranking tables to match the main-text MAGMA baseline set.

## Unified Project Coverage

| Project | Inv. CVEs | Inv. H/C | Slice Findings | Slice CVEs | Slice H/C | CVE Cov. | H/C Cov. |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| libpng | 6 | 3 | 4 | 3 | 1 | 50.0% | 33.3% |
| libsndfile | 13 | 6 | 1 | 0 | 0 | 0.0% | 0.0% |
| libtiff | 13 | 7 | 9 | 8 | 5 | 61.5% | 71.4% |
| libxml2 | 15 | 10 | 6 | 6 | 5 | 40.0% | 50.0% |
| lua | 3 | 1 | 1 | 1 | 0 | 33.3% | 0.0% |
| openssl | 20 | 12 | 5 | 4 | 3 | 20.0% | 25.0% |
| php | 16 | 16 | 3 | 3 | 3 | 18.8% | 18.8% |
| poppler | 19 | 10 | 12 | 10 | 5 | 52.6% | 50.0% |
| sqlite3 | 20 | 19 | 8 | 8 | 7 | 40.0% | 36.8% |

## Stricter Exact-Replay Crash-Backed Slice

- Raw artifacts: `1070`
- Deduplicated findings: `23`
- Projects: `9`
- HIGH-or-CRITICAL positives: `12`

## Stricter Exact-Replay Ranking

| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |
| --- | ---: | ---: | ---: | ---: |
| Oracle-CVSS | 10 | 1.0000 | 1.0000 | 1.0000 |
| Support-Count | 7 | 0.8588 | 1.0000 | 1.0000 |
| Artifact-Completeness | 7 | 0.8301 | 0.9645 | 0.8750 |
| ASan-Severity | 4 | 0.5098 | 0.9308 | 0.8125 |
| Crash-State | 7 | 0.7960 | 0.9645 | 0.8750 |
| StructRisk | 8 | 0.8923 | 0.9950 | 1.0000 |

## Public PoC Package Coverage

- Archive files scanned: `292357`
- Matched PoC files: `286644`
- Covered legacy bug IDs: `49/120`
- Covered legacy CVEs: `45`
- Covered HIGH-or-higher legacy bug IDs: `31`

## Broader Public-PoC Crash-Backed Reconstruction

- Raw crash-backed artifacts: `120`
- Deduplicated crash-backed findings: `46`
- Projects: `7`
- HIGH-or-CRITICAL positives: `30`

## Broader Public-PoC Crash-Backed Ranking

| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |
| --- | ---: | ---: | ---: | ---: |
| Oracle-CVSS | 10 | 1.0000 | 1.0000 | 1.0000 |
| Support-Count | 5 | 0.5909 | 0.8428 | 0.7226 |
| Artifact-Completeness | 4 | 0.6625 | 0.8531 | 0.7321 |
| ASan-Severity | 4 | 0.5586 | 0.8739 | 0.7875 |
| Crash-State | 5 | 0.5909 | 0.8428 | 0.7226 |
| StructRisk | 5 | 0.7343 | 0.8427 | 0.7292 |

## Interpretation

The full inventory audit is a severity-coverage characterization, not a claim that every MAGMA CVE was locally reproduced. The unified crash-backed slice deduplicates exact local replays and public-PoC replays into one evidence-card dataset. The stricter exact-replay and broader public-PoC component slices are retained as coverage diagnostics.
