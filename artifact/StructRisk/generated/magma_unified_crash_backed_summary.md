# MAGMA Unified Crash-Backed Evidence-Card Slice

## Inputs

- `StructRisk/generated/magma_local_crash_backed_enriched_artifacts.jsonl`
- `StructRisk/generated/magma_poc49_crash_backed_enriched_artifacts.jsonl` (component intermediate not bundled)

The anonymous artifact includes the derived unified evidence-card slice and coverage summaries; larger public-PoC replay intermediates are not bundled.

## Coverage

- Input crash-backed artifacts: `1190`
- Deduplicated artifacts: `1154`
- Duplicate artifacts removed: `36`
- Deduplicated findings: `49`
- Projects: `9`
- HIGH-or-CRITICAL positives: `31`
- Distinct MAGMA bug IDs: `48`
- Distinct CVEs: `43`

## Artifact Sources

- `magma_local` input artifacts: `1070`
- `magma_poc49` input artifacts: `120`
- `magma_local` retained artifacts: `1034`
- `magma_local+magma_poc49` retained artifacts: `36`
- `magma_poc49` retained artifacts: `84`

## Project Summary

- `libpng`: findings=4, positives=1, avg_support=194.0, avg_site_anchor=0.5, avg_locality=0.85
- `libsndfile`: findings=1, positives=0, avg_support=1.0, avg_site_anchor=0.5, avg_locality=0.85
- `libtiff`: findings=9, positives=6, avg_support=3.22, avg_site_anchor=0.5, avg_locality=0.85
- `libxml2`: findings=6, positives=5, avg_support=4.83, avg_site_anchor=0.5, avg_locality=0.85
- `lua`: findings=1, positives=0, avg_support=1.0, avg_site_anchor=0.5, avg_locality=0.85
- `openssl`: findings=5, positives=4, avg_support=48.4, avg_site_anchor=0.5, avg_locality=0.85
- `php`: findings=3, positives=3, avg_support=3.33, avg_site_anchor=0.5, avg_locality=0.85
- `poppler`: findings=12, positives=5, avg_support=3.5, avg_site_anchor=0.5, avg_locality=0.85
- `sqlite3`: findings=8, positives=7, avg_support=3.0, avg_site_anchor=0.5, avg_locality=0.85

## Example Cards

- `libpng::finding::67434740` (libpng): bugs=AAH003, cves=CVE-2015-8472, asan=DEADLYSIGNAL
- `libpng::finding::62769382` (libpng): bugs=AAH008, cves=CVE-2013-6954, asan=DEADLYSIGNAL
- `libpng::finding::46928917` (libpng): bugs=AAH001, cves=CVE-2018-13785, asan=DEADLYSIGNAL
- `libpng::finding::56002180` (libpng): bugs=AAH007, cves=n/a, asan=DEADLYSIGNAL
- `libsndfile::finding::56933028` (libsndfile): bugs=SND017, cves=n/a, asan=DEADLYSIGNAL
- `libtiff::finding::05708836` (libtiff): bugs=AAH015, cves=CVE-2016-10270, asan=DEADLYSIGNAL
- `libtiff::finding::20831159` (libtiff): bugs=AAH020, cves=CVE-2016-3658, asan=DEADLYSIGNAL
- `libtiff::finding::35166028` (libtiff): bugs=AAH010, cves=CVE-2016-5314, asan=DEADLYSIGNAL
