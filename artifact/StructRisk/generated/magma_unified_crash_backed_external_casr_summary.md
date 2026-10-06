# MAGMA CASR-Severity Summary

- Findings: `49`
- Findings input: `StructRisk/generated/magma_unified_crash_backed_findings.jsonl`
- Artifact input: `StructRisk/generated/magma_unified_crash_backed_enriched_artifacts.jsonl`

## Global Ranking

| HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 7 | 0.9031 | 0.8588 | 1 |

## Within-Project Ranking

| Projects | HR@1 | HR@3 | NDCG@5 | MRR | MAP |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.8571 | 2.2857 | 0.8996 | 0.9286 | 0.8673 |

## Replay Status

- `nonzero-1`: `2`
- `ok`: `47`

## Severity Classes

- `NOT_EXPLOITABLE`: `47`
- `UNAVAILABLE`: `2`

## Top Ranked Findings

- `libpng::finding::67434740`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `openssl::finding::03878095`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `libpng::finding::62769382`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `openssl::finding::13673498`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `openssl::finding::41121969`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `libxml2::finding::60185483`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `poppler::finding::66183385`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `openssl::finding::35015455`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `libtiff::finding::05708836`: class=NOT_EXPLOITABLE score=0.25 status=ok
- `openssl::finding::72604430`: class=NOT_EXPLOITABLE score=0.25 status=ok
