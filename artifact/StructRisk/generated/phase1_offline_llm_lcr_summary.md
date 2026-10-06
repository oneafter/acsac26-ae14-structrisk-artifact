# Local Tie-Resolution Summary

This variant keeps the StructRisk block order and uses leakage-controlled LLM card scores only to reorder project-local findings within the same half-point structured-score band and weak-evidence bucket. Source-site novelty is applied greedily as a deterministic secondary tie-break when LLM-card scores do not distinguish siblings.

## Metrics

- `HighRisk@5=5`
- `NDCG@5=1.0`
- `HighRisk@10=8`
- `NDCG@10=0.8522`
- `Rank-to-First-HighRisk=1`
- `Effort-to-First-HighRisk=8.03`
- `Effort-per-HighRisk=54.73`

## Project Blocks

| Project | Findings | Blocks | Reranked Blocks | Reranked Items |
| --- | ---: | ---: | ---: | ---: |
| ChaiScript | 1 | 1 | 0 | 0 |
| LIEF | 2 | 1 | 0 | 0 |
| OpenCC | 1 | 1 | 0 | 0 |
| berry | 1 | 1 | 0 | 0 |
| binaryen | 7 | 5 | 0 | 0 |
| ettercap | 1 | 1 | 0 | 0 |
| janet | 1 | 1 | 0 | 0 |
| libfastcommon | 1 | 1 | 0 | 0 |
| lobster | 1 | 1 | 0 | 0 |
| mapnik | 25 | 3 | 0 | 0 |
| micropython | 1 | 1 | 0 | 0 |
| minisat | 1 | 1 | 0 | 0 |
| mruby | 1 | 1 | 0 | 0 |
| openbabel | 3 | 2 | 0 | 0 |
| squirrel | 10 | 5 | 0 | 0 |
| wabt | 5 | 3 | 1 | 3 |
| wasm3 | 1 | 1 | 0 | 0 |
| xlnt | 15 | 5 | 2 | 9 |

## Largest Reranked Blocks

| Rank | Finding | Project | Risk | Block Size | Base Score | LLM Card Score |
| ---: | --- | --- | ---: | ---: | ---: | ---: |
| 27 | `mapnik::finding::02232826` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 28 | `mapnik::finding::03124433` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 29 | `mapnik::finding::04743511` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 30 | `mapnik::finding::12744192` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 31 | `mapnik::finding::14853822` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 32 | `mapnik::finding::19391071` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 33 | `mapnik::finding::20318148` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 34 | `mapnik::finding::25077006` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 35 | `mapnik::finding::26295077` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 36 | `mapnik::finding::36813821` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 37 | `mapnik::finding::39223286` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 38 | `mapnik::finding::43199846` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 39 | `mapnik::finding::52761149` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 40 | `mapnik::finding::54248217` | mapnik | 0 | 16 | 4.2554 | 3.2500 |
| 41 | `mapnik::finding::54325806` | mapnik | 0 | 16 | 4.2554 | 3.1820 |
| 42 | `mapnik::finding::56498363` | mapnik | 0 | 16 | 4.2554 | 3.1820 |
| 17 | `mapnik::finding::00519280` | mapnik | 0 | 8 | 4.8338 | 5.0400 |
| 18 | `mapnik::finding::14134123` | mapnik | 0 | 8 | 4.8338 | 4.9680 |
| 19 | `mapnik::finding::15912203` | mapnik | 0 | 8 | 4.8338 | 4.9680 |
| 20 | `mapnik::finding::20511330` | mapnik | 0 | 8 | 4.8338 | 4.9680 |
