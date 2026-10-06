# Local Tie-Resolution Summary

This variant keeps the StructRisk block order and uses leakage-controlled LLM card scores only to reorder project-local findings within the same half-point structured-score band and weak-evidence bucket. Source-site novelty is applied greedily as a deterministic secondary tie-break when LLM-card scores do not distinguish siblings.

## Metrics

- `HighRisk@5=4`
- `NDCG@5=0.6608`
- `HighRisk@10=6`
- `NDCG@10=0.5619`
- `Rank-to-First-HighRisk=2`
- `Effort-to-First-HighRisk=16.06`
- `Effort-per-HighRisk=39.2`

## Project Blocks

| Project | Findings | Blocks | Reranked Blocks | Reranked Items |
| --- | ---: | ---: | ---: | ---: |
| binaryen | 7 | 5 | 0 | 0 |
| lily | 6 | 5 | 1 | 2 |
| openbabel | 3 | 2 | 0 | 0 |
| raylib | 13 | 8 | 2 | 5 |
| sokol | 5 | 4 | 1 | 2 |
| soloud | 12 | 9 | 1 | 2 |
| squirrel | 10 | 5 | 0 | 0 |
| wabt | 5 | 3 | 1 | 3 |
| wren | 6 | 5 | 0 | 0 |
| xlnt | 15 | 5 | 2 | 9 |

## Largest Reranked Blocks

| Rank | Finding | Project | Risk | Block Size | Base Score | LLM Card Score |
| ---: | --- | --- | ---: | ---: | ---: | ---: |
| 51 | `xlnt::finding::14746173` | xlnt | 0 | 5 | 3.5566 | 3.4000 |
| 52 | `xlnt::finding::27458735` | xlnt | 0 | 5 | 3.5566 | 3.4000 |
| 53 | `xlnt::finding::30095594` | xlnt | 0 | 5 | 3.5566 | 3.4000 |
| 54 | `xlnt::finding::55028362` | xlnt | 0 | 5 | 3.5566 | 3.4000 |
| 46 | `xlnt::finding::95930472` | xlnt | 0 | 5 | 3.6695 | 3.4000 |
| 40 | `squirrel::finding::18752570` | squirrel | 0 | 4 | 3.7769 | 3.4680 |
| 37 | `squirrel::finding::53286305` | squirrel | 0 | 4 | 3.8633 | 4.4840 |
| 41 | `squirrel::finding::62580704` | squirrel | 0 | 4 | 3.7769 | 3.4680 |
| 38 | `squirrel::finding::79491293` | squirrel | 0 | 4 | 3.8633 | 4.4840 |
| 16 | `xlnt::finding::17141216` | xlnt | 0 | 4 | 5.2708 | 7.5650 |
| 17 | `xlnt::finding::50111272` | xlnt | 3 | 4 | 5.2708 | 7.5650 |
| 18 | `xlnt::finding::77280579` | xlnt | 3 | 4 | 5.2692 | 8.0960 |
| 12 | `xlnt::finding::93136174` | xlnt | 0 | 4 | 5.3866 | 8.0960 |
| 70 | `raylib::finding::15757185` | raylib | 0 | 3 | 2.3529 | 3.8480 |
| 68 | `raylib::finding::34428624` | raylib | 0 | 3 | 2.4509 | 4.9920 |
| 55 | `raylib::finding::56043074` | raylib | 0 | 3 | 3.5337 | 3.3280 |
| 69 | `raylib::finding::56198549` | raylib | 0 | 3 | 2.4509 | 4.2920 |
| 56 | `raylib::finding::75341785` | raylib | 0 | 3 | 3.5337 | 4.4240 |
| 47 | `raylib::finding::99878127` | raylib | 0 | 3 | 3.6601 | 4.3310 |
| 8 | `soloud::finding::06044241` | soloud | 3 | 3 | 5.5114 | 8.0990 |
