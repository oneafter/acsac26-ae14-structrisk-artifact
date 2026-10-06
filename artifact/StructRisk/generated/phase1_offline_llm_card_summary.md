# LLM-CardScore Baseline Summary

This baseline directly scores anonymized evidence cards with an LLM. Prompts use opaque IDs and exclude project names, CVE identifiers, public scores, public labels, disclosure links, and outcome fields.

## Metrics

- `HighRisk@5=4`
- `NDCG@5=0.8539`
- `HighRisk@10=5`
- `NDCG@10=0.6275`
- `Rank-to-First-HighRisk=1`
- `Effort-to-First-HighRisk=8.03`
- `Effort-per-HighRisk=54.73`

## Top-15 Findings

| Rank | Finding | Risk | Score | Status | Reason |
| ---: | --- | ---: | ---: | --- | --- |
| 1 | `squirrel::finding::35854739` | 3 | 8.6450 | accepted | Exact 'heap-buffer-overflow' with concrete location 'sqobject.h:269:16'.; Support is 'many' with 5 samples. |
| 2 | `binaryen::finding::36473443` | 3 | 8.1000 | accepted | Exact report has AddressSanitizer heap-buffer-overflow.; Concrete source location is wasm-binary.cpp:4736:10. |
| 3 | `xlnt::finding::77280579` | 3 | 8.0960 | accepted | Exact 'heap-buffer-overflow' with concrete location 'compound_document.cpp:131:44'.; Support is 'several' with 4 samples. |
| 4 | `xlnt::finding::93136174` | 0 | 8.0960 | accepted | Exact 'heap-buffer-overflow' with concrete location 'base64.cpp:148:36'.; Support is 'several' with 4 samples. |
| 5 | `squirrel::finding::11477017` | 3 | 7.7400 | accepted | Exact 'heap-buffer-overflow' with concrete location 'sqfuncstate.cpp:290:41'.; Support is 'few' with 3 samples. |
| 6 | `xlnt::finding::17141216` | 0 | 7.5650 | accepted | Exact 'heap-buffer-overflow' with concrete location 'base64.cpp:176:32'.; Support is 'few' with 3 samples. |
| 7 | `xlnt::finding::50111272` | 3 | 7.5650 | accepted | Exact 'heap-buffer-overflow' with concrete location 'binary.hpp:278:9'.; Support is 'few' with 3 samples. |
| 8 | `xlnt::finding::61192659` | 0 | 7.3920 | accepted | Exact 'heap-buffer-overflow' with concrete location 'compound_document.cpp:975:34'.; Support is 'few' with 2 samples. |
| 9 | `xlnt::finding::88533031` | 0 | 7.3920 | accepted | Exact 'heap-buffer-overflow' with concrete location 'compound_document.hpp:83:30'.; Support is 'few' with 2 samples. |
| 10 | `mruby::finding::69853620` | 0 | 6.9520 | accepted | 'heap-buffer-overflow' is a strong memory-safety signal.; 'vm.c:1953:43' provides a concrete location and exit observation is '1'. |
| 11 | `minisat::finding::34831345` | 3 | 6.8040 | accepted | Exact 'heap-buffer-overflow' with a concrete source location.; 'SolverTypes.h:105:64' localizes the fault precisely. |
| 12 | `openbabel::finding::70823212` | 3 | 6.8040 | accepted | Exact 'heap-buffer-overflow' with a concrete source location.; 'transform3d.cpp:60:18' localizes the fault precisely. |
| 13 | `janet::finding::14567654` | 0 | 6.7240 | accepted | AddressSanitizer reports heap-buffer-overflow with a concrete source location.; Assertion excerpt includes assert failure. |
| 14 | `OpenCC::finding::96413572` | 0 | 6.6420 | accepted | AddressSanitizer reports heap-buffer-overflow with a concrete source location.; Support is many across 2 campaigns with 5 sample crashes. |
| 15 | `binaryen::finding::56457462` | 0 | 6.2900 | accepted | Exact report contains a concrete assertion failure.; Source location is wasm.cpp:1603. |
