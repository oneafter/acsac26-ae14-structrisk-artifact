# StructRisk — ACSAC 2026 Artifact

[![DOI](https://zenodo.org/badge/1362349573.svg)](https://doi.org/10.5281/zenodo.23191951)

StructRisk: Structured Post-Fuzz Ranking for High-Value Vulnerability Prioritization.

Paper authors: **GuanJi Yue, Xuan Yang, Shikun Zhang** (Peking University).

Permanent archive: [10.5281/zenodo.23191951](https://doi.org/10.5281/zenodo.23191951).

## Offline reproduction

Requirements: **Python 3.10+** and **bash**. The quick verification uses only the
Python standard library and runs without network access, API keys, or Docker.

```bash
./install.sh
bash verify_paper_claims.sh all
```

The verifier recomputes Tables 3–6 from the shipped processed benchmark, ranked
outputs, and cached responses. It writes results under `reproduced/` and compares
them with the submitted PDF values in
[`PAPER_CLAIMS.json`](artifact/StructRisk/artifact_2026/PAPER_CLAIMS.json).

Full global statistical verification with 20,000 bootstrap resamples:

```bash
bash verify_paper_claims.sh all --full-statistics --bootstrap-rounds 20000
```

Individual claims:

```bash
bash claims/claim1_global_queue/run.sh
bash claims/claim2_within_project/run.sh
bash claims/claim3_ablation_sensitivity/run.sh
bash claims/claim4_magma_validation/run.sh
```

## Package contents

| Path | Contents |
| --- | --- |
| `artifact/` | Ranking code, processed data, cached LLM responses, CASR reports, and MAGMA evidence slices |
| `claims/` | Claim-specific reproduction scripts and expected outputs |
| `infrastructure/` | Environment and dependency notes |
| [`use.txt`](use.txt) | Reproduction workflow and expected running time |
| [`ARTIFACT_VERSION.txt`](ARTIFACT_VERSION.txt) | Benchmark version and submitted-PDF SHA-256 |
| [`SHA256SUMS.txt`](SHA256SUMS.txt) | Distributed-file integrity checksums |
| [`license.txt`](license.txt) | MIT license reference and third-party data terms |

See the [detailed artifact guide](artifact/StructRisk/artifact_2026/README.md) and
the [reproducibility scope](REPRODUCIBILITY_STATUS.md) for the distinction between
recomputed results and cached evidence. Live LLM inference and original
CASR/MAGMA replay environments are separate from the offline verification.

The public package includes author information and public CVE disclosure links.
LLM prompts retain opaque finding IDs and exclude project names, CVE IDs, public
scores, and outcome fields to prevent evaluation leakage.

The research scripts use the MIT License. Derived benchmark data and
third-party materials remain subject to their original licenses and usage terms.
