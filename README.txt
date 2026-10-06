StructRisk Public Artifact
==========================

Paper authors: GuanJi Yue, Xuan Yang, Shikun Zhang (Peking University)
DOI: https://doi.org/10.5281/zenodo.23191951
See README.md for the rendered DOI badge and public artifact overview.

This package follows the required paper-artifact layout:

  artifact/        Main code, processed data, and cached outputs.
  infrastructure/  Environment notes and dependency assumptions.
  claims/          Claim-specific reproduction scripts and expected outputs.
  install.sh       Lightweight environment check; no network access required.
  use.txt          Reviewer workflow and expected running time.
  license.txt      License and third-party-data notes for public distribution.
  verify_paper_claims.sh  Non-destructive submitted-PDF result verifier.
  ARTIFACT_VERSION.txt   Maintenance version and submitted-PDF SHA-256.

The artifact is designed for offline reproduction. It does not require live LLM/API
calls, network access, or Docker for the quick checks. The included scripts use
Python >= 3.10 and bash. The submitted package centers on the shipped processed
benchmark, evidence-card slices, ranked outputs, cached LLM responses, and CASR
logs needed to audit the reported claims.

Recommended quick start:

  ./install.sh
  bash verify_paper_claims.sh all

The verifier recomputes Tables 3--6 into reproduced/ and checks every value
against the submitted PDF without overwriting artifact/StructRisk/generated/.

Individual claim entry points:

  bash claims/claim1_global_queue/run.sh
  bash claims/claim2_within_project/run.sh
  bash claims/claim3_ablation_sensitivity/run.sh
  bash claims/claim4_magma_validation/run.sh

For the paper-level quick check, run:

  cd artifact
  bash StructRisk/artifact_2026/run_quick_check.sh

See REPRODUCIBILITY_STATUS.md for the precise recomputed-versus-cached scope.

Full global statistical verification (20,000 bootstrap resamples):

  bash verify_paper_claims.sh all --full-statistics --bootstrap-rounds 20000
