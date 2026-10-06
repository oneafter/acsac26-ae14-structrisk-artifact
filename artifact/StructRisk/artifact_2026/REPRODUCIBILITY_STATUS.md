# Reproducibility Status

The default verifier writes regenerated outputs under `StructRisk/reproduced/`
and never overwrites the shipped canonical files under `StructRisk/generated/`.

| Paper result | Default verification | Inputs |
| --- | --- | --- |
| Table 3 global ranking | Recomputed, except CASR replay | Shipped Eval findings; cached CASR ranking |
| Table 4 within-project ranking | Metrics recomputed; LLM-LCR ranking regenerated | Shipped method rankings and cached LLM-card scores |
| Table 5 ablation | Recomputed | Shipped Eval findings and fixed weights |
| Table 6 MAGMA | Recomputed | Shipped unified MAGMA slice and cached CASR ranking |
| Within-project exact p-values | Recomputed | Shipped project rankings |
| Global exact p-values | Checked against canonical output by default | Set `--full-statistics` to recompute |
| 77-variant sensitivity envelope | Checked against canonical output by default | Run `phase1_weight_sensitivity.py` for a full rerun |
| 58-variant signal-constant envelope (author response) | Recomputed by `claims/claim3.../run.sh` | Shipped Eval/within findings; theta fixed |
| Closed-model response generation | Cached only | Live API access is intentionally not required |
| CASR and raw MAGMA replay | Cached reports/slices only | Full source/replay environments are not bundled |

Run all default checks with:

```bash
bash StructRisk/artifact_2026/verify_paper_claims.sh all
```

The verifier checks its regenerated values against `PAPER_CLAIMS.json`, which
is transcribed from the ACSAC submission PDF identified in
`ARTIFACT_VERSION.txt`.
