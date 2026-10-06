#!/usr/bin/env bash
set -euo pipefail
INPUT_TSV="${1:-CVE2SKETCH/examples/user75_cves.tsv}"
OUTPUT_CSV="${2:-StructRisk/structrisk_nvd_cvss31.csv}"
SLEEP_SECS="${3:-1}"
exec python3 StructRisk/scripts/fetch_nvd_cvss31.py "$INPUT_TSV" "$OUTPUT_CSV" "$SLEEP_SECS"
