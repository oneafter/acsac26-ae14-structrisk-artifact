# User 75 CVE Summary Tables

- Snapshot date: `2026-04-15`
- Severity source rule: use the highest available `CVSS v3.1` from the maintained summary workbook; preserve `MITRE_RESERVED` entries as `UNRESOLVED`.
- Detailed CSV: `StructRisk/user75_cve_summary.csv`
- TSV mirror: `CVE2SKETCH/examples/user75_cves.tsv`

## Severity Distribution

| Severity | Count |
| --- | --- |
| HIGH | 23 |
| MEDIUM | 35 |
| LOW | 14 |
| UNRESOLVED | 3 |

## Source Distribution

| CVSS Source | Count |
| --- | --- |
| nvd@nist.gov | 55 |
| cna@vuldb.com | 17 |
| MITRE_RESERVED | 3 |

## Vulnerability Type Distribution

| Vulnerability Type | Count |
| --- | --- |
| Out-Of-Bounds | 19 |
| Memory Corruption | 11 |
| NULL Pointer Dereference | 11 |
| Heap-based Buffer Overflow | 10 |
| Stack-based Buffer Overflow | 6 |
| Use After Free | 5 |
| Uncontrolled Recursion | 5 |
| Divide By Zero | 2 |
| Denial of Service | 2 |
| Integer Overflow | 1 |
| Memory Leak | 1 |
| Off-By-One | 1 |
| Out-Of-Bounds Read | 1 |

## Detailed Records

| index | project | stars | vuln_type | cve_id | cvss31_score | cvss31_severity | cvss31_source | vuln_status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 83 | openbabel | 1.3k | Out-Of-Bounds | CVE-2026-2704 | 8.1 | HIGH | nvd@nist.gov | Modified |
| 84 | openbabel | 1.3k | Out-Of-Bounds | CVE-2026-2705 | 8.1 | HIGH | nvd@nist.gov | Modified |
| 91 | berry | 1k | Out-Of-Bounds | CVE-2026-3285 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 44 | libfastcommon | 0.9k | Stack-based Buffer Overflow | CVE-2026-2016 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 73 | lily | 1.1k | Use After Free | CVE-2026-2660 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 74 | lily | 1.1k | Out-Of-Bounds | CVE-2026-2662 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 57 | minisat | 1.1k | Out-Of-Bounds | CVE-2026-2644 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 32 | raylib | 31.5k | Heap-based Buffer Overflow | CVE-2025-15533 | 7.8 | HIGH | nvd@nist.gov | Modified |
| 33 | raylib | 31.5k | Integer Overflow | CVE-2025-15534 | 7.8 | HIGH | nvd@nist.gov | Modified |
| 23 | sokol | 9.7k | Heap-based Buffer Overflow | CVE-2025-14958 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 25 | sokol | 9.7k | Stack-based Buffer Overflow | CVE-2025-15155 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 87 | soloud | 2.1k | Heap-based Buffer Overflow | CVE-2026-3393 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 88 | soloud | 2.1k | Memory Corruption | CVE-2026-3394 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 68 | squirrel | 1.0k | Out-Of-Bounds | CVE-2026-2659 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 69 | squirrel | 1.0k | Heap-based Buffer Overflow | CVE-2026-2661 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 26 | wabt | 7.9k | Heap-based Buffer Overflow | CVE-2025-15411 | 7.8 | HIGH | nvd@nist.gov | Modified |
| 27 | wabt | 7.9k | Memory Corruption | CVE-2025-15412 | 7.8 | HIGH | nvd@nist.gov | Modified |
| 28 | wasm3 | 7.9k | Memory Corruption | CVE-2025-15413 | 7.8 | HIGH | nvd@nist.gov | Modified |
| 79 | xlnt | 1.6k | Heap-based Buffer Overflow | CVE-2026-3463 | 7.8 | HIGH | nvd@nist.gov | Analyzed |
| 21 | binaryen | 8.4k | Heap-based Buffer Overflow | CVE-2025-14956 | 7.1 | HIGH | nvd@nist.gov | Modified |
| 64 | wren | 7.9k | Out-Of-Bounds | CVE-2026-2858 | 7.1 | HIGH | nvd@nist.gov | Analyzed |
| 66 | wren | 7.9k | Out-Of-Bounds | CVE-2026-3386 | 7.1 | HIGH | nvd@nist.gov | Analyzed |
| 80 | xlnt | 1.6k | Out-Of-Bounds | CVE-2026-3663 | 7.1 | HIGH | nvd@nist.gov | Analyzed |
| 85 | openbabel | 1.3k | NULL Pointer Dereference | CVE-2026-3408 | 6.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 45 | janet | 4.2k | Out-Of-Bounds | CVE-2026-2240 | 6.1 | MEDIUM | nvd@nist.gov | Analyzed |
| 46 | janet | 4.2k | Out-Of-Bounds | CVE-2026-2241 | 6.1 | MEDIUM | nvd@nist.gov | Analyzed |
| 47 | janet | 4.2k | Out-Of-Bounds | CVE-2026-2242 | 6.1 | MEDIUM | nvd@nist.gov | Analyzed |
| 39 | smartdns | 10.6k | Stack-based Buffer Overflow | CVE-2026-1425 | 5.6 | MEDIUM | cna@vuldb.com | Awaiting Analysis |
| 22 | binaryen | 8.4k | NULL Pointer Dereference | CVE-2025-14957 | 5.5 | MEDIUM | nvd@nist.gov | Modified |
| 60 | ChaiScript | 3.1k | Memory Corruption | CVE-2026-3382 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 61 | ChaiScript | 3.1k | Uncontrolled Recursion | CVE-2026-3383 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 62 | ChaiScript | 3.1k | Divide By Zero | CVE-2026-3384 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 92 | ettercap | 2.7k | Out-Of-Bounds | CVE-2026-3606 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 48 | janet | 4.2k | Out-Of-Bounds | CVE-2026-2869 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 42 | libuvc | 1.1k | NULL Pointer Dereference | CVE-2026-1991 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 30 | LIEF | 5.3k | NULL Pointer Dereference | CVE-2025-15504 | 5.5 | MEDIUM | nvd@nist.gov | Modified |
| 75 | lily | 1.1k | Out-Of-Bounds | CVE-2026-3390 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 76 | lily | 1.1k | Out-Of-Bounds | CVE-2026-3391 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 77 | lily | 1.1k | NULL Pointer Dereference | CVE-2026-3392 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 52 | lobster | 2.7k | Memory Corruption | CVE-2026-2258 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 53 | lobster | 2.7k | Memory Corruption | CVE-2026-2259 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 54 | lobster | 2.7k | Uncontrolled Recursion | CVE-2026-2887 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 36 | mapnik | 3.9k | Heap-based Buffer Overflow | CVE-2025-15537 | 5.5 | MEDIUM | nvd@nist.gov | Modified |
| 37 | mapnik | 3.9k | Divide By Zero | CVE-2025-15564 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 43 | micropython | 21.5k | Memory Corruption | CVE-2026-1998 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 40 | mruby | 5.5k | Use After Free | CVE-2026-1979 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 35 | OpenCC | 9.5k | Heap-based Buffer Overflow | CVE-2025-15536 | 5.5 | MEDIUM | nvd@nist.gov | Modified |
| 70 | squirrel | 1.0k | Uncontrolled Recursion | CVE-2026-3388 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 71 | squirrel | 1.0k | NULL Pointer Dereference | CVE-2026-3389 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 29 | wasm3 | 7.9k | Memory Leak | CVE-2025-15572 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 63 | wren | 7.9k | Stack-based Buffer Overflow | CVE-2026-2657 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 65 | wren | 7.9k | Uncontrolled Recursion | CVE-2026-3385 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 67 | wren | 7.9k | NULL Pointer Dereference | CVE-2026-3387 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 78 | xlnt | 1.6k | Off-By-One | CVE-2026-2703 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 81 | xlnt | 1.6k | Out-Of-Bounds | CVE-2026-3664 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 82 | xlnt | 1.6k | NULL Pointer Dereference | CVE-2026-3665 | 5.5 | MEDIUM | nvd@nist.gov | Analyzed |
| 24 | sokol | 9.7k | Stack-based Buffer Overflow | CVE-2025-15013 | 5.3 | MEDIUM | cna@vuldb.com | Awaiting Analysis |
| 20 | whisper.cpp | 47.4k | Use After Free | CVE-2025-14569 | 5.3 | MEDIUM | cna@vuldb.com | Awaiting Analysis |
| 51 | apriltag | 2.2k | Memory Corruption | CVE-2026-2246 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 49 | ccextractor | 0.8k | Out-Of-Bounds | CVE-2026-2245 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 50 | ccextractor | 0.8k | Memory Corruption | CVE-2026-2889 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 55 | ctags | 7.1k | Uncontrolled Recursion | CVE-2026-2641 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 95 | fe | 1.5k | Memory Corruption | CVE-2026-4012 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 41 | oatpp | 8.6k | NULL Pointer Dereference | CVE-2026-1990 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 31 | OpenColorIO | 2k | Out-Of-Bounds Read | CVE-2025-15506 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 94 | pocketlang | 1.5k | Memory Corruption | CVE-2026-4010 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 86 | re2c | 1.3k | NULL Pointer Dereference | CVE-2026-2903 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 89 | soloud | 2.1k | Out-Of-Bounds | CVE-2026-4009 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 56 | the_silver_searcher | 27.2k | NULL Pointer Dereference | CVE-2026-2642 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 90 | yosys | 4.3k | Heap-based Buffer Overflow | CVE-2026-3407 | 3.3 | LOW | cna@vuldb.com | Awaiting Analysis |
| 58 | ChaiScript | 3.1k | Use After Free | CVE-2026-2655 | 2.5 | LOW | cna@vuldb.com | Analyzed |
| 59 | ChaiScript | 3.1k | Use After Free | CVE-2026-2656 | 2.5 | LOW | cna@vuldb.com | Analyzed |
| 96 | assimp | 12.7k | Denial of Service | CVE-2026-26510 |  | UNRESOLVED | MITRE_RESERVED | MITRE Reserved |
| 38 | lede | 31.3k | Stack-based Buffer Overflow | CVE-2025-69895 |  | UNRESOLVED | MITRE_RESERVED | MITRE Reserved |
| 72 | squirrel | 1.0k | Denial of Service | CVE-2026-30725 |  | UNRESOLVED | MITRE_RESERVED | MITRE Reserved |
