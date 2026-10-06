# High-Risk Disclosure Alignment Summary

- Disclosure-backed HIGH cases: `23`
- HIGH cases whose project is present in phase-1: `23`
- Strong alignments: `23`
- Moderate alignments: `0`
- Weak alignments: `0`
- Unresolved / out-of-scope cases: `0`

| Project | CVE | Phase-1 | Match | Confidence | Score | Anchor | Candidate |
|---|---|---:|---|---|---:|---|---|
| berry | CVE-2026-3285 | 1 | berry::finding::66968453 | strong | 12 | target | exec-target:berry; risk3; singleton-project; singleton-disclosure-anchor |
| binaryen | CVE-2025-14956 | 1 | binaryen::finding::36473443 | strong | 17 | location | near-line:wasm/wasm-binary.cpp:4736->4736; asan-summary-match; risk3 |
| libfastcommon | CVE-2026-2016 | 1 | libfastcommon::finding::92700783 | strong | 12 | target | exec-target:fuzz_base64_decode; risk3; singleton-project; singleton-disclosure-anchor |
| lily | CVE-2026-2660 | 1 | lily::finding::96276758 | strong | 20 | location | near-line:lily_symtab.c:521->521; exec-target:lily; asan-summary-match; risk3 |
| lily | CVE-2026-2662 | 1 | lily::finding::42419355 | strong | 20 | location | near-line:lily_emitter.c:1341->1341; exec-target:lily; asan-summary-match; risk3 |
| minisat | CVE-2026-2644 | 1 | minisat::finding::34831345 | strong | 28 | location | near-line:core/solvertypes.h:105->105; exec-target:minisat; asan-summary-match; risk3; singleton-project; singleton-disclosure-anchor |
| openbabel | CVE-2026-2704 | 1 | openbabel::finding::70823212 | strong | 29 | location | near-line:math/transform3d.cpp:60->60; exec-target:obabel; format:cif; format-disclosure-anchor; asan-summary-match; risk3 |
| openbabel | CVE-2026-2705 | 1 | openbabel::finding::89823471 | strong | 13 | target | exec-target:obabel; format:mol2; format-disclosure-anchor; risk3 |
| raylib | CVE-2025-15533 | 1 | raylib::finding::68499575 | strong | 11 | harness | harness-text:harness_raylib_font; asan-summary-match; risk3 |
| raylib | CVE-2025-15534 | 1 | raylib::finding::24525527 | strong | 18 | harness | harness-text:harness_raylib_font; overflow-match; risk3; function:loadfontdata; function-with-loc |
| sokol | CVE-2025-14958 | 1 | sokol::finding::32012039 | strong | 20 | location | near-line:sokol_gfx.h:8148->8148; exec-target:harness_gfx_traditional_fuzzer; asan-summary-match; risk3 |
| sokol | CVE-2025-15155 | 1 | sokol::finding::63165553 | strong | 20 | location | near-line:sokol_gfx.h:24084->24084; exec-target:harness_gfx_traditional_fuzzer; asan-summary-match; risk3 |
| soloud | CVE-2026-3393 | 1 | soloud::finding::06044241 | strong | 17 | location | near-line:audiosource/wav/soloud_wav.cpp:257->257; asan-summary-match; risk3 |
| soloud | CVE-2026-3394 | 1 | soloud::finding::46506111 | strong | 18 | file | same-file:audiosource/wav/soloud_wav.cpp; asan-summary-match; risk3; function:loadmem; function-with-loc |
| squirrel | CVE-2026-2659 | 1 | squirrel::finding::11477017 | strong | 20 | location | near-line:squirrel/squirrel/sqfuncstate.cpp:290->290; exec-target:sq; asan-summary-match; risk3 |
| squirrel | CVE-2026-2661 | 1 | squirrel::finding::35854739 | strong | 20 | location | near-line:squirrel/sqobject.h:269->269; exec-target:sq; asan-summary-match; risk3 |
| wabt | CVE-2025-15411 | 1 | wabt::finding::28115182 | strong | 12 | target-text | target-text:wasm-decompile; risk3; function:insertnode; function-with-loc |
| wabt | CVE-2025-15412 | 1 | wabt::finding::73259399 | strong | 12 | target-text | target-text:wasm-decompile; risk3; function:decompileexpr; function-with-loc |
| wasm3 | CVE-2025-15413 | 1 | wasm3::finding::30113371 | strong | 20 | file | report-file:m3_exec.h; exec-target:wasm3; asan-summary-match; risk3; singleton-project; singleton-disclosure-anchor |
| wren | CVE-2026-2858 | 1 | wren::finding::49674825 | strong | 20 | location | near-line:vm/wren_compiler.c:641->641; exec-target:fuzz_wren; asan-summary-match; risk3 |
| wren | CVE-2026-3386 | 1 | wren::finding::13953049 | strong | 20 | location | near-line:vm/wren_compiler.c:1329->1329; exec-target:fuzz_wren; asan-summary-match; risk3 |
| xlnt | CVE-2026-3463 | 1 | xlnt::finding::50111272 | strong | 20 | location | near-line:source/detail/binary.hpp:278->278; exec-target:fuzz_xlnt; asan-summary-match; risk3 |
| xlnt | CVE-2026-3663 | 1 | xlnt::finding::77280579 | strong | 20 | location | near-line:source/detail/cryptography/compound_document.cpp:132->131; exec-target:fuzz_xlnt; asan-summary-match; risk3 |
