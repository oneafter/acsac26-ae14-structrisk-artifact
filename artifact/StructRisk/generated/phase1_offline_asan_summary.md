# ASan-Severity Baseline Summary

## Metrics
- `HighRisk@5=1`
- `NDCG@5=0.1696`
- `HighRisk@10=1`
- `NDCG@10=0.11`
- `Rank-to-First-HighRisk=3`
- `Effort-to-First-HighRisk=24.7`
- `Effort-per-HighRisk=54.73`

## Top-10 Findings
- `1`. `ChaiScript::finding::11793711` risk=0 score=20.0 asan=`heap-use-after-free` loc=`/src/ChaiScript/static_libs/../include/chaiscript/language/../dispatchkit/../chaiscript_defines.hpp:201:49`
- `2`. `OpenCC::finding::96413572` risk=0 score=10.0 asan=`heap-buffer-overflow` loc=`/src/OpenCC/src/MaxMatchSegmentation.cpp:34:41`
- `3`. `binaryen::finding::36473443` risk=3 score=10.0 asan=`heap-buffer-overflow` loc=`/src/binaryen/src/wasm/wasm-binary.cpp:4736:10`
- `4`. `janet::finding::14567654` risk=0 score=10.0 asan=`heap-buffer-overflow` loc=`/src/janet/src/core/specials.c:311:32`
- `5`. `mapnik::finding::00519280` risk=0 score=10.0 asan=`heap-buffer-overflow` loc=`/src/mapnik/xml_output/default/crashes/id:000043`
- `6`. `mapnik::finding::02232826` risk=0 score=10.0 asan=`requested` loc=`/src/mapnik/xml_output/default/crashes/id:000014`
- `7`. `mapnik::finding::03124433` risk=0 score=10.0 asan=`requested` loc=`/src/mapnik/xml_output/default/crashes/id:000036`
- `8`. `mapnik::finding::04743511` risk=0 score=10.0 asan=`requested` loc=`/src/mapnik/xml_output/default/crashes/id:000011`
- `9`. `mapnik::finding::12744192` risk=0 score=10.0 asan=`requested` loc=`/src/mapnik/xml_output/default/crashes/id:000003`
- `10`. `mapnik::finding::14134123` risk=0 score=10.0 asan=`heap-buffer-overflow` loc=`/src/mapnik/xml_output/default/crashes/id:000018`
