# Crash-State Baseline Summary

## Metrics
- `HighRisk@5=2`
- `NDCG@5=0.3836`
- `HighRisk@10=4`
- `NDCG@10=0.3885`
- `Rank-to-First-HighRisk=2`
- `Effort-to-First-HighRisk=16.45`
- `Effort-per-HighRisk=54.73`

## Top-10 Findings
- `1`. `ChaiScript::finding::11793711` risk=0 score=22.5 asan=`heap-use-after-free` loc=`/src/ChaiScript/static_libs/../include/chaiscript/language/../dispatchkit/../chaiscript_defines.hpp:201:49`
- `2`. `squirrel::finding::35854739` risk=3 score=12.7226 asan=`heap-buffer-overflow` loc=`/src/squirrel/squirrel/sqobject.h:269:16`
- `3`. `binaryen::finding::36473443` risk=3 score=12.5493 asan=`heap-buffer-overflow` loc=`/src/binaryen/src/wasm/wasm-binary.cpp:4736:10`
- `4`. `janet::finding::14567654` risk=0 score=12.5 asan=`heap-buffer-overflow` loc=`/src/janet/src/core/specials.c:311:32`
- `5`. `mruby::finding::69853620` risk=0 score=12.5 asan=`heap-buffer-overflow` loc=`/src/mruby/src/vm.c:1953:43`
- `6`. `OpenCC::finding::96413572` risk=0 score=12.4222 asan=`heap-buffer-overflow` loc=`/src/OpenCC/src/MaxMatchSegmentation.cpp:34:41`
- `7`. `xlnt::finding::77280579` risk=3 score=12.4024 asan=`heap-buffer-overflow` loc=`/src/xlnt/source/detail/cryptography/compound_document.cpp:131:44`
- `8`. `xlnt::finding::93136174` risk=0 score=12.4024 asan=`heap-buffer-overflow` loc=`/src/xlnt/source/detail/cryptography/base64.cpp:148:36`
- `9`. `squirrel::finding::11477017` risk=3 score=12.3466 asan=`heap-buffer-overflow` loc=`/src/squirrel/squirrel/sqfuncstate.cpp:290:41`
- `10`. `xlnt::finding::17141216` risk=0 score=12.3466 asan=`heap-buffer-overflow` loc=`/src/xlnt/source/detail/cryptography/base64.cpp:176:32`
