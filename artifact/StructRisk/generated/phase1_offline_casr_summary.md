# CASR-Severity Baseline Summary

## Primary Metrics
- `HighRisk@5=1`
- `HighRisk@10=4`
- `NDCG@5=0.3392`
- `NDCG@10=0.4233`
- `Rank-to-First-HighRisk=1`
- `Effort-to-First-HighRisk=7.92`

## Top-10 Findings
- `1`. `wasm3::finding::30113371` risk=3 class=EXPLOITABLE score=5.0 tool=`casr-san` line=`/src/wasm3/source/m3_exec.h:968`
- `2`. `squirrel::finding::18752570` risk=0 class=PROBABLY_EXPLOITABLE score=4.0 tool=`casr-san` line=`/src/squirrel/sqstdlib/sqstdrex.cpp:85:32`
- `3`. `squirrel::finding::97123815` risk=0 class=PROBABLY_EXPLOITABLE score=4.0 tool=`casr-san` line=`/src/squirrel/squirrel/sqobject.h:215:15`
- `4`. `xlnt::finding::95930472` risk=0 class=PROBABLY_EXPLOITABLE score=4.0 tool=`casr-san` line=`/src/xlnt/source/../source/detail/binary.hpp:278:9`
- `5`. `binaryen::finding::56457462` risk=0 class=NOT_EXPLOITABLE score=0.25 tool=`casr-gdb` line=`/src/binaryen/src/wasm/wasm.cpp:1603`
- `6`. `binaryen::finding::79565612` risk=0 class=NOT_EXPLOITABLE score=0.25 tool=`casr-gdb` line=`/src/binaryen/build/lib/libbinaryen.so+0xbf5f35`
- `7`. `wabt::finding::28115182` risk=3 class=NOT_EXPLOITABLE score=0.25 tool=`casr-gdb` line=`/src/wabt/include/wabt/decompiler-ast.h:354`
- `8`. `xlnt::finding::82627332` risk=0 class=NOT_EXPLOITABLE score=0.25 tool=`casr-san` line=`/src/xlnt/source/detail/serialization/xlsx_consumer.cpp:2200:22`
- `9`. `squirrel::finding::35854739` risk=3 class=NOT_EXPLOITABLE score=0.25 tool=`casr-san` line=`/src/squirrel/squirrel/sqobject.h:269:16`
- `10`. `binaryen::finding::36473443` risk=3 class=NOT_EXPLOITABLE score=0.25 tool=`casr-san` line=`/src/binaryen/src/wasm/wasm-binary.cpp:4736:10`
