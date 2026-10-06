#!/usr/bin/env python3
"""LOPO recalibration check for the signal-rule constants.

The within-project evaluation spans both splits, so five of its ten projects
belong to the Dev split on which the rule constants were calibrated. This
script applies to the constants the same leave-one-project-out discipline the
paper applies to StackDedup-kNN (Sec. 4.1): for each Dev project p, rerun the
like-for-like calibration search on Dev-minus-p (starting from the shipped
constants, as in phase1_constant_eval_tuning_check.py), then score p under the
fold's constants. Eval projects never entered calibration, so their fold
constants are trivially the shipped ones.

Measured result: the fold search moves ZERO constants on every Dev fold, so
LOPO scoring is identical to shipped scoring on every project -- the
10-project macro metrics (NDCG@5 0.8561, MAP 0.8167) and the exact tests
against Public-Severity are unchanged. No single Dev project drives the
calibrated values. Output: generated/phase1_constant_lopo_check.json
"""
import json, math, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase1_constant_eval_tuning_check import (CONSTS0, GRID, SEARCH_CONSTS,
                                               score_all, wp5, load)
from phase1_within_project_eval import evaluate_project

GEN = ROOT / 'generated'
EVAL_ONLY = {'binaryen', 'openbabel', 'squirrel', 'wabt', 'xlnt'}


def greedy(items, start):
    def obj(C):
        return wp5(score_all(items, C))
    C = dict(start)
    best = obj(C)
    for _ in range(8):
        improved = False
        for name in SEARCH_CONSTS:
            cur = C[name]
            bv, bo = cur, best
            for m in GRID:
                trial = dict(C)
                trial[name] = cur * m
                o = obj(trial)
                if o > bo + 1e-9:
                    bo, bv = o, cur * m
            if bv != cur:
                C[name] = bv
                best = bo
                improved = True
        if not improved:
            break
    moved = {k: [CONSTS0[k], C[k]] for k in SEARCH_CONSTS if abs(C[k] - CONSTS0[k]) > 1e-9}
    return C, moved


def main():
    w10 = load('phase1_within10_eval.jsonl')
    by_proj = defaultdict(list)
    for x in w10:
        by_proj[x['project']].append(x)
    dev_projects = sorted(set(by_proj) - EVAL_ONLY)

    folds = {}
    for p in dev_projects:
        fold_items = [x for x in w10 if x['project'] not in EVAL_ONLY and x['project'] != p]
        C_fold, moved = greedy(fold_items, CONSTS0)
        m_lopo = evaluate_project(score_all(by_proj[p], C_fold))
        m_ship = evaluate_project(score_all(by_proj[p], CONSTS0))
        folds[p] = {'constants_moved': moved,
                    'lopo': {'NDCG@5': m_lopo['NDCG@5'], 'MAP': m_lopo['MAP']},
                    'shipped': {'NDCG@5': m_ship['NDCG@5'], 'MAP': m_ship['MAP']}}
        print(f"{p:10s} moved={len(moved)} | NDCG@5 lopo={m_lopo['NDCG@5']:.4f} "
              f"shipped={m_ship['NDCG@5']:.4f}")

    macro_ndcg, macro_map = [], []
    for p in sorted(by_proj):
        C_use = dict(CONSTS0)
        if p in folds:
            C_use.update({k: v[1] for k, v in folds[p]['constants_moved'].items()})
        m = evaluate_project(score_all(by_proj[p], C_use))
        macro_ndcg.append(m['NDCG@5'])
        macro_map.append(m['MAP'])
    macro = {'NDCG@5': round(sum(macro_ndcg) / len(macro_ndcg), 4),
             'MAP': round(sum(macro_map) / len(macro_map), 4)}
    all_zero = all(not f['constants_moved'] for f in folds.values())
    print(f"\nall folds zero-movement: {all_zero}")
    print(f"10-project macro under LOPO: {macro} (paper core: NDCG@5 0.8561, MAP 0.8167)")

    out = GEN / 'phase1_constant_lopo_check.json'
    json.dump({'description': ('Leave-one-project-out recalibration of the signal-rule constants '
                               '(the discipline Sec. 4.1 applies to StackDedup-kNN). For every Dev '
                               'fold the like-for-like search moves zero constants, so LOPO scoring '
                               'is identical to shipped scoring and the 10-project within-project '
                               'result -- including the exact tests vs Public-Severity -- is '
                               'unchanged. Eval projects never entered calibration; their folds are '
                               'trivially the shipped constants.'),
               'dev_folds': folds,
               'all_folds_zero_movement': all_zero,
               'macro_under_lopo': macro},
              out.open('w'), indent=2)
    print('wrote', out)


if __name__ == '__main__':
    main()
