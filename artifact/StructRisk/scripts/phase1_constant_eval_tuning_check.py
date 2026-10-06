#!/usr/bin/env python3
"""Where were the signal-rule constants calibrated? A two-sided
unclaimed-headroom check over the 17 hand-tunable rule constants.

A calibration leaves no easily reachable gains unclaimed on its own objective.
This script runs the same kind of scripted coordinate search as the original
calibration, once against the DEV objective (Dev within-project tie-aware
NDCG@5 -- the disclosed calibration target) and once against the EVAL
objectives (held-out global NDCG@10 + Eval-only within-project NDCG@5),
starting from the shipped constants in both cases. This is a like-for-like
reconstruction for auditing; the original calibration script itself is not
part of this reviewer package.

Measured signature: against Dev the search finds ZERO headroom (no constant
moves) -- consistent with the constants having been calibrated there.
Against Eval it immediately finds headroom (within-project NDCG@5 0.8981 ->
0.9104 by moving 2 constants) -- gains an Eval calibration would have
captured, so the constants were not tuned on Eval.
Output: generated/phase1_constant_eval_tuning_check.json
"""
import json, math, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from structrisk_rank import (DEFAULT_WEIGHTS, MEMORY_STRONG_RE, WEAK_RE, clamp,
                             exact_report, list_len, location_key, metadata, support_count)
from phase1_within_project_eval import evaluate_project

GEN = ROOT / 'generated'
THETA = DEFAULT_WEIGHTS
CONSTS0 = {
    'eu_support': 0.45, 'eu_site': 0.35, 'eu_spread': 0.20,
    'fs_base': 0.20, 'fs_strong': 0.50, 'fs_deadly': 0.30, 'fs_site': 0.20,
    'fs_exact': 0.10, 'fs_exit': 0.05, 'fs_assert': -0.10, 'fs_weakpat': -0.10,
    'fs_san': 0.15,
    'gate_slope': 1.2, 'gate_floor': 0.2,
    'ss_bonus': 0.5, 'ss_min_count': 20.0, 'ss_weak_max': 0.10,
    'scale_replay': 1.0, 'scale_locality': 1.0, 'scale_sanitizer': 1.0, 'scale_weak': 1.0,
}
GRID = [0.25, 0.5, 0.75, 1.25, 1.5, 2.0]
# scale_* factors rescale the base signals (theta-adjacent; covered by the theta
# grid check) and are NOT part of the calibrated rule constants -- exclude them.
SEARCH_CONSTS = [k for k in CONSTS0 if not k.startswith('scale_')]
EVAL_ONLY = {'binaryen', 'openbabel', 'squirrel', 'wabt', 'xlnt'}


def load(name):
    return [json.loads(l) for l in (GEN / name).open() if l.strip()]


def stats_of(items):
    g = defaultdict(list)
    for it in items:
        g[it.get('project', 'unknown')].append(it)
    return {p: {'max_support': max(support_count(i) for i in its),
                'loc_counts': Counter(location_key(i) for i in its if location_key(i))}
            for p, its in g.items()}


def score_all(items, C):
    st = stats_of(items)
    out = []
    for it in items:
        raw = it.get('signals') or {}
        b = {'replay': clamp(float(raw.get('replay', 0)) * C['scale_replay']),
             'locality': clamp(float(raw.get('locality', 0)) * C['scale_locality']),
             'sanitizer': clamp(float(raw.get('sanitizer', 0)) * C['scale_sanitizer']),
             'weak': max(0.02, min(0.95, float(raw.get('weak', 0)) * C['scale_weak']))}
        meta = metadata(it)
        ps = st[it.get('project', 'unknown')]
        ms = max(1, ps['max_support'])
        cnt = support_count(it)
        slog = math.log1p(cnt) / math.log1p(ms) if ms > 1 else 0.0
        key = location_key(it)
        shared = ps['loc_counts'].get(key, 1) if key else 4
        lu = 1.0 / math.sqrt(max(1, shared))
        camp = max(list_len(meta.get('campaigns')), list_len(meta.get('aligned_targets')), 1)
        spread = min(1.0, math.log1p(camp) / math.log1p(4))
        eu = clamp(C['eu_support'] * slog + C['eu_site'] * lu + C['eu_spread'] * spread)
        text = ' '.join(str(meta.get(k) or '') for k in (
            'matched_summary_line', 'matched_asan_type', 'matched_assertion', 'signature', 'matched_project_loc'))
        site = bool(str(meta.get('matched_project_loc') or '').strip())
        fs = C['fs_base']
        if MEMORY_STRONG_RE.search(text):
            fs += C['fs_strong']
        elif 'deadlysignal' in text.lower() and site:
            fs += C['fs_deadly']
        elif site:
            fs += C['fs_site']
        if exact_report(it):
            fs += C['fs_exact']
        ec = str(meta.get('matched_exit_code') or '')
        if ec and ec not in {'0', 'None', 'none'}:
            fs += C['fs_exit']
        if str(meta.get('matched_assertion') or '').strip():
            fs += C['fs_assert']
        if WEAK_RE.search(text) and not MEMORY_STRONG_RE.search(text):
            fs += C['fs_weakpat']
        fs += C['fs_san'] * b['sanitizer']
        fs = clamp(fs)
        gate = min(1.0, max(C['gate_floor'], C['gate_slope'] * (1.0 - b['weak'])))
        ss = 0.0
        if exact_report(it) and cnt >= C['ss_min_count'] and b['weak'] <= C['ss_weak_max'] and ms > 1:
            ss = clamp(math.log1p(cnt) / math.log1p(ms))
        v = (THETA['replay'] * b['replay'] + THETA['locality'] * b['locality']
             + THETA['evidence_uniqueness_gated'] * eu * gate
             + THETA['failure_semantics_gated'] * fs * gate
             + THETA['sanitizer'] * b['sanitizer'] + THETA['weak'] * b['weak']
             + C['ss_bonus'] * ss)
        m = dict(it)
        m['structrisk_score'] = round(v, 4)
        m['queue_score'] = round(v, 4)
        out.append(m)
    out.sort(key=lambda x: (-x['queue_score'], x['project'], x['id']))
    return out


def ndcg10(items):
    def dcg(s):
        return sum(((2 ** int(x.get('risk_level') or 0)) - 1) / math.log2(i + 1)
                   for i, x in enumerate(s[:10], 1))
    ideal = sorted(items, key=lambda x: int(x.get('risk_level') or 0), reverse=True)
    d = dcg(ideal)
    return 0.0 if d == 0 else dcg(items) / d


def wp5(items):
    byp = defaultdict(list)
    for it in items:
        byp[it['project']].append(it)
    nd = [evaluate_project(its)['NDCG@5'] for p, its in byp.items()
          if any(int(x.get('risk_level') or 0) >= 3 for x in its)]
    return sum(nd) / len(nd)


def main():
    ev = load('phase1_offline_eval.jsonl')
    w10 = load('phase1_within10_eval.jsonl')
    w_eval = [x for x in w10 if x['project'] in EVAL_ONLY]
    w_dev = [x for x in w10 if x['project'] not in EVAL_ONLY]

    def obj_dev(C):
        return wp5(score_all(w_dev, C))

    def obj_eval(C):
        return ndcg10(score_all(ev, C)) + wp5(score_all(w_eval, C))

    def greedy(objective):
        C = dict(CONSTS0)
        best = objective(C)
        evaluations = 1
        for _ in range(8):
            improved = False
            for name in SEARCH_CONSTS:
                cur = C[name]
                bv, bo = cur, best
                for m in GRID:
                    trial = dict(C)
                    trial[name] = cur * m
                    o = objective(trial)
                    evaluations += 1
                    if o > bo + 1e-9:
                        bo, bv = o, cur * m
                if bv != cur:
                    C[name] = bv
                    best = bo
                    improved = True
            if not improved:
                break
        moved = {k: [CONSTS0[k], C[k]] for k in SEARCH_CONSTS if abs(C[k] - CONSTS0[k]) > 1e-9}
        return C, moved, evaluations

    dev_base = obj_dev(CONSTS0)
    Cd, moved_d, ev_d = greedy(obj_dev)
    dev_opt = obj_dev(Cd)
    print(f"DEV objective (calibration target): paper={dev_base:.4f} optimized={dev_opt:.4f} "
          f"(+{dev_opt-dev_base:.4f}), constants moved: {len(moved_d)}/{len(SEARCH_CONSTS)}")

    eval_base_g = ndcg10(score_all(ev, CONSTS0))
    eval_base_w = wp5(score_all(w_eval, CONSTS0))
    Ce, moved_e, ev_e = greedy(obj_eval)
    eval_opt_g = ndcg10(score_all(ev, Ce))
    eval_opt_w = wp5(score_all(w_eval, Ce))
    print(f"EVAL objective: paper g={eval_base_g:.4f} wp={eval_base_w:.4f} -> "
          f"optimized g={eval_opt_g:.4f} wp={eval_opt_w:.4f}, "
          f"constants moved: {len(moved_e)}/{len(SEARCH_CONSTS)} -> {sorted(moved_e)}")

    out = GEN / 'phase1_constant_eval_tuning_check.json'
    json.dump({'description': ('Two-sided unclaimed-headroom check over the 17 hand-tunable rule '
                               'constants, using a like-for-like reconstruction of the original '
                               'scripted coordinate search (the original calibration script is not '
                               'part of this package). Against its own Dev calibration target the '
                               'search finds zero headroom (no constant moves); against the Eval '
                               'objectives it immediately finds headroom an Eval calibration would '
                               'have captured. Together: calibrated on Dev, not tuned on Eval.'),
               'search_constants': SEARCH_CONSTS,
               'dev_objective': {'paper': dev_base, 'optimized': dev_opt,
                                 'constants_moved': moved_d},
               'eval_objective': {'paper': {'eval_g_ndcg10': eval_base_g, 'eval_wp_ndcg5': eval_base_w},
                                  'optimized': {'eval_g_ndcg10': eval_opt_g, 'eval_wp_ndcg5': eval_opt_w},
                                  'constants_moved': moved_e},
               'objective_evaluations': {'dev': ev_d, 'eval': ev_e}},
              out.open('w'), indent=2)
    print('wrote', out)


if __name__ == '__main__':
    main()
