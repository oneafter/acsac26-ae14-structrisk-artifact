#!/usr/bin/env python3
"""Is the paper's theta the grid-optimal value on Dev or Eval?

Sign-preserving grid search over the six theta weights, scoring with the
shipped signal pipeline (including gating and the support-stability bonus,
exactly as structrisk_rank.score_item does). For each split we ask:
  - what is the best grid theta under that split's objective?
  - where does the paper theta rank among all grid points?
  - how does the Dev-optimal theta transfer to Eval (and vice versa)?

Objectives:
  Dev      : within-project tie-aware NDCG@5 / MAP over the 5 Dev projects
  Eval     : global NDCG@10 over the 78 held-out findings, and within-project
             tie-aware NDCG@5 / MAP over the 5 positive multi-finding Eval projects
  Combined : within-project tie-aware NDCG@5 / MAP over all 10 positive
             multi-finding projects (the Table 4 slice, Dev+Eval)
"""
import json, math, sys, itertools
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from structrisk_rank import load_jsonl, DEFAULT_WEIGHTS, SUPPORT_STABILITY_BONUS  # noqa
from phase1_within_project_eval import evaluate_project  # noqa

GEN = ROOT / 'generated'
PAPER = dict(DEFAULT_WEIGHTS)  # replay 2, locality 1, eu 1, fs 1, sanitizer 2, weak -3, bias 0

POS_GRID = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]
NEG_GRID = [-1.0, -2.0, -3.0, -4.0]
FEATS = ['replay', 'locality', 'evidence_uniqueness_gated', 'failure_semantics_gated', 'sanitizer']


def score(item, w):
    s = item['signals']
    val = (w['replay']*s['replay'] + w['locality']*s['locality']
           + w['evidence_uniqueness_gated']*s['evidence_uniqueness_gated']
           + w['failure_semantics_gated']*s['failure_semantics_gated']
           + w['sanitizer']*s['sanitizer'] + w['weak']*s['weak'])
    scale = max(0.0, w['evidence_uniqueness_gated'] / PAPER['evidence_uniqueness_gated'])
    val += SUPPORT_STABILITY_BONUS * scale * float(s.get('support_stability', 0.0) or 0.0)
    return val


def rank(items, w):
    scored = []
    for it in items:
        v = round(score(it, w), 4)
        m = dict(it); m['structrisk_score'] = v; m['queue_score'] = v
        scored.append(m)
    scored.sort(key=lambda x: (-x['queue_score'], x['project'], x['id']))
    return scored


def ndcg10(items):
    def dcg(seq):
        return sum(((2**int(x.get('risk_level') or 0))-1)/math.log2(i+1) for i, x in enumerate(seq[:10], 1))
    ideal = sorted(items, key=lambda x: int(x.get('risk_level') or 0), reverse=True)
    d = dcg(ideal)
    return 0.0 if d == 0 else dcg(items)/d


def wp(items):
    byp = defaultdict(list)
    for it in items:
        byp[it['project']].append(it)
    nd, mp = [], []
    for p, its in byp.items():
        if not any(int(x.get('risk_level') or 0) >= 3 for x in its):
            continue
        m = evaluate_project(its)
        nd.append(m['NDCG@5']); mp.append(m['MAP'])
    return sum(nd)/len(nd), sum(mp)/len(mp)


def main():
    dev = load_jsonl(GEN / 'phase1_offline_dev.jsonl')
    ev = load_jsonl(GEN / 'phase1_offline_eval.jsonl')
    w10 = load_jsonl(GEN / 'phase1_within10_eval.jsonl')
    eval_only_projects = {'binaryen', 'openbabel', 'squirrel', 'wabt', 'xlnt'}
    w_eval = [x for x in w10 if x['project'] in eval_only_projects]
    w_dev = [x for x in w10 if x['project'] not in eval_only_projects]
    print(f"dev={len(dev)} eval={len(ev)} wp_dev={len(w_dev)} wp_eval={len(w_eval)}")

    grid = []
    for combo in itertools.product(POS_GRID, repeat=5):
        for wk in NEG_GRID:
            w = dict(zip(FEATS, combo)); w['weak'] = wk; w['bias'] = 0.0
            grid.append(w)
    print(f"grid points: {len(grid)}")

    def eval_theta(w):
        d_nd, d_mp = wp(rank(w_dev, w))
        e_glob = ndcg10(rank(ev, w))
        e_nd, e_mp = wp(rank(w_eval, w))
        c_nd, c_mp = wp(rank(w10, w))
        return {'dev_wp_ndcg5': d_nd, 'dev_wp_map': d_mp,
                'eval_g_ndcg10': e_glob, 'eval_wp_ndcg5': e_nd, 'eval_wp_map': e_mp,
                'combined_wp_ndcg5': c_nd, 'combined_wp_map': c_mp}

    paper_m = eval_theta(PAPER)
    print("\nPAPER theta:", {k: round(v, 4) for k, v in paper_m.items()})

    results = []
    for i, w in enumerate(grid):
        results.append((w, eval_theta(w)))
        if (i+1) % 5000 == 0:
            print(f"  ...{i+1}/{len(grid)}")

    def report(objective, label):
        vals = [m[objective] for _, m in results]
        best = max(vals)
        n_better = sum(1 for v in vals if v > paper_m[objective] + 1e-9)
        n_tied_best = sum(1 for v in vals if abs(v-best) < 1e-9)
        argmax_w, argmax_m = max(results, key=lambda t: t[1][objective])
        rank_pct = 100.0 * sum(1 for v in vals if v <= paper_m[objective] + 1e-9) / len(vals)
        print(f"\n== objective: {label} ==")
        print(f"paper theta = {paper_m[objective]:.4f} | grid best = {best:.4f} "
              f"(gap {best-paper_m[objective]:+.4f})")
        print(f"paper theta is optimal: {abs(paper_m[objective]-best) < 1e-9}")
        print(f"grid points strictly better than paper: {n_better}/{len(vals)} "
              f"(paper at {rank_pct:.1f} percentile)")
        print(f"one argmax: { {k: argmax_w[k] for k in FEATS+['weak']} }")
        print(f"  its full metrics: { {k: round(v,4) for k,v in argmax_m.items()} }")
        return argmax_w, argmax_m

    dev_best_w, dev_best_m = report('dev_wp_ndcg5', 'Dev within-project NDCG@5 (the tuning target if theta had been fitted on Dev)')
    report('dev_wp_map', 'Dev within-project MAP')
    eg_w, eg_m = report('eval_g_ndcg10', 'Eval global NDCG@10 (would indicate Eval leakage)')
    ew_w, ew_m = report('eval_wp_ndcg5', 'Eval within-project NDCG@5 (would indicate Eval leakage)')
    cb_w, cb_m = report('combined_wp_ndcg5', 'Combined within-project NDCG@5 (all 10 positive projects, Table 4 slice)')
    report('combined_wp_map', 'Combined within-project MAP')

    print("\n== transfer check: Dev-optimal theta applied to Eval ==")
    print(f"Dev-optimal on Dev WP NDCG@5: {dev_best_m['dev_wp_ndcg5']:.4f} (paper {paper_m['dev_wp_ndcg5']:.4f})")
    print(f"Dev-optimal on Eval global NDCG@10: {dev_best_m['eval_g_ndcg10']:.4f} (paper {paper_m['eval_g_ndcg10']:.4f})")
    print(f"Dev-optimal on Eval WP NDCG@5:      {dev_best_m['eval_wp_ndcg5']:.4f} (paper {paper_m['eval_wp_ndcg5']:.4f})")

    out = GEN / 'phase1_theta_optimality.json'
    json.dump({'paper': paper_m,
               'dev_optimal': {'theta': dev_best_w, 'metrics': dev_best_m},
               'eval_global_optimal': {'theta': eg_w, 'metrics': eg_m},
               'eval_wp_optimal': {'theta': ew_w, 'metrics': ew_m},
               'combined_wp_optimal': {'theta': cb_w, 'metrics': cb_m}},
              open(out, 'w'), indent=2)
    print('wrote', out)


if __name__ == '__main__':
    main()
