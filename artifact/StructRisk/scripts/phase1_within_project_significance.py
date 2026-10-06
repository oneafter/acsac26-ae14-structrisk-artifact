#!/usr/bin/env python3
import argparse
import json
import math
from itertools import product
from pathlib import Path
from random import Random


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

PUBLIC_DEFAULT = GENERATED / 'phase1_within10_public_severity_ranked.jsonl'
SUPPORT_DEFAULT = GENERATED / 'phase1_within10_support_count_ranked.jsonl'
ASAN_DEFAULT = GENERATED / 'phase1_within10_asan_ranked.jsonl'
CRASHSTATE_DEFAULT = GENERATED / 'phase1_within10_crashstate_ranked.jsonl'
CASR_DEFAULT = GENERATED / 'phase1_within10_casr_ranked.jsonl'
LLM_CARD_DEFAULT = GENERATED / 'phase1_within10_llm_card_ranked.jsonl'
LCR_DEFAULT = GENERATED / 'phase1_within10_llm_lcr_ranked.jsonl'
JSON_DEFAULT = GENERATED / 'phase1_within_project_significance.json'
MD_DEFAULT = GENERATED / 'phase1_within_project_significance.md'

PRIMARY_METRICS = ['HR@1', 'HR@3', 'NDCG@5', 'MRR', 'MAP']


DEFAULT_METHODS = [
    ('Public-Severity', PUBLIC_DEFAULT),
    ('Support-Count', SUPPORT_DEFAULT),
    ('ASan-Severity', ASAN_DEFAULT),
    ('Crash-State', CRASHSTATE_DEFAULT),
    ('CASR-Severity', CASR_DEFAULT),
    ('LLM-CardScore', LLM_CARD_DEFAULT),
    ('StructRisk+LLM-LCR', LCR_DEFAULT),
]


def parse_method_specs(specs):
    methods = []
    for spec in specs:
        if '=' not in spec:
            raise ValueError(f'invalid --method spec: {spec!r}; expected NAME=PATH')
        name, raw_path = spec.split('=', 1)
        name = name.strip()
        raw_path = raw_path.strip()
        if not name or not raw_path:
            raise ValueError(f'invalid --method spec: {spec!r}; expected NAME=PATH')
        methods.append((name, Path(raw_path)))
    return methods


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for rank, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            row['_global_rank'] = rank
            rows.append(row)
    return rows


def relevance(item):
    return 1 if int(item.get('risk_level') or 0) >= 3 else 0


def score_key(item):
    queue_score = item.get('local_queue_score') if item.get('local_queue_score') is not None else item.get('queue_score')
    structrisk_score = (
        item.get('local_structrisk_score')
        if item.get('local_structrisk_score') is not None
        else item.get('structrisk_score')
    )
    return (
        round(float(queue_score or 0.0), 8),
        round(float(structrisk_score or queue_score or 0.0), 8),
    )


def tie_blocks(items):
    ordered = sorted(items, key=lambda item: (-score_key(item)[0], -score_key(item)[1], item['id']))
    blocks = []
    current_key = None
    current = []
    for item in ordered:
        key = score_key(item)
        if current and key != current_key:
            blocks.append(current)
            current = []
        current_key = key
        current.append(item)
    if current:
        blocks.append(current)
    return blocks


def expected_hr_at_k(blocks, k):
    total = 0.0
    pos = 1
    for block in blocks:
        n = len(block)
        h = sum(relevance(item) for item in block)
        take = max(0, min(pos + n - 1, k) - pos + 1)
        if take:
            total += take * h / n
        pos += n
    return total


def expected_dcg_at_k(blocks, k):
    total = 0.0
    pos = 1
    for block in blocks:
        n = len(block)
        h = sum(relevance(item) for item in block)
        expected_gain = h / n
        for offset in range(n):
            rank = pos + offset
            if rank > k:
                break
            total += expected_gain / math.log2(rank + 1)
        pos += n
    return total


def ideal_dcg_at_k(items, k):
    gains = sorted([relevance(item) for item in items], reverse=True)
    return sum(gain / math.log2(idx + 1) for idx, gain in enumerate(gains[:k], start=1))


def expected_ndcg_at_k(items, blocks, k):
    denom = ideal_dcg_at_k(items, k)
    return 0.0 if denom == 0.0 else expected_dcg_at_k(blocks, k) / denom


def expected_mrr(blocks):
    preceding = 0
    for block in blocks:
        n = len(block)
        h = sum(relevance(item) for item in block)
        if h == 0:
            preceding += n
            continue
        denom = math.comb(n, h)
        expected = 0.0
        for first_offset in range(1, n - h + 2):
            probability = math.comb(n - first_offset, h - 1) / denom
            expected += probability / (preceding + first_offset)
        return expected
    return 0.0


def expected_map(items, blocks):
    total_positives = sum(relevance(item) for item in items)
    if total_positives == 0:
        return 0.0
    ap = 0.0
    preceding_items = 0
    preceding_positives = 0
    for block in blocks:
        n = len(block)
        h = sum(relevance(item) for item in block)
        if h == 0:
            preceding_items += n
            continue
        for offset in range(1, n + 1):
            rank = preceding_items + offset
            probability_positive = h / n
            if n == 1:
                expected_prev_in_block = 0.0
            else:
                expected_prev_in_block = (offset - 1) * (h - 1) / (n - 1)
            expected_precision_if_positive = (preceding_positives + 1 + expected_prev_in_block) / rank
            ap += probability_positive * expected_precision_if_positive
        preceding_items += n
        preceding_positives += h
    return ap / total_positives


def evaluate_project(items):
    blocks = tie_blocks(items)
    return {
        'HR@1': expected_hr_at_k(blocks, 1),
        'HR@3': expected_hr_at_k(blocks, 3),
        'NDCG@5': expected_ndcg_at_k(items, blocks, 5),
        'MRR': expected_mrr(blocks),
        'MAP': expected_map(items, blocks),
    }


def average(rows):
    return {key: sum(row[key] for row in rows) / len(rows) for key in PRIMARY_METRICS}


def metric_direction(metric_name: str) -> str:
    return 'higher'


def quantile(values, q):
    ordered = sorted(values)
    idx = (len(ordered) - 1) * q
    low = int(math.floor(idx))
    high = int(math.ceil(idx))
    if low == high:
        return ordered[low]
    frac = idx - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def fmt(value, metric_name):
    if value is None:
        return 'NA'
    return f'{value:.4f}'


def per_project_metrics(rows):
    by_project = {}
    for row in rows:
        by_project.setdefault(row['project'], []).append(row)
    result = {}
    for project, items in sorted(by_project.items()):
        positives = sum(relevance(item) for item in items)
        if positives == 0 or len(items) <= 1:
            continue
        result[project] = evaluate_project(items)
    return result


def compute_significance(rankings, bootstrap_rounds=20000, seed=1337, target_method='StructRisk+LLM-LCR'):
    per_method = {name: per_project_metrics(rows) for name, rows in rankings.items()}
    projects = sorted(set.intersection(*(set(metrics.keys()) for metrics in per_method.values())))
    if not projects:
        raise ValueError('no shared multi-finding positive projects across methods')

    point_metrics = {
        name: average([per_method[name][project] for project in projects])
        for name in rankings
    }

    target = target_method
    baseline_order = [
        name for name in (
            'Public-Severity',
            'ASan-Severity',
            'Crash-State',
            'LLM-CardScore',
        )
        if name in rankings and name != target
    ]
    comparisons = [(target, right) for right in baseline_order]

    rng = Random(seed)
    diff_bootstrap = {
        f'{left} vs {right}': {metric: [] for metric in PRIMARY_METRICS}
        for left, right in comparisons
    }
    for _ in range(bootstrap_rounds):
        sampled_projects = [rng.choice(projects) for _ in projects]
        sampled_metrics = {
            name: average([per_method[name][project] for project in sampled_projects])
            for name in rankings
        }
        for left, right in comparisons:
            key = f'{left} vs {right}'
            for metric in PRIMARY_METRICS:
                diff_bootstrap[key][metric].append(sampled_metrics[left][metric] - sampled_metrics[right][metric])

    diff_summary = {}
    for left, right in comparisons:
        key = f'{left} vs {right}'
        diff_summary[key] = {}
        for metric in PRIMARY_METRICS:
            point = point_metrics[left][metric] - point_metrics[right][metric]
            samples = diff_bootstrap[key][metric]
            diff_summary[key][metric] = {
                'point': point,
                'ci95': [quantile(samples, 0.025), quantile(samples, 0.975)],
            }

    permutation = {}
    swap_patterns = list(product([0, 1], repeat=len(projects)))
    for left, right in comparisons:
        key = f'{left} vs {right}'
        permutation[key] = {}
        for metric in PRIMARY_METRICS:
            vals = []
            for pattern in swap_patterns:
                left_vals = []
                right_vals = []
                for project, swap in zip(projects, pattern):
                    if swap == 0:
                        left_vals.append(per_method[left][project][metric])
                        right_vals.append(per_method[right][project][metric])
                    else:
                        left_vals.append(per_method[right][project][metric])
                        right_vals.append(per_method[left][project][metric])
                vals.append(sum(left_vals) / len(left_vals) - sum(right_vals) / len(right_vals))
            obs = diff_summary[key][metric]['point']
            p_value = (sum(1 for value in vals if abs(value) >= abs(obs)) + 1) / (len(vals) + 1)
            permutation[key][metric] = {
                'observed_diff': obs,
                'exact_two_sided_p': p_value,
                'num_project_blocks': len(projects),
                'num_patterns': len(vals),
            }

    return {
        'method_order': list(rankings.keys()),
        'comparisons': [f'{left} vs {right}' for left, right in comparisons],
        'projects': projects,
        'bootstrap_rounds': bootstrap_rounds,
        'point_metrics': point_metrics,
        'diff_summary': diff_summary,
        'permutation': permutation,
    }


def to_markdown(results):
    lines = [
        '# Phase-1 Within-Project Significance Summary',
        '',
        f"- Multi-finding positive eval projects: `{len(results['projects'])}` ({', '.join(results['projects'])})",
        f"- Bootstrap: `{results['bootstrap_rounds']}` project-level resamples",
        '- Exact test: project-block sign-flip randomization over all label-preserving swap patterns',
        '',
        '## Macro Metrics',
        '',
        '| Method | HR@1 | HR@3 | NDCG@5 | MRR | MAP |',
        '| --- | ---: | ---: | ---: | ---: | ---: |',
    ]
    for method in results['method_order']:
        metrics = results['point_metrics'][method]
        lines.append(
            f"| {method} | {metrics['HR@1']:.4f} | {metrics['HR@3']:.4f} | {metrics['NDCG@5']:.4f} | {metrics['MRR']:.4f} | {metrics['MAP']:.4f} |"
        )
    lines.extend([
        '',
        f"## {results['comparisons'][0].split(' vs ')[0]} Comparisons" if results['comparisons'] else '## Comparisons',
        '',
        '| Comparison | Metric | Diff | 95% CI | Exact $p$ |',
        '| --- | --- | ---: | --- | ---: |',
    ])
    for comparison in results['comparisons']:
        for metric in PRIMARY_METRICS:
            diff = results['diff_summary'][comparison][metric]
            perm = results['permutation'][comparison][metric]
            lines.append(
                f"| {comparison} | {metric} | {diff['point']:.4f} | [{diff['ci95'][0]:.4f}, {diff['ci95'][1]:.4f}] | {perm['exact_two_sided_p']:.4f} |"
            )
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Within-project significance analysis for StructRisk rankings')
    parser.add_argument('--method', action='append', default=[], help='Override method inputs with NAME=PATH (repeatable)')
    parser.add_argument('--target', default='StructRisk+LLM-LCR', help='Method treated as the comparison target')
    parser.add_argument('--project', action='append', default=[], help='Restrict evaluation to the named project(s) (repeatable)')
    parser.add_argument('--public', default=str(PUBLIC_DEFAULT))
    parser.add_argument('--asan', default=str(ASAN_DEFAULT))
    parser.add_argument('--crashstate', default=str(CRASHSTATE_DEFAULT))
    parser.add_argument('--llm-card', default=str(LLM_CARD_DEFAULT))
    parser.add_argument('--lcr', default=str(LCR_DEFAULT))
    parser.add_argument('--bootstrap-rounds', type=int, default=20000)
    parser.add_argument('--seed', type=int, default=1337)
    parser.add_argument('--json-out', default=str(JSON_DEFAULT))
    parser.add_argument('--md-out', default=str(MD_DEFAULT))
    args = parser.parse_args()

    if args.method:
        methods = parse_method_specs(args.method)
    else:
        methods = [
            ('Public-Severity', Path(args.public)),
            ('ASan-Severity', Path(args.asan)),
            ('Crash-State', Path(args.crashstate)),
            ('LLM-CardScore', Path(args.llm_card)),
            ('StructRisk+LLM-LCR', Path(args.lcr)),
        ]
    project_filter = set(args.project)
    rankings = {}
    for name, path in methods:
        if not path.exists():
            continue
        rows = load_jsonl(path)
        if project_filter:
            rows = [row for row in rows if row['project'] in project_filter]
        rankings[name] = rows
    results = compute_significance(rankings, bootstrap_rounds=args.bootstrap_rounds, seed=args.seed, target_method=args.target)
    Path(args.json_out).write_text(json.dumps(results, indent=2), encoding='utf-8')
    Path(args.md_out).write_text(to_markdown(results), encoding='utf-8')
    print(Path(args.json_out))
    print(Path(args.md_out))
    print(json.dumps(results['point_metrics'], indent=2))


if __name__ == '__main__':
    main()
