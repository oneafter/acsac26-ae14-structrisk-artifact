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

PUBLIC_DEFAULT = GENERATED / 'phase1_offline_public_severity_ranked.jsonl'
ARTIFACT_DEFAULT = GENERATED / 'phase1_offline_artifact_ranked.jsonl'
ASAN_DEFAULT = GENERATED / 'phase1_offline_asan_ranked.jsonl'
CRASHSTATE_DEFAULT = GENERATED / 'phase1_offline_crashstate_ranked.jsonl'
SUPPORT_DEFAULT = GENERATED / 'phase1_offline_support_count_ranked.jsonl'
REPORTKNN_DEFAULT = GENERATED / 'phase1_offline_reportknn_ranked.jsonl'
CASR_DEFAULT = GENERATED / 'phase1_offline_casr_ranked.jsonl'
LLM_CARD_DEFAULT = GENERATED / 'phase1_offline_llm_card_ranked.jsonl'
MANUAL_DEFAULT = GENERATED / 'phase1_offline_manual_ranked.jsonl'
LCR_DEFAULT = GENERATED / 'phase1_offline_llm_lcr_ranked.jsonl'
JSON_DEFAULT = GENERATED / 'phase1_offline_significance.json'
MD_DEFAULT = GENERATED / 'phase1_offline_significance.md'

PRIMARY_METRICS = [
    'HighRisk@5',
    'HighRisk@10',
    'NDCG@5',
    'NDCG@10',
    'Rank-to-First-HighRisk',
]


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def ndcg_at_k(items, k):
    def dcg(seq):
        total = 0.0
        for idx, item in enumerate(seq[:k], start=1):
            rel = item.get('risk_level') or 0
            gain = (2 ** rel) - 1
            total += gain / math.log2(idx + 1)
        return total

    ideal = sorted(items, key=lambda item: item.get('risk_level') or 0, reverse=True)
    denom = dcg(ideal)
    return 0.0 if denom == 0.0 else dcg(items) / denom


def evaluate(items, high_threshold=3):
    labeled = [item for item in items if item.get('risk_level') is not None]
    metrics = {}
    for k in (5, 10):
        metrics[f'HighRisk@{k}'] = sum(1 for item in labeled[:k] if item['risk_level'] >= high_threshold)
        metrics[f'NDCG@{k}'] = ndcg_at_k(labeled, k)
    first_hit_rank = None
    for idx, item in enumerate(labeled, start=1):
        if item['risk_level'] >= high_threshold:
            first_hit_rank = idx
            break
    metrics['Rank-to-First-HighRisk'] = first_hit_rank if first_hit_rank is not None else len(labeled) + 1
    return metrics


def quantile(values, q):
    ordered = sorted(values)
    idx = (len(ordered) - 1) * q
    low = int(math.floor(idx))
    high = int(math.ceil(idx))
    if low == high:
        return ordered[low]
    frac = idx - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def metric_direction(metric_name: str) -> str:
    return 'lower' if metric_name == 'Rank-to-First-HighRisk' else 'higher'


def fmt(value, metric_name):
    if value is None:
        return 'NA'
    if 'NDCG' in metric_name:
        return f'{value:.4f}'
    if isinstance(value, float) and not value.is_integer():
        return f'{value:.2f}'
    return str(int(value)) if float(value).is_integer() else f'{value:.2f}'


def build_merged_rankings(rankings):
    item_maps = {}
    for name, rows in rankings.items():
        item_map = {}
        for idx, row in enumerate(rows, start=1):
            item_map[row['id']] = {
                **row,
                'orig_rank': idx,
            }
        item_maps[name] = item_map

    reference_name = next(iter(rankings))
    merged = {}
    for finding_id, row in item_maps[reference_name].items():
        merged[finding_id] = {
            'id': finding_id,
            'project': row['project'],
            'risk_level': row['risk_level'],
            'review_cost': row.get('review_cost'),
        }
        for name in rankings:
            source = item_maps[name][finding_id]
            merged[finding_id][name] = {
                'queue_score': source['queue_score'],
                'structrisk_score': source.get('structrisk_score', source['queue_score']),
                'orig_rank': source['orig_rank'],
            }
    return merged


def ranked_rows_from_scores(merged, system_name):
    rows = []
    for finding_id, data in merged.items():
        score_row = data[system_name]
        rows.append({
            'id': finding_id,
            'project': data['project'],
            'risk_level': data['risk_level'],
            'queue_score': score_row['queue_score'],
            'structrisk_score': score_row['structrisk_score'],
            'orig_rank': score_row['orig_rank'],
        })
    rows.sort(key=lambda item: (-item['queue_score'], -item['structrisk_score'], item['orig_rank'], item['project'], item['id']))
    return rows


def bootstrap_rows(merged, system_name, sampled_projects, project_to_ids):
    rows = []
    for copy_idx, project in enumerate(sampled_projects, start=1):
        for finding_id in project_to_ids[project]:
            data = merged[finding_id]
            score_row = data[system_name]
            rows.append({
                'id': f'{finding_id}::boot{copy_idx}',
                'project': project,
                'risk_level': data['risk_level'],
                'queue_score': score_row['queue_score'],
                'structrisk_score': score_row['structrisk_score'],
                'orig_rank': score_row['orig_rank'],
                'copy_idx': copy_idx,
            })
    rows.sort(key=lambda item: (-item['queue_score'], -item['structrisk_score'], item['orig_rank'], item['project'], item['id']))
    return rows


def compute_significance(rankings, bootstrap_rounds=20000, seed=1337):
    merged = build_merged_rankings(rankings)
    projects = sorted({data['project'] for data in merged.values()})
    project_to_ids = {
        project: [finding_id for finding_id, data in merged.items() if data['project'] == project]
        for project in projects
    }

    point_metrics = {
        name: evaluate(ranked_rows_from_scores(merged, name))
        for name in rankings
    }

    rng = Random(seed)
    bootstrap = {
        name: {metric: [] for metric in PRIMARY_METRICS}
        for name in rankings
    }
    baseline_order = [
        name for name in (
            'Public-Severity',
            'ASan-Severity',
            'Crash-State',
            'StackDedup-kNN',
            'CASR-Severity',
            'LLM-CardScore',
        )
        if name in rankings
    ]
    target_order = [
        name for name in (
            'StructRisk',
        )
        if name in rankings
    ]
    comparisons = [
        (left, right)
        for right in baseline_order
        for left in target_order
    ]
    diff_bootstrap = {
        f'{left} vs {right}': {metric: [] for metric in PRIMARY_METRICS}
        for left, right in comparisons
    }

    for _ in range(bootstrap_rounds):
        sampled_projects = [rng.choice(projects) for _ in projects]
        cached = {
            name: evaluate(bootstrap_rows(merged, name, sampled_projects, project_to_ids))
            for name in rankings
        }
        for name, metrics in cached.items():
            for metric in PRIMARY_METRICS:
                bootstrap[name][metric].append(metrics[metric])
        for left, right in comparisons:
            key = f'{left} vs {right}'
            for metric in PRIMARY_METRICS:
                if metric_direction(metric) == 'lower':
                    diff_bootstrap[key][metric].append(cached[right][metric] - cached[left][metric])
                else:
                    diff_bootstrap[key][metric].append(cached[left][metric] - cached[right][metric])

    bootstrap_summary = {}
    for name in rankings:
        bootstrap_summary[name] = {}
        for metric in PRIMARY_METRICS:
            samples = bootstrap[name][metric]
            bootstrap_summary[name][metric] = {
                'point': point_metrics[name][metric],
                'ci95': [quantile(samples, 0.025), quantile(samples, 0.975)],
            }

    diff_summary = {}
    for key, metrics in diff_bootstrap.items():
        diff_summary[key] = {}
        left, right = key.split(' vs ')
        for metric, samples in metrics.items():
            point = point_metrics[right][metric] - point_metrics[left][metric] if metric_direction(metric) == 'lower' else point_metrics[left][metric] - point_metrics[right][metric]
            diff_summary[key][metric] = {
                'point': point,
                'ci95': [quantile(samples, 0.025), quantile(samples, 0.975)],
            }

    permutation = {}
    swap_patterns = list(product([0, 1], repeat=len(projects)))
    for left, right in comparisons:
        comparison_key = f'{left} vs {right}'
        permutation[comparison_key] = {}
        observed = diff_summary[comparison_key]
        perm_values = {metric: [] for metric in PRIMARY_METRICS}
        for pattern in swap_patterns:
            project_swap = dict(zip(projects, pattern))
            left_rows = []
            right_rows = []
            for finding_id, data in merged.items():
                project = data['project']
                if project_swap[project] == 0:
                    left_score = data[left]
                    right_score = data[right]
                else:
                    left_score = data[right]
                    right_score = data[left]
                left_rows.append({
                    'id': finding_id,
                    'project': project,
                    'risk_level': data['risk_level'],
                    'queue_score': left_score['queue_score'],
                    'structrisk_score': left_score['structrisk_score'],
                    'orig_rank': left_score['orig_rank'],
                })
                right_rows.append({
                    'id': finding_id,
                    'project': project,
                    'risk_level': data['risk_level'],
                    'queue_score': right_score['queue_score'],
                    'structrisk_score': right_score['structrisk_score'],
                    'orig_rank': right_score['orig_rank'],
                })
            left_rows.sort(key=lambda item: (-item['queue_score'], -item['structrisk_score'], item['orig_rank'], item['project'], item['id']))
            right_rows.sort(key=lambda item: (-item['queue_score'], -item['structrisk_score'], item['orig_rank'], item['project'], item['id']))
            left_metrics = evaluate(left_rows)
            right_metrics = evaluate(right_rows)
            for metric in PRIMARY_METRICS:
                if metric_direction(metric) == 'lower':
                    perm_values[metric].append(right_metrics[metric] - left_metrics[metric])
                else:
                    perm_values[metric].append(left_metrics[metric] - right_metrics[metric])

        for metric in PRIMARY_METRICS:
            obs = observed[metric]['point']
            vals = perm_values[metric]
            p_value = (sum(1 for value in vals if abs(value) >= abs(obs)) + 1) / (len(vals) + 1)
            permutation[comparison_key][metric] = {
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
        'bootstrap_summary': bootstrap_summary,
        'diff_summary': diff_summary,
        'permutation': permutation,
    }


def to_markdown(results):
    lines = [
        '# Phase-1 Significance Summary',
        '',
        f"- Eval projects: `{len(results['projects'])}` ({', '.join(results['projects'])})",
        f"- Bootstrap: `{results['bootstrap_rounds']}` project-level resamples",
        '- Exact test: project-block sign-flip randomization over all label-preserving swap patterns',
        '',
        '## Primary Metrics with 95% Bootstrap CIs',
        '',
        '| Method | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR Rank |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for method in results['method_order']:
        summary = results['bootstrap_summary'][method]
        lines.append(
            '| {method} | {hr5} [{hr5_lo}, {hr5_hi}] | {hr10} [{hr10_lo}, {hr10_hi}] | {ndcg5} [{ndcg5_lo}, {ndcg5_hi}] | {ndcg10} [{ndcg10_lo}, {ndcg10_hi}] | {first} [{first_lo}, {first_hi}] |'.format(
                method=method,
                hr5=fmt(summary['HighRisk@5']['point'], 'HighRisk@5'),
                hr5_lo=fmt(summary['HighRisk@5']['ci95'][0], 'HighRisk@5'),
                hr5_hi=fmt(summary['HighRisk@5']['ci95'][1], 'HighRisk@5'),
                hr10=fmt(summary['HighRisk@10']['point'], 'HighRisk@10'),
                hr10_lo=fmt(summary['HighRisk@10']['ci95'][0], 'HighRisk@10'),
                hr10_hi=fmt(summary['HighRisk@10']['ci95'][1], 'HighRisk@10'),
                ndcg5=fmt(summary['NDCG@5']['point'], 'NDCG@5'),
                ndcg5_lo=fmt(summary['NDCG@5']['ci95'][0], 'NDCG@5'),
                ndcg5_hi=fmt(summary['NDCG@5']['ci95'][1], 'NDCG@5'),
                ndcg10=fmt(summary['NDCG@10']['point'], 'NDCG@10'),
                ndcg10_lo=fmt(summary['NDCG@10']['ci95'][0], 'NDCG@10'),
                ndcg10_hi=fmt(summary['NDCG@10']['ci95'][1], 'NDCG@10'),
                first=fmt(summary['Rank-to-First-HighRisk']['point'], 'Rank-to-First-HighRisk'),
                first_lo=fmt(summary['Rank-to-First-HighRisk']['ci95'][0], 'Rank-to-First-HighRisk'),
                first_hi=fmt(summary['Rank-to-First-HighRisk']['ci95'][1], 'Rank-to-First-HighRisk'),
            )
        )

    lines.extend([
        '',
        '## StructRisk Comparisons',
        '',
        '| Comparison | Metric | Diff | 95% CI | Exact $p$ |',
        '| --- | --- | ---: | --- | ---: |',
    ])
    for comparison in results['comparisons']:
        for metric in ('HighRisk@5', 'HighRisk@10', 'NDCG@5', 'NDCG@10', 'Rank-to-First-HighRisk'):
            diff = results['diff_summary'][comparison][metric]
            perm = results['permutation'][comparison][metric]
            lines.append(
                f"| {comparison} | {metric} | {fmt(diff['point'], metric)} | [{fmt(diff['ci95'][0], metric)}, {fmt(diff['ci95'][1], metric)}] | {perm['exact_two_sided_p']:.4f} |"
            )

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Phase-1 significance analysis for StructRisk rankings')
    parser.add_argument('--public', default=str(PUBLIC_DEFAULT))
    parser.add_argument('--artifact', default=str(ARTIFACT_DEFAULT))
    parser.add_argument('--support', default=str(SUPPORT_DEFAULT))
    parser.add_argument('--asan', default=str(ASAN_DEFAULT))
    parser.add_argument('--crashstate', default=str(CRASHSTATE_DEFAULT))
    parser.add_argument('--reportknn', default=str(REPORTKNN_DEFAULT))
    parser.add_argument('--casr', default=str(CASR_DEFAULT))
    parser.add_argument('--llm-card', default=str(LLM_CARD_DEFAULT))
    parser.add_argument('--manual', default=str(MANUAL_DEFAULT))
    parser.add_argument('--lcr', default=str(LCR_DEFAULT))
    parser.add_argument('--bootstrap-rounds', type=int, default=20000)
    parser.add_argument('--seed', type=int, default=1337)
    parser.add_argument('--json-out', default=str(JSON_DEFAULT))
    parser.add_argument('--md-out', default=str(MD_DEFAULT))
    args = parser.parse_args()

    rankings = {
        'Public-Severity': load_jsonl(Path(args.public)),
    }
    artifact_path = Path(args.artifact)
    if artifact_path.exists():
        rankings['Artifact-Completeness'] = load_jsonl(artifact_path)
    support_path = Path(args.support)
    if support_path.exists():
        rankings['Support-Count'] = load_jsonl(support_path)
    asan_path = Path(args.asan)
    if asan_path.exists():
        rankings['ASan-Severity'] = load_jsonl(asan_path)
    crashstate_path = Path(args.crashstate)
    if crashstate_path.exists():
        rankings['Crash-State'] = load_jsonl(crashstate_path)
    reportknn_path = Path(args.reportknn)
    if reportknn_path.exists():
        rankings['StackDedup-kNN'] = load_jsonl(reportknn_path)
    casr_path = Path(args.casr)
    if casr_path.exists():
        rankings['CASR-Severity'] = load_jsonl(casr_path)
    llm_card_path = Path(args.llm_card)
    if llm_card_path.exists():
        rankings['LLM-CardScore'] = load_jsonl(llm_card_path)
    rankings['StructRisk'] = load_jsonl(Path(args.manual))
    results = compute_significance(rankings, bootstrap_rounds=args.bootstrap_rounds, seed=args.seed)

    json_out = Path(args.json_out)
    md_out = Path(args.md_out)
    json_out.write_text(json.dumps(results, indent=2), encoding='utf-8')
    md_out.write_text(to_markdown(results), encoding='utf-8')
    print(json_out)
    print(md_out)
    print(json.dumps(results['point_metrics'], indent=2))


if __name__ == '__main__':
    main()
