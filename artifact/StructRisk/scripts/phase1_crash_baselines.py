#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def support_count(item):
    return int(item.get('metadata', {}).get('support_count') or 0)


def asan_score(item):
    meta = item.get('metadata', {})
    asan = (meta.get('matched_asan_type') or '').strip().lower()
    # Approximate LLVM ASan's bug-type scariness ordering without using access
    # size, read/write direction, or far-from-bounds details that are not
    # reliably retained in the evidence card.
    if asan in {'stack-use-after-return'}:
        return 30.0
    if asan in {'stack-buffer-overflow', 'stack-buffer-underflow', 'dynamic-stack-buffer-overflow'}:
        return 25.0
    if asan in {'use-after-free', 'heap-use-after-free', 'double-free', 'use-after-poison'}:
        return 20.0
    if asan in {
        'heap-buffer-overflow',
        'heap-buffer-underflow',
        'global-buffer-overflow',
        'container-overflow',
        'stack-use-after-scope',
        'intra-object-overflow',
    }:
        return 10.0
    if 'buffer-overflow' in asan or 'buffer-underflow' in asan or 'out-of-bounds' in asan or asan == 'requested':
        return 10.0
    if asan == 'initialization-order-fiasco':
        return 1.0
    if asan in {'deadlysignal', 'segv'}:
        return 2.0
    return 0.0


def crash_state_score(item):
    meta = item.get('metadata', {})
    base = asan_score(item)
    has_loc = bool((meta.get('matched_project_loc') or '').strip())
    has_summary = bool((meta.get('matched_summary_line') or '').strip())
    exact_report = meta.get('report_match_level') == 'exact'
    support = support_count(item)
    return round(
        base
        + (1.0 if has_loc else 0.0)
        + (0.5 if has_summary else 0.0)
        + (0.5 if exact_report else 0.0)
        + min(1.0, math.log1p(support) / 4.0),
        4,
    )


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


def evaluate(items, high_threshold=3, ks=(5, 10)):
    metrics = {}
    for k in ks:
        metrics[f'HighRisk@{k}'] = sum(1 for item in items[:k] if item.get('risk_level', 0) >= high_threshold)
        metrics[f'NDCG@{k}'] = round(ndcg_at_k(items, k), 4)
    first_hit = None
    high_count = 0
    cumulative_effort = 0.0
    first_effort = None
    for idx, item in enumerate(items, start=1):
        cumulative_effort += float(item.get('review_cost', 10.0))
        if item.get('risk_level', 0) >= high_threshold:
            high_count += 1
            if first_hit is None:
                first_hit = idx
                first_effort = cumulative_effort
    metrics['Rank-to-First-HighRisk'] = first_hit
    metrics['Effort-to-First-HighRisk'] = None if first_effort is None else round(first_effort, 2)
    metrics['Effort-per-HighRisk'] = None if high_count == 0 else round(cumulative_effort / high_count, 2)
    return metrics


def build_ranking(rows, method):
    ranked = []
    for row in rows:
        merged = dict(row)
        if method == 'asan':
            score = asan_score(row)
            merged['asan_severity_score'] = score
            merged['queue_score'] = score
            merged['structrisk_score'] = score
            merged['contribution'] = {'asan_severity': score}
        elif method == 'crashstate':
            score = crash_state_score(row)
            merged['crash_state_score'] = score
            merged['queue_score'] = score
            merged['structrisk_score'] = score
            merged['contribution'] = {'crash_state': score}
        else:
            raise ValueError(method)
        merged['confidence'] = None
        merged['low_confidence'] = False
        ranked.append(merged)
    ranked.sort(key=lambda item: (-item['queue_score'], item['project'], item['id']))
    return ranked


def write_summary(path: Path, method, ranked, metrics):
    lines = [f'# {method} Baseline Summary', '', '## Metrics']
    for key, value in metrics.items():
        lines.append(f'- `{key}={value}`')
    lines.extend(['', '## Top-10 Findings'])
    for idx, item in enumerate(ranked[:10], start=1):
        meta = item.get('metadata', {})
        lines.append(
            f'- `{idx}`. `{item["id"]}` risk={item.get("risk_level")} score={item.get("queue_score")}'
            f' asan=`{meta.get("matched_asan_type", "")}` loc=`{meta.get("matched_project_loc", "")}`'
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='ASan and crash-state baselines for StructRisk phase-1')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--out-prefix', default=str(GENERATED / 'phase1_offline'))
    args = parser.parse_args()

    rows = load_jsonl(Path(args.eval))
    for method, display in [('asan', 'ASan-Severity'), ('crashstate', 'Crash-State')]:
        ranked = build_ranking(rows, method)
        metrics = evaluate(ranked)
        prefix = Path(args.out_prefix)
        ranked_out = prefix.parent / f'{prefix.name}_{method}_ranked.jsonl'
        metrics_out = prefix.parent / f'{prefix.name}_{method}_metrics.json'
        summary_out = prefix.parent / f'{prefix.name}_{method}_summary.md'
        write_jsonl(ranked_out, ranked)
        metrics_out.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        write_summary(summary_out, display, ranked, metrics)
        print(ranked_out)
        print(metrics_out)
        print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
