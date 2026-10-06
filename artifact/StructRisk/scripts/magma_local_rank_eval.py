#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from magma_common import evaluate_global, evaluate_within
from phase1_crash_baselines import asan_score, crash_state_score
from structrisk_rank import DEFAULT_WEIGHTS, annotate, load_jsonl


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
INPUT_DEFAULT = GENERATED / 'magma_local_crash_backed_findings.jsonl'
PREFIX_DEFAULT = GENERATED / 'magma_local_crash_backed'


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def rank_by(items, name, score_fn):
    ranked = []
    for item in items:
        merged = dict(item)
        score = float(score_fn(item))
        merged['queue_score'] = round(score, 6)
        merged['structrisk_score'] = round(score, 6)
        merged['contribution'] = {name: round(score, 6)}
        merged['confidence'] = merged.get('confidence')
        merged['low_confidence'] = bool(merged.get('low_confidence', False))
        ranked.append(merged)
    ranked.sort(key=lambda item: (-float(item['queue_score']), item.get('project') or '', item.get('id') or ''))
    return ranked


def structrisk_rank(items):
    ranked = annotate(items, dict(DEFAULT_WEIGHTS), budget_aware=False)
    for item in ranked:
        item.setdefault('contribution', {})
    return ranked


def write_summary(path, input_path, methods, metrics):
    lines = [
        '# MAGMA Local Ranking Summary',
        '',
        f'- Input: `{input_path}`',
        f'- Findings: `{len(next(iter(methods.values()), []))}`',
        '',
        '## Global Ranking',
        '',
        '| Method | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR |',
        '| --- | ---: | ---: | ---: | ---: | ---: |',
    ]
    for method, values in metrics['global'].items():
        lines.append(
            f"| {method} | {values.get('HighRisk@5')} | {values.get('HighRisk@10')} | {values.get('NDCG@5'):.4f} | {values.get('NDCG@10'):.4f} | {values.get('Rank-to-First-HighRisk')} |"
        )
    lines.extend([
        '',
        '## Within-Project Ranking',
        '',
        '| Method | Projects | HR@1 | HR@3 | NDCG@5 | MRR | MAP |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: |',
    ])
    for method, values in metrics['within_project'].items():
        lines.append(
            f"| {method} | {values.get('projects', 0)} | {values.get('HR@1', 0):.4f} | {values.get('HR@3', 0):.4f} | {values.get('NDCG@5', 0):.4f} | {values.get('MRR', 0):.4f} | {values.get('MAP', 0):.4f} |"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Rank MAGMA local crash-backed findings with StructRisk and baselines.')
    parser.add_argument('--input', default=str(INPUT_DEFAULT))
    parser.add_argument('--out-prefix', default=str(PREFIX_DEFAULT))
    args = parser.parse_args()

    input_path = Path(args.input)
    items = load_jsonl(input_path)
    methods = {
        'StructRisk': structrisk_rank(items),
        'Crash-State': rank_by(items, 'crash_state', crash_state_score),
        'ASan-Severity': rank_by(items, 'asan_severity', asan_score),
        'Public-Severity': rank_by(items, 'public_severity', lambda item: item.get('public_severity_score') or 0.0),
    }
    prefix = Path(args.out_prefix)
    metrics = {'global': {}, 'within_project': {}}
    for method, ranked in methods.items():
        suffix = method.lower().replace('-', '_').replace(' ', '_')
        write_jsonl(prefix.parent / f'{prefix.name}_{suffix}_ranked.jsonl', ranked)
        metrics['global'][method] = evaluate_global(ranked)
        metrics['within_project'][method], _ = evaluate_within(ranked)
    metrics_path = prefix.parent / f'{prefix.name}_rank_metrics.json'
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    summary_path = prefix.parent / f'{prefix.name}_rank_summary.md'
    write_summary(summary_path, input_path, methods, metrics)
    print(metrics_path)
    print(summary_path)
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
