#!/usr/bin/env python3
import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'


DEFAULT_METHODS = [
    ('Public-Severity', GENERATED / 'phase1_within10_public_severity_ranked.jsonl'),
    ('Support-Count', GENERATED / 'phase1_within10_support_count_ranked.jsonl'),
    ('Artifact-Completeness', GENERATED / 'phase1_within10_artifact_ranked.jsonl'),
    ('ASan-Severity', GENERATED / 'phase1_within10_asan_ranked.jsonl'),
    ('Crash-State', GENERATED / 'phase1_within10_crashstate_ranked.jsonl'),
    ('StackDedup-kNN', GENERATED / 'phase1_within10_reportknn_ranked.jsonl'),
    ('CASR-Severity', GENERATED / 'phase1_within10_casr_ranked.jsonl'),
    ('LLM-CardScore', GENERATED / 'phase1_within10_llm_card_ranked.jsonl'),
    ('StructRisk', GENERATED / 'phase1_within10_manual_ranked.jsonl'),
    ('StructRisk+LLM-LCR', GENERATED / 'phase1_within10_llm_lcr_ranked.jsonl'),
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


def comb(n, r):
    if r < 0 or r > n:
        return 0
    return math.comb(n, r)


def expected_mrr(blocks):
    preceding = 0
    for block in blocks:
        n = len(block)
        h = sum(relevance(item) for item in block)
        if h == 0:
            preceding += n
            continue
        denom = comb(n, h)
        expected = 0.0
        for first_offset in range(1, n - h + 2):
            probability = comb(n - first_offset, h - 1) / denom
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
        'NDCG@3': expected_ndcg_at_k(items, blocks, 3),
        'NDCG@5': expected_ndcg_at_k(items, blocks, 5),
        'MRR': expected_mrr(blocks),
        'MAP': expected_map(items, blocks),
    }


def average(rows):
    if not rows:
        return {}
    keys = ['HR@1', 'HR@3', 'NDCG@3', 'NDCG@5', 'MRR', 'MAP']
    return {key: sum(row[key] for row in rows) / len(rows) for key in keys}


def format_float(value):
    return f'{value:.4f}'


def write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ['scope', 'method', 'projects', 'HR@1', 'HR@3', 'NDCG@3', 'NDCG@5', 'MRR', 'MAP']
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(rows, project_rows):
    lines = [
        '# Within-Project Ranking Summary',
        '',
        'Tie-aware expectations are used when a method assigns the same score to multiple findings within a project.',
        '',
        '## Macro Averages',
        '',
        '| Scope | Method | Projects | HR@1 | HR@3 | NDCG@3 | NDCG@5 | MRR | MAP |',
        '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
    ]
    for row in rows:
        lines.append(
            f"| {row['scope']} | {row['method']} | {row['projects']} | {row['HR@1']} | {row['HR@3']} | {row['NDCG@3']} | {row['NDCG@5']} | {row['MRR']} | {row['MAP']} |"
        )
    lines.extend(['', '## Per-Project Rows', '', '| Method | Project | Findings | Positives | HR@1 | HR@3 | NDCG@5 | MRR | MAP |', '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'])
    for row in project_rows:
        lines.append(
            f"| {row['method']} | {row['project']} | {row['findings']} | {row['positives']} | {row['HR@1']} | {row['HR@3']} | {row['NDCG@5']} | {row['MRR']} | {row['MAP']} |"
        )
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Tie-aware within-project evaluation for StructRisk phase-1')
    parser.add_argument('--method', action='append', default=[], help='Override method inputs with NAME=PATH (repeatable)')
    parser.add_argument('--project', action='append', default=[], help='Restrict evaluation to the named project(s) (repeatable)')
    parser.add_argument('--json-out', default=str(GENERATED / 'phase1_within_project_metrics.json'))
    parser.add_argument('--csv-out', default=str(GENERATED / 'phase1_within_project_metrics.csv'))
    parser.add_argument('--md-out', default=str(GENERATED / 'phase1_within_project_metrics.md'))
    args = parser.parse_args()

    methods = parse_method_specs(args.method) if args.method else DEFAULT_METHODS
    project_filter = set(args.project)

    macro_rows = []
    project_rows = []
    result = {'macro': [], 'projects': []}
    for method, path in methods:
        if not path.exists():
            continue
        rows = load_jsonl(path)
        by_project = defaultdict(list)
        for row in rows:
            if project_filter and row['project'] not in project_filter:
                continue
            by_project[row['project']].append(row)
        all_project_metrics = []
        multi_project_metrics = []
        for project, items in sorted(by_project.items()):
            positives = sum(relevance(item) for item in items)
            if positives == 0:
                continue
            metrics = evaluate_project(items)
            all_project_metrics.append(metrics)
            if len(items) > 1:
                multi_project_metrics.append(metrics)
            project_row = {
                'method': method,
                'project': project,
                'findings': len(items),
                'positives': positives,
            }
            for key, value in metrics.items():
                project_row[key] = format_float(value)
            project_rows.append(project_row)
            result['projects'].append({'method': method, 'project': project, 'findings': len(items), 'positives': positives, **metrics})
        for scope, metrics_rows in [('all-positive-projects', all_project_metrics), ('multi-finding-projects', multi_project_metrics)]:
            avg = average(metrics_rows)
            if not avg:
                continue
            row = {'scope': scope, 'method': method, 'projects': len(metrics_rows)}
            row.update({key: format_float(value) for key, value in avg.items()})
            macro_rows.append(row)
            result['macro'].append({'scope': scope, 'method': method, 'projects': len(metrics_rows), **avg})

    Path(args.json_out).write_text(json.dumps(result, indent=2), encoding='utf-8')
    write_csv(Path(args.csv_out), macro_rows)
    Path(args.md_out).write_text(to_markdown(macro_rows, project_rows), encoding='utf-8')
    print(Path(args.json_out))
    print(Path(args.csv_out))
    print(Path(args.md_out))
    print(json.dumps(result['macro'], indent=2))


if __name__ == '__main__':
    main()
