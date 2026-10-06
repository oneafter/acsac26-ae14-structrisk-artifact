#!/usr/bin/env python3
import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

from structrisk_rank import FEATURES as RANK_FEATURES
from structrisk_rank import annotate as annotate_ranked
from structrisk_rank import load_jsonl as load_rank_jsonl


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
WITHIN_DEFAULT = GENERATED / 'phase1_within10_eval.jsonl'
WEIGHTS_DEFAULT = GENERATED / 'phase1_offline_manual_weights.json'
JSON_DEFAULT = GENERATED / 'phase1_ablation.json'
MD_DEFAULT = GENERATED / 'phase1_ablation.md'

FEATURES = list(RANK_FEATURES)


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


def global_metrics(items):
    out = {}
    for k in (5, 10):
        out[f'HighRisk@{k}'] = sum(1 for item in items[:k] if (item.get('risk_level') or 0) >= 3)
        out[f'NDCG@{k}'] = round(ndcg_at_k(items, k), 4)
    first = None
    for idx, item in enumerate(items, start=1):
        if (item.get('risk_level') or 0) >= 3:
            first = idx
            break
    out['Rank-to-First-HighRisk'] = first
    return out


def relevance(item):
    return 1 if (item.get('risk_level') or 0) >= 3 else 0


def tie_blocks(items):
    ordered = sorted(items, key=lambda item: (-item['queue_score'], -item['structrisk_score'], item['id']))
    blocks = []
    current = []
    current_key = None
    for item in ordered:
        key = (round(item['queue_score'], 8), round(item['structrisk_score'], 8))
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
        # exact expectation over first positive within a random permutation of the block
        from math import comb
        denom = comb(n, h)
        total = 0.0
        for first_offset in range(1, n - h + 2):
            prob = comb(n - first_offset, h - 1) / denom
            total += prob / (preceding + first_offset)
        return total
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
            expected_prev_in_block = 0.0 if n == 1 else (offset - 1) * (h - 1) / (n - 1)
            expected_precision_if_positive = (preceding_positives + 1 + expected_prev_in_block) / rank
            ap += probability_positive * expected_precision_if_positive
        preceding_items += n
        preceding_positives += h
    return ap / total_positives


def within_project_metrics(items):
    by_project = defaultdict(list)
    for item in items:
        by_project[item['project']].append(item)
    rows = []
    for project, project_items in sorted(by_project.items()):
        positives = sum(relevance(item) for item in project_items)
        if positives == 0 or len(project_items) <= 1:
            continue
        blocks = tie_blocks(project_items)
        rows.append({
            'project': project,
            'HR@1': expected_hr_at_k(blocks, 1),
            'HR@3': expected_hr_at_k(blocks, 3),
            'NDCG@5': expected_ndcg_at_k(project_items, blocks, 5),
            'MRR': expected_mrr(blocks),
            'MAP': expected_map(project_items, blocks),
        })
    if not rows:
        return {}
    keys = ['HR@1', 'HR@3', 'NDCG@5', 'MRR', 'MAP']
    return {key: sum(row[key] for row in rows) / len(rows) for key in keys} | {'projects': len(rows)}


def rank_with_weights(rows, weights):
    return annotate_ranked([dict(row) for row in rows], weights, budget_aware=False)


def load_weights(path: Path):
    data = json.loads(path.read_text(encoding='utf-8'))
    return data['weights']


def summarize_variant(name, global_rows, within_rows, weights):
    ranked_global = rank_with_weights(global_rows, weights)
    ranked_within = rank_with_weights(within_rows, weights)
    return {
        'name': name,
        'weights': weights,
        'global': global_metrics(ranked_global),
        'within_project': within_project_metrics(ranked_within),
    }


def to_markdown(results):
    lines = [
        '# Phase-1 Ablation Summary',
        '',
        '| Variant | HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR | WP NDCG@5 | WP MRR | WP MAP |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
    ]
    for row in results:
        g = row['global']
        w = row['within_project']
        lines.append(
            f"| {row['name']} | {g['HighRisk@5']} | {g['HighRisk@10']} | {g['NDCG@5']:.4f} | {g['NDCG@10']:.4f} | {g['Rank-to-First-HighRisk']} | {w['NDCG@5']:.4f} | {w['MRR']:.4f} | {w['MAP']:.4f} |"
        )
    lines.extend([
        '',
        'Ablation is implemented by setting the corresponding fixed-prior weight to zero while leaving the other weights unchanged.',
    ])
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Feature ablation for the StructRisk phase-1 fixed scorer')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--within', default=str(WITHIN_DEFAULT))
    parser.add_argument('--weights', default=str(WEIGHTS_DEFAULT))
    parser.add_argument('--json-out', default=str(JSON_DEFAULT))
    parser.add_argument('--md-out', default=str(MD_DEFAULT))
    args = parser.parse_args()

    global_rows = load_rank_jsonl(Path(args.eval))
    within_rows = load_rank_jsonl(Path(args.within))
    base_weights = load_weights(Path(args.weights))

    results = [summarize_variant('Full', global_rows, within_rows, dict(base_weights))]
    for feature in FEATURES:
        ablated = dict(base_weights)
        ablated[feature] = 0.0
        results.append(summarize_variant(f'-{feature}', global_rows, within_rows, ablated))

    Path(args.json_out).write_text(json.dumps(results, indent=2), encoding='utf-8')
    Path(args.md_out).write_text(to_markdown(results), encoding='utf-8')
    print(Path(args.json_out))
    print(Path(args.md_out))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
