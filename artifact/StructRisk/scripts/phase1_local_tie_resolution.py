#!/usr/bin/env python3
import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

BASE_DEFAULT = GENERATED / 'phase1_offline_manual_ranked.jsonl'
CARD_DEFAULT = GENERATED / 'phase1_offline_llm_card_ranked.jsonl'
OUTPUT_DEFAULT = GENERATED / 'phase1_offline_llm_lcr_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_llm_lcr_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'phase1_offline_llm_lcr_summary.md'
STRUCTURED_SCORE_BAND = 0.50
WEAK_BUCKET_BAND = 0.10


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


def ndcg_at_k(items, cutoff):
    def dcg(sequence):
        total = 0.0
        for rank, item in enumerate(sequence[:cutoff], start=1):
            relevance = int(item.get('risk_level') or 0)
            total += ((2 ** relevance) - 1) / math.log2(rank + 1)
        return total

    ideal = sorted(items, key=lambda item: int(item.get('risk_level') or 0), reverse=True)
    denominator = dcg(ideal)
    return 0.0 if denominator == 0.0 else dcg(items) / denominator


def evaluate(items, high_threshold=3):
    metrics = {}
    for cutoff in (5, 10):
        metrics[f'HighRisk@{cutoff}'] = sum(1 for item in items[:cutoff] if int(item.get('risk_level') or 0) >= high_threshold)
        metrics[f'NDCG@{cutoff}'] = round(ndcg_at_k(items, cutoff), 4)
    first_hit = None
    cumulative_effort = 0.0
    first_effort = None
    high_count = 0
    for rank, item in enumerate(items, start=1):
        cumulative_effort += float(item.get('review_cost', 10.0))
        if int(item.get('risk_level') or 0) >= high_threshold:
            high_count += 1
            if first_hit is None:
                first_hit = rank
                first_effort = cumulative_effort
    metrics['Rank-to-First-HighRisk'] = first_hit if first_hit is not None else len(items) + 1
    metrics['Effort-to-First-HighRisk'] = None if first_effort is None else round(first_effort, 2)
    metrics['Effort-per-HighRisk'] = None if high_count == 0 else round(cumulative_effort / high_count, 2)
    return metrics


def weak_bucket(item):
    signals = item.get('signals') or {}
    try:
        weak = float(signals.get('weak') or 0.0)
    except (TypeError, ValueError):
        weak = 0.0
    return round(weak / WEAK_BUCKET_BAND) * WEAK_BUCKET_BAND


def primary_profile(item):
    score = float(item.get('queue_score') or item.get('structrisk_score') or 0.0)
    return (round(score / STRUCTURED_SCORE_BAND) * STRUCTURED_SCORE_BAND, weak_bucket(item))


def source_site_key(item):
    metadata = item.get('metadata') or {}
    location = (metadata.get('matched_project_loc') or '').strip()
    if not location:
        signature = (metadata.get('signature') or '').strip()
        signature_parts = signature.split('|')
        location = signature_parts[-1] if signature_parts else ''
    if ':' in location:
        location_parts = location.split(':')
        if len(location_parts) >= 3:
            location = ':'.join(location_parts[:-2])
    return location or ''


def project_blocks(items):
    ordered = sorted(items, key=lambda row: (-float(row.get('queue_score') or 0.0), row.get('id') or ''))
    blocks = []
    current = []
    current_key = None
    for item in ordered:
        key = primary_profile(item)
        if current and key != current_key:
            blocks.append(current)
            current = []
        current_key = key
        current.append(item)
    if current:
        blocks.append(current)
    return blocks


def rerank_block(block, card_by_id, seen_source_sites):
    remaining = list(block)
    reranked = []
    local_seen_source_sites = set(seen_source_sites)
    while remaining:
        selected = min(
            remaining,
            key=lambda item: (
                -float((card_by_id.get(item['id']) or {}).get('queue_score') or 0.0),
                1 if source_site_key(item) in local_seen_source_sites else 0,
                item.get('id') or '',
            ),
        )
        reranked.append(selected)
        remaining.remove(selected)
        source_site = source_site_key(selected)
        if source_site:
            local_seen_source_sites.add(source_site)
    return reranked


def apply_local_tie_resolution(base_rows, card_rows):
    card_by_id = {row['id']: row for row in card_rows}
    by_project = defaultdict(list)
    for item in base_rows:
        by_project[item['project']].append(dict(item))

    annotated_by_id = {}
    project_summaries = []
    for project, items in sorted(by_project.items()):
        blocks = project_blocks(items)
        seen_source_sites = set()
        changed_blocks = 0
        changed_items = 0
        for block_index, block in enumerate(blocks, start=1):
            if len(block) > 1:
                reranked = rerank_block(block, card_by_id, seen_source_sites)
                if [item.get('id') for item in reranked] != [item.get('id') for item in block]:
                    changed_blocks += 1
                    changed_items += len(block)
            else:
                reranked = block
            for local_offset, item in enumerate(reranked, start=1):
                merged = dict(item)
                card_score = float((card_by_id.get(item['id']) or {}).get('queue_score') or 0.0)
                source_site = source_site_key(item)
                local_score = -float(block_index) + (len(reranked) - local_offset + 1) * 1e-6
                merged['local_queue_score'] = round(local_score, 6)
                merged['local_structrisk_score'] = merged['local_queue_score']
                merged['local_tie_resolution'] = {
                    'project': project,
                    'block_index': block_index,
                    'block_size': len(block),
                    'profile': list(primary_profile(item)),
                    'base_queue_score': item.get('queue_score'),
                    'llm_card_score': round(card_score, 4),
                    'source_site': source_site,
                    'source_site_seen_before': bool(source_site and source_site in seen_source_sites),
                    'local_rank_in_block': local_offset,
                }
                annotated_by_id[item['id']] = merged
            for item in reranked:
                source_site = source_site_key(item)
                if source_site:
                    seen_source_sites.add(source_site)
        project_summaries.append({
            'project': project,
            'findings': len(items),
            'blocks': len(blocks),
            'reranked_blocks': changed_blocks,
            'reranked_items': changed_items,
        })

    output = [annotated_by_id[row['id']] for row in base_rows]
    return output, project_summaries


def write_summary(path: Path, metrics, project_summaries, ranked):
    lines = [
        '# Local Tie-Resolution Summary',
        '',
        'This variant keeps the StructRisk block order and uses leakage-controlled LLM card scores only to reorder project-local findings within the same half-point structured-score band and weak-evidence bucket. Source-site novelty is applied greedily as a deterministic secondary tie-break when LLM-card scores do not distinguish siblings.',
        '',
        '## Metrics',
        '',
    ]
    for key in ['HighRisk@5', 'NDCG@5', 'HighRisk@10', 'NDCG@10', 'Rank-to-First-HighRisk', 'Effort-to-First-HighRisk', 'Effort-per-HighRisk']:
        lines.append(f'- `{key}={metrics.get(key)}`')
    lines.extend([
        '',
        '## Project Blocks',
        '',
        '| Project | Findings | Blocks | Reranked Blocks | Reranked Items |',
        '| --- | ---: | ---: | ---: | ---: |',
    ])
    for row in project_summaries:
        lines.append(
            f"| {row['project']} | {row['findings']} | {row['blocks']} | {row['reranked_blocks']} | {row['reranked_items']} |"
        )
    lines.extend([
        '',
        '## Largest Reranked Blocks',
        '',
        '| Rank | Finding | Project | Risk | Block Size | Base Score | LLM Card Score |',
        '| ---: | --- | --- | ---: | ---: | ---: | ---: |',
    ])
    reranked = [item for item in ranked if item.get('local_tie_resolution', {}).get('block_size', 1) > 1]
    reranked.sort(key=lambda item: (-item['local_tie_resolution']['block_size'], item.get('project') or '', item.get('id') or ''))
    for item in reranked[:20]:
        tie = item['local_tie_resolution']
        lines.append(
            f"| {ranked.index(item) + 1} | `{item.get('id')}` | {item.get('project')} | {item.get('risk_level')} | {tie['block_size']} | {float(tie['base_queue_score'] or 0.0):.4f} | {tie['llm_card_score']:.4f} |"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='StructRisk local tie resolution with leakage-controlled LLM card scores')
    parser.add_argument('--base', default=str(BASE_DEFAULT))
    parser.add_argument('--llm-card', default=str(CARD_DEFAULT))
    parser.add_argument('--output', default=str(OUTPUT_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    args = parser.parse_args()

    base_rows = load_jsonl(Path(args.base))
    card_rows = load_jsonl(Path(args.llm_card))
    ranked, project_summaries = apply_local_tie_resolution(base_rows, card_rows)
    metrics = evaluate(ranked)

    write_jsonl(Path(args.output), ranked)
    Path(args.metrics_out).write_text(json.dumps({'metrics': metrics, 'project_summaries': project_summaries}, indent=2), encoding='utf-8')
    write_summary(Path(args.summary_out), metrics, project_summaries, ranked)
    print(Path(args.output))
    print(Path(args.metrics_out))
    print(Path(args.summary_out))
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
