#!/usr/bin/env python3
import argparse
import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
CVSS_DEFAULT = STRUCTRISK / 'user75_cve_summary.csv'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
RANKED_DEFAULT = GENERATED / 'phase1_offline_public_severity_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_public_severity_metrics.json'


def load_cvss(path: Path):
    out = {}
    with path.open(encoding='utf-8') as handle:
        for row in csv.DictReader(handle):
            project = row['project'].strip()
            try:
                score = float(row.get('highest_cvss31') or row.get('cvss31_score') or 0.0)
            except ValueError:
                score = 0.0
            out[project] = max(out.get(project, 0.0), score)
    return out


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


def ndcg_at_k(items, k):
    ranked = items[:k]

    def dcg(seq):
        total = 0.0
        for idx, item in enumerate(seq, start=1):
            rel = item.get('risk_level') or 0
            gain = (2 ** rel) - 1
            total += gain / math.log2(idx + 1)
        return total

    ideal = sorted(items, key=lambda item: item.get('risk_level') or 0, reverse=True)[:k]
    denom = dcg(ideal)
    return 0.0 if denom == 0.0 else dcg(ranked) / denom


def evaluate(items, high_threshold=3, ks=(5, 10)):
    labeled = [item for item in items if item.get('risk_level') is not None]
    metrics = {}
    for k in ks:
        topk = labeled[:k]
        metrics[f'HighRisk@{k}'] = sum(1 for item in topk if item['risk_level'] >= high_threshold)
        metrics[f'NDCG@{k}'] = round(ndcg_at_k(labeled, k), 4)
    cumulative_effort = 0.0
    first_hit_rank = None
    first_hit_effort = None
    high_count = 0
    for idx, item in enumerate(labeled, start=1):
        cumulative_effort += float(item.get('review_cost', 10.0))
        if item['risk_level'] >= high_threshold:
            high_count += 1
            if first_hit_rank is None:
                first_hit_rank = idx
                first_hit_effort = cumulative_effort
    metrics['Rank-to-First-HighRisk'] = first_hit_rank
    metrics['Effort-to-First-HighRisk'] = None if first_hit_effort is None else round(first_hit_effort, 2)
    metrics['Effort-per-HighRisk'] = None if high_count == 0 else round(cumulative_effort / high_count, 2)
    return metrics


def main():
    parser = argparse.ArgumentParser(description='Score-only Public-Severity baseline for StructRisk phase-1')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--cvss', default=str(CVSS_DEFAULT))
    parser.add_argument('--output', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    args = parser.parse_args()

    cvss = load_cvss(Path(args.cvss))
    rows = load_jsonl(Path(args.eval))
    ranked = []
    for row in rows:
        score = round(cvss.get(row['project'], 0.0) / 10.0, 4)
        merged = dict(row)
        merged['public_severity_score'] = score
        merged['structrisk_score'] = score
        merged['queue_score'] = score
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = {'public_severity': score}
        ranked.append(merged)
    ranked.sort(key=lambda item: (-item['public_severity_score'], item['project'], item['id']))
    metrics = evaluate(ranked)
    write_jsonl(Path(args.output), ranked)
    Path(args.metrics_out).write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    print(Path(args.output))
    print(Path(args.metrics_out))
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
