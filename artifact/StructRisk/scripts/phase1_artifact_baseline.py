#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
RANKED_DEFAULT = GENERATED / 'phase1_offline_artifact_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_artifact_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'phase1_offline_artifact_summary.md'


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


def report_score(level: str):
    level = (level or '').strip().lower()
    if level == 'exact':
        return 2.0, 'exact-report-match'
    if level == 'project':
        return 1.0, 'project-report-match'
    return 0.0, 'no-report-match'


def support_score(count):
    try:
        count = int(count or 0)
    except (TypeError, ValueError):
        count = 0
    return min(1.75, math.log1p(count) * 0.45), count


def artifact_score(item):
    meta = item.get('metadata', {})
    report, report_reason = report_score(meta.get('report_match_level', ''))
    cmdline = 1.0 if (meta.get('cmdline_file') or '').strip() else 0.0
    assertion = 0.75 if (meta.get('matched_assertion') or '').strip() else 0.0
    support, support_count = support_score(meta.get('support_count', 0))
    campaign_count = len(meta.get('campaigns') or [])
    campaigns = min(0.75, math.log1p(campaign_count) * 0.35)

    penalty = 0.0
    penalties = []
    if report == 0.0 and assertion == 0.0:
        penalty -= 1.0
        penalties.append('no-report-and-no-assertion')
    if support_count <= 1:
        penalty -= 0.25
        penalties.append('singleton-support')

    score = report + cmdline + assertion + support + campaigns + penalty
    contribution = {
        'report': round(report, 4),
        'cmdline': round(cmdline, 4),
        'assertion': round(assertion, 4),
        'support': round(support, 4),
        'campaigns': round(campaigns, 4),
        'penalty': round(penalty, 4),
    }
    reasons = {
        'report': report_reason,
        'support_count': support_count,
        'campaign_count': campaign_count,
        'penalties': penalties,
    }
    return round(score, 4), contribution, reasons


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


def write_summary(path: Path, ranked, metrics):
    lines = ['# Artifact-Completeness Baseline Summary', '']
    lines.append('## Primary Metrics')
    for key in ['HighRisk@5', 'HighRisk@10', 'NDCG@5', 'NDCG@10', 'Rank-to-First-HighRisk', 'Effort-to-First-HighRisk']:
        lines.append(f'- `{key}={metrics.get(key)}`')
    lines.extend(['', '## Top-10 Findings'])
    for idx, item in enumerate(ranked[:10], start=1):
        meta = item.get('metadata', {})
        lines.append(
            f'- `{idx}`. `{item["id"]}` risk={item.get("risk_level")} score={item.get("artifact_score")}'
            f' report=`{meta.get("report_match_level", "")}` support=`{meta.get("support_count", 0)}` cmdline=`{meta.get("cmdline_file", "")}`'
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Artifact-completeness baseline for StructRisk phase-1')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--output', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    args = parser.parse_args()

    rows = load_jsonl(Path(args.eval))
    ranked = []
    for row in rows:
        score, contribution, reasons = artifact_score(row)
        merged = dict(row)
        merged['artifact_score'] = score
        merged['queue_score'] = score
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = contribution
        merged['artifact_reasons'] = reasons
        ranked.append(merged)

    ranked.sort(key=lambda item: (-item['artifact_score'], item['project'], item['id']))
    metrics = evaluate(ranked)
    write_jsonl(Path(args.output), ranked)
    Path(args.metrics_out).write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    write_summary(Path(args.summary_out), ranked, metrics)
    print(Path(args.output))
    print(Path(args.metrics_out))
    print(Path(args.summary_out))
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
