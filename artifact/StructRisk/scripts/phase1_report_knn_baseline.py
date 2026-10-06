#!/usr/bin/env python3
import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
DEV_DEFAULT = GENERATED / 'phase1_offline_dev.jsonl'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
RANKED_DEFAULT = GENERATED / 'phase1_offline_reportknn_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_reportknn_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'phase1_offline_reportknn_summary.md'

TOKEN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]+')
FIELDS = [
    'matched_summary_line',
    'matched_asan_type',
    'matched_project_loc',
    'matched_assertion',
]


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


def tokenize(text: str):
    return [token.lower() for token in TOKEN_RE.findall(text or '') if len(token) > 1]


def build_document(row):
    meta = row.get('metadata', {})
    parts = []
    for field in FIELDS:
        value = meta.get(field) or ''
        if value:
            parts.append(value)
    return tokenize(' '.join(parts))


def fit_idf(docs):
    df = Counter()
    for doc in docs:
        for token in set(doc):
            df[token] += 1
    n_docs = len(docs)
    return {token: math.log((1 + n_docs) / (1 + freq)) + 1.0 for token, freq in df.items()}


def vectorize(doc, idf):
    tf = Counter(doc)
    vec = {token: count * idf.get(token, 0.0) for token, count in tf.items() if token in idf}
    norm = math.sqrt(sum(value * value for value in vec.values())) or 1.0
    return {token: value / norm for token, value in vec.items()}


def cosine(lhs, rhs):
    if len(lhs) > len(rhs):
        lhs, rhs = rhs, lhs
    return sum(value * rhs.get(token, 0.0) for token, value in lhs.items())


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


def score_eval_item(eval_vec, train_rows, train_vecs, k):
    sims = []
    for train_row, train_vec in zip(train_rows, train_vecs):
        sim = cosine(eval_vec, train_vec)
        if sim > 0.0:
            sims.append((sim, float(train_row.get('risk_level', 0)) / 3.0, train_row['id']))
    sims.sort(key=lambda item: (-item[0], item[2]))
    top = sims[:k]
    if not top:
        return 0.0, []
    numerator = sum(sim * target for sim, target, _ in top)
    denominator = sum(sim for sim, _, _ in top) or 1.0
    return numerator / denominator, top


def write_summary(path: Path, ranked, metrics):
    lines = ['# StackDedup-kNN Baseline Summary', '', '## Primary Metrics']
    for key in ['HighRisk@5', 'HighRisk@10', 'NDCG@5', 'NDCG@10', 'Rank-to-First-HighRisk', 'Effort-to-First-HighRisk']:
        lines.append(f'- `{key}={metrics.get(key)}`')
    lines.extend(['', '## Top-10 Findings'])
    for idx, item in enumerate(ranked[:10], start=1):
        lines.append(
            f'- `{idx}`. `{item["id"]}` risk={item.get("risk_level")} '
            f'score={item.get("report_knn_score")} '
            f'neighbors={item.get("report_knn_neighbor_ids", [])[:3]}'
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Crash-report kNN baseline for StructRisk phase-1')
    parser.add_argument('--dev', default=str(DEV_DEFAULT))
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--output', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    parser.add_argument('--k', type=int, default=5)
    args = parser.parse_args()

    train_rows = load_jsonl(Path(args.dev))
    eval_rows = load_jsonl(Path(args.eval))

    train_docs = [build_document(row) for row in train_rows]
    idf = fit_idf(train_docs)
    train_vecs = [vectorize(doc, idf) for doc in train_docs]

    ranked = []
    for row in eval_rows:
        eval_doc = build_document(row)
        eval_vec = vectorize(eval_doc, idf)
        score, neighbors = score_eval_item(eval_vec, train_rows, train_vecs, args.k)
        merged = dict(row)
        merged['report_knn_score'] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        merged['structrisk_score'] = round(score, 4)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['report_knn_neighbor_ids'] = [neighbor_id for _, _, neighbor_id in neighbors]
        merged['report_knn_neighbor_sims'] = [round(sim, 4) for sim, _, _ in neighbors]
        merged['contribution'] = {'report_knn': round(score, 4)}
        ranked.append(merged)

    ranked.sort(key=lambda item: (-item['report_knn_score'], item['project'], item['id']))
    metrics = evaluate(ranked)
    payload = {'metrics': metrics, 'k': args.k}
    write_jsonl(Path(args.output), ranked)
    Path(args.metrics_out).write_text(json.dumps(payload, indent=2), encoding='utf-8')
    write_summary(Path(args.summary_out), ranked, metrics)
    print(Path(args.output))
    print(Path(args.metrics_out))
    print(Path(args.summary_out))
    print(json.dumps(payload, indent=2))


if __name__ == '__main__':
    main()
