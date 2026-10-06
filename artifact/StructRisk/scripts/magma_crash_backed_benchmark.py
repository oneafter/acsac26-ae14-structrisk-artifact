#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

from magma_common import evaluate_global, evaluate_within
from phase1_artifact_baseline import artifact_score
from phase1_crash_baselines import asan_score, crash_state_score
from phase1_report_knn_baseline import build_document, fit_idf, score_eval_item as report_knn_score_eval_item, vectorize
from phase1_support_count_baseline import support_score
from structrisk_rank import DEFAULT_WEIGHTS, annotate, load_jsonl


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

TRAIN_DEFAULT = GENERATED / 'phase1_offline_dev.jsonl'
INPUT_DEFAULT = GENERATED / 'magma_unified_crash_backed_findings.jsonl'
PREFIX_DEFAULT = GENERATED / 'magma_unified_crash_backed_external'


def artifact_path(path: Path):
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def rank_simple(items, method_name, score_key, score_fn, sort_key=None):
    ranked = []
    for item in items:
        merged = dict(item)
        score = float(score_fn(item))
        merged[score_key] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        merged['structrisk_score'] = round(score, 4)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = {method_name: round(score, 4)}
        ranked.append(merged)
    if sort_key is None:
        ranked.sort(key=lambda item: (-float(item['queue_score']), item.get('project') or '', item.get('id') or ''))
    else:
        ranked.sort(key=sort_key)
    return ranked


def rank_artifact(items):
    ranked = []
    for item in items:
        score, contribution, reasons = artifact_score(item)
        merged = dict(item)
        merged['artifact_score'] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        merged['structrisk_score'] = round(score, 4)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = contribution
        merged['artifact_reasons'] = reasons
        ranked.append(merged)
    ranked.sort(key=lambda item: (-float(item['artifact_score']), item.get('project') or '', item.get('id') or ''))
    return ranked


def rank_support(items):
    ranked = []
    for item in items:
        score, tie_break, count = support_score(item)
        merged = dict(item)
        merged['support_count_score'] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        merged['structrisk_score'] = round(tie_break, 8)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = {'support_count': count}
        ranked.append(merged)
    ranked.sort(key=lambda item: (-float(item.get('queue_score') or 0.0), -float(item.get('structrisk_score') or 0.0), item.get('project') or '', item.get('id') or ''))
    return ranked


def rank_report_knn(train_rows, eval_rows, k=5):
    train_docs = [build_document(row) for row in train_rows]
    idf = fit_idf(train_docs)
    train_vecs = [vectorize(doc, idf) for doc in train_docs]
    ranked = []
    for row in eval_rows:
        eval_doc = build_document(row)
        eval_vec = vectorize(eval_doc, idf)
        score, neighbors = report_knn_score_eval_item(eval_vec, train_rows, train_vecs, k)
        merged = dict(row)
        merged['report_knn_score'] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        merged['structrisk_score'] = round(score, 4)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['report_knn_neighbor_ids'] = [neighbor_id for _, _, neighbor_id in neighbors]
        merged['report_knn_neighbor_sims'] = [round(similarity, 4) for similarity, _, _ in neighbors]
        merged['contribution'] = {'report_knn': round(score, 4)}
        ranked.append(merged)
    ranked.sort(key=lambda item: (-float(item['report_knn_score']), item.get('project') or '', item.get('id') or ''))
    return ranked


def write_summary(path: Path, input_path: Path, train_path: Path, eval_rows, metrics, project_rows, aux):
    high_count = sum(1 for row in eval_rows if int(row.get('risk_level') or 0) >= 3)
    project_count = len({row.get('project') for row in eval_rows})
    wp_projects = sum(1 for rows in Counter(row.get('project') for row in eval_rows).values() if rows > 1)
    is_unified = input_path.name == 'magma_unified_crash_backed_findings.jsonl'
    title = 'MAGMA Crash-Backed Validation Summary' if is_unified else 'MAGMA Component Replay Diagnostic Summary'
    ranking_heading = 'Main-Text Global Ranking' if is_unified else 'Diagnostic Global Ranking'
    explanatory_note = (
        'The structured `StructRisk` scores use the same frozen sign-constrained weights as the main phase-1 evaluation. '
        'The main-text MAGMA table uses Oracle-CVSS as a label-aware ceiling plus fixed crash-side baselines and CASR-Severity; '
        'auxiliary learned-comparator diagnostics are retained only in the metrics JSON.'
        if is_unified else
        'This component replay diagnostic reuses the same frozen StructRisk scorer, but it is not the submitted MAGMA validation table. '
        'The submitted paper reports the unified crash-backed slice that deduplicates exact local replays and public-PoC replays.'
    )
    main_methods = [
        'Oracle-CVSS',
        'Support-Count',
        'Artifact-Completeness',
        'ASan-Severity',
        'Crash-State',
        'CASR-Severity',
        'StructRisk',
    ]
    lines = [
        f'# {title}',
        '',
        f'- Input: `{artifact_path(input_path)}`',
        f'- Train: `{artifact_path(train_path)}`',
        f'- Findings: `{len(eval_rows)}`',
        f'- Projects: `{project_count}`',
        f'- HIGH-or-CRITICAL positives: `{high_count}`',
        f'- Multi-finding projects: `{wp_projects}`',
        '',
        explanatory_note,
        '',
        f'## {ranking_heading}',
        '',
        '| Method | HR@10 | NDCG@10 |',
        '| --- | ---: | ---: |',
    ]
    for method in main_methods:
        values = metrics['global'].get(method)
        if not values:
            continue
        lines.append(
            f"| {method} | {values.get('HighRisk@10')} | {values.get('NDCG@10'):.4f} |"
        )
    lines.extend([
        '',
        '## Notes',
        '',
        '- `Oracle-CVSS` is a label-aware upper bound using public CVSS only for evaluation-oriented ordering.',
        '- `Support-Count` is a transparent occurrence-count control.',
        '- The generated metrics JSON also retains auxiliary HR@5/First-HR, StackDedup-kNN, and per-project diagnostics for audit; they are not separate main-text claims.',
    ])
    if 'CASR-Severity' in metrics['global']:
        lines.append('- `CASR-Severity` replays one representative crash per finding inside the corresponding MAGMA ASAN image; cached reports can be reused without MAGMA-side tuning.')
    if not is_unified:
        lines.append('- This file is a component replay diagnostic retained for coverage auditing; the submitted MAGMA result is the unified crash-backed validation summary.')
    if project_rows.get('StructRisk'):
        lines.extend(['', '## Diagnostic StructRisk Per-Project Rows', '', '| Project | Findings | Positives | NDCG@5 | MAP |', '| --- | ---: | ---: | ---: | ---: |'])
        for row in project_rows['StructRisk']:
            lines.append(
                f"| {row['project']} | {row['findings']} | {row['positives']} | {row['NDCG@5']:.4f} | {row['MAP']:.4f} |"
            )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Evaluate crash-backed MAGMA findings under the main StructRisk-style finding-level pipeline.')
    parser.add_argument('--train', default=str(TRAIN_DEFAULT))
    parser.add_argument('--input', default=str(INPUT_DEFAULT))
    parser.add_argument('--out-prefix', default=str(PREFIX_DEFAULT))
    parser.add_argument('--casr-ranked', default='', help='Optional precomputed MAGMA CASR ranked JSONL. Defaults to <out-prefix>_casr_ranked.jsonl when present.')
    parser.add_argument('--report-knn-k', type=int, default=5)
    args = parser.parse_args()

    train_path = Path(args.train)
    input_path = Path(args.input)
    out_prefix = Path(args.out_prefix)
    casr_ranked_path = Path(args.casr_ranked) if args.casr_ranked else out_prefix.parent / f'{out_prefix.name}_casr_ranked.jsonl'

    train_rows = load_jsonl(train_path)
    eval_rows = load_jsonl(input_path)

    methods = {
        'Oracle-CVSS': rank_simple(eval_rows, 'oracle_cvss', 'oracle_cvss_score', lambda item: item.get('public_severity_score') or 0.0),
        'Support-Count': rank_support(eval_rows),
        'Artifact-Completeness': rank_artifact(eval_rows),
        'ASan-Severity': rank_simple(eval_rows, 'asan_severity', 'asan_severity_score', asan_score),
        'Crash-State': rank_simple(eval_rows, 'crash_state', 'crash_state_score', crash_state_score),
        'StackDedup-kNN': rank_report_knn(train_rows, eval_rows, k=args.report_knn_k),
        'StructRisk': annotate(eval_rows, dict(DEFAULT_WEIGHTS), budget_aware=False),
    }
    if casr_ranked_path.exists():
        methods['CASR-Severity'] = load_jsonl(casr_ranked_path)

    metrics = {'global': {}, 'within_project': {}, 'within_project_rows': {}}
    for method, ranked in methods.items():
        suffix = method.lower().replace('-', '_').replace(' ', '_')
        write_jsonl(out_prefix.parent / f'{out_prefix.name}_{suffix}_ranked.jsonl', ranked)
        metrics['global'][method] = evaluate_global(ranked)
        metrics['within_project'][method], metrics['within_project_rows'][method] = evaluate_within(ranked)

    payload = {
        'input': artifact_path(input_path),
        'train': artifact_path(train_path),
        'findings': len(eval_rows),
        'projects': len({row.get('project') for row in eval_rows}),
        'high_or_critical_positives': sum(1 for row in eval_rows if int(row.get('risk_level') or 0) >= 3),
        'high_findings': sum(1 for row in eval_rows if int(row.get('risk_level') or 0) >= 3),
        'global': metrics['global'],
        'within_project': metrics['within_project'],
        'within_project_rows': metrics['within_project_rows'],
        'casr_ranked': artifact_path(casr_ranked_path) if casr_ranked_path.exists() else '',
    }

    metrics_path = out_prefix.parent / f'{out_prefix.name}_metrics.json'
    summary_path = out_prefix.parent / f'{out_prefix.name}_summary.md'
    metrics_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    write_summary(
        summary_path,
        input_path,
        train_path,
        eval_rows,
        metrics,
        metrics['within_project_rows'],
        {},
    )
    print(metrics_path)
    print(summary_path)
    print(json.dumps({
        'input': artifact_path(input_path),
        'train': artifact_path(train_path),
        'findings': payload['findings'],
        'high_or_critical_positives': payload['high_or_critical_positives'],
        'global_structrisk': payload['global']['StructRisk'],
    }, indent=2))


if __name__ == '__main__':
    main()
