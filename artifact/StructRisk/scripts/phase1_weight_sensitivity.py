#!/usr/bin/env python3
import argparse
import itertools
import json
import subprocess
import sys
from pathlib import Path

from structrisk_rank import DEFAULT_WEIGHTS, evaluate, load_jsonl, annotate

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
FEATURES = ['replay', 'locality', 'evidence_uniqueness_gated', 'failure_semantics_gated', 'sanitizer', 'weak']
SCALES = [0.8, 1.0, 1.2]


def artifact_path(path):
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def run_within_eval(method_name, ranked_path, json_out, csv_out, md_out):
    subprocess.run([
        sys.executable,
        str(STRUCTRISK / 'scripts' / 'phase1_within_project_eval.py'),
        '--method', f'{method_name}={ranked_path}',
        '--json-out', str(json_out),
        '--csv-out', str(csv_out),
        '--md-out', str(md_out),
    ], check=True)


def run_lcr(base_path, llm_card_path, output_path, metrics_path, summary_path):
    subprocess.run([
        sys.executable,
        str(STRUCTRISK / 'scripts' / 'phase1_local_tie_resolution.py'),
        '--base', str(base_path),
        '--llm-card', str(llm_card_path),
        '--output', str(output_path),
        '--metrics-out', str(metrics_path),
        '--summary-out', str(summary_path),
    ], check=True)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_macro(path, method_name):
    payload = read_json(path)
    for row in payload.get('macro', []):
        if row.get('scope') == 'all-positive-projects' and row.get('method') == method_name:
            return row
    return {}


def rank_with_weights(rows, weights):
    return annotate([dict(row) for row in rows], weights, budget_aware=False)


def scaled_weights(scales):
    weights = dict(DEFAULT_WEIGHTS)
    for feature, scale in scales.items():
        weights[feature] = DEFAULT_WEIGHTS[feature] * scale
    return weights


def variants(mode, include_full_grid):
    yield 'base', {feature: 1.0 for feature in FEATURES}, 'base fixed prior'
    for feature in FEATURES:
        for scale in (0.8, 1.2):
            scales = {name: 1.0 for name in FEATURES}
            scales[feature] = scale
            label = f'oat_{feature}_{int(scale * 100)}'
            yield label, scales, f'one-at-a-time {feature} x {scale}'
    if include_full_grid:
        for combo in itertools.product((0.8, 1.2), repeat=len(FEATURES)):
            scales = dict(zip(FEATURES, combo))
            suffix = '_'.join('lo' if value < 1 else 'hi' for value in combo)
            yield f'corners_{suffix}', scales, 'full ±20% corner'


def summarize_values(rows, metric, key):
    values = [row[metric][key] for row in rows if key in row.get(metric, {}) and row[metric][key] is not None]
    if not values:
        return {}
    base = next((row[metric][key] for row in rows if row['variant'] == 'base'), values[0])
    return {
        'base': base,
        'min': min(values),
        'max': max(values),
        'spread': max(values) - min(values),
        'count': len(values),
    }


def write_summary(path, payload):
    lines = [
        '# StructRisk Weight Sensitivity',
        '',
        'This experiment perturbs the fixed StructRisk prior weights without using Eval/MAGMA labels to select a replacement. It reports stability envelopes; the manuscript primary scorer remains the shipped fixed prior.',
        '',
        '## Perturbation Design',
        '',
        f"- Features: `{', '.join(FEATURES)}`",
        '- One-at-a-time perturbations: each weight scaled by 0.8 or 1.2.',
        '- Full-corner perturbations: all six weights independently scaled by 0.8 or 1.2.',
        '- LCR checks reuse cached LLM-CardScore outputs for deterministic same-project score-band and weak-bucket tie resolution with greedy source-site novelty.',
        '',
        '## Envelope Summary',
        '',
        '| Slice | Metric | Base | Min | Max | Spread | Variants |',
        '| --- | --- | ---: | ---: | ---: | ---: | ---: |',
    ]
    for slice_name, metrics in payload['envelopes'].items():
        for metric_name, values in metrics.items():
            if not values:
                continue
            lines.append(
                f"| {slice_name} | {metric_name} | {values['base']} | {values['min']} | {values['max']} | {values['spread']} | {values['count']} |"
            )
    lines.extend(['', '## Interpretation', ''])
    lines.append('- Small spreads indicate that the result is not tied to a single numerically precise fixed-prior weight vector.')
    lines.append('- Variants are not used to choose a replacement scorer; they are reported only as robustness checks against post-hoc tuning concerns.')
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Perturb StructRisk fixed-prior weights and summarize metric stability.')
    parser.add_argument('--phase-eval', default=str(GENERATED / 'phase1_offline_eval.jsonl'))
    parser.add_argument('--within-eval', default=str(GENERATED / 'phase1_within10_eval.jsonl'))
    parser.add_argument('--phase-llm-card', default=str(GENERATED / 'phase1_offline_llm_card_ranked.jsonl'))
    parser.add_argument('--within-llm-card', default=str(GENERATED / 'phase1_within10_llm_card_ranked.jsonl'))
    parser.add_argument('--prefix', default='phase1_weight_sensitivity')
    parser.add_argument('--include-full-grid', action='store_true', default=True)
    parser.add_argument('--run-lcr', action='store_true', default=True)
    args = parser.parse_args()

    phase_rows = load_jsonl(args.phase_eval)
    within_rows = load_jsonl(args.within_eval)
    out_dir = GENERATED / f'{args.prefix}_ranked'
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for label, scales, description in variants('all', args.include_full_grid):
        weights = scaled_weights(scales)
        phase_ranked = rank_with_weights(phase_rows, weights)
        within_ranked = rank_with_weights(within_rows, weights)
        phase_ranked_path = out_dir / f'{label}_phase_ranked.jsonl'
        within_ranked_path = out_dir / f'{label}_within10_ranked.jsonl'
        write_jsonl(phase_ranked_path, phase_ranked)
        write_jsonl(within_ranked_path, within_ranked)

        within_json = out_dir / f'{label}_within_metrics.json'
        within_csv = out_dir / f'{label}_within_metrics.csv'
        within_md = out_dir / f'{label}_within_metrics.md'
        run_within_eval(f'StructRisk[{label}]', within_ranked_path, within_json, within_csv, within_md)

        row = {
            'variant': label,
            'description': description,
            'scales': scales,
            'weights': weights,
            'phase_global': evaluate(phase_ranked, high_threshold=3, ks=[5, 10]),
            'within_project': read_macro(within_json, f'StructRisk[{label}]'),
            'outputs': {
                'phase_ranked': artifact_path(phase_ranked_path),
                'within_ranked': artifact_path(within_ranked_path),
            },
        }

        if args.run_lcr:
            phase_lcr_ranked = out_dir / f'{label}_phase_lcr_ranked.jsonl'
            phase_lcr_metrics = out_dir / f'{label}_phase_lcr_metrics.json'
            phase_lcr_summary = out_dir / f'{label}_phase_lcr_summary.md'
            run_lcr(phase_ranked_path, Path(args.phase_llm_card), phase_lcr_ranked, phase_lcr_metrics, phase_lcr_summary)
            within_lcr_ranked = out_dir / f'{label}_within10_lcr_ranked.jsonl'
            within_lcr_metrics_raw = out_dir / f'{label}_within10_lcr_metrics_raw.json'
            within_lcr_summary = out_dir / f'{label}_within10_lcr_summary.md'
            run_lcr(within_ranked_path, Path(args.within_llm_card), within_lcr_ranked, within_lcr_metrics_raw, within_lcr_summary)
            within_lcr_json = out_dir / f'{label}_within_lcr_metrics.json'
            within_lcr_csv = out_dir / f'{label}_within_lcr_metrics.csv'
            within_lcr_md = out_dir / f'{label}_within_lcr_metrics.md'
            run_within_eval(f'StructRisk+LCR[{label}]', within_lcr_ranked, within_lcr_json, within_lcr_csv, within_lcr_md)
            row['phase_lcr_global'] = read_json(phase_lcr_metrics).get('metrics', read_json(phase_lcr_metrics))
            row['within_lcr_project'] = read_macro(within_lcr_json, f'StructRisk+LCR[{label}]')
            row['outputs'].update({
                'phase_lcr_ranked': artifact_path(phase_lcr_ranked),
                'within_lcr_ranked': artifact_path(within_lcr_ranked),
            })
        rows.append(row)

    envelopes = {
        'phase_global': {
            'HR@5': summarize_values(rows, 'phase_global', 'HighRisk@5'),
            'HR@10': summarize_values(rows, 'phase_global', 'HighRisk@10'),
            'NDCG@5': summarize_values(rows, 'phase_global', 'NDCG@5'),
            'NDCG@10': summarize_values(rows, 'phase_global', 'NDCG@10'),
        },
        'within_project': {
            'NDCG@5': summarize_values(rows, 'within_project', 'NDCG@5'),
            'MAP': summarize_values(rows, 'within_project', 'MAP'),
            'MRR': summarize_values(rows, 'within_project', 'MRR'),
        },
    }
    if args.run_lcr:
        envelopes['phase_lcr_global'] = {
            'HR@5': summarize_values(rows, 'phase_lcr_global', 'HighRisk@5'),
            'HR@10': summarize_values(rows, 'phase_lcr_global', 'HighRisk@10'),
            'NDCG@5': summarize_values(rows, 'phase_lcr_global', 'NDCG@5'),
            'NDCG@10': summarize_values(rows, 'phase_lcr_global', 'NDCG@10'),
        }
        envelopes['within_lcr_project'] = {
            'NDCG@5': summarize_values(rows, 'within_lcr_project', 'NDCG@5'),
            'MAP': summarize_values(rows, 'within_lcr_project', 'MAP'),
            'MRR': summarize_values(rows, 'within_lcr_project', 'MRR'),
        }

    payload = {
        'status': 'sensitivity-only; primary scorer unchanged',
        'base_weights': DEFAULT_WEIGHTS,
        'scales': SCALES,
        'features': FEATURES,
        'variant_count': len(rows),
        'envelopes': envelopes,
        'variants': rows,
    }
    summary_json = GENERATED / f'{args.prefix}.json'
    summary_md = GENERATED / f'{args.prefix}.md'
    summary_json.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    write_summary(summary_md, payload)
    print(artifact_path(summary_json))
    print(artifact_path(summary_md))
    print(json.dumps({
        'variant_count': len(rows),
        'envelopes': envelopes,
    }, indent=2))


if __name__ == '__main__':
    main()
