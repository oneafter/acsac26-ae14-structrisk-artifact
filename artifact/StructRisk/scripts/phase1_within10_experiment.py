#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
SCRIPTS = STRUCTRISK / 'scripts'

BALANCED_DEFAULT = GENERATED / 'phase1_offline_balanced_findings.jsonl'
CVSS_DEFAULT = STRUCTRISK / 'structrisk_nvd_cvss31.csv'
ARTIFACT_INDEX_DEFAULT = GENERATED / 'phase1_artifact_index.jsonl'
PREFIX_DEFAULT = 'phase1_within10'

OLD_CASR_DEFAULT = GENERATED / 'phase1_offline_casr_ranked.jsonl'
OLD_LLM_CARD_MANIFEST_DEFAULT = GENERATED / 'phase1_llm_card_manifest.jsonl'
OLD_LLM_CARD_RESPONSES_DEFAULT = GENERATED / 'phase1_llm_card_responses_clean.jsonl'


def load_jsonl(path: Path):
    rows = []
    if not path.exists():
        return rows
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


def append_jsonl(path: Path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def relevance(row):
    return 1 if int(row.get('risk_level') or 0) >= 3 else 0


def target_projects(rows):
    by_project = defaultdict(list)
    for row in rows:
        by_project[row['project']].append(row)
    selected = []
    for project, items in sorted(by_project.items()):
        if len(items) <= 1:
            continue
        if sum(relevance(item) for item in items) <= 0:
            continue
        selected.append(project)
    return selected


def sort_ranked_rows(rows):
    return sorted(
        rows,
        key=lambda row: (
            -(float(row.get('queue_score') or 0.0)),
            -(float(row.get('structrisk_score') or row.get('queue_score') or 0.0)),
            row.get('project') or '',
            row.get('id') or '',
        ),
    )


def run(cmd):
    print('+', ' '.join(str(part) for part in cmd), flush=True)
    subprocess.run([str(part) for part in cmd], check=True)


def run_python(script_name, *args):
    run([sys.executable, SCRIPTS / script_name, *args])


def run_codex_json(prompt, model, reasoning_effort):
    with tempfile.NamedTemporaryFile(prefix='codex_last_', suffix='.txt', delete=False) as handle:
        last_message = Path(handle.name)
    try:
        subprocess.run(
            [
                'codex', 'exec', '--skip-git-repo-check', '-m', model,
                '-c', f'model_reasoning_effort="{reasoning_effort}"',
                '-o', str(last_message), '-'
            ],
            input=prompt,
            text=True,
            check=True,
        )
        text = last_message.read_text(encoding='utf-8').strip()
    finally:
        last_message.unlink(missing_ok=True)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def materialize_subset(all_rows, selected_projects, output_path):
    subset = [row for row in all_rows if row['project'] in set(selected_projects)]
    write_jsonl(output_path, subset)
    return subset


def summary_payload(rows, selected_projects):
    by_project = defaultdict(list)
    for row in rows:
        by_project[row['project']].append(row)
    return {
        'projects': selected_projects,
        'project_rows': [
            {
                'project': project,
                'findings': len(by_project[project]),
                'positives': sum(relevance(item) for item in by_project[project]),
            }
            for project in selected_projects
        ],
        'total_findings': len(rows),
        'total_positives': sum(relevance(row) for row in rows),
    }


def lopo_rows(all_rows, project):
    train_rows = [row for row in all_rows if row['project'] != project]
    eval_rows = [row for row in all_rows if row['project'] == project]
    return train_rows, eval_rows


def combine_lopo_baseline(script_name, all_rows, selected_projects, prefix, suffix, extra_args=()):
    tmp_root = GENERATED / f'{prefix}_tmp' / suffix
    tmp_root.mkdir(parents=True, exist_ok=True)
    combined = []
    for project in selected_projects:
        project_dir = tmp_root / project
        project_dir.mkdir(parents=True, exist_ok=True)
        dev_path = project_dir / 'dev.jsonl'
        eval_path = project_dir / 'eval.jsonl'
        ranked_path = project_dir / 'ranked.jsonl'
        metrics_path = project_dir / 'metrics.json'
        summary_path = project_dir / 'summary.md'
        train_rows, eval_rows = lopo_rows(all_rows, project)
        write_jsonl(dev_path, train_rows)
        write_jsonl(eval_path, eval_rows)
        cmd_args = ['--dev', str(dev_path), '--eval', str(eval_path), '--output', str(ranked_path), '--metrics-out', str(metrics_path)]
        if summary_path is not None:
            cmd_args.extend(['--summary-out', str(summary_path)])
        cmd_args.extend(str(arg) for arg in extra_args)
        run_python(script_name, *cmd_args)
        combined.extend(load_jsonl(ranked_path))
    combined = sort_ranked_rows(combined)
    out_path = GENERATED / f'{prefix}_{suffix}_ranked.jsonl'
    write_jsonl(out_path, combined)
    return out_path


def run_manual(subset_path, prefix):
    out_path = GENERATED / f'{prefix}_manual_ranked.jsonl'
    run_python(
        'structrisk_rank.py',
        '--mode', 'manual',
        '--input', str(subset_path),
        '--output', str(out_path),
        '--weights-out', str(GENERATED / f'{prefix}_manual_weights.json'),
        '--metrics-out', str(GENERATED / f'{prefix}_manual_metrics.json'),
    )
    return out_path


def run_public_artifact_crash(subset_path, prefix, cvss_path):
    run_python(
        'phase1_public_baseline.py',
        '--eval', str(subset_path),
        '--cvss', str(cvss_path),
        '--output', str(GENERATED / f'{prefix}_public_severity_ranked.jsonl'),
        '--metrics-out', str(GENERATED / f'{prefix}_public_severity_metrics.json'),
    )
    run_python(
        'phase1_support_count_baseline.py',
        '--eval', str(subset_path),
        '--output', str(GENERATED / f'{prefix}_support_count_ranked.jsonl'),
        '--metrics-out', str(GENERATED / f'{prefix}_support_count_metrics.json'),
        '--summary-out', str(GENERATED / f'{prefix}_support_count_summary.md'),
    )
    run_python(
        'phase1_artifact_baseline.py',
        '--eval', str(subset_path),
        '--output', str(GENERATED / f'{prefix}_artifact_ranked.jsonl'),
        '--metrics-out', str(GENERATED / f'{prefix}_artifact_metrics.json'),
        '--summary-out', str(GENERATED / f'{prefix}_artifact_summary.md'),
    )
    run_python(
        'phase1_crash_baselines.py',
        '--eval', str(subset_path),
        '--out-prefix', str(GENERATED / prefix),
    )


def run_casr(subset_rows, prefix, artifact_index_path, old_casr_path):
    cached_by_id = {row['id']: row for row in load_jsonl(old_casr_path)}
    cached = []
    missing = []
    for row in subset_rows:
        if row['id'] in cached_by_id:
            cached.append(cached_by_id[row['id']])
        else:
            missing.append(row)

    new_rows = []
    if missing:
        missing_eval = GENERATED / f'{prefix}_casr_missing_eval.jsonl'
        missing_ranked = GENERATED / f'{prefix}_casr_missing_ranked.jsonl'
        write_jsonl(missing_eval, missing)
        run_python(
            'phase1_casr_baseline.py',
            '--eval', str(missing_eval),
            '--artifact-index', str(artifact_index_path),
            '--output', str(missing_ranked),
            '--metrics-out', str(GENERATED / f'{prefix}_casr_missing_metrics.json'),
            '--summary-out', str(GENERATED / f'{prefix}_casr_missing_summary.md'),
            '--report-dir', str(GENERATED / f'{prefix}_casr_reports'),
        )
        new_rows = load_jsonl(missing_ranked)

    combined = sort_ranked_rows(cached + new_rows)
    out_path = GENERATED / f'{prefix}_casr_ranked.jsonl'
    write_jsonl(out_path, combined)
    return out_path


def load_llm_card_cache(old_manifest_path, old_responses_path):
    manifest = {row['id']: row['finding_id'] for row in load_jsonl(old_manifest_path)}
    cache = {}
    for row in load_jsonl(old_responses_path):
        response_id = row.get('id')
        finding_id = manifest.get(response_id)
        if not finding_id:
            continue
        cache[finding_id] = row.get('response') if 'response' in row else row
    return cache


def complete_llm_card(subset_path, prefix, model, reasoning_effort, old_manifest_path, old_responses_path):
    prompts_path = GENERATED / f'{prefix}_llm_card_prompts.jsonl'
    manifest_path = GENERATED / f'{prefix}_llm_card_manifest.jsonl'
    responses_path = GENERATED / f'{prefix}_llm_card_responses.jsonl'
    ranked_path = GENERATED / f'{prefix}_llm_card_ranked.jsonl'
    run_python(
        'phase1_llm_card_baseline.py',
        '--eval', str(subset_path),
        '--mode', 'emit-prompts',
        '--prompts-out', str(prompts_path),
        '--manifest-out', str(manifest_path),
        '--responses', str(responses_path),
        '--ranked-out', str(ranked_path),
        '--metrics-out', str(GENERATED / f'{prefix}_llm_card_metrics.json'),
        '--summary-out', str(GENERATED / f'{prefix}_llm_card_summary.md'),
    )

    prompts = {row['id']: row['prompt'] for row in load_jsonl(prompts_path)}
    manifest_rows = load_jsonl(manifest_path)
    existing = {row['id']: row.get('response') if 'response' in row else row for row in load_jsonl(responses_path)}
    cache_by_finding = load_llm_card_cache(old_manifest_path, old_responses_path)

    for row in manifest_rows:
        response_id = row['id']
        if response_id in existing:
            continue
        finding_id = row['finding_id']
        if finding_id in cache_by_finding:
            payload = {'id': response_id, 'response': cache_by_finding[finding_id]}
        else:
            payload = {'id': response_id, 'response': run_codex_json(prompts[response_id], model, reasoning_effort)}
        append_jsonl(responses_path, payload)
        existing[response_id] = payload['response']

    run_python(
        'phase1_llm_card_baseline.py',
        '--eval', str(subset_path),
        '--mode', 'responses',
        '--prompts-out', str(prompts_path),
        '--manifest-out', str(manifest_path),
        '--responses', str(responses_path),
        '--ranked-out', str(ranked_path),
        '--metrics-out', str(GENERATED / f'{prefix}_llm_card_metrics.json'),
        '--summary-out', str(GENERATED / f'{prefix}_llm_card_summary.md'),
    )
    return ranked_path


def complete_lcr(manual_ranked_path, prefix, model, reasoning_effort):
    del model, reasoning_effort
    ranked_path = GENERATED / f'{prefix}_llm_lcr_ranked.jsonl'
    llm_card_ranked_path = GENERATED / f'{prefix}_llm_card_ranked.jsonl'
    run_python(
        'phase1_local_tie_resolution.py',
        '--base', str(manual_ranked_path),
        '--llm-card', str(llm_card_ranked_path),
        '--output', str(ranked_path),
        '--metrics-out', str(GENERATED / f'{prefix}_llm_lcr_metrics.json'),
        '--summary-out', str(GENERATED / f'{prefix}_llm_lcr_summary.md'),
    )
    return ranked_path


def run_within_eval(prefix, refresh_default_outputs=False, bootstrap_rounds=20000):
    methods = [
        ('Public-Severity', GENERATED / f'{prefix}_public_severity_ranked.jsonl'),
        ('Support-Count', GENERATED / f'{prefix}_support_count_ranked.jsonl'),
        ('Artifact-Completeness', GENERATED / f'{prefix}_artifact_ranked.jsonl'),
        ('ASan-Severity', GENERATED / f'{prefix}_asan_ranked.jsonl'),
        ('Crash-State', GENERATED / f'{prefix}_crashstate_ranked.jsonl'),
        ('StackDedup-kNN', GENERATED / f'{prefix}_reportknn_ranked.jsonl'),
        ('CASR-Severity', GENERATED / f'{prefix}_casr_ranked.jsonl'),
        ('LLM-CardScore', GENERATED / f'{prefix}_llm_card_ranked.jsonl'),
        ('StructRisk', GENERATED / f'{prefix}_manual_ranked.jsonl'),
        ('StructRisk+LLM-LCR', GENERATED / f'{prefix}_llm_lcr_ranked.jsonl'),
    ]

    json_out = GENERATED / f'{prefix}_metrics.json'
    csv_out = GENERATED / f'{prefix}_metrics.csv'
    md_out = GENERATED / f'{prefix}_metrics.md'
    args = []
    for name, path in methods:
        args.extend(['--method', f'{name}={path}'])
    args.extend(['--json-out', str(json_out), '--csv-out', str(csv_out), '--md-out', str(md_out)])
    run_python('phase1_within_project_eval.py', *args)

    sig_json = GENERATED / f'{prefix}_significance.json'
    sig_md = GENERATED / f'{prefix}_significance.md'
    sig_args = []
    for name, path in methods:
        if name in {'Public-Severity', 'Support-Count', 'ASan-Severity', 'Crash-State', 'CASR-Severity', 'LLM-CardScore', 'StructRisk+LLM-LCR'}:
            sig_args.extend(['--method', f'{name}={path}'])
    sig_args.extend(['--bootstrap-rounds', str(bootstrap_rounds), '--json-out', str(sig_json), '--md-out', str(sig_md)])
    run_python('phase1_within_project_significance.py', *sig_args)

    if refresh_default_outputs:
        for src, dst in (
            (json_out, GENERATED / 'phase1_within_project_metrics.json'),
            (csv_out, GENERATED / 'phase1_within_project_metrics.csv'),
            (md_out, GENERATED / 'phase1_within_project_metrics.md'),
            (sig_json, GENERATED / 'phase1_within_project_significance.json'),
            (sig_md, GENERATED / 'phase1_within_project_significance.md'),
        ):
            dst.write_text(src.read_text(encoding='utf-8'), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Expand within-project evaluation to all positive multi-finding projects')
    parser.add_argument('--balanced', default=str(BALANCED_DEFAULT))
    parser.add_argument('--cvss', default=str(CVSS_DEFAULT))
    parser.add_argument('--artifact-index', default=str(ARTIFACT_INDEX_DEFAULT))
    parser.add_argument('--prefix', default=PREFIX_DEFAULT)
    parser.add_argument('--model', default='gpt-5.4')
    parser.add_argument('--reasoning-effort', default='high')
    parser.add_argument('--bootstrap-rounds', type=int, default=20000)
    parser.add_argument('--refresh-default-outputs', action='store_true')
    args = parser.parse_args()

    all_rows = load_jsonl(Path(args.balanced))
    selected_projects = target_projects(all_rows)
    subset_path = GENERATED / f'{args.prefix}_eval.jsonl'
    subset_rows = materialize_subset(all_rows, selected_projects, subset_path)
    (GENERATED / f'{args.prefix}_summary.json').write_text(
        json.dumps(summary_payload(subset_rows, selected_projects), indent=2),
        encoding='utf-8',
    )

    run_public_artifact_crash(subset_path, args.prefix, Path(args.cvss))
    manual_ranked = run_manual(subset_path, args.prefix)
    combine_lopo_baseline('phase1_report_knn_baseline.py', all_rows, selected_projects, args.prefix, 'reportknn')
    run_casr(subset_rows, args.prefix, Path(args.artifact_index), OLD_CASR_DEFAULT)
    complete_llm_card(subset_path, args.prefix, args.model, args.reasoning_effort, OLD_LLM_CARD_MANIFEST_DEFAULT, OLD_LLM_CARD_RESPONSES_DEFAULT)
    complete_lcr(manual_ranked, args.prefix, args.model, args.reasoning_effort)
    run_within_eval(args.prefix, refresh_default_outputs=args.refresh_default_outputs, bootstrap_rounds=args.bootstrap_rounds)

    print(json.dumps({'prefix': args.prefix, 'projects': selected_projects, 'findings': len(subset_rows)}, indent=2))


if __name__ == '__main__':
    main()
