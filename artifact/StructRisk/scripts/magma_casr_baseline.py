#!/usr/bin/env python3
import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from magma_common import evaluate_global, evaluate_within
from phase1_casr_baseline import (
    CASR_DIR_DEFAULT,
    CLASS_SCORES,
    UNAVAILABLE_SCORE,
    load_jsonl,
    parse_report,
    pick_artifact,
    select_tool,
    tie_break_bonus,
    write_jsonl,
)


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

FINDINGS_DEFAULT = GENERATED / 'magma_unified_crash_backed_findings.jsonl'
ARTIFACTS_DEFAULT = GENERATED / 'magma_unified_crash_backed_enriched_artifacts.jsonl'
RANKED_DEFAULT = GENERATED / 'magma_unified_crash_backed_external_casr_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'magma_unified_crash_backed_external_casr_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'magma_unified_crash_backed_external_casr_summary.md'
REPORT_DIR_DEFAULT = GENERATED / 'magma_unified_crash_backed_casr_reports'


def load_artifact_map(path: Path):
    return {(row['project'], row['crash_relpath']): row for row in load_jsonl(path)}


def resolve_host_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def resolve_source_root(row) -> Path:
    project_dir = row.get('project_dir') or row.get('host_run_cwd') or ''
    if project_dir:
        resolved = resolve_host_path(project_dir)
        if resolved.name == row.get('project'):
            return resolved.parent
        return resolved
    crash_path = row.get('crash_path') or ''
    if crash_path:
        resolved = resolve_host_path(crash_path)
        parts = resolved.parts
        if row.get('project') in parts:
            idx = parts.index(row['project'])
            return Path(*parts[:idx]) / row['project'] if idx > 0 else resolved.parent
    raise ValueError(f"cannot resolve source root for {row.get('project')}:{row.get('crash_relpath')}")


def safe_name(finding_id: str) -> str:
    return finding_id.replace('/', '_').replace(':', '_')


def run_magma_casr(row, tool, docker_image, source_root, casr_dir, timeout_sec):
    from phase1_casr_baseline import build_casr_shell

    shell = build_casr_shell(row, tool, timeout_sec)
    cmd = [
        'docker', 'run', '--rm',
        '--entrypoint', 'bash',
        '--cap-add=SYS_PTRACE', '--security-opt', 'seccomp=unconfined',
        '-v', f'{source_root}:/src',
        '-v', f'{casr_dir}:/casr',
        '-w', '/src',
        docker_image,
        '-lc', shell,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def build_unknown(finding, status: str, reason: str, tie_break: float, tie_detail, stdout_path: Path | None, stderr_path: Path | None, tool: str = ''):
    merged = dict(finding)
    score = UNAVAILABLE_SCORE + tie_break
    merged['queue_score'] = round(score, 6)
    merged['structrisk_score'] = round(score, 6)
    merged['casr_tool'] = tool
    merged['casr_severity_type'] = 'UNAVAILABLE'
    merged['casr_short_description'] = ''
    merged['casr_description'] = ''
    merged['casr_crash_line'] = ''
    merged['casr_severity_score'] = round(UNAVAILABLE_SCORE, 4)
    merged['casr_replay_status'] = status
    merged['casr_reasons'] = [reason]
    merged['casr_report_path'] = '' if stdout_path is None else str(stdout_path)
    merged['casr_stderr_path'] = '' if stderr_path is None else str(stderr_path)
    merged['contribution'] = {'casr_severity': UNAVAILABLE_SCORE, **tie_detail}
    return merged


def write_summary(path: Path, findings_path: Path, artifacts_path: Path, ranked, metrics, status_counts):
    class_counts = Counter(item.get('casr_severity_type') or 'UNKNOWN' for item in ranked)
    lines = [
        '# MAGMA CASR-Severity Summary',
        '',
        f'- Findings: `{len(ranked)}`',
        f'- Findings input: `{findings_path}`',
        f'- Artifact input: `{artifacts_path}`',
        '',
        '## Global Ranking',
        '',
        '| HR@5 | HR@10 | NDCG@5 | NDCG@10 | First-HR |',
        '| ---: | ---: | ---: | ---: | ---: |',
        f"| {metrics['global'].get('HighRisk@5', 0)} | {metrics['global'].get('HighRisk@10', 0)} | {metrics['global'].get('NDCG@5', 0):.4f} | {metrics['global'].get('NDCG@10', 0):.4f} | {metrics['global'].get('Rank-to-First-HighRisk', 0)} |",
        '',
        '## Within-Project Ranking',
        '',
        '| Projects | HR@1 | HR@3 | NDCG@5 | MRR | MAP |',
        '| ---: | ---: | ---: | ---: | ---: | ---: |',
        f"| {metrics['within_project'].get('projects', 0)} | {metrics['within_project'].get('HR@1', 0):.4f} | {metrics['within_project'].get('HR@3', 0):.4f} | {metrics['within_project'].get('NDCG@5', 0):.4f} | {metrics['within_project'].get('MRR', 0):.4f} | {metrics['within_project'].get('MAP', 0):.4f} |",
        '',
        '## Replay Status',
        '',
    ]
    for key, value in sorted(status_counts.items()):
        lines.append(f'- `{key}`: `{value}`')
    lines.extend(['', '## Severity Classes', ''])
    for key, value in sorted(class_counts.items()):
        lines.append(f'- `{key}`: `{value}`')
    lines.extend(['', '## Top Ranked Findings', ''])
    for item in ranked[:10]:
        lines.append(
            f"- `{item['id']}`: class={item.get('casr_severity_type', 'UNKNOWN')} score={item.get('casr_severity_score')} status={item.get('casr_replay_status')}"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Run CASR-Severity over the unified crash-backed MAGMA evidence-card slice.')
    parser.add_argument('--findings', default=str(FINDINGS_DEFAULT))
    parser.add_argument('--artifacts', default=str(ARTIFACTS_DEFAULT))
    parser.add_argument('--ranked-out', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    parser.add_argument('--report-dir', default=str(REPORT_DIR_DEFAULT))
    parser.add_argument('--casr-dir', default=str(CASR_DIR_DEFAULT))
    parser.add_argument('--docker-image-prefix', default='magma/llvm_asan')
    parser.add_argument('--timeout', type=int, default=25)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()

    findings_path = Path(args.findings)
    artifacts_path = Path(args.artifacts)
    ranked_out = Path(args.ranked_out)
    metrics_out = Path(args.metrics_out)
    summary_out = Path(args.summary_out)
    report_dir = Path(args.report_dir)
    casr_dir = Path(args.casr_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    findings = load_jsonl(findings_path)
    artifact_map = load_artifact_map(artifacts_path)

    ranked = []
    status_counts = Counter()
    for finding in findings:
        tie_break, tie_detail = tie_break_bonus(finding)
        artifact = pick_artifact(finding, artifact_map)
        chosen_tool = ''
        stdout_path = report_dir / f'{safe_name(finding["id"])}.casrep'
        stderr_path = report_dir / f'{safe_name(finding["id"])}.stderr.txt'

        if artifact is None:
            ranked.append(build_unknown(finding, 'missing-artifact', 'missing-sample-artifact', tie_break, tie_detail, None, None))
            status_counts['missing-artifact'] += 1
            continue

        chosen_tool = select_tool(finding, artifact)
        parsed = None
        replay_status = ''
        returncode = None

        if stdout_path.exists() and stdout_path.stat().st_size > 0 and not args.force:
            try:
                parsed = parse_report(stdout_path.read_text(encoding='utf-8'))
                replay_status = 'cached'
            except Exception:
                parsed = None

        if parsed is None:
            try:
                source_root = resolve_source_root(artifact)
                proc = run_magma_casr(
                    artifact,
                    chosen_tool,
                    f'{args.docker_image_prefix}/{finding["project"]}',
                    source_root.resolve(),
                    casr_dir.resolve(),
                    args.timeout,
                )
                stdout_path.write_text(proc.stdout or '', encoding='utf-8')
                stderr_path.write_text(proc.stderr or '', encoding='utf-8')
                returncode = proc.returncode
                if proc.returncode == 0 and (proc.stdout or '').strip():
                    parsed = parse_report(proc.stdout)
                    replay_status = 'ok'
                else:
                    replay_status = f'nonzero-{proc.returncode}'
            except Exception as exc:
                stderr_path.write_text(str(exc), encoding='utf-8')
                replay_status = 'exception'

        if parsed is None:
            merged = build_unknown(
                finding,
                replay_status or 'failed',
                'casr-report-unavailable',
                tie_break,
                tie_detail,
                stdout_path,
                stderr_path,
                tool=chosen_tool,
            )
            merged['casr_returncode'] = returncode
            merged['casr_selected_crash'] = artifact.get('crash_relpath', '')
            merged['casr_selected_target'] = artifact.get('target_name') or artifact.get('magma_target') or ''
            ranked.append(merged)
            status_counts[replay_status or 'failed'] += 1
            continue

        score = float(parsed['base_score']) + tie_break
        merged = dict(finding)
        merged['queue_score'] = round(score, 6)
        merged['structrisk_score'] = round(score, 6)
        merged['casr_tool'] = chosen_tool
        merged['casr_severity_type'] = parsed['severity_type']
        merged['casr_short_description'] = parsed['short_description']
        merged['casr_description'] = parsed['description']
        merged['casr_crash_line'] = parsed['crash_line']
        merged['casr_severity_score'] = round(float(parsed['base_score']), 4)
        merged['casr_replay_status'] = replay_status
        merged['casr_returncode'] = returncode
        merged['casr_report_path'] = str(stdout_path)
        merged['casr_stderr_path'] = str(stderr_path)
        merged['casr_selected_crash'] = artifact.get('crash_relpath', '')
        merged['casr_selected_target'] = artifact.get('target_name') or artifact.get('magma_target') or ''
        merged['contribution'] = {'casr_severity': round(float(parsed['base_score']), 4), **tie_detail}
        ranked.append(merged)
        status_counts[replay_status] += 1

    ranked.sort(key=lambda item: (-float(item.get('queue_score') or 0.0), item.get('project') or '', item.get('id') or ''))
    write_jsonl(ranked_out, ranked)

    metrics = {
        'global': evaluate_global(ranked),
        'within_project': {},
        'within_project_rows': [],
        'status_counts': dict(status_counts),
    }
    metrics['within_project'], metrics['within_project_rows'] = evaluate_within(ranked)
    metrics_out.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    write_summary(summary_out, findings_path, artifacts_path, ranked, metrics, status_counts)

    print(ranked_out)
    print(metrics_out)
    print(summary_out)
    print(json.dumps({
        'findings': len(ranked),
        'status_counts': dict(status_counts),
        'global': metrics['global'],
        'within_project': metrics['within_project'],
    }, indent=2))


if __name__ == '__main__':
    main()
