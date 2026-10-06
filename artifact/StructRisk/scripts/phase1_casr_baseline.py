#!/usr/bin/env python3
import argparse
import json
import math
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
ARTIFACT_INDEX_DEFAULT = GENERATED / 'phase1_artifact_index.jsonl'
RANKED_DEFAULT = GENERATED / 'phase1_offline_casr_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_casr_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'phase1_offline_casr_summary.md'
REPORT_DIR_DEFAULT = GENERATED / 'phase1_casr_reports'
DOCKER_IMAGE_DEFAULT = 'aflplusplus/aflplusplus'
SOURCE_ROOT_DEFAULT = STRUCTRISK / 'StructRisk_src_full' / 'src'
CASR_DIR_DEFAULT = STRUCTRISK / 'external' / 'casr_linux' / 'unpack' / 'casr-x86_64-unknown-linux-gnu'

ASAN_OPTIONS = (
    'abort_on_error=1:'
    'detect_odr_violation=0:'
    'alloc_dealloc_mismatch=0:'
    'new_delete_type_mismatch=0:'
    'symbolize=0:'
    'detect_leaks=0:'
    'allocator_may_return_null=1'
)

CLASS_SCORES = {
    'EXPLOITABLE': 5.0,
    'PROBABLY_EXPLOITABLE': 4.0,
    'UNKNOWN': 2.5,
    'PROBABLY_NOT_EXPLOITABLE': 1.0,
    'NOT_EXPLOITABLE': 0.25,
}
UNAVAILABLE_SCORE = 0.0


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


def load_artifact_map(path: Path):
    out = {}
    for row in load_jsonl(path):
        out[(row['project'], row['crash_relpath'])] = row
    return out


def infer_target_hint(finding):
    meta = finding.get('metadata', {})
    assertion = (meta.get('matched_assertion') or '').strip()
    if assertion and ':' in assertion:
        prefix = assertion.split(':', 1)[0].strip()
        if prefix:
            return prefix
    return (meta.get('target_name') or '').strip()


def pick_artifact(finding, artifact_map):
    project = finding['project']
    crashes = finding.get('metadata', {}).get('sample_crashes', [])
    target_hint = infer_target_hint(finding)
    candidates = []
    for crash_relpath in crashes:
        row = artifact_map.get((project, crash_relpath))
        if not row:
            continue
        tokens = row.get('container_cmdline_tokens') or []
        if not tokens:
            continue
        score = 0.0
        if row.get('report_has_asan'):
            score += 1.0
        if row.get('report_stack_frame_count'):
            score += 0.5
        if target_hint and row.get('target_name') == target_hint:
            score += 3.0
        elif target_hint and target_hint in (row.get('container_cmdline') or ''):
            score += 2.0
        elif finding.get('metadata', {}).get('target_name') and row.get('target_name') == finding['metadata']['target_name']:
            score += 1.0
        candidates.append((score, row))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1].get('crash_relpath', '')))
    return candidates[0][1]


def quote_tokens(tokens):
    return ' '.join(shlex.quote(token) for token in tokens)


def select_tool(finding, artifact_row):
    if artifact_row.get('report_has_asan') or (finding.get('metadata', {}).get('matched_asan_type') or '').strip():
        return 'san'
    return 'gdb'


def build_casr_shell(row, tool: str, timeout_sec: int):
    run_cwd = row['container_run_cwd']
    tokens = list(row.get('container_cmdline_tokens') or [])
    if not tokens:
        raise ValueError('missing container_cmdline_tokens')
    crash_path = row.get('container_crash_path')
    casr_cmd = [f'/casr/casr-{tool}', '--stdout']
    if row.get('uses_stdin'):
        casr_cmd.extend(['--stdin', crash_path])
    casr_cmd.append('--')
    casr_cmd.extend(tokens)
    return (
        f"export ASAN_OPTIONS={shlex.quote(ASAN_OPTIONS)}; "
        f"cd {shlex.quote(run_cwd)}; "
        f"timeout {int(timeout_sec)}s {quote_tokens(casr_cmd)}"
    )


def report_exactness(level: str) -> float:
    level = (level or '').strip().lower()
    if level == 'exact':
        return 0.003
    if level == 'project':
        return 0.002
    if level == 'target':
        return 0.001
    return 0.0


def tie_break_bonus(finding):
    meta = finding.get('metadata', {})
    exactness = report_exactness(meta.get('report_match_level'))
    support_count = int(meta.get('support_count') or 0)
    support = min(0.0009, math.log1p(support_count) * 0.0002)
    return exactness + support, {'report_exactness': round(exactness, 6), 'support_count': support_count, 'support_bonus': round(support, 6)}


def run_casr(row, tool, docker_image, source_root, casr_dir, timeout_sec):
    shell = build_casr_shell(row, tool, timeout_sec)
    cmd = [
        'docker', 'run', '--rm',
        '--cap-add=SYS_PTRACE', '--security-opt', 'seccomp=unconfined',
        '-v', f'{source_root}:/src',
        '-v', f'{casr_dir}:/casr',
        '-w', '/src',
        docker_image,
        'bash', '-lc', shell,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def parse_report(stdout_text):
    report = json.loads(stdout_text)
    severity = report.get('CrashSeverity') or {}
    severity_type = str(severity.get('Type') or 'UNKNOWN').upper()
    base_score = CLASS_SCORES.get(severity_type, CLASS_SCORES['UNKNOWN'])
    return {
        'report': report,
        'severity_type': severity_type,
        'short_description': severity.get('ShortDescription') or '',
        'description': severity.get('Description') or '',
        'crash_line': report.get('CrashLine') or '',
        'base_score': float(base_score),
    }


def write_summary(path: Path, ranked, metrics):
    lines = ['# CASR-Severity Baseline Summary', '', '## Primary Metrics']
    for key in ['HighRisk@5', 'HighRisk@10', 'NDCG@5', 'NDCG@10', 'Rank-to-First-HighRisk', 'Effort-to-First-HighRisk']:
        lines.append(f'- `{key}={metrics.get(key)}`')
    lines.extend(['', '## Top-10 Findings'])
    for idx, item in enumerate(ranked[:10], start=1):
        lines.append(
            f'- `{idx}`. `{item["id"]}` risk={item.get("risk_level")} '
            f'class={item.get("casr_severity_type", "UNKNOWN")} '
            f'score={item.get("casr_severity_score")} '
            f'tool=`casr-{item.get("casr_tool", "")}` '
            f'line=`{item.get("casr_crash_line", "")}`'
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='CASR-Severity baseline for StructRisk phase-1')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--artifact-index', default=str(ARTIFACT_INDEX_DEFAULT))
    parser.add_argument('--output', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    parser.add_argument('--report-dir', default=str(REPORT_DIR_DEFAULT))
    parser.add_argument('--docker-image', default=DOCKER_IMAGE_DEFAULT)
    parser.add_argument('--source-root', default=str(SOURCE_ROOT_DEFAULT))
    parser.add_argument('--casr-dir', default=str(CASR_DIR_DEFAULT))
    parser.add_argument('--timeout-sec', type=int, default=45)
    parser.add_argument('--limit', type=int)
    args = parser.parse_args()

    eval_rows = load_jsonl(Path(args.eval))
    artifact_map = load_artifact_map(Path(args.artifact_index))
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    ranked = []
    failures = []

    for idx, row in enumerate(eval_rows):
        if args.limit is not None and idx >= args.limit:
            break
        merged = dict(row)
        artifact = pick_artifact(row, artifact_map)
        if not artifact:
            merged['casr_tool'] = ''
            merged['casr_severity_type'] = 'UNAVAILABLE'
            merged['casr_short_description'] = ''
            merged['casr_description'] = ''
            merged['casr_crash_line'] = ''
            merged['casr_severity_score'] = UNAVAILABLE_SCORE
            merged['casr_replay_status'] = 'missing-artifact'
            merged['casr_reasons'] = ['missing-sample-artifact']
            tie_break, tie_detail = tie_break_bonus(row)
            merged['queue_score'] = UNAVAILABLE_SCORE
            merged['structrisk_score'] = round(UNAVAILABLE_SCORE + tie_break, 8)
            merged['confidence'] = None
            merged['low_confidence'] = False
            merged['contribution'] = {'casr_severity': UNAVAILABLE_SCORE, **tie_detail}
            ranked.append(merged)
            failures.append({'id': row['id'], 'error': 'missing-artifact'})
            continue

        tool = select_tool(row, artifact)
        proc = run_casr(
            artifact,
            tool=tool,
            docker_image=args.docker_image,
            source_root=Path(args.source_root),
            casr_dir=Path(args.casr_dir),
            timeout_sec=args.timeout_sec,
        )
        safe_name = row['id'].replace('/', '__').replace(':', '_')
        stdout_path = report_dir / f'{safe_name}.casrep'
        stderr_path = report_dir / f'{safe_name}.stderr.txt'
        stdout_path.write_text(proc.stdout or '', encoding='utf-8', errors='ignore')
        stderr_path.write_text(proc.stderr or '', encoding='utf-8', errors='ignore')

        try:
            parsed = parse_report(proc.stdout)
            status = 'ok' if proc.returncode == 0 else 'nonzero-report'
        except Exception as exc:
            parsed = {
                'report': None,
                'severity_type': 'UNAVAILABLE',
                'short_description': '',
                'description': '',
                'crash_line': '',
                'base_score': UNAVAILABLE_SCORE,
            }
            status = 'timeout' if proc.returncode == 124 else 'error'
            failures.append({'id': row['id'], 'error': status, 'returncode': proc.returncode, 'detail': str(exc)})

        tie_break, tie_detail = tie_break_bonus(row)
        merged['casr_tool'] = tool
        merged['casr_severity_type'] = parsed['severity_type']
        merged['casr_short_description'] = parsed['short_description']
        merged['casr_description'] = parsed['description']
        merged['casr_crash_line'] = parsed['crash_line']
        merged['casr_severity_score'] = round(float(parsed['base_score']), 4)
        merged['casr_replay_status'] = status
        merged['casr_returncode'] = proc.returncode
        merged['casr_report_path'] = str(stdout_path)
        merged['casr_stderr_path'] = str(stderr_path)
        merged['queue_score'] = round(float(parsed['base_score']), 4)
        merged['structrisk_score'] = round(float(parsed['base_score']) + tie_break, 8)
        merged['confidence'] = None
        merged['low_confidence'] = False
        merged['contribution'] = {'casr_severity': round(float(parsed['base_score']), 4), **tie_detail}
        ranked.append(merged)

    ranked.sort(key=lambda item: (-float(item.get('queue_score') or 0.0), -float(item.get('structrisk_score') or 0.0), item.get('project', ''), item.get('id', '')))
    metrics = evaluate(ranked)
    payload = {'metrics': metrics, 'failures': failures, 'failure_count': len(failures)}
    write_jsonl(Path(args.output), ranked)
    Path(args.metrics_out).write_text(json.dumps(payload, indent=2), encoding='utf-8')
    write_summary(Path(args.summary_out), ranked, metrics)
    print(Path(args.output))
    print(Path(args.metrics_out))
    print(Path(args.summary_out))
    print(json.dumps(payload, indent=2))


if __name__ == '__main__':
    main()
