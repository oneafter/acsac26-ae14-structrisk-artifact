#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
INDEX_DEFAULT = GENERATED / 'phase1_artifact_index.jsonl'
RANKER = STRUCTRISK / 'scripts' / 'structrisk_rank.py'
HIGH_CVE_ALIGNMENT_DEFAULT = GENERATED / 'high_risk_disclosure_alignment.csv'

ID_RE = re.compile(r'(id:\d{6}[^\s]*)')
RAYLIB_RE = re.compile(r'^Test\s+#\d+:\s*(\S+)')
XLNT_RE = re.compile(r'^种子\s*#\d+:\s*(id:\d{6}[^\s]*)')
SOKOL_RE = re.compile(r'^Testing\s+seed:\s*(id:\d{6}[^\s]*)')
RUN_RE = re.compile(r'^Running(?:\s+seed)?:\s*(?:[^\n]*?)(id:\d{6}[^\s]*)')
BINARYEN_RE = re.compile(r'^处理文件:\s*(id:\d{6}[^\s]*)')
PROCESSING_RE = re.compile(r'^Processing:\s*(?:crashes/)?(id:\d{6}[^\s]*)')
FILE_SECTION_RE = re.compile(r'^(?:===\s*FILE:|FILE:|Crash:|POC:)\s*(?:crashes/)?(\S+)')
ASAN_TYPE_RE = re.compile(r'AddressSanitizer:(?:\s*DEADLYSIGNAL|\s*([A-Za-z0-9_-]+))')
SUMMARY_RE = re.compile(r'SUMMARY:\s*AddressSanitizer:\s*([^\n]+)')
SRC_LOC_RE = re.compile(r'((?:/src|/magma/targets)/[^\s:]+:\d+(?::\d+)?)')
EXIT_RE = re.compile(r'(?:Exit code|Process exited with code|退出码)[:：]\s*([-]?\d+)')
STATUS_FAIL_RE = re.compile(r'状态[:：]\s*失败')
ASSERT_RE = re.compile(r'Assertion `[^`]+` failed|VALIDATION_FAILED|assert', re.I)
ENV_ERR_RE = re.compile(r'error while loading shared libraries|cannot open shared object file|not found|No such file or directory', re.I)
FATAL_RE = re.compile(r'Fatal: error|parse exception', re.I)

STRONG_TYPES = {
    'heap-buffer-overflow', 'stack-buffer-overflow', 'global-buffer-overflow',
    'use-after-free', 'heap-use-after-free', 'double-free', 'stack-use-after-return',
    'container-overflow'
}
MEDIUM_TYPES = {'SEGV', 'DEADLYSIGNAL'}
TEXT_SUFFIX = {'.txt', '.log', '.out', '.err', '.md'}


def clamp(value, low=0.0, high=1.0):
    return max(low, min(high, value))


def read_jsonl(path):
    rows = []
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def write_csv(path, rows, fieldnames=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def stable_finding_id(project, signature):
    digest = hashlib.sha1(signature.encode('utf-8')).hexdigest()
    suffix = int(digest[:12], 16) % 100000000
    return f'{project}::finding::{suffix:08d}'


def load_high_cve_alignment(path):
    path = Path(path)
    by_finding = defaultdict(list)
    if not path.exists():
        return by_finding
    with path.open(newline='', encoding='utf-8') as handle:
        for row in csv.DictReader(handle):
            finding_id = (row.get('matched_finding_id') or '').strip()
            cve_id = (row.get('cve_id') or '').strip()
            confidence = (row.get('confidence') or '').strip().lower()
            if not finding_id or not cve_id:
                continue
            if confidence not in {'strong', 'moderate'}:
                continue
            by_finding[finding_id].append(cve_id)
    return by_finding


def apply_labels(findings, high_cve_alignment, label_mode):
    labeled = []
    for item in findings:
        merged = dict(item)
        metadata = dict(merged.get('metadata', {}))
        proxy_level = int(metadata.get('evidence_proxy_level', 0))
        if label_mode == 'proxy':
            risk_level = proxy_level
            label_source = 'evidence_proxy_diagnostic'
            cve_ids = []
        else:
            cve_ids = sorted(high_cve_alignment.get(merged['id'], []))
            risk_level = 3 if cve_ids else 0
            label_source = 'disclosure_backed_high_cve' if cve_ids else 'not_aligned_to_high_cve'
        metadata.update({
            'evidence_proxy_level': proxy_level,
            'label_source': label_source,
            'aligned_high_cve_ids': cve_ids,
        })
        merged['risk_level'] = risk_level
        merged['metadata'] = metadata
        labeled.append(merged)
    return labeled


def discover_report_files(project_dir):
    files = []
    for path in project_dir.rglob('*'):
        if not path.is_file():
            continue
        name = path.name.lower()
        if path.suffix.lower() not in TEXT_SUFFIX:
            continue
        if 'result' not in name and 'results' not in name and 'crash' not in name and 'output' not in name:
            continue
        if path.stat().st_size > 25_000_000:
            continue
        files.append(path)
    return sorted(files)


def detect_key(line):
    m = FILE_SECTION_RE.search(line)
    if m:
        return m.group(1)
    for rx in (XLNT_RE, SOKOL_RE, RUN_RE, BINARYEN_RE, PROCESSING_RE):
        m = rx.search(line)
        if m:
            return m.group(1)
    m = RAYLIB_RE.search(line)
    if m:
        return m.group(1)
    m = ID_RE.search(line)
    if m and any(tag in line for tag in ('=== FILE:', 'Running:', 'Running seed:', 'Testing seed:', '处理文件:')):
        return m.group(1)
    return None


def parse_sections(text):
    sections = {}
    current_key = None
    current_lines = []
    for line in text.splitlines():
        key = detect_key(line)
        if key is not None:
            if current_key and current_lines:
                block = '\n'.join(current_lines).strip()
                if block and len(block) > len(sections.get(current_key, '')):
                    sections[current_key] = block
            current_key = key
            current_lines = [line]
        elif current_key is not None:
            current_lines.append(line)
    if current_key and current_lines:
        block = '\n'.join(current_lines).strip()
        if block and len(block) > len(sections.get(current_key, '')):
            sections[current_key] = block
    return sections


def first_match(pattern, text, default=''):
    m = pattern.search(text)
    return m.group(1) if m else default


def normalize_text(value):
    value = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', value)
    value = re.sub(r'\s+', ' ', value).strip()
    return value


def parse_section_features(text, project):
    project_markers = (f'/src/{project}/', f'/magma/targets/{project}/')
    project_locs = []
    all_locs = []
    for loc in SRC_LOC_RE.findall(text):
        all_locs.append(loc)
        if any(marker in loc for marker in project_markers) and '/crashes/' not in loc:
            project_locs.append(loc)
    summary_line = ''
    for line in text.splitlines():
        if 'SUMMARY:' in line or 'AddressSanitizer:' in line:
            summary_line = line.strip()
            break
    asan_type = first_match(ASAN_TYPE_RE, text, '')
    if not asan_type and 'AddressSanitizer:DEADLYSIGNAL' in text:
        asan_type = 'DEADLYSIGNAL'
    exit_code = first_match(EXIT_RE, text, '')
    assertion = ''
    for line in text.splitlines():
        if ASSERT_RE.search(line):
            assertion = line.strip()
            break
    command = ''
    for line in text.splitlines():
        if line.startswith('Command:') or line.startswith('命令:'):
            command = line.split(':', 1)[1].strip()
            break
    project_loc = project_locs[0] if project_locs else ''
    summary_loc = ''
    for loc in project_locs:
        if loc in summary_line:
            summary_loc = loc
            break
    return {
        'text': text,
        'has_section': bool(text),
        'asan_type': asan_type,
        'summary_line': summary_line,
        'project_loc': project_loc,
        'summary_loc': summary_loc,
        'project_frame_count': len(dict.fromkeys(project_locs)),
        'all_frame_count': len(dict.fromkeys(all_locs)),
        'exit_code': int(exit_code) if exit_code else None,
        'assertion': assertion,
        'env_error': bool(ENV_ERR_RE.search(text)),
        'fatal_error': bool(FATAL_RE.search(text)),
        'command': command,
    }


def project_level_info(report_texts, project):
    combined = '\n\n'.join(report_texts)
    return parse_section_features(combined, project) if combined else parse_section_features('', project)


def enrich_row(row, project_sections, project_info):
    crash_name = row['crash_name']
    section_text = project_sections.get(crash_name, '')
    if not section_text:
        section_text = ''
    section = parse_section_features(section_text, row['project']) if section_text else None
    data = section if section and section['has_section'] else project_info
    if section and section['has_section']:
        match_level = 'exact'
    elif project_info['has_section']:
        match_level = 'project'
    else:
        match_level = 'none'
    return {**row, **{
        'report_match_level': match_level,
        'matched_asan_type': data['asan_type'],
        'matched_summary_line': data['summary_line'],
        'matched_project_loc': data['project_loc'],
        'matched_summary_loc': data['summary_loc'],
        'matched_project_frame_count': data['project_frame_count'],
        'matched_all_frame_count': data['all_frame_count'],
        'matched_exit_code': data['exit_code'],
        'matched_assertion': data['assertion'],
        'matched_env_error': data['env_error'],
        'matched_fatal_error': data['fatal_error'],
        'matched_command': data['command'],
        'matched_has_section': bool(section and section['has_section']),
    }}


def signature_for(row):
    project = row['project']
    asan_type = row.get('matched_asan_type') or ''
    loc = row.get('matched_summary_loc') or row.get('matched_project_loc') or ''
    assertion = normalize_text(row.get('matched_assertion') or '')
    exit_code = row.get('matched_exit_code')
    target = row.get('target_name') or ''
    campaign = row.get('campaign') or ''
    loc_file = loc.split(':', 1)[0] if loc else ''
    asan_norm = asan_type.strip().upper()
    report_summary = (row.get('report_summary_line') or '').strip()
    report_frames = row.get('report_stack_frames') or []
    report_top = report_frames[0] if report_frames else ''
    if (
        project == 'wasm3'
        and asan_norm in {'DEADLYSIGNAL', 'SEGV'}
        and loc_file.endswith('/m3_exec.h')
    ):
        return f'{project}|family|vm-exec|{asan_norm}|m3_exec.h'
    if (
        project == 'wasm3'
        and not asan_norm
        and 'AddressSanitizer:DEADLYSIGNAL' in report_summary
        and '/src/wasm3/source/m3_exec.h:' in report_top
    ):
        return f'{project}|family|vm-exec|DEADLYSIGNAL|m3_exec.h'
    if asan_type and loc:
        return f'{project}|asan|{asan_type}|{loc}'
    if loc:
        return f'{project}|loc|{loc}'
    if asan_type:
        return f'{project}|asan|{asan_type}|{target}'
    if assertion:
        return f'{project}|assert|{assertion[:160]}'
    if exit_code is not None:
        return f'{project}|exit|{exit_code}|{target}|{campaign}'
    return f'{project}|artifact|{target}|{campaign}'


def environment_score(row):
    score = 0.0
    target = (row.get('target_name') or '').lower()
    cmd_tokens = row.get('cmdline_tokens') or []
    cmd = ' '.join(cmd_tokens).lower()
    if 'fuzz' in target or 'harness' in target:
        score += 0.35
    if row.get('uses_stdin'):
        score += 0.15
    if '@@' in cmd or any(token == '@@' for token in cmd_tokens):
        score += 0.25
    if row.get('matched_command'):
        score += 0.15
    if row.get('cmdline_file'):
        score += 0.10
    if int(row.get('project_harness_file_count') or 0) >= 2:
        score += 0.10
    if any(flag in cmd for flag in ('-i', '--run-all-exports', '-o', '/dev/null', '-icif', '-icdxml', '-osmi')):
        score += 0.10
    if not ('fuzz' in target or 'harness' in target) and not row.get('uses_stdin') and '@@' not in cmd:
        score -= 0.10
    return round(clamp(score), 4)


def sanitizer_score(row):
    asan = (row.get('matched_asan_type') or '').strip().lower()
    if asan in {'use-after-free', 'heap-use-after-free', 'stack-use-after-return', 'double-free'}:
        return 1.0
    if asan in {'heap-buffer-overflow', 'stack-buffer-overflow', 'global-buffer-overflow', 'container-overflow'}:
        return 0.9
    if 'buffer-overflow' in asan or 'out-of-bounds' in asan or asan == 'requested':
        return 0.8
    if asan in {'deadlysignal', 'segv'}:
        return 0.4
    if row.get('matched_assertion'):
        return 0.3
    return 0.0


def replay_score(row):
    score = 0.45
    if row.get('cmdline_file'):
        score += 0.20
    if row.get('matched_has_section'):
        score += 0.20
    elif row.get('report_match_level') == 'project':
        score += 0.10
    if row.get('matched_command'):
        score += 0.10
    if row.get('project_crash_report_file_count'):
        score += 0.05
    return round(clamp(score), 4)


def locality_score(row):
    score = 0.15
    if row.get('matched_project_loc'):
        score += 0.45
    if row.get('matched_project_frame_count', 0) >= 3:
        score += 0.15
    if row.get('matched_summary_loc'):
        score += 0.15
    if row.get('matched_asan_type'):
        score += 0.10
    return round(clamp(score), 4)


def site_anchor_score(row):
    score = 0.10
    if row.get('matched_summary_loc'):
        score += 0.50
    elif row.get('matched_project_loc'):
        score += 0.30
    if row.get('matched_assertion'):
        score += 0.10
    if row.get('matched_asan_type'):
        score += 0.10
    return round(clamp(score), 4)


def weak_score(row):
    score = 0.80
    if row.get('matched_has_section'):
        score -= 0.20
    if row.get('matched_asan_type'):
        score -= 0.20
    if row.get('matched_project_loc'):
        score -= 0.15
    if row.get('matched_summary_loc'):
        score -= 0.10
    if row.get('matched_command'):
        score -= 0.05
    if row.get('matched_env_error'):
        score += 0.15
    return round(clamp(score, 0.02, 0.95), 4)



def proxy_risk_level(row):
    if row.get('matched_env_error'):
        return 0
    asan = (row.get('matched_asan_type') or '').upper()
    if asan in {x.upper() for x in STRONG_TYPES} and (row.get('matched_summary_loc') or row.get('matched_project_loc')):
        return 3
    if asan in MEDIUM_TYPES and (row.get('matched_summary_loc') or row.get('matched_project_loc')):
        return 2
    if row.get('matched_assertion') or row.get('matched_fatal_error'):
        return 2 if row.get('matched_project_loc') or row.get('matched_summary_loc') else 1
    if row.get('matched_has_section') or row.get('cmdline_file'):
        return 1
    return 0


def review_cost(signals, support_count):
    cost = 11.0
    cost -= 2.0 * signals['site_anchor']
    cost -= 1.5 * signals['locality']
    cost -= 1.0 * min(support_count, 5) / 5.0
    cost += 2.0 * signals['weak']
    return round(max(5.0, cost), 2)


def aggregate_findings(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[signature_for(row)].append(row)
    findings = []
    for sig, members in groups.items():
        members = sorted(members, key=lambda r: (
            bool(r.get('matched_summary_loc')), bool(r.get('matched_project_loc')),
            bool(r.get('matched_asan_type')), bool(r.get('matched_assertion')), r.get('crash_size', 0)
        ), reverse=True)
        rep = members[0]
        signals = {
            'replay': replay_score(rep),
            'locality': locality_score(rep),
            'site_anchor': site_anchor_score(rep),
            'environment': environment_score(rep),
            'sanitizer': sanitizer_score(rep),
            'weak': weak_score(rep),
        }
        support_count = len(members)
        signals['replay'] = round(clamp(signals['replay'] + min(support_count, 10) * 0.02), 4)
        signals['weak'] = round(clamp(signals['weak'] - min(support_count, 10) * 0.01, 0.02, 0.95), 4)
        evidence_proxy_level = max(proxy_risk_level(member) for member in members)
        findings.append({
            'id': stable_finding_id(rep['project'], sig),
            'project': rep['project'],
            'risk_level': None,
            'review_cost': review_cost(signals, support_count),
            'signals': signals,
            'metadata': {
                'signature': sig,
                'evidence_proxy_level': evidence_proxy_level,
                'support_count': support_count,
                'campaigns': sorted({m['campaign'] for m in members}),
                'sample_crashes': [m['crash_relpath'] for m in members[:5]],
                'target_name': rep.get('target_name'),
                'cmdline_file': rep.get('cmdline_file'),
                'report_match_level': rep.get('report_match_level'),
                'matched_asan_type': rep.get('matched_asan_type'),
                'matched_summary_line': rep.get('matched_summary_line'),
                'matched_project_loc': rep.get('matched_project_loc'),
                'matched_assertion': rep.get('matched_assertion'),
                'matched_exit_code': rep.get('matched_exit_code'),
            }
        })
    findings.sort(key=lambda x: (x['project'], -x['signals']['site_anchor'], -x['signals']['locality'], -x['metadata']['support_count'], x['id']))
    return findings


def balanced_sample(findings, per_project):
    groups = defaultdict(list)
    for item in findings:
        groups[item['project']].append(item)
    out = []
    for project, items in sorted(groups.items()):
        items.sort(key=lambda x: (
            -x['signals']['site_anchor'], -x['signals']['locality'], -x['metadata']['support_count'], x['signals']['weak'], x['id']
        ))
        out.extend(items[:per_project])
    return out


def split_dev_eval(findings):
    dev_projects = {'raylib', 'soloud', 'sokol', 'wren', 'lily'}
    dev = [x for x in findings if x['project'] in dev_projects]
    evals = [x for x in findings if x['project'] not in dev_projects]
    return dev, evals


def summary_rows(findings):
    by_project = defaultdict(list)
    for item in findings:
        by_project[item['project']].append(item)
    rows = []
    for project, items in sorted(by_project.items()):
        dist = Counter(i['risk_level'] for i in items)
        proxy_dist = Counter(i.get('metadata', {}).get('evidence_proxy_level') for i in items)
        rows.append({
            'project': project,
            'finding_count': len(items),
            'risk_3': dist.get(3, 0),
            'risk_2': dist.get(2, 0),
            'risk_1': dist.get(1, 0),
            'risk_0': dist.get(0, 0),
            'proxy_3': proxy_dist.get(3, 0),
            'proxy_2': proxy_dist.get(2, 0),
            'proxy_1': proxy_dist.get(1, 0),
            'proxy_0': proxy_dist.get(0, 0),
            'avg_support_count': round(sum(i['metadata']['support_count'] for i in items) / len(items), 2),
            'avg_site_anchor': round(sum(i['signals']['site_anchor'] for i in items) / len(items), 3),
            'avg_locality': round(sum(i['signals']['locality'] for i in items) / len(items), 3),
            'avg_sanitizer': round(sum(i['signals'].get('sanitizer', 0.0) for i in items) / len(items), 3),
            'avg_weak': round(sum(i['signals']['weak'] for i in items) / len(items), 3),
        })
    return rows


def run_ranker(input_path=None, prefix='phase1_offline'):
    out_dir = GENERATED
    cmd = [sys.executable, str(RANKER), '--mode', 'manual', '--input', str(input_path), '--output', str(out_dir / f'{prefix}_manual_ranked.jsonl'), '--weights-out', str(out_dir / f'{prefix}_manual_weights.json'), '--metrics-out', str(out_dir / f'{prefix}_manual_metrics.json')]
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-index', default=str(INDEX_DEFAULT))
    parser.add_argument('--per-project', type=int, default=25)
    parser.add_argument('--high-cve-alignment', default=str(HIGH_CVE_ALIGNMENT_DEFAULT))
    parser.add_argument('--label-mode', choices=['external-high-cve', 'proxy'], default='external-high-cve')
    args = parser.parse_args()

    GENERATED.mkdir(parents=True, exist_ok=True)
    rows = read_jsonl(args.artifact_index)
    by_project = defaultdict(list)
    for row in rows:
        by_project[row['project']].append(row)

    enriched = []
    for project, items in sorted(by_project.items()):
        project_dir = Path(items[0]['project_dir'])
        report_files = discover_report_files(project_dir)
        project_sections = {}
        report_texts = []
        for report in report_files:
            try:
                text = report.read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            sections = parse_sections(text)
            if not sections:
                report_texts.append(text)
            for key, block in sections.items():
                if len(block) > len(project_sections.get(key, '')):
                    project_sections[key] = block
        proj_info = project_level_info(report_texts, project)
        for row in items:
            enriched.append(enrich_row(row, project_sections, proj_info))

    write_jsonl(GENERATED / 'phase1_offline_enriched_artifacts.jsonl', enriched)
    findings = aggregate_findings(enriched)
    high_cve_alignment = load_high_cve_alignment(args.high_cve_alignment)
    findings = apply_labels(findings, high_cve_alignment, args.label_mode)
    write_jsonl(GENERATED / 'phase1_offline_full_findings.jsonl', findings)
    write_csv(GENERATED / 'phase1_offline_project_summary.csv', summary_rows(findings))
    balanced = balanced_sample(findings, args.per_project)
    write_jsonl(GENERATED / 'phase1_offline_balanced_findings.jsonl', balanced)
    dev, evals = split_dev_eval(balanced)
    write_jsonl(GENERATED / 'phase1_offline_dev.jsonl', dev)
    write_jsonl(GENERATED / 'phase1_offline_eval.jsonl', evals)
    write_csv(GENERATED / 'phase1_offline_eval_project_summary.csv', summary_rows(evals))
    run_ranker(input_path=GENERATED / 'phase1_offline_eval.jsonl', prefix='phase1_offline')
    print('ENRICHED', len(enriched))
    print('FINDINGS_FULL', len(findings))
    print('FINDINGS_BALANCED', len(balanced))
    print('DEV', len(dev))
    print('EVAL', len(evals))
    print('LABEL_MODE', args.label_mode)
    print('HIGH_CVE_LABELS_LOADED', sum(1 for item in findings if item['risk_level'] >= 3))
    print('LABEL_DIST_FULL', Counter(item['risk_level'] for item in findings))
    print('LABEL_DIST_EVAL', Counter(item['risk_level'] for item in evals))


if __name__ == '__main__':
    main()
