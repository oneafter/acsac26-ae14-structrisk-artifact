#!/usr/bin/env python3
import argparse
import csv
import json
import re
import posixpath
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple


STRUCTRISK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SRC_ROOT = STRUCTRISK_ROOT / 'StructRisk_src_full' / 'src'
TEXT_SUFFIX = {'.txt', '.log', '.md', '.out', '.err', ''}
ID_RE = re.compile(r'(id:\d{6}[^\s]*)')
RAYLIB_RE = re.compile(r'^Test\s+#\d+:\s*(\S+)')
XLNT_RE = re.compile(r'^种子\s*#\d+:\s*(id:\d{6}[^\s]*)')
SOKOL_RE = re.compile(r'^Testing\s+seed:\s*(id:\d{6}[^\s]*)')
RUN_RE = re.compile(r'^Running(?:\s+seed)?:\s*(?:[^\n]*?)(id:\d{6}[^\s]*)')
BINARYEN_RE = re.compile(r'^处理文件:\s*(id:\d{6}[^\s]*)')
PROCESSING_RE = re.compile(r'^Processing:\s*(?:crashes/)?(id:\d{6}[^\s]*)')
GENERIC_FUNCTION_HINTS = {
    '__libc_start_main', '__asan_memcpy', '__new_allocator', 'call', 'main', 'malloc', 'free',
    'read', 'write', 'start', '_start', 'decompile', 'expr', 'exprtype', 'node', 'nodetype',
    'module', 'vector', 'allocator', 'allocator_traits', '__normal_iterator', '_m_realloc_insert',
    'programmain', 'decompileoptions', 'basic_string_view', 'char_traits', 'memoryfile', 'handle',
    'soloud', 'calloc'
}


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def norm_text(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', (text or '').lower())


def clean_path(raw: str) -> str:
    if not raw:
        return ''
    text = raw.replace('\\', '/').strip()
    text = re.sub(r'\s*\(.*?\)', '', text)
    text = text.split(' ')[0]
    text = re.sub(r'^/src/[^/]+/', '', text)
    text = re.sub(r'^home/[^/]+/src/[^/]+/', '', text)
    text = re.sub(r'^/(?:home)/[^/]+/src/[^/]+/', '', text)
    text = re.sub(r'^src/', '', text)
    if ':' in text:
        path_part, suffix = text.rsplit(':', 1)
        if suffix.isdigit():
            text = posixpath.normpath(path_part) + ':' + suffix
        else:
            text = posixpath.normpath(text)
    else:
        text = posixpath.normpath(text)
    return text.lower()


def extract_line(raw: str):
    match = re.search(r':(\d+)(?::\d+)?$', raw)
    return int(match.group(1)) if match else None


def split_path_line(raw: str) -> Tuple[str, int]:
    cleaned = clean_path(raw)
    if not cleaned:
        return '', None
    line = extract_line(cleaned)
    path_only = re.sub(r':\d+(?::\d+)?$', '', cleaned)
    return path_only, line


def extract_report_locations(report_md: str) -> List[str]:
    patterns = re.findall(r'(?:/src/[^\s:]+(?::\d+){1,2}|/(?:home)/[^\s:]+(?::\d+){1,2}|src/[^\s:]+(?::\d+){1,2}|[A-Za-z0-9_./-]+\.(?:c|cc|cpp|h|hpp):\d+(?::\d+)?)', report_md or '')
    results = []
    seen = set()
    for item in patterns:
        cleaned = clean_path(item)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)
    return results


def extract_report_file_hints(report_md: str) -> List[str]:
    patterns = re.findall(r'(?:/src/[^\s:]+|src/[^\s:]+|[A-Za-z0-9_./-]+\.(?:c|cc|cpp|h|hpp))', report_md or '')
    results = []
    seen = set()
    for item in patterns:
        cleaned = clean_path(item)
        cleaned = re.sub(r':\d+(?::\d+)?$', '', cleaned)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)
    return results


def extract_function_hints(report_md: str) -> List[str]:
    text = report_md or ''
    hints = set()
    def add_hint(token: str):
        hint = str(token).split('::')[-1].strip().lower()
        hint = re.sub(r'[^a-z0-9_]+', '', hint)
        if len(hint) < 4 or hint in GENERIC_FUNCTION_HINTS:
            return
        hints.add(hint)

    for token in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_:]*\b', text):
        add_hint(token)
    patterns = [
        r'\bin\s+([A-Za-z_][A-Za-z0-9_:]*)\s*\(',
        r'\bwithin\s+([A-Za-z_][A-Za-z0-9_:]*)\s+function\b',
        r'\b([A-Za-z_][A-Za-z0-9_:]*)\s+function\b',
        r'\bCrash Location:\s*([A-Za-z_][A-Za-z0-9_:]*)\b',
        r'\bFunction:\s*([A-Za-z_][A-Za-z0-9_:]*)\b',
        r'\bRoot Cause Location:\s*[^\n]*\(in\s+([A-Za-z_][A-Za-z0-9_:]*)\)',
    ]
    for pattern in patterns:
        for token in re.findall(pattern, text, flags=re.IGNORECASE):
            add_hint(token)
    return sorted(hints)


def detect_key(line: str):
    for rx in (XLNT_RE, SOKOL_RE, RUN_RE, BINARYEN_RE, PROCESSING_RE):
        m = rx.search(line)
        if m:
            return m.group(1)
    m = RAYLIB_RE.search(line)
    if m:
        return m.group(1)
    m = ID_RE.search(line)
    if m and any(tag in line for tag in ('=== FILE:', 'Running:', 'Running seed:', 'Testing seed:', '处理文件:', 'Processing:')):
        return m.group(1)
    return None


def parse_sections(text: str) -> Dict[str, str]:
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


@lru_cache(None)
def load_project_report_sections(project: str, src_root_str: str) -> Dict[str, str]:
    project_dir = Path(src_root_str) / project
    if not project_dir.exists():
        return {}
    sections: Dict[str, str] = {}
    for path in sorted(project_dir.rglob('*')):
        if not path.is_file():
            continue
        name = path.name.lower()
        if path.suffix.lower() not in TEXT_SUFFIX:
            continue
        if 'result' not in name and 'results' not in name and 'crash' not in name and 'output' not in name:
            continue
        try:
            if path.stat().st_size > 25_000_000:
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for key, block in parse_sections(text).items():
            if block and len(block) > len(sections.get(key, '')):
                sections[key] = block
    return sections


def sample_crash_ids(sample_crashes: List[str]) -> List[str]:
    out = []
    seen = set()
    for item in sample_crashes or []:
        m = ID_RE.search(item)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
    return out


def finding_report_blob(project: str, sample_crashes: List[str], src_root: Path) -> str:
    sections = load_project_report_sections(project, str(src_root))
    blocks = []
    for crash_id in sample_crash_ids(sample_crashes):
        block = sections.get(crash_id, '')
        if block and block not in blocks:
            blocks.append(block)
    return '\n'.join(blocks[:4])


def extract_exec_from_cmd(cmd: str) -> str:
    if not cmd:
        return ''
    token = cmd.strip().split()[0]
    token = token.split('/')[-1]
    return token.lower()


def extract_tokens_from_report(report_md: str) -> Dict[str, List[str]]:
    text = report_md or ''
    harnesses = set()
    executables = set()
    formats = set()

    for token in re.findall(r'\b(?:harness|fuzz)_[A-Za-z0-9_]+(?:\.c)?\b', text):
        harnesses.add(token[:-2].lower() if token.endswith('.c') else token.lower())

    for token in re.findall(r'\./([A-Za-z0-9_./-]+)', text):
        exe = token.split()[0].split('/')[-1].lower()
        if exe:
            executables.add(exe)

    for fmt in re.findall(r'\b-i([a-z0-9]+)\b', text.lower()):
        formats.add(fmt)

    return {
        'harnesses': sorted(harnesses),
        'executables': sorted(executables),
        'formats': sorted(formats),
    }


def disclosure_features(disclosure: Dict[str, object]) -> Dict[str, object]:
    report_md = disclosure.get('report_md', '')
    explicit_locs = []
    if disclosure.get('location'):
        explicit_locs.append(clean_path(str(disclosure['location'])))
    report_locs = extract_report_locations(report_md)
    all_locs = []
    seen = set()
    for item in explicit_locs + report_locs:
        if item and item not in seen:
            seen.add(item)
            all_locs.append(item)

    token_info = extract_tokens_from_report(report_md)
    target_field = str(disclosure.get('target', '') or '')
    target_exec = extract_exec_from_cmd(str(disclosure.get('reproduce_cmd', '') or ''))
    function_field = str(disclosure.get('function', '') or '')
    function_simple = function_field.split('(')[0].split('::')[-1].strip().lower()
    location_field = str(disclosure.get('location', '') or '')
    if not function_simple and '::' in location_field and not re.search(r'\.(?:c|cc|cpp|h|hpp):\d', location_field.lower()):
        function_simple = location_field.split('(')[0].split('::')[-1].strip().lower()
    function_hints = set(extract_function_hints(report_md))
    if function_simple:
        function_hints.add(function_simple)
    report_file_hints = set(extract_report_file_hints(report_md))
    for loc in all_locs:
        path_only, _ = split_path_line(loc)
        if path_only:
            report_file_hints.add(path_only)

    asan_summary_type = ''
    match = re.search(r'AddressSanitizer:\s*([A-Za-z0-9_-]+)', report_md, flags=re.IGNORECASE)
    if match:
        asan_summary_type = match.group(1).lower()

    formats = set(token_info['formats'])
    if 'mmcif' in report_md.lower():
        formats.add('cif')
    if 'mol2' in report_md.lower():
        formats.add('mol2')
    if 'cdxml' in report_md.lower():
        formats.add('cdxml')

    return {
        'project': disclosure['project'],
        'cve_id': disclosure['cve_id'],
        'explicit_locs': explicit_locs,
        'all_locs': all_locs,
        'target_field': target_field.lower(),
        'target_exec': target_exec,
        'function_simple': function_simple,
        'function_hints': function_hints,
        'report_file_hints': report_file_hints,
        'asan_summary_type': asan_summary_type,
        'harnesses': set(token_info['harnesses']),
        'executables': set(token_info['executables']) | ({target_exec} if target_exec else set()),
        'formats': formats,
        'vuln_type': str(disclosure.get('vuln_type', '')),
        'report_md': report_md,
    }


def finding_features(finding: Dict[str, object], src_root: Path) -> Dict[str, object]:
    metadata = finding.get('metadata', {})
    loc = str(metadata.get('matched_project_loc', '') or '')
    path_only, line = split_path_line(loc)
    summary = str(metadata.get('matched_summary_line', '') or '')
    assertion = str(metadata.get('matched_assertion', '') or '')
    signature = str(metadata.get('signature', '') or '')
    cmdline_file = str(metadata.get('cmdline_file', '') or '')
    target_name = str(metadata.get('target_name', '') or '').lower()
    sample_crashes = list(metadata.get('sample_crashes') or [])
    report_blob = finding_report_blob(str(finding['project']), sample_crashes, src_root)
    text_blob = ' '.join([summary, assertion, signature, target_name, cmdline_file, report_blob]).lower()
    campaign_formats = set(re.findall(r'out_([a-z0-9]+)', signature.lower() + ' ' + cmdline_file.lower()))
    return {
        'id': finding['id'],
        'project': finding['project'],
        'risk_level': int(finding.get('risk_level', 0) or 0),
        'loc_raw': loc,
        'path_only': path_only,
        'line': line,
        'asan_type': str(metadata.get('matched_asan_type', '') or '').lower(),
        'target_name': target_name,
        'text_blob': text_blob,
        'summary': summary,
        'assertion': assertion,
        'signature': signature,
        'cmdline_file': cmdline_file,
        'report_blob': report_blob,
        'sample_crashes': sample_crashes,
        'campaign_formats': campaign_formats,
    }


def vuln_compat(vuln_type: str, asan_type: str, asan_summary_type: str) -> Tuple[int, str]:
    v = (vuln_type or '').lower()
    a = (asan_type or '').lower()
    s = (asan_summary_type or '').lower()
    if s and a and s == a:
        return 4, 'asan-summary-match'
    if 'heap-based buffer overflow' in v and a == 'heap-buffer-overflow':
        return 3, 'type-match'
    if 'stack-based buffer overflow' in v and a == 'stack-buffer-overflow':
        return 3, 'type-match'
    if 'use after free' in v and 'use-after-free' in a:
        return 3, 'type-match'
    if 'integer overflow' in v and ('requested' in a or 'overflow' in s or 'overflow' in a):
        return 3, 'overflow-match'
    if 'out-of-bounds' in v and any(x in a for x in ['heap-buffer-overflow', 'global-buffer-overflow', 'stack-buffer-overflow']):
        return 2, 'broad-type-match'
    if 'memory corruption' in v and any(x in a for x in ['heap-buffer-overflow', 'global-buffer-overflow', 'stack-buffer-overflow', 'use-after-free']):
        return 2, 'broad-type-match'
    return 0, ''


def score_pair(df: Dict[str, object], ff: Dict[str, object], project_finding_count: int) -> Dict[str, object]:
    score = 0
    reasons = []
    anchors = []

    for dloc in df['all_locs']:
        dpath, dline = split_path_line(dloc)
        if not dpath or not ff['path_only']:
            continue
        path_match = dpath == ff['path_only'] or dpath.endswith('/' + ff['path_only']) or ff['path_only'].endswith('/' + dpath)
        if path_match:
            if dline is not None and ff['line'] is not None and abs(dline - ff['line']) <= 2:
                score += 12
                reasons.append(f'near-line:{dpath}:{dline}->{ff["line"]}')
                anchors.append('location')
                break
            score += 5
            reasons.append(f'same-file:{dpath}')
            anchors.append('file')
            break

    if not anchors:
        for hinted_file in sorted(df['report_file_hints']):
            if ff['path_only'] and (hinted_file == ff['path_only'] or hinted_file.endswith('/' + ff['path_only']) or ff['path_only'].endswith('/' + hinted_file)):
                score += 4
                reasons.append(f'report-file:{hinted_file}')
                anchors.append('file')
                break

    matched_function = ''

    exact_exec_tokens = set(df['executables']) | set(df['harnesses'])
    if ff['target_name'] and ff['target_name'] in exact_exec_tokens:
        score += 3
        reasons.append(f'exec-target:{ff["target_name"]}')
        anchors.append('target')
    else:
        matched_harness = next((h for h in df['harnesses'] if h and h in ff['text_blob']), '')
        if matched_harness:
            score += 6
            reasons.append(f'harness-text:{matched_harness}')
            anchors.append('harness')
        elif df['target_exec'] and df['target_exec'] in ff['text_blob']:
            score += 3
            reasons.append(f'target-text:{df["target_exec"]}')
            anchors.append('target-text')

    if df['formats']:
        common = sorted(df['formats'] & ff['campaign_formats'])
        if common:
            score += 7
            reasons.append(f'format:{"/".join(common)}')
            anchors.append('format')
            if df['report_file_hints'] or matched_function or df['all_locs']:
                score += 2
                reasons.append('format-disclosure-anchor')

    compat_score, compat_reason = vuln_compat(df['vuln_type'], ff['asan_type'], df['asan_summary_type'])
    if compat_score:
        score += compat_score
        reasons.append(compat_reason)

    if 'calloc parameters overflow' in df['report_md'].lower() and 'requested allocation size' in ff['summary'].lower():
        score += 4
        reasons.append('allocation-overflow-pair')
        anchors.append('overflow')

    if ff['risk_level'] >= 3 and score > 0:
        score += 1
        reasons.append('risk3')

    if project_finding_count == 1 and any(anchor in anchors for anchor in ['target', 'harness', 'target-text', 'format', 'function']):
        score += 4
        reasons.append('singleton-project')
        anchors.append('singleton')
        if df['report_file_hints'] or matched_function or df['all_locs']:
            score += 4
            reasons.append('singleton-disclosure-anchor')

    if 'location' not in anchors and score < 11:
        for function_name in sorted(df['function_hints'], key=lambda item: (-len(item), item)):
            func_key = norm_text(function_name)
            if func_key and func_key in norm_text(ff['text_blob']):
                score += 5
                reasons.append(f'function:{function_name}')
                anchors.append('function')
                matched_function = function_name
                if ff['path_only']:
                    score += 3
                    reasons.append('function-with-loc')
                break

    if not reasons:
        confidence = 'unresolved'
        anchor = 'none'
    elif score >= 11 and any(anchor in anchors for anchor in ['location', 'format', 'harness', 'target', 'function', 'overflow']):
        confidence = 'strong'
        anchor = anchors[0]
    elif score >= 7:
        confidence = 'moderate'
        anchor = anchors[0] if anchors else 'soft'
    else:
        confidence = 'weak'
        anchor = anchors[0] if anchors else 'soft'

    return {
        'score': score,
        'reasons': reasons,
        'confidence': confidence,
        'anchor': anchor,
    }


def project_assignment(disclosures: List[Dict[str, object]], findings: List[Dict[str, object]]):
    scores = [[score_pair(d, f, len(findings)) for f in findings] for d in disclosures]

    @lru_cache(None)
    def dp(i: int, used_mask: int):
        if i == len(disclosures):
            return 0, []
        best_score, best_pairs = dp(i + 1, used_mask)
        best_pairs = [('unmatched', -1)] + best_pairs
        for j in range(len(findings)):
            if used_mask & (1 << j):
                continue
            pair = scores[i][j]
            if pair['score'] < 4:
                continue
            cand_score, cand_pairs = dp(i + 1, used_mask | (1 << j))
            cand_score += pair['score']
            if cand_score > best_score:
                best_score = cand_score
                best_pairs = [(findings[j]['id'], j)] + cand_pairs
        return best_score, best_pairs

    _, plan = dp(0, 0)
    return scores, plan


def write_outputs(rows: List[Dict[str, object]], jsonl_path: Path, csv_path: Path, md_path: Path):
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')

    fields = [
        'project', 'cve_id', 'phase1_project_present', 'matched_finding_id', 'confidence',
        'score', 'anchor', 'reason_summary', 'matched_loc', 'matched_asan_type',
        'matched_target', 'matched_risk_level', 'candidate_count', 'top_candidates'
    ]
    with csv_path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, '') for field in fields})

    strong = sum(1 for r in rows if r['confidence'] == 'strong')
    moderate = sum(1 for r in rows if r['confidence'] == 'moderate')
    weak = sum(1 for r in rows if r['confidence'] == 'weak')
    unmatched = sum(1 for r in rows if r['confidence'] in {'unresolved', 'project-absent'})
    present = sum(1 for r in rows if r['phase1_project_present'])
    lines = [
        '# High-Risk Disclosure Alignment Summary',
        '',
        f'- Disclosure-backed HIGH cases: `{len(rows)}`',
        f'- HIGH cases whose project is present in phase-1: `{present}`',
        f'- Strong alignments: `{strong}`',
        f'- Moderate alignments: `{moderate}`',
        f'- Weak alignments: `{weak}`',
        f'- Unresolved / out-of-scope cases: `{unmatched}`',
        '',
        '| Project | CVE | Phase-1 | Match | Confidence | Score | Anchor | Candidate |',
        '|---|---|---:|---|---|---:|---|---|',
    ]
    for row in rows:
        lines.append(
            f"| {row['project']} | {row['cve_id']} | {int(row['phase1_project_present'])} | {row['matched_finding_id'] or '-'} | {row['confidence']} | {row['score']} | {row['anchor']} | {row['reason_summary']} |"
        )
    md_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Heuristic strong alignment between disclosure-backed HIGH CVEs and phase-1 findings.')
    parser.add_argument('--disclosures', default='StructRisk/generated/high_risk_disclosures.jsonl')
    parser.add_argument('--findings', default='StructRisk/generated/phase1_offline_full_findings.jsonl')
    parser.add_argument('--src-root', default=str(DEFAULT_SRC_ROOT))
    parser.add_argument('--jsonl-out', default='StructRisk/generated/high_risk_disclosure_alignment.jsonl')
    parser.add_argument('--csv-out', default='StructRisk/generated/high_risk_disclosure_alignment.csv')
    parser.add_argument('--summary-out', default='StructRisk/generated/high_risk_disclosure_alignment_summary.md')
    args = parser.parse_args()

    disclosures_raw = load_jsonl(Path(args.disclosures))
    findings_raw = load_jsonl(Path(args.findings))
    src_root = Path(args.src_root)
    disclosures = [disclosure_features(d) | d for d in disclosures_raw]
    findings = [finding_features(f, src_root) | {'raw': f} for f in findings_raw]

    findings_by_project: Dict[str, List[Dict[str, object]]] = {}
    for finding in findings:
        findings_by_project.setdefault(finding['project'], []).append(finding)

    rows = []
    for project in sorted({d['project'] for d in disclosures}):
        project_disclosures = [d for d in disclosures if d['project'] == project]
        project_findings = findings_by_project.get(project, [])
        if not project_findings:
            for disclosure in project_disclosures:
                rows.append({
                    'project': project,
                    'cve_id': disclosure['cve_id'],
                    'phase1_project_present': False,
                    'matched_finding_id': '',
                    'confidence': 'project-absent',
                    'score': 0,
                    'anchor': 'none',
                    'reason_summary': 'project not present in current phase-1 findings',
                    'matched_loc': '',
                    'matched_asan_type': '',
                    'matched_target': '',
                    'matched_risk_level': '',
                    'candidate_count': 0,
                    'top_candidates': '[]',
                })
            continue

        scores, plan = project_assignment(project_disclosures, project_findings)
        for disclosure, (match_id, matched_index), row_scores in zip(project_disclosures, plan, scores):
            ranked = sorted(
                [
                    {
                        'finding_id': project_findings[idx]['id'],
                        'score': result['score'],
                        'confidence': result['confidence'],
                        'anchor': result['anchor'],
                        'reasons': result['reasons'],
                    }
                    for idx, result in enumerate(row_scores)
                    if result['score'] > 0
                ],
                key=lambda item: (-item['score'], item['finding_id'])
            )
            if match_id == 'unmatched':
                rows.append({
                    'project': project,
                    'cve_id': disclosure['cve_id'],
                    'phase1_project_present': True,
                    'matched_finding_id': '',
                    'confidence': 'unresolved',
                    'score': 0,
                    'anchor': 'none',
                    'reason_summary': 'no candidate reached assignment threshold',
                    'matched_loc': '',
                    'matched_asan_type': '',
                    'matched_target': '',
                    'matched_risk_level': '',
                    'candidate_count': len(ranked),
                    'top_candidates': json.dumps(ranked[:3], ensure_ascii=False),
                })
                continue

            pair = row_scores[matched_index]
            chosen = project_findings[matched_index]
            rows.append({
                'project': project,
                'cve_id': disclosure['cve_id'],
                'phase1_project_present': True,
                'matched_finding_id': chosen['id'],
                'confidence': pair['confidence'],
                'score': pair['score'],
                'anchor': pair['anchor'],
                'reason_summary': '; '.join(pair['reasons']),
                'matched_loc': chosen['loc_raw'],
                'matched_asan_type': chosen['asan_type'],
                'matched_target': chosen['target_name'],
                'matched_risk_level': chosen['risk_level'],
                'candidate_count': len(ranked),
                'top_candidates': json.dumps(ranked[:3], ensure_ascii=False),
            })

    rows.sort(key=lambda item: (item['project'], item['cve_id']))
    write_outputs(rows, Path(args.jsonl_out), Path(args.csv_out), Path(args.summary_out))
    print(Path(args.jsonl_out))
    print(Path(args.csv_out))
    print(Path(args.summary_out))
    print(f'alignments={len(rows)}')


if __name__ == '__main__':
    main()
