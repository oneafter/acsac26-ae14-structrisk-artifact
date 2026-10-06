#!/usr/bin/env python3
import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from magma_common import (
    BUGS_HTML_DEFAULT,
    GENERATED,
    NVD_CACHE_DEFAULT,
    enrich_cvss,
    parse_bug_inventory,
)


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


def severity_counts(rows):
    by_cve = {}
    for row in rows:
        cve_id = row.get('cve_id') or ''
        if cve_id:
            by_cve.setdefault(cve_id, row)
    counts = Counter((row.get('cvss_severity') or 'UNKNOWN').upper() for row in by_cve.values())
    return by_cve, counts


def project_rows(rows):
    projects = defaultdict(lambda: {'bug_records': 0, 'cves': set(), 'high_or_critical': set()})
    for row in rows:
        project = row.get('project') or row.get('project_display') or 'unknown'
        cve_id = row.get('cve_id') or ''
        projects[project]['bug_records'] += 1
        if cve_id:
            projects[project]['cves'].add(cve_id)
            if (row.get('cvss_severity') or '').upper() in {'HIGH', 'CRITICAL'}:
                projects[project]['high_or_critical'].add(cve_id)
    return [
        {
            'project': project,
            'bug_records': values['bug_records'],
            'distinct_cves': len(values['cves']),
            'high_or_critical_cves': len(values['high_or_critical']),
        }
        for project, values in sorted(projects.items())
    ]


def parse_local_summary(path):
    if not path.exists():
        return None
    text = path.read_text(encoding='utf-8')

    def extract(label):
        match = re.search(rf'- {re.escape(label)}: `?(\d+)`?', text)
        return int(match.group(1)) if match else None

    return {
        'raw_artifacts': extract('Raw artifacts'),
        'findings': extract('Deduplicated findings'),
        'projects': extract('Projects'),
        'high_findings': extract('HIGH-or-CRITICAL positives') or extract('HIGH findings'),
    }


def parse_rank_metrics(path):
    if not path.exists():
        return None
    metrics = json.loads(path.read_text(encoding='utf-8'))
    rows = []
    for method, values in metrics.get('global', {}).items():
        within = metrics.get('within_project', {}).get(method, {})
        rows.append({
            'method': method,
            'hr10': values.get('HighRisk@10'),
            'ndcg10': values.get('NDCG@10'),
            'wp_ndcg5': within.get('NDCG@5'),
            'wp_map': within.get('MAP'),
        })
    return rows


def parse_unified_summary(path):
    if not path.exists():
        return None
    text = path.read_text(encoding='utf-8')

    def extract(label):
        match = re.search(rf'- {re.escape(label)}: `?(\d+)`?', text)
        return int(match.group(1)) if match else None

    return {
        'input_artifacts': extract('Input crash-backed artifacts'),
        'deduplicated_artifacts': extract('Deduplicated artifacts'),
        'duplicates_removed': extract('Duplicate artifacts removed'),
        'findings': extract('Deduplicated findings'),
        'projects': extract('Projects'),
        'high_findings': extract('HIGH-or-CRITICAL positives') or extract('HIGH findings'),
        'distinct_bug_ids': extract('Distinct MAGMA bug IDs'),
        'distinct_cves': extract('Distinct CVEs'),
    }


def coverage_from_findings(path: Path, inventory_by_cve, inventory_by_project):
    findings = load_jsonl(path)
    by_project = defaultdict(lambda: {
        'findings': 0,
        'high_or_critical_positives': 0,
        'bug_ids': set(),
        'cves': set(),
        'high_or_critical_cves': set(),
    })
    covered_cves = set()
    covered_high_cves = set()
    covered_bug_ids = set()
    for row in findings:
        project = row.get('project') or 'unknown'
        meta = row.get('metadata', {})
        bug_ids = {bug for bug in meta.get('aligned_bug_ids', []) if bug}
        cves = {cve for cve in meta.get('aligned_cve_ids', []) if cve}
        by_project[project]['findings'] += 1
        if int(row.get('risk_level') or 0) >= 3:
            by_project[project]['high_or_critical_positives'] += 1
        by_project[project]['bug_ids'].update(bug_ids)
        by_project[project]['cves'].update(cves)
        covered_bug_ids.update(bug_ids)
        covered_cves.update(cves)
        for cve_id in cves:
            severity = (inventory_by_cve.get(cve_id, {}).get('cvss_severity') or '').upper()
            if severity in {'HIGH', 'CRITICAL'}:
                by_project[project]['high_or_critical_cves'].add(cve_id)
                covered_high_cves.add(cve_id)

    project_rows = []
    all_projects = sorted(set(inventory_by_project) | set(by_project))
    for project in all_projects:
        inventory = inventory_by_project.get(project, {})
        slice_row = by_project.get(project, {})
        inventory_cves = int(inventory.get('distinct_cves') or 0)
        inventory_high = int(inventory.get('high_or_critical_cves') or 0)
        slice_cves = len(slice_row.get('cves', set()))
        slice_high = len(slice_row.get('high_or_critical_cves', set()))
        project_rows.append({
            'project': project,
            'inventory_bug_records': int(inventory.get('bug_records') or 0),
            'inventory_distinct_cves': inventory_cves,
            'inventory_high_or_critical_cves': inventory_high,
            'unified_findings': int(slice_row.get('findings') or 0),
            'unified_high_or_critical_positives': int(slice_row.get('high_or_critical_positives') or 0),
            'unified_distinct_bug_ids': len(slice_row.get('bug_ids', set())),
            'unified_distinct_cves': slice_cves,
            'unified_high_or_critical_cves': slice_high,
            'cve_coverage_pct': round((100.0 * slice_cves / inventory_cves), 1) if inventory_cves else 0.0,
            'high_or_critical_cve_coverage_pct': round((100.0 * slice_high / inventory_high), 1) if inventory_high else 0.0,
        })

    return {
        'findings': len(findings),
        'covered_bug_ids': len(covered_bug_ids),
        'covered_cves': len(covered_cves),
        'covered_high_or_critical_cves': len(covered_high_cves),
        'project_rows': project_rows,
    }


def write_csv(path, rows, fieldnames):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description='Audit MAGMA full-inventory severity coverage and experiment slices')
    parser.add_argument('--bugs-html', default=str(BUGS_HTML_DEFAULT))
    parser.add_argument('--nvd-cache', default=str(NVD_CACHE_DEFAULT))
    parser.add_argument('--generated-dir', default=str(GENERATED))
    parser.add_argument('--fetch-nvd', action='store_true')
    parser.add_argument('--retry-nvd-errors', action='store_true')
    parser.add_argument('--nvd-sleep', type=float, default=6.6)
    args = parser.parse_args()

    generated_dir = Path(args.generated_dir)
    rows = parse_bug_inventory(Path(args.bugs_html))
    rows = enrich_cvss(
        rows,
        Path(args.nvd_cache),
        fetch=args.fetch_nvd,
        sleep_secs=args.nvd_sleep,
        retry_errors=args.retry_nvd_errors,
    )
    by_cve, counts = severity_counts(rows)
    high_or_critical = counts['HIGH'] + counts['CRITICAL']
    projects = project_rows(rows)
    inventory_projects = {row['project']: row for row in projects}
    local_summary = parse_local_summary(generated_dir / 'magma_local_crash_backed_summary.md')
    local_rank = parse_rank_metrics(generated_dir / 'magma_local_crash_backed_external_metrics.json')
    unified_summary = parse_unified_summary(generated_dir / 'magma_unified_crash_backed_summary.md')
    unified_rank = parse_rank_metrics(generated_dir / 'magma_unified_crash_backed_external_metrics.json')
    unified_coverage = coverage_from_findings(generated_dir / 'magma_unified_crash_backed_findings.jsonl', by_cve, inventory_projects)
    poc_coverage_path = generated_dir / 'magma_poc_package_coverage.json'
    poc_coverage = json.loads(poc_coverage_path.read_text(encoding='utf-8')) if poc_coverage_path.exists() else None
    poc49_summary = parse_local_summary(generated_dir / 'magma_poc49_crash_backed_summary.md')
    poc49_rank = parse_rank_metrics(generated_dir / 'magma_poc49_crash_backed_external_metrics.json')

    severity_csv = generated_dir / 'magma_full_inventory_nvd_severity.csv'
    write_csv(
        severity_csv,
        [
            {
                'cve_id': cve_id,
                'nvd_preferred_severity': row.get('cvss_severity') or '',
                'cvss_score': row.get('cvss_score') or '',
                'cvss_vector': row.get('cvss_vector') or '',
                'project': row.get('project') or '',
                'bug_id': row.get('bug_id') or '',
                'bug_type': row.get('bug_type') or '',
            }
            for cve_id, row in sorted(by_cve.items())
        ],
        ['cve_id', 'nvd_preferred_severity', 'cvss_score', 'cvss_vector', 'project', 'bug_id', 'bug_type'],
    )

    project_csv = generated_dir / 'magma_inventory_project_summary.csv'
    write_csv(project_csv, projects, ['project', 'bug_records', 'distinct_cves', 'high_or_critical_cves'])

    coverage_csv = generated_dir / 'magma_inventory_project_coverage.csv'
    write_csv(
        coverage_csv,
        unified_coverage['project_rows'],
        [
            'project',
            'inventory_bug_records',
            'inventory_distinct_cves',
            'inventory_high_or_critical_cves',
            'unified_findings',
            'unified_high_or_critical_positives',
            'unified_distinct_bug_ids',
            'unified_distinct_cves',
            'unified_high_or_critical_cves',
            'cve_coverage_pct',
            'high_or_critical_cve_coverage_pct',
        ],
    )

    payload = {
        'full_inventory': {
            'bug_records': len(rows),
            'distinct_cves': len(by_cve),
            'severity_counts': dict(sorted(counts.items())),
            'high_or_critical_cves': high_or_critical,
            'projects': len(projects),
        },
        'projects': projects,
        'unified_crash_backed': unified_summary,
        'unified_coverage': unified_coverage,
        'unified_crash_backed_rank': unified_rank,
        'strict_crash_backed': local_summary,
        'strict_crash_backed_rank': local_rank,
        'poc_package_coverage': None if poc_coverage is None else poc_coverage.get('union'),
        'broader_public_poc_crash_backed': poc49_summary,
        'broader_public_poc_crash_backed_rank': poc49_rank,
    }
    json_path = generated_dir / 'magma_inventory_audit.json'
    json_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    def markdown_rank_rows(rows):
        return [row for row in rows if row.get('method') != 'StackDedup-kNN']

    md_lines = [
        '# MAGMA Coverage Audit',
        '',
        'This audit characterizes the full MAGMA bug inventory alongside the crash-backed validation slice used in the paper.',
        '',
        '## Full Inventory',
        '',
        f'- Bug records: `{len(rows)}`',
        f'- Distinct CVEs: `{len(by_cve)}`',
        f'- HIGH or CRITICAL CVEs under preferred NVD CVSS: `{high_or_critical}`',
        '- Severity counts: ' + ', '.join(f'{key}={counts[key]}' for key in sorted(counts)),
        f'- Projects: `{len(projects)}`',
    ]
    if local_summary:
        pass
    if unified_summary:
        md_lines.extend([
            '',
            '## Unified Crash-Backed Evidence-Card Slice',
            '',
            f"- Input crash-backed artifacts: `{unified_summary['input_artifacts']}`",
            f"- Deduplicated artifacts: `{unified_summary['deduplicated_artifacts']}`",
            f"- Duplicate artifacts removed: `{unified_summary['duplicates_removed']}`",
            f"- Deduplicated findings: `{unified_summary['findings']}`",
            f"- Projects: `{unified_summary['projects']}`",
            f"- HIGH-or-CRITICAL positives: `{unified_summary['high_findings']}`",
            f"- Distinct MAGMA bug IDs: `{unified_summary['distinct_bug_ids']}`",
            f"- Distinct CVEs: `{unified_summary['distinct_cves']}`",
            f"- CVE coverage vs full inventory: `{unified_coverage['covered_cves']}/{len(by_cve)}` ({(100.0 * unified_coverage['covered_cves'] / len(by_cve)):.1f}%)",
            f"- HIGH-or-CRITICAL CVE coverage vs full inventory: `{unified_coverage['covered_high_or_critical_cves']}/{high_or_critical}` ({(100.0 * unified_coverage['covered_high_or_critical_cves'] / high_or_critical):.1f}%)",
        ])
    if unified_rank:
        md_lines.extend([
            '',
            '## Unified Crash-Backed Ranking',
            '',
            '| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |',
            '| --- | ---: | ---: | ---: | ---: |',
        ])
        for row in markdown_rank_rows(unified_rank):
            md_lines.append(
                f"| {row['method']} | {row['hr10']} | {row['ndcg10']:.4f} | {row['wp_ndcg5']:.4f} | {row['wp_map']:.4f} |"
            )
        md_lines.append('')
        md_lines.append('StackDedup-kNN is retained in the metrics JSON as an auxiliary learned-comparator diagnostic, but is omitted from the Markdown ranking tables to match the main-text MAGMA baseline set.')
    if unified_coverage['project_rows']:
        md_lines.extend([
            '',
            '## Unified Project Coverage',
            '',
            '| Project | Inv. CVEs | Inv. H/C | Slice Findings | Slice CVEs | Slice H/C | CVE Cov. | H/C Cov. |',
            '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
        ])
        for row in unified_coverage['project_rows']:
            md_lines.append(
                f"| {row['project']} | {row['inventory_distinct_cves']} | {row['inventory_high_or_critical_cves']} | {row['unified_findings']} | {row['unified_distinct_cves']} | {row['unified_high_or_critical_cves']} | {row['cve_coverage_pct']:.1f}% | {row['high_or_critical_cve_coverage_pct']:.1f}% |"
            )
    if local_summary:
        md_lines.extend([
            '',
            '## Stricter Exact-Replay Crash-Backed Slice',
            '',
            f"- Raw artifacts: `{local_summary['raw_artifacts']}`",
            f"- Deduplicated findings: `{local_summary['findings']}`",
            f"- Projects: `{local_summary['projects']}`",
            f"- HIGH-or-CRITICAL positives: `{local_summary['high_findings']}`",
        ])
    if local_rank:
        md_lines.extend([
            '',
            '## Stricter Exact-Replay Ranking',
            '',
            '| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |',
            '| --- | ---: | ---: | ---: | ---: |',
        ])
        for row in markdown_rank_rows(local_rank):
            md_lines.append(
                f"| {row['method']} | {row['hr10']} | {row['ndcg10']:.4f} | {row['wp_ndcg5']:.4f} | {row['wp_map']:.4f} |"
            )
    if poc_coverage:
        union = poc_coverage['union']
        md_lines.extend([
            '',
            '## Public PoC Package Coverage',
            '',
            f"- Archive files scanned: `{union['archive_files']}`",
            f"- Matched PoC files: `{union['matched_poc_files']}`",
            f"- Covered legacy bug IDs: `{union['legacy_covered']}/{union['legacy_inventory_ids']}`",
            f"- Covered legacy CVEs: `{union['legacy_cves']}`",
            f"- Covered HIGH-or-higher legacy bug IDs: `{union['legacy_high_bug_ids']}`",
        ])
    if poc49_summary:
        md_lines.extend([
            '',
            '## Broader Public-PoC Crash-Backed Reconstruction',
            '',
            f"- Raw crash-backed artifacts: `{poc49_summary['raw_artifacts']}`",
            f"- Deduplicated crash-backed findings: `{poc49_summary['findings']}`",
            f"- Projects: `{poc49_summary['projects']}`",
            f"- HIGH-or-CRITICAL positives: `{poc49_summary['high_findings']}`",
        ])
    if poc49_rank:
        md_lines.extend([
            '',
            '## Broader Public-PoC Crash-Backed Ranking',
            '',
            '| Method | HR@10 | NDCG@10 | WP NDCG@5 | WP MAP |',
            '| --- | ---: | ---: | ---: | ---: |',
        ])
        for row in markdown_rank_rows(poc49_rank):
            md_lines.append(
                f"| {row['method']} | {row['hr10']} | {row['ndcg10']:.4f} | {row['wp_ndcg5']:.4f} | {row['wp_map']:.4f} |"
            )
    md_lines.extend([
        '',
        '## Interpretation',
        '',
        'The full inventory audit is a severity-coverage characterization, not a claim that every MAGMA CVE was locally reproduced. The unified crash-backed slice deduplicates exact local replays and public-PoC replays into one evidence-card dataset. The stricter exact-replay and broader public-PoC component slices are retained as coverage diagnostics.',
    ])
    md_path = generated_dir / 'magma_inventory_audit.md'
    md_path.write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    print(json_path)
    print(md_path)
    print(json.dumps(payload['full_inventory'], indent=2))


if __name__ == '__main__':
    main()
