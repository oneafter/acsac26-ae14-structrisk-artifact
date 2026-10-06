#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from magma_common import (
    BUGS_HTML_DEFAULT,
    NVD_CACHE_DEFAULT,
    enrich_cvss,
    parse_bug_inventory,
    parse_legacy_preprint_inventory,
)
from phase1_offline_experiment import (
    aggregate_findings,
    discover_report_files,
    enrich_row,
    parse_sections,
    project_level_info,
    signature_for,
    stable_finding_id,
    summary_rows,
    write_csv,
    write_jsonl,
)
from phase1_triage import compute_bootstrap_signals, estimate_review_cost, iter_artifacts, project_snapshot


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
REPRO_ROOT = STRUCTRISK / 'external' / 'magma_repro'
SRC_ROOT_DEFAULT = REPRO_ROOT / 'src'
MANIFEST_DEFAULT = REPRO_ROOT / 'poc_manifest.jsonl'
OUT_DIR_DEFAULT = STRUCTRISK / 'generated'
PREFIX_DEFAULT = 'magma_local'


def read_jsonl(path: Path):
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def inventory_by_bug(fetch: bool):
    merged = {}
    if BUGS_HTML_DEFAULT.exists():
        for row in parse_bug_inventory(BUGS_HTML_DEFAULT):
            current = dict(row)
            current.setdefault('inventory_source', 'magma-v1.2.1-bugs-html')
            current.setdefault('bug_type', '')
            current.setdefault('pov', '')
            merged[row['bug_id']] = current
    for row in parse_legacy_preprint_inventory():
        current = merged.get(row['bug_id'], {}).copy()
        for key, value in row.items():
            if value not in {'', None} or key not in current:
                current[key] = value
        current.setdefault('inventory_source', row.get('inventory_source', 'magma-preprint-legacy-report-ids'))
        merged[row['bug_id']] = current
    rows = list(merged.values())
    rows = enrich_cvss(rows, NVD_CACHE_DEFAULT, fetch=fetch, sleep_secs=0.0, retry_errors=False)
    return {row['bug_id']: row for row in rows}


def project_cvss_meta(inventory_rows):
    meta = {}
    for row in inventory_rows.values():
        score = float(row['cvss_score']) if row.get('cvss_score') not in {'', None} else 0.0
        current = meta.get(row['project'])
        if current is None or score > float(current['score']):
            meta[row['project']] = {
                'score': score,
                'severity': row.get('cvss_severity') or 'UNKNOWN',
            }
    return meta


def manifest_index(rows):
    return {(row['project'], row['crash_relpath']): row for row in rows}


def merge_manifest(row, manifest_row, inventory_row):
    merged = dict(row)
    if manifest_row:
        merged.update({
            'magma_bug_id': manifest_row.get('bug_id', ''),
            'magma_target': manifest_row.get('target', ''),
            'magma_poc_name': manifest_row.get('poc_name', ''),
            'magma_source_member': manifest_row.get('source_member', ''),
        })
    if inventory_row:
        merged.update({
            'magma_cve_id': inventory_row.get('cve_id', ''),
            'magma_bug_type': inventory_row.get('bug_type', ''),
            'magma_pov': inventory_row.get('pov', ''),
            'magma_cvss_score': inventory_row.get('cvss_score', ''),
            'magma_cvss_severity': inventory_row.get('cvss_severity', ''),
            'magma_cvss_vector': inventory_row.get('cvss_vector', ''),
            'magma_risk_level': inventory_row.get('risk_level'),
            'magma_inventory_source': inventory_row.get('inventory_source', ''),
        })
    return merged


def bootstrap_rows(rows):
    out = []
    for row in rows:
        signals = compute_bootstrap_signals(row)
        out.append({
            'id': row['id'],
            'project': row['project'],
            'review_cost': estimate_review_cost(row, signals),
            'signals': signals,
            'metadata': {
                'campaign': row['campaign'],
                'crash_relpath': row['crash_relpath'],
                'cmdline_file': row['cmdline_file'],
                'host_cmdline': row['host_cmdline'],
                'container_cmdline': row['container_cmdline'],
                'report_has_asan': row['report_has_asan'],
                'report_summary_line': row['report_summary_line'],
                'report_stack_frames': row['report_stack_frames'],
                'report_files': row['report_files'],
                'magma_bug_id': row.get('magma_bug_id', ''),
                'magma_cve_id': row.get('magma_cve_id', ''),
                'magma_bug_type': row.get('magma_bug_type', ''),
            },
        })
    return out


def enrich_projects(rows):
    by_project = defaultdict(list)
    for row in rows:
        by_project[row['project']].append(row)
    enriched = []
    section_cache = {}
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
            merged = enrich_row(row, project_sections, proj_info)
            merged['matched_section_text'] = project_sections.get(row['crash_name'], '')
            enriched.append(merged)
            section_cache[(row['project'], row['crash_relpath'])] = merged['matched_section_text']
    return enriched, section_cache


def attach_ground_truth(findings, enriched_rows):
    groups = defaultdict(list)
    for row in enriched_rows:
        groups[signature_for(row)].append(row)

    max_cvss = 0.0
    for row in enriched_rows:
        score = row.get('magma_cvss_score')
        if score not in {'', None}:
            max_cvss = max(max_cvss, float(score))
    max_cvss = max_cvss or 10.0

    cards = []
    for finding in findings:
        sig = finding['metadata']['signature']
        members = groups[sig]
        rep = max(
            members,
            key=lambda row: (
                bool(row.get('matched_summary_loc')),
                bool(row.get('matched_project_loc')),
                bool(row.get('matched_asan_type')),
                len(row.get('matched_section_text') or ''),
            ),
        )
        bug_ids = sorted({row.get('magma_bug_id') for row in members if row.get('magma_bug_id')})
        cve_ids = sorted({row.get('magma_cve_id') for row in members if row.get('magma_cve_id')})
        bug_types = sorted({row.get('magma_bug_type') for row in members if row.get('magma_bug_type')})
        targets = sorted({row.get('magma_target') or row.get('target_name') for row in members if (row.get('magma_target') or row.get('target_name'))})
        cvss_scores = [float(row['magma_cvss_score']) for row in members if row.get('magma_cvss_score') not in {'', None}]
        finding['risk_level'] = max((int(row.get('magma_risk_level') or 0) for row in members), default=0)
        finding['public_severity_score'] = round((max(cvss_scores) / max_cvss), 4) if cvss_scores else 0.0
        finding['metadata'].update({
            'aligned_bug_ids': bug_ids,
            'aligned_cve_ids': cve_ids,
            'aligned_bug_types': bug_types,
            'aligned_targets': targets,
            'sample_pocs': [row['crash_relpath'] for row in members[:5]],
            'inventory_source': rep.get('magma_inventory_source', ''),
        })
        cards.append({
            'id': finding['id'],
            'project': finding['project'],
            'risk_level': finding['risk_level'],
            'public_severity_score': finding['public_severity_score'],
            'review_cost': finding['review_cost'],
            'signals': finding['signals'],
            'bug_ids': bug_ids,
            'cve_ids': cve_ids,
            'bug_types': bug_types,
            'targets': targets,
            'support_count': finding['metadata']['support_count'],
            'sample_crashes': finding['metadata']['sample_crashes'],
            'report_files': rep.get('report_files', []),
            'matched_summary_line': rep.get('matched_summary_line', ''),
            'matched_project_loc': rep.get('matched_project_loc', ''),
            'matched_asan_type': rep.get('matched_asan_type', ''),
            'matched_command': rep.get('matched_command', ''),
            'matched_section_text': rep.get('matched_section_text', ''),
        })
    return findings, cards


def is_crash_backed(row):
    if not row.get('matched_has_section'):
        return False
    if row.get('report_match_level') != 'exact':
        return False
    return bool(
        row.get('matched_asan_type')
        or row.get('matched_project_loc')
        or row.get('matched_assertion')
        or row.get('matched_summary_line')
    )


def write_summary(path: Path, artifacts, findings, cards):
    positive_count = sum(1 for row in findings if row['risk_level'] >= 3)
    title = 'MAGMA Crash-Backed Component Summary' if '_crash_backed_summary' in path.name else 'MAGMA Component Artifact Summary'
    lines = [
        f'# {title}',
        '',
        f'- Raw artifacts: `{len(artifacts)}`',
        f'- Deduplicated findings: `{len(findings)}`',
        f'- Projects: `{len({row["project"] for row in artifacts})}`',
        f'- HIGH-or-CRITICAL positives: `{positive_count}`',
        f'- Projects with reports: `{sum(1 for row in summary_rows(findings) if row["avg_sanitizer"] > 0)}`',
        '',
        '## Project Summary',
        '',
    ]
    for row in summary_rows(findings):
        lines.append(
            f"- `{row['project']}`: findings={row['finding_count']}, positives={row['risk_3']}, avg_support={row['avg_support_count']}, avg_site_anchor={row['avg_site_anchor']}, avg_locality={row['avg_locality']}"
        )
    lines += ['', '## Example Cards', '']
    for card in cards[:5]:
        lines.append(
            f"- `{card['id']}` ({card['project']}): bugs={','.join(card['bug_ids']) or 'n/a'}, cves={','.join(card['cve_ids']) or 'n/a'}, asan={card['matched_asan_type'] or 'n/a'}"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description='Build MAGMA local artifact index, enriched rows, and evidence cards.')
    parser.add_argument('--src-root', default=str(SRC_ROOT_DEFAULT))
    parser.add_argument('--manifest', default=str(MANIFEST_DEFAULT))
    parser.add_argument('--out-dir', default=str(OUT_DIR_DEFAULT))
    parser.add_argument('--prefix', default=PREFIX_DEFAULT)
    parser.add_argument('--fetch-cvss', action='store_true')
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows = read_jsonl(Path(args.manifest))
    if not manifest_rows:
        raise SystemExit(f'empty manifest: {args.manifest}')
    manifest_map = manifest_index(manifest_rows)
    inventory = inventory_by_bug(fetch=args.fetch_cvss)
    cvss_meta = project_cvss_meta(inventory)

    projects = sorted({row['project'] for row in manifest_rows})
    artifacts = []
    for project in projects:
        snapshot = project_snapshot(project, Path(args.src_root) / project, Path(args.src_root), cvss_meta)
        for row in iter_artifacts(snapshot, per_project_limit=0):
            manifest_row = manifest_map.get((row['project'], row['crash_relpath']))
            inventory_row = inventory.get((manifest_row or {}).get('bug_id', '')) if manifest_row else None
            artifacts.append(merge_manifest(row, manifest_row, inventory_row))

    prefix = args.prefix
    artifact_index_path = out_dir / f'{prefix}_artifact_index.jsonl'
    bootstrap_path = out_dir / f'{prefix}_bootstrap_evidence.jsonl'
    enriched_path = out_dir / f'{prefix}_enriched_artifacts.jsonl'
    findings_path = out_dir / f'{prefix}_findings.jsonl'
    cards_path = out_dir / f'{prefix}_cards.jsonl'
    summary_csv_path = out_dir / f'{prefix}_project_summary.csv'
    summary_md_path = out_dir / f'{prefix}_summary.md'

    write_jsonl(artifact_index_path, artifacts)
    write_jsonl(bootstrap_path, bootstrap_rows(artifacts))
    enriched, _ = enrich_projects(artifacts)
    write_jsonl(enriched_path, enriched)
    findings = aggregate_findings(enriched)
    findings, cards = attach_ground_truth(findings, enriched)
    write_jsonl(findings_path, findings)
    write_jsonl(cards_path, cards)
    write_csv(summary_csv_path, summary_rows(findings))
    write_summary(summary_md_path, artifacts, findings, cards)

    crash_backed_enriched = [row for row in enriched if is_crash_backed(row)]
    crash_backed_findings = aggregate_findings(crash_backed_enriched)
    crash_backed_findings, crash_backed_cards = attach_ground_truth(crash_backed_findings, crash_backed_enriched)
    crash_backed_enriched_path = out_dir / f'{prefix}_crash_backed_enriched_artifacts.jsonl'
    crash_backed_findings_path = out_dir / f'{prefix}_crash_backed_findings.jsonl'
    crash_backed_cards_path = out_dir / f'{prefix}_crash_backed_cards.jsonl'
    crash_backed_summary_csv_path = out_dir / f'{prefix}_crash_backed_project_summary.csv'
    crash_backed_summary_md_path = out_dir / f'{prefix}_crash_backed_summary.md'
    write_jsonl(crash_backed_enriched_path, crash_backed_enriched)
    write_jsonl(crash_backed_findings_path, crash_backed_findings)
    write_jsonl(crash_backed_cards_path, crash_backed_cards)
    write_csv(crash_backed_summary_csv_path, summary_rows(crash_backed_findings))
    write_summary(crash_backed_summary_md_path, crash_backed_enriched, crash_backed_findings, crash_backed_cards)

    print(f'PROJECTS {projects}')
    print(f'ARTIFACTS {len(artifacts)}')
    print(f'FINDINGS {len(findings)}')
    print(f'HIGH_OR_CRITICAL_POSITIVES {sum(1 for row in findings if row["risk_level"] >= 3)}')
    print(f'CRASH_BACKED_ARTIFACTS {len(crash_backed_enriched)}')
    print(f'CRASH_BACKED_FINDINGS {len(crash_backed_findings)}')
    print(f'WROTE {artifact_index_path}')
    print(f'WROTE {bootstrap_path}')
    print(f'WROTE {enriched_path}')
    print(f'WROTE {findings_path}')
    print(f'WROTE {cards_path}')
    print(f'WROTE {summary_csv_path}')
    print(f'WROTE {summary_md_path}')
    print(f'WROTE {crash_backed_enriched_path}')
    print(f'WROTE {crash_backed_findings_path}')
    print(f'WROTE {crash_backed_cards_path}')
    print(f'WROTE {crash_backed_summary_csv_path}')
    print(f'WROTE {crash_backed_summary_md_path}')


if __name__ == '__main__':
    main()
