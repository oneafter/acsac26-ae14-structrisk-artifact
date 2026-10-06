#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from magma_local_artifact_eval import attach_ground_truth, summary_rows
from phase1_offline_experiment import aggregate_findings, write_csv


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

INPUT_DEFAULTS = [
    GENERATED / 'magma_local_crash_backed_enriched_artifacts.jsonl',
    GENERATED / 'magma_poc49_crash_backed_enriched_artifacts.jsonl',
]
PREFIX_DEFAULT = GENERATED / 'magma_unified_crash_backed'


def artifact_path(path: Path):
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def artifact_key(row):
    return (
        row.get('project') or '',
        row.get('magma_target') or row.get('target_name') or '',
        row.get('magma_bug_id') or '',
        row.get('crash_name') or Path(row.get('crash_relpath') or '').name,
    )


def richness_score(row):
    return (
        bool(row.get('matched_has_section')),
        row.get('report_match_level') == 'exact',
        bool(row.get('matched_project_loc')),
        bool(row.get('matched_asan_type')),
        bool(row.get('matched_assertion')),
        len(row.get('matched_section_text') or ''),
        int(row.get('support_count') or 0),
    )


def merge_artifacts(inputs):
    merged = {}
    source_counts = Counter()
    duplicate_count = 0
    for source_label, rows in inputs:
        source_counts[source_label] += len(rows)
        for row in rows:
            key = artifact_key(row)
            candidate = dict(row)
            candidate['_magma_source_slices'] = sorted(set(candidate.get('_magma_source_slices') or []) | {source_label})
            previous = merged.get(key)
            if previous is None:
                merged[key] = candidate
                continue
            duplicate_count += 1
            sources = sorted(set(previous.get('_magma_source_slices') or []) | {source_label})
            if richness_score(candidate) > richness_score(previous):
                candidate['_magma_source_slices'] = sources
                merged[key] = candidate
            else:
                previous['_magma_source_slices'] = sources
    artifacts = sorted(
        merged.values(),
        key=lambda row: (row.get('project') or '', row.get('magma_target') or row.get('target_name') or '', row.get('magma_bug_id') or '', row.get('crash_name') or ''),
    )
    return artifacts, source_counts, duplicate_count


def write_summary(path: Path, input_paths, artifacts, findings, cards, source_counts, duplicate_count) -> None:
    distinct_bugs = sorted({bug for row in findings for bug in row.get('metadata', {}).get('aligned_bug_ids', [])})
    distinct_cves = sorted({cve for row in findings for cve in row.get('metadata', {}).get('aligned_cve_ids', [])})
    source_mix = Counter()
    for row in artifacts:
        source_mix['+'.join(row.get('_magma_source_slices') or ['unknown'])] += 1

    lines = [
        '# MAGMA Unified Crash-Backed Evidence-Card Slice',
        '',
        '## Inputs',
        '',
    ]
    for input_path in input_paths:
        suffix = '' if input_path.exists() else ' (component intermediate not bundled)'
        lines.append(f'- `{artifact_path(input_path)}`{suffix}')
    lines.extend([
        '',
        'The public artifact includes the derived unified evidence-card slice and coverage summaries; larger public-PoC replay intermediates are not bundled.',
        '',
        '## Coverage',
        '',
        f'- Input crash-backed artifacts: `{sum(source_counts.values())}`',
        f'- Deduplicated artifacts: `{len(artifacts)}`',
        f'- Duplicate artifacts removed: `{duplicate_count}`',
        f'- Deduplicated findings: `{len(findings)}`',
        f'- Projects: `{len({row["project"] for row in findings})}`',
        f'- HIGH-or-CRITICAL positives: `{sum(1 for row in findings if int(row.get("risk_level") or 0) >= 3)}`',
        f'- Distinct MAGMA bug IDs: `{len(distinct_bugs)}`',
        f'- Distinct CVEs: `{len(distinct_cves)}`',
        '',
        '## Artifact Sources',
        '',
    ])
    for key, value in sorted(source_counts.items()):
        lines.append(f'- `{key}` input artifacts: `{value}`')
    for key, value in sorted(source_mix.items()):
        lines.append(f'- `{key}` retained artifacts: `{value}`')
    lines.extend(['', '## Project Summary', ''])
    for row in summary_rows(findings):
        lines.append(
            f"- `{row['project']}`: findings={row['finding_count']}, positives={row['risk_3']}, avg_support={row['avg_support_count']}, avg_site_anchor={row['avg_site_anchor']}, avg_locality={row['avg_locality']}"
        )
    lines.extend(['', '## Example Cards', ''])
    for card in cards[:8]:
        lines.append(
            f"- `{card['id']}` ({card['project']}): bugs={','.join(card['bug_ids']) or 'n/a'}, cves={','.join(card['cve_ids']) or 'n/a'}, asan={card['matched_asan_type'] or 'n/a'}"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Merge exact-replay and public-PoC MAGMA crash-backed artifacts into one evidence-card slice.')
    parser.add_argument('--input', action='append', default=[], help='Crash-backed enriched JSONL input. Can be repeated.')
    parser.add_argument('--out-prefix', default=str(PREFIX_DEFAULT))
    args = parser.parse_args()

    input_paths = [Path(item) for item in args.input] if args.input else INPUT_DEFAULTS
    inputs = []
    for path in input_paths:
        label = path.name.replace('_crash_backed_enriched_artifacts.jsonl', '')
        rows = load_jsonl(path)
        inputs.append((label, rows))

    artifacts, source_counts, duplicate_count = merge_artifacts(inputs)
    findings = aggregate_findings(artifacts)
    findings, cards = attach_ground_truth(findings, artifacts)

    prefix = Path(args.out_prefix)
    enriched_path = prefix.parent / f'{prefix.name}_enriched_artifacts.jsonl'
    findings_path = prefix.parent / f'{prefix.name}_findings.jsonl'
    cards_path = prefix.parent / f'{prefix.name}_cards.jsonl'
    summary_csv_path = prefix.parent / f'{prefix.name}_project_summary.csv'
    summary_md_path = prefix.parent / f'{prefix.name}_summary.md'

    write_jsonl(enriched_path, artifacts)
    write_jsonl(findings_path, findings)
    write_jsonl(cards_path, cards)
    write_csv(summary_csv_path, summary_rows(findings))
    write_summary(summary_md_path, input_paths, artifacts, findings, cards, source_counts, duplicate_count)

    payload = {
        'input_artifacts': sum(source_counts.values()),
        'deduplicated_artifacts': len(artifacts),
        'duplicate_artifacts_removed': duplicate_count,
        'findings': len(findings),
        'projects': len({row.get('project') for row in findings}),
        'high_findings': sum(1 for row in findings if int(row.get('risk_level') or 0) >= 3),
        'high_or_critical_positives': sum(1 for row in findings if int(row.get('risk_level') or 0) >= 3),
        'distinct_bug_ids': len({bug for row in findings for bug in row.get('metadata', {}).get('aligned_bug_ids', [])}),
        'distinct_cves': len({cve for row in findings for cve in row.get('metadata', {}).get('aligned_cve_ids', [])}),
        'enriched_path': artifact_path(enriched_path),
        'findings_path': artifact_path(findings_path),
        'cards_path': artifact_path(cards_path),
        'summary_path': artifact_path(summary_md_path),
    }
    print(json.dumps(payload, indent=2))


if __name__ == '__main__':
    main()
