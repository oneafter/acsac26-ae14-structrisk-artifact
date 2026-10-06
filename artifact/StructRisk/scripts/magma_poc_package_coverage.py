#!/usr/bin/env python3
import argparse
import json
import re
import tarfile
from collections import Counter
from pathlib import Path

from magma_common import NVD_CACHE_DEFAULT, enrich_cvss, parse_bug_inventory, parse_legacy_preprint_inventory


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
EXTERNAL = STRUCTRISK / 'external'
GENERATED = STRUCTRISK / 'generated'

POC_PACKAGES = [
    'poc_afl.tar.gz',
    'poc_aflfast.tar.gz',
    'poc_aflplusplus.tar.gz',
    'poc_aflplusplus_lto.tar.gz',
    'poc_honggfuzz.tar.gz',
    'poc_moptafl.tar.gz',
    'poc_angora.tar.gz',
    'poc_instrim.tar.gz',
]
POC_RE = re.compile(
    r'^(?P<fuzzer>.+?)_(?P<project>libpng|libtiff|libxml2|sqlite3|poppler|openssl|php|lua|libsndfile)_(?P<target>.+)_(?P<bug_id>(?:AAH|JCH|MAE|LUA|SND|PHP|SQL|PNG|TIF|XML|PDF|SSL)\d{3})\.[^.]+$'
)


def inventory_maps():
    legacy = parse_legacy_preprint_inventory()
    legacy = enrich_cvss(legacy, NVD_CACHE_DEFAULT, fetch=False, sleep_secs=0.0, retry_errors=False)
    html = parse_bug_inventory(STRUCTRISK / 'external' / 'magma' / 'bugs.html')
    html = enrich_cvss(html, NVD_CACHE_DEFAULT, fetch=False, sleep_secs=0.0, retry_errors=False)
    return ({row['bug_id']: row for row in legacy}, {row['bug_id']: row for row in html})


def scan_package(path):
    bug_counts = Counter()
    projects = Counter()
    targets = Counter()
    examples = []
    files = 0
    unmatched = 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            if not member.isfile():
                continue
            files += 1
            match = POC_RE.match(Path(member.name).name)
            if not match:
                unmatched += 1
                if len(examples) < 5:
                    examples.append(member.name)
                continue
            row = match.groupdict()
            bug_counts[row['bug_id']] += 1
            projects[row['project']] += 1
            targets[f"{row['project']}/{row['target']}"] += 1
    return {
        'files': files,
        'matched': sum(bug_counts.values()),
        'unmatched': unmatched,
        'bug_ids': len(bug_counts),
        'projects': dict(projects),
        'targets': dict(targets),
        'top_bug_ids': bug_counts.most_common(10),
        'unmatched_examples': examples,
        '_bug_counts': bug_counts,
        '_projects': projects,
        '_targets': targets,
    }


def clean_package(row):
    return {key: value for key, value in row.items() if not key.startswith('_')}


def main():
    parser = argparse.ArgumentParser(description='Scan public MAGMA PoC packages and report bug-ID coverage.')
    parser.add_argument('--poc-dir', default=str(EXTERNAL))
    parser.add_argument('--out-prefix', default=str(GENERATED / 'magma_poc_package_coverage'))
    args = parser.parse_args()

    poc_dir = Path(args.poc_dir)
    legacy_by_bug, html_by_bug = inventory_maps()
    packages = {}
    union_bug_counts = Counter()
    union_projects = Counter()
    union_targets = Counter()
    total_files = 0
    total_matched = 0
    missing = []
    for name in POC_PACKAGES:
        path = poc_dir / name
        if not path.exists():
            missing.append(name)
            continue
        row = scan_package(path)
        packages[name] = row
        union_bug_counts.update(row['_bug_counts'])
        union_projects.update(row['_projects'])
        union_targets.update(row['_targets'])
        total_files += row['files']
        total_matched += row['matched']

    covered = set(union_bug_counts)
    legacy_ids = set(legacy_by_bug)
    html_ids = set(html_by_bug)
    legacy_covered = covered & legacy_ids
    html_covered = covered & html_ids
    legacy_cves = {legacy_by_bug[bug].get('cve_id') for bug in legacy_covered if legacy_by_bug[bug].get('cve_id')}
    legacy_high = {bug for bug in legacy_covered if int(legacy_by_bug[bug].get('risk_level') or 0) >= 3}

    payload = {
        'missing_packages': missing,
        'packages': {name: clean_package(row) for name, row in packages.items()},
        'union': {
            'archive_files': total_files,
            'matched_poc_files': total_matched,
            'distinct_bug_ids': len(covered),
            'projects': dict(union_projects),
            'targets': dict(union_targets),
            'legacy_inventory_ids': len(legacy_ids),
            'legacy_covered': len(legacy_covered),
            'legacy_missing': len(legacy_ids - legacy_covered),
            'legacy_cves': len(legacy_cves),
            'legacy_high_bug_ids': len(legacy_high),
            'html_inventory_ids': len(html_ids),
            'html_covered': len(html_covered),
            'html_missing': len(html_ids - html_covered),
            'covered_legacy_ids': sorted(legacy_covered),
            'missing_legacy_ids': sorted(legacy_ids - legacy_covered),
            'covered_html_ids': sorted(html_covered),
        },
    }
    prefix = Path(args.out_prefix)
    json_path = prefix.with_suffix('.json')
    md_path = prefix.with_suffix('.md')
    json_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    lines = [
        '# MAGMA PoC Package Coverage',
        '',
        '## Packages',
        '',
        '| Package | Files | Matched | Bug IDs | Projects |',
        '| --- | ---: | ---: | ---: | ---: |',
    ]
    for name in POC_PACKAGES:
        row = packages.get(name)
        if row is None:
            lines.append(f'| `{name}` | missing | missing | missing | missing |')
        else:
            lines.append(f"| `{name}` | {row['files']} | {row['matched']} | {row['bug_ids']} | {len(row['projects'])} |")
    union = payload['union']
    lines.extend([
        '',
        '## Union',
        '',
        f"- Archive files scanned: `{union['archive_files']}`",
        f"- Matched PoC files: `{union['matched_poc_files']}`",
        f"- Distinct parsed bug IDs: `{union['distinct_bug_ids']}`",
        f"- Legacy inventory coverage: `{union['legacy_covered']}/{union['legacy_inventory_ids']}` bug IDs, `{union['legacy_cves']}` CVEs, `{union['legacy_high_bug_ids']}` HIGH-or-higher bug IDs",
        f"- Current HTML inventory coverage: `{union['html_covered']}/{union['html_inventory_ids']}` bug IDs",
        '',
        'Covered legacy bug IDs: `' + ', '.join(union['covered_legacy_ids']) + '`',
    ])
    md_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json_path)
    print(md_path)
    print(json.dumps(payload['union'], indent=2))


if __name__ == '__main__':
    main()
