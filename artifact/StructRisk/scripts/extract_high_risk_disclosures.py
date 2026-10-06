#!/usr/bin/env python3
import argparse
import csv
import json
import re
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET

NS = {
    "a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


def col_to_num(col: str) -> int:
    num = 0
    for ch in col:
        num = num * 26 + (ord(ch.upper()) - 64)
    return num


def load_xlsx_rows(path: Path):
    with ZipFile(path) as archive:
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        rel_map = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels}
        first_sheet = next(iter(workbook.find("a:sheets", NS)))
        target = rel_map[first_sheet.attrib["{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"]]

        shared_strings = []
        if "xl/sharedStrings.xml" in archive.namelist():
            sst = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            for si in sst.findall("a:si", NS):
                shared_strings.append("".join(t.text or "" for t in si.iterfind('.//a:t', NS)))

        worksheet = ET.fromstring(archive.read("xl/" + target.lstrip('/')))
        rows = []
        for row in worksheet.findall('.//a:sheetData/a:row', NS):
            values = {}
            for cell in row.findall('a:c', NS):
                ref = cell.attrib.get('r', '')
                match = re.match(r'([A-Z]+)(\d+)', ref)
                if not match:
                    continue
                idx = col_to_num(match.group(1))
                cell_type = cell.attrib.get('t')
                value_node = cell.find('a:v', NS)
                value = '' if value_node is None or value_node.text is None else value_node.text
                if cell_type == 's':
                    value = shared_strings[int(value)] if value else ''
                elif cell_type == 'inlineStr':
                    value = ''.join(t.text or '' for t in cell.iterfind('.//a:t', NS))
                values[idx] = value
            if values:
                rows.append(values)

    header_map = rows[0]
    header_lookup = {name: col for col, name in header_map.items() if name}
    body = rows[1:]

    def get(row, name: str) -> str:
        col = header_lookup.get(name)
        return '' if col is None else str(row.get(col, '') or '')

    materialized = []
    for row in body:
        materialized.append({name: get(row, name) for name in header_lookup})
    return materialized


def extract_field(text: str, patterns):
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return ''


def summarize(record):
    report = record.get('commit(.md format)', '')
    lower = report.lower()
    stack_frames = len(re.findall(r'^\s*#\d+\s', report, flags=re.MULTILINE))
    target = extract_field(report, [r'^-\s*Target:\s*(.+)$', r'^Target:\s*(.+)$'])
    location = extract_field(report, [r'^-\s*Location:\s*(.+)$', r'^Location:\s*(.+)$'])
    function = extract_field(report, [r'^-\s*Function:\s*(.+)$', r'^Function:\s*(.+)$'])
    reproduce_cmd = extract_field(
        report,
        [
            r'```\n([^`\n]+@@[^`\n]*)\n```',
            r'```\n([^`\n]*repro[^`\n]*)\n```',
        ],
    )
    return {
        'project': record.get('project', ''),
        'cve_id': record.get('cve_id', ''),
        'vuln_type': record.get('vuln_type', ''),
        'vuln_status': record.get('vuln_status', ''),
        'highest_cvss31': record.get('highest_cvss31', ''),
        'highest_cvss31_severity': record.get('highest_cvss31_severity', ''),
        'highest_cvss31_source': record.get('highest_cvss31_source', ''),
        'nvd_cvss31': record.get('nvd_cvss31', ''),
        'disclose_url': record.get('commit url', ''),
        'target': target,
        'location': location,
        'function': function,
        'stack_frame_count': stack_frames,
        'has_asan_report': 'addresssanitizer' in lower or 'asan report' in lower or 'summary: addresssanitizer' in lower,
        'has_root_cause': 'root cause' in lower,
        'has_reproduce': 'reproduce' in lower,
        'has_location': bool(location) or '/src/' in report,
        'has_target': bool(target),
        'report_char_count': len(report),
        'report_line_count': len(report.splitlines()),
        'reproduce_cmd': reproduce_cmd,
        'report_md': report,
    }


def write_jsonl(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + '\n')


def write_csv(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        'project', 'cve_id', 'vuln_type', 'vuln_status', 'highest_cvss31',
        'highest_cvss31_severity', 'highest_cvss31_source', 'nvd_cvss31',
        'target', 'location', 'function', 'stack_frame_count',
        'has_asan_report', 'has_root_cause', 'has_reproduce',
        'has_location', 'has_target', 'report_char_count', 'report_line_count',
        'reproduce_cmd', 'disclose_url'
    ]
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field, '') for field in fields})


def write_summary(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    total = len(records)
    projects = len({r['project'] for r in records})
    with_asan = sum(1 for r in records if r['has_asan_report'])
    with_root = sum(1 for r in records if r['has_root_cause'])
    with_repro = sum(1 for r in records if r['has_reproduce'])
    with_loc = sum(1 for r in records if r['has_location'])
    lines = [
        '# High-Risk Disclosure Summary',
        '',
        f'- Records: `{total}`',
        f'- Projects: `{projects}`',
        f'- With ASan report text: `{with_asan}`',
        f'- With root-cause discussion: `{with_root}`',
        f'- With reproduce section: `{with_repro}`',
        f'- With explicit or recovered location: `{with_loc}`',
        '',
        '| Project | CVE | Type | CVSS | Source | ASan | Root Cause | URL |',
        '|---|---|---|---:|---|---:|---:|---|',
    ]
    for record in sorted(records, key=lambda item: (item['project'], item['cve_id'])):
        lines.append(
            f"| {record['project']} | {record['cve_id']} | {record['vuln_type']} | {record['highest_cvss31']} | {record['highest_cvss31_source']} | {int(record['has_asan_report'])} | {int(record['has_root_cause'])} | {record['disclose_url']} |"
        )
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Extract HIGH disclosure-backed CVE records from StructRisk xlsx without external dependencies.')
    parser.add_argument('--input', default='StructRisk/structrisk_nvd_cvss31.xlsx')
    parser.add_argument('--jsonl-out', default='StructRisk/generated/high_risk_disclosures.jsonl')
    parser.add_argument('--csv-out', default='StructRisk/generated/high_risk_disclosures.csv')
    parser.add_argument('--summary-out', default='StructRisk/generated/high_risk_disclosures_summary.md')
    parser.add_argument('--keep-disclosure-urls', action='store_true', help='accepted for compatibility; public issue/advisory URLs are always retained')
    args = parser.parse_args()

    records = load_xlsx_rows(Path(args.input))
    high = [summarize(r) for r in records if (r.get('highest_cvss31_severity') or '').upper() == 'HIGH']
    high.sort(key=lambda item: (item['project'], item['cve_id']))
    write_jsonl(Path(args.jsonl_out), high)
    write_csv(Path(args.csv_out), high)
    write_summary(Path(args.summary_out), high)
    print(Path(args.jsonl_out))
    print(Path(args.csv_out))
    print(Path(args.summary_out))
    print(f'extracted_high_records={len(high)}')


if __name__ == '__main__':
    main()
