#!/usr/bin/env python3
import csv
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
CVE2SKETCH = ROOT / 'CVE2SKETCH'

XLSX_PATH = STRUCTRISK / 'user75_cve_summary.xlsx'
CSV_PATH = STRUCTRISK / 'user75_cve_summary.csv'
MD_PATH = STRUCTRISK / 'user75_cve_tables.md'
TSV_PATH = CVE2SKETCH / 'examples' / 'user75_cves.tsv'

NS = {
    'a': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
}


def read_xlsx(path: Path):
    with zipfile.ZipFile(path) as zf:
        shared = []
        if 'xl/sharedStrings.xml' in zf.namelist():
            root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
            for si in root.findall('a:si', NS):
                shared.append(''.join(node.text or '' for node in si.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')))

        workbook = ET.fromstring(zf.read('xl/workbook.xml'))
        first_sheet = next(iter(workbook.find('a:sheets', NS)))
        rels = ET.fromstring(zf.read('xl/_rels/workbook.xml.rels'))
        targets = {rel.attrib['Id']: rel.attrib['Target'] for rel in rels}
        rid = first_sheet.attrib['{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id']
        target = 'xl/' + targets[rid]

        sheet = ET.fromstring(zf.read(target))
        rows = []
        for row in sheet.findall('.//a:sheetData/a:row', NS):
            values = {}
            for cell in row.findall('a:c', NS):
                ref = cell.attrib.get('r', '')
                match = re.match(r'([A-Z]+)(\d+)', ref)
                if not match:
                    continue
                col = 0
                for ch in match.group(1):
                    col = col * 26 + ord(ch) - 64
                col -= 1
                cell_type = cell.attrib.get('t')
                value_node = cell.find('a:v', NS)
                value = ''
                if cell_type == 's' and value_node is not None:
                    value = shared[int(value_node.text)]
                elif cell_type == 'inlineStr':
                    is_node = cell.find('a:is', NS)
                    if is_node is not None:
                        value = ''.join(node.text or '' for node in is_node.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t'))
                elif value_node is not None and value_node.text is not None:
                    value = value_node.text
                values[col] = value
            if values:
                rows.append([values.get(i, '') for i in range(max(values) + 1)])
    return rows


def markdown_table(headers, rows):
    out = []
    out.append('| ' + ' | '.join(headers) + ' |')
    out.append('|' + '|'.join([' --- ' for _ in headers]) + '|')
    for row in rows:
        out.append('| ' + ' | '.join(str(row.get(h, '')).replace('\n', ' ') for h in headers) + ' |')
    return out


def main():
    rows = read_xlsx(XLSX_PATH)
    headers = rows[0]
    records = []
    for row in rows[1:]:
        padded = row + [''] * max(0, len(headers) - len(row))
        record = dict(zip(headers, padded))
        if (record.get('project') or '').strip():
            records.append(record)

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(records)

    TSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    tsv_fields = ['index', 'project', 'stars', 'vuln_type', 'cve_id']
    with TSV_PATH.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=tsv_fields, delimiter='\t')
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field, '') for field in tsv_fields})

    severity_counter = Counter(record.get('cvss31_severity', 'UNRESOLVED') or 'UNRESOLVED' for record in records)
    source_counter = Counter(record.get('cvss31_source', 'UNKNOWN') or 'UNKNOWN' for record in records)
    type_counter = Counter(record.get('vuln_type', 'UNKNOWN') or 'UNKNOWN' for record in records)

    md_lines = [
        '# User 75 CVE Summary Tables',
        '',
        '- Snapshot date: `2026-04-15`',
        '- Severity source rule: use the highest available `CVSS v3.1` from the maintained summary workbook; preserve `NVD_NO_RECORD` entries as `UNRESOLVED`.',
        '- Detailed CSV: `StructRisk/user75_cve_summary.csv`',
        '- TSV mirror: `CVE2SKETCH/examples/user75_cves.tsv`',
        '',
        '## Severity Distribution',
        '',
    ]
    md_lines += markdown_table(['Severity', 'Count'], [{'Severity': key, 'Count': value} for key, value in severity_counter.items()])
    md_lines += [
        '',
        '## Source Distribution',
        '',
    ]
    md_lines += markdown_table(['CVSS Source', 'Count'], [{'CVSS Source': key, 'Count': value} for key, value in source_counter.items()])
    md_lines += [
        '',
        '## Vulnerability Type Distribution',
        '',
    ]
    md_lines += markdown_table(['Vulnerability Type', 'Count'], [{'Vulnerability Type': key, 'Count': value} for key, value in type_counter.most_common()])
    md_lines += [
        '',
        '## Detailed Records',
        '',
    ]
    detail_fields = ['index', 'project', 'stars', 'vuln_type', 'cve_id', 'cvss31_score', 'cvss31_severity', 'cvss31_source', 'vuln_status']
    md_lines += markdown_table(detail_fields, records)
    MD_PATH.write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    print(f'WROTE {CSV_PATH} ({len(records)} rows)')
    print(f'WROTE {TSV_PATH} ({len(records)} rows)')
    print(f'WROTE {MD_PATH}')


if __name__ == '__main__':
    main()
