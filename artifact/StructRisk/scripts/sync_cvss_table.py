#!/usr/bin/env python3
import csv
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
XLSX_PATH = STRUCTRISK / 'structrisk_nvd_cvss31.xlsx'
CSV_PATH = STRUCTRISK / 'structrisk_nvd_cvss31.csv'
PROJECTS_PATH = STRUCTRISK / 'phase1_projects.txt'
SUMMARY_PATH = STRUCTRISK / 'generated' / 'cvss_table_summary.txt'

NS = {
    'a': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
}
MAIN_NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'


def col_index(ref: str) -> int:
    letters = ''.join(ch for ch in ref if ch.isalpha())
    value = 0
    for ch in letters:
        value = value * 26 + ord(ch.upper()) - 64
    return value - 1


def load_shared_strings(zf: zipfile.ZipFile):
    if 'xl/sharedStrings.xml' not in zf.namelist():
        return []
    root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
    shared = []
    for si in root.findall('a:si', NS):
        shared.append(''.join(node.text or '' for node in si.iter(f'{MAIN_NS}t')))
    return shared


def workbook_sheet_target(zf: zipfile.ZipFile) -> str:
    wb = ET.fromstring(zf.read('xl/workbook.xml'))
    sheets = wb.find('a:sheets', NS)
    first = next(iter(sheets))
    rels = ET.fromstring(zf.read('xl/_rels/workbook.xml.rels'))
    rid = first.attrib[f'{{{NS["r"]}}}id']
    targets = {rel.attrib['Id']: rel.attrib['Target'] for rel in rels}
    return 'xl/' + targets[rid]


def read_sheet_rows(zf: zipfile.ZipFile, sheet_target: str):
    shared = load_shared_strings(zf)
    root = ET.fromstring(zf.read(sheet_target))
    rows = []
    row_nodes = []
    for row in root.findall('.//a:sheetData/a:row', NS):
        row_nodes.append(row)
        rowmap = {}
        for cell in row.findall('a:c', NS):
            ref = cell.attrib.get('r', '')
            idx = col_index(ref)
            cell_type = cell.attrib.get('t')
            value_node = cell.find('a:v', NS)
            value = ''
            if cell_type == 's' and value_node is not None:
                value = shared[int(value_node.text)]
            elif cell_type == 'inlineStr':
                is_node = cell.find('a:is', NS)
                if is_node is not None:
                    value = ''.join(n.text or '' for n in is_node.iter(f'{MAIN_NS}t'))
            elif value_node is not None and value_node.text is not None:
                value = value_node.text
            rowmap[idx] = value
        if rowmap:
            max_col = max(rowmap)
            rows.append([rowmap.get(i, '') for i in range(max_col + 1)])
        else:
            rows.append([])
    return root, row_nodes, rows


def set_first_cell_numeric(row_node: ET.Element, row_number: int, value: int) -> None:
    cell = None
    for current in row_node.findall('a:c', NS):
        if col_index(current.attrib.get('r', '')) == 0:
            cell = current
            break
    if cell is None:
        cell = ET.Element(f'{MAIN_NS}c', {'r': f'A{row_number}'})
        row_node.insert(0, cell)
    cell.attrib.pop('t', None)
    is_node = cell.find('a:is', NS)
    if is_node is not None:
        cell.remove(is_node)
    value_node = cell.find('a:v', NS)
    if value_node is None:
        value_node = ET.SubElement(cell, f'{MAIN_NS}v')
    value_node.text = str(value)
    cell.attrib['r'] = f'A{row_number}'


def sync_table() -> None:
    with zipfile.ZipFile(XLSX_PATH, 'r') as zf:
        sheet_target = workbook_sheet_target(zf)
        sheet_root, row_nodes, rows = read_sheet_rows(zf, sheet_target)
        headers = rows[0]
        data_rows = []
        for idx, row in enumerate(rows[1:], start=2):
            padded = row + [''] * max(0, len(headers) - len(row))
            record = dict(zip(headers, padded))
            if (record.get('project') or '').strip():
                data_rows.append((idx, record))

        for serial, (row_number, _) in enumerate(data_rows, start=1):
            set_first_cell_numeric(row_nodes[row_number - 1], row_number, serial)

        sheet_bytes = ET.tostring(sheet_root, encoding='utf-8', xml_declaration=True)
        tmp_path = XLSX_PATH.with_suffix('.xlsx.tmp')
        with zipfile.ZipFile(XLSX_PATH, 'r') as src, zipfile.ZipFile(tmp_path, 'w') as dst:
            for item in src.infolist():
                payload = sheet_bytes if item.filename == sheet_target else src.read(item.filename)
                dst.writestr(item, payload)
        tmp_path.replace(XLSX_PATH)

    with zipfile.ZipFile(XLSX_PATH, 'r') as zf:
        _, _, rows = read_sheet_rows(zf, workbook_sheet_target(zf))

    headers = rows[0]
    cleaned = []
    for row in rows[1:]:
        padded = row + [''] * max(0, len(headers) - len(row))
        record = dict(zip(headers, padded))
        if (record.get('project') or '').strip():
            cleaned.append(record)

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(cleaned)

    seen = set()
    ordered_projects = []
    for record in cleaned:
        project = (record.get('project') or '').strip()
        if project and project not in seen:
            ordered_projects.append(project)
            seen.add(project)
    PROJECTS_PATH.write_text('\n'.join(ordered_projects) + '\n', encoding='utf-8')

    severity = Counter((record.get('highest_cvss31_severity') or 'NONE').strip() or 'NONE' for record in cleaned)
    by_source = defaultdict(Counter)
    for record in cleaned:
        source = (record.get('highest_cvss31_source') or 'NONE').strip() or 'NONE'
        sev = (record.get('highest_cvss31_severity') or 'NONE').strip() or 'NONE'
        by_source[source][sev] += 1

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(
        '\n'.join([
            f'total_cves={len(cleaned)}',
            f'total_projects={len(ordered_projects)}',
            f'severity={dict(severity)}',
            f'source_severity={{{", ".join(f"{src}: {dict(cnt)}" for src, cnt in by_source.items())}}}',
        ]) + '\n',
        encoding='utf-8',
    )

    print(f'SYNCED {XLSX_PATH}')
    print(f'WROTE {CSV_PATH} ({len(cleaned)} rows)')
    print(f'WROTE {PROJECTS_PATH} ({len(ordered_projects)} projects)')
    print(f'WROTE {SUMMARY_PATH}')


if __name__ == '__main__':
    sync_table()
