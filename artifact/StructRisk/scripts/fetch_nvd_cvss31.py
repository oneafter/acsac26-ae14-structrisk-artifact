#!/usr/bin/env python3
import csv
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

INPUT_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('CVE2SKETCH/examples/user75_cves.tsv')
OUTPUT_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('StructRisk/structrisk_nvd_cvss31.csv')
SLEEP_SECS = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

FIELDNAMES = [
    'index',
    'project',
    'vuln_type',
    'cve_id',
    'vuln_status',
    'nvd_cvss31',
    'highest_cvss31',
    'highest_cvss31_severity',
    'highest_cvss31_source',
    'highest_cvss31_type',
    'highest_cvss31_vector',
]


def init_record(row):
    return {
        'index': row.get('index', ''),
        'project': row.get('project', ''),
        'vuln_type': row.get('vuln_type', ''),
        'cve_id': row.get('cve_id', ''),
        'vuln_status': '',
        'nvd_cvss31': '',
        'highest_cvss31': '',
        'highest_cvss31_severity': '',
        'highest_cvss31_source': '',
        'highest_cvss31_type': '',
        'highest_cvss31_vector': '',
    }


def fetch_payload(cve_id):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    req = Request(url, headers={'User-Agent': 'StructRisk/0.1'})
    with urlopen(req, timeout=30) as resp:
        return json.load(resp)


def fill_metrics(record, payload):
    vulns = payload.get('vulnerabilities', []) or []
    if not vulns:
        return record
    cve = (vulns[0].get('cve') or {})
    record['vuln_status'] = cve.get('vulnStatus', '')
    entries = ((cve.get('metrics') or {}).get('cvssMetricV31') or [])
    best = None
    for item in entries:
        cvss = item.get('cvssData') or {}
        try:
            score = float(cvss.get('baseScore'))
        except (TypeError, ValueError):
            continue
        if item.get('source') == 'nvd@nist.gov':
            record['nvd_cvss31'] = score
        candidate = {
            'score': score,
            'severity': cvss.get('baseSeverity', ''),
            'source': item.get('source', ''),
            'type': item.get('type', ''),
            'vector': cvss.get('vectorString', ''),
        }
        if best is None or candidate['score'] > best['score']:
            best = candidate
    if best is not None:
        record['highest_cvss31'] = best['score']
        record['highest_cvss31_severity'] = best['severity']
        record['highest_cvss31_source'] = best['source']
        record['highest_cvss31_type'] = best['type']
        record['highest_cvss31_vector'] = best['vector']
    return record


def main():
    if not INPUT_PATH.exists():
        raise SystemExit(f'Input file not found: {INPUT_PATH}')

    rows = list(csv.DictReader(INPUT_PATH.open(encoding='utf-8'), delimiter='\t'))
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            record = init_record(row)
            cve_id = record['cve_id']
            if cve_id:
                try:
                    payload = fetch_payload(cve_id)
                    fill_metrics(record, payload)
                    print(f'fetched {cve_id}', file=sys.stderr)
                except Exception as exc:
                    print(f'failed {cve_id}: {exc}', file=sys.stderr)
                if SLEEP_SECS > 0:
                    time.sleep(SLEEP_SECS)
            writer.writerow(record)
    print(OUTPUT_PATH)


if __name__ == '__main__':
    main()
