#!/usr/bin/env python3
import csv
import json
import math
import re
import time
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
EXTERNAL = STRUCTRISK / 'external' / 'magma'
GENERATED = STRUCTRISK / 'generated'

BUGS_HTML_DEFAULT = EXTERNAL / 'bugs.html'
NVD_CACHE_DEFAULT = EXTERNAL / 'nvd_cache.json'

CVSS_RE = re.compile(r'^CVE-\d{4}-\d+$')
PROJECT_NORMALIZATION = {
    'libpng': 'libpng',
    'LibTIFF': 'libtiff',
    'Libxml2': 'libxml2',
    'Poppler': 'poppler',
    'OpenSSL': 'openssl',
    'SQLite': 'sqlite3',
    'PHP': 'php',
    'Lua': 'lua',
    'libsndfile': 'libsndfile',
}

LEGACY_PREPRINT_INVENTORY = '''
libpng,AAH001,CVE-2018-13785,"Integer overflow; divide by zero",yes
libpng,AAH002,CVE-2019-7317,Use-after-free,yes
libpng,AAH003,CVE-2015-8472,API inconsistency,yes
libpng,AAH004,CVE-2015-0973,Integer overflow,no
libpng,AAH005,CVE-2014-9495,"Integer overflow; buffer overflow",yes
libpng,AAH007,,Memory leak,yes
libpng,AAH008,CVE-2013-6954,Null-pointer dereference,yes
libtiff,AAH009,CVE-2016-9535,Heap buffer overflow,yes
libtiff,AAH010,CVE-2016-5314,Heap buffer overflow,yes
libtiff,AAH011,CVE-2016-10266,Divide by zero,no
libtiff,AAH012,CVE-2016-10267,Divide by zero,no
libtiff,AAH013,CVE-2016-10269,Out-of-bounds read,yes
libtiff,AAH014,CVE-2016-10269,Out-of-bounds read,yes
libtiff,AAH015,CVE-2016-10270,Out-of-bounds read,yes
libtiff,AAH016,CVE-2015-8784,Heap buffer overflow,yes
libtiff,AAH017,CVE-2019-7663,Null-pointer dereference,yes
libtiff,AAH018,CVE-2018-8905,Heap buffer underflow,yes
libtiff,AAH019,CVE-2018-7456,Out-of-bounds read,no
libtiff,AAH020,CVE-2016-3658,Heap buffer overflow,yes
libtiff,AAH021,CVE-2018-18557,Out-of-bounds write,no
libtiff,AAH022,CVE-2017-11613,Resource exhaustion,yes
libxml2,AAH024,CVE-2017-9047,Stack buffer overflow,yes
libxml2,AAH025,CVE-2017-0663,Type confusion,yes
libxml2,AAH026,CVE-2017-7375,XML external entity,yes
libxml2,AAH027,CVE-2018-14567,Resource exhaustion,no
libxml2,AAH028,CVE-2017-5130,"Integer overflow; heap corruption",no
libxml2,AAH029,CVE-2017-9048,Stack buffer overflow,no
libxml2,AAH030,CVE-2017-8872,Out-of-bounds read,no
libxml2,AAH031,,Out-of-bounds read,no
libxml2,AAH032,CVE-2015-8317,Out-of-bounds read,yes
libxml2,AAH033,CVE-2016-4449,XML external entity,no
libxml2,AAH034,CVE-2016-1834,Heap buffer overflow,no
libxml2,AAH035,CVE-2016-1836,Use-after-free,no
libxml2,AAH036,CVE-2016-1837,Use-after-free,no
libxml2,AAH037,CVE-2016-1838,Heap buffer overread,yes
libxml2,AAH038,CVE-2016-1839,Heap buffer overread,no
libxml2,AAH039,,Heap buffer overread,no
libxml2,AAH040,CVE-2016-1840,Heap buffer overflow,no
libxml2,AAH041,CVE-2016-1762,Heap buffer overread,yes
poppler,AAH042,CVE-2019-14494,Divide by zero,yes
poppler,AAH043,CVE-2019-9959,Resource exhaustion,yes
poppler,AAH045,CVE-2017-9865,Stack buffer overflow,yes
poppler,AAH046,CVE-2019-10873,Null-pointer dereference,yes
poppler,AAH047,CVE-2019-12293,Heap buffer overread,yes
poppler,AAH048,CVE-2019-10872,Heap buffer overflow,yes
poppler,AAH049,CVE-2019-9200,Heap buffer underwrite,yes
poppler,AAH050,,Divide by zero,yes
poppler,AAH051,,Integer overflow,yes
poppler,AAH052,,Null-pointer dereference,yes
poppler,JCH201,CVE-2019-7310,Heap buffer overflow,yes
poppler,JCH202,CVE-2018-21009,Integer overflow,no
poppler,JCH203,CVE-2018-20650,Type confusion,no
poppler,JCH204,CVE-2018-20481,Null-pointer dereference,no
poppler,JCH206,CVE-2018-19058,Type confusion,no
poppler,JCH207,CVE-2018-13988,Out-of-bounds read,yes
poppler,JCH208,CVE-2019-12360,Stack buffer overflow,no
poppler,JCH209,CVE-2018-10768,Null-pointer dereference,no
poppler,JCH210,CVE-2017-9776,Integer overflow,no
poppler,JCH211,CVE-2017-18267,Resource exhaustion,no
poppler,JCH212,CVE-2017-14617,Divide by zero,yes
poppler,JCH214,CVE-2019-12493,Stack buffer overread,no
openssl,AAH053,CVE-2016-0705,Double-free,yes
openssl,AAH054,CVE-2016-2842,Out-of-bounds write,no
openssl,AAH055,CVE-2016-2108,Out-of-bounds read,yes
openssl,AAH056,CVE-2016-6309,Use-after-free,yes
openssl,AAH057,CVE-2016-2109,Resource exhaustion,no
openssl,AAH058,CVE-2016-2176,Stack buffer overread,no
openssl,AAH059,CVE-2016-6304,Resource exhaustion,no
openssl,MAE100,CVE-2016-2105,Integer overflow,no
openssl,MAE102,CVE-2016-6303,Integer overflow,no
openssl,MAE103,CVE-2017-3730,Null-pointer dereference,no
openssl,MAE104,CVE-2017-3735,Out-of-bounds read,yes
openssl,MAE105,CVE-2016-0797,Integer overflow,no
openssl,MAE106,CVE-2015-1790,Null-pointer dereference,no
openssl,MAE107,CVE-2015-0288,Null-pointer dereference,no
openssl,MAE108,CVE-2015-0208,Null-pointer dereference,no
openssl,MAE109,CVE-2015-0286,Type confusion,no
openssl,MAE110,CVE-2015-0289,Null-pointer dereference,no
openssl,MAE111,CVE-2015-1788,Resource exhaustion,no
openssl,MAE112,CVE-2016-7052,Null-pointer dereference,no
openssl,MAE113,CVE-2016-6308,Resource exhaustion,no
openssl,MAE114,CVE-2016-6305,Resource exhaustion,no
openssl,MAE115,CVE-2016-6302,Out-of-bounds read,yes
sqlite3,JCH214,CVE-2019-9936,Heap buffer overflow,no
sqlite3,JCH215,CVE-2019-20218,Stack buffer overread,yes
sqlite3,JCH216,CVE-2019-19923,Null-pointer dereference,no
sqlite3,JCH217,CVE-2019-19959,Out-of-bounds read,no
sqlite3,JCH218,CVE-2019-19925,Null-pointer dereference,no
sqlite3,JCH219,CVE-2019-19244,Out-of-bounds read,no
sqlite3,JCH220,CVE-2018-8740,Null-pointer dereference,no
sqlite3,JCH221,CVE-2017-15286,Null-pointer dereference,no
sqlite3,JCH222,CVE-2017-2520,Heap buffer overflow,no
sqlite3,JCH223,CVE-2017-2518,Use-after-free,no
sqlite3,JCH225,CVE-2017-10989,Heap buffer overflow,no
sqlite3,JCH226,CVE-2019-19646,Logical error,yes
sqlite3,JCH227,CVE-2013-7443,Heap buffer overflow,no
sqlite3,JCH228,CVE-2019-19926,Logical error,yes
sqlite3,JCH229,CVE-2019-19317,Resource exhaustion,no
sqlite3,JCH230,CVE-2015-3415,Double-free,no
sqlite3,JCH231,CVE-2020-9327,Null-pointer dereference,no
sqlite3,JCH232,CVE-2015-3414,Uninitialized memory access,yes
sqlite3,JCH233,CVE-2015-3416,Stack buffer overflow,no
sqlite3,JCH234,CVE-2019-19880,Null-pointer dereference,no
php,MAE001,CVE-2019-9020,Use-after-free,no
php,MAE002,CVE-2019-9021,Heap buffer overread,no
php,MAE004,CVE-2019-9641,Uninitialized memory access,no
php,MAE006,CVE-2019-11041,Out-of-bounds read,no
php,MAE008,CVE-2019-11034,Out-of-bounds read,yes
php,MAE009,CVE-2019-11039,Out-of-bounds read,no
php,MAE010,CVE-2019-11040,Heap buffer overflow,no
php,MAE011,CVE-2018-20783,Out-of-bounds read,no
php,MAE012,CVE-2019-9022,Out-of-bounds read,no
php,MAE013,CVE-2019-9024,Out-of-bounds read,no
php,MAE014,CVE-2019-9638,Uninitialized memory access,yes
php,MAE015,CVE-2019-9640,Out-of-bounds read,no
php,MAE016,CVE-2018-14883,Heap buffer overread,no
php,MAE017,CVE-2018-7584,Stack buffer underread,no
php,MAE018,CVE-2017-11362,Stack buffer overflow,no
php,MAE019,CVE-2014-9912,Out-of-bounds write,no
php,MAE020,CVE-2016-10159,Integer overflow,no
php,MAE021,CVE-2016-7414,Out-of-bounds read,no
'''



class MagmaBugParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_h2 = False
        self.in_td = False
        self.current_text = ''
        self.current_link = ''
        self.project = ''
        self.cells = []
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'h2':
            self.in_h2 = True
            self.current_text = ''
        if tag == 'td':
            self.in_td = True
            self.current_text = ''
            self.current_link = ''
        if self.in_td and tag == 'a':
            self.current_link = attrs.get('href', '')

    def handle_data(self, data):
        if self.in_h2 or self.in_td:
            self.current_text += data

    def handle_endtag(self, tag):
        if tag == 'h2':
            self.project = self.current_text.strip()
            self.in_h2 = False
        if tag == 'td':
            self.cells.append((self.current_text.strip(), self.current_link))
            self.in_td = False
        if tag == 'tr':
            if len(self.cells) >= 2 and self.project and self.cells[0][0] != 'Bug':
                self.rows.append({
                    'project': PROJECT_NORMALIZATION.get(self.project, self.project.lower()),
                    'project_display': self.project,
                    'bug_id': self.cells[0][0],
                    'patch_url': self.cells[0][1],
                    'identifier': self.cells[1][0],
                    'identifier_url': self.cells[1][1],
                })
            self.cells = []


def parse_bug_inventory(path: Path):
    parser = MagmaBugParser()
    parser.feed(path.read_text(encoding='utf-8'))
    rows = []
    for row in parser.rows:
        cve_id = row['identifier'] if CVSS_RE.match(row['identifier']) else ''
        rows.append({**row, 'cve_id': cve_id})
    return rows


def parse_legacy_preprint_inventory():
    rows = []
    reader = csv.DictReader(
        (line for line in LEGACY_PREPRINT_INVENTORY.strip().splitlines()),
        fieldnames=['project', 'bug_id', 'cve_id', 'bug_type', 'pov'],
    )
    for row in reader:
        cve_id = row['cve_id'] if CVSS_RE.match(row['cve_id'] or '') else ''
        rows.append({
            'project': row['project'],
            'project_display': row['project'],
            'bug_id': row['bug_id'],
            'patch_url': '',
            'identifier': cve_id,
            'identifier_url': '',
            'cve_id': cve_id,
            'bug_type': row['bug_type'],
            'pov': row['pov'],
            'inventory_source': 'magma-preprint-legacy-report-ids',
        })
    return rows


def fetch_nvd(cve_id: str):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    request = Request(url, headers={'User-Agent': 'StructRisk-CrashBacked/0.1'})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def best_cvss(payload):
    vulnerabilities = payload.get('vulnerabilities') or []
    if not vulnerabilities:
        return {'score': None, 'severity': '', 'vector': '', 'source': '', 'metric': ''}
    cve = vulnerabilities[0].get('cve') or {}
    metrics = cve.get('metrics') or {}
    for metric_name in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(metric_name) or []
        primary = [item for item in entries if str(item.get('type', '')).lower() == 'primary']
        for item in primary + [item for item in entries if item not in primary]:
            data = item.get('cvssData') or {}
            try:
                score = float(data.get('baseScore'))
            except (TypeError, ValueError):
                continue
            severity = data.get('baseSeverity') or item.get('baseSeverity') or ''
            return {
                'score': score,
                'severity': severity,
                'vector': data.get('vectorString') or '',
                'source': item.get('source') or '',
                'metric': metric_name,
            }
    return {'score': None, 'severity': '', 'vector': '', 'source': '', 'metric': ''}


def risk_level_from_severity(severity):
    severity = (severity or '').upper()
    if severity in {'CRITICAL', 'HIGH'}:
        return 3
    if severity == 'MEDIUM':
        return 2
    if severity == 'LOW':
        return 1
    return None


def load_cache(path: Path):
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


def save_cache(path: Path, cache):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2), encoding='utf-8')


def normalize_cached_cvss(cached):
    empty = {'score': None, 'severity': '', 'vector': '', 'source': '', 'metric': ''}
    if not isinstance(cached, dict):
        return empty
    if 'vulnerabilities' in cached:
        return best_cvss(cached)
    if any(key in cached for key in ('score', 'severity', 'vector', 'source', 'metric')):
        return {**empty, **cached}
    return empty


def enrich_cvss(rows, cache_path: Path, fetch: bool, sleep_secs: float, retry_errors: bool, fetch_bug_ids=None):
    cache = load_cache(cache_path)
    changed = False
    fetch_bug_ids = set(fetch_bug_ids or [])
    out = []
    for row in rows:
        cve_id = row.get('cve_id') or ''
        cvss = {'score': None, 'severity': '', 'vector': '', 'source': '', 'metric': ''}
        if cve_id:
            cached = cache.get(cve_id)
            needs_fetch = fetch and (not cached or (retry_errors and cached.get('error'))) and (not fetch_bug_ids or row['bug_id'] in fetch_bug_ids)
            if needs_fetch:
                try:
                    payload = fetch_nvd(cve_id)
                    cvss = best_cvss(payload)
                    cache[cve_id] = payload
                    changed = True
                    time.sleep(sleep_secs)
                except Exception as exc:
                    cache[cve_id] = {'score': None, 'severity': '', 'vector': '', 'source': '', 'metric': '', 'error': str(exc)}
                    changed = True
            else:
                cvss = normalize_cached_cvss(cached)
        score = cvss.get('score')
        severity = cvss.get('severity') or ''
        out.append({
            **row,
            'cvss_score': '' if score is None else score,
            'cvss_severity': severity,
            'cvss_vector': cvss.get('vector') or '',
            'risk_level': risk_level_from_severity(severity),
        })
    if changed:
        save_cache(cache_path, cache)
    return out


def ndcg_at_k(items, k):
    def dcg(sequence):
        total = 0.0
        for rank, item in enumerate(sequence[:k], start=1):
            relevance = int(item.get('risk_level') or 0)
            total += ((2 ** relevance) - 1) / math.log2(rank + 1)
        return total
    ideal = sorted(items, key=lambda item: int(item.get('risk_level') or 0), reverse=True)
    denominator = dcg(ideal)
    return 0.0 if denominator == 0.0 else dcg(items) / denominator


def evaluate_global(items):
    metrics = {}
    for cutoff in (5, 10, 20):
        metrics[f'HighRisk@{cutoff}'] = sum(1 for item in items[:cutoff] if int(item['risk_level']) >= 3)
        metrics[f'NDCG@{cutoff}'] = round(ndcg_at_k(items, cutoff), 4)
    first = None
    for rank, item in enumerate(items, start=1):
        if int(item['risk_level']) >= 3:
            first = rank
            break
    metrics['Rank-to-First-HighRisk'] = first
    return metrics


def group_by_project(items):
    grouped = defaultdict(list)
    for item in items:
        grouped[item['project']].append(item)
    return grouped


def average_precision(items):
    positives = 0
    total = 0.0
    for rank, item in enumerate(items, start=1):
        if int(item['risk_level']) >= 3:
            positives += 1
            total += positives / rank
    return 0.0 if positives == 0 else total / positives


def reciprocal_rank(items):
    for rank, item in enumerate(items, start=1):
        if int(item['risk_level']) >= 3:
            return 1.0 / rank
    return 0.0


def evaluate_within(items):
    rows = []
    for project, project_items in sorted(group_by_project(items).items()):
        positives = sum(1 for item in project_items if int(item['risk_level']) >= 3)
        if positives <= 0 or len(project_items) <= 1:
            continue
        ordered = sorted(project_items, key=lambda item: (-float(item['queue_score']), item['id']))
        rows.append({
            'project': project,
            'findings': len(project_items),
            'positives': positives,
            'HR@1': sum(1 for item in ordered[:1] if int(item['risk_level']) >= 3),
            'HR@3': sum(1 for item in ordered[:3] if int(item['risk_level']) >= 3),
            'NDCG@5': ndcg_at_k(ordered, 5),
            'MRR': reciprocal_rank(ordered),
            'MAP': average_precision(ordered),
        })
    if not rows:
        return {}, []
    macro = {key: sum(row[key] for row in rows) / len(rows) for key in ('HR@1', 'HR@3', 'NDCG@5', 'MRR', 'MAP')}
    macro['projects'] = len(rows)
    return macro, rows
