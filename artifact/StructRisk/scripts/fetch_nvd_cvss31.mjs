#!/usr/bin/env node
import fs from 'fs';
import https from 'https';

const inputPath = process.argv[2] || 'CVE2SKETCH/examples/user75_cves.tsv';
const outputPath = process.argv[3] || 'structrisk_nvd_cvss31.csv';
const sleepSecs = Number(process.env.SLEEP_SECS || '1');

function parseTsv(path) {
  const text = fs.readFileSync(path, 'utf8').trim();
  const lines = text.split(/\r?\n/);
  const header = lines[0].split('\t');
  return lines.slice(1).filter(Boolean).map((line) => {
    const cols = line.split('\t');
    const row = {};
    header.forEach((name, idx) => { row[name] = cols[idx] ?? ''; });
    return row;
  });
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`JSON parse failed for ${url}: ${err.message}`));
        }
      });
    }).on('error', reject);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function toRecord(row, payload) {
  const record = {
    index: row.index || '',
    project: row.project || '',
    vuln_type: row.vuln_type || '',
    cve_id: row.cve_id || '',
    vuln_status: '',
    nvd_cvss31: '',
    highest_cvss31: '',
    highest_cvss31_severity: '',
    highest_cvss31_source: '',
    highest_cvss31_type: '',
    highest_cvss31_vector: '',
  };

  const vulns = payload?.vulnerabilities || [];
  if (!vulns.length) return record;

  const cve = vulns[0]?.cve || {};
  record.vuln_status = cve.vulnStatus || '';
  const entries = cve?.metrics?.cvssMetricV31 || [];
  let best = null;
  for (const item of entries) {
    const cvss = item?.cvssData || {};
    const score = Number(cvss.baseScore);
    if (!Number.isFinite(score)) continue;
    if (item.source === 'nvd@nist.gov') record.nvd_cvss31 = score;
    const candidate = {
      score,
      severity: cvss.baseSeverity || '',
      source: item.source || '',
      type: item.type || '',
      vector: cvss.vectorString || '',
    };
    if (!best || candidate.score > best.score) best = candidate;
  }
  if (best) {
    record.highest_cvss31 = best.score;
    record.highest_cvss31_severity = best.severity;
    record.highest_cvss31_source = best.source;
    record.highest_cvss31_type = best.type;
    record.highest_cvss31_vector = best.vector;
  }
  return record;
}

async function main() {
  const rows = parseTsv(inputPath);
  const header = [
    'index','project','vuln_type','cve_id','vuln_status','nvd_cvss31','highest_cvss31',
    'highest_cvss31_severity','highest_cvss31_source','highest_cvss31_type','highest_cvss31_vector'
  ];
  fs.writeFileSync(outputPath, header.join(',') + '\n');

  for (const row of rows) {
    if (!row.cve_id) continue;
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(row.cve_id)}`;
    try {
      const payload = await fetchJson(url);
      const record = toRecord(row, payload);
      fs.appendFileSync(outputPath, header.map((k) => csvEscape(record[k])).join(',') + '\n');
      console.log(`fetched ${row.cve_id}`);
    } catch (err) {
      fs.appendFileSync(outputPath, header.map((k) => csvEscape(({
        index: row.index || '', project: row.project || '', vuln_type: row.vuln_type || '', cve_id: row.cve_id || ''
      })[k])).join(',') + '\n');
      console.error(`failed ${row.cve_id}: ${err.message}`);
    }
    if (sleepSecs > 0) await sleep(sleepSecs * 1000);
  }
  console.log(`Wrote ${outputPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
