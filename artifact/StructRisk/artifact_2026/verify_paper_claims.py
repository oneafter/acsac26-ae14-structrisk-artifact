#!/usr/bin/env python3
"""Recompute reviewer-facing StructRisk results without mutating canonical files."""

import argparse
import csv
import json
import math
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
STRUCTRISK = SCRIPT_DIR.parent
SCRIPTS = STRUCTRISK / 'scripts'
GENERATED = STRUCTRISK / 'generated'
CLAIMS_PATH = SCRIPT_DIR / 'PAPER_CLAIMS.json'


class VerificationError(RuntimeError):
    pass


def load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def metric_payload(path: Path):
    payload = load_json(path)
    return payload.get('metrics', payload)


def rounded_equal(actual, expected):
    if isinstance(expected, bool):
        return actual is expected
    if isinstance(expected, int) and not isinstance(expected, bool):
        return int(actual) == expected
    if isinstance(expected, float):
        return math.isclose(round(float(actual), 4), round(expected, 4), abs_tol=0.00005)
    return actual == expected


class Verifier:
    def __init__(self, claims, temp_root: Path, output_dir: Path, bootstrap_rounds: int, full_statistics: bool):
        self.claims = claims
        self.temp_root = temp_root
        self.output_dir = output_dir
        self.bootstrap_rounds = bootstrap_rounds
        self.full_statistics = full_statistics
        self.checks = []
        self.commands = []

    def run_script(self, script_name, *args):
        command = [sys.executable, str(SCRIPTS / script_name), *[str(arg) for arg in args]]
        started = time.monotonic()
        result = subprocess.run(
            command,
            cwd=str(STRUCTRISK.parent),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        elapsed = round(time.monotonic() - started, 3)
        self.commands.append({
            'script': script_name,
            'elapsed_seconds': elapsed,
            'returncode': result.returncode,
        })
        if result.returncode != 0:
            tail = '\n'.join((result.stdout + '\n' + result.stderr).splitlines()[-30:])
            raise VerificationError(f'{script_name} failed with exit code {result.returncode}:\n{tail}')
        return result

    def check(self, section, name, actual, expected, source='recomputed'):
        passed = rounded_equal(actual, expected)
        self.checks.append({
            'section': section,
            'name': name,
            'expected': expected,
            'actual': actual,
            'source': source,
            'passed': passed,
        })
        return passed

    def check_mapping(self, section, method, actual, expected, source='recomputed'):
        for key, expected_value in expected.items():
            if key not in actual:
                self.checks.append({
                    'section': section,
                    'name': f'{method}.{key}',
                    'expected': expected_value,
                    'actual': '<missing>',
                    'source': source,
                    'passed': False,
                })
                continue
            self.check(section, f'{method}.{key}', actual[key], expected_value, source=source)

    def verify_dataset(self):
        expected = self.claims['dataset']
        archive_rows = list(csv.DictReader((STRUCTRISK / 'user75_cve_summary.csv').open(encoding='utf-8')))
        artifact_rows = load_jsonl(GENERATED / 'phase1_artifact_index.jsonl')
        full_rows = load_jsonl(GENERATED / 'phase1_offline_full_findings.jsonl')
        dev_rows = load_jsonl(GENERATED / 'phase1_offline_dev.jsonl')
        eval_rows = load_jsonl(GENERATED / 'phase1_offline_eval.jsonl')
        within_rows = load_jsonl(GENERATED / 'phase1_within10_eval.jsonl')

        actual = {
            'archive_cves': len(archive_rows),
            'archive_high_cves': sum(1 for row in archive_rows if (row.get('cvss31_severity') or '').upper() == 'HIGH'),
            'raw_artifacts': len(artifact_rows),
            'findings': len(full_rows),
            'dev_findings': len(dev_rows),
            'eval_findings': len(eval_rows),
            'eval_projects': len({row['project'] for row in eval_rows}),
            'eval_positives': sum(1 for row in eval_rows if int(row.get('risk_level') or 0) >= 3),
            'within_findings': len(within_rows),
            'within_projects': len({row['project'] for row in within_rows}),
            'within_positives': sum(1 for row in within_rows if int(row.get('risk_level') or 0) >= 3),
        }
        self.check_mapping('dataset', 'dataset', actual, expected, source='counted from shipped records')

    def verify_global(self):
        section = 'table3_global'
        out = self.temp_root / 'global'
        out.mkdir(parents=True, exist_ok=True)
        eval_path = GENERATED / 'phase1_offline_eval.jsonl'
        dev_path = GENERATED / 'phase1_offline_dev.jsonl'

        public_ranked = out / 'public_ranked.jsonl'
        public_metrics = out / 'public_metrics.json'
        self.run_script(
            'phase1_public_baseline.py',
            '--eval', eval_path,
            '--cvss', STRUCTRISK / 'user75_cve_summary.csv',
            '--output', public_ranked,
            '--metrics-out', public_metrics,
        )

        artifact_ranked = out / 'artifact_ranked.jsonl'
        artifact_metrics = out / 'artifact_metrics.json'
        self.run_script(
            'phase1_artifact_baseline.py',
            '--eval', eval_path,
            '--output', artifact_ranked,
            '--metrics-out', artifact_metrics,
            '--summary-out', out / 'artifact_summary.md',
        )

        crash_prefix = out / 'crash'
        self.run_script('phase1_crash_baselines.py', '--eval', eval_path, '--out-prefix', crash_prefix)
        asan_ranked = out / 'crash_asan_ranked.jsonl'
        crashstate_ranked = out / 'crash_crashstate_ranked.jsonl'

        report_ranked = out / 'reportknn_ranked.jsonl'
        report_metrics = out / 'reportknn_metrics.json'
        self.run_script(
            'phase1_report_knn_baseline.py',
            '--dev', dev_path,
            '--eval', eval_path,
            '--output', report_ranked,
            '--metrics-out', report_metrics,
            '--summary-out', out / 'reportknn_summary.md',
            '--k', '5',
        )

        support_ranked = out / 'support_ranked.jsonl'
        support_metrics = out / 'support_metrics.json'
        self.run_script(
            'phase1_support_count_baseline.py',
            '--eval', eval_path,
            '--output', support_ranked,
            '--metrics-out', support_metrics,
            '--summary-out', out / 'support_summary.md',
        )

        manual_ranked = out / 'structrisk_ranked.jsonl'
        manual_metrics = out / 'structrisk_metrics.json'
        self.run_script(
            'structrisk_rank.py',
            '--mode', 'manual',
            '--input', eval_path,
            '--output', manual_ranked,
            '--weights-out', out / 'structrisk_weights.json',
            '--metrics-out', manual_metrics,
        )

        llm_ranked = out / 'llm_card_ranked.jsonl'
        llm_metrics = out / 'llm_card_metrics.json'
        self.run_script(
            'phase1_llm_card_baseline.py',
            '--mode', 'responses',
            '--eval', eval_path,
            '--prompts-out', out / 'llm_prompts.jsonl',
            '--manifest-out', out / 'llm_manifest.jsonl',
            '--responses', GENERATED / 'phase1_llm_card_responses_clean.jsonl',
            '--ranked-out', llm_ranked,
            '--metrics-out', llm_metrics,
            '--summary-out', out / 'llm_card_summary.md',
        )

        lcr_ranked = out / 'lcr_ranked.jsonl'
        self.run_script(
            'phase1_local_tie_resolution.py',
            '--base', manual_ranked,
            '--llm-card', llm_ranked,
            '--output', lcr_ranked,
            '--metrics-out', out / 'lcr_metrics.json',
            '--summary-out', out / 'lcr_summary.md',
        )

        casr_ranked = GENERATED / 'phase1_offline_casr_ranked.jsonl'
        actual = {
            'Public-Severity': metric_payload(public_metrics),
            'Support-Count': metric_payload(support_metrics),
            'Artifact-Completeness': metric_payload(artifact_metrics),
            'ASan-Severity': metric_payload(out / 'crash_asan_metrics.json'),
            'Crash-State': metric_payload(out / 'crash_crashstate_metrics.json'),
            'StackDedup-kNN': metric_payload(report_metrics),
            'CASR-Severity': metric_payload(GENERATED / 'phase1_offline_casr_metrics.json'),
            'LLM-CardScore': metric_payload(llm_metrics),
            'StructRisk': metric_payload(manual_metrics),
        }
        for method, expected in self.claims['tables'][section].items():
            source = 'cached CASR ranking/report' if method == 'CASR-Severity' else 'recomputed'
            self.check_mapping(section, method, actual[method], expected, source=source)

        significance_out = GENERATED / 'phase1_offline_significance.json'
        significance_source = 'canonical exact-permutation output'
        if self.full_statistics:
            significance_out = out / 'significance.json'
            self.run_script(
                'phase1_significance.py',
                '--public', public_ranked,
                '--artifact', artifact_ranked,
                '--support', support_ranked,
                '--asan', asan_ranked,
                '--crashstate', crashstate_ranked,
                '--reportknn', report_ranked,
                '--casr', casr_ranked,
                '--llm-card', llm_ranked,
                '--manual', manual_ranked,
                '--lcr', lcr_ranked,
                '--bootstrap-rounds', str(self.bootstrap_rounds),
                '--seed', '1337',
                '--json-out', significance_out,
                '--md-out', out / 'significance.md',
            )
            significance_source = 'recomputed exact permutation and bootstrap'
        sig = load_json(significance_out)['permutation']['StructRisk vs ASan-Severity']
        expected_stats = self.claims['statistics']
        self.check('statistics', 'global StructRisk vs ASan HR@5 p', sig['HighRisk@5']['exact_two_sided_p'], expected_stats['global_structrisk_vs_asan_hr5_p'], significance_source)
        self.check('statistics', 'global StructRisk vs ASan HR@10 p', sig['HighRisk@10']['exact_two_sided_p'], expected_stats['global_structrisk_vs_asan_hr10_p'], significance_source)
        self.check('statistics', 'global StructRisk vs ASan NDCG@10 p', sig['NDCG@10']['exact_two_sided_p'], expected_stats['global_structrisk_vs_asan_ndcg10_p'], significance_source)
        self.check('statistics', 'global StructRisk vs ASan NDCG@10 diff', sig['NDCG@10']['observed_diff'], expected_stats['global_structrisk_vs_asan_ndcg10_diff'], significance_source)

    def within_method_specs(self, lcr_ranked):
        return {
            'Public-Severity': GENERATED / 'phase1_within10_public_severity_ranked.jsonl',
            'Support-Count': GENERATED / 'phase1_within10_support_count_ranked.jsonl',
            'Artifact-Completeness': GENERATED / 'phase1_within10_artifact_ranked.jsonl',
            'ASan-Severity': GENERATED / 'phase1_within10_asan_ranked.jsonl',
            'Crash-State': GENERATED / 'phase1_within10_crashstate_ranked.jsonl',
            'StackDedup-kNN': GENERATED / 'phase1_within10_reportknn_ranked.jsonl',
            'CASR-Severity': GENERATED / 'phase1_within10_casr_ranked.jsonl',
            'LLM-CardScore': GENERATED / 'phase1_within10_llm_card_ranked.jsonl',
            'StructRisk': GENERATED / 'phase1_within10_manual_ranked.jsonl',
            'StructRisk+LLM-LCR': lcr_ranked,
        }

    def run_within_metrics(self, out, method_specs, projects=()):
        args = []
        for method, path in method_specs.items():
            args.extend(['--method', f'{method}={path}'])
        for project in projects:
            args.extend(['--project', project])
        args.extend([
            '--json-out', out / 'metrics.json',
            '--csv-out', out / 'metrics.csv',
            '--md-out', out / 'metrics.md',
        ])
        self.run_script('phase1_within_project_eval.py', *args)
        return load_json(out / 'metrics.json')

    def run_within_significance(self, out, lcr_ranked, projects=(), target=None, methods=None):
        if methods is not None:
            args = []
            for name, path in methods.items():
                args.extend(['--method', f'{name}={path}'])
            args.extend([
                '--bootstrap-rounds', str(min(self.bootstrap_rounds, 1000)),
                '--seed', '1337',
                '--json-out', out / 'significance.json',
                '--md-out', out / 'significance.md',
            ])
            if target is not None:
                args.extend(['--target', target])
            for project in projects:
                args.extend(['--project', project])
            self.run_script('phase1_within_project_significance.py', *args)
            return load_json(out / 'significance.json')
        args = [
            '--public', GENERATED / 'phase1_within10_public_severity_ranked.jsonl',
            '--asan', GENERATED / 'phase1_within10_asan_ranked.jsonl',
            '--crashstate', GENERATED / 'phase1_within10_crashstate_ranked.jsonl',
            '--llm-card', GENERATED / 'phase1_within10_llm_card_ranked.jsonl',
            '--lcr', lcr_ranked,
            '--bootstrap-rounds', str(min(self.bootstrap_rounds, 1000)),
            '--seed', '1337',
            '--json-out', out / 'significance.json',
            '--md-out', out / 'significance.md',
        ]
        if target is not None:
            args.extend(['--target', target])
        for project in projects:
            args.extend(['--project', project])
        self.run_script('phase1_within_project_significance.py', *args)
        return load_json(out / 'significance.json')

    def verify_within(self):
        section = 'table4_within_project'
        out = self.temp_root / 'within'
        out.mkdir(parents=True, exist_ok=True)
        lcr_ranked = out / 'lcr_ranked.jsonl'
        self.run_script(
            'phase1_local_tie_resolution.py',
            '--base', GENERATED / 'phase1_within10_manual_ranked.jsonl',
            '--llm-card', GENERATED / 'phase1_within10_llm_card_ranked.jsonl',
            '--output', lcr_ranked,
            '--metrics-out', out / 'lcr_metrics.json',
            '--summary-out', out / 'lcr_summary.md',
        )
        method_specs = self.within_method_specs(lcr_ranked)
        metrics = self.run_within_metrics(out, method_specs)
        rows = {
            row['method']: row
            for row in metrics['macro']
            if row['scope'] == 'multi-finding-projects'
        }
        for method, expected in self.claims['tables'][section].items():
            source = 'metrics recomputed from shipped method ranking'
            if method == 'StructRisk+LLM-LCR':
                source = 'ranking and metrics recomputed from shipped card scores'
            self.check_mapping(section, method, rows[method], expected, source=source)

        sig = self.run_within_significance(out, lcr_ranked)
        comparison = sig['permutation']['StructRisk+LLM-LCR vs Public-Severity']
        expected_stats = self.claims['statistics']
        self.check('statistics', 'within LCR vs Public NDCG@5 p', comparison['NDCG@5']['exact_two_sided_p'], expected_stats['within_lcr_vs_public_ndcg5_p'])
        self.check('statistics', 'within LCR vs Public MAP p', comparison['MAP']['exact_two_sided_p'], expected_stats['within_lcr_vs_public_map_p'])

        core_out = out / 'core_target'
        core_out.mkdir(parents=True, exist_ok=True)
        core_methods = {
            'Public-Severity': GENERATED / 'phase1_within10_public_severity_ranked.jsonl',
            'ASan-Severity': GENERATED / 'phase1_within10_asan_ranked.jsonl',
            'Crash-State': GENERATED / 'phase1_within10_crashstate_ranked.jsonl',
            'LLM-CardScore': GENERATED / 'phase1_within10_llm_card_ranked.jsonl',
            'StructRisk': GENERATED / 'phase1_within10_manual_ranked.jsonl',
        }
        core_sig = self.run_within_significance(core_out, lcr_ranked, target='StructRisk', methods=core_methods)
        core_cmp = core_sig['permutation']['StructRisk vs Public-Severity']
        self.check('statistics', 'within core vs Public NDCG@5 p', core_cmp['NDCG@5']['exact_two_sided_p'], expected_stats['within_core_vs_public_ndcg5_p'])
        self.check('statistics', 'within core vs Public MAP p', core_cmp['MAP']['exact_two_sided_p'], expected_stats['within_core_vs_public_map_p'])

        eval_projects = ('binaryen', 'openbabel', 'squirrel', 'wabt', 'xlnt')
        eval_out = out / 'eval_only'
        eval_out.mkdir(parents=True, exist_ok=True)
        self.run_within_metrics(eval_out, method_specs, eval_projects)
        eval_sig = self.run_within_significance(eval_out, lcr_ranked, eval_projects)
        eval_comparison = eval_sig['permutation']['StructRisk+LLM-LCR vs Public-Severity']
        self.check('statistics', 'Eval-only LCR vs Public NDCG@5 p', eval_comparison['NDCG@5']['exact_two_sided_p'], expected_stats['eval_only_lcr_vs_public_ndcg5_p'])

    def verify_ablation(self):
        section = 'table5_ablation'
        out = self.temp_root / 'ablation'
        out.mkdir(parents=True, exist_ok=True)
        ablation_path = out / 'ablation.json'
        self.run_script(
            'phase1_ablation.py',
            '--eval', GENERATED / 'phase1_offline_eval.jsonl',
            '--within', GENERATED / 'phase1_within10_manual_ranked.jsonl',
            '--weights', GENERATED / 'phase1_offline_manual_weights.json',
            '--json-out', ablation_path,
            '--md-out', out / 'ablation.md',
        )
        rows = {row['name']: row for row in load_json(ablation_path)}
        for variant, expected in self.claims['tables'][section].items():
            actual = {
                'NDCG@10': rows[variant]['global']['NDCG@10'],
                'HighRisk@10': rows[variant]['global']['HighRisk@10'],
                'WP_NDCG@5': rows[variant]['within_project']['NDCG@5'],
                'WP_MAP': rows[variant]['within_project']['MAP'],
            }
            self.check_mapping(section, variant, actual, expected)

        sensitivity = load_json(GENERATED / 'phase1_weight_sensitivity.json')
        expected_sensitivity = self.claims['sensitivity']
        self.check('sensitivity', 'variant_count', sensitivity['variant_count'], expected_sensitivity['variant_count'], 'canonical 77-variant output')
        ranges = {
            'WP_core_NDCG@5_range': [sensitivity['envelopes']['within_project']['NDCG@5']['min'], sensitivity['envelopes']['within_project']['NDCG@5']['max']],
            'WP_core_MAP_range': [sensitivity['envelopes']['within_project']['MAP']['min'], sensitivity['envelopes']['within_project']['MAP']['max']],
            'WP_LCR_NDCG@5_range': [sensitivity['envelopes']['within_lcr_project']['NDCG@5']['min'], sensitivity['envelopes']['within_lcr_project']['NDCG@5']['max']],
            'WP_LCR_MAP_range': [sensitivity['envelopes']['within_lcr_project']['MAP']['min'], sensitivity['envelopes']['within_lcr_project']['MAP']['max']],
        }
        for name, expected_range in expected_sensitivity.items():
            if name == 'variant_count':
                continue
            actual_range = ranges[name]
            for index, label in enumerate(('min', 'max')):
                self.check('sensitivity', f'{name}.{label}', actual_range[index], expected_range[index], 'canonical 77-variant output')

    def verify_magma(self):
        section = 'table6_magma'
        out = self.temp_root / 'magma'
        generated_out = out / 'generated'
        generated_out.mkdir(parents=True, exist_ok=True)
        for source in GENERATED.glob('magma*'):
            if source.is_file():
                shutil.copy2(source, generated_out / source.name)

        prefix = generated_out / 'magma_unified_crash_backed_external'
        self.run_script(
            'magma_crash_backed_benchmark.py',
            '--train', GENERATED / 'phase1_offline_dev.jsonl',
            '--input', GENERATED / 'magma_unified_crash_backed_findings.jsonl',
            '--out-prefix', prefix,
            '--casr-ranked', GENERATED / 'magma_unified_crash_backed_external_casr_ranked.jsonl',
        )
        self.run_script(
            'magma_inventory_audit.py',
            '--bugs-html', STRUCTRISK / 'external' / 'magma' / 'bugs.html',
            '--nvd-cache', STRUCTRISK / 'external' / 'magma' / 'nvd_cache.json',
            '--generated-dir', generated_out,
        )
        metrics = load_json(generated_out / 'magma_unified_crash_backed_external_metrics.json')
        for method, expected in self.claims['tables'][section].items():
            self.check_mapping(section, method, metrics['global'][method], expected)

        expected_inventory = self.claims['magma_inventory']
        inventory = load_json(generated_out / 'magma_inventory_audit.json')
        actual_inventory = {
            'findings': metrics['findings'],
            'projects': metrics['projects'],
            'high_or_critical_positives': metrics['high_or_critical_positives'],
            'bug_records': inventory['full_inventory']['bug_records'],
            'distinct_cves': inventory['full_inventory']['distinct_cves'],
            'high_or_critical_cves': inventory['full_inventory']['high_or_critical_cves'],
        }
        self.check_mapping('magma_inventory', 'magma', actual_inventory, expected_inventory)

    def finish(self, claim, started):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        for child in self.temp_root.iterdir():
            destination = self.output_dir / child.name
            if child.is_dir():
                shutil.copytree(child, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(child, destination)

        failed = [check for check in self.checks if not check['passed']]
        report = {
            'artifact_version': (SCRIPT_DIR / 'ARTIFACT_VERSION.txt').read_text(encoding='utf-8').splitlines()[1].split(':', 1)[1].strip(),
            'paper_sha256': self.claims['paper']['sha256'],
            'claim_scope': claim,
            'full_statistics': self.full_statistics,
            'bootstrap_rounds': self.bootstrap_rounds if self.full_statistics else min(self.bootstrap_rounds, 1000),
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'checks_total': len(self.checks),
            'checks_passed': len(self.checks) - len(failed),
            'checks_failed': len(failed),
            'commands': self.commands,
            'checks': self.checks,
        }
        report_path = self.output_dir / 'verification_report.json'
        report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')

        section_counts = {}
        for check in self.checks:
            counts = section_counts.setdefault(check['section'], {'passed': 0, 'failed': 0})
            counts['passed' if check['passed'] else 'failed'] += 1
        for section, counts in sorted(section_counts.items()):
            status = 'PASS' if counts['failed'] == 0 else 'FAIL'
            print(f'{status}: {section} ({counts["passed"]} passed, {counts["failed"]} failed)')
        print(f'Report: {report_path}')
        if failed:
            for check in failed:
                print(f'FAIL: {check["section"]}.{check["name"]}: expected={check["expected"]!r} actual={check["actual"]!r}')
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description='Recompute StructRisk paper claims without changing canonical outputs')
    parser.add_argument('--claim', choices=['all', 'global', 'within', 'ablation', 'magma'], default='all')
    parser.add_argument('--output-dir', default=str(STRUCTRISK / 'reproduced' / 'paper_claims'))
    parser.add_argument('--full-statistics', action='store_true', help='recompute the global exact-permutation and bootstrap analysis')
    parser.add_argument('--bootstrap-rounds', type=int, default=20000)
    args = parser.parse_args()

    claims = load_json(CLAIMS_PATH)
    output_dir = Path(args.output_dir).resolve()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='structrisk_verify_') as temp_dir:
        verifier = Verifier(claims, Path(temp_dir), output_dir, args.bootstrap_rounds, args.full_statistics)
        if args.claim in {'all', 'global'}:
            verifier.verify_dataset()
            verifier.verify_global()
        if args.claim in {'all', 'within'}:
            verifier.verify_within()
        if args.claim in {'all', 'ablation'}:
            verifier.verify_ablation()
        if args.claim in {'all', 'magma'}:
            verifier.verify_magma()
        verifier.finish(args.claim, started)


if __name__ == '__main__':
    main()
