#!/usr/bin/env python3
"""Signal-constant perturbation audit for StructRisk.

Complements the theta-level audit in phase1_weight_sensitivity.py by perturbing
the hand-set constants of the signal-extraction rules themselves, one level
below the scorer weights:

  A) Base-rule constants (replay / locality / sanitizer / weak). Each base rule
     is a clamped sum of hand-set increments, so scaling every increment of one
     rule by s is algebraically identical to scaling the shipped signal value by
     s and re-clamping. We perturb each rule at s in {0.8, 1.2} one-at-a-time,
     plus all 16 four-rule corners.
  B) Derived-rule constants, recomputed exactly from shipped metadata:
     EvidenceUniq mixture weights (0.45/0.35/0.20), FailureSem base and
     increments, the weak-gate slope (1.2) and floor (0.2), and the
     support-stability bonus (0.5) and thresholds (support >= 20, weak <= 0.10).
     One-at-a-time at x0.8 / x1.2.

Theta stays at the shipped fixed prior throughout; no variant is selected.
Global metrics use the deterministic held-out ordering (as in structrisk_rank);
within-project metrics use the tie-aware expected metrics of
phase1_within_project_eval over the ten positive multi-finding projects.

Usage:
  python3 StructRisk/scripts/phase1_signal_constant_sensitivity.py
Outputs:
  StructRisk/generated/phase1_signal_constant_sensitivity.{json,md}
"""
import json
import math
import re
import sys
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'
sys.path.insert(0, str(STRUCTRISK / 'scripts'))

from structrisk_rank import (  # noqa: E402
    DEFAULT_WEIGHTS, MEMORY_STRONG_RE, WEAK_RE,
    clamp, exact_report, list_len, location_key, metadata, support_count,
)
from phase1_within_project_eval import evaluate_project  # noqa: E402

EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
WITHIN_DEFAULT = GENERATED / 'phase1_within10_eval.jsonl'
JSON_OUT = GENERATED / 'phase1_signal_constant_sensitivity.json'
MD_OUT = GENERATED / 'phase1_signal_constant_sensitivity.md'

BASE_RULES = ('replay', 'locality', 'sanitizer', 'weak')
DERIVED_CONSTANTS = {
    'eu_support': 0.45, 'eu_site': 0.35, 'eu_spread': 0.20,
    'fs_base': 0.20, 'fs_strong': 0.50, 'fs_deadly': 0.30, 'fs_site': 0.20,
    'fs_exact': 0.10, 'fs_exit': 0.05, 'fs_assert': -0.10, 'fs_weakpat': -0.10,
    'fs_san': 0.15,
    'gate_slope': 1.2, 'gate_floor': 0.2,
    'ss_bonus': 0.5, 'ss_min_count': 20.0, 'ss_weak_max': 0.10,
}
SCALES = (0.8, 1.2)


def load_rows(path):
    rows = []
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def project_stats(items):
    grouped = defaultdict(list)
    for item in items:
        grouped[item.get('project', 'unknown')].append(item)
    stats = {}
    for project, project_items in grouped.items():
        stats[project] = {
            'max_support': max(support_count(item) for item in project_items),
            'loc_counts': Counter(location_key(item) for item in project_items if location_key(item)),
        }
    return stats


def score_items(items, base_scales, consts):
    """Score items under perturbed constants; theta stays at DEFAULT_WEIGHTS."""
    stats = project_stats(items)
    scored = []
    for item in items:
        raw = item.get('signals') or {}
        base = {
            'replay': clamp(float(raw.get('replay', 0.0)) * base_scales.get('replay', 1.0)),
            'locality': clamp(float(raw.get('locality', 0.0)) * base_scales.get('locality', 1.0)),
            'sanitizer': clamp(float(raw.get('sanitizer', 0.0)) * base_scales.get('sanitizer', 1.0)),
            'weak': max(0.02, min(0.95, float(raw.get('weak', 0.0)) * base_scales.get('weak', 1.0))),
        }
        meta = metadata(item)
        pstat = stats[item.get('project', 'unknown')]
        max_support = max(1, pstat['max_support'])
        count = support_count(item)
        support_log = math.log1p(count) / math.log1p(max_support) if max_support > 1 else 0.0
        key = location_key(item)
        shared = pstat['loc_counts'].get(key, 1) if key else 4
        location_unique = 1.0 / math.sqrt(max(1, shared))
        campaign_count = max(list_len(meta.get('campaigns')), list_len(meta.get('aligned_targets')), 1)
        target_spread = min(1.0, math.log1p(campaign_count) / math.log1p(4))
        eu = clamp(consts['eu_support'] * support_log
                   + consts['eu_site'] * location_unique
                   + consts['eu_spread'] * target_spread)

        text = ' '.join(str(meta.get(k) or '') for k in (
            'matched_summary_line', 'matched_asan_type', 'matched_assertion', 'signature', 'matched_project_loc'))
        has_site = bool(str(meta.get('matched_project_loc') or '').strip())
        fs = consts['fs_base']
        if MEMORY_STRONG_RE.search(text):
            fs += consts['fs_strong']
        elif 'deadlysignal' in text.lower() and has_site:
            fs += consts['fs_deadly']
        elif has_site:
            fs += consts['fs_site']
        if exact_report(item):
            fs += consts['fs_exact']
        exit_code = str(meta.get('matched_exit_code') or '')
        if exit_code and exit_code not in {'0', 'None', 'none'}:
            fs += consts['fs_exit']
        if str(meta.get('matched_assertion') or '').strip():
            fs += consts['fs_assert']
        if WEAK_RE.search(text) and not MEMORY_STRONG_RE.search(text):
            fs += consts['fs_weakpat']
        fs += consts['fs_san'] * base['sanitizer']
        fs = clamp(fs)

        gate = min(1.0, max(consts['gate_floor'], consts['gate_slope'] * (1.0 - base['weak'])))
        stability = 0.0
        if (exact_report(item) and count >= consts['ss_min_count']
                and base['weak'] <= consts['ss_weak_max'] and max_support > 1):
            stability = clamp(math.log1p(count) / math.log1p(max_support))

        score = (DEFAULT_WEIGHTS['replay'] * base['replay']
                 + DEFAULT_WEIGHTS['locality'] * base['locality']
                 + DEFAULT_WEIGHTS['evidence_uniqueness_gated'] * eu * gate
                 + DEFAULT_WEIGHTS['failure_semantics_gated'] * fs * gate
                 + DEFAULT_WEIGHTS['sanitizer'] * base['sanitizer']
                 + DEFAULT_WEIGHTS['weak'] * base['weak']
                 + consts['ss_bonus'] * stability)
        merged = dict(item)
        merged['structrisk_score'] = round(score, 4)
        merged['queue_score'] = round(score, 4)
        scored.append(merged)
    scored.sort(key=lambda it: (-it['queue_score'], -it['structrisk_score'], it.get('project', ''), it['id']))
    return scored


def ndcg_at(items, k):
    def dcg(seq):
        return sum(((2 ** int(x.get('risk_level') or 0)) - 1) / math.log2(i + 1)
                   for i, x in enumerate(seq[:k], 1))
    ideal = sorted(items, key=lambda x: int(x.get('risk_level') or 0), reverse=True)
    denom = dcg(ideal)
    return 0.0 if denom == 0.0 else dcg(items) / denom


def hr_at(items, k):
    return sum(1 for x in items[:k] if int(x.get('risk_level') or 0) >= 3)


def within_macro(scored):
    by_project = defaultdict(list)
    for item in scored:
        by_project[item['project']].append(item)
    ndcg5, map_ = [], []
    for project, items in by_project.items():
        if not any(int(x.get('risk_level') or 0) >= 3 for x in items):
            continue
        metrics = evaluate_project(items)
        ndcg5.append(metrics['NDCG@5'])
        map_.append(metrics['MAP'])
    return (round(sum(ndcg5) / len(ndcg5), 4), round(sum(map_) / len(map_), 4))


def run_variant(label, base_scales, consts, eval_rows, within_rows):
    ranked = score_items(eval_rows, base_scales, consts)
    wp = score_items(within_rows, base_scales, consts)
    wp_ndcg5, wp_map = within_macro(wp)
    return {
        'variant': label,
        'global_NDCG@10': round(ndcg_at(ranked, 10), 4),
        'global_HR@10': hr_at(ranked, 10),
        'global_HR@5': hr_at(ranked, 5),
        'wp_NDCG@5': wp_ndcg5,
        'wp_MAP': wp_map,
    }


def variants():
    for rule in BASE_RULES:
        for scale in SCALES:
            yield f'rule_{rule}_x{int(scale * 100)}', {rule: scale}, dict(DERIVED_CONSTANTS)
    for combo in product(SCALES, repeat=len(BASE_RULES)):
        label = 'corner_' + ''.join('L' if s == 0.8 else 'H' for s in combo)
        yield label, dict(zip(BASE_RULES, combo)), dict(DERIVED_CONSTANTS)
    for name, default in DERIVED_CONSTANTS.items():
        for scale in SCALES:
            consts = dict(DERIVED_CONSTANTS)
            consts[name] = default * scale
            yield f'const_{name}_x{int(scale * 100)}', {}, consts


def main():
    eval_rows = load_rows(EVAL_DEFAULT)
    within_rows = load_rows(WITHIN_DEFAULT)
    rows = [run_variant('base', {}, dict(DERIVED_CONSTANTS), eval_rows, within_rows)]
    for label, base_scales, consts in variants():
        rows.append(run_variant(label, base_scales, consts, eval_rows, within_rows))

    base_row = rows[0]
    variant_rows = rows[1:]
    envelope = {}
    for key in ('global_NDCG@10', 'global_HR@10', 'global_HR@5', 'wp_NDCG@5', 'wp_MAP'):
        values = [r[key] for r in variant_rows]
        envelope[key] = {'base': base_row[key], 'min': min(values), 'max': max(values)}

    payload = {
        'description': ('Structure-preserving +/-20% perturbation of every hand-set '
                        'signal-extraction constant, with theta fixed at the shipped prior. '
                        'No variant is selected; this reports stability envelopes only.'),
        'theta': DEFAULT_WEIGHTS,
        'base_rule_scales': list(SCALES),
        'derived_constants': DERIVED_CONSTANTS,
        'variant_count': len(variant_rows),
        'envelope': envelope,
        'rows': rows,
    }
    JSON_OUT.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    lines = [
        '# Signal-Constant Perturbation Audit',
        '',
        ('This audit complements the theta-level perturbation study: it perturbs every '
         'hand-set constant of the signal-extraction rules by +/-20% (base rules '
         'one-at-a-time and at all 16 corners; every derived-rule constant '
         'one-at-a-time), with theta fixed at the shipped prior. No variant is '
         'selected against any label.'),
        '',
        f'- Variants: `{len(variant_rows)}` (+ base)',
        '- Global metrics: deterministic held-out ordering (78 findings).',
        '- Within-project metrics: tie-aware expected metrics over the ten positive multi-finding projects.',
        '',
        '## Envelope',
        '',
        '| Metric | Base | Min | Max |',
        '| --- | ---: | ---: | ---: |',
    ]
    for key, env in envelope.items():
        lines.append(f"| {key} | {env['base']} | {env['min']} | {env['max']} |")
    lines += ['', '## Variants', '', '| Variant | global NDCG@10 | global HR@10 | global HR@5 | wp NDCG@5 | wp MAP |',
              '| --- | ---: | ---: | ---: | ---: | ---: |']
    for row in rows:
        lines.append(f"| {row['variant']} | {row['global_NDCG@10']} | {row['global_HR@10']} | "
                     f"{row['global_HR@5']} | {row['wp_NDCG@5']} | {row['wp_MAP']} |")
    MD_OUT.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    print(JSON_OUT)
    print(MD_OUT)
    print(json.dumps({'base': base_row, 'envelope': envelope}, indent=2))


if __name__ == '__main__':
    main()
