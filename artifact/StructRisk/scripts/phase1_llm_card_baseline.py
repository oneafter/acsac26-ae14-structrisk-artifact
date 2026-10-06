#!/usr/bin/env python3
import argparse
import json
import math
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
GENERATED = STRUCTRISK / 'generated'

EVAL_DEFAULT = GENERATED / 'phase1_offline_eval.jsonl'
PROMPTS_DEFAULT = GENERATED / 'phase1_llm_card_prompts.jsonl'
MANIFEST_DEFAULT = GENERATED / 'phase1_llm_card_manifest.jsonl'
RESPONSES_DEFAULT = GENERATED / 'phase1_llm_card_responses.jsonl'
RANKED_DEFAULT = GENERATED / 'phase1_offline_llm_card_ranked.jsonl'
METRICS_DEFAULT = GENERATED / 'phase1_offline_llm_card_metrics.json'
SUMMARY_DEFAULT = GENERATED / 'phase1_offline_llm_card_summary.md'

FORBIDDEN_KEYS = {
    'risk_level',
    'aligned_high_cve_ids',
    'label_source',
    'evidence_proxy_level',
    'matched_cve_id',
    'cve_id',
    'cvss',
    'cvss31',
    'nvd',
    'severity',
    'disclosure',
    'disclose',
}

FORBIDDEN_TEXT = re.compile(r'\b(CVE-\d{4}-\d+|CVSS|NVD|CRITICAL|HIGH|MEDIUM|LOW|exploit-db)\b')
ABSOLUTE_SRC = re.compile(r'/src/[^\s:]+/')
HEX_ADDRESS = re.compile(r'0x[0-9a-fA-F]+')
PID_PREFIX = re.compile(r'==\d+==')

SYSTEM_INSTRUCTION = (
    'Use only the anonymized crash-side evidence in this prompt. Do not use external knowledge, '
    'public vulnerability records, advisories, issue trackers, commits, patches, publication status, '
    'or any ground-truth outcome. Score analyst review priority from local evidence only. Return only valid JSON.'
)


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def redact_project_text(value, project):
    if value is None:
        return ''
    text = str(value)
    project_text = str(project or '')
    if project_text:
        text = re.sub(re.escape(project_text), '<PROJECT>', text, flags=re.IGNORECASE)
    text = ABSOLUTE_SRC.sub('<SRC>/', text)
    text = HEX_ADDRESS.sub('<ADDR>', text)
    text = PID_PREFIX.sub('==PID==', text)
    text = FORBIDDEN_TEXT.sub('[redacted]', text)
    return text.strip()


def basename_location(location, project):
    text = redact_project_text(location, project)
    if not text:
        return ''
    parts = text.split('/')
    return parts[-1] if parts else text


def bucket_count(value):
    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return 'none'
    if count == 1:
        return 'one'
    if count <= 3:
        return 'few'
    if count <= 10:
        return 'several'
    if count <= 50:
        return 'many'
    return 'very_many'


def safe_item(item, opaque_id):
    metadata = item.get('metadata', {})
    project = item.get('project') or ''
    asan_type = redact_project_text(metadata.get('matched_asan_type'), project)
    summary_line = redact_project_text(metadata.get('matched_summary_line'), project)
    assertion = redact_project_text(metadata.get('matched_assertion'), project)
    location = basename_location(metadata.get('matched_project_loc'), project)
    support_bucket = bucket_count(metadata.get('support_count'))
    campaigns = metadata.get('campaigns') or []
    sample_crashes = metadata.get('sample_crashes') or []
    report_match = redact_project_text(metadata.get('report_match_level'), project)
    exit_code = redact_project_text(metadata.get('matched_exit_code'), project)
    safe = {
        'opaque_id': opaque_id,
        'report_match_level': report_match or 'none',
        'sanitizer_or_signal': asan_type or 'none',
        'summary_excerpt': summary_line[:220],
        'source_location_basename': location,
        'assertion_excerpt': assertion[:260],
        'exit_observation': exit_code or 'none',
        'support_bucket': support_bucket,
        'campaign_count': len(campaigns),
        'sample_crash_count': len(sample_crashes),
        'cmdline_present': bool((metadata.get('cmdline_file') or '').strip()),
    }
    serialized = json.dumps(safe, ensure_ascii=False)
    if FORBIDDEN_TEXT.search(serialized):
        raise ValueError(f'forbidden token in prompt item {opaque_id}')
    return safe


def build_prompt(item, opaque_id):
    safe = safe_item(item, opaque_id)
    payload = {
        'system_instruction': SYSTEM_INSTRUCTION,
        'task': 'Assign an analyst review priority score from anonymized local crash evidence only.',
        'allowed_output_schema': {
            'priority_score': 'number in [0,10]',
            'confidence': 'number in [0,1]',
            'memory_safety_signal': 'integer in {0,1,2}',
            'locality_signal': 'integer in {0,1,2}',
            'reproducibility_signal': 'integer in {0,1,2}',
            'input_surface_signal': 'integer in {0,1,2}',
            'evidence_completeness': 'integer in {0,1,2}',
            'grounded_terms': ['terms copied exactly from the prompt evidence'],
            'short_reason': ['at most three evidence-grounded reasons'],
        },
        'evidence': safe,
        'decision_rules': [
            'Give higher scores to precise memory-safety faults, exact localized reports, strong reproducibility/support, and concrete internal invariant failures.',
            'Give lower scores to sparse artifacts, missing sanitizer or location evidence, generic assertions, and project-only report matches.',
            'Do not use external records, project reputation, public labels, publication status, or known vulnerability facts.',
        ],
    }
    prompt = json.dumps(payload, ensure_ascii=False, indent=2)
    if FORBIDDEN_TEXT.search(prompt):
        raise ValueError(f'forbidden token in prompt {opaque_id}')
    return prompt


def emit_prompts(items, prompts_path, manifest_path):
    prompt_rows = []
    manifest_rows = []
    for index, item in enumerate(items, start=1):
        opaque_id = f'card{index:03d}'
        prompt_rows.append({'id': opaque_id, 'prompt': build_prompt(item, opaque_id)})
        manifest_rows.append({'id': opaque_id, 'finding_id': item.get('id')})
    write_jsonl(prompts_path, prompt_rows)
    write_jsonl(manifest_path, manifest_rows)
    return prompt_rows, manifest_rows


def parse_response(raw):
    if isinstance(raw, dict):
        return raw
    text = str(raw).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find('{')
        end = text.rfind('}')
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


def clamp_float(value, low, high, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def clamp_int(value, allowed, default=0):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number in allowed else default


def read_responses(path: Path):
    responses = {}
    if not path.exists():
        return responses
    for row in load_jsonl(path):
        response_id = row.get('id') or row.get('opaque_id')
        response = row.get('response') if 'response' in row else row
        if response_id:
            responses[response_id] = response
    return responses


def verify_response(response, prompt_text):
    result = parse_response(response)
    serialized = json.dumps(result, ensure_ascii=False)
    if FORBIDDEN_TEXT.search(serialized):
        return {'score': 0.0, 'confidence': 0.0, 'grounding': 0.0, 'status': 'rejected-forbidden-token', 'raw': result}
    score = clamp_float(result.get('priority_score'), 0.0, 10.0, 0.0)
    confidence = clamp_float(result.get('confidence'), 0.0, 1.0, 0.0)
    for key in ['memory_safety_signal', 'locality_signal', 'reproducibility_signal', 'input_surface_signal', 'evidence_completeness']:
        result[key] = clamp_int(result.get(key), {0, 1, 2}, 0)
    terms = result.get('grounded_terms') or []
    if not isinstance(terms, list):
        terms = []
    terms = [str(term).strip() for term in terms if str(term).strip()]
    grounded = [term for term in terms if term in prompt_text]
    grounding = 1.0 if not terms else len(grounded) / len(terms)
    status = 'accepted'
    if grounding < 0.5:
        score = 0.0
        confidence = min(confidence, 0.25)
        status = 'neutralized-low-grounding'
    return {
        'score': round(score, 4),
        'confidence': round(confidence, 4),
        'grounding': round(grounding, 4),
        'status': status,
        'raw': result,
    }


def ndcg_at_k(items, cutoff):
    def dcg(sequence):
        total = 0.0
        for rank, item in enumerate(sequence[:cutoff], start=1):
            relevance = int(item.get('risk_level') or 0)
            total += ((2 ** relevance) - 1) / math.log2(rank + 1)
        return total
    ideal = sorted(items, key=lambda item: int(item.get('risk_level') or 0), reverse=True)
    denominator = dcg(ideal)
    return 0.0 if denominator == 0.0 else dcg(items) / denominator


def evaluate(items, high_threshold=3):
    metrics = {}
    for cutoff in (5, 10):
        metrics[f'HighRisk@{cutoff}'] = sum(1 for item in items[:cutoff] if int(item.get('risk_level') or 0) >= high_threshold)
        metrics[f'NDCG@{cutoff}'] = round(ndcg_at_k(items, cutoff), 4)
    first_hit = None
    high_count = 0
    cumulative_effort = 0.0
    first_effort = None
    for rank, item in enumerate(items, start=1):
        cumulative_effort += float(item.get('review_cost', 10.0))
        if int(item.get('risk_level') or 0) >= high_threshold:
            high_count += 1
            if first_hit is None:
                first_hit = rank
                first_effort = cumulative_effort
    metrics['Rank-to-First-HighRisk'] = first_hit
    metrics['Effort-to-First-HighRisk'] = None if first_effort is None else round(first_effort, 2)
    metrics['Effort-per-HighRisk'] = None if high_count == 0 else round(cumulative_effort / high_count, 2)
    return metrics


def build_ranking(items, prompts, manifest_rows, responses):
    prompt_by_id = {row['id']: row['prompt'] for row in prompts}
    item_by_finding = {item['id']: item for item in items}
    ranked = []
    for manifest in manifest_rows:
        response_id = manifest['id']
        finding_id = manifest['finding_id']
        item = dict(item_by_finding[finding_id])
        verified = verify_response(responses.get(response_id, {}), prompt_by_id[response_id]) if response_id in responses else {
            'score': 0.0,
            'confidence': 0.0,
            'grounding': 0.0,
            'status': 'missing-response',
            'raw': {},
        }
        item['llm_card'] = verified
        item['queue_score'] = verified['score'] * verified['confidence'] * max(verified['grounding'], 0.0)
        item['structrisk_score'] = item['queue_score']
        item['contribution'] = {'llm_card_score': item['queue_score']}
        item['confidence'] = verified['confidence']
        item['low_confidence'] = verified['status'] != 'accepted' or verified['confidence'] < 0.4
        ranked.append(item)
    ranked.sort(key=lambda item: (-float(item.get('queue_score') or 0.0), item.get('id') or ''))
    return ranked


def write_summary(path: Path, ranked, metrics):
    lines = [
        '# LLM-CardScore Baseline Summary',
        '',
        'This baseline directly scores anonymized evidence cards with an LLM. Prompts use opaque IDs and exclude project names, CVE identifiers, public scores, public labels, disclosure links, and outcome fields.',
        '',
        '## Metrics',
        '',
    ]
    for key, value in metrics.items():
        lines.append(f'- `{key}={value}`')
    lines.extend(['', '## Top-15 Findings', '', '| Rank | Finding | Risk | Score | Status | Reason |', '| ---: | --- | ---: | ---: | --- | --- |'])
    for rank, item in enumerate(ranked[:15], start=1):
        llm_card = item.get('llm_card') or {}
        raw = llm_card.get('raw') or {}
        reasons = raw.get('short_reason') if isinstance(raw.get('short_reason'), list) else []
        reason = '; '.join(str(reason) for reason in reasons[:2])
        lines.append(f"| {rank} | `{item.get('id')}` | {item.get('risk_level')} | {item.get('queue_score'):.4f} | {llm_card.get('status')} | {reason} |")
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Leakage-controlled LLM card-scoring baseline')
    parser.add_argument('--eval', default=str(EVAL_DEFAULT))
    parser.add_argument('--mode', choices=['emit-prompts', 'responses'], default='emit-prompts')
    parser.add_argument('--prompts-out', default=str(PROMPTS_DEFAULT))
    parser.add_argument('--manifest-out', default=str(MANIFEST_DEFAULT))
    parser.add_argument('--responses', default=str(RESPONSES_DEFAULT))
    parser.add_argument('--ranked-out', default=str(RANKED_DEFAULT))
    parser.add_argument('--metrics-out', default=str(METRICS_DEFAULT))
    parser.add_argument('--summary-out', default=str(SUMMARY_DEFAULT))
    args = parser.parse_args()

    items = load_jsonl(Path(args.eval))
    prompts, manifest_rows = emit_prompts(items, Path(args.prompts_out), Path(args.manifest_out))
    if args.mode == 'emit-prompts':
        print(json.dumps({'mode': args.mode, 'prompts': len(prompts), 'prompts_out': args.prompts_out, 'manifest_out': args.manifest_out}, indent=2))
        return

    responses = read_responses(Path(args.responses))
    ranked = build_ranking(items, prompts, manifest_rows, responses)
    metrics = evaluate(ranked)
    write_jsonl(Path(args.ranked_out), ranked)
    Path(args.metrics_out).write_text(json.dumps({'metrics': metrics, 'responses': len(responses)}, indent=2), encoding='utf-8')
    write_summary(Path(args.summary_out), ranked, metrics)
    print(json.dumps({'metrics': metrics, 'responses': len(responses), 'ranked_out': args.ranked_out}, indent=2))


if __name__ == '__main__':
    main()
