#!/usr/bin/env python3
import argparse
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

FEATURES = ["replay", "locality", "evidence_uniqueness_gated", "failure_semantics_gated", "sanitizer", "weak"]
ALIASES = {
    "replay": "replay",
    "locality": "locality",
    "evidence_uniqueness": "evidence_uniqueness_gated",
    "evidence_uniqueness_gated": "evidence_uniqueness_gated",
    "failure_semantics": "failure_semantics_gated",
    "failure_semantics_gated": "failure_semantics_gated",
    "sanitizer": "sanitizer",
    "impact": "sanitizer",
    "asan": "sanitizer",
    "weak": "weak",
    "weakness": "weak",
}
DEFAULT_WEIGHTS = {
    "replay": 2.00,
    "locality": 1.00,
    "evidence_uniqueness_gated": 1.00,
    "failure_semantics_gated": 1.00,
    "sanitizer": 2.00,
    "weak": -3.00,
    "bias": 0.00,
}
CONFIDENCE_WEIGHTS = {
    "replay": 0.40,
    "locality": 0.15,
    "evidence_uniqueness_gated": 0.15,
    "failure_semantics_gated": 0.15,
    "sanitizer": 0.25,
    "weak": -0.30,
}
MEMORY_STRONG_RE = re.compile(
    r"(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|heap-use-after-free|"
    r"use-after-free|double-free|stack-use-after-return|stack-buffer-underflow|heap-buffer-underflow|out-of-bounds|overflow)",
    re.I,
)
WEAK_RE = re.compile(r"(null|divide-by-zero|timeout|leak|assert|requested|deadlysignal)", re.I)
SUPPORT_STABILITY_MIN_COUNT = 20
SUPPORT_STABILITY_WEAK_MAX = 0.10
SUPPORT_STABILITY_BONUS = 0.50
LCR_SCORE_BAND = 0.50


def clamp(value):
    return max(0.0, min(1.0, float(value)))


def metadata(item):
    return item.get("metadata") or {}


def list_len(value):
    if isinstance(value, list):
        return len(value)
    return 1 if value else 0


def support_count(item):
    value = metadata(item).get("support_count", item.get("support_count", 1))
    try:
        return max(1, int(float(value)))
    except (TypeError, ValueError):
        return 1


def exact_report(item):
    return str(metadata(item).get("report_match_level") or "").lower() == "exact"


def location_key(item):
    loc = str(metadata(item).get("matched_project_loc") or "")
    if loc:
        return re.sub(r":\d+(?::\d+)?$", "", loc)[-120:]
    signature = str(metadata(item).get("signature") or "")
    return signature.split("|")[-1][:80] if signature else ""


def project_stats(items):
    grouped = defaultdict(list)
    for item in items:
        grouped[item.get("project", "unknown")].append(item)
    stats = {}
    for project, project_items in grouped.items():
        max_support = max(support_count(item) for item in project_items) if project_items else 1
        loc_counts = Counter(location_key(item) for item in project_items if location_key(item))
        stats[project] = {"max_support": max_support, "loc_counts": loc_counts}
    return stats


def evidence_uniqueness(item, stats):
    project_stat = stats.get(item.get("project", "unknown"), {"max_support": 1, "loc_counts": Counter()})
    max_support = max(1, project_stat["max_support"])
    support_log = math.log1p(support_count(item)) / math.log1p(max_support) if max_support > 1 else 0.0
    key = location_key(item)
    shared = project_stat["loc_counts"].get(key, 1) if key else 4
    location_unique = 1.0 / math.sqrt(max(1, shared))
    meta = metadata(item)
    campaign_count = max(list_len(meta.get("campaigns")), list_len(meta.get("aligned_targets")), 1)
    target_spread = min(1.0, math.log1p(campaign_count) / math.log1p(4))
    return clamp(0.45 * support_log + 0.35 * location_unique + 0.20 * target_spread)


def support_stability(item, stats):
    signals = item.get("signals") or {}
    weak = float(signals.get("weak", 0.0) or 0.0)
    count = support_count(item)
    if not exact_report(item) or count < SUPPORT_STABILITY_MIN_COUNT or weak > SUPPORT_STABILITY_WEAK_MAX:
        return 0.0
    project_stat = stats.get(item.get("project", "unknown"), {"max_support": 1})
    max_support = max(1, project_stat.get("max_support", 1))
    if max_support <= 1:
        return 0.0
    return clamp(math.log1p(count) / math.log1p(max_support))


def failure_semantics(item):
    meta = metadata(item)
    signals = item.get("signals") or {}
    text = " ".join(str(meta.get(key) or "") for key in ("matched_summary_line", "matched_asan_type", "matched_assertion", "signature", "matched_project_loc"))
    has_project_site = bool(str(meta.get("matched_project_loc") or "").strip())
    report_exact = str(meta.get("report_match_level") or "").lower() == "exact"
    assertion = bool(str(meta.get("matched_assertion") or "").strip())
    exit_code = str(meta.get("matched_exit_code") or "")
    score = 0.20
    if MEMORY_STRONG_RE.search(text):
        score += 0.50
    elif "deadlysignal" in text.lower() and has_project_site:
        score += 0.30
    elif has_project_site:
        score += 0.20
    if report_exact:
        score += 0.10
    if exit_code and exit_code not in {"0", "None", "none"}:
        score += 0.05
    if assertion:
        score -= 0.10
    if WEAK_RE.search(text) and not MEMORY_STRONG_RE.search(text):
        score -= 0.10
    score += 0.15 * float(signals.get("sanitizer", 0.0) or 0.0)
    return clamp(score)


def add_derived_signals(items):
    stats = project_stats(items)
    for item in items:
        signals = item["signals"]
        signals["evidence_uniqueness"] = evidence_uniqueness(item, stats)
        signals["support_stability"] = support_stability(item, stats)
        signals["failure_semantics"] = failure_semantics(item)
        weak_gate = min(1.0, max(0.2, 1.2 * (1.0 - float(signals.get("weak", 0.0) or 0.0))))
        signals["evidence_uniqueness_gated"] = signals["evidence_uniqueness"] * weak_gate
        signals["failure_semantics_gated"] = signals["failure_semantics"] * weak_gate
    return items


def canonical_signals(raw):
    signals = {name: 0.0 for name in FEATURES + ["site_anchor", "environment", "evidence_uniqueness", "support_stability", "failure_semantics"]}
    for key, value in (raw or {}).items():
        name = ALIASES.get(key)
        if name is None and key in signals:
            name = key
        if name is not None:
            signals[name] = clamp(value)
    return signals


def load_jsonl(path):
    items = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            row["signals"] = canonical_signals(row.get("signals", {}))
            row.setdefault("id", f"finding-{len(items)+1}")
            row.setdefault("project", "unknown")
            row.setdefault("review_cost", 10.0)
            if "risk_level" in row and row["risk_level"] is not None:
                row["risk_level"] = int(row["risk_level"])
            items.append(row)
    return add_derived_signals(items)


def feature_vector(item):
    signals = item["signals"]
    return {
        "replay": signals["replay"],
        "locality": signals["locality"],
        "evidence_uniqueness_gated": signals["evidence_uniqueness_gated"],
        "failure_semantics_gated": signals["failure_semantics_gated"],
        "sanitizer": signals["sanitizer"],
        "weak": signals["weak"],
        "bias": 1.0,
    }


def score_item(item, weights):
    vector = feature_vector(item)
    score = sum(weights[name] * vector[name] for name in vector)
    evidence_weight = weights.get("evidence_uniqueness_gated", DEFAULT_WEIGHTS["evidence_uniqueness_gated"])
    evidence_scale = max(0.0, evidence_weight / DEFAULT_WEIGHTS["evidence_uniqueness_gated"])
    score += SUPPORT_STABILITY_BONUS * evidence_scale * float(item["signals"].get("support_stability", 0.0) or 0.0)
    return score


def confidence_item(item):
    signals = item["signals"]
    score = 0.0
    for name, weight in CONFIDENCE_WEIGHTS.items():
        score += weight * signals.get(name, 0.0)
    return score


def ndcg_at_k(items, k):
    ranked = items[:k]
    def dcg(seq):
        total = 0.0
        for idx, item in enumerate(seq, start=1):
            rel = item.get("risk_level") or 0
            gain = (2 ** rel) - 1
            total += gain / math.log2(idx + 1)
        return total
    ideal = sorted(items, key=lambda item: item.get("risk_level") or 0, reverse=True)[:k]
    denom = dcg(ideal)
    return 0.0 if denom == 0.0 else dcg(ranked) / denom


def evaluate(items, high_threshold, ks):
    labeled = [item for item in items if item.get("risk_level") is not None]
    if not labeled:
        return {}
    metrics = {}
    for k in ks:
        topk = labeled[:k]
        count = sum(1 for item in topk if item["risk_level"] >= high_threshold)
        metrics[f"HighRisk@{k}"] = count
        metrics[f"NDCG@{k}"] = round(ndcg_at_k(labeled, k), 4)
    cumulative_effort = 0.0
    first_hit_effort = None
    first_hit_rank = None
    high_count = 0
    abstained = 0
    abstained_non_high = 0
    for idx, item in enumerate(labeled, start=1):
        cumulative_effort += float(item.get("review_cost", 10.0))
        if item["risk_level"] >= high_threshold:
            high_count += 1
            if first_hit_rank is None:
                first_hit_rank = idx
                first_hit_effort = cumulative_effort
        if item.get("low_confidence"):
            abstained += 1
            if item["risk_level"] < high_threshold:
                abstained_non_high += 1
    metrics["Rank-to-First-HighRisk"] = first_hit_rank
    metrics["Effort-to-First-HighRisk"] = None if first_hit_effort is None else round(first_hit_effort, 2)
    metrics["Effort-per-HighRisk"] = None if high_count == 0 else round(cumulative_effort / high_count, 2)
    metrics["Abstention precision"] = None if abstained == 0 else round(abstained_non_high / abstained, 4)
    return metrics


def annotate(items, weights, budget_aware=False, eps=1.0, confidence_threshold=0.35):
    annotated = []
    for item in items:
        score = score_item(item, weights)
        confidence = confidence_item(item)
        review_cost = float(item.get("review_cost", 10.0))
        queue_score = score / (review_cost + eps) if budget_aware else score
        contribution = {}
        vector = feature_vector(item)
        for name in vector:
            contribution[name] = round(weights[name] * vector[name], 4)
        evidence_weight = weights.get("evidence_uniqueness_gated", DEFAULT_WEIGHTS["evidence_uniqueness_gated"])
        evidence_scale = max(0.0, evidence_weight / DEFAULT_WEIGHTS["evidence_uniqueness_gated"])
        contribution["support_stability"] = round(
            SUPPORT_STABILITY_BONUS * evidence_scale * float(item["signals"].get("support_stability", 0.0) or 0.0),
            4,
        )
        merged = dict(item)
        merged["structrisk_score"] = round(score, 4)
        merged["queue_score"] = round(queue_score, 4)
        merged["confidence"] = round(confidence, 4)
        merged["low_confidence"] = bool(
            confidence < confidence_threshold
            or (item["signals"]["replay"] < 0.25 and item["signals"]["evidence_uniqueness_gated"] < 0.10)
        )
        merged["contribution"] = contribution
        annotated.append(merged)
    annotated.sort(key=lambda item: (-item["queue_score"], -item["structrisk_score"], item["project"], item["id"]))
    return annotated


def write_jsonl(path, items):
    with Path(path).open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description="StructRisk sign-constrained ranking prototype")
    parser.add_argument("--input", help="JSONL findings file for manual ranking")
    parser.add_argument("--mode", choices=["manual"], default="manual")
    parser.add_argument("--output", default="StructRisk/outputs/ranked_findings.jsonl")
    parser.add_argument("--weights-out", default="StructRisk/outputs/weights.json")
    parser.add_argument("--metrics-out", default="StructRisk/outputs/metrics.json")
    parser.add_argument("--high-threshold", type=int, default=3)
    parser.add_argument("--budget-aware", action="store_true")
    args = parser.parse_args()

    if not args.input:
        raise SystemExit("--input is required")
    eval_items = load_jsonl(args.input)
    weights = dict(DEFAULT_WEIGHTS)
    history = []

    ranked = annotate(eval_items, weights, budget_aware=args.budget_aware)
    metrics = evaluate(ranked, high_threshold=args.high_threshold, ks=[5, 10])

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_path, ranked)

    weights_path = Path(args.weights_out)
    weights_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_mode = "frozen"
    provenance = ("The three-tier structure and sign constraints are domain-informed, and "
                  "the tier weights theta were set manually from domain experience. The "
                  "signal-rule constants were calibrated by scripted search on the "
                  "5-project development split (its artifacts and labels). Every value was "
                  "frozen before any of the 18 evaluation projects was scored; no "
                  "evaluation data influenced any value. Deployment applies these weights "
                  "and constants as a fixed rule.")
    weights_path.write_text(json.dumps({"mode": metadata_mode, "provenance": provenance, "weights": weights, "history": history}, indent=2), encoding="utf-8")

    metrics_path = Path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(output_path)
    print(weights_path)
    print(metrics_path)
    if metrics:
        print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
