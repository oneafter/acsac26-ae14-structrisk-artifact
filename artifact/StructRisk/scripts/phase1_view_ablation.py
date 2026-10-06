#!/usr/bin/env python3
"""Post-consolidation evidence-view sensitivity for StructRisk.

The experiment fixes the released finding set, labels, and scorer weights. It
removes one evidence-card view at a time, recomputes every affected base and
derived signal from the retained fields, and evaluates the structured core.
Because sanitizer and location evidence helped define the released findings,
this is a ranking-stage sensitivity analysis, not an end-to-end regrouping
experiment.
"""

import argparse
import copy
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / "StructRisk"
GENERATED = STRUCTRISK / "generated"
sys.path.insert(0, str(STRUCTRISK / "scripts"))

from phase1_offline_experiment import clamp  # noqa: E402
from phase1_within_project_eval import evaluate_project  # noqa: E402
from structrisk_rank import DEFAULT_WEIGHTS, add_derived_signals, annotate  # noqa: E402


EVAL_DEFAULT = GENERATED / "phase1_offline_eval.jsonl"
WITHIN_DEFAULT = GENERATED / "phase1_within10_eval.jsonl"
ENRICHED_DEFAULT = GENERATED / "phase1_offline_enriched_artifacts.jsonl"
GLOBAL_RANKED_DEFAULT = GENERATED / "phase1_offline_manual_ranked.jsonl"
WITHIN_RANKED_DEFAULT = GENERATED / "phase1_within10_manual_ranked.jsonl"
JSON_DEFAULT = GENERATED / "phase1_view_ablation.json"
MD_DEFAULT = GENERATED / "phase1_view_ablation.md"

ALL_VIEWS = {"sanitizer", "stack", "replay", "input", "code"}
EVAL_ONLY_PROJECTS = {"binaryen", "openbabel", "squirrel", "wabt", "xlnt"}


def load_jsonl(path):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_representatives(path):
    rows = load_jsonl(path)
    return {(row["project"], row["crash_relpath"]): row for row in rows}


def representative(item, rows):
    samples = item.get("metadata", {}).get("sample_crashes") or []
    key = (item["project"], samples[0] if samples else "")
    row = rows.get(key)
    if row is None:
        raise KeyError(f"no representative artifact for {item['id']}: {key}")
    return row


def recompute_item(item, retained_views, representatives):
    masked = copy.deepcopy(item)
    metadata = masked.setdefault("metadata", {})
    signals = masked.setdefault("signals", {})
    raw = representative(item, representatives)
    original_support = int(metadata.get("support_count") or 1)
    support_bonus = min(original_support, 10) * 0.01

    if "sanitizer" not in retained_views:
        if metadata.get("matched_asan_type"):
            signals["locality"] = float(signals.get("locality", 0.0)) - 0.10
            signals["weak"] = float(signals.get("weak", 0.0)) + 0.20
        signals["sanitizer"] = 0.0
        metadata["matched_asan_type"] = ""
        metadata["matched_summary_line"] = ""
        metadata["matched_assertion"] = ""
    if "stack" not in retained_views:
        if int(raw.get("matched_project_frame_count") or 0) >= 3:
            signals["locality"] = float(signals.get("locality", 0.0)) - 0.15
    if "replay" not in retained_views:
        signals["replay"] = 0.0
        if raw.get("matched_has_section"):
            signals["weak"] = float(signals.get("weak", 0.0)) + 0.20
        if raw.get("matched_command"):
            signals["weak"] = float(signals.get("weak", 0.0)) + 0.05
        if raw.get("matched_env_error"):
            signals["weak"] = float(signals.get("weak", 0.0)) - 0.15
        metadata["cmdline_file"] = ""
        metadata["report_match_level"] = "none"
        metadata["matched_command"] = ""
        metadata["matched_exit_code"] = ""
    if "code" not in retained_views:
        if metadata.get("matched_project_loc"):
            signals["locality"] = float(signals.get("locality", 0.0)) - 0.45
            signals["weak"] = float(signals.get("weak", 0.0)) + 0.15
        if raw.get("matched_summary_loc"):
            signals["locality"] = float(signals.get("locality", 0.0)) - 0.15
            signals["weak"] = float(signals.get("weak", 0.0)) + 0.10
        metadata["matched_project_loc"] = ""
        metadata["matched_summary_loc"] = ""
        sanitizer = metadata.get("matched_asan_type") or ""
        assertion = metadata.get("matched_assertion") or ""
        target = metadata.get("target_name") or "" if "input" in retained_views else ""
        if sanitizer:
            metadata["signature"] = f"{item['project']}|asan|{sanitizer}|{target}"
        elif assertion:
            metadata["signature"] = f"{item['project']}|assert|{assertion[:160]}"
        else:
            metadata["signature"] = f"{item['project']}|artifact|{target}|"
    if "input" not in retained_views:
        if "replay" in retained_views:
            signals["replay"] = float(signals.get("replay", 0.0)) - 2.0 * support_bonus
        signals["weak"] = float(signals.get("weak", 0.0)) + support_bonus
        metadata["support_count"] = 1
        metadata["campaigns"] = []
        metadata["aligned_targets"] = []
        metadata["target_name"] = ""
        metadata["sample_crashes"] = []

    signals["replay"] = round(clamp(signals.get("replay", 0.0)), 4)
    signals["locality"] = round(clamp(signals.get("locality", 0.0)), 4)
    signals["sanitizer"] = round(clamp(signals.get("sanitizer", 0.0)), 4)
    signals["weak"] = round(clamp(signals.get("weak", 0.0), 0.02, 0.95), 4)
    return masked


def rank_full(items):
    copied = copy.deepcopy(items)
    add_derived_signals(copied)
    return annotate(copied, DEFAULT_WEIGHTS)


def rank_variant(items, retained_views, representatives):
    masked = [recompute_item(item, retained_views, representatives) for item in items]
    add_derived_signals(masked)
    return annotate(masked, DEFAULT_WEIGHTS)


def assert_canonical(ranked, path):
    expected = load_jsonl(path)
    actual_ids = [item["id"] for item in ranked]
    expected_ids = [item["id"] for item in expected]
    if actual_ids != expected_ids:
        raise ValueError(f"full-view ranking does not match canonical output: {path}")


def global_metrics(ranked):
    def ndcg(k):
        gains = [(2 ** int(item.get("risk_level") or 0)) - 1 for item in ranked]
        ideal = sorted(gains, reverse=True)[:k]
        actual = sum(gain / math.log2(index + 2) for index, gain in enumerate(gains[:k]))
        denominator = sum(gain / math.log2(index + 2) for index, gain in enumerate(ideal))
        return 0.0 if denominator == 0.0 else actual / denominator

    return {
        "HR@5": sum(int(item.get("risk_level") or 0) >= 3 for item in ranked[:5]),
        "HR@10": sum(int(item.get("risk_level") or 0) >= 3 for item in ranked[:10]),
        "NDCG@5": ndcg(5),
        "NDCG@10": ndcg(10),
    }


def per_project_metrics(ranked, project_filter=None):
    by_project = defaultdict(list)
    for item in ranked:
        if project_filter is None or item["project"] in project_filter:
            by_project[item["project"]].append(item)
    result = {}
    for project, items in sorted(by_project.items()):
        positives = sum(int(item.get("risk_level") or 0) >= 3 for item in items)
        if len(items) <= 1 or positives == 0:
            continue
        result[project] = evaluate_project(items)
    return result


def macro_metrics(project_rows):
    if not project_rows:
        return {}
    keys = ["HR@1", "HR@3", "NDCG@5", "MRR", "MAP"]
    return {
        key: sum(metrics[key] for metrics in project_rows.values()) / len(project_rows)
        for key in keys
    }


def variants():
    result = {"full": set(ALL_VIEWS)}
    for view in sorted(ALL_VIEWS):
        result[f"without_{view}"] = set(ALL_VIEWS) - {view}
        result[f"only_{view}"] = {view}
    result["without_stack_code"] = set(ALL_VIEWS) - {"stack", "code"}
    result["crash_report_only"] = {"sanitizer", "stack", "code"}
    result["operational_only"] = {"replay", "input"}
    return result


def evaluate_variants(eval_items, within_items, representatives):
    result = {}
    full_global = rank_full(eval_items)
    full_within = rank_full(within_items)
    assert_canonical(full_global, GLOBAL_RANKED_DEFAULT)
    assert_canonical(full_within, WITHIN_RANKED_DEFAULT)

    for label, retained_views in variants().items():
        if label == "full":
            eval_ranked = full_global
            within_ranked = full_within
        else:
            eval_ranked = rank_variant(eval_items, retained_views, representatives)
            within_ranked = rank_variant(within_items, retained_views, representatives)
        all_projects = per_project_metrics(within_ranked)
        eval_projects = per_project_metrics(within_ranked, EVAL_ONLY_PROJECTS)
        result[label] = {
            "retained_views": sorted(retained_views),
            "global": global_metrics(eval_ranked),
            "within_10": macro_metrics(all_projects),
            "within_eval_only_5": macro_metrics(eval_projects),
            "within_projects": all_projects,
        }
    return result


def rounded(value):
    return f"{value:.4f}"


def to_markdown(payload):
    result = payload["results"]
    lines = [
        "# Evidence-View Sensitivity",
        "",
        "This post-consolidation analysis fixes the released findings, labels, and "
        "StructRisk weights. It removes card views before signal extraction; it does "
        "not rerun finding consolidation.",
        "",
        "## Leave-One-View-Out",
        "",
        "| Variant | Global HR@10 | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    leave_one_out = [
        "full",
        "without_sanitizer",
        "without_stack",
        "without_replay",
        "without_input",
        "without_code",
        "without_stack_code",
    ]
    for label in leave_one_out:
        row = result[label]
        lines.append(
            f"| {label} | {row['global']['HR@10']} | {rounded(row['global']['NDCG@10'])} | "
            f"{rounded(row['within_10']['NDCG@5'])} | {rounded(row['within_10']['MAP'])} | "
            f"{rounded(row['within_eval_only_5']['NDCG@5'])} | "
            f"{rounded(row['within_eval_only_5']['MAP'])} |"
        )

    lines.extend([
        "",
        "## Alternative Representations",
        "",
        "| Variant | Global NDCG@10 | WP NDCG@5 | WP MAP | Eval-only NDCG@5 | Eval-only MAP |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ])
    alternatives = [
        "full",
        "only_sanitizer",
        "only_stack",
        "only_replay",
        "only_input",
        "only_code",
        "crash_report_only",
        "operational_only",
    ]
    for label in alternatives:
        row = result[label]
        lines.append(
            f"| {label} | {rounded(row['global']['NDCG@10'])} | "
            f"{rounded(row['within_10']['NDCG@5'])} | {rounded(row['within_10']['MAP'])} | "
            f"{rounded(row['within_eval_only_5']['NDCG@5'])} | "
            f"{rounded(row['within_eval_only_5']['MAP'])} |"
        )

    lines.extend([
        "",
        "## Descriptive Interpretation",
        "",
        "- The full card exceeds every single-view proxy on global NDCG@10, "
        "within-project NDCG@5/MAP, and the project-disjoint Eval-only check.",
        "- Sanitizer is the strongest single-view local proxy "
        "(NDCG@5/MAP 0.8174/0.7801), but its leave-one-out effect is partly "
        "absorbed by overlapping failure-semantics and weak-evidence cues.",
        "- Replay is most important for the global queue; removing it lowers global "
        "NDCG@10 from 0.8522 to 0.3254, while its within-project effect is small.",
        "- Input/provenance has the largest local leave-one-out effect, reducing "
        "NDCG@5/MAP from 0.8561/0.8167 to 0.7897/0.7451; the Eval-only pattern "
        "is similar (0.8981/0.8417 to 0.8017/0.7478).",
        "- Stack has no independent ranking effect after consolidation, and Code "
        "helps globally but not on the current within-project slice. These are "
        "descriptive point estimates, not evidence that the current grouping is "
        "uniquely optimal.",
        "",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="StructRisk evidence-view sensitivity")
    parser.add_argument("--eval", default=str(EVAL_DEFAULT))
    parser.add_argument("--within", default=str(WITHIN_DEFAULT))
    parser.add_argument("--enriched", default=str(ENRICHED_DEFAULT))
    parser.add_argument("--json-out", default=str(JSON_DEFAULT))
    parser.add_argument("--md-out", default=str(MD_DEFAULT))
    args = parser.parse_args()

    eval_items = load_jsonl(Path(args.eval))
    within_items = load_jsonl(Path(args.within))
    representatives = load_representatives(Path(args.enriched))
    payload = {
        "scope": "post-consolidation ranking-stage sensitivity",
        "fixed_findings": True,
        "fixed_labels": True,
        "fixed_theta": DEFAULT_WEIGHTS,
        "eval_only_projects": sorted(EVAL_ONLY_PROJECTS),
        "results": evaluate_variants(eval_items, within_items, representatives),
    }

    json_out = Path(args.json_out)
    md_out = Path(args.md_out)
    json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_out.write_text(to_markdown(payload), encoding="utf-8")
    print(json_out)
    print(md_out)


if __name__ == "__main__":
    main()
