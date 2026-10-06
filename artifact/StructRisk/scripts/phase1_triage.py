#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK_ROOT = REPO_ROOT / "StructRisk"
DEFAULT_SRC_ROOT = STRUCTRISK_ROOT / "StructRisk_src_full" / "src"
DEFAULT_PHASE1 = STRUCTRISK_ROOT / "phase1_projects.txt"
DEFAULT_CVSS = STRUCTRISK_ROOT / "structrisk_nvd_cvss31.csv"
DEFAULT_OUT_DIR = STRUCTRISK_ROOT / "generated"
TEXT_SUFFIXES = {".txt", ".log", ".md", ".out", ".err", ""}
STACK_RE = re.compile(r"((?:/src|/magma/targets)/[^\s:]+(?::\d+){1,2})")
ASAN_RE = re.compile(r"(AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|runtime error|SUMMARY:)")
DOCKER_REPLAY_ENV_DEFAULTS = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_odr_violation=0:alloc_dealloc_mismatch=0:new_delete_type_mismatch=0:symbolize=0:detect_leaks=0:allocator_may_return_null=1",
    "AFL_SKIP_CPUFREQ": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_TRY_AFFINITY": "1",
}


def docker_replay_env() -> Dict[str, str]:
    return {key: os.environ.get(key, value) for key, value in DOCKER_REPLAY_ENV_DEFAULTS.items()}


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_projects(path: Path) -> List[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_cvss(path: Path) -> Dict[str, Dict[str, object]]:
    project_meta: Dict[str, Dict[str, object]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            project = row["project"].strip()
            try:
                score = float(row.get("highest_cvss31") or row.get("cvss31_score") or 0.0)
            except ValueError:
                score = 0.0
            severity = (row.get("highest_cvss31_severity") or row.get("cvss31_severity") or "").strip().upper()
            current = project_meta.get(project)
            if current is None or score > float(current["score"]):
                project_meta[project] = {"score": score, "severity": severity}
    return project_meta


def find_files(project_dir: Path, predicate) -> List[Path]:
    found: List[Path] = []
    for path in project_dir.rglob("*"):
        try:
            if predicate(path):
                found.append(path)
        except OSError:
            continue
    return sorted(found)


def read_cmdline_tokens(path: Path) -> List[str]:
    tokens = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line:
            tokens.append(line)
    return tokens


def relpath(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def iter_crash_files(crash_dir: Path) -> List[Path]:
    files = [path for path in sorted(crash_dir.iterdir()) if path.is_file() and not path.name.startswith('.')]
    id_style = [path for path in files if path.name.startswith("id:")]
    if id_style:
        return id_style
    return [path for path in files if path.name != 'cmdline']


def read_small_text(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def pick_associated_cmdline(crash_dir: Path, project_dir: Path, cmdline_files: List[Path]) -> Optional[Path]:
    current = crash_dir.parent
    while True:
        candidate = current / "cmdline"
        if candidate.exists():
            return candidate
        if current == project_dir:
            break
        current = current.parent
    if not cmdline_files:
        return None
    best = None
    best_score = -1
    for cmdline in cmdline_files:
        try:
            score = len(os.path.commonpath([str(cmdline.parent), str(crash_dir)]).split(os.sep))
        except ValueError:
            score = 0
        if score > best_score:
            best = cmdline
            best_score = score
    return best


def candidate_run_dirs(project_dir: Path, cmdline_file: Optional[Path]) -> List[Path]:
    candidates: List[Path] = [project_dir]
    if cmdline_file:
        current = cmdline_file.parent
        while True:
            if current == project_dir or project_dir in current.parents:
                if current not in candidates:
                    candidates.append(current)
            if current == project_dir:
                break
            current = current.parent
    return candidates


def choose_run_cwd(project_dir: Path, cmdline_file: Optional[Path], exec_token: str) -> Path:
    if not exec_token or exec_token.startswith('/src/') or exec_token.startswith('/'):
        return project_dir
    for candidate in candidate_run_dirs(project_dir, cmdline_file):
        probe = (candidate / exec_token).resolve()
        if probe.exists():
            return candidate
    return project_dir


def normalize_host_token(token: str, run_cwd: Path, src_root: Path) -> str:
    if token.startswith("/src/"):
        rel = token[len("/src/") :]
        return str(src_root / rel)
    if token.startswith("./") or token.startswith("../"):
        return str((run_cwd / token).resolve())
    return token


def to_container_path(local_path: Path, src_root: Path) -> str:
    try:
        rel = local_path.resolve().relative_to(src_root.resolve())
        return f"/src/{rel.as_posix()}"
    except Exception:
        return str(local_path)


def build_host_cmdline(tokens: List[str], crash_path: Path, project_dir: Path, src_root: Path, cmdline_file: Optional[Path]) -> Dict[str, object]:
    uses_stdin = "@@" not in tokens
    run_cwd = choose_run_cwd(project_dir, cmdline_file, tokens[0] if tokens else "")
    resolved = []
    for token in tokens:
        if token == "@@":
            resolved.append(str(crash_path))
        else:
            resolved.append(normalize_host_token(token, run_cwd, src_root))
    return {
        "tokens": resolved,
        "uses_stdin": uses_stdin,
        "target": resolved[0] if resolved else "",
        "run_cwd": str(run_cwd),
    }


def build_container_cmdline(project: str, tokens: List[str], crash_relpath: str, project_dir: Path, src_root: Path, cmdline_file: Optional[Path]) -> Dict[str, object]:
    uses_stdin = "@@" not in tokens
    container_crash = f"/src/{project}/{crash_relpath}"
    run_cwd = choose_run_cwd(project_dir, cmdline_file, tokens[0] if tokens else "")
    container_run_cwd = to_container_path(run_cwd, src_root)
    resolved = []
    for token in tokens:
        if token == "@@":
            resolved.append(container_crash)
        elif token.startswith('./') or token.startswith('../'):
            resolved.append(token)
        elif token.startswith('/src/'):
            resolved.append(token)
        else:
            resolved.append(token)
    return {
        "tokens": resolved,
        "uses_stdin": uses_stdin,
        "target": resolved[0] if resolved else "",
        "project_dir": f"/src/{project}",
        "run_cwd": container_run_cwd,
        "crash_path": container_crash,
    }


def detect_reports(project_dir: Path) -> List[Path]:
    def pred(path: Path) -> bool:
        return path.is_file() and "crash" in path.name.lower() and path.suffix.lower() in TEXT_SUFFIXES
    return find_files(project_dir, pred)


def analyze_reports(project: str, report_files: List[Path], project_dir: Path) -> Dict[str, object]:
    has_asan = False
    stack_frames: List[str] = []
    summary_line = ""
    for report in report_files[:8]:
        text = read_small_text(report)
        if not text:
            continue
        if ASAN_RE.search(text):
            has_asan = True
        if not summary_line:
            for line in text.splitlines():
                if "SUMMARY:" in line or "AddressSanitizer:" in line:
                    summary_line = line.strip()
                    break
        project_markers = (f"/src/{project}/", f"/magma/targets/{project}/")
        for match in STACK_RE.findall(text):
            if any(marker in match for marker in project_markers):
                stack_frames.append(match)
        if len(stack_frames) >= 12:
            break
    unique_frames = []
    seen = set()
    for frame in stack_frames:
        if frame not in seen:
            seen.add(frame)
            unique_frames.append(frame)
    return {
        "has_asan": has_asan,
        "summary_line": summary_line,
        "stack_frames": unique_frames[:8],
        "stack_frame_count": len(unique_frames),
        "report_files": [relpath(path, project_dir) for path in report_files[:8]],
    }


def target_name(cmd_tokens: List[str]) -> str:
    if not cmd_tokens:
        return ""
    return Path(cmd_tokens[0]).name.lower()


def compute_bootstrap_signals(record: Dict[str, object]) -> Dict[str, float]:
    has_cmdline = bool(record.get("cmdline_file"))
    has_exec = bool(record.get("host_target_exists")) or bool(record.get("container_target_hint"))
    has_asan = bool(record.get("report_has_asan"))
    frame_count = int(record.get("report_stack_frame_count") or 0)
    project_harness_count = int(record.get("project_harness_file_count") or 0)
    project_cmdline_count = int(record.get("project_cmdline_file_count") or 0)
    crash_report_count = int(record.get("project_crash_report_file_count") or 0)
    target = str(record.get("target_name") or "")
    uses_stdin = bool(record.get("uses_stdin"))

    replay = 0.35
    replay += 0.35 if has_cmdline else 0.0
    replay += 0.15 if has_exec else 0.0
    replay += 0.10 if crash_report_count > 0 else 0.0
    replay += 0.05 if not uses_stdin else 0.0
    replay = clamp(replay)

    locality = 0.20
    locality += 0.35 if has_asan else 0.0
    locality += 0.20 if frame_count > 0 else 0.0
    locality += 0.15 if any(k in target for k in ["fuzz", "harness"]) else 0.0
    locality = clamp(locality)

    site_anchor = 0.10
    site_anchor += 0.40 if frame_count > 0 else 0.0
    site_anchor += 0.20 if has_asan else 0.0
    site_anchor += 0.15 if crash_report_count > 0 else 0.0
    site_anchor = clamp(site_anchor)

    environment = 0.20
    environment += 0.25 if any(k in target for k in ["fuzz", "harness"]) else 0.0
    environment += 0.15 if project_harness_count >= 2 else 0.0
    environment += 0.10 if project_cmdline_count >= 2 else 0.0
    environment += 0.10 if not uses_stdin else 0.0
    environment = clamp(environment)

    weak = 0.85
    weak -= 0.25 if has_cmdline else 0.0
    weak -= 0.20 if has_exec else 0.0
    weak -= 0.20 if has_asan else 0.0
    weak -= 0.10 if frame_count > 0 else 0.0
    weak -= 0.05 if crash_report_count > 0 else 0.0
    weak = clamp(weak, 0.02, 0.95)

    return {
        "replay": round(replay, 4),
        "locality": round(locality, 4),
        "site_anchor": round(site_anchor, 4),
        "environment": round(environment, 4),
        "weak": round(weak, 4),
    }


def estimate_review_cost(record: Dict[str, object], signals: Dict[str, float]) -> float:
    cost = 8.0
    if not record.get("report_has_asan"):
        cost += 2.0
    if bool(record.get("uses_stdin")):
        cost += 1.5
    if signals["weak"] > 0.45:
        cost += 2.0
    if signals["site_anchor"] > 0.55:
        cost -= 1.0
    return round(max(5.0, cost), 2)


def project_snapshot(project: str, project_dir: Path, src_root: Path, cvss_meta: Dict[str, Dict[str, object]]) -> Dict[str, object]:
    cmdlines = sorted(project_dir.rglob("cmdline"))
    crash_dirs = sorted([p for p in project_dir.rglob("crashes") if p.is_dir()])
    harness_files = find_files(project_dir, lambda p: p.is_file() and any(k in p.name.lower() for k in ["harness", "fuzz"]))
    exec_candidates = find_files(
        project_dir,
        lambda p: p.is_file() and (p.stat().st_mode & 0o111) and any(k in p.name.lower() for k in ["harness", "fuzz", "berry", "obabel", "sq", "wren", "lily", "wasm", "xlnt", "raylib", "tracker", "wav"]),
    )
    report_files = detect_reports(project_dir)
    report_info = analyze_reports(project, report_files, project_dir)
    cvss = cvss_meta.get(project, {"score": 0.0, "severity": "UNKNOWN"})
    return {
        "project": project,
        "project_dir": project_dir,
        "src_root": src_root,
        "cmdlines": cmdlines,
        "crash_dirs": crash_dirs,
        "harness_files": harness_files,
        "exec_candidates": exec_candidates,
        "report_files": report_files,
        "report_info": report_info,
        "cvss": cvss,
    }


def iter_artifacts(snapshot: Dict[str, object], per_project_limit: int = 0) -> Iterable[Dict[str, object]]:
    project = str(snapshot["project"])
    project_dir: Path = snapshot["project_dir"]
    src_root: Path = snapshot["src_root"]
    cmdlines: List[Path] = snapshot["cmdlines"]
    report_info: Dict[str, object] = snapshot["report_info"]
    emitted = 0
    for crash_dir in snapshot["crash_dirs"]:
        cmdline = pick_associated_cmdline(crash_dir, project_dir, cmdlines)
        cmd_tokens = read_cmdline_tokens(cmdline) if cmdline and cmdline.exists() else []
        campaign = relpath(crash_dir.parent, project_dir)
        for crash_path in iter_crash_files(crash_dir):
            crash_relpath = relpath(crash_path, project_dir)
            host_cmd = build_host_cmdline(cmd_tokens, crash_path, project_dir, src_root, cmdline)
            container_cmd = build_container_cmdline(project, cmd_tokens, crash_relpath, project_dir, src_root, cmdline)
            host_target = Path(host_cmd["target"]) if host_cmd["target"] else None
            row = {
                "id": f"{project}::{campaign.replace('/', '__')}::{crash_path.name}",
                "project": project,
                "campaign": campaign,
                "project_dir": str(project_dir),
                "container_project_dir": container_cmd["project_dir"],
                "host_run_cwd": host_cmd["run_cwd"],
                "container_run_cwd": container_cmd["run_cwd"],
                "crash_dir": relpath(crash_dir, project_dir),
                "crash_path": str(crash_path),
                "crash_relpath": crash_relpath,
                "container_crash_path": container_cmd["crash_path"],
                "crash_name": crash_path.name,
                "crash_size": crash_path.stat().st_size,
                "cmdline_file": relpath(cmdline, project_dir) if cmdline else "",
                "cmdline_tokens": cmd_tokens,
                "cmdline": " ".join(cmd_tokens),
                "host_cmdline_tokens": host_cmd["tokens"],
                "host_cmdline": " ".join(shlex.quote(token) for token in host_cmd["tokens"]),
                "container_cmdline_tokens": container_cmd["tokens"],
                "container_cmdline": " ".join(shlex.quote(token) for token in container_cmd["tokens"]),
                "uses_stdin": host_cmd["uses_stdin"],
                "host_target_path": str(host_target) if host_target else "",
                "host_target_exists": bool(host_target and host_target.exists()),
                "container_target_hint": container_cmd["target"],
                "target_name": target_name(cmd_tokens),
                "project_cvss31": snapshot["cvss"]["score"],
                "project_cvss31_severity": snapshot["cvss"]["severity"],
                "project_cmdline_file_count": len(snapshot["cmdlines"]),
                "project_crash_dir_count": len(snapshot["crash_dirs"]),
                "project_harness_file_count": len(snapshot["harness_files"]),
                "project_exec_candidate_count": len(snapshot["exec_candidates"]),
                "project_crash_report_file_count": len(snapshot["report_files"]),
                "report_has_asan": report_info["has_asan"],
                "report_summary_line": report_info["summary_line"],
                "report_stack_frame_count": report_info["stack_frame_count"],
                "report_stack_frames": report_info["stack_frames"],
                "report_files": report_info["report_files"],
            }
            yield row
            emitted += 1
            if per_project_limit and emitted >= per_project_limit:
                return


def write_jsonl(path: Path, rows: Iterable[Dict[str, object]]) -> int:
    ensure_parent(path)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def load_jsonl(path: Path) -> List[Dict[str, object]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def command_index(args: argparse.Namespace) -> None:
    projects = load_projects(Path(args.phase1))
    cvss = load_cvss(Path(args.cvss))
    rows = []
    summary = []
    for project in projects:
        project_dir = Path(args.src_root) / project
        snapshot = project_snapshot(project, project_dir, Path(args.src_root), cvss)
        project_rows = list(iter_artifacts(snapshot, per_project_limit=args.per_project_limit))
        rows.extend(project_rows)
        summary.append({
            "project": project,
            "artifact_count": len(project_rows),
            "cmdline_file_count": len(snapshot["cmdlines"]),
            "crash_dir_count": len(snapshot["crash_dirs"]),
            "harness_file_count": len(snapshot["harness_files"]),
            "exec_candidate_count": len(snapshot["exec_candidates"]),
            "crash_report_file_count": len(snapshot["report_files"]),
        })
    count = write_jsonl(Path(args.output), rows)
    ensure_parent(Path(args.summary_csv))
    with Path(args.summary_csv).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)
    print(f"WROTE {args.output} ({count} rows)")
    print(f"WROTE {args.summary_csv}")


def command_bootstrap(args: argparse.Namespace) -> None:
    rows = load_jsonl(Path(args.input))
    out = []
    for row in rows:
        signals = compute_bootstrap_signals(row)
        out.append({
            "id": row["id"],
            "project": row["project"],
            "review_cost": estimate_review_cost(row, signals),
            "signals": signals,
            "metadata": {
                "campaign": row["campaign"],
                "crash_relpath": row["crash_relpath"],
                "cmdline_file": row["cmdline_file"],
                "host_cmdline": row["host_cmdline"],
                "container_cmdline": row["container_cmdline"],
                "host_target_path": row["host_target_path"],
                "host_target_exists": row["host_target_exists"],
                "container_target_hint": row["container_target_hint"],
                "uses_stdin": row["uses_stdin"],
                "project_cvss31": row["project_cvss31"],
                "project_cvss31_severity": row["project_cvss31_severity"],
                "report_has_asan": row["report_has_asan"],
                "report_summary_line": row["report_summary_line"],
                "report_stack_frames": row["report_stack_frames"],
                "report_files": row["report_files"],
            },
        })
    count = write_jsonl(Path(args.output), out)
    print(f"WROTE {args.output} ({count} rows)")


def replay_host(record: Dict[str, object], timeout: float) -> Dict[str, object]:
    project_dir = Path(record["project_dir"])
    crash_path = Path(record["crash_path"])
    tokens = list(record.get("host_cmdline_tokens") or [])
    if not tokens:
        return {"status": "skipped", "reason": "no_cmdline"}
    uses_stdin = bool(record.get("uses_stdin"))
    stdin_data = crash_path.read_bytes() if uses_stdin else None
    start = time.time()
    try:
        proc = subprocess.run(
            tokens,
            cwd=project_dir,
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed_ms = round((time.time() - start) * 1000, 2)
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stack_frames = STACK_RE.findall(stderr)[:8]
        sanitizer = bool(ASAN_RE.search(stderr))
        status = "ok"
        if proc.returncode < 0:
            status = "signal"
        elif proc.returncode != 0:
            status = "nonzero"
        if sanitizer:
            status = "sanitizer"
        return {
            "engine": "host",
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": status,
            "returncode": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "stderr_head": stderr[:4000],
            "stdout_head": stdout[:1000],
            "stack_frames": stack_frames,
            "sanitizer": sanitizer,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        stderr = (exc.stderr or b"").decode("utf-8", errors="ignore") if isinstance(exc.stderr, (bytes, bytearray)) else str(exc.stderr or "")
        stdout = (exc.stdout or b"").decode("utf-8", errors="ignore") if isinstance(exc.stdout, (bytes, bytearray)) else str(exc.stdout or "")
        return {
            "engine": "host",
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": "timeout",
            "returncode": None,
            "elapsed_ms": elapsed_ms,
            "stderr_head": stderr[:4000],
            "stdout_head": stdout[:1000],
            "stack_frames": STACK_RE.findall(stderr)[:8],
            "sanitizer": bool(ASAN_RE.search(stderr)),
        }
    except OSError as exc:
        status = "host_exec_format" if exc.errno == 8 else "error"
        return {
            "engine": "host",
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": status,
            "reason": repr(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "engine": "host",
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": "error",
            "reason": repr(exc),
        }


def replay_docker(record: Dict[str, object], timeout: float, container: str) -> Dict[str, object]:
    crash_path = Path(record["crash_path"])
    tokens = list(record.get("container_cmdline_tokens") or [])
    if not tokens:
        return {"status": "skipped", "reason": "no_cmdline"}
    uses_stdin = bool(record.get("uses_stdin"))
    stdin_data = crash_path.read_bytes() if uses_stdin else None
    workdir = str(record.get("container_run_cwd") or record.get("container_project_dir") or f"/src/{record['project']}")
    project_root = str(record.get("container_project_dir") or f"/src/{record['project']}")
    ld_candidates = [
        f"{project_root}/build_afl/lib",
        f"{project_root}/build_afl/lib64",
        f"{project_root}/build/lib",
        f"{project_root}/build/lib64",
        f"{project_root}/lib",
        f"{project_root}/build_afl/lib/openbabel/3.1.0",
        f"{project_root}/build/lib/openbabel/3.1.0",
        f"{project_root}/build/source",
    ]
    ld_path = ':'.join(ld_candidates)
    docker_cmd = [
        "docker",
        "exec",
    ]
    if uses_stdin:
        docker_cmd.append("-i")
    for key, value in docker_replay_env().items():
        docker_cmd += ["-e", f"{key}={value}"]
    docker_cmd += [
        container,
        "sh",
        "-lc",
        'cd "$1" && export LD_LIBRARY_PATH="$2${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && shift 2 && exec "$@"',
        "sh",
        workdir,
        ld_path,
        *tokens,
    ]
    start = time.time()
    try:
        proc = subprocess.run(
            docker_cmd,
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed_ms = round((time.time() - start) * 1000, 2)
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stack_frames = STACK_RE.findall(stderr)[:8]
        sanitizer = bool(ASAN_RE.search(stderr))
        status = "ok"
        if proc.returncode < 0:
            status = "signal"
        elif proc.returncode != 0:
            status = "nonzero"
        if sanitizer:
            status = "sanitizer"
        return {
            "engine": "docker",
            "container": container,
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": status,
            "returncode": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "stderr_head": stderr[:4000],
            "stdout_head": stdout[:1000],
            "stack_frames": stack_frames,
            "sanitizer": sanitizer,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        stderr = (exc.stderr or b"").decode("utf-8", errors="ignore") if isinstance(exc.stderr, (bytes, bytearray)) else str(exc.stderr or "")
        stdout = (exc.stdout or b"").decode("utf-8", errors="ignore") if isinstance(exc.stdout, (bytes, bytearray)) else str(exc.stdout or "")
        return {
            "engine": "docker",
            "container": container,
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": "timeout",
            "returncode": None,
            "elapsed_ms": elapsed_ms,
            "stderr_head": stderr[:4000],
            "stdout_head": stdout[:1000],
            "stack_frames": STACK_RE.findall(stderr)[:8],
            "sanitizer": bool(ASAN_RE.search(stderr)),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "engine": "docker",
            "container": container,
            "command": " ".join(shlex.quote(token) for token in tokens),
            "status": "error",
            "reason": repr(exc),
        }


def command_replay(args: argparse.Namespace) -> None:
    rows = load_jsonl(Path(args.input))
    if args.limit:
        rows = rows[: args.limit]
    out = []
    for row in rows:
        attempts = []
        for _ in range(args.repeats):
            if args.engine == "docker":
                attempts.append(replay_docker(row, timeout=args.timeout, container=args.container))
            else:
                attempts.append(replay_host(row, timeout=args.timeout))
        statuses = [attempt.get("status") for attempt in attempts]
        stable = len(set(statuses)) == 1
        merged = {
            "id": row["id"],
            "project": row["project"],
            "crash_relpath": row["crash_relpath"],
            "engine": args.engine,
            "repeats": args.repeats,
            "stable": stable,
            "statuses": statuses,
            "attempts": attempts,
        }
        out.append(merged)
    count = write_jsonl(Path(args.output), out)
    print(f"WROTE {args.output} ({count} rows)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phase-1 triage helpers for StructRisk.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("index", help="Build a per-crash artifact index for phase-1 projects.")
    p_index.add_argument("--phase1", default=str(DEFAULT_PHASE1))
    p_index.add_argument("--src-root", default=str(DEFAULT_SRC_ROOT))
    p_index.add_argument("--cvss", default=str(DEFAULT_CVSS))
    p_index.add_argument("--per-project-limit", type=int, default=0)
    p_index.add_argument("--output", default=str(DEFAULT_OUT_DIR / "phase1_artifact_index.jsonl"))
    p_index.add_argument("--summary-csv", default=str(DEFAULT_OUT_DIR / "phase1_artifact_summary.csv"))
    p_index.set_defaults(func=command_index)

    p_boot = sub.add_parser("bootstrap", help="Convert artifact index to bootstrap evidence JSONL.")
    p_boot.add_argument("--input", default=str(DEFAULT_OUT_DIR / "phase1_artifact_index.jsonl"))
    p_boot.add_argument("--output", default=str(DEFAULT_OUT_DIR / "phase1_bootstrap_evidence.jsonl"))
    p_boot.set_defaults(func=command_bootstrap)

    p_replay = sub.add_parser("replay", help="Replay indexed crashes with preserved cmdlines.")
    p_replay.add_argument("--input", default=str(DEFAULT_OUT_DIR / "phase1_artifact_index.jsonl"))
    p_replay.add_argument("--output", default=str(DEFAULT_OUT_DIR / "phase1_replay_results.jsonl"))
    p_replay.add_argument("--engine", choices=["host", "docker"], default="host")
    p_replay.add_argument("--container", default="")
    p_replay.add_argument("--limit", type=int, default=0)
    p_replay.add_argument("--repeats", type=int, default=1)
    p_replay.add_argument("--timeout", type=float, default=5.0)
    p_replay.set_defaults(func=command_replay)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "command", None) == "replay" and args.engine == "docker" and not args.container:
        parser.error("--container is required when --engine docker")
    args.func(args)


if __name__ == "__main__":
    main()
