#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
STRUCTRISK = ROOT / 'StructRisk'
MAGMA_LOCAL = STRUCTRISK / 'external' / 'magma_local' / 'magma-1.2.1'
REPRO_ROOT = STRUCTRISK / 'external' / 'magma_repro'
SRC_ROOT_DEFAULT = REPRO_ROOT / 'src'
MANIFEST_DEFAULT = REPRO_ROOT / 'poc_manifest.jsonl'
PROJECTS_FILE_DEFAULT = REPRO_ROOT / 'projects.txt'
POC_URL_DEFAULT = 'https://osf.io/download/r54yz/'
ASAN_ENV = {
    'ASAN_OPTIONS': 'abort_on_error=1:detect_odr_violation=0:alloc_dealloc_mismatch=0:new_delete_type_mismatch=0:symbolize=1:detect_leaks=0:allocator_may_return_null=1',
    'AFL_SKIP_CPUFREQ': '1',
    'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES': '1',
    'AFL_TRY_AFFINITY': '1',
}
POC_RE = re.compile(
    r'^(?P<fuzzer>.+?)_(?P<project>libpng|libtiff|libxml2|sqlite3|poppler|openssl|php|lua|libsndfile)_(?P<target>.+)_(?P<bug_id>(?:AAH|JCH|MAE|LUA|SND|PHP|SQL|PNG|TIF|XML|PDF|SSL)\d{3})\.[^.]+$'
)
TARGET_CMDLINES = {
    'asn1': ['/magma_out/asn1', '@@'],
    'client': ['/magma_out/client', '@@'],
    'exif': ['/magma_out/exif', '@@'],
    'json': ['/magma_out/json', '@@'],
    'libpng_read_fuzzer': ['/magma_out/libpng_read_fuzzer', '@@'],
    'lua': ['/magma_out/lua', '@@'],
    'parser': ['/magma_out/parser', '@@'],
    'tiff_read_rgba_fuzzer': ['/magma_out/tiff_read_rgba_fuzzer', '@@'],
    'tiffcp': ['/magma_out/tiffcp', '-M', '@@', 'tmp.out'],
    'libxml2_xml_read_memory_fuzzer': ['/magma_out/libxml2_xml_read_memory_fuzzer', '@@'],
    'libxml2_xml_reader_for_file_fuzzer': ['/magma_out/libxml2_xml_reader_for_file_fuzzer', '@@'],
    'xmllint': ['/magma_out/xmllint', '--valid', '--oldxml10', '--push', '--memory', '@@'],
    'sqlite3_fuzz': ['/magma_out/sqlite3_fuzz', '@@'],
    'pdf_fuzzer': ['/magma_out/pdf_fuzzer', '@@'],
    'pdfimages': ['/magma_out/pdfimages', '@@', '/tmp/out'],
    'pdftoppm': ['/magma_out/pdftoppm', '-mono', '-cropbox', '@@'],
    'server': ['/magma_out/server', '@@'],
    'sndfile_fuzzer': ['/magma_out/sndfile_fuzzer', '@@'],
    'unserialize': ['/magma_out/unserialize', '@@'],
    'x509': ['/magma_out/x509', '@@'],
}


def parse_csv_arg(value: str) -> List[str]:
    return [item.strip() for item in (value or '').split(',') if item.strip()]


def write_jsonl(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')


def read_jsonl(path: Path) -> List[Dict[str, object]]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def parse_poc_name(name: str) -> Optional[Dict[str, str]]:
    m = POC_RE.match(Path(name).name)
    if not m:
        return None
    row = m.groupdict()
    row['poc_name'] = Path(name).name
    return row


def ensure_cmdline(path: Path, target: str) -> None:
    tokens = TARGET_CMDLINES.get(target)
    if not tokens:
        raise KeyError(f'unsupported MAGMA target: {target}')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(tokens) + '\n', encoding='utf-8')


def want_poc(meta: Dict[str, str], projects: set, targets: set, bug_ids: set) -> bool:
    if projects and meta['project'] not in projects:
        return False
    if targets and meta['target'] not in targets:
        return False
    if bug_ids and meta['bug_id'] not in bug_ids:
        return False
    if meta['target'] not in TARGET_CMDLINES:
        return False
    return True


def iter_tar_members(tar_path: Optional[Path], poc_url: str):
    if tar_path:
        with tarfile.open(tar_path, 'r:gz') as tar:
            for member in tar:
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                yield member.name, handle.read()
        return
    with urlopen(poc_url) as response:
        with tarfile.open(fileobj=response, mode='r|gz') as tar:
            for member in tar:
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                yield member.name, handle.read()


def command_stage(args: argparse.Namespace) -> None:
    projects = set(parse_csv_arg(args.projects))
    targets = set(parse_csv_arg(args.targets))
    bug_ids = set(parse_csv_arg(args.bug_ids))
    src_root = Path(args.src_root)
    manifest_path = Path(args.manifest)
    if args.clean and src_root.exists():
        shutil.rmtree(src_root)
    if args.clean and manifest_path.exists():
        manifest_path.unlink()

    existing_rows = [] if args.clean else read_jsonl(manifest_path)
    existing_by_key = {
        (row.get('project'), row.get('crash_relpath')): row
        for row in existing_rows
    }
    per_target_counts: Counter[Tuple[str, str]] = Counter()
    per_bug_counts: Counter[str] = Counter()
    for row in existing_rows:
        project = row.get('project')
        target = row.get('target')
        if project and target:
            per_target_counts[(project, target)] += 1
        bug_id = row.get('bug_id')
        if bug_id:
            per_bug_counts[str(bug_id)] += 1
    staged = []
    for member_name, data in iter_tar_members(Path(args.poc_tar) if args.poc_tar else None, args.poc_url):
        meta = parse_poc_name(member_name)
        if not meta or not want_poc(meta, projects, targets, bug_ids):
            continue
        key = (meta['project'], meta['target'])
        if args.limit_per_target and per_target_counts[key] >= args.limit_per_target:
            continue
        if args.limit_per_bug and per_bug_counts[meta['bug_id']] >= args.limit_per_bug:
            continue
        project_dir = src_root / meta['project'] / meta['target']
        crash_dir = project_dir / 'crashes'
        crash_dir.mkdir(parents=True, exist_ok=True)
        ensure_cmdline(project_dir / 'cmdline', meta['target'])
        crash_path = crash_dir / meta['poc_name']
        if not crash_path.exists() or args.overwrite:
            crash_path.write_bytes(data)
        row = {
            'project': meta['project'],
            'target': meta['target'],
            'bug_id': meta['bug_id'],
            'fuzzer': meta['fuzzer'],
            'poc_name': meta['poc_name'],
            'crash_relpath': f"{meta['target']}/crashes/{meta['poc_name']}",
            'cmdline_file': f"{meta['target']}/cmdline",
            'cmdline_tokens': TARGET_CMDLINES[meta['target']],
            'source_member': member_name,
            'source_url': args.poc_url if not args.poc_tar else str(Path(args.poc_tar).resolve()),
            'crash_size': len(data),
        }
        existing_by_key[(row['project'], row['crash_relpath'])] = row
        staged.append(row)
        per_target_counts[key] += 1
        per_bug_counts[meta['bug_id']] += 1

    merged_rows = sorted(
        existing_by_key.values(),
        key=lambda row: (row['project'], row['target'], row['bug_id'], row['poc_name'])
    )
    write_jsonl(manifest_path, merged_rows)
    projects_file = Path(args.projects_file)
    projects_file.parent.mkdir(parents=True, exist_ok=True)
    projects_file.write_text('\n'.join(sorted({row['project'] for row in merged_rows})) + '\n', encoding='utf-8')
    print(f'STAGED {len(staged)} POCs into {src_root}')
    print(f'MANIFEST_ROWS {len(merged_rows)}')
    print(f'PROJECTS {sorted({row["project"] for row in merged_rows})}')
    print(f'WROTE {manifest_path}')
    print(f'WROTE {projects_file}')


def build_env(project: str, fuzzer: str, canary_mode: int) -> Dict[str, str]:
    env = os.environ.copy()
    env['MAGMA'] = str(MAGMA_LOCAL)
    env['FUZZER'] = fuzzer
    env['TARGET'] = project
    env['CANARY_MODE'] = str(canary_mode)
    return env


def command_build(args: argparse.Namespace) -> None:
    projects = parse_csv_arg(args.projects)
    build_script = MAGMA_LOCAL / 'tools' / 'captain' / 'build.sh'
    for project in projects:
        env = build_env(project, args.fuzzer, args.canary_mode)
        if args.base_image:
            env['BASE_IMAGE'] = args.base_image
        if args.fatal_canaries:
            env['ISAN'] = '1'
        print(f'BUILD {project} with {args.fuzzer}', flush=True)
        subprocess.run([str(build_script)], cwd=MAGMA_LOCAL, env=env, check=True)


def docker_result_status(returncode: int, stderr: str) -> str:
    if 'AddressSanitizer:' in stderr or 'SUMMARY:' in stderr:
        return 'sanitizer'
    if returncode < 0:
        return 'signal'
    if returncode != 0:
        return 'nonzero'
    return 'ok'


def run_poc(image: str, src_root: Path, row: Dict[str, object], timeout: float) -> Dict[str, object]:
    workdir = f"/src/{row['project']}/{row['target']}"
    crash_path = f"/src/{row['project']}/{row['crash_relpath']}"
    cmd_tokens = [crash_path if token == '@@' else token for token in list(row['cmdline_tokens'])]
    docker_cmd = [
        'docker', 'run', '--rm',
        '-v', f'{src_root.resolve()}:/src',
        '-w', workdir,
    ]
    for key, value in ASAN_ENV.items():
        docker_cmd += ['-e', f'{key}={value}']
    docker_cmd += ['--entrypoint', 'sh', image, '-lc', 'exec "$@"', 'sh', *cmd_tokens]
    start = time.time()
    proc = subprocess.run(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    elapsed_ms = round((time.time() - start) * 1000, 2)
    stdout = proc.stdout.decode('utf-8', errors='ignore')
    stderr = proc.stderr.decode('utf-8', errors='ignore')
    return {
        'image': image,
        'workdir': workdir,
        'command_tokens': cmd_tokens,
        'command': ' '.join(cmd_tokens),
        'returncode': proc.returncode,
        'elapsed_ms': elapsed_ms,
        'status': docker_result_status(proc.returncode, stderr),
        'stdout': stdout,
        'stderr': stderr,
    }


def append_report(report_path: Path, row: Dict[str, object], result: Dict[str, object]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open('a', encoding='utf-8') as handle:
        handle.write(f"=== FILE: {row['poc_name']}\n")
        handle.write(f"Project: {row['project']}\n")
        handle.write(f"Target: {row['target']}\n")
        handle.write(f"Bug-ID: {row['bug_id']}\n")
        handle.write(f"Image: {result['image']}\n")
        handle.write(f"Workdir: {result['workdir']}\n")
        handle.write(f"Command: {result['command']}\n")
        handle.write(f"Status: {result['status']}\n")
        handle.write(f"Exit code: {result['returncode']}\n")
        handle.write(f"Elapsed ms: {result['elapsed_ms']}\n")
        handle.write('[STDOUT]\n')
        if result['stdout']:
            handle.write(result['stdout'])
            if not result['stdout'].endswith('\n'):
                handle.write('\n')
        handle.write('[STDERR]\n')
        if result['stderr']:
            handle.write(result['stderr'])
            if not result['stderr'].endswith('\n'):
                handle.write('\n')
        handle.write('\n')


def command_replay(args: argparse.Namespace) -> None:
    manifest = read_jsonl(Path(args.manifest))
    if not manifest:
        raise SystemExit(f'empty manifest: {args.manifest}')
    src_root = Path(args.src_root)
    projects = set(parse_csv_arg(args.projects))
    targets = set(parse_csv_arg(args.targets))
    grouped: Dict[Tuple[str, str], List[Dict[str, object]]] = defaultdict(list)
    for row in manifest:
        if projects and row['project'] not in projects:
            continue
        if targets and row['target'] not in targets:
            continue
        grouped[(row['project'], row['target'])].append(row)

    total = 0
    for (project, target), items in sorted(grouped.items()):
        image = f'magma/{args.fuzzer}/{project}'
        report_path = src_root / project / target / args.report_name
        if report_path.exists() and not args.append:
            report_path.unlink()
        for row in sorted(items, key=lambda item: (item['bug_id'], item['poc_name']))[: args.limit or None]:
            print(f'REPLAY {project}/{target}/{row["poc_name"]}', flush=True)
            try:
                result = run_poc(image, src_root, row, timeout=args.timeout)
            except subprocess.TimeoutExpired:
                result = {
                    'image': image,
                    'workdir': f"/src/{project}/{target}",
                    'command': ' '.join(row['cmdline_tokens']),
                    'returncode': None,
                    'elapsed_ms': round(args.timeout * 1000, 2),
                    'status': 'timeout',
                    'stdout': '',
                    'stderr': '',
                }
            append_report(report_path, row, result)
            total += 1
    print(f'REPLAYED {total} PoCs')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Local MAGMA PoC staging/build/replay helpers.')
    sub = parser.add_subparsers(dest='command', required=True)

    p_stage = sub.add_parser('stage', help='Stage MAGMA PoCs under a StructRisk-style src tree.')
    p_stage.add_argument('--poc-url', default=POC_URL_DEFAULT)
    p_stage.add_argument('--poc-tar', default='')
    p_stage.add_argument('--src-root', default=str(SRC_ROOT_DEFAULT))
    p_stage.add_argument('--manifest', default=str(MANIFEST_DEFAULT))
    p_stage.add_argument('--projects-file', default=str(PROJECTS_FILE_DEFAULT))
    p_stage.add_argument('--projects', default='libpng,libtiff,libxml2,sqlite3')
    p_stage.add_argument('--targets', default='')
    p_stage.add_argument('--bug-ids', default='')
    p_stage.add_argument('--limit-per-target', type=int, default=0)
    p_stage.add_argument('--limit-per-bug', type=int, default=0)
    p_stage.add_argument('--overwrite', action='store_true')
    p_stage.add_argument('--clean', action='store_true')
    p_stage.set_defaults(func=command_stage)

    p_build = sub.add_parser('build', help='Build local MAGMA ASAN images for selected projects.')
    p_build.add_argument('--projects', default='libpng,libtiff,libxml2')
    p_build.add_argument('--fuzzer', default='llvm_asan')
    p_build.add_argument('--canary-mode', type=int, default=2)
    p_build.add_argument('--base-image', default='node:24.13.0')
    p_build.add_argument('--fatal-canaries', action='store_true')
    p_build.set_defaults(func=command_build)

    p_replay = sub.add_parser('replay', help='Replay staged PoCs inside local MAGMA docker images.')
    p_replay.add_argument('--manifest', default=str(MANIFEST_DEFAULT))
    p_replay.add_argument('--src-root', default=str(SRC_ROOT_DEFAULT))
    p_replay.add_argument('--projects', default='')
    p_replay.add_argument('--targets', default='')
    p_replay.add_argument('--fuzzer', default='llvm_asan')
    p_replay.add_argument('--timeout', type=float, default=20.0)
    p_replay.add_argument('--limit', type=int, default=0)
    p_replay.add_argument('--report-name', default='crash_output.txt')
    p_replay.add_argument('--append', action='store_true')
    p_replay.set_defaults(func=command_replay)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
