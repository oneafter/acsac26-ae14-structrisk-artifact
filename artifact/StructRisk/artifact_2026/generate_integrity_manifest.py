#!/usr/bin/env python3
"""Generate deterministic file inventory and SHA-256 checksums for a package."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


EXCLUDED_NAMES = {'SHA256SUMS.txt', 'TREE.txt', 'PACKAGE_METADATA.json', '.DS_Store'}
EXCLUDED_PARTS = {'__pycache__', 'reproduced', '.git'}


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def included_files(root: Path):
    files = []
    for path in root.rglob('*'):
        if not path.is_file() or path.name in EXCLUDED_NAMES:
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def main():
    parser = argparse.ArgumentParser(description='Generate package tree, checksums, and metadata')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--paper-sha256', help='override the paper hash from PAPER_CLAIMS.json')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    version_path = Path(__file__).resolve().parent / 'ARTIFACT_VERSION.txt'
    version = next(line.split(':', 1)[1].strip()
                   for line in version_path.read_text(encoding='utf-8').splitlines()
                   if line.startswith('Artifact version:'))
    claims = json.loads((version_path.parent / 'PAPER_CLAIMS.json').read_text(encoding='utf-8'))
    files = included_files(root)
    tree = '\n'.join(relative.as_posix() for relative in files) + '\n'
    checksums = '\n'.join(f'{sha256(root / relative)}  {relative.as_posix()}' for relative in files) + '\n'
    (root / 'TREE.txt').write_text(tree, encoding='utf-8')
    (root / 'SHA256SUMS.txt').write_text(checksums, encoding='utf-8')
    metadata = {
        'artifact_version': version,
        'paper_submission': 154,
        'paper_sha256': args.paper_sha256 or claims['paper']['sha256'],
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'checksummed_file_count': len(files),
        'checksum_file': 'SHA256SUMS.txt',
        'tree_file': 'TREE.txt',
        'excluded_runtime_directory': 'reproduced/',
    }
    (root / 'PACKAGE_METADATA.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
