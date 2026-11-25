#!/usr/bin/env python3
"""Verify local archive files. No network, shell command, ADB or device access."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def check(root):
    root = root.resolve()
    manifest = json.loads((root / 'MANIFEST.json').read_text(encoding='utf-8-sig'))
    problems = []
    for number, item in enumerate(manifest['files'], 1):
        rel = PurePosixPath(item['path'])
        if rel.is_absolute() or '..' in rel.parts or ':' in str(rel):
            raise ValueError('Unsafe manifest path: ' + str(rel))
        path = root.joinpath(*rel.parts)
        if root not in path.resolve().parents:
            raise ValueError('Path escaped archive root: ' + str(rel))
        if not path.is_file():
            problems.append({'path': str(rel), 'problem': 'missing'})
        elif path.stat().st_size != item['bytes']:
            problems.append({'path': str(rel), 'problem': 'size mismatch'})
        elif hash_file(path) != item['sha256']:
            problems.append({'path': str(rel), 'problem': 'SHA-256 mismatch'})
        if number % 200 == 0:
            print('Checked {}/{}'.format(number, len(manifest['files'])), flush=True)
    result = {'edition': manifest['edition'], 'checked': len(manifest['files']),
              'passed': not problems, 'problems': problems,
              'note': 'Archive integrity only. Not a device or tool functionality test.'}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not problems else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        return check(args.root)
    except (OSError, ValueError, KeyError) as exc:
        print('VERIFY FAILED: {}'.format(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
