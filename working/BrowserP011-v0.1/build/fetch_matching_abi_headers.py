"""Fetch official development sources matching the observed device NSS/NSPR."""
from pathlib import Path
import hashlib
import json
import urllib.request

root = Path('E:/P011-browser-build/downloads')
specs = [
    ('nss', '3.35', 'https://archive.mozilla.org/pub/security/nss/releases/NSS_3_35_RTM/src/',
     'nss-3.35.tar.gz', 'f4127de09bede39f5fd0f789d33c3504c5d261e69ea03022d46b319b3e32f6fa'),
    ('nspr', '4.19', 'https://archive.mozilla.org/pub/nspr/releases/v4.19/src/',
     'nspr-4.19.tar.gz', '2ed95917fa2277910d1d1cf36030607dccc0ba522bba08e2af13c113dcd8f729'),
]
rows = []
for name, version, base, filename, expected in specs:
    checksum_text = urllib.request.urlopen(base + 'SHA256SUMS', timeout=30).read()
    actual_official = next(line.split()[0].decode() for line in checksum_text.splitlines()
                           if line.split()[-1].decode() == filename)
    if actual_official != expected:
        raise SystemExit('Official checksum differs: ' + filename)
    path = root / filename
    if not path.is_file():
        with urllib.request.urlopen(base + filename, timeout=60) as src, path.open('xb') as dest:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dest.write(block)
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != expected:
        raise SystemExit('Source checksum differs: ' + filename)
    (root / (filename + '.official-SHA256SUMS')).write_bytes(checksum_text)
    rows.append({'module': name, 'version': version, 'url': base + filename,
                 'sha256': expected, 'bytes': len(body), 'official_checksum_url': base + 'SHA256SUMS'})
(root / 'matching-abi-headers-source-lock.json').write_text(json.dumps({'sources': rows}, indent=2), encoding='utf-8')
print(json.dumps(rows, indent=2))
