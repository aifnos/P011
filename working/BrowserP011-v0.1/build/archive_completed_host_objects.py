"""Archive only five completed, reconstructible browser685 host object trees."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path('/browser-work').resolve()
out = Path('/archive-output').resolve()
names = ['build-host-qtbase', 'build-host-qtshadertools', 'build-host-qtdeclarative',
         'build-host-qtwayland', 'build-host-qtwebchannel']
rows = []
for name in names:
    path = root / name
    if path.is_symlink() or path.resolve().parent != root or not path.is_dir():
        raise SystemExit('Object allowlist boundary failed: ' + str(path))
    cache = path / 'CMakeCache.txt'
    expected = '/browser-work/sources/' + name.removeprefix('build-host-') + '-6.8.5'
    if not cache.is_file() or expected not in cache.read_text(errors='replace'):
        raise SystemExit('Object identity mismatch: ' + str(path))
    if os.stat(path).st_dev != os.stat(root).st_dev:
        raise SystemExit('Unexpected separate mount in object allowlist: ' + str(path))
    size = 0
    count = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        for filename in files:
            file = Path(current) / filename
            if file.is_file() and not file.is_symlink():
                size += file.stat().st_size
                count += 1
    rows.append({'absolute_path': str(path), 'files': count, 'bytes': size,
                 'cache_sha256': hashlib.sha256(cache.read_bytes()).hexdigest()})
token = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
archive = out / ('browser685-completed-host-objects-' + token + '.tar')
part = archive.with_suffix('.tar.part')
if part.exists() or archive.exists():
    raise SystemExit('Archive destination exists')
print(json.dumps({'event': 'archive.begin', 'allowlist': rows, 'archive': str(archive)}), flush=True)
subprocess.run(['tar', '--create', '--file', str(part), '--directory', str(root), *names], check=True)
subprocess.run(['tar', '--compare', '--file', str(part), '--directory', str(root), *names], check=True)
digest = hashlib.sha256()
with part.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
part.rename(archive)
manifest = {'schema': 1, 'purpose': 'Completed browser685 host objects archive',
            'archive': archive.name, 'sha256': digest.hexdigest(), 'bytes': archive.stat().st_size,
            'tar_compare_passed': True, 'inputs': rows, 'released_paths': [],
            'host_qt_install_retained': '/browser-work/host-qt', 'device_touched': False}
manifest_path = archive.with_suffix('.manifest.json')
manifest_path.write_text(json.dumps(manifest, indent=2))
for row in rows:
    path = Path(row['absolute_path'])
    if path.is_symlink() or path.resolve().parent != root or path.name not in names:
        raise SystemExit('Object release boundary failed: ' + str(path))
    cache = path / 'CMakeCache.txt'
    if hashlib.sha256(cache.read_bytes()).hexdigest() != row['cache_sha256']:
        raise SystemExit('Object identity changed after archive: ' + str(path))
    shutil.rmtree(path)
    manifest['released_paths'].append(str(path))
    manifest_path.write_text(json.dumps(manifest, indent=2))
print(json.dumps({'event': 'archive.complete', 'sha256': digest.hexdigest(),
                  'archive_bytes': archive.stat().st_size, 'released_inputs': rows}), flush=True)
