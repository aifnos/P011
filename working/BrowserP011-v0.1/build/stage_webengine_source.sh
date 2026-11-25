#!/bin/sh
set -eu
python3 - <<'PY'
import hashlib, json, pathlib
root = pathlib.Path('/input-downloads')
lock = json.loads((root / 'qt685-official-source-lock.json').read_text())
spec = next(row for row in lock['sources'] if row['module'] == 'qtwebengine')
source = root / 'qtwebengine-everywhere-opensource-src-6.8.5.tar.xz'
digest = hashlib.sha256()
with source.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
if digest.hexdigest() != spec['sha256']:
    raise SystemExit('Official WebEngine archive identity differs')
print(json.dumps(spec))
PY
mkdir -p /browser-work/sources/qtwebengine-6.8.5 /browser-work/host-tools/node
if [ ! -f /browser-work/sources/qtwebengine-6.8.5/.browser685-extracted ]; then
    tar -xJf /input-downloads/qtwebengine-everywhere-opensource-src-6.8.5.tar.xz \
        -C /browser-work/sources/qtwebengine-6.8.5 --strip-components=1
    touch /browser-work/sources/qtwebengine-6.8.5/.browser685-extracted
fi
if [ ! -x /browser-work/host-tools/node/bin/node ]; then
    tar -xJf /input-downloads/node-v20.19.0-linux-x64.tar.xz \
        -C /browser-work/host-tools/node --strip-components=1
fi
cat /browser-work/sources/qtwebengine-6.8.5/CHROMIUM_VERSION
/browser-work/host-tools/node/bin/node --version
grep -R -n -E 'NINJAFLAGS|BUILD_JOBS|NINJA_JOBS|CMAKE_BUILD_PARALLEL_LEVEL|NINJA.*-j' \
    /browser-work/sources/qtwebengine-6.8.5/cmake | head -n 40 || true
