"""Export the finite Qt GUI probe; never distribute vendor drivers or fonts."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

work = Path('/browser-work')
qt = work / 'target-qt'
out = Path('/gui-output')
runtime = work / 'cxx-runtime-threaded'
prefix = work / 'prefix'
readelf = 'arm-linux-gnueabihf-readelf'
strip = 'arm-linux-gnueabihf-strip'
system_names = {
    'ld-linux-armhf.so.3', 'libc.so.6', 'libm.so.6', 'libdl.so.2',
    'libpthread.so.0', 'librt.so.1', 'libresolv.so.2', 'libutil.so.1',
    'libEGL.so.1', 'libGLESv2.so.2', 'libmali.so.0', 'libmali.so.0.28.0',
    'libdrm.so.2',
}
sources = {}
queue = []

def add(source, relative):
    dest = out / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.resolve() != source.resolve():
        raise SystemExit('Fresh export required: ' + str(dest))
    if dest.resolve() != source.resolve():
        shutil.copyfile(source.resolve(), dest)
    subprocess.run([strip, '--strip-unneeded', str(dest)], check=True)
    dest.chmod(0o755)
    sources[str(relative)] = str(source.resolve())
    queue.append(dest)

probe = out / 'bin/p011-browser-gui-probe'
subprocess.run([strip, '--strip-unneeded', str(probe)], check=True)
queue.append(probe)
for folder, pattern in [
    ('platforms', 'libqwayland-*.so'),
    ('wayland-shell-integration', '*wl-shell*.so'),
    ('wayland-graphics-integration-client', '*egl*.so'),
]:
    matched = list((qt / 'plugins' / folder).glob(pattern))
    if not matched:
        raise SystemExit('Required plugin missing: ' + folder + '/' + pattern)
    for source in matched:
        add(source, Path('plugins') / folder / source.name)

system_needed = set()
seen = set()
while queue:
    path = queue.pop(0)
    if str(path) in seen:
        continue
    seen.add(str(path))
    text = subprocess.check_output([readelf, '-d', str(path)], text=True)
    for name in re.findall(r'Shared library: \[([^]]+)\]', text):
        if name in system_names:
            system_needed.add(name)
            continue
        if (out / 'lib' / name).exists():
            continue
        matches = [folder / name for folder in [qt / 'lib', runtime / 'lib', prefix / 'lib']
                   if (folder / name).is_file()]
        if not matches:
            raise SystemExit('Unresolved private dependency: ' + name)
        add(matches[0], Path('lib') / name)

(out / 'bin/qt.conf').write_text('[Paths]\nPrefix=..\nLibraries=lib\nPlugins=plugins\n', encoding='ascii')
notices = out / 'notices'
notices.mkdir(exist_ok=True)
for name in ['LGPL-3.0-only.txt', 'GPL-3.0-only.txt', 'LicenseRef-Qt-Commercial.txt']:
    source = work / 'sources/qtbase-6.8.5/LICENSES' / name
    if source.is_file():
        shutil.copyfile(source, notices / name)
(notices / 'README.txt').write_text(
    'Qt 6.8.5 finite GUI compatibility probe. Qt source modules are unmodified.\n'
    'Build definitions accompany this export in working/BrowserP011-v0.1/build.\n'
    'This package contains no font files and no vendor GPU driver.\n'
    'GCC runtime library exception applies to private libstdc++/libgcc runtime.\n', encoding='utf-8')
files = {}
for path in sorted(out.rglob('*')):
    if not path.is_file() or path.name == 'manifest.json':
        continue
    body = path.read_bytes()
    row = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
           'mode': '0755' if body[:4] == b'\x7fELF' else '0644'}
    if body[:4] == b'\x7fELF':
        text = subprocess.check_output([readelf, '--version-info', str(path)], text=True)
        required = sorted(set(re.findall(r'\bGLIBC_([0-9.]+)', text)),
                          key=lambda value: tuple(map(int, value.split('.'))))
        if any(tuple(map(int, value.split('.'))) > (2, 27) for value in required):
            raise SystemExit('GLIBC gate failed: ' + str(path))
        row['required_glibc'] = required
    files[path.relative_to(out).as_posix()] = row
manifest = {'schema': 1, 'status': 'HOST_ARM_LINK_PASS_DEVICE_PENDING',
            'purpose': 'Finite Qt 6.8.5 Wayland/EGL probe, not WebEngine',
            'qt_version': '6.8.5', 'device_tested': False, 'seconds': 0.9,
            'binary': 'bin/p011-browser-gui-probe', 'no_network': True,
            'source_sha256': hashlib.sha256(Path('/build-defs/qt_gui_probe.cpp').read_bytes()).hexdigest(),
            'frameless': True, 'system_needed': sorted(system_needed), 'files': files,
            'payload_bytes': sum(row['bytes'] for row in files.values())}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(json.dumps(manifest, indent=2))
