"""Collect the actual ARM browser runtime once, using ordinary SONAME files."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

work = Path('/browser-work')
qt = work / 'target-qt'
out = Path('/browser-output')
runtime = work / 'cxx-runtime-threaded'
prefix = work / 'prefix'
readelf = 'arm-linux-gnueabihf-readelf'
strip = 'arm-linux-gnueabihf-strip'
system_names = {'ld-linux-armhf.so.3', 'libc.so.6', 'libm.so.6', 'libdl.so.2',
                'libpthread.so.0', 'librt.so.1', 'libresolv.so.2', 'libutil.so.1',
                'libEGL.so.1', 'libGLESv2.so.2', 'libmali.so.0', 'libmali.so.0.28.0'}
queue = []
provenance = {}

def copy(source, relative):
    dest = out / relative
    if dest.exists():
        raise SystemExit('Fresh output directory required: ' + str(dest))
    if not source.is_file():
        raise SystemExit('Missing runtime input: ' + str(source))
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source.resolve(), dest)
    provenance[Path(relative).as_posix()] = str(source.resolve())
    if dest.read_bytes()[:4] == b'\x7fELF':
        subprocess.run([strip, '--strip-unneeded', str(dest)], check=True)
        dest.chmod(0o755)
        queue.append(dest)
    else:
        dest.chmod(0o644)

probe = out / 'bin/p011-browser-probe'
subprocess.run([strip, '--strip-unneeded', str(probe)], check=True)
queue.append(probe)
copy(qt / 'libexec/QtWebEngineProcess', Path('libexec/QtWebEngineProcess'))
for folder, patterns in {
    'platforms': ['libqwayland-generic.so', 'libqwayland-egl.so'],
    'wayland-shell-integration': ['libwl-shell-plugin.so'],
    'wayland-graphics-integration-client': ['libqt-plugin-wayland-egl.so'],
    'imageformats': ['*.so'],
    'tls': ['*.so'],
}.items():
    for pattern in patterns:
        matches = list((qt / 'plugins' / folder).glob(pattern))
        if not matches and folder not in {'imageformats', 'tls'}:
            raise SystemExit('Missing plugin: ' + folder + '/' + pattern)
        for source in matches:
            copy(source, Path('plugins') / folder / source.name)

qml_allowed = {'.so', '.qml', '.js', '.mjs', '.qmltypes', '.png', '.svg', '.qsb', '.json', '.metainfo', '.conf'}
for folder in ['QML', 'QtQml', 'QtQuick', 'QtWebChannel', 'QtWebEngine']:
    source_root = qt / 'qml' / folder
    if not source_root.is_dir():
        raise SystemExit('Missing QML module tree: ' + folder)
    for source in sorted(source_root.rglob('*')):
        if source.is_file() and (source.name == 'qmldir' or source.suffix in qml_allowed):
            copy(source, Path('qml') / source.relative_to(qt / 'qml'))

for source in sorted((qt / 'resources').glob('*')):
    if source.is_file() and source.suffix in {'.pak', '.dat', '.bin'}:
        copy(source, Path('resources') / source.name)
for name in ['qtwebengine_resources.pak', 'qtwebengine_resources_100p.pak', 'qtwebengine_resources_200p.pak']:
    if not (out / 'resources' / name).is_file():
        raise SystemExit('Missing Chromium resource: ' + name)
copy(qt / 'translations/qtwebengine_locales/en-US.pak', Path('translations/qtwebengine_locales/en-US.pak'))

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
        old_sysroot = Path('/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot')
        matches = [folder / name for folder in [qt / 'lib', runtime / 'lib', prefix / 'lib',
                                               old_sysroot / 'lib', old_sysroot / 'usr/lib']
                   if (folder / name).is_file()]
        if not matches:
            raise SystemExit('Unresolved private dependency: ' + name)
        copy(matches[0], Path('lib') / name)

# These helpers are the root-reviewed bounded device controller; no font files.
for source in sorted(Path('/runtime-source').glob('*.py')):
    copy(source, Path('runtime') / source.name)
(out / 'bin/qt.conf').write_text('[Paths]\nPrefix=..\nLibraries=lib\nPlugins=plugins\nQmlImports=qml\nTranslations=translations\n', encoding='ascii')
(out / 'libexec/qt.conf').write_text('[Paths]\nPrefix=..\nLibraries=lib\nPlugins=plugins\n', encoding='ascii')
for module in ['qtbase', 'qtdeclarative', 'qtshadertools', 'qtwayland', 'qtwebchannel', 'qtwebengine']:
    for source in sorted((work / ('sources/' + module + '-6.8.5/LICENSES')).glob('*.txt')):
        copy(source, Path('notices') / module / source.name)
for name in ['COPYING3', 'COPYING.RUNTIME']:
    copy(work / 'sources/gcc-11.4.0' / name, Path('notices/gcc-runtime') / name)
for name in ['qt685-official-source-lock.json', 'aux-source-lock.json', 'matching-abi-headers-source-lock.json', 'libdrm-source-lock.json']:
    copy(Path('/input-downloads') / name, Path('notices') / name)
chromium_license = work / 'sources/qtwebengine-6.8.5/src/3rdparty/chromium/LICENSE'
copy(chromium_license, Path('notices/chromium-LICENSE'))
chromium_credits = work / 'build-target-qtwebengine/src/core/Release/arm/gen/components/resources/about_credits.html'
copy(chromium_credits, Path('notices/chromium-third-party-credits.html'))
# This libdrm release stores its permission/copyright notices in the source
# files rather than a top-level COPYING. Preserve the actual core inputs.
for name in ['xf86drm.c', 'xf86drmHash.c', 'xf86drmRandom.c', 'xf86drmSL.c',
             'xf86drmMode.c', 'xf86drm.h', 'xf86drmMode.h', 'xf86atomic.h']:
    copy(work / 'sources/libdrm-2.4.113' / name, Path('notices/libdrm-core-source') / name)
copy(work / 'sources/wayland-1.20.0/COPYING', Path('notices/wayland-COPYING'))
(out / 'notices/BUILD.txt').write_text(
    'Qt WebEngine 6.8.5 ARMv7 hard-float, old glibc 2.27 sysroot.\n'
    'Qt/Chromium official sources unmodified. GN/Ninja bounded jobs=4, 8 or12, Release symbol_level=0, jumbo=off.\n'
    'Build-local GN override angle_enable_vulkan=false; Qt Vulkan backend disabled.\n'
    'Bundled FFmpeg proprietary codecs enabled; WebRTC/PDF/printing disabled for this candidate.\n'
    'GCC 11.4 libstdc++ rebuilt for old ABI with POSIX threads; original SDK libgcc.\n'
    'No vendor GPU drivers and no font files are redistributed.\n'
    'Build definitions accompany this package in working/BrowserP011-v0.1/build.\n'
    'This manifest records host build identity, not device or website acceptance.\n', encoding='utf-8')
app_sources = {}
for source in sorted(Path('/app-source').glob('*')):
    if source.is_file() and source.suffix in {'.cpp', '.h', '.qml', '.html', '.js', '.txt'}:
        body = source.read_bytes()
        app_sources[source.name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
(out / 'notices/app-source-lock.json').write_text(json.dumps(app_sources, indent=2), encoding='utf-8')
files = {}
for path in sorted(out.rglob('*')):
    if not path.is_file() or path.name == 'manifest.json':
        continue
    if path.suffix.lower() in {'.ttf', '.otf', '.woff', '.woff2'}:
        raise SystemExit('Bundled font forbidden: ' + str(path))
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
total = sum(row['bytes'] for row in files.values())
manifest = {'schema': 1, 'status': 'HOST_ARM_LINK_PASS_DEVICE_PENDING',
            'qt_version': '6.8.5', 'webengine_version': '6.8.5',
            'chromium_version': '122.0.6261.171', 'device_tested': False,
            'source_modified': False, 'system_needed': sorted(system_needed),
            'payload_bytes': total, 'preferred_250mib_budget_passed': total <= 250 * 1024 * 1024,
            'files': files}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
largest = sorted(({'path': name, 'bytes': row['bytes']} for name, row in files.items()),
                 key=lambda row: row['bytes'], reverse=True)[:12]
print(json.dumps({'status': manifest['status'], 'payload_bytes': total, 'files': len(files),
                  'preferred_250mib_budget_passed': manifest['preferred_250mib_budget_passed'],
                  'largest_files': largest}, indent=2))
