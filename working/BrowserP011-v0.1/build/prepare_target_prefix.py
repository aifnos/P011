"""Populate only the new prefix from read-only caches and verified target libs."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess

prefix = Path('/browser-work/prefix')
prefix.mkdir(parents=True, exist_ok=True)
cache = Path('/old-cache/p011/prefix')
if cache.is_dir() and not (prefix / '.old-prefix-imported').exists():
    shutil.copytree(cache, prefix, dirs_exist_ok=True, symlinks=True)
    for path in (prefix / 'lib/pkgconfig').glob('*.pc'):
        path.write_text(path.read_text().replace('/work/p011/prefix', str(prefix)))
    (prefix / '.old-prefix-imported').touch()

for sub in ['include', 'lib', 'lib/pkgconfig']:
    (prefix / sub).mkdir(parents=True, exist_ok=True)

manifest = json.loads(Path('/target-deps/device-manifest.json').read_text())
for spec in manifest['files']:
    source = Path('/target-deps') / spec['path'].lstrip('/')
    body = source.read_bytes()
    if len(body) != spec['bytes'] or hashlib.sha256(body).hexdigest() != spec['sha256']:
        raise ValueError('Target identity differs: ' + str(source))
    if not body.startswith(b'\x7fELF'):
        continue
    # Keep the cached newly built freetype rather than replacing it with an
    # older vendor build while retaining new freetype development headers.
    if source.name.startswith(('libfreetype', 'libharfbuzz')):
        continue
    dest = prefix / 'lib' / source.name
    if dest.is_symlink():
        dest.unlink()
    dest.write_bytes(body)
    text = subprocess.check_output(['arm-linux-gnueabihf-readelf', '-d', str(dest)], text=True)
    soname = re.search(r'\(SONAME\).*\[(.*?)\]', text)
    if soname:
        for alias in (soname.group(1), source.name.split('.so')[0] + '.so'):
            link = prefix / 'lib' / alias
            if link.name != dest.name and not link.exists():
                link.symlink_to(dest.name)

# These are public C headers; ARM architecture branches are selected by the
# cross compiler. DBus has one generated architecture header, handled below.
for name in ['fontconfig', 'nss', 'nspr', 'xkbcommon']:
    shutil.copytree(Path('/usr/include') / name, prefix / 'include' / name, dirs_exist_ok=True)
for name in ['expat.h', 'expat_external.h']:
    shutil.copyfile(Path('/usr/include') / name, prefix / 'include' / name)
shutil.copytree('/usr/include/dbus-1.0/dbus', prefix / 'include/dbus-1.0/dbus', dirs_exist_ok=True)
arch = Path('/usr/lib/x86_64-linux-gnu/dbus-1.0/include/dbus/dbus-arch-deps.h').read_text()
arch = arch.replace('typedef long dbus_int64_t', 'typedef long long dbus_int64_t')
arch = arch.replace('typedef unsigned long dbus_uint64_t', 'typedef unsigned long long dbus_uint64_t')
arch = arch.replace('(val##L)', '(val##LL)').replace('(val##UL)', '(val##ULL)')
(prefix / 'include/dbus-1.0/dbus/dbus-arch-deps.h').write_text(arch)

def pc(name, version, libs, includes):
    content = f'prefix={prefix}\nlibdir=${{prefix}}/lib\nincludedir=${{prefix}}/include\n'
    content += f'Name: {name}\nDescription: Browser private target C ABI link prefix\nVersion: {version}\n'
    content += f'Libs: -L${{libdir}} {libs}\nCflags: {includes}\n'
    (prefix / 'lib/pkgconfig' / (name + '.pc')).write_text(content)

pc('dbus-1', '1.12.0', '-ldbus-1', '-I${includedir}/dbus-1.0')
pc('fontconfig', '2.12.0', '-lfontconfig -lexpat -lfreetype', '-I${includedir} -I${includedir}/freetype2')
pc('nss', '3.34', '-lssl3 -lsmime3 -lnss3 -lnssutil3 -lplds4 -lplc4 -lnspr4', '-I${includedir}/nss -I${includedir}/nspr')
pc('nspr', '4.0', '-lplds4 -lplc4 -lnspr4', '-I${includedir}/nspr')
pc('xkbcommon', '0.5.0', '-lxkbcommon', '-I${includedir}')
(prefix / 'target-prefix-provenance.json').write_text(json.dumps(dict(
    target_manifest_sha256=hashlib.sha256(Path('/target-deps/device-manifest.json').read_bytes()).hexdigest(),
    status='CONFIGURE_CANDIDATE_NOT_DEVICE_ACCEPTED',
    headers='Public host dev headers, architecture dependent DBus int64 adjusted for ARM32; final target linking required',
    pc_versions='Conservative ABI floors for target libraries, not exact package version claims',
    cached_prefix_readonly=True), indent=2))
print('TARGET_PREFIX_READY=' + str(prefix))
