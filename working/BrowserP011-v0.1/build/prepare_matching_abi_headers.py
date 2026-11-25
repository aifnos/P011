"""Export version-matched public NSS/NSPR headers into the new browser prefix."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess

work = Path('/browser-work')
prefix = work / 'prefix'
marker = prefix / 'matching-nss-nspr-headers.json'
if marker.is_file():
    print(marker.read_text())
    raise SystemExit(0)
nss = work / 'sources/nss-3.35/nss'
nspr = work / 'sources/nspr-4.19/nspr'
lock = json.loads((work / 'downloads/matching-abi-headers-source-lock.json').read_text())
for row in lock['sources']:
    source = work / 'downloads' / row['url'].rsplit('/', 1)[-1]
    if hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']:
        raise SystemExit('Official source identity failed: ' + str(source))
for name, old_version in [('nss', '3.98'), ('nspr', '4.35')]:
    current = prefix / 'include' / name
    previous = prefix / 'include' / (name + '-previous-host-' + old_version)
    if not previous.exists():
        current.rename(previous)
        current.mkdir()
    elif not current.is_dir():
        raise SystemExit('Partial header export has no candidate directory: ' + str(current))

count = 0
for manifest in sorted((nss / 'lib').rglob('manifest.mn')):
    text = manifest.read_text().replace('\\\n', ' ')
    for match in re.finditer(r'^EXPORTS\s*\+?=\s*(.*)$', text, re.MULTILINE):
        for name in match.group(1).split():
            if not name.endswith('.h') or '$' in name:
                continue
            source = manifest.parent / name
            if not source.is_file():
                matches = list(manifest.parent.rglob(Path(name).name))
                if len(matches) == 1:
                    source = matches[0]
            dest = prefix / 'include/nss' / source.name
            if not source.is_file():
                raise SystemExit('Public NSS export missing: ' + str(source))
            if dest.is_file() and dest.read_bytes() != source.read_bytes():
                raise SystemExit('Conflicting public NSS header: ' + source.name)
            shutil.copyfile(source, dest)
            count += 1
for source in sorted((nspr / 'pr/include').glob('*.h')):
    shutil.copyfile(source, prefix / 'include/nspr' / source.name)
for sub in ['obsolete', 'private']:
    shutil.copytree(nspr / 'pr/include' / sub, prefix / 'include/nspr' / sub)
for source in sorted((nspr / 'lib').glob('*/**/*.h')):
    if source.name in {'plarena.h', 'plbase64.h', 'plgetopt.h', 'plhash.h', 'plstr.h', 'plerror.h'}:
        shutil.copyfile(source, prefix / 'include/nspr' / source.name)
shutil.copyfile(nspr / 'pr/include/md/_linux.cfg', prefix / 'include/nspr/prcpucfg.h')
for name, version in [('nss', '3.35'), ('nspr', '4.19')]:
    path = prefix / ('lib/pkgconfig/' + name + '.pc')
    text = re.sub(r'^Version:.*$', 'Version: ' + version, path.read_text(), flags=re.MULTILINE)
    path.write_text(text)
probe = work / 'matching-nss-nspr-header-probe.cpp'
probe.write_text('''#include <nss.h>
#include <prinit.h>
#include <secitem.h>
static_assert(sizeof(void*) == 4, "ARM32 headers required");
static_assert(NSS_VMAJOR == 3 && NSS_VMINOR == 35, "NSS version mismatch");
static_assert(PR_VMAJOR == 4 && PR_VMINOR == 19, "NSPR version mismatch");
int main() { return NSS_GetVersion() && PR_GetVersion() ? 0 : 1; }
''')
sysroot = '/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot'
subprocess.run(['arm-linux-gnueabihf-g++-11', '--sysroot=' + sysroot,
                '-B' + sysroot + '/usr/lib/', '-B' + sysroot + '/lib/',
                '-march=armv7-a', '-mfpu=neon', '-mfloat-abi=hard',
                '-nostdinc', '-nostdinc++', '-isystem', '/usr/lib/gcc-cross/arm-linux-gnueabihf/11/include',
                '-isystem', sysroot + '/usr/include', '-I' + str(prefix / 'include/nss'),
                '-I' + str(prefix / 'include/nspr'), str(probe), '-L' + str(prefix / 'lib'),
                '-Wl,-rpath-link,' + str(prefix / 'lib'), '-lnss3', '-lnspr4',
                '-o', str(work / 'matching-nss-nspr-header-probe')], check=True)
result = {'status': 'HOST_ARM_HEADER_LINK_PASS_DEVICE_PENDING', 'nss_headers': '3.35',
          'nspr_headers': '4.19', 'nss_public_header_count': count,
          'nss_runtime_evidence': 'Version: NSS 3.35 string in verified device ELF',
          'nspr_runtime_evidence': 'nspr-4.19 build path and 4.19 string in verified device ELF',
          'source_lock': lock, 'device_tested': False}
marker.write_text(json.dumps(result, indent=2))
print(marker.read_text())
