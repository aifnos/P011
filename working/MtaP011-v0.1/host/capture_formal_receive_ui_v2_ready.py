"""Shell-only scheduling hint, then the frozen Receive READY proof and DRM reader.

No Python target observer exists during the original foreign-worker preflight.
The hint is not READY authority; the original held-log/exact-live watcher must
still succeed. No launch, input, RF, state-root argument, retry or closure claim.
"""
import argparse
import datetime
import hashlib
from pathlib import Path
import re
import secrets
import subprocess
import sys
import types

BASE = Path(__file__).resolve().parents[1]
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
WATCHER = ('host/capture_formal_receive_ui_v1_ready.py', 3049,
           'f0c5ef10db89f98807ad8b79676add655520250c4977a432eabc6ccb80600f4d')

# Fixed log/candidate paths only. The real Runner's state/alias/GO root paths
# must not appear in this waiting command line. Tool failure never falls back.
HINT = r'''
candidate=/mnt/data/p011-toolbox/mta-ui/2c3d526c2d034da16e6c4a61/Z03.mta-ui-candidate
log=/var/volatile/tmp/p011-mta-ui-session-2c3d526c2d034da16e6c4a61-formal-receive-ui-v1/candidate.stderr.raw
for tool in readlink tail grep sleep; do command -v "$tool" >/dev/null 2>&1 || exit 3; done
IFS=' ' read -r up ignored < /proc/uptime || exit 3
seconds=${up%%.*}
case "$seconds" in ''|*[!0-9]*) exit 3;; esac
until=$((seconds+65))
sample() {
 count=0
 found=
 for file in /proc/[0-9]*/exe; do
  exe=$(readlink "$file" 2>/dev/null) || continue
  [ "$exe" = "$candidate" ] || continue
  path=${file%/exe}
  pid=${path##*/}
  case "$pid" in ''|*[!0-9]*) continue;; esac
  IFS= read -r line < "$path/stat" || continue
  rest=${line##*) }
  set -f
  set -- $rest
  set +f
  [ "$#" -ge 20 ] || continue
  case "$1" in Z|X) continue;; esac
  shift 19
  case "$1" in ''|*[!0-9]*) continue;; esac
  count=$((count+1))
  found="$pid $1"
 done
 [ "$count" -eq 1 ] && printf '%s\n' "$found"
}
i=0
while [ "$i" -lt 325 ]; do
 IFS=' ' read -r up ignored < /proc/uptime || exit 3
 seconds=${up%%.*}
 case "$seconds" in ''|*[!0-9]*) exit 3;; esac
 [ "$seconds" -lt "$until" ] || exit 2
 if [ -f "$log" ] && tail -c 65536 "$log" 2>/dev/null | grep -F -q 'P011_MTA FORMAL_UI_READY'; then
  before=$(sample)
  if [ -n "$before" ]; then
   after=$(sample)
   if [ "$before" = "$after" ]; then
    printf 'MTA_RECEIVE_UI_READY_HINT\n'
    exit 0
   fi
  fi
 fi
 i=$((i+1))
 sleep 0.2 || exit 3
done
exit 2
'''


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('capture_source_pin')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    original = read_pin(WATCHER)
    transport_raw = read_pin(TRANSPORT)
    if any(word in HINT for word in (
            'python', '/var/volatile/tmp/p011-mta-formal-', '/tmp/p011-mta-formal-',
            'p011-mta-go-only')):
        raise ValueError('hint_foreign_worker_boundary')
    if not args.check_device:
        print('RECEIVE_UI_CAPTURE_V2_SOURCE_ONLY; device_not_invoked', flush=True)
        return 0
    out = BASE / 'results' / ('receive-ui-v2-ready-hint-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    for name, raw in (('watcher-source.py', original), ('transport-source.py', transport_raw),
                      ('hint.sh', HINT.encode('ascii'))):
        with (private / name).open('xb') as handle:
            if handle.write(raw) != len(raw): raise OSError('short_write')
    module = types.ModuleType('fixed_receive_ui_v2_hint_transport')
    module.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(transport_raw, module.__file__, 'exec'), module.__dict__)
    adb = module.Adb(private)
    command = '(\n' + HINT + "\n); r=$?; printf '\\nMTA_HINT_REMOTE_EXIT=%s\\n' \"$r\""
    raw = adb.run('shell-only-ready-hint', ['shell', command], timeout=75)
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    if (derived.splitlines().count('MTA_RECEIVE_UI_READY_HINT') != 1 or
            re.findall(r'^MTA_HINT_REMOTE_EXIT=(-?\d+)$', derived, re.M) != ['0']):
        print('RECEIVE_UI_V2_HINT_NOT_OBSERVED; no_python_watch_started', flush=True)
        return 1
    # No model/user round-trip. This hint grants only scheduling, not acceptance.
    read_pin(WATCHER)
    result = subprocess.run([sys.executable, '-I', '-B', str(BASE / WATCHER[0]),
                             '--check-device'], cwd=str(BASE))
    print('RECEIVE_UI_V2_HINT_PRIVATE=' + str(out), flush=True)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
