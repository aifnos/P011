"""Shell-only READY scheduling, actual retained-log/live proof, then DRM capture.

No Python observer exists during Receiver foreign-worker startup checks.
The shell hint is never READY authority. The fixed original watcher still
proves exact current candidate PID/start and held READY log before capture.
No input, UI launch, credentials, RF or closure claim; all images stay private.
"""
import argparse
import ast
import datetime
import hashlib
from pathlib import Path
import re
import secrets
import subprocess
import sys
import types


BASE = Path(__file__).resolve().parents[1]
SESSION = '1293b528d39ff32746dbe196'
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
HINT_SOURCE = ('host/capture_formal_receive_ui_v2_ready.py', 4840,
               '59d9fc01845c5ff083192efeb9d41fb9f437cd6f3ff9b60b0dc8faa9a99a8b52')
WATCH_SOURCE = ('host/capture_formal_ui_v7_ready.py', 3650,
                'd3b6934a6b1b1a099345153d615d5cc9ae9c42cb646685187cb8c10e6a5c3c69')


def need(value, code):
    if value is not True: raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'capture_source_pin')
    return raw


def literal(raw, name):
    rows = [row for row in ast.parse(raw).body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'capture_literal')
    value = ast.literal_eval(rows[0].value)
    need(type(value) is str, 'capture_literal_type')
    return value


def bindings():
    hint = literal(fixed(HINT_SOURCE), 'HINT')
    old = '2c3d526c2d034da16e6c4a61'
    need(hint.count(old) == 2 and hint.count('-formal-receive-ui-v1') == 1, 'hint_path_count')
    hint = hint.replace(old, SESSION).replace('-formal-receive-ui-v1', '-formal-receive-filecenter-ui-v1')
    need(not any(word in hint for word in ('python', '/tmp/p011-mta-formal-',
         '/var/volatile/tmp/p011-mta-formal-', 'p011-mta-go-only')), 'hint_foreign_worker_boundary')
    watch = literal(fixed(WATCH_SOURCE), 'WATCH')
    old = 'a44b98dd639095d9063c9e1a'
    need(watch.count(old) == 2 and watch.count('-formal-send-filecenter-ui-v7') == 1, 'watch_path_count')
    watch = watch.replace(old, SESSION).replace('-formal-send-filecenter-ui-v7', '-formal-receive-filecenter-ui-v1')
    ast.parse(watch, feature_version=(3, 5))
    return hint, watch


def save(path, raw):
    with path.open('xb') as handle: need(handle.write(raw) == len(raw), 'capture_write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    hint, watch = bindings()
    transport_raw = fixed(TRANSPORT)
    if not args.check_device:
        print('RECEIVE_FILECENTER_UI_CAPTURE_SOURCE_ONLY; device_not_invoked', flush=True)
        return 0
    out = BASE / 'results' / ('receive-filecenter-ui-v1-ready-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'; private.mkdir(parents=True, exist_ok=False)
    for name, raw in (('hint.sh', hint.encode('ascii')), ('watch.py', watch.encode('ascii')),
                      ('transport-source.py', transport_raw), ('hint-source.py', fixed(HINT_SOURCE)),
                      ('watch-source.py', fixed(WATCH_SOURCE))): save(private / name, raw)
    module = types.ModuleType('fixed_receive_filecenter_ui_capture_transport')
    module.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(transport_raw, module.__file__, 'exec'), module.__dict__)
    adb = module.Adb(private)
    command = '(\n' + hint + "\n); r=$?; printf '\\nMTA_HINT_REMOTE_EXIT=%s\\n' \"$r\""
    raw = adb.run('shell-only-ready-hint', ['shell', command], timeout=75)
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    if (derived.splitlines().count('MTA_RECEIVE_UI_READY_HINT') != 1 or
            re.findall(r'^MTA_HINT_REMOTE_EXIT=(-?\d+)$', derived, re.M) != ['0']):
        print('RECEIVE_FILECENTER_UI_HINT_NOT_OBSERVED; no_python_watch_started', flush=True)
        return 1
    facts = adb.python('fixed-receive-filecenter-ui-ready-readonly', watch, timeout=75)
    need(type(facts) is dict and facts.get('ready') is True and
         facts.get('candidate_live') is True and facts.get('watch_fd_closed') is True,
         'actual_current_ready_not_observed')
    # No model/user round-trip between actual READY and the audited DRM reader.
    result = subprocess.run([sys.executable, '-I', '-B',
        str(BASE / 'host/capture_ui_scanout_v1.py'), '--check-device'], cwd=str(BASE))
    print('RECEIVE_FILECENTER_UI_READY_PRIVATE=' + str(out), flush=True)
    return result.returncode


if __name__ == '__main__': raise SystemExit(main())
