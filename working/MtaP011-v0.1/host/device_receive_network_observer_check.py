"""Explicit P011 readonly test of the actual network observer producer.

Only a unique private volatile directory and one pinned helper are written.
No MTA admission, radio/network mutations or old pending disposition. The
actual Python producer retains two original FD/Popen/pipe calls. Identifiers,
raw observations and original stdout/stderr remain private.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
BINARY = 'results/receive-network-observer-build-20261004-120127-0ce26786/mta-connman-observer'
PINS = {
    BINARY: (46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2'),
    'runtime/mta_receive_network.py': (15860, '1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6'),
    'runtime/p011_json.py': (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    'host/device_probe.py': (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(name, raw):
    data = base64.b64encode(raw).decode('ascii')
    return name + '=(\n' + ''.join(repr(data[n:n+128]) + '\n' for n in range(0, len(data), 128)) + ')\n'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def actual_remote(adb, source):
    data = (source + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    if any(len(line) > 512 for line in data.splitlines()):
        raise ValueError('legacy_terminal_line_limit')
    # Arm before canonical stdin input. Chunked lines avoid the earlier
    # oversized canonical terminal line failure; preserve the raw echo.
    command = ('python3 -B -c "import signal,sys;signal.alarm(55);'
        'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-network-observer-readonly; '
        'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    raw = adb.run('actual-observer', ['shell', command], timeout=65, input_data=data)
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = derived.splitlines()
    results = [line[7:] for line in rows if line.startswith('RESULT=')]
    if (rows.count('MTA_REMOTE_OK') != 1 or len(results) != 1 or
            re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M) != ['0']):
        raise RuntimeError('observer_remote_failed')
    return ast.literal_eval(results[0])


REMOTE = r'''
import base64,hashlib,os,stat,sys,time,types
def pending():
 p='/var/volatile/tmp/p011-mta-p2p-device.pending'
 try:s=os.lstat(p)
 except FileNotFoundError:return None
 if not stat.S_ISREG(s.st_mode) or s.st_size>1048576:raise ValueError('pending_unknown')
 fd=os.open(p,0x88000)
 try:
  h=hashlib.sha256();count=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   count+=len(b)
   if count>1048576:raise ValueError('pending_limit')
   h.update(b)
  a=os.fstat(fd)
 finally:os.close(fd)
 if (s.st_dev,s.st_ino,s.st_size,s.st_mtime)!=(a.st_dev,a.st_ino,a.st_size,a.st_mtime):raise ValueError('pending_changed')
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime,h.hexdigest())
if os.getuid()!=0 or os.uname()[4]!='armv7l':raise ValueError('target_profile')
if os.path.realpath('/tmp')!='/var/volatile/tmp':raise ValueError('target_anchor')
for p in ('/var','/var/volatile','/var/volatile/tmp'):
 s=os.lstat(p)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0:raise ValueError('target_anchor')
before_pending=pending()
raw=base64.b64decode(BINARY_DATA)
if len(raw)!=BINARY_SIZE or hashlib.sha256(raw).hexdigest()!=BINARY_SHA:raise ValueError('binary_changed')
os.mkdir(STAGE,0o700)
binary=STAGE+'/mta-connman-observer'
fd=os.open(binary,1|0x40|0x80|0x88000,0o700)
try:
 at=0
 while at<len(raw):
  n=os.write(fd,raw[at:])
  if n<=0:raise ValueError('stage_short_write')
  at+=n
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size!=len(raw):raise ValueError('stage_identity')
finally:os.close(fd)
for name,payload,expected_size,expected_sha in MODULES:
 src=base64.b64decode(payload)
 if len(src)!=expected_size or hashlib.sha256(src).hexdigest()!=expected_sha:raise ValueError('source_changed')
 module=types.ModuleType(name);module.__file__='<pinned-private-observer-memory>'
 sys.modules[name]=module
 exec(compile(src,module.__file__,'exec'),module.__dict__)
network=sys.modules['mta_receive_network']
until=time.monotonic()+24.0
observer=network.NetworkObserver.__new__(network.NetworkObserver)
observer.__init__(binary,BINARY_SIZE,BINARY_SHA,until,clock=time.monotonic)
first=observer.observe(until)
second=observer.observe(until)
rows=[]
for observed in (first,second):
 t=observed._ticket;p=t['process']
 rows.append({'valid':observed.valid,'error':observed.error,
  'resources_closed':observed.resources_closed(),'stdout':observed.raw_stdout,
  'stderr':observed.raw_stderr,'exit':None if p is None else p.returncode,
  'reaped':t['reaped'],'binary_fd_closed':t['fd_closed'],
  'spawn_resolved':t['spawn_resolved']})
after_pending=pending()
print('RESULT='+repr({'rows':rows,'same':network.compare_observations(first,second),
 'observer_closed':observer.close(),'pending_unchanged':before_pending==after_pending,
 'pending_present':before_pending is not None,'stage_bytes':s.st_size}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-network-observer-' + ('device-' if args.check_device else 'source-') + stamp)
    out.mkdir(parents=True)
    report = {'passed': False, 'device_attempted': False, 'device_tested': False,
        'observations_valid': False, 'observations_same': False, 'observer_resources_closed': False,
        'limited_stock_unchanged': False, 'pending_unchanged': None, 'pending_present': None,
        'pending_removed': False, 'rf_mutation_requested': False, 'receive_admission': False,
        'receive_tested': False, 'phone_tested': False, 'full_network_restore_verified': False,
        'profile_bytes_observed': False, 'source_preserved': False, 'inputs': [], 'error': None}
    originals = {}
    try:
        for name, pin in PINS.items():
            raw = (BASE / name).read_bytes()
            if (len(raw), sha(raw)) != pin:
                raise ValueError('input_identity_changed')
            originals[name] = raw
        name = 'host/device_receive_network_observer_check.py'
        originals[name] = Path(__file__).read_bytes()
        for name, raw in originals.items():
            target = out / 'private-inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            report['inputs'].append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
        ast.parse(originals['runtime/mta_receive_network.py'].decode('utf-8'), feature_version=(3, 5))
        ast.parse(REMOTE, feature_version=(3, 5))
        if args.check_device:
            probe = load('_network_readonly_device_probe', BASE / 'host/device_probe.py')
            adb = probe.Adb(out / 'private-raw')
            before = adb.python('before', probe.source())
            if before['stock']['hashes'] != probe.PINS:
                raise ValueError('stock_identity_changed')
            names = ('Z03', 'control_engine', 'weston')
            if not all(sum(row['name'] == name for row in before['stock']['processes']) == 1 for name in names):
                raise ValueError('stock_process_unknown')
            raw = originals[BINARY]
            source = encoded('BINARY_DATA', raw)
            source += 'BINARY_SIZE=%r\nBINARY_SHA=%r\n' % (len(raw), sha(raw))
            source += 'STAGE=%r\n' % ('/var/volatile/tmp/p011-mta-network-baseline-' + stamp)
            for variable, name in (('CODEC_DATA', 'runtime/p011_json.py'),
                                   ('OBSERVER_DATA', 'runtime/mta_receive_network.py')):
                source += encoded(variable, originals[name])
            source += 'MODULES=[\n'
            for module, variable, name in (('p011_json', 'CODEC_DATA', 'runtime/p011_json.py'),
                                          ('mta_receive_network', 'OBSERVER_DATA', 'runtime/mta_receive_network.py')):
                source += '(%r,%s,%r,%r),\n' % (module, variable, len(originals[name]), sha(originals[name]))
            source += ']\n' + REMOTE
            (out / 'target-source-private.py').write_text(source, encoding='utf-8')
            report['device_attempted'] = True
            actual = actual_remote(adb, source)
            report['device_tested'] = True
            report['remote_exit'] = 0
            rows = actual['rows']
            report['observations_valid'] = len(rows) == 2 and all(row['valid'] is True for row in rows)
            report['observations_same'] = actual['same'] is True
            report['observer_resources_closed'] = (actual['observer_closed'] is True and len(rows) == 2 and
                all(row['resources_closed'] is True and row['reaped'] is True and
                    row['binary_fd_closed'] is True and row['spawn_resolved'] is True for row in rows))
            report['observer_exit_codes'] = [row['exit'] for row in rows]
            report['observer_stderr_bytes'] = [None if row['stderr'] is None else len(row['stderr']) for row in rows]
            report['observer_errors'] = [row['error'] for row in rows]
            report['pending_unchanged'] = actual['pending_unchanged'] is True
            report['pending_present'] = actual['pending_present'] is True
            after = adb.python('after', probe.source())
            report['limited_stock_unchanged'] = before['stock'] == after['stock']
        report['source_preserved'] = all((BASE / name).read_bytes() == raw for name, raw in originals.items())
        report['passed'] = report['source_preserved'] and (not args.check_device or all(report[field] is True
            for field in ('observations_valid', 'observations_same', 'observer_resources_closed',
                          'limited_stock_unchanged', 'pending_unchanged')))
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'error-private.txt').write_text(str(error), encoding='utf-8')
    (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text(
        'Actual P011 observer producer executes only with explicit --check-device.\n'
        'Two original pinned ARM FD/Popen/pipe calls; no fixtures or RF mutation.\n'
        'Exclusive new volatile helper retained. Old pending and stock untouched.\n'
        'Same read-only ConnMan data is not recovery after a transfer or phone acceptance.\n'
        'Profile file bytes are NOT observed. Private addresses/service paths/raw stay local.\n', encoding='utf-8')
    with zipfile.ZipFile(out / 'public-result.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, ensure_ascii=False))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
