"""Fixed v39 actual readonly baseline; default SOURCE only, no automatic ADB.

ROOT reviews this exact driver before --read-current, an explicit transport ID
and this exact driver SHA are supplied together. The one target invocation is
stdin Python definitions + actual readonly leaf collect(); it writes no target
files and never starts F/Parent/Stage/RF. Timeout is retained, not retried.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import types
import zipfile

BASE = Path(__file__).absolute().parents[1]
STATIC = BASE / 'host/client_static_stage_v38.py'
STATIC_SHA = 'b5659c2af52a4af99fc28882d2f53c73847d584a2f92201f77f3ab1e34142bdf'
MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
LEAF = BASE / 'candidate/client-readonly-baseline-v39/runtime/mta_client_readonly_baseline.py'
LEAF_SHA = 'cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff'
ADB = Path('C:/Program Files/ADB/adb.exe')
ADB_SHA = 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f'
MAX_BYTES = 67108864
REMOTE_COMMAND = 'python3 -B -; mta_v39_rc=$?; printf "\\nP011_V39_EXIT=%s\\n" "$mta_v39_rc"'
BOOLS = ('attempted', 'ended', 'read_success', 'resource_pending', 'neutral_store_opened',
    'pending_absence_before', 'pending_absence_after', 'staging_attempted', 'rf_requested',
    'restoration_verified', 'source_factory_ready', 'send_available', 'receive_available', 'phone_tested')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _fixed(path, pin, size=None):
    if any(item.is_symlink() for item in (path,) + tuple(path.parents)):
        raise ValueError('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_BYTES:
        raise ValueError('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(MAX_BYTES + 1)
    after = path.stat()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
    if (any(getattr(before, name) != getattr(opened, name) or
            getattr(before, name) != getattr(after, name) for name in keys) or
            before.st_ctime_ns != after.st_ctime_ns or len(raw) != before.st_size or
            size is not None and len(raw) != size or _sha(raw) != pin):
        raise ValueError('source_changed')
    return raw


def source_check():
    # Execute only this already-reviewed PC source-reader definition. Its
    # private __name__ prevents its main; candidate modules remain mere bytes.
    raw = _fixed(STATIC, STATIC_SHA, 10402)
    helper = types.ModuleType('v39_fixed_static_reader')
    helper.__file__ = str(STATIC)
    exec(compile(raw, '<v39-fixed-pc-source-reader>', 'exec'), helper.__dict__)
    checked, rows, native, manifest_raw, stage_raw = helper.source_check()
    leaf_raw = _fixed(LEAF, LEAF_SHA, 13811)
    if checked['source_manifest_sha256'] != MANIFEST_SHA or len(rows) != 35:
        raise ValueError('source_graph')
    self_raw = Path(__file__).absolute().read_bytes()
    report = {'schema': 'client-readonly-baseline-v39', 'source_check_pass': True,
        'source_manifest_sha256': MANIFEST_SHA, 'driver_sha256': _sha(self_raw),
        'leaf_sha256': LEAF_SHA, 'source_count': 35, 'adb_invoked': False,
        'target_selected': False, 'readonly_payload_started': False,
        'read_success': False, 'remote_closure_verified': False,
        'full_native_rounds': 0, 'resource_pending': True,
        'staging_attempted': False, 'rf_requested': False, 'parent_started': False,
        'restoration_verified': False, 'source_factory_ready': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False,
        'reason': 'source_only'}
    return report, rows, leaf_raw


TARGET_BODY = r'''
import base64,hashlib,os,sys,time,traceback,types
issued=time.monotonic();original_until=issued+30.0
modules={};owner=None;public=None;private={'error':None}
def projection(value):
 if value is None or type(value) in (str,int,float,bool):return value
 if type(value) is bytes:return {'bytes_b64':base64.b64encode(value).decode('ascii'),'bytes':len(value)}
 ip=modules.get('mta_ip')
 if ip is not None and type(value) in (ip.IpSnapshot,ip.AddressRecord,ip.RouteRecord,ip.RuleRecord):return {key:projection(getattr(value,key)) for key in type(value)._fields}
 if type(value) in (tuple,list):return [projection(row) for row in value]
 if type(value) is dict:return {key:projection(row) for key,row in value.items()}
 if hasattr(type(value),'__slots__'):return {key:projection(getattr(value,key)) for key in type(value).__slots__ if not key.startswith('_')}
 raise ValueError('private_projection_type')
try:
 if sys.flags.optimize or sys.platform!='linux' or os.uname()[4]!='armv7l' or os.geteuid()!=0 or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_platform')
 for name,pin,encoded in SOURCES:
  raw=base64.b64decode(encoded)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('target_source_pin')
  value=types.ModuleType(name);value.__file__='<v39-fixed-source-'+name+'>'
  sys.modules[name]=value;modules[name]=value
  exec(compile(raw,value.__file__,'exec'),value.__dict__)
 raw=base64.b64decode(LEAF_DATA)
 if hashlib.sha256(raw).hexdigest()!=LEAF_PIN:raise ValueError('target_leaf_pin')
 leaf=types.ModuleType('mta_client_readonly_baseline');leaf.__file__='<v39-fixed-readonly-leaf>'
 sys.modules[leaf.__name__]=leaf
 exec(compile(raw,leaf.__file__,'exec'),leaf.__dict__)
 owner=leaf.ReadonlyBaselineOwner(RUN_TOKEN,original_until)
 result=owner.collect()
 public=owner.status()
 if owner.result is not result or public['read_success'] is not True or public['resource_pending'] is not False:raise ValueError('target_read_unclosed')
except BaseException:
 private['error']=traceback.format_exc()[:16384]
finally:
 if owner is not None:
  private['owner_status']=owner.status();private['snapshot']=projection(owner.result)
  private['platform_before']=projection(owner.platform_before);private['platform_after']=projection(owner.platform_after)
  private['issued_at']=owner.issued_at;private['until']=owner.until
  private['collectors']=[]
  for row in owner.collector_rows:
   collector=row['collector'];entry={'unknown':row['unknown'],'returned':row['returned']}
   if collector is not None:
    entry['status']=collector.status();entry['raw']=projection(collector._raw)
    entry['rounds']=projection(collector._rounds)
    entry['tickets']=[{key:projection(ticket.get(key)) for key in
     ('kind','fd','unknown','attempted','closed','kill_attempted','waited','pipe_refs_valid')} for ticket in collector._tickets]
   private['collectors'].append(entry)
  reader=owner.reader
  private['proc']={'pending':reader._pending,'active':reader._active,'history_active':reader._history_active,
   'history_closed':reader.history_closed(),'history':[]}
  for generation in reader._history:
   private['proc']['history'].append({'ordinal':generation.ordinal,'ended':generation.ended,
    'active':generation.active,'unknown':generation.unknown,'late':generation.late,
    'raw':projection(generation.raw),'tickets':[{key:projection(getattr(ticket,key)) for key in
     ('ordinal','descriptor','open_called','returned','registered','failed_without_fd','close_attempted',
      'close_returned','close_result','ebadf_observed','ebadf_errno','unknown')} for ticket in generation.tickets]})
  private['budget']=projection(owner.budget.status())
  if public is None:public=owner.status()
 if public is None:
  public={'evidence':'CLIENT_READONLY_BASELINE_V39_ONLY','source_manifest_sha256':SOURCE_MAP,
   'attempted':False,'ended':False,'read_success':False,'resource_pending':True,'neutral_store_opened':False,
   'pending_absence_before':False,'pending_absence_after':False,'full_native_rounds':0,
   'staging_attempted':False,'rf_requested':False,'restoration_verified':False,'source_factory_ready':False,
   'send_available':False,'receive_available':False,'phone_tested':False}
 codec=modules.get('p011_json')
 if codec is None:raise ValueError('target_json_unavailable')
 encoded_private=codec.dumps(private,sort_keys=True)
 if len(encoded_private.encode('utf-8'))>16777216:raise ValueError('target_private_budget')
 print('P011_V39_PRIVATE='+encoded_private)
 print('P011_V39_PUBLIC='+codec.dumps(public,sort_keys=True))
 print('P011_V39_DONE')
if private['error'] is not None:raise SystemExit(1)
'''


def _payload(rows, leaf_raw, token):
    sources = [(name, pin, base64.b64encode(raw).decode('ascii')) for name, size, pin, raw in rows]
    header = ('SOURCES=' + repr(sources) + '\nLEAF_DATA=' + repr(base64.b64encode(leaf_raw).decode('ascii')) +
        '\nLEAF_PIN=' + repr(LEAF_SHA) + '\nRUN_TOKEN=' + repr(token) + '\nSOURCE_MAP=' + repr(MANIFEST_SHA) + '\n')
    return (header + TARGET_BODY).encode('utf-8')


def _run(private, stem, argv, input_data=None, timeout=45):
    before = time.monotonic()
    timed_out, code = False, None
    try:
        value = subprocess.run(argv, input=input_data, capture_output=True, timeout=timeout)
        stdout, stderr, code = value.stdout, value.stderr, value.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, timed_out = error.stdout or b'', error.stderr or b'', True
    except BaseException:
        # Record that no actual return is available; do not invent an exit.
        (private / (stem + '.host-exit')).write_text('UNRETURNED', encoding='ascii')
        raise
    (private / (stem + '.stdout.raw')).write_bytes(stdout)
    (private / (stem + '.stderr.raw')).write_bytes(stderr)
    (private / (stem + '.host-exit')).write_text('TIMEOUT' if timed_out else str(code), encoding='ascii')
    (private / (stem + '.remote-exit')).write_text('NOT_OBSERVED', encoding='ascii')
    elapsed = time.monotonic() - before
    return stdout, stderr, code, timed_out, elapsed


def _select(raw, requested):
    if type(requested) is not str or re.fullmatch('[1-9][0-9]{0,9}', requested) is None or len(raw) > 262144:
        raise ValueError('target_input')
    found = []
    for line in raw.decode('utf-8', 'strict').splitlines():
        words = line.split()
        if len(words) < 2 or words[1] != 'device' or words[0].startswith('emulator-'):
            continue
        attrs = words[2:]
        if 'product:sprdtrum' not in attrs or 'model:sprdisk' not in attrs:
            continue
        values = [word[13:] for word in attrs if word.startswith('transport_id:')]
        if len(values) != 1 or re.fullmatch('[1-9][0-9]{0,9}', values[0]) is None:
            raise ValueError('target_enumeration')
        found.append(values[0])
    if found != [requested]:
        raise ValueError('target_not_unique')
    return requested


def _remote_exit(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('remote_output_budget')
    # Derived view only; originals remain byte-for-byte private files.
    lines = raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n').splitlines()
    exit_rows = [line[14:] for line in lines if line.startswith('P011_V39_EXIT=')]
    if len(exit_rows) != 1 or re.fullmatch('[0-9]{1,3}', exit_rows[0]) is None:
        raise ValueError('remote_exit_unknown')
    code = int(exit_rows[0])
    if code > 255:
        raise ValueError('remote_exit_unknown')
    return code, lines


def _decode(raw):
    code, lines = _remote_exit(raw)
    public_rows = [line[16:] for line in lines if line.startswith('P011_V39_PUBLIC=')]
    private_rows = [line[17:] for line in lines if line.startswith('P011_V39_PRIVATE=')]
    if len(public_rows) != 1 or len(private_rows) != 1 or lines.count('P011_V39_DONE') != 1:
        raise ValueError('remote_protocol')
    value = json.loads(public_rows[0])
    expected = set(BOOLS) | {'evidence', 'source_manifest_sha256', 'full_native_rounds'}
    if (type(value) is not dict or set(value) != expected or
            any(type(value[key]) is not bool for key in BOOLS) or
            value['evidence'] != 'CLIENT_READONLY_BASELINE_V39_ONLY' or
            value['source_manifest_sha256'] != MANIFEST_SHA or
            type(value['full_native_rounds']) is not int or not 0 <= value['full_native_rounds'] <= 2):
        raise ValueError('remote_projection')
    if any(value[key] for key in ('neutral_store_opened', 'staging_attempted', 'rf_requested',
            'restoration_verified', 'source_factory_ready', 'send_available', 'receive_available', 'phone_tested')):
        raise ValueError('remote_scope')
    # Private JSON stays only in raw; decoding public fields cannot grant stage.
    return value, code


def _publish(output, report, pins):
    members = [('result.json', json.dumps(report, indent=2).encode('utf-8')),
        ('source-pins.json', json.dumps(pins, indent=2).encode('utf-8')),
        ('README.txt', ('Readonly baseline only. No staging, F/Parent/RF, ready, recovery or phone proof.\n'
            'Private raw includes identifiers/IP/process/source evidence and is excluded from this ZIP.\n'
            'HOST return, remote marker and native read/closure are distinct; failures/timeouts are not retried.\n'
            'Raw stdout/stderr are exactly the ADB host streams; exec-out does not promise a separate remote stderr channel.\n'
            'Full baseline is not atomicity or formal RF admission. No user/Received paths are created.\n').encode('utf-8'))]
    members.append(('SHA256SUMS.txt', ''.join(_sha(raw) + '  ' + name + '\n' for name, raw in members).encode('ascii')))
    for name, raw in members:
        with (output / name).open('xb') as handle:
            handle.write(raw)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members:
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive, 'r') as bundle:
        if bundle.namelist() != [name for name, raw in members] or bundle.testzip() is not None:
            raise ValueError('public_zip_crc')
        if any(bundle.getinfo(name).file_size != len(raw) or bundle.read(name) != raw for name, raw in members):
            raise ValueError('public_zip_readback')


def read_current(expected_driver, transport):
    report, rows, leaf_raw = source_check()
    if (type(expected_driver) is not str or re.fullmatch('[0-9a-f]{64}', expected_driver) is None or
            expected_driver != report['driver_sha256'] or type(transport) is not str or
            re.fullmatch('[1-9][0-9]{0,9}', transport) is None):
        raise ValueError('reviewed_input')
    _fixed(ADB, ADB_SHA)
    parent = BASE / 'results'
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('result_parent')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = parent / ('client-readonly-baseline-v39-' + stamp + '-' + os.urandom(4).hex())
    output.mkdir(exist_ok=False)
    private = output / 'private-raw'
    private.mkdir(exist_ok=False)
    pins = {'manifest_sha256': MANIFEST_SHA, 'leaf_sha256': LEAF_SHA, 'static_reader_sha256': STATIC_SHA,
        'adb_exe_sha256': ADB_SHA, 'sources': [[name, size, pin] for name, size, pin, raw in rows]}
    try:
        report['adb_invoked'] = True
        raw, err, code, timeout, elapsed = _run(private, '01-enumeration', [str(ADB), 'devices', '-l'], timeout=10)
        if timeout or code != 0:
            raise ValueError('enumeration_failed')
        selected = _select(raw, transport)
        report['target_selected'] = True
        token = os.urandom(16).hex()
        payload = _payload(rows, leaf_raw, token)
        with (private / 'payload.py').open('xb') as handle:
            handle.write(payload)
        report['readonly_payload_started'] = True
        raw, err, code, timeout, elapsed = _run(private, '02-native-readonly',
            [str(ADB), '-t', selected, 'exec-out', REMOTE_COMMAND], input_data=payload)
        report.update(host_exit=code, host_timeout=timeout, host_seconds=elapsed)
        remote = _remote_exit(raw)[0]
        (private / '02-native-readonly.remote-exit').write_text(str(remote), encoding='ascii')
        report['remote_exit'] = remote
        native, remote = _decode(raw)
        report.update(remote_exit=remote, full_native_rounds=native['full_native_rounds'],
            resource_pending=native['resource_pending'])
        good = (code == 0 and not timeout and remote == 0 and native['read_success'] and
            native['attempted'] and native['ended'] and not native['resource_pending'] and
            native['pending_absence_before'] and native['pending_absence_after'] and native['full_native_rounds'] == 2)
        closed = (not timeout and code == 0 and native['attempted'] and native['ended'] and
            not native['resource_pending'])
        report.update(read_success=bool(good), remote_closure_verified=bool(closed),
            reason='read_closed' if good else 'readonly_failed')
    except BaseException as error:
        report.update(read_success=False, remote_closure_verified=False, reason='readonly_failed')
        (private / 'driver-error.txt').write_text(type(error).__name__, encoding='ascii')
    _publish(output, report, pins)
    report['result_directory'] = str(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-current', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    parser.add_argument('--transport-id')
    args = parser.parse_args(argv)
    if args.read_current != (args.expected_driver_sha256 is not None) or args.read_current != (args.transport_id is not None):
        parser.error('Explicit read-current, reviewed SHA and explicit transport are required together')
    try:
        report = read_current(args.expected_driver_sha256, args.transport_id) if args.read_current else source_check()[0]
        print(json.dumps(report, indent=2))
        success = report.get('read_success') if args.read_current else report['source_check_pass']
        return 0 if success else 1
    except Exception:
        print(json.dumps({'source_check_pass': False, 'read_success': False, 'reason': 'source_or_input_invalid',
            'staging_attempted': False, 'rf_requested': False, 'restoration_verified': False,
            'source_factory_ready': False, 'send_available': False, 'receive_available': False, 'phone_tested': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
