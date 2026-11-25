"""Isolated v51 exact unopened-PID comm ENOENT transport; default SOURCE only, no automatic ADB.

ROOT reviews this exact driver before --read-current, an explicit transport ID
and this exact driver SHA are supplied together. The one target invocation is
fixed-length shell stdin definitions + actual readonly leaf collect(); it writes no target
files and never starts F/Parent/Stage/RF. Timeout is retained, not retried.
The original collection gates remain except for exact original ENOENT of one
known-unopened numeric PID comm ticket; private v47 receipts remain intact.
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
ORIGINAL_MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
MANIFEST = BASE / 'host/client_readonly_proc_vanish_v51_source_manifest.json'
MANIFEST_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
BASELINE_PATH = 'candidate/client-readonly-proc-vanish-v51/runtime/mta_client_baseline.py'
BASELINE_SHA = 'e950877bd99ee7907c66ee237e3140960ac8e4d64f979310b82bfdab2fa271ea'
BASELINE_BYTES = 31338
LEAF = BASE / 'candidate/client-readonly-proc-vanish-v51/runtime/mta_client_readonly_baseline.py'
LEAF_SHA = 'c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad'
ADB = Path('C:/Program Files/ADB/adb.exe')
ADB_SHA = 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f'
MAX_BYTES = 67108864
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
    helper = types.ModuleType('v47_fixed_static_reader')
    helper.__file__ = str(STATIC)
    exec(compile(raw, '<v47-fixed-pc-source-reader>', 'exec'), helper.__dict__)
    checked, rows, native, manifest_raw, stage_raw = helper.source_check()
    # The reviewed reader still authenticates its original 35-source graph.
    # The new fixed graph permits exactly one delta: this read-only baseline.
    if (checked['source_manifest_sha256'] != ORIGINAL_MANIFEST_SHA or
            _sha(manifest_raw) != ORIGINAL_MANIFEST_SHA or len(rows) != 35):
        raise ValueError('source_graph')
    old = json.loads(manifest_raw.decode('utf-8', 'strict'))
    manifest_raw_new = _fixed(MANIFEST, MANIFEST_SHA, 8096)
    new = json.loads(manifest_raw_new.decode('utf-8', 'strict'))
    if (type(old) is not dict or type(new) is not dict or
            set(new) != {'previous_manifest_sha256', 'schema', 'sources'} or
            new['previous_manifest_sha256'] != ORIGINAL_MANIFEST_SHA or
            new['schema'] != 'client-readonly-diagnostic-v47-source' or
            type(old.get('sources')) is not list or len(old['sources']) != 35 or
            type(new['sources']) is not list or len(new['sources']) != 35):
        raise ValueError('source_graph')
    replaced, changes = [], 0
    for original, current, row in zip(old['sources'], new['sources'], rows):
        if (type(original) is not dict or type(current) is not dict or
                set(current) != {'bytes', 'module', 'path', 'sha256'} or
                (original['module'], original['bytes'], original['sha256']) != row[:3] or
                current['module'] != original['module']):
            raise ValueError('source_graph')
        if original['module'] == 'mta_client_baseline':
            expected = {'bytes': BASELINE_BYTES, 'module': 'mta_client_baseline',
                'path': BASELINE_PATH, 'sha256': BASELINE_SHA}
            if current != expected:
                raise ValueError('source_delta')
            replacement = _fixed(BASE / BASELINE_PATH, BASELINE_SHA, BASELINE_BYTES)
            replaced.append((current['module'], BASELINE_BYTES, BASELINE_SHA, replacement))
            changes += 1
        else:
            if current != original:
                raise ValueError('source_delta')
            replaced.append(row)  # Retain the 34 authenticated original bytes.
    if changes != 1:
        raise ValueError('source_delta')
    rows = replaced
    leaf_raw = _fixed(LEAF, LEAF_SHA, 13934)
    self_raw = Path(__file__).absolute().read_bytes()
    report = {'schema': 'client-readonly-proc-vanish-v51', 'source_check_pass': True,
        'source_manifest_sha256': MANIFEST_SHA, 'driver_sha256': _sha(self_raw),
        'leaf_sha256': LEAF_SHA, 'source_count': 35,
        'original_source_manifest_sha256': ORIGINAL_MANIFEST_SHA, 'baseline_only_delta': True,
        'private_original_exception_diagnostic_installed': True,
        'requested_open_path_retained_before_syscall': True, 'diagnostic_data_public': False,
        'adb_invoked': False,
        'target_selected': False, 'readonly_payload_attempted': False, 'readonly_payload_started': False,
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
print('P011_V51_STARTED')
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
def exception_original(value):
 if value is None:return None
 if not isinstance(value,BaseException):raise ValueError('private_exception_type')
 raw=''.join(traceback.format_exception(type(value),value,value.__traceback__)).encode('utf-8','replace')
 number=getattr(value,'errno',None)
 return {'type':type(value).__name__,'module':type(value).__module__,
  'errno':number if type(number) is int else None,
  'filename':projection(getattr(value,'filename',None)),
  'filename2':projection(getattr(value,'filename2',None)),
  'traceback_available':value.__traceback__ is not None,
  'trace_utf8':raw[:16384].decode('utf-8','ignore'),'trace_truncated':len(raw)>16384}
try:
 if sys.flags.optimize or sys.platform!='linux' or os.uname()[4]!='armv7l' or os.geteuid()!=0 or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_platform')
 for name,pin,encoded in SOURCES:
  raw=base64.b64decode(encoded)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('target_source_pin')
  value=types.ModuleType(name);value.__file__='<v51-fixed-source-'+name+'>'
  sys.modules[name]=value;modules[name]=value
  exec(compile(raw,value.__file__,'exec'),value.__dict__)
 raw=base64.b64decode(LEAF_DATA)
 if hashlib.sha256(raw).hexdigest()!=LEAF_PIN:raise ValueError('target_leaf_pin')
 leaf=types.ModuleType('mta_client_readonly_baseline');leaf.__file__='<v51-fixed-readonly-leaf>'
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
  private['owner_error_original']=exception_original(owner.error)
  private['collectors']=[]
  for row in owner.collector_rows:
   collector=row['collector'];entry={'unknown':row['unknown'],'returned':row['returned']}
   if collector is not None:
    entry['status']=collector.status();entry['raw']=projection(collector._raw)
    entry['rounds']=projection(collector._rounds)
    entry['caught_original_v47']=exception_original(collector._caught_original_v47)
    entry['tickets']=[]
    for ticket in collector._tickets:
     saved={key:projection(ticket.get(key)) for key in
      ('kind','fd','unknown','attempted','closed','kill_attempted','waited','pipe_refs_valid',
       'open_requested_path_v47','open_requested_flags_v47')}
     saved['open_error_original_v47']=exception_original(ticket.get('open_error_original_v47'))
     entry['tickets'].append(saved)
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
  public={'evidence':'CLIENT_READONLY_PROC_VANISH_V51_ONLY','source_manifest_sha256':SOURCE_MAP,
   'attempted':False,'ended':False,'read_success':False,'resource_pending':True,'neutral_store_opened':False,
   'pending_absence_before':False,'pending_absence_after':False,'full_native_rounds':0,
   'staging_attempted':False,'rf_requested':False,'restoration_verified':False,'source_factory_ready':False,
   'send_available':False,'receive_available':False,'phone_tested':False}
 codec=modules.get('p011_json')
 if codec is None:raise ValueError('target_json_unavailable')
 encoded_private=codec.dumps(private,sort_keys=True)
 if len(encoded_private.encode('utf-8'))>16777216:raise ValueError('target_private_budget')
 print('P011_V51_PRIVATE='+encoded_private)
 print('P011_V51_PUBLIC='+codec.dumps(public,sort_keys=True))
 print('P011_V51_DONE')
if private['error'] is not None:raise SystemExit(1)
'''


def _payload(rows, leaf_raw, token):
    def encoded_lines(raw):
        if type(raw) is not bytes or not raw:
            raise ValueError('payload_source_shape')
        encoded = base64.b64encode(raw).decode('ascii')
        if base64.b64decode(encoded, validate=True) != raw:
            raise ValueError('payload_source_roundtrip')
        # Adjacent literals concatenate without changing the original bytes.
        return ['  ' + repr(encoded[index:index + 512]) for index in range(0, len(encoded), 512)]
    lines = ['SOURCES=[']
    for name, size, pin, raw in rows:
        lines.append(' (' + repr(name) + ',' + repr(pin) + ',(')
        lines.extend(encoded_lines(raw))
        lines.append(' )),')
    lines.extend([']', 'LEAF_DATA=('])
    lines.extend(encoded_lines(leaf_raw))
    lines.extend([')', 'LEAF_PIN=' + repr(LEAF_SHA), 'RUN_TOKEN=' + repr(token),
        'SOURCE_MAP=' + repr(MANIFEST_SHA)])
    if any(len(line.encode('ascii')) > 1024 for line in lines):
        raise ValueError('payload_line_budget')
    header = '\n'.join(lines) + '\n'
    return (header + TARGET_BODY).encode('utf-8')


def _transport(payload):
    # Reuse only the already device-verified fixed-length shell stdin pattern
    # from device_client_caps_readonly._transport/device_probe.Adb.python.
    # No old driver import/main, compressed fallback or target file is used.
    if type(payload) is not bytes or not 0 < len(payload) <= 16777216:
        raise ValueError('payload_budget')
    return ('python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(payload)) +
        '))" p011-client-readonly-proc-vanish-v51; mta_v51_rc=$?; printf \'\\nP011_V51_EXIT=%s\\n\' "$mta_v51_rc"')


def _run(private, stem, argv, input_data=None, timeout=45):
    before = time.monotonic()
    timed_out, code = False, None
    try:
        value = subprocess.run(argv, input=input_data, capture_output=True, timeout=timeout)
        stdout, stderr, code = value.stdout, value.stderr, value.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, timed_out = error.stdout or b'', error.stderr or b'', True
    except BaseException as error:
        # No return is not a zero-byte/zero-exit observation. Retain available
        # original exception streams, otherwise explicit empty/not-observed
        # placeholders and the private original exception before propagation.
        out, err = getattr(error, 'stdout', None), getattr(error, 'stderr', None)
        (private / (stem + '.stdout.raw')).write_bytes(out if type(out) is bytes else b'')
        (private / (stem + '.stderr.raw')).write_bytes(err if type(err) is bytes else b'')
        (private / (stem + '.host-exit')).write_text('UNRETURNED', encoding='ascii')
        (private / (stem + '.remote-exit')).write_text('NOT_OBSERVED', encoding='ascii')
        record = {'error_type': type(error).__name__, 'error_repr': repr(error),
            'stdout_observed': type(out) is bytes, 'stderr_observed': type(err) is bytes,
            'host_returned': False, 'host_exit_known': False, 'remote_exit_known': False}
        (private / (stem + '.invocation-error.json')).write_text(json.dumps(record, indent=2), encoding='utf-8')
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


def _view(raw, echo=None):
    if len(raw) > MAX_BYTES:
        raise ValueError('remote_output_budget')
    # Derived view only; originals remain byte-for-byte private files.
    value = raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')
    if echo is not None:
        if type(echo) is not bytes:
            raise ValueError('echo_shape')
        expected = echo.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')
        if value.startswith(expected):
            value = value[len(expected):]  # Only an exact whole-payload echo prefix.
    return value.splitlines()


def _started_marker(raw, echo=None):
    return _view(raw, echo).count('P011_V51_STARTED') == 1


def _remote_exit(raw, echo=None):
    lines = _view(raw, echo)
    exit_rows = [line[14:] for line in lines if line.startswith('P011_V51_EXIT=')]
    if len(exit_rows) != 1 or re.fullmatch('[0-9]{1,3}', exit_rows[0]) is None:
        raise ValueError('remote_exit_unknown')
    code = int(exit_rows[0])
    if code > 255:
        raise ValueError('remote_exit_unknown')
    return code, lines


def _decode(raw, echo=None):
    code, lines = _remote_exit(raw, echo)
    public_rows = [line[16:] for line in lines if line.startswith('P011_V51_PUBLIC=')]
    private_rows = [line[17:] for line in lines if line.startswith('P011_V51_PRIVATE=')]
    if (len(public_rows) != 1 or len(private_rows) != 1 or lines.count('P011_V51_DONE') != 1 or
            lines.count('P011_V51_STARTED') != 1):
        raise ValueError('remote_protocol')
    value = json.loads(public_rows[0])
    expected = set(BOOLS) | {'evidence', 'source_manifest_sha256', 'full_native_rounds'}
    if (type(value) is not dict or set(value) != expected or
            any(type(value[key]) is not bool for key in BOOLS) or
            value['evidence'] != 'CLIENT_READONLY_PROC_VANISH_V51_ONLY' or
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
        ('README.txt', ('Original readonly baseline with exact original ENOENT known-unopened PID comm continuation only.\n'
            'Other failures remain strict; no active scan, stage, F/Parent/RF, ready, recovery or phone proof.\n'
            'Only one baseline source row differs; original quotas and 5/10/30/45-second limits remain.\n'
            'Original exception traces/requested paths are private and never enter public fields or ZIP.\n'
            'Private raw includes identifiers/IP/process/source evidence and is excluded from this ZIP.\n'
            'HOST return, remote marker and native read/closure are distinct; failures/timeouts are not retried.\n'
            'Raw stdout/stderr are exactly the ADB host streams; shell transport does not promise a separate remote stderr channel.\n'
            'Payload attempted and remote STARTED marker are separate; unreturned invocation keeps explicit not-observed raw records.\n'
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
    output = parent / ('client-readonly-proc-vanish-v51-' + stamp + '-' + os.urandom(4).hex())
    output.mkdir(exist_ok=False)
    private = output / 'private-raw'
    private.mkdir(exist_ok=False)
    pins = {'manifest_sha256': MANIFEST_SHA, 'original_manifest_sha256': ORIGINAL_MANIFEST_SHA,
        'baseline_sha256': BASELINE_SHA, 'leaf_sha256': LEAF_SHA, 'static_reader_sha256': STATIC_SHA,
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
        command = _transport(payload)
        report['readonly_payload_attempted'] = True
        raw, err, code, timeout, elapsed = _run(private, '02-native-readonly',
            [str(ADB), '-t', selected, 'shell', command], input_data=payload)
        report.update(host_exit=code, host_timeout=timeout, host_seconds=elapsed)
        report['readonly_payload_started'] = _started_marker(raw, payload)
        remote = _remote_exit(raw, payload)[0]
        (private / '02-native-readonly.remote-exit').write_text(str(remote), encoding='ascii')
        report['remote_exit'] = remote
        native, remote = _decode(raw, payload)
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


