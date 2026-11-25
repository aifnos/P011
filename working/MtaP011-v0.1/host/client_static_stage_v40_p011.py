"""Fixed append-only source staging; default SOURCE only, no automatic ADB.

Explicit stage-sources + exact reviewed driver SHA + fresh unique P011 transport
are required together. Target loads only original readonly v37/leaf definitions;
v38 candidate is byte data. Two original native read phases and all known closes
occur in one original 120s task. No F/Parent/watchdog/RF or formal deployment.
Old roots, partial stages, user paths and archived mains are never altered.
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
STAGED_MANIFEST = BASE / 'host/client_refusal_prescreen_v38_source_manifest.json'
STAGED_MANIFEST_SHA = '0ea4db9b3ac41d1036d5796602db48b7740f6c51f1f0281604d6d8ebeb19319c'
STAGE_SOURCE = BASE / 'candidate/client-static-stage-v40/runtime/mta_client_static_stage.py'
STAGE_SHA = 'e0b4b1d596ca629024cebef6fbee53218bbbc26ad53a1a2d163d36d6bb40c3e0'
STAGE_BYTES = 28860
NEW_PENDING_SHA = '14e85b8297868a7a07d964a598bc3cbc665e1e6cf19d615466e165386a27f524'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
ADB = Path('C:/Program Files/ADB/adb.exe')
ADB_SHA = 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f'
MAX_BYTES = 67108864
BOOLS = ('attempted', 'ended', 'staging_attempted', 'before_read_closed', 'after_read_closed',
    'static_sources_staged', 'resource_pending', 'device_exclusive_lease', 'rf_admission',
    'deployment_available', 'source_factory_ready', 'rf_requested', 'parent_started',
    'send_available', 'receive_available', 'phone_tested', 'restoration_verified')


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
    # Only the already-reviewed fixed PC source-reader definitions are executed.
    # Private __name__ prevents old main; candidate/leaf/stage remain mere bytes.
    raw = _fixed(STATIC, STATIC_SHA, 10402)
    helper = types.ModuleType('v40_fixed_readonly_source_reader')
    helper.__file__ = str(STATIC)
    exec(compile(raw, '<v40-fixed-pc-source-reader>', 'exec'), helper.__dict__)
    checked, rows, wpa, old_manifest_raw, unused_stage = helper.source_check()
    leaf_raw = _fixed(LEAF, LEAF_SHA, 13811)
    if checked['source_manifest_sha256'] != MANIFEST_SHA or len(rows) != 35:
        raise ValueError('readonly_source_graph')
    current_raw = _fixed(STAGED_MANIFEST, STAGED_MANIFEST_SHA, 8084)
    current, old = json.loads(current_raw.decode('utf-8')), json.loads(old_manifest_raw.decode('utf-8'))
    if (type(current) is not dict or set(current) != {'schema', 'previous_manifest_sha256', 'sources'} or
            current['schema'] != 'client-refusal-prescreen-v38-host' or
            current['previous_manifest_sha256'] != MANIFEST_SHA or
            type(current['sources']) is not list or len(current['sources']) != 35):
        raise ValueError('staged_source_graph')
    new_pending, staged_pins = None, []
    for before, after in zip(old['sources'], current['sources']):
        if type(after) is not dict or set(after) != {'module', 'path', 'bytes', 'sha256'}:
            raise ValueError('staged_source_row')
        if before['module'] != after['module']:
            raise ValueError('staged_source_order')
        if after['module'] == 'mta_client_pending':
            if after != {'module': 'mta_client_pending', 'path': 'candidate/client-budget-refusal-v38/runtime/mta_client_pending.py',
                    'bytes': 57246, 'sha256': NEW_PENDING_SHA}:
                raise ValueError('staged_pending')
            new_pending = _fixed(BASE / after['path'], NEW_PENDING_SHA, 57246)
        elif after != before:
            raise ValueError('staged_unaffected_source')
        staged_pins.append((after['module'], after['bytes'], after['sha256']))
    if new_pending is None or len(staged_pins) != 35 or len(wpa) != WPA_BYTES or _sha(wpa) != WPA_SHA:
        raise ValueError('staged_source_graph')
    stage_raw = _fixed(STAGE_SOURCE, STAGE_SHA, STAGE_BYTES)
    constants = helper._literals(stage_raw)
    if (constants.get('SOURCE_PINS') != tuple(staged_pins) or
            constants.get('SOURCE_MANIFEST_SHA') != STAGED_MANIFEST_SHA or
            constants.get('READONLY_MANIFEST_SHA') != MANIFEST_SHA or
            constants.get('READONLY_LEAF_SHA') != LEAF_SHA or constants.get('WPA_SHA') != WPA_SHA or
            constants.get('WPA_BYTES') != WPA_BYTES or constants.get('STAGE_SECONDS') != 120.0):
        raise ValueError('stage_source_binding')
    report = {'schema': 'client-static-stage-v40-source', 'source_check_pass': True,
        'loaded_readonly_map_sha256': MANIFEST_SHA, 'staged_native_map_sha256': STAGED_MANIFEST_SHA,
        'driver_sha256': _sha(Path(__file__).absolute().read_bytes()), 'stage_sha256': STAGE_SHA,
        'readonly_leaf_sha256': LEAF_SHA, 'source_count': 35, 'staged_pending_executed': False,
        'adb_invoked': False, 'target_selected': False, 'stage_payload_attempted': False,
        'stage_payload_started': False, 'static_sources_staged': False, 'resource_pending': True,
        'staging_attempted': False, 'before_read_closed': False, 'after_read_closed': False,
        'device_exclusive_lease': False, 'rf_admission': False, 'deployment_available': False,
        'source_factory_ready': False, 'rf_requested': False, 'parent_started': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False,
        'restoration_verified': False, 'reason': 'source_only'}
    return report, rows, new_pending, wpa, stage_raw, leaf_raw


TARGET_BODY = r'''
import base64,hashlib,os,sys,time,traceback,types
issued=time.monotonic();original_until=issued+120.0
print('P011_V40_STARTED')
modules={};task=None;public=None;private={'error':None}
def projection(value):
 if value is None or type(value) in (str,int,float,bool):return value
 if type(value) is bytes:return {'bytes_b64':base64.b64encode(value).decode('ascii'),'bytes':len(value)}
 ip=modules.get('mta_ip')
 if ip is not None and type(value) in (ip.IpSnapshot,ip.AddressRecord,ip.RouteRecord,ip.RuleRecord):return {key:projection(getattr(value,key)) for key in type(value)._fields}
 if type(value) in (tuple,list):return [projection(row) for row in value]
 if type(value) is dict:return {key:projection(row) for key,row in value.items()}
 if hasattr(type(value),'__slots__'):return {key:projection(getattr(value,key)) for key in type(value).__slots__ if not key.startswith('_')}
 raise ValueError('private_projection_type')
def owner_record(owner):
 result={'status':owner.status(),'snapshot':projection(owner.result),'platform_before':projection(owner.platform_before),'platform_after':projection(owner.platform_after),'issued_at':owner.issued_at,'until':owner.until,'collectors':[]}
 for row in owner.collector_rows:
  collector=row['collector'];entry={'unknown':row['unknown'],'returned':row['returned']}
  if collector is not None:
   entry['status']=collector.status();entry['raw']=projection(collector._raw);entry['rounds']=projection(collector._rounds)
   entry['tickets']=[{key:projection(ticket.get(key)) for key in ('kind','fd','unknown','attempted','closed','kill_attempted','waited','pipe_refs_valid')} for ticket in collector._tickets]
  result['collectors'].append(entry)
 reader=owner.reader;result['proc']={'pending':reader._pending,'active':reader._active,'history_active':reader._history_active,'history_closed':reader.history_closed(),'history':[]}
 for generation in reader._history:
  result['proc']['history'].append({'ordinal':generation.ordinal,'ended':generation.ended,'active':generation.active,'unknown':generation.unknown,'late':generation.late,'raw':projection(generation.raw),'tickets':[{key:projection(getattr(ticket,key)) for key in ('ordinal','descriptor','open_called','returned','registered','failed_without_fd','close_attempted','close_returned','close_result','ebadf_observed','ebadf_errno','unknown')} for ticket in generation.tickets]})
 result['budget']=projection(owner.budget.status())
 return result
try:
 if sys.flags.optimize or sys.platform!='linux' or os.uname()[4]!='armv7l' or os.geteuid()!=0 or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_platform')
 payloads={}
 for name,pin,encoded in SOURCES:
  raw=base64.b64decode(encoded)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('readonly_source_pin')
  payloads[name]=raw;value=types.ModuleType(name);value.__file__='<v40-readonly-source-'+name+'>'
  sys.modules[name]=value;modules[name]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__)
 for name,encoded,pin in (('mta_client_readonly_baseline',LEAF_DATA,LEAF_PIN),('mta_client_static_stage',STAGE_DATA,STAGE_PIN)):
  raw=base64.b64decode(encoded)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('target_adapter_pin')
  value=types.ModuleType(name);value.__file__='<v40-fixed-'+name+'>'
  sys.modules[name]=value;modules[name]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__)
 pending=base64.b64decode(PENDING_DATA);wpa=base64.b64decode(WPA_DATA)
 if len(pending)!=57246 or hashlib.sha256(pending).hexdigest()!=PENDING_PIN or len(wpa)!=1351192 or hashlib.sha256(wpa).hexdigest()!=WPA_PIN:raise ValueError('staged_bytes_pin')
 payloads['mta_client_pending']=pending
 # Only the original readonly graph definitions execute. New Pending is bytes;
 # no candidate F/Parent lifecycle or native WPA is started.
 task=modules['mta_client_static_stage'].StaticStagingTask(RUN_TOKEN,original_until)
 task.run(payloads,wpa);public=task.status()
 if public['static_sources_staged'] is not True or public['resource_pending'] is not False:raise ValueError('target_stage_unclosed')
except BaseException:
 private['error']=traceback.format_exc()[:16384]
finally:
 if task is not None:
  private['task']={'issued_at':task.issued_at,'until':task.until,'phase':task.phase,'token':task.token,'candidate_sha256':task.candidate_sha,'writer_constructor_attempted':task.writer_constructor_attempted,'writer_constructor_returned':task.writer_constructor_returned,'writer_closed':task.writer_closed,'status':task.status(),'readonly':[]}
  for row in task.readonly_rows:
   entry={'phase':row['phase'],'until':row['until'],'constructor_attempted':row['constructor_attempted'],'constructor_returned':row['constructor_returned'],'returned':row['returned']}
   if row['owner'] is not None:entry['original_owner']=owner_record(row['owner'])
   private['task']['readonly'].append(entry)
  if task.writer is not None:
   writer=task.writer;private['task']['writer']={'pending':writer.pending,'close_attempted':writer.close_attempted,'rows':projection(writer.inventory()),'mutations':projection(writer.mutations),'entries_before':projection(writer.entries_before),'entries_after':projection(writer.entries_after),'writes':[{key:projection(row.get(key)) for key in ('name','metadata','sealed_entry','content_sha256','unknown','attempted','closed')} for row in writer.writes]}
  if public is None:public=task.status()
 if public is None:
  public={'evidence':'CLIENT_STATIC_STAGE_V40_ONLY','loaded_readonly_map_sha256':READONLY_MAP,'staged_native_map_sha256':STAGED_MAP,'readonly_leaf_sha256':LEAF_PIN,'attempted':False,'ended':False,'staging_attempted':False,'before_read_closed':False,'after_read_closed':False,'static_sources_staged':False,'resource_pending':True,'stage_native_files':0,'original_root_entries':0,'device_exclusive_lease':False,'rf_admission':False,'deployment_available':False,'source_factory_ready':False,'rf_requested':False,'parent_started':False,'send_available':False,'receive_available':False,'phone_tested':False,'restoration_verified':False}
 codec=modules.get('p011_json')
 if codec is None:raise ValueError('target_json_unavailable')
 encoded_private=codec.dumps(private,sort_keys=True)
 if len(encoded_private.encode('utf-8'))>16777216:raise ValueError('target_private_budget')
 print('P011_V40_PRIVATE='+encoded_private)
 print('P011_V40_PUBLIC='+codec.dumps(public,sort_keys=True))
 print('P011_V40_DONE')
if private['error'] is not None:raise SystemExit(1)
'''


def _payload(rows, new_pending, wpa, stage_raw, leaf_raw, token):
    def encoded_lines(raw):
        if type(raw) is not bytes or not raw:
            raise ValueError('payload_source_shape')
        encoded = base64.b64encode(raw).decode('ascii')
        if base64.b64decode(encoded, validate=True) != raw:
            raise ValueError('payload_source_roundtrip')
        return ['  ' + repr(encoded[index:index + 512]) for index in range(0, len(encoded), 512)]
    lines = ['SOURCES=[']
    for name, size, pin, raw in rows:
        lines.append(' (' + repr(name) + ',' + repr(pin) + ',(')
        lines.extend(encoded_lines(raw)); lines.append(' )),')
    lines.append(']')
    for name, raw in (('LEAF_DATA', leaf_raw), ('STAGE_DATA', stage_raw),
            ('PENDING_DATA', new_pending), ('WPA_DATA', wpa)):
        lines.append(name + '=('); lines.extend(encoded_lines(raw)); lines.append(')')
    for name, value in (('LEAF_PIN', LEAF_SHA), ('STAGE_PIN', STAGE_SHA), ('PENDING_PIN', NEW_PENDING_SHA),
            ('WPA_PIN', WPA_SHA), ('RUN_TOKEN', token), ('READONLY_MAP', MANIFEST_SHA), ('STAGED_MAP', STAGED_MANIFEST_SHA)):
        lines.append(name + '=' + repr(value))
    if any(len(line.encode('ascii')) > 1024 for line in lines):
        raise ValueError('payload_line_budget')
    return ('\n'.join(lines) + '\n' + TARGET_BODY).encode('utf-8')


def _transport(payload):
    # Reuse only the already device-verified fixed-length shell stdin pattern
    # from device_client_caps_readonly._transport/device_probe.Adb.python.
    # No old driver import/main, compressed fallback or target file is used.
    if type(payload) is not bytes or not 0 < len(payload) <= 16777216:
        raise ValueError('payload_budget')
    return ('python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(payload)) +
        '))" p011-client-static-stage-v40; mta_v40_rc=$?; printf \'\\nP011_V40_EXIT=%s\\n\' "$mta_v40_rc"')


def _run(private, stem, argv, input_data=None, timeout=150):
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
    return _view(raw, echo).count('P011_V40_STARTED') == 1


def _remote_exit(raw, echo=None):
    lines = _view(raw, echo)
    exit_rows = [line[14:] for line in lines if line.startswith('P011_V40_EXIT=')]
    if len(exit_rows) != 1 or re.fullmatch('[0-9]{1,3}', exit_rows[0]) is None:
        raise ValueError('remote_exit_unknown')
    code = int(exit_rows[0])
    if code > 255:
        raise ValueError('remote_exit_unknown')
    return code, lines


def _decode(raw, echo=None):
    code, lines = _remote_exit(raw, echo)
    public_rows = [line[16:] for line in lines if line.startswith('P011_V40_PUBLIC=')]
    private_rows = [line[17:] for line in lines if line.startswith('P011_V40_PRIVATE=')]
    if (len(public_rows) != 1 or len(private_rows) != 1 or lines.count('P011_V40_DONE') != 1 or
            lines.count('P011_V40_STARTED') != 1):
        raise ValueError('remote_protocol')
    value = json.loads(public_rows[0])
    expected = set(BOOLS) | {'evidence', 'loaded_readonly_map_sha256', 'staged_native_map_sha256',
        'readonly_leaf_sha256', 'stage_native_files', 'original_root_entries'}
    if (type(value) is not dict or set(value) != expected or
            any(type(value[key]) is not bool for key in BOOLS) or
            value['evidence'] != 'CLIENT_STATIC_STAGE_V40_ONLY' or
            value['loaded_readonly_map_sha256'] != MANIFEST_SHA or
            value['staged_native_map_sha256'] != STAGED_MANIFEST_SHA or value['readonly_leaf_sha256'] != LEAF_SHA or
            type(value['stage_native_files']) is not int or not 0 <= value['stage_native_files'] <= 38 or
            type(value['original_root_entries']) is not int or not 0 <= value['original_root_entries'] <= 4096):
        raise ValueError('remote_projection')
    if any(value[key] for key in ('device_exclusive_lease', 'rf_admission', 'deployment_available', 'rf_requested',
            'parent_started', 'restoration_verified', 'source_factory_ready', 'send_available', 'receive_available', 'phone_tested')):
        raise ValueError('remote_scope')
    # Public data proves neither RF admission nor a future deployment/restore.
    return value, code


def _publish(output, report, pins):
    members = [('result.json', json.dumps(report, indent=2).encode('utf-8')),
        ('source-pins.json', json.dumps(pins, indent=2).encode('utf-8')),
        ('README.txt', ('Append-only static staging only. No F/Parent/RF, ready, recovery or phone proof.\n'
            'Private raw includes identifiers/IP/process/source evidence and is excluded from this ZIP.\n'
            'Loaded readonly graph 4b9 and staged byte graph 0ea4 are distinct; candidate Pending is not executed.\n'
            'Two fresh original readonly owners plus anchored entry/PENDING checks belong to this one task.\n'
            'HOST return, remote marker, source write and native closure are distinct; failures/timeouts are not retried.\n'
            'Raw stdout/stderr are exactly the ADB host streams; shell transport does not promise a separate remote stderr channel.\n'
            'Payload attempted and remote STARTED marker are separate; unreturned invocation keeps explicit not-observed raw records.\n'
            'No device-wide lease/atomicity is claimed. Old root entries/subtrees and user/Received paths are not changed.\n'
            'Partial new stages are retained on failure; no automatic removal or repeated staging.\n').encode('utf-8'))]
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


def stage_sources(expected_driver, transport):
    report, rows, new_pending, wpa, stage_raw, leaf_raw = source_check()
    if (type(expected_driver) is not str or re.fullmatch('[0-9a-f]{64}', expected_driver) is None or
            expected_driver != report['driver_sha256'] or type(transport) is not str or
            re.fullmatch('[1-9][0-9]{0,9}', transport) is None):
        raise ValueError('reviewed_input')
    _fixed(ADB, ADB_SHA)
    parent = BASE / 'results'
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('result_parent')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = parent / ('client-static-stage-v40-' + stamp + '-' + os.urandom(4).hex())
    output.mkdir(exist_ok=False)
    private = output / 'private-raw'
    private.mkdir(exist_ok=False)
    staged = [[name, 57246 if name == 'mta_client_pending' else size,
        NEW_PENDING_SHA if name == 'mta_client_pending' else pin] for name, size, pin, raw in rows]
    pins = {'loaded_readonly_map_sha256': MANIFEST_SHA, 'staged_native_map_sha256': STAGED_MANIFEST_SHA,
        'leaf_sha256': LEAF_SHA, 'stage_sha256': STAGE_SHA, 'static_reader_sha256': STATIC_SHA,
        'adb_exe_sha256': ADB_SHA, 'wpa_sha256': WPA_SHA,
        'readonly_sources': [[name, size, pin] for name, size, pin, raw in rows], 'staged_sources': staged}
    try:
        report['adb_invoked'] = True
        raw, err, code, timeout, elapsed = _run(private, '01-enumeration', [str(ADB), 'devices', '-l'], timeout=10)
        if timeout or code != 0:
            raise ValueError('enumeration_failed')
        selected = _select(raw, transport)
        report['target_selected'] = True
        token = os.urandom(16).hex()
        payload = _payload(rows, new_pending, wpa, stage_raw, leaf_raw, token)
        with (private / 'payload.py').open('xb') as handle:
            handle.write(payload)
        command = _transport(payload)
        report['stage_payload_attempted'] = True
        raw, err, code, timeout, elapsed = _run(private, '02-native-static-stage',
            [str(ADB), '-t', selected, 'shell', command], input_data=payload)
        report.update(host_exit=code, host_timeout=timeout, host_seconds=elapsed)
        report['stage_payload_started'] = _started_marker(raw, payload)
        remote = _remote_exit(raw, payload)[0]
        (private / '02-native-static-stage.remote-exit').write_text(str(remote), encoding='ascii')
        report['remote_exit'] = remote
        native, remote = _decode(raw, payload)
        report.update(native)
        good = (code == 0 and not timeout and remote == 0 and native['static_sources_staged'] and
            native['attempted'] and native['ended'] and not native['resource_pending'] and
            native['staging_attempted'] and native['before_read_closed'] and native['after_read_closed'] and
            native['stage_native_files'] == 38)
        closed = (not timeout and code == 0 and native['attempted'] and native['ended'] and
            not native['resource_pending'])
        report.update(static_sources_staged=bool(good), remote_closure_verified=bool(closed),
            reason='static_staged_closed' if good else 'static_stage_failed')
    except BaseException as error:
        report.update(static_sources_staged=False, remote_closure_verified=False, reason='static_stage_failed')
        (private / 'driver-error.txt').write_text(type(error).__name__ + '\n' + repr(error), encoding='utf-8')
    _publish(output, report, pins)
    report['result_directory'] = str(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-sources', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    parser.add_argument('--transport-id')
    args = parser.parse_args(argv)
    if args.stage_sources != (args.expected_driver_sha256 is not None) or args.stage_sources != (args.transport_id is not None):
        parser.error('Explicit stage-sources, reviewed SHA and explicit transport are required together')
    try:
        report = stage_sources(args.expected_driver_sha256, args.transport_id) if args.stage_sources else source_check()[0]
        print(json.dumps(report, indent=2))
        success = report.get('static_sources_staged') if args.stage_sources else report['source_check_pass']
        return 0 if success else 1
    except Exception:
        print(json.dumps({'source_check_pass': False, 'static_sources_staged': False, 'reason': 'source_or_input_invalid',
            'staging_attempted': False, 'rf_requested': False, 'restoration_verified': False,
            'device_exclusive_lease': False, 'rf_admission': False, 'deployment_available': False,
            'source_factory_ready': False, 'send_available': False, 'receive_available': False, 'phone_tested': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
