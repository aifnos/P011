"""Reviewed explicit actual P011 GO append and no-RF watchdog check.

Default is PC SOURCE validation only. Device execution additionally requires
--check-watchdog, this exact reviewed driver SHA and one explicit freshly
enumerated P011 transport. One original120s target task, one150s HOST invocation,
one new EXCL go-token directory; no RF/controller/bootstrap/FD3/global lease.
The GO17 deployment is real fixed source bytes with device-read Python ELF SHA,
not the earlier HOST model. Parent readonly35 and childGO17 are separate domains.
Raw identifiers/argv/FD/stock observations are private; public ZIP has only fixed
scope/counts/pins. Existing roots, pending markers and partial stages are kept.
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
GO_MANIFEST = BASE / 'host/go_bootstrap_native_v34_source_manifest.json'
GO_MANIFEST_SHA = '491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296'
STAGE_SOURCE = BASE / 'candidate/go-watchdog-device-v41-r2/runtime/mta_go_watchdog_device.py'
STAGE_SHA = 'ac9f9880f1e0f7d0a2a1741469633350cd39cc8de0678d7cc443fd2fbae858e3'
STAGE_BYTES = 48722
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
ADB = Path('C:/Program Files/ADB/adb.exe')
ADB_SHA = 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f'
MAX_BYTES = 67108864
BOOLS = ('attempted','ended','staging_attempted','before_read_closed','after_read_closed',
    'go_sources_staged','resource_pending','watchdog_verified','child_exit_verified',
    'notify_eof_verified','child_ofd_verified','device_exclusive_lease','rf_admission',
    'source_factory_ready','rf_requested','go_parent_started','go_store_opened','fd3_verified',
    'controller_started','send_available','receive_available','phone_tested','restoration_verified')
DENIED = ('device_exclusive_lease','rf_admission','source_factory_ready','rf_requested',
    'go_parent_started','go_store_opened','fd3_verified','controller_started','send_available',
    'receive_available','phone_tested','restoration_verified')


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
    raw = _fixed(STATIC, STATIC_SHA, 10402)
    helper = types.ModuleType('v41_fixed_readonly_source_reader')
    helper.__file__ = str(STATIC)
    exec(compile(raw, '<v41-fixed-pc-source-reader>', 'exec'), helper.__dict__)
    checked, readonly_rows, wpa, old_manifest_raw, unused_stage = helper.source_check()
    leaf_raw = _fixed(LEAF, LEAF_SHA, 13811)
    if checked['source_manifest_sha256'] != MANIFEST_SHA or len(readonly_rows) != 35:
        raise ValueError('readonly_source_graph')
    go_manifest_raw = _fixed(GO_MANIFEST, GO_MANIFEST_SHA, 3952)
    tree = json.loads(go_manifest_raw.decode('utf-8'))
    if (type(tree) is not dict or set(tree) != {'schema','sources'} or
            tree['schema'] != 'go-bootstrap-native-v34-host' or
            type(tree['sources']) is not list or len(tree['sources']) != 17):
        raise ValueError('go_source_graph')
    go_rows, names = [], set()
    for row in tree['sources']:
        if (type(row) is not dict or set(row) != {'module','path','bytes','sha256'} or
                type(row['module']) is not str or re.fullmatch('[a-z][a-z0-9_]*',row['module']) is None or
                type(row['path']) is not str or row['path'].startswith('/') or '\\' in row['path'] or
                any(part in ('','.','..') for part in row['path'].split('/')) or
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= 262144 or
                type(row['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',row['sha256']) is None or
                row['module'] in names):
            raise ValueError('go_source_row')
        names.add(row['module'])
        go_rows.append((row['module'],row['bytes'],row['sha256'],
            _fixed(BASE / row['path'],row['sha256'],row['bytes'])))
    stage_raw = _fixed(STAGE_SOURCE, STAGE_SHA, STAGE_BYTES)
    constants = helper._literals(stage_raw)
    if (constants.get('SOURCE_PINS') != tuple((n,z,h) for n,z,h,r in go_rows) or
            constants.get('SOURCE_MANIFEST_SHA') != GO_MANIFEST_SHA or
            constants.get('READONLY_MANIFEST_SHA') != MANIFEST_SHA or
            constants.get('READONLY_LEAF_SHA') != LEAF_SHA or
            constants.get('GO_ROOT_NAME') != 'p011-mta-go-session' or
            constants.get('STAGE_SECONDS') != 120.0 or constants.get('WATCHDOG_SECONDS') != 25.0 or
            constants.get('WPA_SHA') != WPA_SHA or constants.get('WPA_BYTES') != WPA_BYTES or
            len(wpa) != WPA_BYTES or _sha(wpa) != WPA_SHA):
        raise ValueError('target_source_binding')
    report = {'schema':'go-watchdog-device-v41-source','source_check_pass':True,
        'loaded_readonly_map_sha256':MANIFEST_SHA,'staged_native_map_sha256':GO_MANIFEST_SHA,
        'driver_sha256':_sha(Path(__file__).absolute().read_bytes()),'stage_sha256':STAGE_SHA,
        'readonly_leaf_sha256':LEAF_SHA,'readonly_source_count':35,'go_source_count':17,
        'adb_invoked':False,'target_selected':False,'stage_payload_attempted':False,
        'stage_payload_started':False,'attempted':False,'ended':False,
        'staging_attempted':False,'before_read_closed':False,'after_read_closed':False,
        'go_sources_staged':False,'watchdog_verified':False,'child_exit_verified':False,
        'notify_eof_verified':False,'child_ofd_verified':False,'resource_pending':True,
        'reason':'source_only'}
    for key in DENIED: report[key] = False
    return report,readonly_rows,go_rows,wpa,stage_raw,leaf_raw,go_manifest_raw,old_manifest_raw


TARGET_BODY = r'''
import base64,hashlib,os,sys,time,traceback,types
issued=time.monotonic();original_until=issued+120.0
print('P011_V41_STARTED')
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
  payloads[name]=raw;value=types.ModuleType(name);value.__file__='<v41-readonly-source-'+name+'>'
  sys.modules[name]=value;modules[name]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__)
 for name,encoded,pin in (('mta_client_readonly_baseline',LEAF_DATA,LEAF_PIN),('mta_go_watchdog_device',STAGE_DATA,STAGE_PIN)):
  raw=base64.b64decode(encoded)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('target_adapter_pin')
  value=types.ModuleType(name);value.__file__='<v41-fixed-'+name+'>'
  sys.modules[name]=value;modules[name]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__)
 go_payloads={}
 for name,size,pin,encoded in GO_SOURCES:
  raw=base64.b64decode(encoded)
  if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('go_source_pin')
  go_payloads[name]=raw
 wpa=base64.b64decode(WPA_DATA)
 if len(wpa)!=1351192 or hashlib.sha256(wpa).hexdigest()!=WPA_PIN:raise ValueError('wpa_pin')
 # No GO module executes in this parent. Its exact child executable script
 # separately performs native GoDeploymentLoader.main/watchdog/_entry.
 task=modules['mta_go_watchdog_device'].GoWatchdogTask(RUN_TOKEN,original_until)
 task.run(go_payloads,wpa);public=task.status()
 if public['go_sources_staged'] is not True or public['watchdog_verified'] is not True or public['resource_pending'] is not False:raise ValueError('target_watchdog_unclosed')
except BaseException:
 private['error']=traceback.format_exc()[:16384]
finally:
 if task is not None:
  private['task']={'issued_at':task.issued_at,'until':task.until,'phase':task.phase,'token':task.token,'deployment_sha256':task.deployment_sha,'python_sha256':task.python_sha,'writer_constructor_attempted':task.writer_constructor_attempted,'writer_constructor_returned':task.writer_constructor_returned,'writer_closed':task.writer_closed,'status':task.status(),'readonly':[]}
  for row in task.readonly_rows:
   entry={'phase':row['phase'],'until':row['until'],'constructor_attempted':row['constructor_attempted'],'constructor_returned':row['constructor_returned'],'returned':row['returned']}
   if row['owner'] is not None:entry['original_owner']=owner_record(row['owner'])
   private['task']['readonly'].append(entry)
  if task.writer is not None:
   writer=task.writer;private['task']['writer']={'pending':writer.pending,'close_attempted':writer.close_attempted,'rows':projection(writer.inventory()),'mutations':projection(writer.mutations),'entries_before':projection(writer.entries_before),'entries_after':projection(writer.entries_after),'writes':[{key:projection(row.get(key)) for key in ('name','metadata','sealed_entry','content_sha256','unknown','attempted','closed')} for row in writer.writes]}
  if public is None:public=task.status()
 if task is not None and task.process_owner is not None:
  ticket=task.process_ticket
  private['process']={'status':task.process_owner.status(),'until':task.watchdog_until,
   'until_text':task.watchdog_until_text,'task_until':task.until,'persist_rows':[],
   'cleanup_errors':task.cleanup_errors,'stop_reap_rows':projection(task.stop_reap_rows),
   'notify':projection(task.notify_rows),
   'reader_history_closed':task.process_reader.history_closed(),
   'budget':projection(task.process_store._resource_budget_v23.status())}
  if ticket is not None:
   private['process']['ticket']={key:projection(getattr(ticket,key)) for key in
    ('pid','parent','boot','preexec','postexec','deadline','started','fork_requested','fork_returned','fork_negative','unknown',
     'persist_requested','persist_returned','release_requested','released','wait_requested','waited','wait_status',
     'exit_code','exit_observation','exit_verified','notify_requests','reason','stage')}
   private['process']['ticket']['spec']={'role':ticket.spec.role,'exe':ticket.spec.exe,'argv':list(ticket.spec.argv),
    'sha256':ticket.spec.sha,'argv_sha256':ticket.spec.argv_sha}
   private['process']['ticket']['fds']=[{key:projection(getattr(row,key)) for key in
    ('role','fd','metadata','returned','unknown','attempted','closed')} for row in ticket.fds]
   for row in task.persist_rows:
    private['process']['persist_rows'].append({'same_ticket':row['ticket'] is ticket,
     'same_preexec':row['actor'] is ticket.preexec,'receipt_original':row['returned'] is ticket.persist_receipt})
  private['process']['proc_history']=[{'ordinal':g.ordinal,'ended':g.ended,'active':g.active,'unknown':g.unknown,
   'late':g.late,'raw':projection(g.raw),'tickets':[{key:projection(getattr(t,key)) for key in
   ('descriptor','close_attempted','close_returned','close_result','ebadf_observed','unknown')} for t in g.tickets]}
   for g in task.process_reader._history]
 if task is not None and task.writer is not None:
  private['task']['writer']['python_rows']=[{key:projection(row.get(key)) for key in
   ('metadata','sha256','unknown','attempted','closed')} for row in task.writer.python_rows]
  private['task']['writer']['flock_rows']=[{'kind':row['row']['kind'],'fd':row['row']['fd'],
   'metadata':projection(row['row']['metadata']),'called':row['called'],'returned':row['returned'],
   'result':row['result'],'errno':row['errno']} for row in task.writer.flock_rows]
 if public is None:
  public={key:False for key in PUBLIC_BOOL_KEYS}
  public.update(evidence='GO_WATCHDOG_DEVICE_V41_COMPONENT_ONLY',loaded_readonly_map_sha256=READONLY_MAP,
   staged_native_map_sha256=GO_MAP,readonly_leaf_sha256=LEAF_PIN,stage_native_files=0,original_root_entries=0,resource_pending=True)
 codec=modules.get('p011_json')
 if codec is None:raise ValueError('target_json_unavailable')
 encoded_private=codec.dumps(private,sort_keys=True)
 if len(encoded_private.encode('utf-8'))>16777216:raise ValueError('target_private_budget')
 print('P011_V41_PRIVATE='+encoded_private)
 print('P011_V41_PUBLIC='+codec.dumps(public,sort_keys=True))
 print('P011_V41_DONE')
if private['error'] is not None:raise SystemExit(1)
'''


def _payload(readonly_rows,go_rows,wpa,stage_raw,leaf_raw,token):
    def encoded_lines(raw):
        if type(raw) is not bytes or not raw: raise ValueError('payload_source_shape')
        value=base64.b64encode(raw).decode('ascii')
        if base64.b64decode(value,validate=True)!=raw:raise ValueError('payload_source_roundtrip')
        return ['  '+repr(value[index:index+512]) for index in range(0,len(value),512)]
    lines=['SOURCES=[']
    for name,size,pin,raw in readonly_rows:
        lines.append(' ('+repr(name)+','+repr(pin)+',(');lines.extend(encoded_lines(raw));lines.append(' )),')
    lines.append(']');lines.append('GO_SOURCES=[')
    for name,size,pin,raw in go_rows:
        lines.append(' ('+repr(name)+','+str(size)+','+repr(pin)+',(');lines.extend(encoded_lines(raw));lines.append(' )),')
    lines.append(']')
    for name,raw in (('LEAF_DATA',leaf_raw),('STAGE_DATA',stage_raw),('WPA_DATA',wpa)):
        lines.append(name+'=(');lines.extend(encoded_lines(raw));lines.append(')')
    for name,value in (('LEAF_PIN',LEAF_SHA),('STAGE_PIN',STAGE_SHA),('WPA_PIN',WPA_SHA),
            ('RUN_TOKEN',token),('READONLY_MAP',MANIFEST_SHA),('GO_MAP',GO_MANIFEST_SHA),
            ('PUBLIC_BOOL_KEYS',BOOLS)):
        lines.append(name+'='+repr(value))
    if any(len(line.encode('ascii'))>1024 for line in lines):raise ValueError('payload_line_budget')
    return ('\n'.join(lines)+'\n'+TARGET_BODY).encode('utf-8')


def _transport(payload):
    # Reuse only the already device-verified fixed-length shell stdin pattern
    # from device_client_caps_readonly._transport/device_probe.Adb.python.
    # No old driver import/main, compressed fallback or target file is used.
    if type(payload) is not bytes or not 0 < len(payload) <= 16777216:
        raise ValueError('payload_budget')
    return ('python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(payload)) +
        '))" p011-go-watchdog-device-v41; mta_v41_rc=$?; printf \'\\nP011_V41_EXIT=%s\\n\' "$mta_v41_rc"')


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
    return _view(raw, echo).count('P011_V41_STARTED') == 1


def _remote_exit(raw, echo=None):
    lines = _view(raw, echo)
    exit_rows = [line[14:] for line in lines if line.startswith('P011_V41_EXIT=')]
    if len(exit_rows) != 1 or re.fullmatch('[0-9]{1,3}', exit_rows[0]) is None:
        raise ValueError('remote_exit_unknown')
    code = int(exit_rows[0])
    if code > 255:
        raise ValueError('remote_exit_unknown')
    return code, lines


def _decode(raw,echo=None):
    code,lines=_remote_exit(raw,echo)
    pub=[line[16:] for line in lines if line.startswith('P011_V41_PUBLIC=')]
    priv=[line[17:] for line in lines if line.startswith('P011_V41_PRIVATE=')]
    if len(pub)!=1 or len(priv)!=1 or lines.count('P011_V41_DONE')!=1 or lines.count('P011_V41_STARTED')!=1:
        raise ValueError('remote_protocol')
    value=json.loads(pub[0])
    expected=set(BOOLS)|{'evidence','loaded_readonly_map_sha256','staged_native_map_sha256',
        'readonly_leaf_sha256','stage_native_files','original_root_entries'}
    if (type(value) is not dict or set(value)!=expected or
            any(type(value[key]) is not bool for key in BOOLS) or
            value['evidence']!='GO_WATCHDOG_DEVICE_V41_COMPONENT_ONLY' or
            value['loaded_readonly_map_sha256']!=MANIFEST_SHA or
            value['staged_native_map_sha256']!=GO_MANIFEST_SHA or value['readonly_leaf_sha256']!=LEAF_SHA or
            type(value['stage_native_files']) is not int or not 0<=value['stage_native_files']<=19 or
            type(value['original_root_entries']) is not int or not 0<=value['original_root_entries']<=4096):
        raise ValueError('remote_projection')
    if any(value[key] for key in DENIED):raise ValueError('remote_scope')
    return value,code


def _publish(output,report,pins):
    readme=('Actual P011 GO17 loader/watchdog component only when the explicit new trial passes.\n'
        'Default is PC SOURCE only, not device evidence. No RF, GO issuer/Store, controller, FD3 or phone test.\n'
        'Readonly35 parent and GO17 child are independent native class domains; Python ELF SHA is device-read.\n'
        'Private raw includes source payload, original stream bytes, argv/FD/inode/IP/process observations.\n'
        'Only one new GO EXCL token subtree and scratch600 flock file are added; partial additions remain.\n'
        'R, actual EOF, actual exit0/waitpid, original Proc absence, child-only OFD contention and closure are distinct.\n'
        'In-memory PersistReceipt only links the actual callback; it is not GoStore fsync/launch grant.\n'
        'Original120s target cap/one25s child cap/one150s HOST limit are not renewed; no retry/kill/repair/delete.\n')
    members=[('result.json',json.dumps(report,indent=2).encode('utf-8'))]
    if report.get('go_sources_staged') is True and report.get('watchdog_verified') is True:
        members.append(('source-pins.json',json.dumps(pins,indent=2).encode('utf-8')))
    members.append(('README.txt',readme.encode('utf-8')))
    if len(members)==3:
        members.append(('SHA256SUMS.txt',''.join(_sha(raw)+'  '+name+'\n' for name,raw in members).encode('ascii')))
    for name,raw in members:
        with (output/name).open('xb') as handle:handle.write(raw)
    archive=output/'public-result.zip'
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name,raw in members:bundle.writestr(name,raw)
    with zipfile.ZipFile(archive,'r') as bundle:
        if bundle.namelist()!=[name for name,raw in members] or bundle.testzip() is not None:
            raise ValueError('public_zip_crc')
        if any(bundle.getinfo(name).file_size!=len(raw) or bundle.read(name)!=raw for name,raw in members):
            raise ValueError('public_zip_readback')


def check_watchdog(expected_driver,transport):
    report,readonly_rows,go_rows,wpa,stage_raw,leaf_raw,go_map_raw,old_map_raw=source_check()
    if (type(expected_driver) is not str or re.fullmatch('[0-9a-f]{64}',expected_driver) is None or
            expected_driver!=report['driver_sha256'] or type(transport) is not str or
            re.fullmatch('[1-9][0-9]{0,9}',transport) is None):raise ValueError('reviewed_input')
    _fixed(ADB,ADB_SHA)
    parent=BASE/'results'
    if not parent.is_dir() or parent.is_symlink():raise ValueError('result_parent')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output=parent/('go-watchdog-device-v41-'+stamp+'-'+os.urandom(4).hex());output.mkdir(exist_ok=False)
    private=output/'private-raw';private.mkdir(exist_ok=False)
    pins={'loaded_readonly_map_sha256':MANIFEST_SHA,'staged_native_map_sha256':GO_MANIFEST_SHA,
        'leaf_sha256':LEAF_SHA,'runtime_sha256':STAGE_SHA,'static_reader_sha256':STATIC_SHA,
        'adb_exe_sha256':ADB_SHA,'wpa_sha256':WPA_SHA,'driver_sha256':expected_driver,
        'readonly_sources':[[n,z,h] for n,z,h,r in readonly_rows],
        'go_sources':[[n,z,h] for n,z,h,r in go_rows]}
    for name,raw in (('reviewed-driver.py',_fixed(Path(__file__).absolute(),expected_driver)),
            ('go-source-map.json',go_map_raw),('readonly-source-map.json',old_map_raw),
            ('runtime-source.py',stage_raw),('readonly-leaf.py',leaf_raw)):
        with (private/name).open('xb') as handle:handle.write(raw)
    try:
        report['adb_invoked']=True
        raw,err,code,timeout,elapsed=_run(private,'01-enumeration',[str(ADB),'devices','-l'],timeout=10)
        if timeout or code!=0:raise ValueError('enumeration_failed')
        selected=_select(raw,transport);report['target_selected']=True
        token=os.urandom(16).hex()
        payload=_payload(readonly_rows,go_rows,wpa,stage_raw,leaf_raw,token)
        with (private/'payload.py').open('xb') as handle:handle.write(payload)
        command=_transport(payload);report['stage_payload_attempted']=True
        raw,err,code,timeout,elapsed=_run(private,'02-native-go-watchdog',
            [str(ADB),'-t',selected,'shell',command],input_data=payload)
        report.update(host_exit=code,host_timeout=timeout,host_seconds=elapsed)
        report['stage_payload_started']=_started_marker(raw,payload)
        remote=_remote_exit(raw,payload)[0]
        (private/'02-native-go-watchdog.remote-exit').write_text(str(remote),encoding='ascii')
        report['remote_exit']=remote
        native,remote=_decode(raw,payload);report.update(native)
        good=(code==0 and not timeout and remote==0 and all(native[key] for key in
            ('attempted','ended','staging_attempted','before_read_closed','after_read_closed',
             'go_sources_staged','watchdog_verified','child_exit_verified','notify_eof_verified','child_ofd_verified')) and
            not native['resource_pending'] and native['stage_native_files']==19)
        report.update(go_sources_staged=bool(good),watchdog_verified=bool(good),
            remote_closure_verified=bool(good),reason='watchdog_component_closed' if good else 'watchdog_component_failed')
    except BaseException as error:
        report.update(go_sources_staged=False,watchdog_verified=False,
            remote_closure_verified=False,reason='watchdog_component_failed')
        (private/'driver-error.txt').write_text(type(error).__name__+'\n'+repr(error),encoding='utf-8')
    _publish(output,report,pins);report['result_directory']=str(output)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-watchdog',action='store_true')
    parser.add_argument('--expected-driver-sha256');parser.add_argument('--transport-id')
    args=parser.parse_args(argv)
    if args.check_watchdog!=(args.expected_driver_sha256 is not None) or args.check_watchdog!=(args.transport_id is not None):
        parser.error('Explicit check-watchdog, exact reviewed SHA and explicit transport are required together')
    try:
        report=check_watchdog(args.expected_driver_sha256,args.transport_id) if args.check_watchdog else source_check()[0]
        print(json.dumps(report,indent=2))
        return 0 if (report.get('watchdog_verified') if args.check_watchdog else report['source_check_pass']) else 1
    except Exception:
        report={'source_check_pass':False,'go_sources_staged':False,'watchdog_verified':False,
            'reason':'source_or_input_invalid','staging_attempted':False}
        for key in DENIED:report[key]=False
        print(json.dumps(report))
        return 1


if __name__=='__main__':
    sys.exit(main())
