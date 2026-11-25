"""One explicit, limited read-only observation of the retained GO64 reservation.

This HOST wrapper reads pinned private originals to choose the one fixed old
run. Target code opens existing files/locks only; no O_CREAT, helper, network
command, process signal, marker deletion or restoration/admission producer.
An exclusive nonblocking flock is temporary coordination, not a file write.
Two PID-path passes are observations, NOT Proc25-issued absence/CloseProof.
The interface check is sysfs netdev names, NOT a complete nl80211 WDEV dump.
All identifiers, original bytes and target raw output remain private. The
public ZIP contains only boolean/count projections and a scope description.
Default invocation does not create Adb or perform target IO.
"""
import argparse
import base64
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
SCHEMA = 'p011-go-bootstrap-v33-r2'
OLD = BASE / 'results/go-active-budget-v64-20261002-213823-170ca3c0/private-raw/native-private.json'
FIRST = BASE / 'results/device-state-readonly-20261004-005134-3391c163/private-raw/01-current-state-first.stdout.raw'
SECOND = BASE / 'results/device-state-readonly-20261004-005134-3391c163/private-raw/02-current-state-second.stdout.raw'
INPUT_PINS = (
    (OLD, 2812086, '8b263eeea803b39d04699a3b57c41582722be9b2a2bcd763f721229ffdbc629e'),
    (FIRST, 4953, 'b843527be7d8476f2a65a7ac58dc57001432e3c001dac10d32a0fd161d821536'),
    (SECOND, 4953, '7956b8a7a99172a8af74490c242496a593732cda63ca69f83ef5222922a001a2'),
    (BASE / 'runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    (BASE / 'host/device_probe.py', 8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
)
PENDING_SHA = '80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818'
JOURNAL_SHA = '01c200261bae27578881dd3ef97e165e848a14b877b883405a017bc298d210c6'
IDENTITY_KEYS = ('schema', 'run_token', 'candidate_sha', 'task_id', 'boot_id', 'issued_at', 'until')
ACTOR_KEYS = {'pid', 'start', 'exe', 'argv_sha', 'tasks'}
NETWORK_KEYS = ('interface_intent', 'owned', 'controller', 'group_add', 'group_observed')
JOURNAL_KEYS = set(IDENTITY_KEYS) | set(NETWORK_KEYS) | {
    'phase', 'generation', 'baseline', 'watchdog', 'cleanup_until', 'restored'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_inputs():
    result = {}
    for path, size, pin in INPUT_PINS:
        raw = path.read_bytes()
        if len(raw) != size or digest(raw) != pin:
            raise ValueError('fixed_input_changed')
        result[path] = raw
    return result


def actor_shape(value):
    if type(value) is not dict or set(value) != ACTOR_KEYS:
        raise ValueError('original_actor_shape')
    if (type(value['pid']) is not int or not 1 <= value['pid'] <= 0x7fffffff or
            type(value['start']) is not int or not 1 <= value['start'] < 2 ** 64 or
            type(value['exe']) is not str or not value['exe'].startswith('/') or
            type(value['argv_sha']) is not str or not re.fullmatch('[0-9a-f]{64}', value['argv_sha'])):
        raise ValueError('original_actor_shape')
    tasks = value['tasks']
    if type(tasks) is not list or not 1 <= len(tasks) <= 128:
        raise ValueError('original_actor_shape')
    for row in tasks:
        if (type(row) is not list or len(row) != 3 or type(row[0]) is not int or
                not 1 <= row[0] <= 0x7fffffff or type(row[1]) is not int or
                not 1 <= row[1] < 2 ** 64 or row[2] not in ('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I', 'P')):
            raise ValueError('original_actor_shape')
    if len({row[0] for row in tasks}) != len(tasks) or not any(row[:2] == [value['pid'], value['start']] for row in tasks):
        raise ValueError('original_actor_shape')
    return value


def fixed_config(inputs):
    original = json.loads(inputs[OLD].decode('utf-8'))
    process = original['process']
    journal = process['journal']
    if (type(journal) is not dict or set(journal) != JOURNAL_KEYS or journal['schema'] != SCHEMA or
            journal['phase'] != 'restore_intent' or type(journal['generation']) is not int or
            journal['generation'] != 4 or any(journal[key] is not None for key in NETWORK_KEYS) or
            journal['restored'] is not None or not re.fullmatch('[0-9a-f]{32}', journal['run_token'])):
        raise ValueError('original_journal_shape')
    rows = process['journal_rows']
    if type(rows) is not list or len(rows) != 1:
        raise ValueError('original_journal_rows')
    raw = base64.b64decode(rows[0]['raw']['bytes_b64'], validate=True)
    if (len(raw) != 7138 or digest(raw) != JOURNAL_SHA or rows[0]['sha256'] != JOURNAL_SHA or
            json.loads(raw.decode('ascii')) != journal or rows[0]['closed'] is not True or
            rows[0]['unknown'] is not False):
        raise ValueError('original_journal_bytes')
    pending = []
    for path in (FIRST, SECOND):
        # This fixed original is Python repr of an ASCII JSON bytes literal.
        # Never eval or parse a source AST. No escapes occur in this marker.
        matches = re.findall(r"b'(\{[^']*\})'", inputs[path].decode('utf-8'))
        matches = [text for text in matches if SCHEMA in text]
        if len(matches) != 1 or '\\' in matches[0]:
            raise ValueError('original_pending_literal')
        pending.append(matches[0].encode('ascii'))
    marker = json.loads(pending[0].decode('ascii'))
    if (pending[0] != pending[1] or len(pending[0]) != 340 or digest(pending[0]) != PENDING_SHA or
            set(marker) != set(IDENTITY_KEYS) or any(marker[key] != journal[key] for key in IDENTITY_KEYS)):
        raise ValueError('original_pending_identity')
    factor = actor_shape(process['child_actor'])
    watchdog = journal['watchdog']
    if (type(watchdog) is not dict or set(watchdog) != {'phase', 'spec_sha', 'argv_sha', 'until', 'actor'} or
            watchdog['phase'] != 'live' or watchdog['until'] != journal['until']):
        raise ValueError('original_watchdog')
    wactor = actor_shape(watchdog['actor'])
    argv = process['argv']
    if (factor['pid'] != process['pid'] or type(argv) is not list or
            any(type(item) is not str for item in argv) or
            digest(b''.join(item.encode('ascii') + b'\0' for item in argv)) != factor['argv_sha'] or
            factor['argv_sha'] != process['argv_sha256'] or wactor['argv_sha'] != watchdog['argv_sha']):
        raise ValueError('original_process_identity')
    return dict(schema=SCHEMA, run_token=journal['run_token'], boot=journal['boot_id'],
        pending_b64=base64.b64encode(pending[0]).decode('ascii'),
        journal_b64=base64.b64encode(raw).decode('ascii'), journal_metadata=rows[0]['metadata'],
        actors=[dict(role='f', actor=factor), dict(role='watchdog', actor=wactor)])


BODY = r'''
import ctypes,errno,hashlib,math,os,re,stat,sys,time
if (os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5)):
 raise ValueError('target_identity')
start=time.monotonic();end=start+30.0;last=start
if type(start) is not float or not math.isfinite(start):raise ValueError('clock_unknown')
codec_raw=base64.b64decode(CODEC_B64.encode('ascii'),validate=True)
if (len(codec_raw),hashlib.sha256(codec_raw).hexdigest())!=CODEC_PIN:raise ValueError('codec_pin')
codec={};exec(compile(codec_raw,'<fixed-p011-json>','exec'),codec)
cfg=codec['loads'](base64.b64decode(CONFIG_B64.encode('ascii'),validate=True).decode('ascii'))
if (type(cfg) is not dict or set(cfg)!={'schema','run_token','boot','pending_b64','journal_b64','journal_metadata','actors'} or
 cfg['schema']!='p011-go-bootstrap-v33-r2' or not re.fullmatch('[0-9a-f]{32}',cfg['run_token']) or
 not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',cfg['boot'])):raise ValueError('config_shape')
root='/var/volatile/tmp';area=root+'/p011-mta-go-session';run=area+'/go-'+cfg['run_token']
pending_path=root+'/p011-mta-p2p-device.pending'
device_path=root+'/p011-mta-p2p-device.lock';journal_path=run+'/go-journal.json';jlock_path=run+'/go-journal.lock'
expected_pending=base64.b64decode(cfg['pending_b64'].encode('ascii'),validate=True)
expected_journal=base64.b64decode(cfg['journal_b64'].encode('ascii'),validate=True)
identity=('schema','run_token','candidate_sha','task_id','boot_id','issued_at','until')
network=('interface_intent','owned','controller','group_add','group_observed')
expected=codec['loads'](expected_journal.decode('ascii'))
if (len(expected_pending)!=340 or len(expected_journal)!=7138 or expected['schema']!=cfg['schema'] or
 expected['run_token']!=cfg['run_token'] or expected['boot_id']!=cfg['boot'] or expected['phase']!='restore_intent' or
 type(expected['generation']) is not int or expected['generation']!=4 or any(expected[k] is not None for k in network) or
 expected['restored'] is not None or type(cfg['actors']) is not list or len(cfg['actors'])!=2):raise ValueError('config_shape')
rows=[];anchors=[];locks=[];errors=[];first_error=None;stage='begin'
RFLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
if (os.O_NOFOLLOW!=0x8000 or os.O_CLOEXEC!=0x80000 or os.O_NONBLOCK!=0x800):raise ValueError('target_flags')
libc=ctypes.CDLL(None,use_errno=True);flock=libc.flock;flock.argtypes=(ctypes.c_int,ctypes.c_int);flock.restype=ctypes.c_int
result=dict(complete=False,record_match=False,same_boot=False,old_period_expired=False,locks_acquired=False,
 records_unchanged=False,actors_paths_absent=False,project_netdevs_absent=False,old_unix_live_absent=False,
 local_fds_closed=False,read_only=True,rows=rows,before=None,after=None,actor_passes=[],network_passes=[],
 error=None,close_errors=[],paths=dict(pending=pending_path,journal=journal_path,device_lock=device_path,journal_lock=jlock_path))

def fail(code):raise ValueError(code)
def now():
 global last
 value=time.monotonic()
 if type(value) is not float or not math.isfinite(value) or value<last:fail('clock_unknown')
 last=value
 if value>=end:fail('read_deadline')
 return value
def meta(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def dirsig(value):return meta(value)[:5]
def close(row):
 if row['closed'] or row['close_called']:return
 if not row['returned']:
  if not row['open_called'] or row['no_fd']:row['closed']=True;row['unknown']=False;return
  fail('close_unknown')
 if row['unknown'] or row['signature'] is None:fail('close_unknown')
 # Closing this already-held original descriptor neither renews IO nor touches
 # a path; do not refuse physical cleanup merely because the read cap expired.
 try:
  if meta(os.fstat(row['fd']))[:6]!=row['signature']:fail('close_identity')
  row['close_called']=True
  returned=os.close(row['fd']);row['close_returned']=True;row['close_result']=returned
  try:os.fstat(row['fd'])
  except OSError as error:
   if type(error.errno) is int and error.errno==errno.EBADF:
    row['ebadf']=True;row['closed']=returned is None
  if not row['closed']:row['unknown']=True;fail('close_unknown')
 except BaseException:
  row['unknown']=True;raise
def opened(path,role,directory=False):
 now()
 if len(rows)>=40:fail('open_limit')
 row=dict(role=role,path=path,fd=None,metadata=None,signature=None,open_called=False,returned=False,
  no_fd=False,unknown=True,close_called=False,close_returned=False,close_result=None,ebadf=False,closed=False)
 rows.append(row)
 before=os.lstat(path)
 flags=RFLAGS|(os.O_DIRECTORY if directory else 0)
 now();row['open_called']=True
 try:fd=os.open(path,flags)
 except OSError as error:
  if type(error.errno) is int and 1<=error.errno<=4095:row['no_fd']=True;row['unknown']=False
  raise
 row['fd']=fd;row['returned']=True
 if type(fd) is not int or fd<0:fail('open_unknown')
 actual=os.fstat(fd);row['metadata']=meta(actual);row['signature']=meta(actual)[:6];row['unknown']=False
 if meta(actual)!=meta(before) or meta(os.lstat(path))!=meta(before):fail('open_identity')
 if directory:
  if not stat.S_ISDIR(actual.st_mode):fail('directory_shape')
 elif not stat.S_ISREG(actual.st_mode):fail('file_shape')
 now();return row
def anchors_current():
 for row,signature,mode in anchors:
  if row['closed'] or row['unknown'] or dirsig(os.fstat(row['fd']))!=signature or dirsig(os.lstat(row['path']))!=signature:fail('anchor_changed')
  if os.path.realpath(row['path'])!=row['path']:fail('anchor_alias')
 now()
def lock_current():
 anchors_current()
 for row in locks:
  if row['closed'] or row['unknown'] or not row.get('flock_acquired') or meta(os.fstat(row['fd']))!=row['metadata'] or meta(os.lstat(row['path']))!=row['metadata']:fail('lock_changed')
 now()
def read_file(path,limit,role,held_record=False):
 row=opened(path,role);read_error=None
 try:
  m=row['metadata']
  if m[6]<0 or m[6]>limit:fail('read_limit')
  if held_record and (m[3:6]!=(0,0,1) or stat.S_IMODE(m[2])!=0o600):fail('record_shape')
  data=b''
  while True:
   now();requested=min(4096,limit+1-len(data));chunk=os.read(row['fd'],requested)
   if type(chunk) is not bytes or len(chunk)>requested:fail('read_return')
   data+=chunk;row['raw']=data
   if len(data)>limit:fail('read_limit')
   if not chunk:break
  if held_record and len(data)!=m[6]:fail('read_identity')
  if meta(os.fstat(row['fd']))!=m or meta(os.lstat(path))!=m:fail('read_identity')
  row['raw']=data;now();return data,m
 except BaseException as error:
  read_error=error;raise
 finally:
  try:close(row)
  except BaseException as error:
   errors.append(error);result['close_errors'].append(dict(role=row['role'],kind=type(error).__name__,errno=error.errno if isinstance(error,OSError) and type(error.errno) is int else None))
   if read_error is None:raise
def records():
 lock_current()
 p,pm=read_file(pending_path,131072,'pending',True);j,jm=read_file(journal_path,131072,'journal',True)
 if p!=expected_pending or j!=expected_journal:fail('record_changed')
 document=codec['loads'](j.decode('ascii'));marker=codec['loads'](p.decode('ascii'))
 if (set(marker)!=set(identity) or set(document)!=set(expected) or
  any(marker[k]!=document[k] or type(marker[k]) is not type(document[k]) for k in identity) or document!=expected):fail('record_identity')
 if list(jm)!=cfg['journal_metadata']:fail('historical_journal_metadata_changed')
 lock_current();return dict(pending_raw=p,pending_metadata=pm,journal_raw=j,journal_metadata=jm)
def path_state(path):
 now()
 try:value=os.lstat(path)
 except OSError as error:
  now()
  if type(error.errno) is int and error.errno==errno.ENOENT:return None
  raise
 now();return meta(value)
def actor_pass():
 lock_current();values=[]
 for source in cfg['actors']:
  actor=source['actor'];pid=actor['pid'];tasks=actor['tasks']
  if type(pid) is not int or pid<1 or type(tasks) is not list or not tasks:fail('actor_shape')
  p='/proc/'+str(pid);paths=[p,p+'/task']
  for task in tasks:paths.extend(('/proc/'+str(task[0]),p+'/task/'+str(task[0])))
  states=[(path,path_state(path)) for path in sorted(set(paths))]
  actual_start=None;stat_raw=None
  if states[[item[0] for item in states].index(p)][1] is not None:
   stat_raw,unused=read_file(p+'/stat',8192,'actor_stat')
   stop=stat_raw.rfind(b') ');fields=stat_raw[stop+2:].split()
   if stop<0 or not stat_raw.startswith(str(pid).encode('ascii')+b' (') or len(fields)<20 or not re.fullmatch(b'[0-9]+',fields[19]):fail('actor_stat_shape')
   actual_start=int(fields[19])
  values.append(dict(role=source['role'],expected=actor,paths=states,raw_stat=stat_raw,current_start=actual_start,
   all_paths_absent=all(item[1] is None for item in states),pid_reused=actual_start is not None and actual_start!=actor['start']))
 lock_current();return values
def network_pass():
 lock_current();names=os.listdir('/sys/class/net')
 if type(names) is not list or len(names)>128 or any(type(n) is not str or not re.fullmatch('[A-Za-z0-9_.:-]{1,64}',n) for n in names):fail('netdev_shape')
 project=tuple(sorted(n for n in names if re.fullmatch('mta[0-9a-f]{8}',n) or n.startswith('p2p')))
 entries=os.listdir(run)
 if type(entries) is not list or len(entries)>4096:fail('run_entries_limit')
 endpoints=[]
 for name in sorted(entries):
  if re.fullmatch('go-read-[0-9]{4}',name):endpoints.append((name,path_state(run+'/'+name)))
 ctrl=run+'/ctrl';ctrlmeta=path_state(ctrl);ctrlentries=[]
 if ctrlmeta is not None:
  if not stat.S_ISDIR(ctrlmeta[2]) or ctrlmeta[3:5]!=(0,0) or stat.S_IMODE(ctrlmeta[2])!=0o700:fail('ctrl_shape')
  ctrlentries=os.listdir(ctrl)
  if type(ctrlentries) is not list or len(ctrlentries)>128:fail('ctrl_entries_limit')
  for name in sorted(ctrlentries):
   if type(name) is not str or not re.fullmatch('[A-Za-z0-9_.-]{1,64}',name):fail('ctrl_entries_limit')
   endpoints.append(('ctrl/'+name,path_state(ctrl+'/'+name)))
 unix,unused=read_file('/proc/net/unix',65536,'unix_table');live=[]
 for line in unix.decode('ascii').splitlines()[1:]:
  fields=line.split(None,7)
  if len(fields) not in (7,8):fail('unix_shape')
  if len(fields)==8 and fields[7].startswith(run+'/'):live.append(tuple(fields))
 lock_current();return dict(netdevs=tuple(sorted(names)),project_netdevs=project,old_endpoint_paths=endpoints,old_unix_live=live,unix_raw=unix)

try:
 stage='anchors'
 for path,mode in (('/',None),('/var',0o755),('/var/volatile',0o1777),('/var/volatile/tmp',0o1777),(area,0o700),(run,0o700)):
  row=opened(path,'anchor',True);m=row['metadata']
  if m[3:5]!=(0,0) or mode is not None and stat.S_IMODE(m[2])!=mode:fail('anchor_shape')
  anchors.append((row,m[:5],mode))
 anchors_current();stage='locks'
 for path in (device_path,jlock_path):
  row=opened(path,'lock');locks.append(row);m=row['metadata']
  if m[3:7]!=(0,0,1,0) or stat.S_IMODE(m[2])!=0o600:fail('lock_shape')
  now();row['flock_called']=True;ctypes.set_errno(0);answer=flock(row['fd'],6)
  row['flock_return']=answer;row['flock_errno']=ctypes.get_errno()
  if answer!=0:fail('lock_busy_or_unknown')
  row['flock_acquired']=True;lock_current()
 result['locks_acquired']=True;stage='before'
 beforeboot,unused=read_file('/proc/sys/kernel/random/boot_id',128,'boot')
 if beforeboot.strip().decode('ascii')!=cfg['boot']:fail('boot_changed')
 result['before']=records();result['record_match']=True;result['same_boot']=True
 result['old_period_expired']=now()>=expected['until']
 stage='first_paths';result['actor_passes'].append(actor_pass());result['network_passes'].append(network_pass())
 stage='second_paths';result['actor_passes'].append(actor_pass());result['network_passes'].append(network_pass())
 stage='after';result['after']=records()
 afterboot,unused=read_file('/proc/sys/kernel/random/boot_id',128,'boot')
 if afterboot!=beforeboot:fail('boot_changed')
 result['records_unchanged']=result['before']==result['after']
 result['actors_paths_absent']=all(row['all_paths_absent'] for group in result['actor_passes'] for row in group)
 result['project_netdevs_absent']=all(not row['project_netdevs'] for row in result['network_passes'])
 result['old_unix_live_absent']=all(not row['old_unix_live'] for row in result['network_passes'])
 lock_current();now();stage='complete'
except BaseException as error:
 first_error=error;errors.append(error)
 result['error']=dict(stage=stage,kind=type(error).__name__,errno=error.errno if isinstance(error,OSError) and type(error.errno) is int else None)
finally:
 # Locks stay held through the whole observation. Close journal/device OFDs
 # last, never retry a previously attempted original FD by its numeric value.
 ordered=[r for r in reversed(rows) if r not in locks]+list(reversed(locks))
 for row in ordered:
  try:close(row)
  except BaseException as error:
   errors.append(error);result['close_errors'].append(dict(role=row['role'],kind=type(error).__name__,errno=error.errno if isinstance(error,OSError) and type(error.errno) is int else None))
 result['local_fds_closed']=all(r['closed'] and not r['unknown'] for r in rows)
result['complete']=first_error is None and not result['close_errors'] and result['local_fds_closed'] and stage=='complete'
print('RESULT='+repr(result))
'''


def b64_literal(name, raw):
    value = base64.b64encode(raw).decode('ascii')
    return name + '=(\n' + ''.join(repr(value[i:i + 1024]) + '\n' for i in range(0, len(value), 1024)) + ')\n'


def source(inputs, config):
    raw = json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    value = ('import base64\n' + b64_literal('CODEC_B64', inputs[BASE / 'runtime/p011_json.py']) +
        'CODEC_PIN=' + repr((8061, INPUT_PINS[3][2])) + '\n' + b64_literal('CONFIG_B64', raw) + BODY)
    if len(value.encode('utf-8')) > 65536 or any(len(line.encode('utf-8')) > 2048 for line in value.splitlines()):
        raise ValueError('target_source_limit')
    return value


def public_projection(value, source_unchanged, adb_unchanged):
    available = type(value) is dict
    flag = lambda key: available and value.get(key) is True
    actors = value.get('actor_passes', []) if available else []
    networks = value.get('network_passes', []) if available else []
    rows = value.get('rows', []) if available else []
    complete = flag('complete') and source_unchanged and adb_unchanged
    return dict(schema='p011-old-go-pending-readonly-20261004', diagnostic_complete=complete,
        remote_result_available=available, source_before_after_equal=source_unchanged,
        adb_before_after_equal=adb_unchanged, original_record_match=flag('record_match'),
        records_before_after_equal=flag('records_unchanged'), same_original_boot=flag('same_boot'),
        old_active_period_expired=flag('old_period_expired'), existing_locks_acquired=flag('locks_acquired'),
        original_watchdog_and_f_paths_absent_twice=flag('actors_paths_absent'),
        project_netdev_names_absent_twice=flag('project_netdevs_absent'),
        old_run_unix_live_endpoints_absent_twice=flag('old_unix_live_absent'),
        local_original_fds_closed=flag('local_fds_closed'), actor_pass_count=len(actors),
        actor_observation_count=sum(len(group) for group in actors), network_pass_count=len(networks),
        project_netdev_counts=[len(row['project_netdevs']) for row in networks],
        old_live_unix_counts=[len(row['old_unix_live']) for row in networks],
        old_filesystem_endpoint_counts=[len(row['old_endpoint_paths']) for row in networks],
        opened_fd_count=sum(row['returned'] is True for row in rows),
        known_closed_fd_count=sum(row['closed'] is True and row['unknown'] is False for row in rows),
        local_close_error_count=len(value.get('close_errors', [])) if available else 0,
        target_files_created=False, target_files_deleted=False, target_file_bytes_changed=False,
        helper_started=False, process_signalled=False, network_configuration=False,
        radio_operations=False, diagnostic_absence_only=True, no_original_absence_ticket=True,
        proc_issuer_absence_verified=False,
        non_netdev_p2p_absence_verified=False, complete_netlink_baseline_verified=False,
        historical_full_snapshot_key_equal=False, old_native_inventory_closure_verified=False,
        journal_reconciled_verified=False, pending_retired=False, restoration_grant_issued=False,
        full_network_restore_verified=False, admission_issued=False, receive_available=False,
        send_available=False, phone_tested=False, private_raw_included=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-current', action='store_true', required=True)
    parser.parse_args()
    inputs = fixed_inputs()
    config = fixed_config(inputs)
    target = source(inputs, config)
    # Import this pinned HOST transport only after checking its exact bytes.
    from device_probe import Adb, ADB
    own_raw = Path(__file__).read_bytes()
    adb_raw = ADB.read_bytes()
    out = BASE / 'results' / ('go-pending-readonly-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    (private / 'host-source.py').write_bytes(own_raw)
    (private / 'target-source.py').write_bytes(target.encode('utf-8'))
    (private / 'original-config.json').write_text(json.dumps(config, ensure_ascii=True, indent=2) + '\n', encoding='ascii')
    value = None
    failure = None
    try:
        adb = Adb(private)
        value = adb.python('old-go-reservation-readonly', target, timeout=45)
        (private / 'remote-result.json').write_text(json.dumps(value, ensure_ascii=True, indent=2,
            default=lambda item: {'bytes': len(item), 'bytes_b64': base64.b64encode(item).decode('ascii')}
            if type(item) is bytes else None) + '\n', encoding='ascii')
    except BaseException as error:
        failure = error
        (private / 'host-error.txt').write_text(type(error).__name__ + '\n', encoding='ascii')
    source_ok = False
    try:
        source_ok = fixed_inputs() == inputs and Path(__file__).read_bytes() == own_raw
    except BaseException:
        pass
    public = public_projection(value, source_ok, ADB.read_bytes() == adb_raw)
    if failure is not None:
        public['diagnostic_complete'] = False
    result_raw = (json.dumps(public, ensure_ascii=True, indent=2) + '\n').encode('ascii')
    readme = (b'Limited old GO64 reservation read-only observation only. Existing file reads and temporary nonblocking flock; no target file creation/deletion, helper, process signal, RF or network command.\n'
        b'Two PID-path passes are not Proc25-issued absence. Sysfs netdev names do not cover non-netdev P2P WDEVs. Old Unix filesystem paths and live kernel endpoints are separate.\n'
        b'No complete historical Snapshot.key comparison, old Native inventory proof, reconciliation, pending retirement, restored/ready/admission grant or phone acceptance. Raw identifiers and originals remain private.\n')
    (out / 'result.json').write_bytes(result_raw)
    (out / 'README.txt').write_bytes(readme)
    with zipfile.ZipFile(out / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result_raw)
        archive.writestr('README.txt', readme)
    print(json.dumps(dict(directory=str(out), result=public), ensure_ascii=True))
    return 0 if public['diagnostic_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
