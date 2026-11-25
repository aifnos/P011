"""Integrated v9 fixed P011 CLIENT init/restore; default source-only, no RF.

ROOT alone approves the final source graph and explicit execution. No old
pending cleanup, source fallback, transport kill or automatic retry exists.
"""
import argparse
import ast
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
import traceback
import types
import zipfile

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
STATUS_DRIVER_SHA = '99362b8c2a5872737d692672774afe000e630155a556ddef950869fb25a3e50b'
ADB_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
EXECUTOR_SHA = '1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3'
PROVIDER_SHA = '8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
NATIVE = BASE / 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant'
PINS = (
    ('p011_json', 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a'),
    ('mta_client_proc', '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'),
    ('mta_client_caps', 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('mta_client_baseline', '1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1'),
    ('mta_client_journal_codec', '17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73'),
    ('mta_client_coordination', 'ea2f27c6920b4dd2cf47e5f71015382bd08dba65ed7eba9927c16f9a219b408d'),
    ('mta_client_files', 'd95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3'),
    ('mta_client_pending', 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af'),
    ('mta_client_store', '2c1bcd60013e416fe4d0ef961ceef3bc700ceae6bc40c4c079bab0a663b411cb'),
    ('mta_client_process_owner', '219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76'),
    ('mta_client_launch_registration', '833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0'),
    ('mta_client_two_phase_lease', '402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005'),
    ('mta_p2p_client_ctrl', '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'),
    ('mta_client_wpa_status', '4f0fa75132c8c81427f1d593fdc415b01657b061cd9d1dbcbcde789b52daf742'),
    ('mta_client_linux_provider', PROVIDER_SHA), ('mta_client_executor', EXECUTOR_SHA))
SOURCE_LOCATIONS = {
    'mta_client_executor': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_executor.py',
    'mta_client_process_owner': BASE / 'candidate/client-init-nlink2/runtime/mta_client_process_owner.py',
    'mta_client_baseline': BASE / 'candidate/client-readparts-v6/runtime/mta_client_baseline.py',
    'mta_p2p_client_init': BASE / 'candidate/client-caps-v7/runtime/mta_p2p_client_init.py',
    'mta_client_pending': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_pending.py',
    'mta_client_store': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_store.py',
    'mta_client_linux_provider': BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py'}
MAX_SOURCE, MAX_RAW = 4 * 1024 * 1024, 16 * 1024 * 1024
_ATTEMPTS = []
_BOOLS = ('source_check_pass', 'target_selected', 'remote_reply_confirmed', 'pending_absence_before',
    'staging_attempted', 'staging_verified', 'rf_requested', 'client_init_observed', 'parent_waited',
    'parent_absence_verified', 'parent_resources_closed', 'baseline_before_after_equal',
    'pending_absence_after', 'restoration_verified', 'resource_pending', 'pass', 'send_available',
    'receive_available', 'phone_tested')
_STAGES = ('source_only', 'unavailable', 'platform', 'pending', 'python', 'baseline_before',
    'stage', 'staged', 'pending_before_rf', 'parent', 'baseline_after', 'complete', 'transport_unknown')
_REASONS = ('source_only', 'unavailable', 'not_recorded', 'complete', 'platform', 'pending_blocked',
    'python_invalid', 'baseline_invalid', 'stage_exists', 'stage_unknown', 'parent_pending', 'budget_before_rf',
    'restoration_pending', 'os_error', 'unexpected', 'interrupted', 'transport_unknown')


def _hash(raw): return hashlib.sha256(raw).hexdigest()


def _read(path, pin, limit=262144):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)): raise ValueError('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= limit: raise ValueError('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno()); raw = handle.read(limit + 1)
    after = path.stat()
    # On CPython 3.12/Windows stat and fstat expose different legacy ctime
    # semantics. Preserve path ctime before/after; do not equate it to FD ctime.
    if any(getattr(before, key) != getattr(opened, key) or getattr(before, key) != getattr(after, key)
           for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')) or \
            before.st_ctime_ns != after.st_ctime_ns or \
            os.name != 'nt' and before.st_ctime_ns != opened.st_ctime_ns or len(raw) != before.st_size:
        raise ValueError('source_changed')
    if pin is not None and _hash(raw) != pin: raise ValueError('source_pin')
    return raw


def _module(path, pin, name):
    raw = _read(path, pin); value = types.ModuleType(name); value.__file__ = str(path)
    exec(raw, value.__dict__); return value


def _literal(value):
    """Bounded multiline Python literal, never a >4095-byte canonical line."""
    if type(value) in (tuple, list):
        return '(\n' + ''.join(_literal(v) + ',\n' for v in value) + ')'
    if type(value) is dict:
        return '{\n' + ''.join(repr(k) + ':' + _literal(v) + ',\n' for k, v in sorted(value.items())) + '}'
    if value is None or type(value) in (str, int, bool):
        text = repr(value)
        if len(text.encode('utf-8')) > 2048: raise ValueError('source_line')
        return text
    raise ValueError('source_literal')


def _encoded(rows):
    chunks = []
    for name, pin, raw in rows:
        encoded = base64.b64encode(raw).decode('ascii')
        chunks.append('(%r,%r,\n%s),\n' % (name, pin,
            '\n'.join(repr(encoded[i:i+1000]) for i in range(0, len(encoded), 1000))))
    return '(\n' + ''.join(chunks) + ')'


LOADER = '''import base64,builtins,hashlib,types
modules={};payloads={};original=builtins.__import__
def pinned_import(name,globals=None,locals=None,fromlist=(),level=0):
 if name in dict(PINS):
  if level or name not in modules:raise ValueError('memory_order')
  return modules[name]
 if level or name.startswith(('mta_','p011_')):raise ValueError('memory_import')
 return original(name,globals,locals,fromlist,level)
for name,pin,encoded in ENCODED:
 raw=base64.b64decode(encoded.encode('ascii'),validate=True)
 if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('memory_pin')
 payloads[name]=raw
 module=types.ModuleType(name);module.__file__='<pinned-client-init-host>'
 module.__dict__['__builtins__']=dict(vars(builtins),__import__=pinned_import)
 exec(raw,module.__dict__);modules[name]=module
'''

TARGET = r'''
import errno,os,stat,sys,time,traceback
f=modules['mta_client_executor'];core=modules['mta_p2p_client_init'];proc=modules['mta_client_proc']
pm=modules['mta_client_linux_provider'];codec=modules['p011_json']
public={key:False for key in BOOLS};public.update(source_check_pass=True,resource_pending=False,stage='platform',reason='not_recorded')
private={'source_graph':CANDIDATE,'errors':[],'owners':[],'writes':[],'reads':[],'parent':None}
end=time.monotonic()+165
def fail(reason):raise ValueError(reason)
def check():
 if time.monotonic()>=end:fail('unexpected')
def pending_absent():
 check()
 try:os.lstat('/tmp/p011-mta-p2p-device.pending')
 except OSError as error:
  if type(error.errno) is int and error.errno==errno.ENOENT:return True
  raise
 fail('pending_blocked')
def same(a,b):
 return a.key()==b.key() and all(x.live() for x in a.stock_actors) and all(x.live() for x in b.stock_actors)
def projection(value):
 if value is None or type(value) in (str,bytes,int,float,bool):return value
 if type(value) in (tuple,list):return tuple(projection(x) for x in value)
 if type(value) is dict:return {key:projection(x) for key,x in value.items()}
 if hasattr(value,'__slots__'):return {key:projection(getattr(value,key)) for key in value.__slots__ if not key.startswith('_')}
 return '<private retained owner>'
def directory(path,create=False):
 check()
 if create:os.mkdir(path,0o700)
 f._ReadOwner(f._LinuxIo(),time.monotonic,time.monotonic()+2).anchors(path,True)
 value=f._meta(os.lstat(path))
 if not stat.S_ISDIR(value[2]) or value[3:5]!=(0,0) or stat.S_IMODE(value[2])!=0o700:fail('stage_unknown')
 return value[:6]
def read_proc(kind,*args):
 row={'kind':'proc','owner':None,'unknown':True};private['reads'].append(row)
 reader=proc.ProcReader(timeout=3);row['owner']=reader;row['unknown']=False;private['owners'].append(reader)
 return reader,getattr(reader,kind)(*args)
def reads_closed():
 for row in private['reads']:
  owner=row['owner']
  if row['unknown'] or owner is None:return False
  if row['kind']=='proc':
   if not f._reader_closed(owner):return False
  elif owner.pending or any(x['unknown'] or not x['closed'] for x in owner.rows):return False
 return True
def publish(path,raw,mode):
 check();row={'path':path,'fd':None,'meta':None,'unknown':True,'attempted':False,'closed':False};private['writes'].append(row)
 try:
  row['fd']=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  row['meta']=f._meta(os.fstat(row['fd']))
  if not stat.S_ISREG(row['meta'][2]) or row['meta'][3:6]!=(0,0,1) or stat.S_IMODE(row['meta'][2])!=0o600:fail('stage_unknown')
  row['unknown']=False;position=0
  while position<len(raw):
   check();count=os.write(row['fd'],raw[position:position+65536])
   if type(count) is not int or not 1<=count<=min(65536,len(raw)-position):fail('stage_unknown')
   position+=count
  os.fsync(row['fd']);os.lseek(row['fd'],0,0);data=b''
  while len(data)<=len(raw):
   check();part=os.read(row['fd'],min(65536,len(raw)+1-len(data)))
   if type(part) is not bytes:fail('stage_unknown')
   data+=part
   if not part:break
  if data!=raw or f._meta(os.fstat(row['fd']))[:6]!=row['meta'][:6]:fail('stage_unknown')
  os.fchmod(row['fd'],mode);os.fsync(row['fd']);row['meta']=f._meta(os.fstat(row['fd']))
  if row['meta']!=f._meta(os.lstat(path)) or stat.S_IMODE(row['meta'][2])!=mode:fail('stage_unknown')
 finally:
  if not row['unknown']:
   row['attempted']=True
   try:
    if f._meta(os.fstat(row['fd']))!=row['meta']:fail('stage_unknown')
    returned=os.close(row['fd'])
    try:os.fstat(row['fd'])
    except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
   except BaseException:pass
  if not row['closed']:public['resource_pending']=True
 if not row['closed']:fail('stage_unknown')
before=after=None;provider=None;parent=None
try:
 if sys.flags.optimize or tuple(sys.version_info[:3])!=(3,5,5):fail('platform')
 f._LinuxIo().validate()
 public['stage']='pending';public['pending_absence_before']=pending_absent()
 public['stage']='python'
 reader,observed=read_proc('read_self');private['python_before']=projection(observed)
 actor=f._actor(observed,core,proc,True)
 if not f._reader_closed(reader):fail('python_invalid')
 read_row={'kind':'file','owner':None,'unknown':True};private['reads'].append(read_row)
 files=f._ReadOwner(f._LinuxIo(),time.monotonic,time.monotonic()+10);read_row['owner']=files;read_row['unknown']=False;private['owners'].append(files)
 try:
  raw,row=files.read_file(actor.exe,16777216,binary=True)
  if raw[:7]!=b'\x7fELF\x01\x01\x01' or len(raw)<52 or int.from_bytes(raw[18:20],'little')!=40:fail('python_invalid')
  python_sha=hashlib.sha256(raw).hexdigest()
 finally:
  try:
   if not files.close():fail('python_invalid')
  finally:
   private['python_files']=tuple({key:projection(item.get(key)) for key in
    ('path','fd','metadata','unknown','attempted','closed')} for item in files.rows)
 reader2,current=read_proc('read_actor',actor.pid,actor);private['python_after']=projection(current)
 if f._actor(current,core,proc,True).key()!=actor.key() or current.boot!=observed.boot or not f._reader_closed(reader2):fail('python_invalid')
 run=f.ROOT+'/client-'+TOKEN
 provider_value={'version':1,'run_token':TOKEN,'candidate_sha':CANDIDATE_SHA,'ifname':'mta'+TOKEN[:8],
  'baseline_manifest':BASELINE_MANIFEST,'status_manifest':STATUS_MANIFEST,'wpa_exe':run+'/native/mta-wpa-supplicant',
  'wpa_sha':WPA_SHA,'python_exe':actor.exe,'python_sha':python_sha,
  'executor_path':run+'/runtime/mta_client_executor.py','executor_sha':dict(PINS)['mta_client_executor']}
 deployment={'version':1,'provider':provider_value,'sources':[list(row) for row in PINS]}
 deployment_raw=codec.dumps(deployment,sort_keys=True).encode('utf-8');deployment_sha=hashlib.sha256(deployment_raw).hexdigest()
 manifest=pm.ProviderManifest(provider_value,_manifest_sha256=deployment_sha)
 assembly=pm.assemble(manifest);private['owners'].append(assembly);provider=assembly[0]
 public['stage']='baseline_before';provider.executor(time.monotonic()+5)
 before=provider.snapshot(time.monotonic()+5);private['baseline_before']=projection(before)
 if not provider.original_actors(before,time.monotonic()+5):fail('baseline_invalid')
 proof=provider.close_resources((),time.monotonic()+5);private['preview_close']=projection(proof)
 if type(proof) is not core.CloseProof or not proof.complete():fail('baseline_invalid')
 pending_absent();public['stage']='stage';public['staging_attempted']=True
 try:root_meta=directory(f.ROOT)
 except OSError as error:
  if type(error.errno) is not int or error.errno!=errno.ENOENT:raise
  root_meta=directory(f.ROOT,True)
 if os.listdir(f.ROOT):fail('stage_exists')
 for path in (run,run+'/runtime',run+'/native',run+'/ctrl'):directory(path,True)
 for name,pin in PINS:publish(run+'/runtime/'+name+'.py',payloads[name],0o400)
 wpa=base64.b64decode(WPA_ENCODED.encode('ascii'),validate=True)
 if hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_unknown')
 publish(run+'/native/mta-wpa-supplicant',wpa,0o500)
 candidate_raw=base64.b64decode(CANDIDATE_ENCODED.encode('ascii'),validate=True)
 if hashlib.sha256(candidate_raw).hexdigest()!=CANDIDATE_SHA or codec.loads(candidate_raw.decode('utf-8'))!=codec.loads(codec.dumps(CANDIDATE)):fail('stage_unknown')
 publish(run+'/candidate.json',candidate_raw,0o400)
 publish(run+'/deployment.json',deployment_raw,0o400)
 for path in (run+'/runtime',run+'/native',run, f.ROOT):
  row={'path':path,'fd':None,'unknown':True,'attempted':False,'closed':False};private['writes'].append(row)
  try:
   row['fd']=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
   row['meta']=f._meta(os.fstat(row['fd']))
   if row['meta'][:6]!=directory(path) or row['meta']!=f._meta(os.lstat(path)):fail('stage_unknown')
   row['unknown']=False;os.fsync(row['fd'])
  finally:
   if not row['unknown']:
    row['attempted']=True
    try:
     if f._meta(os.fstat(row['fd']))!=row['meta']:fail('stage_unknown')
     returned=os.close(row['fd'])
     try:os.fstat(row['fd'])
     except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
    except BaseException:pass
   if not row['closed']:public['resource_pending']=True
  if not row['closed']:fail('stage_unknown')
 loader=f.DeploymentLoader(TOKEN,deployment_sha);private['owners'].append(loader)
 loaded=loader.load();loader.authenticate(loaded)
 read_row={'kind':'file','owner':None,'unknown':True};private['reads'].append(read_row)
 verify=f._ReadOwner(f._LinuxIo(),time.monotonic,time.monotonic()+3);read_row['owner']=verify;read_row['unknown']=False
 try:
  if verify.read_file(run+'/candidate.json',65536,CANDIDATE_SHA,True)[0]!=candidate_raw:fail('stage_unknown')
 finally:
  if not verify.close():fail('stage_unknown')
 public['staging_verified']=True;public['stage']='pending_before_rf';pending_absent()
 fresh=provider.snapshot(time.monotonic()+5);private['baseline_before_rf']=projection(fresh)
 if not same(before,fresh) or not provider.closed_resources((),time.monotonic()+5).complete():fail('baseline_invalid')
 pending_absent()
 if not end-time.monotonic()>=125:fail('budget_before_rf')
 public['stage']='parent';parent=f.ParentExecutor(loaded);private['owners'].append(parent)
 public['rf_requested']=True;initial=parent.start(ttl=20);private['parent_initial']=initial
 ready_end=time.monotonic()+22
 if parent.actor is not None and not parent.spawn_ticket['unknown']:
  while time.monotonic()<ready_end:
   parent.poll()
   if parent.frames and (parent.frames[-1]['client_init_ready'] or parent.frames[-1]['done']):break
   if parent.failures:break
   parent.io.ready(tuple(row['fd'] for row in parent.pipes[1:]),.05)
 result=parent.finish(timeout=90);private['parent']=result
 public['client_init_observed']=any(row['client_init_ready'] for row in parent.frames)
 for key in ('parent_waited','parent_absence_verified','parent_resources_closed'):public[key]=result[key]
 private['f_stdout']=tuple(raw for index,raw in parent.raw if index==1)
 private['f_stderr']=tuple(raw for index,raw in parent.raw if index==2)
 private['f_exit']=parent.exit_code;private['f_frames']=parent.frames
 private['parent_errors']=tuple({'class':type(error).__name__,'code':getattr(error,'code',None)} for error in parent.failures)
 if result['resource_pending']:public['resource_pending']=True
 public['stage']='baseline_after';after=provider.snapshot(time.monotonic()+5);private['baseline_after']=projection(after)
 public['baseline_before_after_equal']=same(before,after)
 public['pending_absence_after']=pending_absent()
 close=provider.closed_resources((),time.monotonic()+5);private['preview_final_close']=projection(close)
 public['restoration_verified']=bool(result['done'] and public['baseline_before_after_equal'] and
  public['pending_absence_after'] and type(close) is core.CloseProof and close.complete() and not public['resource_pending'])
 public['pass']=bool(public['restoration_verified'] and public['client_init_observed'] and
  all(public[key] for key in ('parent_waited','parent_absence_verified','parent_resources_closed')))
 public['stage']='complete';public['reason']='complete' if public['pass'] else 'restoration_pending'
except BaseException as error:
 code=str(error) if type(error) is ValueError and str(error) in REASONS else 'os_error' if isinstance(error,OSError) else 'interrupted' if not isinstance(error,Exception) else 'unexpected'
 if public['stage']=='python' and type(error) is f.ExecutorError and error.code=='source_invalid':code='python_invalid'
 public['reason']=code;private['errors'].append({'class':type(error).__name__,'traceback':traceback.format_exc()})
 if public['staging_attempted'] or public['rf_requested'] or not reads_closed():public['resource_pending']=True
finally:
 if parent is not None:
  try:
   private['parent_final_passive']=parent.status()
   private['f_stdout']=tuple(raw for index,raw in parent.raw if index==1)
   private['f_stderr']=tuple(raw for index,raw in parent.raw if index==2)
   private['f_exit']=parent.exit_code
   private['parent_actor']=projection(parent.actor)
   private['parent_pipe_inventory']=tuple({key:row.get(key) for key in ('fd','metadata','attempted','closed','unknown')} for row in parent.pipes)
   private['parent_spawn']=None if parent.spawn_ticket is None else {'unknown':parent.spawn_ticket['unknown'],
    'argv':tuple(parent.spawn_ticket.get('argv',()))}
  except BaseException as error:
   public['resource_pending']=True;private['errors'].append({'class':type(error).__name__,'traceback':traceback.format_exc()})
 if not reads_closed():public['resource_pending']=True
 private['writes']=tuple(private['writes'])
 print('RESULT='+repr({'public':public,'private':{k:projection(v) for k,v in private.items() if k!='owners'}}))
'''


def source_check():
    _read(BASE / 'host/device_probe.py', ADB_PIN)
    driver = _module(BASE / 'host/client_wpa_status_readonly.py', STATUS_DRIVER_SHA, 'fixed_client_status_source')
    legacy, status_source, status_check = driver.source_check()
    match = re.search(r'^MANIFEST=(.*)$', status_source, re.M)
    if match is None: raise ValueError('status_manifest')
    status_manifest = ast.literal_eval(match.group(1))
    rows = []
    for name, pin in PINS:
        if pin is None: continue
        raw = _read(SOURCE_LOCATIONS.get(name, BASE / 'runtime' / (name + '.py')), pin)
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5)); rows.append((name, pin, raw))
    native = _read(NATIVE, WPA_SHA, 2 * 1024 * 1024)
    report = {'source_check_pass': PROVIDER_SHA is not None, 'stage': 'source_only' if PROVIDER_SHA else 'unavailable',
        'reason': 'source_only' if PROVIDER_SHA else 'unavailable', 'provider_stable': PROVIDER_SHA is not None,
        'send_available': False, 'receive_available': False, 'phone_tested': False,
        'driver_sha256': _hash(_read(Path(__file__).absolute(), None)), 'source_count': len(rows)}
    return report, rows, native, status_manifest, legacy


def build_source(rows, native, status_manifest, token, driver_sha, _pins=None, _native_pin=None):
    # Private fixture seams only; production always uses the fixed graph.
    pins, native_pin = PINS if _pins is None else _pins, WPA_SHA if _native_pin is None else _native_pin
    if type(token) is not str or type(driver_sha) is not str or not re.fullmatch('[0-9a-f]{32}', token) or not re.fullmatch('[0-9a-f]{64}', driver_sha): raise ValueError('input_shape')
    if tuple((name, pin) for name, pin, unused in rows) != pins or any(type(raw) is not bytes or _hash(raw) != pin for name, pin, raw in rows):
        raise ValueError('source_graph')
    if type(native) is not bytes or _hash(native) != native_pin: raise ValueError('native_pin')
    candidate = {'version': 1, 'kind': 'client-init-integrated-v9', 'driver_sha256': driver_sha,
        'files': [[('runtime/' + name + '.py'), len(raw), pin] for name, pin, raw in rows] +
        [['native/mta-wpa-supplicant', len(native), native_pin]]}
    candidate_raw = json.dumps(candidate, sort_keys=True).encode('utf-8')
    candidate_sha = _hash(candidate_raw)
    chunks = base64.b64encode(native).decode('ascii')
    source = 'PINS=' + _literal(pins) + '\nENCODED=' + _encoded(rows) + '\nWPA_ENCODED=(\n' + \
        '\n'.join(repr(chunks[i:i+1000]) for i in range(0, len(chunks), 1000)) + ')\n'
    source += 'TOKEN=' + repr(token) + '\nWPA_SHA=' + repr(native_pin) + '\nCANDIDATE=' + _literal(candidate) + \
        '\nCANDIDATE_ENCODED=(\n' + '\n'.join(repr(base64.b64encode(candidate_raw).decode('ascii')[i:i+1000])
            for i in range(0, len(base64.b64encode(candidate_raw)), 1000)) + ')\n' + \
        '\nCANDIDATE_SHA=' + repr(candidate_sha) + '\nSTATUS_MANIFEST=' + _literal(status_manifest) + \
        '\nBASELINE_MANIFEST=' + _literal(tuple(sorted(tuple(driver_pins()) + (('/usr/sbin/wpa_cli', CLI_SHA),)))) + \
        '\nBOOLS=' + repr(_BOOLS) + '\nREASONS=' + repr(_REASONS) + '\n' + LOADER + TARGET
    _validate_source(source)
    return source, candidate_sha


CLI_SHA = 'e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849'


def driver_pins():
    return (('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
        ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
        ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'))


def _validate_source(source):
    tree = ast.parse(source, feature_version=(3, 5))
    if len(source.encode('utf-8')) > MAX_SOURCE or max(len(line.encode('utf-8')) for line in source.splitlines()) > 2048 or \
            any(isinstance(node, ast.Assert) for node in ast.walk(tree)): raise ValueError('source_budget')


class HostAdbCall(object):
    """One actual HOST transport; timeout never kills an unknown remote F."""
    def __init__(self, helper, directory, _popen=None, _process_type=None, _fstat=None):
        self.helper, self.directory, self.popen = helper, Path(directory), _popen or subprocess.Popen
        self.process_type, self.fstat = _process_type or subprocess.Popen, _fstat or os.fstat
        self.transport = self.process = self.ticket = None
        self.raw, self.failure = {}, None
    def select(self):
        if self.transport is not None: raise ValueError('once_or_target')
        self.transport = self.helper.select_target()
        if type(self.transport) is not str or re.fullmatch('[1-9][0-9]{0,9}', self.transport) is None:
            raise ValueError('target_shape')
        return self.transport
    def run(self, source):
        if self.ticket is not None or self.transport is None: raise ValueError('once_or_target')
        data = (source + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
        command = 'python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(data)) + \
            '))" p011-client-init-host; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"'
        argv = [str(self.helper.ADB), '-t', self.transport, 'shell', command]
        self.ticket = {'creator': self.popen, 'argv': argv, 'returned': None, 'unknown': True,
            'pipes': [], 'waited': False, 'pipes_closed': False}
        try:
            value = self.popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            self.process = value; self.ticket['returned'] = value
            if type(value) is not self.process_type or type(value.pid) is not int or not 1 <= value.pid <= 0x7fffffff:
                raise ValueError('process_shape')
            for handle in (value.stdin, value.stdout, value.stderr):
                row = {'original': handle, 'fd': None, 'closed': False}; self.ticket['pipes'].append(row)
                row['fd'] = handle.fileno()
                if type(row['fd']) is not int or row['fd'] < 0 or any(x is not row and x['fd'] == row['fd'] for x in self.ticket['pipes']):
                    raise ValueError('pipe_shape')
            self.ticket['unknown'] = False
            out, err = value.communicate(data, timeout=195)
            self.raw = {'stdout': out, 'stderr': err, 'host_exit': value.returncode}
            if type(value.returncode) is not int or not -255 <= value.returncode <= 255:
                raise ValueError('wait_unknown')
            self.ticket['waited'] = True
            for row in self.ticket['pipes']:
                if row['original'].closed is not True: continue
                try: row['original'].fileno()
                except ValueError:
                    try: self.fstat(row['fd'])
                    except OSError as error:
                        row['closed'] = type(error.errno) is int and error.errno == 9
            self.ticket['pipes_closed'] = all(row['closed'] for row in self.ticket['pipes'])
            if not self.ticket['pipes_closed']: raise ValueError('pipe_unknown')
        except BaseException as error:
            self.failure = error
            if not self.raw:
                self.raw = {'stdout': getattr(error, 'stdout', None), 'stderr': getattr(error, 'stderr', None), 'host_exit': 'UNKNOWN'}
            raise
        return self.raw, data


def parse(raw, echo=None):
    stdout, stderr, code = raw['stdout'], raw['stderr'], raw['host_exit']
    if type(stdout) is not bytes or type(stderr) is not bytes or type(code) is not int or code != 0 or stderr or len(stdout) > MAX_RAW:
        raise ValueError('transport_result')
    text = stdout.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')
    if echo is not None:
        prefix = echo.decode('utf-8').replace('\r\r\n', '\n').replace('\r\n', '\n')
        if text.startswith(prefix): text = text[len(prefix):]
    lines = [line for line in text.split('\n') if line]
    if len(lines) != 3 or not lines[0].startswith('RESULT=') or lines[1:] != ['MTA_REMOTE_OK', 'MTA_REMOTE_EXIT=0']:
        raise ValueError('remote_frame')
    value = ast.literal_eval(lines[0][7:])
    if type(value) is not dict or set(value) != {'public', 'private'} or type(value['private']) is not dict: raise ValueError('remote_shape')
    public = value['public']
    if type(public) is not dict or set(public) != set(_BOOLS) | {'stage', 'reason'} or \
            any(type(public[key]) is not bool for key in _BOOLS) or type(public['stage']) is not str or type(public['reason']) is not str or \
            public['stage'] not in _STAGES or public['reason'] not in _REASONS or \
            any(public[key] for key in ('send_available', 'receive_available', 'phone_tested')): raise ValueError('public_shape')
    required = ('source_check_pass', 'pending_absence_before', 'staging_attempted', 'staging_verified', 'rf_requested',
        'client_init_observed', 'parent_waited', 'parent_absence_verified', 'parent_resources_closed',
        'baseline_before_after_equal', 'pending_absence_after', 'restoration_verified')
    if public['pass'] and (not all(public[key] for key in required) or public['resource_pending'] or
            public['stage'] != 'complete' or public['reason'] != 'complete'): raise ValueError('false_success')
    return value


def execute(expected, _check=None, _transport_factory=None, _output=None):
    checks, rows, native, status_manifest, legacy = (_check or source_check)()
    if checks['source_check_pass'] is not True or expected != checks['driver_sha256'] or _ATTEMPTS: raise ValueError('unavailable_or_reviewed')
    record = {'checks': checks, 'transport': None}; _ATTEMPTS.append(record)
    token = os.urandom(16).hex(); source, candidate_sha = build_source(rows, native, status_manifest, token, expected)
    out = Path(_output) if _output is not None else ROOT / 'logs' / ('MtaP011-ClientInitIntegratedV9-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex())
    out.mkdir(parents=True, exist_ok=False)
    public = {key: False for key in _BOOLS}; public.update(source_check_pass=True, resource_pending=True,
        stage='transport_unknown', reason='transport_unknown')
    try:
        helper = _module(BASE / 'host/device_probe.py', ADB_PIN, 'fixed_client_init_adb')
        call = (_transport_factory or HostAdbCall)(helper, out / 'private-raw'); record['transport'] = call
        call.directory.mkdir(parents=True, exist_ok=False); call.select(); public['target_selected'] = True
        raw, echo = call.run(source); record['raw'] = raw
        value = parse(raw, echo); record['result'] = value
        public.update(value['public']); public['target_selected'] = public['remote_reply_confirmed'] = True
    except BaseException as error:
        record['first_error'] = error
    finally:
        call = record['transport']
        raw = call.raw if call is not None else {}
        private_dir = out / 'private-raw'; private_dir.mkdir(exist_ok=True)
        for name in ('stdout', 'stderr'):
            data = raw.get(name)
            if type(data) is bytes: (private_dir / (name + '.raw')).write_bytes(data)
        (private_dir / 'host-exit').write_text(str(raw.get('host_exit', 'NOT_RECORDED')), encoding='ascii')
        exits = re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)', raw.get('stdout', b'')) if type(raw.get('stdout')) is bytes else []
        (private_dir / 'remote-exit').write_text(exits[0].decode('ascii') if len(exits) == 1 else 'UNKNOWN', encoding='ascii')
        (private_dir / 'target-source.py').write_text(source, encoding='utf-8')
        if 'first_error' in record:
            error = record['first_error']
            (private_dir / 'host-first-error.txt').write_text(''.join(traceback.format_exception(type(error), error, error.__traceback__)), encoding='utf-8')
    public.update(driver_sha256=expected, candidate_sha256=candidate_sha, evidence='P011_CLIENT_INIT_RESTORE_ONLY',
        canonical_python_pin='ACTUAL_OBSERVATION_NOT_INDEPENDENT_REVIEWED_PIN')
    (out / 'result.json').write_text(json.dumps(public, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text('One CLIENT init/restore only. No connection/DHCP/IP/file/phone acceptance.\n'
        'Private source/stdout/stderr/host-exit/remote-exit retain identity and first failure.\n'
        'No pending cleanup, retry, timeout kill or archived START. Candidate is not production availability.\n', encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'), 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json', 'README.txt'): bundle.write(out / name, name)
    return public


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-reviewed', action='store_true'); parser.add_argument('--expected-driver-sha256')
    args = parser.parse_args(argv)
    if args.execute_reviewed != (args.expected_driver_sha256 is not None): parser.error('Explicit execute and reviewed SHA required together')
    try:
        report = execute(args.expected_driver_sha256) if args.execute_reviewed else source_check()[0]
        print(json.dumps(report, indent=2)); return 0 if report.get('pass', report.get('source_check_pass', False)) else 1
    except Exception:
        print(json.dumps({'pass': False, 'stage': 'unavailable', 'send_available': False, 'receive_available': False})); return 1


if __name__ == '__main__': sys.exit(main())
