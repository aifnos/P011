"""Fixed first-baseline READONLY diagnostic; default source check only.

No staging, Store acquire, child launch, interface mutation or RF trial. The
old source graph is pinned; six failed predicates receive only a site note
in one private in-memory baseline copy. ROOT reviews before actual execution.
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
import traceback
import zipfile

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
REFERENCE = BASE / 'host/client_init_baseline_v3_p011.py'
REFERENCE_SHA = '518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122'
BASELINE_SHA = 'ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a'
MAX_RAW = 16 * 1024 * 1024
_ATTEMPTS = []
SITES = ('not_recorded', 'actor_image', 'self_round', 'observation_boot', 'self_final',
    'snapshot_identity', 'snapshot_tasks')
BOOLS = ('source_check_pass', 'target_selected', 'remote_reply_confirmed',
    'pending_absence_before', 'canonical_python_closed', 'snapshot_returned',
    'collector_present', 'collector_inventory_closed', 'external_reads_closed',
    'actor_key_equal', 'actors_live', 'actor_tasks_differ', 'only_task_states_differ',
    'snapshot_key_equal', 'snapshot_stock_keys_equal', 'snapshot_actors_live',
    'snapshot_tasks_differ', 'snapshot_only_task_states_differ', 'timing_valid',
    'diagnostic_complete', 'resource_pending', 'staging_attempted', 'rf_requested',
    'restoration_verified', 'send_available', 'receive_available', 'phone_tested')
COUNTS = ('collector_resource_count', 'collector_closed_count', 'collector_unknown_count',
    'collector_fd_count', 'collector_fd_ebadf_count', 'comm_read_count',
    'baseline_datagram_count', 'status_datagram_count', 'status_reader_count',
    'observation_count', 'round_count', 'proc_file_count', 'proc_closed_count',
    'timing_count', 'baseline_elapsed_milliseconds')
STAGES = ('source_only', 'platform', 'pending', 'python', 'baseline_before', 'complete', 'transport_unknown')
REASONS = ('source_only', 'not_recorded', 'complete', 'platform', 'pending_blocked',
    'python_invalid', 'baseline_failed', 'inventory_unknown', 'serialization_budget',
    'os_error', 'unexpected', 'interrupted', 'transport_unknown')

# Each original condition and original _fail remains byte-for-byte. Only
# the true branch registers the exact comparison inputs before that _fail.
REPLACEMENTS = (
    ("            if fresh.actor.key() != actor.key() or fresh.actor.tasks != actor.tasks: _fail('actor_changed')",
     "            if fresh.actor.key() != actor.key() or fresh.actor.tasks != actor.tasks:\n"
     "                self._diagnostic_actor_change = ('actor_image', actor, fresh)\n"
     "                _fail('actor_changed')"),
    ("                if current.boot != before.boot or current.actor.key() != before.actor.key(): _fail('actor_changed')",
     "                if current.boot != before.boot or current.actor.key() != before.actor.key():\n"
     "                    self._diagnostic_actor_change = ('self_round', before, current)\n"
     "                    _fail('actor_changed')"),
    ("                if any(v.boot != before.boot for v in self._observations): _fail('actor_changed')",
     "                if any(v.boot != before.boot for v in self._observations):\n"
     "                    self._diagnostic_actor_change = ('observation_boot', before, tuple(self._observations))\n"
     "                    _fail('actor_changed')"),
    ("            if after.boot != before.boot or after.actor.key() != before.actor.key(): _fail('actor_changed')",
     "            if after.boot != before.boot or after.actor.key() != before.actor.key():\n"
     "                self._diagnostic_actor_change = ('self_final', before, after)\n"
     "                _fail('actor_changed')"),
    ("            if self._rounds[0].key() != result.key(): _fail('snapshot_changed')",
     "            if self._rounds[0].key() != result.key():\n"
     "                self._diagnostic_actor_change = ('snapshot_identity', self._rounds[0], result)\n"
     "                _fail('snapshot_changed')"),
    ("            if tuple(sorted((a.pid, a.tasks) for a in self._rounds[0].stock_actors)) != \\\n"
     "                    tuple(sorted((a.pid, a.tasks) for a in result.stock_actors)): _fail('snapshot_changed')",
     "            if tuple(sorted((a.pid, a.tasks) for a in self._rounds[0].stock_actors)) != \\\n"
     "                    tuple(sorted((a.pid, a.tasks) for a in result.stock_actors)):\n"
     "                self._diagnostic_actor_change = ('snapshot_tasks', self._rounds[0], result)\n"
     "                _fail('snapshot_changed')"))


def _legacy():
    # Importing this module is pure. Only this explicit source-check function
    # reads the already reviewed reference; no Adb initialization occurs here.
    import types
    raw = REFERENCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA: raise ValueError('reference_pin')
    module = types.ModuleType('fixed_baseline_diagnostic_reference')
    module.__file__ = str(REFERENCE); exec(raw, module.__dict__)
    module._read(REFERENCE, REFERENCE_SHA)
    return module


def derive_baseline(raw):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != BASELINE_SHA:
        raise ValueError('baseline_pin')
    text = raw.decode('utf-8')
    for before, after in REPLACEMENTS:
        if text.count(before) != 1: raise ValueError('baseline_fragment')
        text = text.replace(before, after, 1)
    derived = text.encode('utf-8')
    ast.parse(text, feature_version=(3, 5))
    return derived, hashlib.sha256(derived).hexdigest()


def source_check():
    old = _legacy(); report, rows, native, manifest, unused = old.source_check()
    raw = next(raw for name, pin, raw in rows if name == 'mta_client_baseline')
    derived, derived_sha = derive_baseline(raw)
    return ({'source_check_pass': report['source_check_pass'], 'stage': 'source_only',
        'reason': 'source_only', 'source_count': len(rows), 'site_count': len(REPLACEMENTS),
        'driver_sha256': hashlib.sha256(old._read(Path(__file__).absolute(), None)).hexdigest(),
        'reference_sha256': REFERENCE_SHA, 'baseline_original_sha256': BASELINE_SHA,
        'baseline_derived_sha256': derived_sha, 'send_available': False,
        'receive_available': False, 'phone_tested': False}, rows, native, manifest, old)


TARGET = r'''
import errno,math,os,stat,sys,time,traceback
f=modules['mta_client_executor'];core=modules['mta_p2p_client_init'];proc=modules['mta_client_proc']
pm=modules['mta_client_linux_provider'];bl=modules['mta_client_baseline']
public={key:False for key in BOOLS};public.update({key:0 for key in COUNTS})
public.update(source_check_pass=True,stage='platform',reason='not_recorded',failure_site='not_recorded')
private={'errors':[],'reads':[],'owners':[],'collector':None,'provider_observers':None}
end=time.monotonic()+30;provider=None
def fail(reason):raise ValueError(reason)
def check():
 if time.monotonic()>=end:fail('unexpected')
def projection(value):
 if value is None or type(value) in (str,int,float,bool):return value
 if type(value) is bytes:
  if value.startswith(b'\x7fELF'):return {'binary_digest':hashlib.sha256(value).hexdigest(),'length':len(value)}
  return {'bytes_b64':base64.b64encode(value).decode('ascii'),'length':len(value)}
 if type(value) in (tuple,list):return tuple(projection(x) for x in value)
 if type(value) is dict:return {key:projection(x) for key,x in value.items()}
 if hasattr(value,'__slots__'):return {key:projection(getattr(value,key)) for key in value.__slots__ if not key.startswith('_')}
 fail('inventory_unknown')
def pending_absent():
 check()
 try:os.lstat('/tmp/p011-mta-p2p-device.pending')
 except OSError as error:
  if type(error.errno) is int and error.errno==errno.ENOENT:return True
  raise
 fail('pending_blocked')
def ebadf(io,fd):
 if type(fd) is not int or fd<0:return False
 try:io.fstat(fd)
 except OSError as error:return type(error.errno) is int and error.errno==errno.EBADF
 return False
def ticket(row,io):
 value={key:projection(row.get(key)) for key in
  ('kind','fd','unknown','attempted','closed','kill_attempted','waited','pipe_refs_valid')}
 value['original_fd_ebadf']=ebadf(io,row.get('fd')) if row.get('fd') is not None else None
 return value
def proc_inventory(reader):
 refs=getattr(reader,'_fd_refs',())
 attempt=getattr(reader,'_open_attempt',None)
 return {'active':getattr(reader,'_active',None),'pending':getattr(reader,'_pending',None),
  'file_count':getattr(reader,'_files',None),'closed_count':getattr(reader,'_closed',None),
  'attempt':None if attempt is None else {key:projection(attempt.get(key)) for key in
   ('path','flags','descriptor','returned','registered','failed_without_fd')},
  'original_fds':tuple({'fd':fd,'original_fd_ebadf':ebadf(io,fd)} for io,fd in refs)}
def read_proc(kind,*args):
 row={'kind':'proc','owner':None,'unknown':True};private['reads'].append(row)
 reader=proc.ProcReader(timeout=3);row['owner']=reader;private['owners'].append(reader)
 value=getattr(reader,kind)(*args);row['value']=value;row['unknown']=False
 return reader,value
def reads_closed():
 for row in private['reads']:
  owner=row['owner']
  if row['unknown'] or owner is None:return False
  if row['kind']=='proc':
   if not f._reader_closed(owner):return False
  elif owner.pending or any(x['unknown'] or not x['closed'] for x in owner.rows):return False
 return True
def timed_collector(p,unused_original_budget):
 reader=pm._AuthenticatedCollector(p,10)
 reader._diagnostic_timings=[];reader._diagnostic_timing_invalid=False
 reader._diagnostic_binary_calls=0
 def wrap(name,label):
  original=getattr(reader,name)
  def timed(*args,**kwargs):
   phase=label
   if name=='_read_file':
    binary=kwargs.get('binary',args[3] if len(args)>3 else False)
    if binary is not True:return original(*args,**kwargs)
    phase='manifest_binary' if reader._diagnostic_binary_calls<len(reader._manifest) else 'rehash'
    reader._diagnostic_binary_calls+=1
   begin=time.monotonic();outcome='raised'
   try:
    value=original(*args,**kwargs);outcome='returned';return value
   finally:
    finish=time.monotonic()
    if type(begin) not in (int,float) or type(finish) not in (int,float) or \
     not math.isfinite(float(begin)) or not math.isfinite(float(finish)) or \
     not 0<=begin<=finish<1e12 or len(reader._diagnostic_timings)>=128:
     reader._diagnostic_timing_invalid=True
    else:reader._diagnostic_timings.append({'phase':phase,'begin':begin,'end':finish,
     'elapsed':finish-begin,'outcome':outcome})
  setattr(reader,name,timed)
 for name,label in (('_read_file','binary'),('_actor_image','actor_image'),('_actors','actors'),
  ('_interfaces','interfaces'),('_status','status'),('_ipv4','ipv4'),('_ipv6','ipv6'),
  ('_proc','proc'),('collect','collect')):wrap(name,label)
 return reader
def retain_collector():
 if provider is None:return
 rows=provider._collectors
 private['provider_observers']=tuple({'value_present':r['value'] is not None,'unknown':r['unknown']} for r in rows)
 if len(rows)!=1 or rows[0]['reader'] is None:return
 reader=rows[0]['reader'];public['collector_present']=True
 tickets=tuple(ticket(r,reader._io) for r in reader._tickets)
 current_reader=proc_inventory(reader._reader)
 status_rows=[]
 for call in reader.status_readers:
  observed=call['reader'];source=call.get('source');record={'unknown':call['unknown'],'reader_present':observed is not None}
  if observed is not None:
   record.update(status=projection(observed.status()),raw=projection(observed._raw),
    sources=projection(observed._sources),rights=tuple(ticket(r,observed._io) for r in observed._rights),
    socket_fd=observed._socket_fd,socket_attempted=observed._socket_attempted,
    socket_closed=observed._socket_closed,socket_unknown=observed._socket_unknown,
    socket_original_fd_ebadf=ebadf(observed._io,observed._socket_fd))
   public['status_datagram_count']+=len(observed._raw)
  if source is not None:
   record['source_files']=tuple(tuple(ticket(r,files._io) for r in files._tickets) for files in source._files)
   record['source_proc']=tuple(proc_inventory(r['reader']) for r in source._actor_calls if r['reader'] is not None)
   record['source_raw']=projection(source._raw)
   record['source_actor_calls']=tuple({key:projection(r[key]) for key in
    ('method','pid','expected','started','returned','value','unknown')} for r in source._actor_calls)
  status_rows.append(record)
 site=getattr(reader,'_diagnostic_actor_change',None)
 if site is not None:
  if type(site) is not tuple or len(site)!=3 or site[0] not in SITES[1:]:fail('inventory_unknown')
  public['failure_site']=site[0]
  if site[0]=='actor_image':
   left,right=site[1],site[2].actor
   public['actor_key_equal']=left.key()==right.key()
   public['actors_live']=left.live() and right.live()
   public['actor_tasks_differ']=left.tasks!=right.tasks
   public['only_task_states_differ']=public['actor_key_equal'] and public['actor_tasks_differ'] and \
    tuple(t[:2] for t in left.tasks)==tuple(t[:2] for t in right.tasks)
  elif site[0] in ('snapshot_identity','snapshot_tasks'):
   left,right=site[1],site[2]
   public['snapshot_key_equal']=left.key()==right.key()
   public['snapshot_stock_keys_equal']=tuple(sorted(a.key() for a in left.stock_actors))==tuple(sorted(a.key() for a in right.stock_actors))
   public['snapshot_actors_live']=all(a.live() for a in left.stock_actors+right.stock_actors)
   public['snapshot_tasks_differ']=tuple(sorted((a.pid,a.tasks) for a in left.stock_actors))!=tuple(sorted((a.pid,a.tasks) for a in right.stock_actors))
   public['snapshot_only_task_states_differ']=public['snapshot_key_equal'] and \
    public['snapshot_stock_keys_equal'] and public['snapshot_tasks_differ']
 timings=getattr(reader,'_diagnostic_timings',())
 public['timing_valid']=getattr(reader,'_diagnostic_timing_invalid',True) is False
 public['timing_count']=len(timings)
 totals=[r['elapsed'] for r in timings if r['phase']=='collect']
 if len(totals)==1:public['baseline_elapsed_milliseconds']=int(totals[0]*1000)
 else:public['timing_valid']=False
 private['collector']={'status':reader.status(),'observations':projection(reader._observations),
  'raw':projection(reader._raw),'rounds':projection(reader._rounds),
  'binaries':{path:{'ticket':ticket(value[0],reader._io),'metadata':projection(value[1]),
    'parents':projection(value[2])} for path,value in reader._binaries.items()},
  'tickets':tickets,'reader':current_reader,'status_readers':tuple(status_rows),'failure_comparison':projection(site),
  'timings':projection(timings),'diagnostic_collector_budget_seconds':10}
 public.update(collector_resource_count=len(tickets),collector_closed_count=sum(r['closed'] is True for r in tickets),
  collector_unknown_count=sum(r['unknown'] is True for r in tickets),
  collector_fd_count=sum(r['fd'] is not None for r in tickets),
  collector_fd_ebadf_count=sum(r['original_fd_ebadf'] is True for r in tickets),
  baseline_datagram_count=reader._packets,status_reader_count=len(status_rows),
  observation_count=len(reader._observations),round_count=len(reader._rounds),
  comm_read_count=sum(type(r) is tuple and len(r)==4 and r[0]=='file' and
   type(r[1]) is str and re.fullmatch('/proc/[1-9][0-9]*/comm',r[1]) is not None for r in reader._raw),
  proc_file_count=sum(r.file_count for r in reader._observations),
  proc_closed_count=sum(r.closed_count for r in reader._observations))
 public['collector_inventory_closed']=bool(reader._ended and not reader._pending and
  all(r['closed'] is True and r['unknown'] is False and
   (r['fd'] is None or r['original_fd_ebadf'] is True) for r in tickets) and
  current_reader['pending'] is False and current_reader['active'] is False and
  all(r['original_fd_ebadf'] is True for r in current_reader['original_fds']) and
  all(r.resource_pending is False and r.file_count==r.closed_count for r in reader._observations) and
  all(r['unknown'] is False and r['status']['resource_pending'] is False and
   r['status']['socket_closed'] is True and r['socket_original_fd_ebadf'] is True and
   all(x['closed'] is True and x['unknown'] is False and x['original_fd_ebadf'] is True for x in r['rights']) and
   all(x['closed'] is True and x['unknown'] is False and
    (x['fd'] is None or x['original_fd_ebadf'] is True) for group in r['source_files'] for x in group) and
   all(x['pending'] is False and x['active'] is False and
    all(y['original_fd_ebadf'] is True for y in x['original_fds']) for x in r['source_proc']) for r in status_rows))
try:
 if sys.flags.optimize or tuple(sys.version_info[:3])!=(3,5,5):fail('platform')
 f._LinuxIo().validate()
 public['stage']='pending';public['pending_absence_before']=pending_absent()
 public['stage']='python';reader,observed=read_proc('read_self')
 private['python_before']=projection(observed);actor=f._actor(observed,core,proc,True)
 if not f._reader_closed(reader):fail('python_invalid')
 read_row={'kind':'file','owner':None,'unknown':True};private['reads'].append(read_row)
 files=f._ReadOwner(f._LinuxIo(),time.monotonic,time.monotonic()+10)
 read_row['owner']=files;read_row['unknown']=False;private['owners'].append(files)
 try:
  raw,row=files.read_file(actor.exe,16777216,binary=True)
  if raw[:7]!=b'\x7fELF\x01\x01\x01' or len(raw)<52 or int.from_bytes(raw[18:20],'little')!=40:fail('python_invalid')
  python_sha=hashlib.sha256(raw).hexdigest();private['python_image']={'sha256':python_sha,'length':len(raw)}
 finally:
  try:
   public['canonical_python_closed']=files.close()
   if not public['canonical_python_closed']:fail('python_invalid')
  finally:private['python_files']=tuple({k:projection(r.get(k)) for k in
   ('path','fd','metadata','unknown','attempted','closed')} for r in files.rows)
 reader2,current=read_proc('read_actor',actor.pid,actor);private['python_after']=projection(current)
 if f._actor(current,core,proc,True).key()!=actor.key() or current.boot!=observed.boot or not f._reader_closed(reader2):fail('python_invalid')
 run=f.ROOT+'/client-'+TOKEN
 value={'version':1,'run_token':TOKEN,'candidate_sha':CANDIDATE_SHA,'ifname':'mta'+TOKEN[:8],
  'baseline_manifest':BASELINE_MANIFEST,'status_manifest':STATUS_MANIFEST,'wpa_exe':run+'/native/mta-wpa-supplicant',
  'wpa_sha':WPA_SHA,'python_exe':actor.exe,'python_sha':python_sha,
  'executor_path':run+'/runtime/mta_client_executor.py','executor_sha':dict(PINS)['mta_client_executor']}
 deployment=modules['p011_json'].dumps({'version':1,'provider':value,'sources':[list(x) for x in PINS]},sort_keys=True).encode('utf-8')
 manifest=pm.ProviderManifest(value,_manifest_sha256=hashlib.sha256(deployment).hexdigest())
 assembly=pm.assemble(manifest);private['owners'].append(assembly);provider=assembly[0]
 provider._collector_factory=timed_collector
 public['stage']='baseline_before';provider.executor(time.monotonic()+5)
 result=provider.snapshot(time.monotonic()+10);private['snapshot']=projection(result);public['snapshot_returned']=True
 public['reason']='complete'
except BaseException as error:
 public['reason']='baseline_failed' if type(error) is bl.BaselineError else \
  str(error) if type(error) is ValueError and str(error) in REASONS else \
  'os_error' if isinstance(error,OSError) else 'interrupted' if not isinstance(error,Exception) else 'unexpected'
 if public['stage']=='python' and type(error) is f.ExecutorError and error.code=='source_invalid':public['reason']='python_invalid'
 private['errors'].append({'class':type(error).__name__,'code':getattr(error,'code',None),
  'traceback':traceback.format_exc()[:65536]})
finally:
 try:
  retain_collector();public['external_reads_closed']=reads_closed()
  private['external_proc']=tuple(proc_inventory(r['owner']) for r in private['reads'] if r['kind']=='proc' and r['owner'] is not None)
  private['provider_proc']=() if provider is None else tuple({'unknown':r['unknown'],'value':projection(r['value']),
   'inventory':proc_inventory(r['reader'])} for r in provider._proc_calls if r['reader'] is not None)
  public['resource_pending']=not public['external_reads_closed'] or \
   (public['stage']=='baseline_before' and (not public['collector_inventory_closed'] or
    provider is None or any(r['unknown'] for r in provider._collectors+provider._proc_calls)))
  public['diagnostic_complete']=public['stage']=='baseline_before' and public['collector_present'] and \
   public['external_reads_closed'] and public['collector_inventory_closed'] and public['timing_valid']
 except BaseException as error:
  public['resource_pending']=True;private['errors'].append({'class':type(error).__name__,'traceback':traceback.format_exc()[:65536]})
  public['reason']='inventory_unknown';public['diagnostic_complete']=False
 private.pop('reads',None)
 final={'public':public,'private':{k:v for k,v in private.items() if k!='owners'}}
 text=repr(final)
 if len(text.encode('utf-8'))>12*1024*1024:
  public['diagnostic_complete']=False;public['reason']='serialization_budget'
  text=repr({'public':public,'private':{'errors':({'class':'SerializationBudget'},)}})
 print('RESULT='+text)
'''


def build_source(rows, native, manifest, token, driver_sha):
    old = _legacy()
    if type(token) is not str or re.fullmatch('[0-9a-f]{32}', token) is None or \
            type(driver_sha) is not str or re.fullmatch('[0-9a-f]{64}', driver_sha) is None:
        raise ValueError('input_shape')
    if tuple((n, p) for n, p, raw in rows) != old.PINS or any(
            type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != p for n, p, raw in rows):
        raise ValueError('source_graph')
    if type(native) is not bytes or hashlib.sha256(native).hexdigest() != old.WPA_SHA: raise ValueError('native_pin')
    derived, derived_sha = derive_baseline(next(raw for name, p, raw in rows if name == 'mta_client_baseline'))
    candidate = {'version': 1, 'kind': 'client-v3-baseline-readonly-performance',
        'driver_sha256': driver_sha, 'reference_sha256': REFERENCE_SHA,
        'baseline_derived_sha256': derived_sha,
        'sources': [(name, pin, len(raw)) for name, pin, raw in rows],
        'native': {'sha256': old.WPA_SHA, 'length': len(native)}}
    candidate_sha = hashlib.sha256(json.dumps(candidate, sort_keys=True).encode('utf-8')).hexdigest()
    loader_before = ' payloads[name]=raw\n'
    loader_after = loader_before + " if name=='mta_client_baseline':\n" + \
        "  raw=base64.b64decode(DERIVED_ENCODED.encode('ascii'),validate=True)\n" + \
        "  if hashlib.sha256(raw).hexdigest()!=DERIVED_SHA:raise ValueError('derived_pin')\n"
    if old.LOADER.count(loader_before) != 1: raise ValueError('loader_fragment')
    encoded = base64.b64encode(derived).decode('ascii')
    source = 'PINS=' + old._literal(old.PINS) + '\nENCODED=' + old._encoded(rows) + \
        '\nDERIVED_SHA=' + repr(derived_sha) + '\nDERIVED_ENCODED=(\n' + \
        '\n'.join(repr(encoded[i:i+1000]) for i in range(0, len(encoded), 1000)) + ')\n'
    source += 'TOKEN=' + repr(token) + '\nWPA_SHA=' + repr(old.WPA_SHA) + \
        '\nCANDIDATE_SHA=' + repr(candidate_sha) + '\nSTATUS_MANIFEST=' + old._literal(manifest) + \
        '\nBASELINE_MANIFEST=' + old._literal(tuple(sorted(old.driver_pins() + (('/usr/sbin/wpa_cli', old.CLI_SHA),)))) + \
        '\nBOOLS=' + repr(BOOLS) + '\nCOUNTS=' + repr(COUNTS) + '\nSITES=' + repr(SITES) + \
        '\nREASONS=' + repr(REASONS) + '\nimport re\n' + old.LOADER.replace(loader_before, loader_after, 1) + TARGET
    old._validate_source(source)
    if len(source.encode('utf-8')) > 4*1024*1024: raise ValueError('source_budget')
    return source, candidate_sha, derived_sha


def parse(raw, echo=None):
    stdout, stderr, code = raw['stdout'], raw['stderr'], raw['host_exit']
    if type(stdout) is not bytes or type(stderr) is not bytes or type(code) is not int or code != 0 or stderr or len(stdout)>MAX_RAW:
        raise ValueError('transport_result')
    text = stdout.decode('utf-8', 'strict').replace('\r\r\n','\n').replace('\r\n','\n')
    if echo is not None:
        prefix = echo.decode('utf-8').replace('\r\r\n','\n').replace('\r\n','\n')
        if text.startswith(prefix): text=text[len(prefix):]
    lines=[line for line in text.split('\n') if line]
    if len(lines)!=3 or not lines[0].startswith('RESULT=') or lines[1:]!=['MTA_REMOTE_OK','MTA_REMOTE_EXIT=0']:
        raise ValueError('remote_frame')
    result=ast.literal_eval(lines[0][7:])
    if type(result) is not dict or set(result)!={'public','private'} or type(result['private']) is not dict:
        raise ValueError('remote_shape')
    public=result['public']
    if type(public) is not dict or set(public)!=set(BOOLS)|set(COUNTS)|{'stage','reason','failure_site'} or \
            any(type(public[k]) is not bool for k in BOOLS) or \
            any(type(public[k]) is not int or not 0<=public[k]<=1000000 for k in COUNTS) or \
            any(type(public[k]) is not str for k in ('stage','reason','failure_site')) or \
            public['stage'] not in STAGES or public['reason'] not in REASONS or public['failure_site'] not in SITES or \
            any(public[k] for k in ('staging_attempted','rf_requested','restoration_verified','send_available','receive_available','phone_tested')):
        raise ValueError('public_shape')
    if public['diagnostic_complete'] and not all(public[k] for k in
            ('source_check_pass','pending_absence_before','canonical_python_closed','collector_present',
             'collector_inventory_closed','external_reads_closed','timing_valid')): raise ValueError('false_success')
    return result


def execute(expected, _check=None, _transport_factory=None, _output=None):
    report, rows, native, manifest, old = (_check or source_check)()
    if expected!=report['driver_sha256'] or report['source_check_pass'] is not True or _ATTEMPTS:
        raise ValueError('reviewed_or_once')
    record={'report':report,'transport':None};_ATTEMPTS.append(record)
    source,candidate_sha,derived_sha=build_source(rows,native,manifest,os.urandom(16).hex(),expected)
    output=Path(_output) if _output is not None else ROOT/'logs'/('MtaP011-ClientBaselineV3Performance-'+
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex())
    output.mkdir(parents=True,exist_ok=False)
    public={k:False for k in BOOLS};public.update({k:0 for k in COUNTS})
    public.update(source_check_pass=True,resource_pending=True,stage='transport_unknown',reason='transport_unknown',failure_site='not_recorded')
    try:
        helper=old._module(BASE/'host/device_probe.py',old.ADB_PIN,'fixed_baseline_diag_adb')
        call=(_transport_factory or old.HostAdbCall)(helper,output/'private-raw');record['transport']=call
        call.directory.mkdir(parents=True,exist_ok=False);call.select();public['target_selected']=True
        raw,echo=call.run(source);record['raw']=raw;value=parse(raw,echo);record['result']=value
        public.update(value['public']);public['target_selected']=public['remote_reply_confirmed']=True
    except BaseException as error:record['first_error']=error
    finally:
        call=record['transport'];raw=call.raw if call is not None else {};directory=output/'private-raw'
        directory.mkdir(exist_ok=True)
        for key in ('stdout','stderr'):
            if type(raw.get(key)) is bytes:(directory/(key+'.raw')).write_bytes(raw[key])
        (directory/'host-exit').write_text(str(raw.get('host_exit','NOT_RECORDED')),encoding='ascii')
        exits=re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)',raw.get('stdout',b'')) if type(raw.get('stdout')) is bytes else []
        (directory/'remote-exit').write_text(exits[0].decode('ascii') if len(exits)==1 else 'UNKNOWN',encoding='ascii')
        (directory/'target-source.py').write_text(source,encoding='utf-8')
        if 'first_error' in record:
            error=record['first_error'];(directory/'host-first-error.txt').write_text(
                ''.join(traceback.format_exception(type(error),error,error.__traceback__)),encoding='utf-8')
    public.update(driver_sha256=expected,candidate_sha256=candidate_sha,baseline_derived_sha256=derived_sha,
        evidence='P011_V3_BASELINE_READONLY_PERFORMANCE',canonical_python_pin='ACTUAL_OBSERVATION_NOT_INDEPENDENT_PIN')
    (output/'result.json').write_text(json.dumps(public,indent=2),encoding='utf-8')
    (output/'README.txt').write_text('V3 first baseline READONLY timing diagnostic; private collector budget10s only. No staging/Store/child/interface/RF.\n'
        'diagnostic_complete means diagnostic and its registered reader inventory completed, NOT baseline PASS or restoration.\n'
        'Private raw contains original observations, task states, source, stdout/stderr and independent exits.\n'
        'No native/ELF contents serialized; only digests/metadata. Historical first failures unchanged.\n',encoding='utf-8')
    with zipfile.ZipFile(output.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for key in ('result.json','README.txt'):bundle.write(output/key,key)
    return public


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly',action='store_true');parser.add_argument('--expected-driver-sha256')
    args=parser.parse_args(argv)
    if args.execute_readonly!=(args.expected_driver_sha256 is not None):parser.error('Explicit readonly and reviewed SHA required together')
    try:
        report=execute(args.expected_driver_sha256) if args.execute_readonly else source_check()[0]
        print(json.dumps(report,indent=2));return 0 if report.get('diagnostic_complete',report.get('source_check_pass',False)) else 1
    except Exception:
        print(json.dumps({'diagnostic_complete':False,'stage':'transport_unknown','send_available':False,'receive_available':False}));return 1


if __name__=='__main__':raise SystemExit(main())
