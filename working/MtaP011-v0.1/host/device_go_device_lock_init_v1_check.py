"""Independent fixed shared-device empty-lock initialization; PC SOURCE default.

Only explicit --initialize-device can make one EXCL empty 0600 file after two
typed-ENOENT/pending/process/FD gates. Existing, unsafe, busy or unknown fails.
No original business/main, Parent, Stage, Owner, helper or RF is executed.
The empty entry is retained even after failure; no repair, unlink or retry.
PASS never signs Parent, radio admission, restoration or old Owner closure.
Raw process/FD evidence, streams and exact input sources stay private.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_device_lock_init_v1_check.py'
HOST_CMD = 'HOST_MTA_GO_DEVICE_LOCK_INIT_V1_SOURCE_CHECK.cmd'
INIT_CMD = 'INIT_MTA_GO_DEVICE_LOCK_V1.cmd'
MOTHER = ('host/device_formal_send_repair_prerequisite_roots_v1_check.py', 16667,
          '94325f0c0f666c88e198dec11a18efce39daf3d1463c925c9ee51bbe649450fd')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
OBSERVER = ('candidate/go-observer-native-v2/runtime/mta_go_readonly_preflight.py', 64962,
            'ad190dff407fcacd06353713c318aa05489f3d2ec2dad6d0f05546a1ef5c5e75')
COORDINATION = ('candidate/client-tmp-alias-v11/runtime/mta_client_coordination.py', 35591,
                '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f')
STORE = ('candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap_store.py', 78430,
         '24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae')
HELPERS = frozenset(('sha', 'need', 'write_new', 'literal', 'probe_definitions',
                    'compressed_budget', 'receipt', 'run_readonly', 'stock_identity'))
LOCK = '/var/volatile/tmp/p011-mta-p2p-device.lock'
PENDING = '/var/volatile/tmp/p011-mta-p2p-device.pending'
LOCK_ALIASES = (LOCK, '/var/tmp/p011-mta-p2p-device.lock', '/tmp/p011-mta-p2p-device.lock')
TARGET = r'''
import ctypes,errno,hashlib,math,os,signal,stat,sys,time
R=dict(complete=False,created=False,creation_unknown=False,lock_close_verified=False,
 alarm_installed=False,alarm_released=False,cleanup_alarm_retained=False,cleanup_before_deadline=False,
 local_inventory_closed=False,active_seconds_limit=25,cleanup_seconds_reserved=5,
 root_fds_closed=False,retained_entry_verified=False,file_synced=False,parent_synced=False,
 pending_absent_after=False,gate_rounds=0,processes_checked=0,fd_links_checked=0,
 old_project_actors=0,old_lock_fds=0,open_attempts=0,close_errors=0,error=None,error_errno=None,
 metadata_before=None,metadata_after=None,process_snapshots=[],directory_rows=[],
 lock_row=None,device_writes=False,parent_invoked=False,owner_started=False,
 radio_operations=False,production_admitted=False,restoration_verified=False)
rows=[];last=None;end=None;aliases=None
def fail(code):raise ValueError(code)
def expired(signum,frame):fail('alarm_expired')
signal.signal(signal.SIGALRM,expired)
alarm_origin=time.monotonic()
remaining=signal.getitimer(signal.ITIMER_REAL)[0]
if type(alarm_origin)is not float or not math.isfinite(alarm_origin) or type(remaining)is not float or not 0<remaining<=30:fail('alarm_unknown')
cleanup_until=alarm_origin+remaining;R['alarm_installed']=True
def now():
 global last
 v=time.monotonic()
 if type(v)is not float or not math.isfinite(v) or last is not None and v<last:fail('clock_unknown')
 last=v
 if end is not None and v>=end:fail('deadline')
 return v
def meta(v):
 r=tuple(getattr(v,k,None) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 if any(type(x)is not int or not 0<=x<1<<64 for x in r):fail('metadata_unknown')
 return r
def close(r):
 if r['closed'] or r['close_called']:return
 if r['fd']is None:
  if not r['open_called'] or r.get('negative_open')is True:r['closed']=True;return
  fail('open_unknown')
 if r['unknown']:fail('fd_unknown')
 if meta(os.fstat(r['fd']))[:6]!=r['identity'][:6]:fail('fd_changed')
 r['close_called']=True;r['close_return']=os.close(r['fd'])
 try:os.fstat(r['fd'])
 except OSError as e:
  r['close_errno']=e.errno if type(e.errno)is int else None
  r['closed']=r['close_return']is None and type(e.errno)is int and e.errno==errno.EBADF
 if not r['closed']:fail('close_unknown')
def opened(path,flags,mode=0,parent=None,creation=False):
 now()
 if len(rows)>=4101:fail('fd_budget')
 r=dict(fd=None,open_called=False,unknown=True,close_called=False,closed=False,identity=None)
 rows.append(r);R['open_attempts']+=1;r['open_called']=True
 try:r['fd']=os.open(path,flags,mode,dir_fd=parent) if parent is not None else os.open(path,flags,mode)
 except OSError as e:
  if type(e.errno)is int and 1<=e.errno<=4095:r['negative_open']=True;r['unknown']=False;r['closed']=True
  raise
 if type(r['fd'])is not int or r['fd']<0 or any(x is not r and not x['closed'] and x['fd']==r['fd'] for x in rows):fail('fd_unknown')
 if creation:R['created']=True;R['device_writes']=True
 r['identity']=meta(os.fstat(r['fd']));r['unknown']=False;now();return r
def read(path):
 r=opened(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  raw=os.read(r['fd'],4097)
  if type(raw)is not bytes or len(raw)>4096:fail('proc_read_budget')
  return raw
 finally:close(r)
def typed_absent(name):
 now()
 try:os.stat(name,dir_fd=roots[-1]['fd'],follow_symlinks=False)
 except OSError as e:
  if type(e.errno)is int and e.errno==errno.ENOENT:return
  raise
 fail('existing_entry')
def aliases_current():
 pair=tuple((meta(os.lstat(p)),os.readlink(p)) for p in ('/tmp','/var/tmp'))
 for (m,l),t in zip(pair,('/var/tmp','/var/volatile/tmp')):
  if m[2]!=stat.S_IFLNK|0o777 or m[3:6]!=(0,0,1) or m[6]!=len(t) or l!=t:fail('alias_unsafe')
 if aliases is not None and pair!=aliases:fail('alias_changed')
 return pair
def roots_current():
 now();aliases_current()
 for r,p,n,m in anchors:
  a=meta(os.fstat(r['fd']))
  b=meta(os.stat('/',follow_symlinks=False) if p is None else os.stat(n,dir_fd=p,follow_symlinks=False))
  if a[:5]!=m[:5] or b[:5]!=m[:5] or a[5]<1 or b[5]<1:fail('root_changed')
def ident(pid):
 raw=read('/proc/'+pid+'/stat');at=raw.rfind(b')');first=raw.find(b'(');f=raw[at+2:].split()
 if first<0 or at<=first or len(f)<20 or not f[1].isdigit() or not f[19].isdigit():fail('proc_identity')
 return (int(pid),raw[first+1:at],int(f[1]),int(f[19]))
def exe_of(pid,cmd):
 try:return os.readlink('/proc/'+pid+'/exe')
 except OSError as e:
  if cmd==b'' and type(e.errno)is int and e.errno==errno.ENOENT:return ''
  raise
def proc_gate():
 names=os.listdir('/proc')
 if type(names)is not list or len(names)>4096:fail('proc_budget')
 pids=tuple(sorted(n for n in names if type(n)is str and n.isdigit()))
 if len(pids)>512:fail('proc_budget')
 result=[];links=0;budget=0
 for pid in pids:
  now()
  if int(pid)==os.getpid():continue
  a=ident(pid);cmd=read('/proc/'+pid+'/cmdline');exe=exe_of(pid,cmd)
  budget+=len(cmd)+len(exe.encode('utf-8'))
  if budget>65536:fail('fd_links_budget')
  if any(t in cmd or t in exe.encode('utf-8') or t in a[1] for t in (b'p011-mta',b'MtaP011',b'ToolsTest',b'mta-',b'mta_')):
   R['old_project_actors']+=1;fail('project_actor_present')
  d='/proc/'+pid+'/fd';ns=os.listdir(d)
  if type(ns)is not list or len(ns)>256 or any(type(n)is not str or not n.isdigit() for n in ns):fail('fd_links_budget')
  ns=tuple(sorted(ns));values=[]
  for n in ns:
   now();links+=1
   if links>8192:fail('fd_links_budget')
   p=d+'/'+n;v=os.readlink(p)
   if type(v)is not str or len(v)>4096:fail('fd_links_budget')
   budget+=len(v.encode('utf-8'))
   if budget>65536:fail('fd_links_budget')
   if v.endswith(' (deleted)'):test=v[:-10]
   else:test=v
   if test in LOCK_ALIASES:R['old_lock_fds']+=1;fail('old_lock_fd_present')
   if os.readlink(p)!=v:fail('fd_links_changed')
   values.append((n,v))
  if tuple(sorted(os.listdir(d)))!=ns or ident(pid)!=a or read('/proc/'+pid+'/cmdline')!=cmd:fail('proc_changed')
  if exe_of(pid,cmd)!=exe:fail('proc_changed')
  result.append((a,cmd,exe,tuple(values)))
 if tuple(sorted(n for n in os.listdir('/proc') if type(n)is str and n.isdigit()))!=pids:fail('proc_changed')
 R['processes_checked']+=len(result);R['fd_links_checked']+=links
 value=tuple(result)
 R['process_snapshots'].append((len(result),links,budget,hashlib.sha256(repr(value).encode('utf-8')).hexdigest()))
 return value
def lock_current(r):
 roots_current();a=meta(os.fstat(r['fd']));b=meta(os.stat(NAME,dir_fd=roots[-1]['fd'],follow_symlinks=False))
 if a!=b or a!=r['identity'] or a[2]!=stat.S_IFREG|0o600 or a[3:7]!=(0,0,1,0):fail('lock_identity')
 return a
roots=[];anchors=[];lock=None;complete=False
try:
 end=cleanup_until-5.0;now()
 if sys.platform!='linux' or sys.byteorder!='little' or os.geteuid()!=0 or os.getegid()!=0:fail('platform')
 if os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):fail('platform')
 if (os.O_NOFOLLOW,os.O_CLOEXEC,os.O_NONBLOCK,os.O_DIRECTORY)!=(0x8000,0x80000,0x800,0x4000):fail('platform_flags')
 if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd or os.stat not in os.supports_follow_symlinks:fail('platform_dirfd')
 lib=ctypes.CDLL(None,use_errno=True);lib.flock.argtypes=(ctypes.c_int,ctypes.c_int);lib.flock.restype=ctypes.c_int
 aliases=aliases_current()
 for n,mode in (('/',None),('var',0o755),('volatile',0o1777),('tmp',0o1777)):
  p=None if not roots else roots[-1]['fd'];b=meta(os.stat(n,follow_symlinks=False) if p is None else os.stat(n,dir_fd=p,follow_symlinks=False))
  if b[3:5]!=(0,0) or b[5]<1 or not stat.S_ISDIR(b[2]) or (mode is None and b[2]&0o022) or (mode is not None and b[2]!=stat.S_IFDIR|mode):fail('root_unsafe')
  r=opened(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,parent=p)
  if r['identity'][:5]!=b[:5]:fail('root_changed')
  roots.append(r);anchors.append((r,p,n,b));R['directory_rows'].append(r)
 roots_current();typed_absent(NAME);typed_absent(PNAME);first=proc_gate();R['gate_rounds']=1
 roots_current();second=proc_gate()
 if first!=second:fail('proc_changed')
 roots_current();typed_absent(NAME);typed_absent(PNAME);R['gate_rounds']=2
 R['creation_unknown']=True
 lock=opened(NAME,os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_CREAT|os.O_EXCL,0o600,roots[-1]['fd'],True)
 R['creation_unknown']=False;R['lock_row']=lock;R['metadata_before']=lock_current(lock)
 now();ctypes.set_errno(0);v=lib.flock(lock['fd'],2|4);e=ctypes.get_errno()
 if type(v)is not int or type(e)is not int or (v,e)!=(0,0):fail('lock_busy_or_unknown')
 lock_current(lock);typed_absent(PNAME);R['pending_absent_after']=True
 now()
 if os.fsync(lock['fd'])is not None:fail('fsync_unknown')
 R['file_synced']=True;lock_current(lock);now()
 if os.fsync(roots[-1]['fd'])is not None:fail('fsync_unknown')
 R['parent_synced']=True;lock_current(lock);typed_absent(PNAME);complete=True
except BaseException as e:
 codes=('alarm_expired','alarm_unknown','clock_unknown','deadline','metadata_unknown','open_unknown','fd_unknown',
  'fd_changed','close_unknown','fd_budget','proc_read_budget','existing_entry','alias_unsafe','alias_changed',
  'root_changed','proc_identity','proc_budget','project_actor_present','fd_links_budget','old_lock_fd_present',
  'fd_links_changed','proc_changed','lock_identity','platform','platform_flags','platform_dirfd','root_unsafe',
  'lock_busy_or_unknown','fsync_unknown')
 R['error']=e.args[0] if type(e)is ValueError and len(e.args)==1 and e.args[0] in codes else ('io_error' if isinstance(e,OSError) else 'unknown')
 if isinstance(e,OSError) and type(e.errno)is int and 1<=e.errno<=4095:R['error_errno']=e.errno
finally:
 # Keep the pre-input absolute alarm during cleanup; never renew its period.
 # Expiry terminates this process and yields FAIL/unknown, not a close receipt.
 signal.signal(signal.SIGALRM,signal.SIG_DFL);R['cleanup_alarm_retained']=True
 for r in reversed(rows):
  try:close(r)
  except BaseException:R['close_errors']+=1
 R['lock_close_verified']=lock is not None and lock['closed'] and lock['close_called']
 R['root_fds_closed']=len(roots)==4 and all(r['closed'] and r['close_called'] for r in roots)
 if R['created'] and not R['creation_unknown'] and R['lock_close_verified']:
  try:
   aliases_current()
   for r,p,n,m in anchors:
    path='/' if n=='/' else '/var' if n=='var' else '/var/volatile' if n=='volatile' else '/var/volatile/tmp'
    if meta(os.lstat(path))[:5]!=m[:5]:fail('root_changed')
   R['metadata_after']=meta(os.lstat(LOCK))
   if R['metadata_after']!=R['metadata_before']:fail('lock_identity')
   try:os.lstat(PENDING)
   except OSError as e:
    if type(e.errno)is not int or e.errno!=errno.ENOENT:raise
   else:fail('existing_entry')
   R['retained_entry_verified']=True
  except BaseException:
   if R['error']is None:R['error']='post_identity_unknown'
 v=time.monotonic()
 R['cleanup_before_deadline']=type(v)is float and math.isfinite(v) and last is not None and last<=v<cleanup_until
 R['local_inventory_closed']=all(r['closed'] and not r['unknown'] for r in rows)
 signal.alarm(0);R['alarm_released']=True
 R['complete']=(complete and R['error']is None and R['close_errors']==0 and R['alarm_released'] and R['cleanup_before_deadline']
  and R['local_inventory_closed']
  and R['lock_close_verified'] and R['root_fds_closed'] and R['retained_entry_verified'])
print('RESULT='+repr(R))
if not R['complete']:raise SystemExit(1)
'''


def need(value, code='source_contract'):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_input(inputs, out, row):
    path = row[0] if type(row) is tuple else row
    raw = (BASE / path).read_bytes()
    if path in inputs:
        need(inputs[path] == raw, 'source_changed')
    else:
        inputs[path] = raw
        target = out / 'private-inputs' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'source_changed')
        need(target.read_bytes() == raw, 'source_changed')
    if type(row) is tuple:
        need((len(raw), sha(raw)) == row[1:], 'input_pin')
    return raw


def prepare(inputs, out):
    raw = read_input(inputs, out, MOTHER)
    tree = ast.parse(raw.decode('ascii'))
    helpers = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in HELPERS]
    need(len(helpers) == len(HELPERS) and {n.name for n in helpers} == HELPERS)
    constants = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1 and
                 isinstance(n.targets[0], ast.Name) and n.targets[0].id in ('BASE', 'TRANSPORT')]
    need(len(constants) == 2)
    nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) or n in helpers or n in constants]
    driver = dict(__file__=str(BASE / SELF), __name__='device_lock_init_private')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<frozen-metadata-PC-helpers>', 'exec'), driver)
    need(driver['TRANSPORT'] == TRANSPORT)
    return driver


def derive_transport(raw):
    changes = ((b'python3 -B -c "import sys;exec(sys.stdin.buffer.read(',
                b'python3 -B -c "import signal;signal.alarm(30);import sys;exec(sys.stdin.buffer.read('),
               (b'mta-readonly-probe', b'fixed-lock-init'))
    result = raw
    for before, after in changes:
        need(result.count(before) == 1 and result.count(after) == 0)
        result = result.replace(before, after)
        need(result.count(after) == 1)
    inverse = result
    for before, after in reversed(changes):
        need(inverse.count(after) == 1)
        inverse = inverse.replace(after, before)
    need(inverse == raw and ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(raw.decode('ascii')), include_attributes=True))
    return result, dict(original=list(TRANSPORT), derived_bytes=len(result), derived_sha256=sha(result),
        complete_byte_ast_inverse=True, changes=[dict(before=a.decode('ascii'), after=b.decode('ascii'), count=1)
                                                for a, b in changes], original_Adb_run_unchanged=True)


def initializer_budget(program):
    raw = program.encode('ascii')
    need(len(raw) <= 65536 and max(map(len, raw.splitlines())) <= 256, 'source_budget')
    ast.parse(program, feature_version=(3, 5))
    payload = base64.b64encode(zlib.compress(raw)).decode('ascii')
    inline = ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
              payload + '\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    # The exact fixed source must choose the frozen method's stdin branch.
    need(len(inline) > 3500, 'source_budget')
    data = (program + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    command = ('python3 -B -c "import signal;signal.alarm(30);import sys;exec(sys.stdin.buffer.read(' +
               str(len(data)) + '))" fixed-lock-init; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(data) <= 65536 and len(command) <= 3500, 'source_budget')
    return dict(target_bytes=len(raw), target_max_line=max(map(len, raw.splitlines())),
        stdin_bytes=len(data), shell_bytes=len(command), pre_read_alarm_seconds=30,
        host_timeout_seconds=45, output_limit=65536, fixed_stdin_branch=True,
        active_seconds_limit=25, cleanup_seconds_reserved=5, cleanup_alarm_retained=True,
        remote_cleanup_hard_bound_verified=False)


def source_contract(inputs, out, driver):
    observer = read_input(inputs, out, OBSERVER)
    coordination = read_input(inputs, out, COORDINATION)
    store = read_input(inputs, out, STORE)
    transport = read_input(inputs, out, TRANSPORT)
    literal = driver['literal']
    need(literal(observer, 'DEVICE_LOCK') == LOCK and literal(observer, 'PENDING') == PENDING and
         literal(coordination, 'DEVICE_LOCK') == literal(store, 'DEVICE_LOCK') == LOCK.rsplit('/', 1)[1] and
         literal(coordination, 'GLOBAL_PENDING') == literal(store, 'GLOBAL_PENDING') == PENDING.rsplit('/', 1)[1])
    for raw, tokens in ((observer, (b'def open(self, path): return os.open(path, ARM_READ)',
            b"meta[3:7] != (0, 0, 1, 0)", b'lock = self._open(DEVICE_LOCK)')),
            (coordination, (b"if before is None: flags |= self._flags('O_CREAT', 'O_EXCL')",
             b"if before is None and _errno(error, errno.EEXIST): _fail('lock_create_race')")),
            (store, (b"if before is None: flags |= self.io.flags('O_CREAT', 'O_EXCL')",
             b"if name != GLOBAL_PENDING: _fail('fixed_name_required')"))):
        need(all(raw.count(token) == 1 for token in tokens))
    for path in (SELF, HOST_CMD, INIT_CMD):
        read_input(inputs, out, path)
    program = ('LOCK=' + repr(LOCK) + '\nPENDING=' + repr(PENDING) + '\nNAME=' +
               repr(LOCK.rsplit('/', 1)[1]) + '\nPNAME=' + repr(PENDING.rsplit('/', 1)[1]) +
               '\nLOCK_ALIASES=' + repr(LOCK_ALIASES) + '\n' + TARGET)
    budget = initializer_budget(program)
    baseline = 'PINS=' + repr(literal(transport, 'PINS')) + '\n' + literal(transport, 'PROBE')
    driver['compressed_budget'](baseline)
    derived, contract = derive_transport(transport)
    driver['write_new'](out / 'private-raw' / 'derived-transport.private.py', derived)
    driver['write_new'](out / 'private-raw' / 'source-contract.private.json',
        (json.dumps(dict(transport=contract, budget=budget), sort_keys=True, indent=2) + '\n').encode('ascii'))
    return program, derived, budget


def accept(value):
    expected = {'complete', 'created', 'creation_unknown', 'lock_close_verified', 'alarm_installed', 'alarm_released',
        'cleanup_alarm_retained', 'cleanup_before_deadline', 'local_inventory_closed', 'active_seconds_limit', 'cleanup_seconds_reserved',
        'root_fds_closed', 'retained_entry_verified', 'file_synced', 'parent_synced', 'pending_absent_after',
        'gate_rounds', 'processes_checked', 'fd_links_checked', 'old_project_actors', 'old_lock_fds',
        'open_attempts', 'close_errors', 'error', 'error_errno', 'metadata_before', 'metadata_after', 'process_snapshots',
        'directory_rows', 'lock_row', 'device_writes', 'parent_invoked', 'owner_started',
        'radio_operations', 'production_admitted', 'restoration_verified'}
    need(type(value) is dict and set(value) == expected, 'remote_result')
    need(all(value[k] is True for k in ('complete', 'created', 'lock_close_verified', 'alarm_installed', 'alarm_released',
        'cleanup_alarm_retained', 'cleanup_before_deadline', 'local_inventory_closed',
        'root_fds_closed', 'retained_entry_verified', 'file_synced', 'parent_synced', 'pending_absent_after',
        'device_writes')) and all(value[k] is False for k in ('creation_unknown', 'parent_invoked',
        'owner_started', 'radio_operations', 'production_admitted', 'restoration_verified')) and
        value['error'] is None and value['error_errno'] is None, 'remote_result')
    limits = {'active_seconds_limit': (25, 25), 'cleanup_seconds_reserved': (5, 5),
              'gate_rounds': (2, 2), 'processes_checked': (0, 1022), 'fd_links_checked': (0, 16384),
              'old_project_actors': (0, 0), 'old_lock_fds': (0, 0), 'open_attempts': (5, 4101), 'close_errors': (0, 0)}
    need(all(type(value[k]) is int and low <= value[k] <= high for k, (low, high) in limits.items()), 'remote_result')
    metadata = value['metadata_before']
    need(type(metadata) is tuple and len(metadata) == 9 and
         all(type(v) is int and 0 <= v < 1 << 64 for v in metadata) and
         metadata == value['metadata_after'] and metadata[2] == 0o100600 and
         metadata[3:7] == (0, 0, 1, 0), 'remote_result')
    snapshots = value['process_snapshots']
    need(type(snapshots) is list and len(snapshots) == 2 and snapshots[0] == snapshots[1], 'remote_result')
    for row in snapshots:
        need(type(row) is tuple and len(row) == 4 and
             all(type(v) is int for v in row[:3]) and 0 <= row[0] <= 511 and
             0 <= row[1] <= 8192 and 0 <= row[2] <= 65536 and type(row[3]) is str and
             re.fullmatch('[0-9a-f]{64}', row[3]) is not None, 'remote_result')
    need(value['processes_checked'] == 2 * snapshots[0][0] and
         value['fd_links_checked'] == 2 * snapshots[0][1], 'remote_result')
    directories = value['directory_rows']
    need(type(directories) is list and len(directories) == 4 and type(value['lock_row']) is dict, 'remote_result')
    for row in directories + [value['lock_row']]:
        need(type(row) is dict and set(row) == {'fd', 'open_called', 'unknown', 'close_called', 'closed',
             'identity', 'close_return', 'close_errno'} and type(row['fd']) is int and row['fd'] >= 0 and
             row['open_called'] is True and row['unknown'] is False and row['close_called'] is True and
             row['closed'] is True and row['close_return'] is None and type(row['close_errno']) is int and
             row['close_errno'] == 9 and type(row['identity']) is tuple and len(row['identity']) == 9 and
             all(type(v) is int and 0 <= v < 1 << 64 for v in row['identity']), 'remote_result')
    need(value['lock_row']['identity'] == metadata, 'remote_result')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--source-only', action='store_true')
    group.add_argument('--initialize-device', action='store_true')
    args = parser.parse_args()
    mode = 'initialize' if args.initialize_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('go-device-lock-init-v1-' + mode + '-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}; driver = probe = adb = before = after = None
    report = dict(kind='go-device-lock-init-v1', mode=mode, passed=False,
        source_complete=False, source_preserved=False, input_count=0, device_invoked=False,
        created=False, creation_unknown=False, device_writes=False, initialization_complete=False,
        lock_close_verified=False, root_fds_closed=False, retained_entry_verified=False,
        file_synced=False, parent_synced=False, gate_rounds=0,
        alarm_installed=None, alarm_released=None, cleanup_alarm_retained=None,
        cleanup_before_deadline=None, local_inventory_closed=None, remote_cleanup_hard_bound_verified=False,
        stock_identity_ok=None, stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        baseline_before_receipt=None, baseline_after_receipt=None, initialize_receipt=None,
        parent_invoked=False, stage_invoked=False, owner_started=False, helper_invoked=False,
        radio_operations=False, production_admitted=False, restoration_verified=False,
        old_owner_closure_verified=False, old_tests_run=0, error_code=None)
    try:
        driver = prepare(inputs, out)
        program, transport, budget = source_contract(inputs, out, driver)
        driver['write_new'](private / 'initializer.source.private.py', program.encode('ascii'))
        report['source_budget'] = budget
        report['source_complete'] = True
        if mode != 'source':
            probe = driver['probe_definitions'](transport)
            report['device_invoked'] = True
            adb = probe.Adb(private)
            before = driver['run_readonly'](adb, probe, private, 'stock-before', probe.source(), report, 'baseline_before_receipt')
            driver['write_new'](private / 'stock-before.private.json', (json.dumps(before, sort_keys=True) + '\n').encode('ascii'))
            need(driver['stock_identity'](before, probe.PINS), 'stock_baseline')
            report['wifi_connected_before'] = before['capabilities']['wifi_connected']
            stem = '%02d-initialize' % (adb.index + 1)
            try:
                report.update(created=None, device_writes=None, creation_unknown=True)
                value = probe.Adb.python(adb, 'initialize', program, timeout=45)
            finally:
                report['initialize_receipt'], derived = driver['receipt'](private, stem)
                lines = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
                if len(lines) == 1:
                    retained = ast.literal_eval(lines[0])
                    driver['write_new'](private / 'initializer.result.private.json', (json.dumps(retained, sort_keys=True) + '\n').encode('ascii'))
                    if type(retained) is dict:
                        for field in ('created', 'creation_unknown', 'device_writes', 'lock_close_verified',
                                      'alarm_installed', 'alarm_released', 'cleanup_alarm_retained',
                                      'cleanup_before_deadline', 'local_inventory_closed',
                                      'root_fds_closed', 'retained_entry_verified', 'file_synced', 'parent_synced'):
                            if type(retained.get(field)) is bool: report[field] = retained[field]
                        if type(retained.get('gate_rounds')) is int: report['gate_rounds'] = retained['gate_rounds']
            current = report['initialize_receipt']
            need(current['host_exit'] == 0 and current['remote_status_known'] and current['remote_exit'] == 0 and
                 current['stderr_bytes'] == 0 and derived.splitlines().count('MTA_REMOTE_OK') == 1, 'remote_result')
            accept(value)
            report['initialization_complete'] = True
    except BaseException as error:
        allowed = ('input_pin', 'source_contract', 'source_budget', 'source_changed', 'stock_baseline', 'remote_result')
        report['error_code'] = error.args[0] if type(error) is ValueError and len(error.args) == 1 and error.args[0] in allowed else 'host_transport' if type(error) is RuntimeError else 'unexpected'
    finally:
        if adb is not None:
            try:
                after = driver['run_readonly'](adb, probe, private, 'stock-after', probe.source(), report, 'baseline_after_receipt')
                driver['write_new'](private / 'stock-after.private.json', (json.dumps(after, sort_keys=True) + '\n').encode('ascii'))
                report['stock_identity_ok'] = before is not None and driver['stock_identity'](before, probe.PINS) and driver['stock_identity'](after, probe.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                report['wifi_connected_after'] = after['capabilities']['wifi_connected']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None: report['error_code'] = 'stock_changed'
        inventory = {}; preserved = bool(inputs)
        for path, raw in inputs.items():
            inventory[path] = dict(bytes=len(raw), sha256=sha(raw))
            try:
                preserved = preserved and (out / 'private-inputs' / path).read_bytes() == raw and (BASE / path).read_bytes() == raw
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        raw_inventory = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii')
        with (out / 'private-inputs.json').open('xb') as handle: need(handle.write(raw_inventory) == len(raw_inventory), 'source_changed')
    report['passed'] = report['source_complete'] and report['source_preserved'] and report['error_code'] is None and (mode == 'source' or report['initialization_complete'] and report['stock_identity_ok'] is True and report['stock_unchanged'] is True)
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE; explicit fixed initialize-device only.\n'
        b'Two typed-ENOENT/pending/proc/FD gates, one EXCL empty shared lock creation.\n'
        b'Existing/unsafe/busy/unknown fails; no open fallback, repair, unlink or retry.\n'
        b'The newly created empty lock entry is retained even on failure.\n'
        b'Pre-input alarm30 is not renewed; active<=25 with 5 seconds cleanup reserve.\n'
        b'Cleanup retains that alarm; timeout means FAIL/unknown, never a close receipt.\n'
        b'Host45/alarm limits are not a guarantee against uninterruptible kernel I/O.\n'
        b'No Parent/Stage/Owner/helper/RF; no admission, restoration or old Owner closure.\n'
        b'Private sources/process/FD evidence/raw stdout/stderr/host and remote exits retained.\n'
        b'Public ZIP exactly result+README; SOURCE PASS performs no device action.\n')
    for name, raw in (('result.json', result), ('README.txt', readme)):
        with (out / name).open('xb') as handle: need(handle.write(raw) == len(raw), 'source_changed')
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and archive.read('result.json') == result and archive.read('README.txt') == readme, 'source_changed')
    code = 0 if report['passed'] else 1
    with (out / 'checker-exit.txt').open('xb') as handle: need(handle.write((str(code) + '\n').encode('ascii')) == 2, 'source_changed')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out)), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
