"""Prepare only the one missing empty CLIENT work root; default HOST SOURCE.

Explicit --prepare-device: fixed readonly native observations and held-directory
checks precede one exclusive mkdir. Existing roots/history and unknowns refuse.
No runtime graph, Owner, Trial, radio initialization, run, cleanup or rollback.
Created=True remains a fact on a later failure. Identifiers stay private.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_prepare_empty_client_root_v1.py'
CMDS = ('HOST_MTA_PREPARE_EMPTY_CLIENT_ROOT_V1_SOURCE_CHECK.cmd',
        'PREPARE_MTA_EMPTY_CLIENT_ROOT_V1_DEVICE.cmd')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
BARRIER = ('candidate/formal-receive-v3/runtime/mta_receive_barrier.py', 24113,
    'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397')
RADIO = ('runtime/mta_receive_radio_baseline.py', 3971,
    '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c')
JSON = ('runtime/p011_json.py', 8061,
    'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
RUNNER = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_session.py', 79279,
    '88c3dc8daac2f4315affb7f439e01a7a60a9c764053019fe9043f891b676a5aa')
NATIVE = ('results/receive-radio-baseline-build-20261004-112415-de67547c/mta-bluez-radio-baseline',
    74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
    '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
README = (b'One missing empty CLIENT root preparation only; no receive admission.\n'
    b'Default SOURCE is HOST-only. --prepare-device authorizes only one fixed mkdir.\n'
    b'Existing roots, history, links, unknowns, pending or project actors refuse.\n'
    b'Original pinned readonly --capabilities helper is reused without staging.\n'
    b'Fresh two-pass zero connection/advertisement and limited stock observations.\n'
    b'Held physical TMP FD, fixed aliases, two ENOENT observations, root:root0700.\n'
    b'Created fact survives later FAIL; no deletion, rollback, run or old graph.\n'
    b'No scan/listen/advertise/pair/connect/disconnect/Wi-Fi/init/Owner/Trial/phone.\n'
    b'No full-network-restoration or receiving-ready claim. Raw identities private.\n'
    b'Inputs and private SOURCE ZIP readback precede metadata-only public sealing.\n')

TARGET = r'''
import errno,hashlib,os,stat,subprocess,sys,time,traceback
END=time.monotonic()+60.0
SELF_PID=os.getpid();PARENT_PID=os.getppid()
ROWS=[];OBS=[];PROBES=[];ERRORS=[]
FACTS=dict(passed=False,created=False,mkdir_attempted=False,absence_observations=0,
 radio_observations=0,zero_connections=False,zero_advertisements=False,
 radio_same=False,radio_after_verified=False,limited_stock_before_verified=False,limited_stock_after_verified=False,
 limited_stock_unchanged=False,old_project_actors_absent=False,pending_absent=False,
 aliases_verified=False,root_readback_verified=False,root_empty=False,
 resources_closed=False,observer_actors_closed=False,resource_pending=True,
 rf_mutation_requested=False,receiving_ready=False,receive_admission=False,
 full_network_restore_verified=False,reason='not_started',error=None)
def require(value,reason):
 if value is not True:raise ValueError(reason)
def check():
 require(time.monotonic()<END,'active_deadline')
 require(os.getpid()==SELF_PID and os.getppid()==PARENT_PID,'caller_changed')
def observe(kind,value):
 require(len(OBS)<8192,'observation_limit');OBS.append((kind,value));return value
def ticket_open(name,flags,parent=None,mode=None):
 check();require(len(ROWS)<4096,'fd_limit')
 row=dict(name=name,fd=None,returned=False,closed=False,close_attempted=False,
  unknown=True,original=None,error=None)
 ROWS.append(row)
 try:
  fd=os.open(name,flags) if parent is None else os.open(name,flags,dir_fd=parent)
  row['fd']=fd;row['returned']=True
  require(type(fd) is int and fd>=0,'fd_return')
  raw=os.fstat(fd);row['original']=barrier._meta(raw)
  if mode is not None:barrier._directory(raw,mode)
  row['unknown']=False;check();return row
 except BaseException:
  row['error']=traceback.format_exc();raise
def close_row(row):
 if row['close_attempted']:return row['closed']
 row['close_attempted']=True
 if not row['returned']:
  row['closed']=row['fd'] is None;row['unknown']=not row['closed'];return row['closed']
 try:
  fd=row['fd'];require(type(fd) is int and fd>=0 and row['original'] is not None,'close_identity')
  require(barrier._meta(os.fstat(fd))[:5]==row['original'][:5],'close_identity')
  returned=os.close(fd);row['close_return']=returned
  try:os.fstat(fd)
  except OSError as error:
   row['close_errno']=error.errno
   if returned is None and error.errno==errno.EBADF:
    row['closed']=True;row['unknown']=False;return True
  raise ValueError('close_unknown')
 except BaseException:
  row['unknown']=True;row['close_error']=traceback.format_exc();return False
def read(path,limit,expected=None,parent=None,keep=False,mode=None,proc=False):
 check();raw_before=os.stat(path,dir_fd=parent,follow_symlinks=False) if parent is not None else os.lstat(path)
 before=barrier._meta(raw_before)
 require(stat.S_ISREG(before[2]) and before[5]==1 and 0<=before[6]<=limit,'read_file')
 if not proc:require(before[3:5]==(0,0),'read_owner')
 if mode is not None:require(stat.S_IMODE(before[2])==mode,'read_mode')
 row=ticket_open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,parent)
 failed=False
 try:
  require(row['original']==before,'read_identity');parts=[];count=0
  while True:
   check();part=os.read(row['fd'],min(65536,limit+1-count))
   if not part:break
   parts.append(part);count+=len(part);require(count<=limit,'read_limit')
  raw=b''.join(parts)
  after=os.stat(path,dir_fd=parent,follow_symlinks=False) if parent is not None else os.lstat(path)
  require((proc or count==before[6]) and barrier._meta(os.fstat(row['fd']))==before and
   barrier._meta(after)==before,'read_changed')
  sha=hashlib.sha256(raw).hexdigest();observe('file',(path,before,count,sha))
  if expected is not None:require((count,sha)==expected,'read_pin')
  if keep:return raw,row
  return raw
 except BaseException:
  failed=True;row['read_error']=traceback.format_exc();raise
 finally:
  if not keep:
   closed=close_row(row)
   if not failed:require(closed,'read_close')
def proc_identity(pid):
 raw=read('/proc/'+str(pid)+'/stat',4096,proc=True)
 at=raw.rindex(b')');fields=raw[at+2:].split()
 require(len(fields)>=20 and fields[1].isdigit() and fields[19].isdigit(),'proc_fields')
 require(raw[:raw.index(b' ')].isdigit() and int(raw[:raw.index(b' ')])==pid,'proc_pid')
 return (pid,int(fields[1]),int(fields[19]),raw[raw.index(b'(')+1:at])
def process_snapshot():
 check();names=os.listdir('/proc');require(type(names) is list and len(names)<=4096,'proc_limit')
 pids=sorted(int(name) for name in names if type(name) is str and name.isdigit())
 require(len(pids)<=512,'proc_limit');stock=[];actors=[]
 for pid in pids:
  first=proc_identity(pid)
  if pid in (SELF_PID,PARENT_PID):
   require(first==(SELF_ID if pid==SELF_PID else PARENT_ID),'excluded_actor_changed')
   if pid==PARENT_PID:require(os.readlink('/proc/'+str(pid)+'/exe')==PARENT_EXE,'parent_shell_changed')
   continue
  raw=read('/proc/'+str(pid)+'/cmdline',4096,proc=True)
  if not raw:continue
  require(raw[-1:]==b'\0','proc_cmdline');args=raw.split(b'\0')[:-1]
  exe=os.readlink('/proc/'+str(pid)+'/exe')
  actor=(any(b'p011-mta-' in arg or b'/p011-toolbox/candidates/' in arg or
   b'/p011-toolbox/sessions/' in arg or arg.startswith((b'mta-',b'p011-')) for arg in args) or
   first[3] in (b'mta-bluez-helper',b'mta-network-hel',b'mta-connman-obs') or
   exe.startswith(('/var/volatile/tmp/p011-mta-','/tmp/p011-mta-',
    '/mnt/data/p011-toolbox/candidates/')))
  tracked=first[3] in (b'Z03',b'control_engine',b'weston')
  require(proc_identity(pid)==first and read('/proc/'+str(pid)+'/cmdline',4096,proc=True)==raw and
   os.readlink('/proc/'+str(pid)+'/exe')==exe,'proc_changed')
  row=(first,exe,hashlib.sha256(raw).hexdigest())
  if actor:actors.append(row)
  if tracked:stock.append(row)
 observe('project_actors',tuple(actors));require(not actors,'old_project_actor')
 require(all(sum(row[0][3]==name for row in stock)==1 for name in
  (b'Z03',b'control_engine',b'weston')),'stock_process')
 require(all(row[1]=='/usr/bin/'+row[0][3].decode('ascii') for row in stock),'stock_process')
 hashes=tuple((path,hashlib.sha256(read(path,134217728)).hexdigest()) for path in sorted(STOCK_PINS))
 require(dict(hashes)==STOCK_PINS,'stock_hash')
 boot=read('/proc/sys/kernel/random/boot_id',128,proc=True)
 return (tuple(sorted(stock)),hashes,boot)
def dir_open(parent,name,mode):
 raw=os.lstat(name) if parent is None else os.stat(name,dir_fd=parent['fd'],follow_symlinks=False)
 before=barrier._directory(raw,mode)
 row=ticket_open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
  None if parent is None else parent['fd'],mode)
 require(row['original']==before,'anchor_changed')
 ANCHORS.append((parent,name,mode,row));return row
def anchors():
 check()
 for parent,name,mode,row in ANCHORS:
  require(not row['closed'] and not row['unknown'],'anchor_fd')
  current=os.lstat(name) if parent is None else os.stat(name,dir_fd=parent['fd'],follow_symlinks=False)
  require(barrier._directory(current,mode)[:5]==row['original'][:5] and
   barrier._directory(os.fstat(row['fd']),mode)[:5]==row['original'][:5],'anchor_changed')
 for parent,name,target,original in ALIASES:
  current=barrier._meta(os.stat(name,dir_fd=parent['fd'],follow_symlinks=False))
  require(current==original and os.readlink(name,dir_fd=parent['fd'])==target,'alias_changed')
 FACTS['aliases_verified']=True
def pending_absent():
 anchors()
 try:value=os.stat('p011-mta-p2p-device.pending',dir_fd=TMP['fd'],follow_symlinks=False)
 except OSError as error:
  observe('pending_error',error.errno)
  if type(error.errno) is int and error.errno==errno.ENOENT:
   FACTS['pending_absent']=True;return
  raise
 observe('pending',barrier._meta(value));raise ValueError('pending_exists')
def root_absent():
 pending_absent()
 try:value=os.stat('p011-mta-client-rfinit',dir_fd=TMP['fd'],follow_symlinks=False)
 except OSError as error:
  observe('root_absence_error',error.errno)
  if type(error.errno) is int and error.errno==errno.ENOENT:
   FACTS['absence_observations']+=1;return
  raise
 observe('existing_client_root',barrier._meta(value));raise ValueError('client_root_exists')
def radio_probe():
 check();pending_absent()
 require(barrier._meta(os.fstat(NATIVE_FD['fd']))==NATIVE_FD['original'],'native_changed')
 row=dict(returned=False,exit=None,stdout=b'',stderr=b'',error=None,reaped=False,pipes_closed=False)
 PROBES.append(row);process=None
 try:
  process=subprocess.Popen(['/proc/self/fd/'+str(NATIVE_FD['fd']),'--capabilities','hci0'],
   pass_fds=(NATIVE_FD['fd'],),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  row['returned']=True;row['pid']=process.pid
  # The pinned helper has its own finite native query timeouts. On timeout do
  # not signal an uncertain actor or authorize mkdir; retain it as pending.
  out,err=process.communicate(timeout=min(15.0,max(0.01,END-time.monotonic())))
  row.update(stdout=out,stderr=err,exit=process.returncode,reaped=process.poll() is not None)
  check();require(process.returncode==0 and not err and 0<len(out)<=4096,'radio_receipt')
  value=p011_json.loads(out.decode('utf-8'));normal=radio.normalize(value)
  require(value['connected_devices']==[] and value['active_instance_ids']==[] and
   value['active_instances']==0 and value['global_advertising'] is False and
   value['bluez_advertising_active'] is False,'radio_busy')
  FACTS['radio_observations']+=1;return normal
 except BaseException as failure:
  if isinstance(failure,subprocess.TimeoutExpired):
   row['stdout']=failure.output or b'';row['stderr']=failure.stderr or b''
  row['error']=traceback.format_exc();raise
 finally:
  if process is not None:
   row['pipe_close_errors']=[]
   for pipe in (process.stdout,process.stderr):
    if pipe is not None:
     try:pipe.close()
     except BaseException:row['pipe_close_errors'].append(traceback.format_exc())
   row['pipes_closed']=not row['pipe_close_errors'] and process.stdout.closed and process.stderr.closed
   row['reaped']=process.poll() is not None
try:
 require(sys.platform=='linux' and os.uname()[4]=='armv7l' and sys.byteorder=='little' and
  os.geteuid()==0 and os.getegid()==0 and os.O_NOFOLLOW==0x8000 and os.O_CLOEXEC==0x80000,
  'target_profile')
 SELF_ID=proc_identity(SELF_PID);PARENT_ID=proc_identity(PARENT_PID)
 PARENT_EXE=os.readlink('/proc/'+str(PARENT_PID)+'/exe')
 observe('caller_identity',(SELF_ID,PARENT_ID,PARENT_EXE))
 require(PARENT_ID[3] in (b'sh',b'ash',b'bash',b'dash') and
  PARENT_EXE in ('/bin/sh','/bin/ash','/bin/bash','/bin/bash.bash','/bin/dash','/bin/busybox','/usr/bin/busybox'),
  'parent_shell_profile')
 require(b'p011-empty-client-root-v1' in read('/proc/'+str(SELF_PID)+'/cmdline',4096,proc=True).split(b'\0'),
  'self_marker')
 ANCHORS=[];ALIASES=[]
 ROOT=dir_open(None,'/',None);VAR=dir_open(ROOT,'var',0o755)
 VOLATILE=dir_open(VAR,'volatile',0o1777);TMP=dir_open(VOLATILE,'tmp',0o1777)
 for parent,name,target in ((ROOT,'tmp','/var/tmp'),(VAR,'tmp','/var/volatile/tmp')):
  raw=os.stat(name,dir_fd=parent['fd'],follow_symlinks=False);meta=barrier._meta(raw)
  require(stat.S_ISLNK(meta[2]) and stat.S_IMODE(meta[2])==0o777 and
   meta[3:6]==(0,0,1) and meta[6]==len(target) and
   os.readlink(name,dir_fd=parent['fd'])==target,'alias_profile')
  ALIASES.append((parent,name,target,meta))
 anchors();root_absent()
 ASSET=dir_open(TMP,'p011-mta-rx-durable-v1',0o700);NATIVE_DIR=dir_open(ASSET,'native',0o700)
 unused,NATIVE_FD=read('mta-bluez-helper',74920,NATIVE_PIN,NATIVE_DIR['fd'],keep=True,mode=0o500)
 before=process_snapshot();FACTS['limited_stock_before_verified']=True
 first=radio_probe();second=radio_probe();require(first==second,'radio_changed')
 immediate=process_snapshot();require(before==immediate,'stock_before_changed')
 FACTS.update(radio_same=True,zero_connections=True,zero_advertisements=True,
  old_project_actors_absent=True)
 root_absent();require(FACTS['absence_observations']==2,'root_absence_count')
 check();anchors();pending_absent();check();FACTS['mkdir_attempted']=True
 os.mkdir('p011-mta-client-rfinit',0o700,dir_fd=TMP['fd'])
 FACTS['created']=True
 check();CLIENT=dir_open(TMP,'p011-mta-client-rfinit',0o700)
 for unused in range(2):
  anchors();names=os.listdir(CLIENT['fd']);observe('client_names',names)
  require(type(names) is list and names==[],'client_root_not_empty')
  require(barrier._directory(os.fstat(CLIENT['fd']),0o700)==CLIENT['original'] and
   barrier._directory(os.stat('p011-mta-client-rfinit',dir_fd=TMP['fd'],follow_symlinks=False),
    0o700)==CLIENT['original'],
   'client_root_changed');pending_absent()
 FACTS.update(root_readback_verified=True,root_empty=True)
 after=process_snapshot();FACTS['limited_stock_after_verified']=True
 require(before==after,'stock_after_changed');FACTS['limited_stock_unchanged']=True
 third=radio_probe();fourth=radio_probe();require(first==third==fourth,'radio_after_changed')
 FACTS['radio_after_verified']=True
 require(os.listdir(CLIENT['fd'])==[] and
  barrier._directory(os.fstat(CLIENT['fd']),0o700)==CLIENT['original'] and
  barrier._directory(os.stat('p011-mta-client-rfinit',dir_fd=TMP['fd'],follow_symlinks=False),
   0o700)==CLIENT['original'],'client_root_changed')
 pending_absent();anchors();FACTS['reason']='created_verified'
except BaseException as error:
 FACTS['error']=type(error).__name__
 code=str(error) if type(error) is ValueError else 'operation_error'
 FACTS['reason']=code if code in TARGET_REASONS else 'operation_error'
 ERRORS.append(traceback.format_exc())
finally:
 for row in reversed(ROWS):close_row(row)
 FACTS['resources_closed']=all(row['closed'] is True and row['unknown'] is False for row in ROWS)
 FACTS['observer_actors_closed']=(len(PROBES)==4 and all(row['reaped'] is True and
  row['pipes_closed'] is True and row['exit']==0 and row['error'] is None for row in PROBES))
 FACTS['resource_pending']=not FACTS['resources_closed'] or any(not row['reaped'] or
  not row['pipes_closed'] for row in PROBES)
 FACTS['passed']=(FACTS['error'] is None and FACTS['reason']=='created_verified' and
  FACTS['created'] and FACTS['resources_closed'] and FACTS['observer_actors_closed'] and
  FACTS['limited_stock_unchanged'] and FACTS['root_readback_verified'] and not FACTS['resource_pending'])
 print('RESULT='+repr(dict(facts=FACTS,private=dict(fd_rows=ROWS,observations=OBS,
  probes=PROBES,errors=ERRORS))))
 raise SystemExit(0 if FACTS['passed'] else 1)
'''

BOOL_FIELDS = ('passed', 'created', 'mkdir_attempted', 'zero_connections', 'zero_advertisements',
    'radio_same', 'radio_after_verified', 'limited_stock_before_verified', 'limited_stock_after_verified',
    'limited_stock_unchanged', 'old_project_actors_absent', 'pending_absent', 'aliases_verified',
    'root_readback_verified', 'root_empty', 'resources_closed', 'observer_actors_closed',
    'resource_pending', 'rf_mutation_requested', 'receiving_ready', 'receive_admission',
    'full_network_restore_verified')
COUNT_FIELDS = ('absence_observations', 'radio_observations')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def selected_source(raw, names):
    tree = ast.parse(raw)
    nodes = [row for row in tree.body if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name in names]
    need(tuple(row.name for row in nodes) == names and all(not row.decorator_list for row in nodes), 'selected_definitions')
    lines = raw.splitlines(keepends=True)
    return b'\n'.join(b''.join(lines[row.lineno-1:row.end_lineno]) for row in nodes)


def build_source(inputs):
    transport_tree = ast.parse(inputs[TRANSPORT[0]])
    assignments = [row for row in transport_tree.body if isinstance(row, ast.Assign) and
        len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'PINS']
    need(len(assignments) == 1, 'stock_pins_inventory')
    stock = ast.literal_eval(assignments[0].value)
    need(type(stock) is dict and len(stock) == 3, 'stock_pins_inventory')
    runner = ast.parse(inputs[RUNNER[0]])
    rows = [row for row in runner.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
        isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'HELPER_PINS']
    need(len(rows) == 1 and tuple(row for row in ast.literal_eval(rows[0].value)
        if row[0] == 'mta-bluez-helper') == (('mta-bluez-helper',)+NATIVE[1:],), 'actual75_native_pin')
    barrier_raw = inputs[BARRIER[0]]
    reason_rows = [row for row in ast.parse(barrier_raw).body if isinstance(row, ast.Assign) and
        len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'REASONS']
    need(len(reason_rows) == 1, 'barrier_reasons_binding')
    reason_row = reason_rows[0]
    reason_source = b''.join(barrier_raw.splitlines(keepends=True)[reason_row.lineno-1:reason_row.end_lineno])
    capsule = b'import stat\n' + reason_source + selected_source(inputs[BARRIER[0]],
        ('BarrierError', '_fail', '_meta', '_directory')) + b'\n'
    modules = (('barrier', capsule), ('p011_json', inputs[JSON[0]]), ('radio', inputs[RADIO[0]]))
    lines = ['import hashlib,types', 'MODULES=(']
    for name, raw in modules:
        lines.append('('+repr(name)+','+str(len(raw))+','+repr(digest(raw))+',(')
        lines.extend(repr(raw[at:at+96])+',' for at in range(0, len(raw), 96))
        lines.append(')),')
    reasons = target_reasons()
    lines.extend((')', 'for name,size,sha,chunks in MODULES:', ' raw=b"".join(chunks)',
        ' if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("module_pin")',
        ' module=types.ModuleType(name)', ' exec(compile(raw,"<empty-client-root-pure-data>","exec"),module.__dict__)',
        ' globals()[name]=module', 'STOCK_PINS='+repr(stock), 'NATIVE_PIN='+repr(NATIVE[1:]),
        'TARGET_REASONS=(', *(repr(code)+',' for code in reasons), ')'))
    raw = ('\n'.join(lines)+'\n'+TARGET).encode('ascii')
    need(len(raw) <= 65536 and max(map(len, raw.splitlines())) <= 512, 'new_source_budget')
    ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return raw


def target_reasons():
    tree = ast.parse(TARGET)
    reasons = {'not_started', 'created_verified', 'operation_error', 'client_root_exists', 'pending_exists'}
    for row in ast.walk(tree):
        if isinstance(row, ast.Call) and isinstance(row.func, ast.Name) and row.func.id == 'require':
            need(len(row.args) == 2 and isinstance(row.args[1], ast.Constant) and
                type(row.args[1].value) is str, 'finite_target_reason')
            reasons.add(row.args[1].value)
    return tuple(sorted(reasons))


def parse_result(raw):
    need(type(raw) is bytes and len(raw)<=8*1024*1024, 'remote_output_budget')
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    exits = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
    rows = re.findall(r'^RESULT=(.*)$', text, re.M)
    need(len(exits) == len(rows) == 1, 'strict_remote_receipt')
    value = ast.literal_eval(rows[0]);remote = int(exits[0])
    need(type(value) is dict and set(value) == {'facts', 'private'} and type(value['facts']) is dict and
        type(value['private']) is dict and type(value['facts'].get('passed')) is bool and
        remote == (0 if value['facts']['passed'] else 1), 'strict_remote_result')
    facts=value['facts']
    need(set(facts)==set(BOOL_FIELDS+COUNT_FIELDS+('reason','error')) and
        all(type(facts[key]) is bool for key in BOOL_FIELDS) and
        all(type(facts[key]) is int and 0<=facts[key]<=4 for key in COUNT_FIELDS) and
        facts['reason'] in target_reasons() and (facts['error'] is None or
        type(facts['error']) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',facts['error']) is not None) and
        all(facts[key] is False for key in ('rf_mutation_requested','receiving_ready',
            'receive_admission','full_network_restore_verified')), 'metadata_only_facts')
    return remote, value


def load_transport(raw):
    fragment = selected_source(raw, ('select_target', 'Adb'))
    module = types.ModuleType('empty_client_root_transport_only')
    module.__dict__.update(Path=Path, re=re, subprocess=subprocess,
        ADB=Path('C:/Program Files/ADB/adb.exe'))
    exec(compile(fragment, str(BASE / TRANSPORT[0]), 'exec'), module.__dict__)
    need('main' not in module.__dict__ and 'PROBE' not in module.__dict__, 'no_old_probe')
    return module


def main():
    need(sys.argv[1:] in ([], ['--prepare-device']), 'explicit_mode_only')
    device = sys.argv[1:] == ['--prepare-device']
    mode = 'prepare' if device else 'source'
    out = BASE / 'results' / ('prepare-empty-client-root-v1-'+mode+'-'+
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw';private.mkdir()
    inputs = {};evidence = None;sealer = None;program = None
    report = dict(schema='p011-prepare-empty-client-root-v1', mode=mode, passed=False,error=None,
        source_checked=False,source_preserved=False,device_invoked=False,created=False,
        remote_exit='UNKNOWN' if device else 'NOT_RUN',remote_status_known=False,
        host_exit='UNKNOWN' if device else 'NOT_RUN',receiving_ready=False,receive_admission=False,
        rf_mutation_requested=False,phone_tested=False,full_network_restore_verified=False)
    try:
        seed = (BASE / SEALER[0]).read_bytes();inputs[SEALER[0]]=seed
        need((len(seed),digest(seed)) == SEALER[1:], 'sealer_pin')
        sealer=types.ModuleType('empty_client_root_actual_sealer')
        exec(compile(seed,str(BASE / SEALER[0]),'exec'),sealer.__dict__)
        evidence=sealer.InputEvidence(inputs)
        for pin in (TRANSPORT,BARRIER,RADIO,JSON,RUNNER,NATIVE):
            evidence.read(BASE / pin[0],pin[0],pin[1:])
        for name in (SELF,)+CMDS:evidence.read(BASE / name,name)
        program=build_source(inputs);sealer.fresh(out/'target-source.private.py',program)
        report.update(source_checked=True,target_bytes=len(program),target_line_max=max(map(len,program.splitlines())))
        if device:
            transport=load_transport(inputs[TRANSPORT[0]])
            adb=transport.Adb(private)
            command=('python3 -B -c "import signal,sys;signal.alarm(75);'
                'exec(sys.stdin.buffer.read('+str(len(program))+'))" p011-empty-client-root-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report.update(device_invoked=True,created='UNKNOWN')
            raw=adb.run('prepare-empty-client-root',['shell',command],85,input_data=program)
            remote,value=parse_result(raw)
            report.update(remote_exit=remote,remote_status_known=True,host_exit=0)
            report['facts']=value['facts'];report['created']=value['facts']['created']
            sealer.fresh(out/'private-observation.txt',(repr(value)+'\n').encode('utf-8'))
    except BaseException as failure:
        report['error']=type(failure).__name__
        if sealer is not None:
            diagnostic=traceback.format_exc().encode('utf-8')
            try:sealer.fresh(private/'host-error.private.txt',diagnostic)
            except BaseException as diagnostic_failure:report['diagnostic_error']=type(diagnostic_failure).__name__
        else:
            with (private/'unsealed-error.private.txt').open('xb') as stream:
                stream.write(traceback.format_exc().encode('utf-8'))
    finally:
        try:
            need(sealer is not None and evidence is not None,'private_sealer_required')
            evidence.snapshot(out,lambda name:name)
            report['source_preserved']=(not evidence.partial and not evidence.changed_attempts and
                all((BASE/name).read_bytes()==raw and (out/'private-inputs'/name).read_bytes()==raw
                    for name,raw in inputs.items()))
            members={'private-inputs/'+name:raw for name,raw in sorted(inputs.items())}
            if program is not None:members['target-source.private.py']=program
            private_zip=out/'private-source.zip'
            with zipfile.ZipFile(private_zip,'x',zipfile.ZIP_DEFLATED) as archive:
                for name,raw in members.items():archive.writestr(name,raw)
            report['private_source_zip_sha256']=sealer._verify_zip(private_zip,members)
            report['private_source_zip_readback']=True
        except BaseException as failure:
            report['source_preserved']=False;report['error']=report['error'] or type(failure).__name__
            if sealer is not None:
                diagnostic=traceback.format_exc().encode('utf-8')
                try:sealer.fresh(private/'source-seal-error.private.txt',diagnostic)
                except BaseException as diagnostic_failure:report['source_diagnostic_error']=type(diagnostic_failure).__name__
    report['input_pins']=[dict(path=name,bytes=len(raw),sha256=digest(raw)) for name,raw in inputs.items()]
    report['passed']=(report['error'] is None and report['source_checked'] and report['source_preserved'] and
        (not device or report['remote_status_known'] and report['remote_exit']==0 and
         report['host_exit']==0 and report.get('facts',{}).get('passed') is True))
    if sealer is None:
        for name,raw in inputs.items():
            target=out/'private-inputs'/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:need(stream.write(raw)==len(raw),'unsealed_input_write')
        with (out/'unsealed-failure.private.json').open('xb') as stream:
            raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
            need(stream.write(raw)==len(raw),'unsealed_report_write')
        print(json.dumps(dict(passed=False,result_dir=str(out),public_result_zip=None)))
        return 1
    sealed=sealer.seal_result(out,report,README)
    print(json.dumps(dict(passed=sealed['report']['passed'],result_dir=str(out),
        public_result_zip=str(sealed['archive']) if sealed['archive'] else None),sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
