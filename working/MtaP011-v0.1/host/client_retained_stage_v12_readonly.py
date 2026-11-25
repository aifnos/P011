"""Retained v11 stage observations only; default SOURCE-only, never recovery.

The historical INIT program is parsed as data, never executed. Only six pinned
definition modules are loaded. Explicit execution needs this new driver SHA.
"""
import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

BASE = Path(__file__).absolute().parents[1]
REFERENCE = BASE.parents[1] / 'logs/MtaP011-ClientInitTmpAliasV11-20261001-201536-51704b69/private-raw'
SOURCE_SHA = 'b73e750d1cb55fab5c207391fc7112960cc7c77f740b606132d592614b184e6d'
RECEIPT_SHA = 'd39860a1024a3eaf32d101fc0b9ef72127fda5ae9cca4d976314b07460341966'
DRIVER_V11_SHA = '89a982b0fba22e9720e00a98d95a84547287d38945567f2a53c639e8c5f09248'
CANDIDATE_SHA = '8494abc69a933d72b7f3f85748e92fdb78ff857aa134885b133eb514c4a93298'
INFRA_SHA = 'cb50e2a92b669b64061f9872bcbb27265d3b3818517cc95cfabeaef3f8e714df'
PROBE_SHA = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
DEFINITIONS = ('p011_json', 'mta_ip', 'mta_client_tmp_alias',
    'mta_p2p_client_init', 'mta_client_proc', 'mta_client_journal_codec')
COPIES = {
    'mta_client_tmp_alias': 'client-tmp-alias-v11',
    'mta_p2p_client_init': 'client-caps-v7',
    'mta_client_baseline': 'client-readparts-v6',
    'mta_client_coordination': 'client-tmp-alias-v11',
    'mta_client_files': 'client-tmp-alias-v11',
    'mta_client_pending': 'client-recovery-budget-v8',
    'mta_client_store': 'client-recovery-budget-v8',
    'mta_client_process_owner': 'client-init-nlink2',
    'mta_client_two_phase_lease': 'client-prepare-v10',
    'mta_client_linux_provider': 'client-tmp-alias-v11',
    'mta_client_executor': 'client-tmp-alias-v11'}
_ATTEMPTS = []
MAX_SOURCE, MAX_RAW = 4194304, 16777216


def digest(raw): return hashlib.sha256(raw).hexdigest()


def read_pinned(path, pin, limit=MAX_SOURCE):
    path = Path(path)
    if path.is_symlink(): raise ValueError('local_symlink')
    before = path.stat(); raw = path.read_bytes(); after = path.stat()
    if len(raw) > limit or (before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns) or digest(raw) != pin:
        raise ValueError('local_pin')
    return raw


def literals(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: value = ast.literal_eval(node.value)
            except (ValueError, TypeError): continue
            name = node.targets[0].id
            if name in result: raise ValueError('literal_duplicate')
            result[name] = value
    return result


def normalized(raw):
    return raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')


def strict_receipt(raw, echo):
    if set(raw) != {'stdout', 'stderr', 'host_exit'} or raw['host_exit'] != 0 or \
            type(raw['host_exit']) is not int or type(raw['stdout']) is not bytes or \
            type(raw['stderr']) is not bytes or raw['stderr'] or len(raw['stdout']) > MAX_RAW:
        raise ValueError('transport_result')
    text, prefix = normalized(raw['stdout']), normalized(echo)
    if not text.startswith(prefix): raise ValueError('source_echo')
    lines = [line for line in text[len(prefix):].split('\n') if line]
    if len(lines) != 3 or not lines[0].startswith('RESULT=') or \
            lines[1:] != ['MTA_REMOTE_OK', 'MTA_REMOTE_EXIT=0']:
        raise ValueError('strict_frames')
    value = ast.literal_eval(lines[0][7:])
    if type(value) is not dict or set(value) != {'public', 'private'} or \
            type(value['public']) is not dict or type(value['private']) is not dict:
        raise ValueError('receipt_shape')
    return value


def infrastructure():
    """Extract only the reviewed LOADER string and transport class definition."""
    raw = read_pinned(BASE / 'host/client_init_prepare_v10_p011.py', INFRA_SHA)
    text = raw.decode('utf-8'); tree = ast.parse(text)
    loader = literals(raw)['LOADER']
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'HostAdbCall']
    if len(classes) != 1 or type(loader) is not str: raise ValueError('infra_shape')
    code = ast.get_source_segment(text, classes[0])
    if code.count('timeout=225') != 1: raise ValueError('transport_delta')
    code = code.replace('timeout=225', 'timeout=60', 1)
    namespace = {'Path': Path, 'subprocess': subprocess, 'os': os, 're': re}
    exec(compile(code, '<pinned-readonly-transport-def>', 'exec'), namespace)
    return loader, namespace['HostAdbCall']


def reference():
    raw = read_pinned(REFERENCE / 'target-source.py', SOURCE_SHA)
    env = literals(raw)
    pins, encoded = env['PINS'], env['ENCODED']
    if type(pins) is not tuple or len(pins) != 20 or len(set(n for n, p in pins)) != 20 or \
            tuple((n, p) for n, p, e in encoded) != pins or \
            tuple(n for n, p in pins if n in DEFINITIONS) != DEFINITIONS:
        raise ValueError('reference_graph')
    payloads = []
    for name, pin, code in encoded:
        if not re.fullmatch('[a-z][a-z0-9_]*', name) or not re.fullmatch('[0-9a-f]{64}', pin):
            raise ValueError('reference_pin')
        data = base64.b64decode(code, validate=True)
        location = BASE / ('candidate/' + COPIES[name] + '/runtime/' + name + '.py'
            if name in COPIES else 'runtime/' + name + '.py')
        if read_pinned(location, pin) != data: raise ValueError('current_source')
        if name in DEFINITIONS: payloads.append((name, pin, code))
    candidate_raw = base64.b64decode(env['CANDIDATE_ENCODED'], validate=True)
    candidate = json.loads(candidate_raw)
    files = [['runtime/' + n + '.py', len(base64.b64decode(e, validate=True)), p] for n, p, e in encoded]
    native = read_pinned(BASE / 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant', env['WPA_SHA'])
    if native != base64.b64decode(env['WPA_ENCODED'], validate=True): raise ValueError('native_reference')
    files.append(['native/mta-wpa-supplicant', len(native), env['WPA_SHA']])
    if digest(candidate_raw) != CANDIDATE_SHA or env['CANDIDATE_SHA'] != CANDIDATE_SHA or \
            candidate != {'version': 1, 'kind': 'client-init-tmp-alias-v11',
            'driver_sha256': DRIVER_V11_SHA, 'files': files} or \
            type(env['TOKEN']) is not str or not re.fullmatch('[0-9a-f]{32}', env['TOKEN']):
        raise ValueError('candidate_reference')
    receipt_raw = read_pinned(REFERENCE / 'stdout.raw', RECEIPT_SHA, MAX_RAW)
    old_echo = (normalized(raw) + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    old_stderr = read_pinned(REFERENCE / 'stderr.raw', digest(b''), MAX_RAW)
    old_host = read_pinned(REFERENCE / 'host-exit', digest(b'0'), 8)
    read_pinned(REFERENCE / 'remote-exit', digest(b'0'), 8)
    receipt = strict_receipt({'stdout': receipt_raw, 'stderr': old_stderr,
        'host_exit': int(old_host.decode('ascii'))}, old_echo)
    private = receipt['private']
    if json.loads(json.dumps(private['source_graph'])) != candidate: raise ValueError('receipt_graph')
    boot = private['baseline_before']['boot']
    python = private['python_before']['actor']['exe']
    if not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) or \
            python != '/usr/bin/python3.5': raise ValueError('receipt_binding')
    token = env['TOKEN']; run = '/tmp/p011-mta-client-rfinit/client-' + token
    expected_provider = {'version': 1, 'run_token': token, 'candidate_sha': CANDIDATE_SHA,
        'ifname': 'mta' + token[:8], 'baseline_manifest': env['BASELINE_MANIFEST'],
        'status_manifest': env['STATUS_MANIFEST'],
        'wpa_exe': '/var/volatile/tmp/p011-mta-client-rfinit/client-' + token + '/native/mta-wpa-supplicant',
        'wpa_sha': env['WPA_SHA'], 'python_exe': python,
        'executor_path': run + '/runtime/mta_client_executor.py', 'executor_sha': dict(pins)['mta_client_executor']}
    plan = {'candidate_encoded': env['CANDIDATE_ENCODED'], 'candidate_sha': CANDIDATE_SHA,
        'files': files, 'pins': pins, 'token': token, 'boot': boot, 'provider': expected_provider}
    return plan, tuple(payloads)


TARGET = r'''
import errno,hashlib,math,os,stat,time
codec=modules['p011_json'];common=modules['mta_client_tmp_alias']
core=modules['mta_p2p_client_init'];proc=modules['mta_client_proc'];journal_codec=modules['mta_client_journal_codec']
READ_CODES=frozenset(('actor_budget','actor_not_live','actor_schema','alias_final','alias_result','candidate_mismatch','deployment_binding','deployment_missing','deployment_schema','directory_changed','directory_invalid','entry_changed','file_budget','file_changed','file_metadata','journal_actor_binding','journal_binding','manifest_changed','metadata_unknown','original_fd_unknown','python_digest_shape','read_unknown','readonly_deadline','sidecar_binding','sidecar_canonical','sidecar_deadline','sidecar_manifest','sidecar_postexec','sidecar_preexec','sidecar_schema','sidecar_stage','sidecar_target','sidecar_ticket','observation_unknown'))
class ReadError(ValueError):
 def __init__(self,code):self.code=code if code in READ_CODES else 'observation_unknown';ValueError.__init__(self,self.code)
def fail(code):raise ReadError(code)
def meta(value):
 row=tuple(getattr(value,key,None) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 if any(type(v)is not int or v<0 for v in row):fail('metadata_unknown')
 return row
def directory(value,mode):
 row=meta(value)
 if not stat.S_ISDIR(row[2]) or row[3:5]!=(0,0) or row[5]<1 or (stat.S_IMODE(row[2])!=mode if mode is not None else bool(stat.S_IMODE(row[2])&0o022)):fail('directory_invalid')
 return row[:5]
def projection(value):
 if value is None or type(value)in(bool,int,float,str):return value
 if type(value)is bytes:return {'bytes_hex':value.hex()}
 if type(value)in(tuple,list):return tuple(projection(v) for v in value)
 if type(value)is dict:return {k:projection(v) for k,v in value.items()}
 return {k:projection(getattr(value,k)) for k in getattr(value,'__slots__',()) if not k.startswith('_')}
class Io(object):
 def stat_root(self):return os.stat('/',follow_symlinks=False)
 def stat_at(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
 def fstat(self,fd):return os.fstat(fd)
 def readlink_at(self,fd,name):return os.readlink(name,dir_fd=fd)
class ReadOwner(object):
 def __init__(self):
  self._io=Io();self._tmp_alias=None;self.rows=[];self.errors=[];self.end=time.monotonic()+30;self.last=None;self.close_attempted=False
 def check(self):
  now=time.monotonic()
  if type(now)not in(int,float) or not math.isfinite(now) or (self.last is not None and now<self.last) or now>=self.end:fail('readonly_deadline')
  self.last=now
 def add(self,parent,name,kind,mode):
  row={'label':name,'parent':parent,'kind':kind,'mode':mode,'fd':None,'generation':None,'metadata':None,'unknown':True,'attempted':False,'closed':False,'no_fd':False}
  self.rows.append(row);return row
 def entry(self,row):
  return self._io.stat_root() if row['parent']is None else self._io.stat_at(self.fd_of(row['parent']),row['label'])
 def fd_of(self,row):
  self.check()
  if not any(row is x for x in self.rows) or row['unknown'] or row['attempted'] or row['closed'] or type(row['fd'])is not int:fail('original_fd_unknown')
  if directory(self._io.fstat(row['fd']),row['mode'])!=row['generation']:fail('directory_changed')
  if directory(self.entry(row),row['mode'])!=row['generation']:fail('entry_changed')
  return row['fd']
 def open_dir(self,parent,name,mode=None):
  if mode is None and parent is not None:mode=0o755 if name=='var' else 0o1777
  self.check()
  parentfd=None if parent is None else self.fd_of(parent)
  before=directory(self._io.stat_root() if parent is None else self._io.stat_at(parentfd,name),mode)
  row=self.add(parent,name,'directory',mode)
  self.check()
  try:fd=os.open('/' if parent is None else name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
  except OSError:row['no_fd']=True;row['unknown']=False;raise
  row['fd']=fd
  if type(fd)is not int or fd<0 or any(x is not row and x['fd']==fd and not x['closed'] for x in self.rows):fail('original_fd_unknown')
  row['generation']=meta(os.fstat(fd))[:5]
  if directory(os.fstat(fd),mode)!=before or directory(self._io.stat_root() if parent is None else self._io.stat_at(parentfd,name),mode)!=before:fail('directory_changed')
  row['unknown']=False;row['metadata']=meta(os.fstat(fd));return row
 def read_bytes(self,row,limit):
  self.check();os.lseek(row['fd'],0,os.SEEK_SET);parts=[];total=0
  while True:
   self.check();chunk=os.read(row['fd'],min(65536,limit-total+1))
   if type(chunk)is not bytes:fail('read_unknown')
   if not chunk:break
   total+=len(chunk)
   if total>limit:fail('file_budget')
   parts.append(chunk)
  return b''.join(parts)
 def file(self,parent,name,mode,limit,hold=False):
  self.check();parentfd=self.fd_of(parent);before=meta(self._io.stat_at(parentfd,name))
  if not stat.S_ISREG(before[2]) or before[3:6]!=(0,0,1) or stat.S_IMODE(before[2])!=mode or before[6]>limit:fail('file_metadata')
  row=self.add(parent,name,'file',mode)
  try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parentfd)
  except OSError:row['no_fd']=True;row['unknown']=False;raise
  row['fd']=fd
  if type(fd)is not int or fd<0 or any(x is not row and x['fd']==fd and not x['closed'] for x in self.rows):fail('original_fd_unknown')
  actual=meta(os.fstat(fd));row['generation']=actual[:5];row['metadata']=actual
  if actual!=before:fail('file_changed')
  row['unknown']=False;raw=self.read_bytes(row,limit)
  if len(raw)!=before[6] or meta(os.fstat(fd))!=before or meta(self._io.stat_at(parentfd,name))!=before:fail('file_changed')
  if hold:row['held_raw']=raw;row['limit']=limit
  else:self.close_row(row)
  return raw,row
 def verify_held(self,row):
  raw=self.read_bytes(row,row['limit']);parentfd=self.fd_of(row['parent'])
  if raw!=row['held_raw'] or meta(os.fstat(row['fd']))!=row['metadata'] or meta(self._io.stat_at(parentfd,row['label']))!=row['metadata']:fail('manifest_changed')
  return True
 def close_row(self,row):
  if row['attempted']:return row['closed'] or row['no_fd']
  row['attempted']=True
  if row['no_fd']:return True
  fd=row['fd']
  if type(fd)is not int or fd<0 or row['generation']is None:return False
  try:
   if meta(os.fstat(fd))[:5]!=row['generation']:return False
   os.close(fd)
   try:os.fstat(fd)
   except OSError as error:
    row['closed']=type(error.errno)is int and error.errno==errno.EBADF
  except BaseException as error:self.errors.append({'label':row['label'],'kind':type(error).__name__})
  return row['closed']
 def close(self):
  if self.close_attempted:return all(r['closed']or r['no_fd'] for r in self.rows)
  self.close_attempted=True
  for row in reversed(self.rows):self.close_row(row)
  return all(r['closed']or r['no_fd'] for r in self.rows)
def actor_from(value):
 if type(value)is not dict or set(value)!=set(('pid','start','exe','argv_sha','tasks')):fail('actor_schema')
 actor=core.Actor(value['pid'],value['start'],value['exe'],value['argv_sha'],tuple(tuple(x) for x in value['tasks']))
 if not actor.live() or len(actor.tasks)!=1:fail('actor_not_live')
 return actor
def sidecar(raw,role):
 tree=codec.loads(raw.decode('utf-8'));identity=core.Identity(PLAN['candidate_sha'])
 keys=('version','kind','stage','identity','run','role','deadline','boot','target_ticket','target','parent','preexec','postexec')
 if type(tree)is not dict or set(tree)!=set(keys) or tree['version']!=1 or type(tree['version'])is not int or tree['kind']!='direct_child_launch_registration' or tree['stage']not in('pre_exec_durable','post_exec_durable') or tree['identity']!=list(identity.key()) or tree['run']!='client-'+PLAN['token'] or tree['role']!=role or tree['boot']!=PLAN['boot']:fail('sidecar_binding')
 if codec.dumps(tree,sort_keys=True).encode('utf-8')!=raw:fail('sidecar_canonical')
 if type(tree['deadline'])not in(int,float) or not math.isfinite(tree['deadline']) or tree['deadline']<=0:fail('sidecar_deadline')
 target,ticket=tree['target'],tree['target_ticket']
 if type(target)is not dict or set(target)!=set(('exe','argv_sha','binary_sha')) or type(ticket)is not dict or set(ticket)!=set(('token','role','boot','exe','argv_sha')):fail('sidecar_schema')
 expected_exe=PLAN['provider']['wpa_exe'] if role=='controller' else PLAN['provider']['python_exe']
 expected_sha=PLAN['provider']['wpa_sha'] if role=='controller' else deployment_python_sha
 if target['exe']!=expected_exe or target['binary_sha']!=expected_sha or ticket['role']!=role or ticket['boot']!=PLAN['boot'] or ticket['exe']!=target['exe'] or ticket['argv_sha']!=target['argv_sha']:fail('sidecar_target')
 typed_ticket=core.Ticket(ticket['token'],role,ticket['boot'],ticket['exe'],ticket['argv_sha'])
 parent,pre=actor_from(tree['parent']),actor_from(tree['preexec'])
 if parent.exe!=PLAN['provider']['python_exe'] or pre.exe!=parent.exe or pre.argv_sha!=parent.argv_sha:fail('sidecar_preexec')
 post=None if tree['postexec']is None else actor_from(tree['postexec'])
 if (tree['stage']=='post_exec_durable')!=(post is not None):fail('sidecar_stage')
 if post is not None and ((post.pid,post.start)!=(pre.pid,pre.start) or post.exe!=target['exe'] or post.argv_sha!=target['argv_sha']):fail('sidecar_postexec')
 if journal is not None:
  present=getattr(journal,role+'_ticket')
  if present is not None and present.key()!=typed_ticket.key():fail('sidecar_ticket')
 return tree,post if post is not None else pre
def proc_closed(reader):
 refs=getattr(reader,'_fd_refs',None);rows=[]
 if type(refs)is not list:return False,rows
 for fs,fd in refs:
  closed=False
  try:fs.fstat(fd)
  except OSError as error:closed=type(error.errno)is int and error.errno==errno.EBADF
  except BaseException:pass
  rows.append({'fd':fd,'fresh_ebadf':closed})
 okay=getattr(reader,'_pending',True)is False and getattr(reader,'_active',True)is False and getattr(reader,'_files',-1)==getattr(reader,'_closed',-2) and getattr(reader,'_open_attempt',None)is None and all(r['fresh_ebadf'] for r in rows)
 return okay,rows
owner=ReadOwner();facts={};private={'facts':facts,'errors':[],'actor_observations':[],'proc_inventory':[],'source_graph':PLAN['pins'],'definitions':PINS,'original_source_sha':ORIGINAL_SOURCE_SHA,'original_receipt_sha':ORIGINAL_RECEIPT_SHA};held=[];plans=[];reader_attempts=[];journal=None;deployment_python_sha=None;proc_pending=False;manifest_valid=False
def error_fact(label,error):
 state='ABSENT' if isinstance(error,OSError) and type(error.errno)is int and error.errno==errno.ENOENT else 'OPAQUE'
 facts[label]={'state':state,'error_kind':type(error).__name__}
 if state!='ABSENT':private['errors'].append({'label':label,'kind':type(error).__name__,'code':getattr(error,'code',None)})
def read_fact(parent,name,label,mode,limit,hold=False):
 if parent is None:facts[label]={'state':'NOT_EVALUATED'};return None
 try:
  raw,row=owner.file(parent,name,mode,limit,hold);facts[label]={'state':'PRESENT','size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'metadata':row['metadata']}
  if hold:held.append((label,row))
  return raw
 except BaseException as error:error_fact(label,error);return None
try:
 root=owner.open_dir(None,'/',None);alias=common.FixedTmpAnchor(owner,owner._io,root,owner.fd_of,owner.open_dir,owner.check);owner._tmp_alias=alias
 if alias.prepare()is not alias:fail('alias_result')
 tmp=owner.open_dir(alias.tmp_parent,'tmp',0o1777)
 if alias.bind_tmp(tmp)is not alias or alias.authenticate(owner,root)is not alias:fail('alias_result')
 facts['fixed_alias']={'state':'MATCH'}
 pending_raw=read_fact(tmp,'p011-mta-p2p-device.pending','global_pending',0o600,65536)
 if pending_raw is not None:private['global_pending_raw']=projection(pending_raw)
 run=None;runtime=None;native=None
 try:
  retained=owner.open_dir(tmp,'p011-mta-client-rfinit',0o700);run=owner.open_dir(retained,'client-'+PLAN['token'],0o700)
 except BaseException as error:error_fact('run_directory',error)
 for name in ('runtime','native'):
  try:
   value=None if run is None else owner.open_dir(run,name,0o700)
   if name=='runtime':runtime=value
   else:native=value
  except BaseException as error:error_fact(name+'_directory',error)
 candidate_raw=read_fact(run,'candidate.json','candidate_manifest',0o400,131072,True)
 deployment_raw=read_fact(run,'deployment.json','deployment_manifest',0o400,131072,True)
 try:
  if candidate_raw is None or candidate_raw!=base64.b64decode(PLAN['candidate_encoded'],validate=True):fail('candidate_mismatch')
  facts['candidate_manifest']['state']='MATCH'
  if deployment_raw is None:fail('deployment_missing')
  tree=codec.loads(deployment_raw.decode('utf-8'))
  if type(tree)is not dict or set(tree)!=set(('version','provider','sources')) or type(tree['version'])is not int or tree['version']!=1 or tree['sources']!=[list(x) for x in PLAN['pins']] or type(tree['provider'])is not dict or set(tree['provider'])!=set(PLAN['provider'])|set(('python_sha',)):fail('deployment_schema')
  deployment_python_sha=tree['provider']['python_sha']
  if type(deployment_python_sha)is not str or len(deployment_python_sha)!=64 or any(c not in '0123456789abcdef' for c in deployment_python_sha):fail('python_digest_shape')
  expected=codec.loads(codec.dumps(PLAN['provider'],sort_keys=True))
  if any(tree['provider'][k]!=v for k,v in expected.items()) or codec.dumps(tree,sort_keys=True).encode('utf-8')!=deployment_raw:fail('deployment_binding')
  facts['deployment_manifest']['state']='MATCH';private['deployment_manifest']=tree;manifest_valid=True
 except BaseException as error:error_fact('manifest_binding',error)
 for path,size,pin in PLAN['files']:
  group,name=path.split('/');data=read_fact(runtime if group=='runtime' else native,name,path,0o400 if group=='runtime' else 0o500,4194304)
  if data is not None:facts[path]['state']='MATCH' if len(data)==size and hashlib.sha256(data).hexdigest()==pin else 'MISMATCH'
 raw=read_fact(run,'journal.json','journal',0o600,131072)
 if raw is not None:
  try:
   record=journal_codec.decode_journal(raw)
   if not manifest_valid or record.identity.key()!=core.Identity(PLAN['candidate_sha']).key() or record.baseline.boot!=PLAN['boot'] or (record.owned is not None and record.owned.name!=PLAN['provider']['ifname']):fail('journal_binding')
   journal=record;facts['journal']['state']='PARSED_BOUND';private['journal']=journal_codec._document(record)
   for role in ('controller','watchdog'):
    actor=getattr(record,role);ticket=getattr(record,role+'_ticket')
    if actor is not None:
     expected=PLAN['provider']['wpa_exe'] if role=='controller' else PLAN['provider']['python_exe']
     if ticket is None or actor.exe!=expected or ticket.exe!=expected or actor.argv_sha!=ticket.argv_sha:fail('journal_actor_binding')
     plans.append((role+'_journal',actor,record.baseline.boot))
  except BaseException as error:error_fact('journal_parse',error)
 for role in ('watchdog','controller'):
  label='launch_'+role;raw=read_fact(run,'launch-'+role+'.json',label,0o600,65536)
  if raw is not None:
   try:
    if not manifest_valid:fail('sidecar_manifest')
    tree,actor=sidecar(raw,role);private[label]=tree;facts[label]['state']='PARSED_BOUND';plans.append((label,actor,tree['boot']))
   except BaseException as error:error_fact(label+'_parse',error)
 seen=[]
 actor_binding_valid=manifest_valid and all(facts.get(path,{}).get('state')=='MATCH' for path,size,pin in PLAN['files'])
 private['actor_binding_valid_at_read']=actor_binding_valid
 for label,actor,boot in (plans if actor_binding_valid else ()):
  key=(actor.key(),boot)
  if key in seen:continue
  seen.append(key)
  if len(seen)>4:fail('actor_budget')
  result={'label':label,'state':'OPAQUE','observations':[]};private['actor_observations'].append(result)
  for method in ('read_absence','read_actor'):
   reader=None
   try:
    owner.check();remaining=owner.end-time.monotonic()
    if remaining<0.1:fail('readonly_deadline')
    attempt={'reader':None,'unknown':True};reader_attempts.append(attempt)
    reader=proc.ProcReader(timeout=min(3.0,remaining))
    attempt['reader']=reader;attempt['unknown']=False
    observed=reader.read_absence(actor,boot) if method=='read_absence' else reader.read_actor(actor.pid,actor)
    closed,inventory=proc_closed(reader);proc_pending=proc_pending or not closed
    private['proc_inventory'].append({'method':method,'closed':closed,'original_fds':inventory,'files':getattr(reader,'_files',None),'closed_files':getattr(reader,'_closed',None)})
    result['observations'].append(projection(observed))
    if observed.resource_pending or not closed:break
    if method=='read_absence' and observed.passes==2 and observed.boot==boot and observed.kind=='absence' and observed.same_boot and observed.pid_path_absent and not observed.remaining_tasks:result['state']='KNOWN_ABSENT';break
    if method=='read_actor' and observed.passes==2 and observed.boot==boot and observed.kind=='live_actor' and type(observed.actor)is core.Actor and observed.actor.live() and observed.actor.key()==actor.key():result['state']='LIVE'
   except BaseException as error:
    result.setdefault('errors',[]).append({'method':method,'kind':type(error).__name__})
    closed=False
    if reader is not None:
     closed,inventory=proc_closed(reader);proc_pending=proc_pending or not closed;private['proc_inventory'].append({'method':method,'closed':closed,'original_fds':inventory})
    if method!='read_absence' or not isinstance(error,Exception) or reader is None or not closed:break
  result['read_complete']=result['state']!='OPAQUE' and bool(result['observations']) and all(o.get('kind')in('absence','live_actor') and o.get('passes')==2 and o.get('boot')==boot and o.get('same_boot')is True and o.get('resource_pending')is False for o in result['observations'])
  if not result['read_complete']:private['errors'].append({'label':label,'kind':'ActorObservation','code':'actor_observation_incomplete'})
  # No scan, wait/reap, numeric FD borrow, owner creation or recovery follows.
 for label,row in held:
  try:owner.verify_held(row);facts[label]['final_bytes_metadata_match']=True
  except BaseException as error:facts[label]['final_bytes_metadata_match']=False;error_fact(label+'_final',error);manifest_valid=False
 if alias.authenticate(owner,root)is not alias:fail('alias_final')
 facts['fixed_alias']['final_match']=True
except BaseException as error:error_fact('readonly_observation',error)
finally:
 closed=owner.close();private['original_inventory']=tuple({key:projection(row[key]) for key in ('label','kind','fd','generation','metadata','unknown','attempted','closed','no_fd')} for row in owner.rows);private['close_errors']=owner.errors
 private['reader_owner_count']=len(reader_attempts);private['reader_construction_unknown']=any(r['unknown'] for r in reader_attempts)
 proc_pending=proc_pending or private['reader_construction_unknown']
 public={'schema':'retained-stage-readonly-v12','stage':'observed','readonly_complete':not private['errors'] and closed and not proc_pending,'resource_pending':not closed or proc_pending,'fixed_alias_verified':facts.get('fixed_alias',{}).get('final_match')is True,'manifest_match':manifest_valid and all(facts.get(label,{}).get('final_bytes_metadata_match')is True for label in ('candidate_manifest','deployment_manifest')),'retained_files_match':all(facts.get(path,{}).get('state')=='MATCH' for path,size,pin in PLAN['files']),'journal_state':facts.get('journal',{}).get('state','NOT_EVALUATED'),'global_pending_state':facts.get('global_pending',{}).get('state','NOT_EVALUATED'),'recorded_actor_count':len(private['actor_observations']),'recorded_actors_known_absent':bool(private['actor_observations']) and all(r['state']=='KNOWN_ABSENT' for r in private['actor_observations']),'get_interface_status':'NOT_EVALUATED','restoration_verified':False,'rf_requested':False,'staging_attempted':False,'send_available':False,'receive_available':False,'phone_tested':False}
print('RESULT='+repr({'public':public,'private':private}))
'''


def literal_lines(value):
    # repr(plan) can exceed the target line limit. JSON is data, not evaluated code.
    raw = json.dumps(value, sort_keys=True).encode('utf-8')
    encoded = base64.b64encode(raw).decode('ascii')
    return "modules['p011_json'].loads(base64.b64decode(\n" + '\n'.join(repr(encoded[i:i+1000]) for i in range(0, len(encoded), 1000)) + ").decode('utf-8'))"


def build_source(plan, definitions, loader):
    lines = ['PINS=(\n' + '\n'.join(repr((n, p)) + ',' for n, p, e in definitions) + '\n)', 'ENCODED=(']
    for name, pin, encoded in definitions:
        lines.append('(' + repr(name) + ',' + repr(pin) + ',(')
        lines.extend(repr(encoded[i:i+1000]) for i in range(0, len(encoded), 1000))
        lines.append(')),')
    lines.extend((')', loader, 'PLAN=' + literal_lines(plan),
        'ORIGINAL_SOURCE_SHA=' + repr(SOURCE_SHA), 'ORIGINAL_RECEIPT_SHA=' + repr(RECEIPT_SHA), TARGET))
    source = '\n'.join(lines)
    tree = ast.parse(source, feature_version=(3, 5))
    if len(source.encode('utf-8')) > MAX_SOURCE or max(len(x.encode('utf-8')) for x in source.splitlines()) > 2048 or any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        raise ValueError('target_source_budget')
    return source


def source_check():
    plan, definitions = reference(); loader, transport = infrastructure()
    source = build_source(plan, definitions, loader)
    return {'kind': 'retained-stage-readonly-v12', 'source_only': True, 'source_check_pass': True,
        'driver_sha256': digest(Path(__file__).read_bytes()), 'definition_count': 6,
        'inspected_source_count': 20, 'inspected_file_count': 21,
        'historical_source_sha256': SOURCE_SHA, 'historical_receipt_sha256': RECEIPT_SHA,
        'candidate_sha256': CANDIDATE_SHA, 'get_interface_status': 'NOT_EVALUATED',
        'restoration_verified': False, 'rf_requested': False, 'staging_attempted': False}, source, transport


def validate_public(value):
    keys = {'schema', 'stage', 'readonly_complete', 'resource_pending', 'fixed_alias_verified',
        'manifest_match', 'retained_files_match', 'journal_state', 'global_pending_state',
        'recorded_actor_count', 'recorded_actors_known_absent', 'get_interface_status',
        'restoration_verified', 'rf_requested', 'staging_attempted', 'send_available',
        'receive_available', 'phone_tested'}
    if set(value) != keys or value['schema'] != 'retained-stage-readonly-v12' or value['stage'] != 'observed' or \
            value['get_interface_status'] != 'NOT_EVALUATED' or type(value['recorded_actor_count']) is not int or \
            not 0 <= value['recorded_actor_count'] <= 4: raise ValueError('public_schema')
    for key in keys - {'schema', 'stage', 'journal_state', 'global_pending_state', 'recorded_actor_count', 'get_interface_status'}:
        if type(value[key]) is not bool: raise ValueError('public_boolean')
    if any(value[k] for k in ('restoration_verified', 'rf_requested', 'staging_attempted',
            'send_available', 'receive_available', 'phone_tested')): raise ValueError('public_authority')
    if value['journal_state'] not in ('PRESENT', 'PARSED_BOUND', 'ABSENT', 'OPAQUE', 'NOT_EVALUATED') or \
            value['global_pending_state'] not in ('PRESENT', 'ABSENT', 'OPAQUE', 'NOT_EVALUATED'):
        raise ValueError('public_status')
    return value


def execute(expected, _check=None, _transport=None, _helper=None, _directory=None):
    checks, source, transport_type = (_check or source_check)()
    if checks['source_check_pass'] is not True or expected != checks['driver_sha256'] or _ATTEMPTS:
        raise ValueError('unreviewed_or_once')
    _ATTEMPTS.append(expected)
    directory = Path(_directory) if _directory else BASE.parents[1] / 'logs' / ('MtaP011-ClientRetainedStageV12-' + time.strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex())
    directory.mkdir(parents=True, exist_ok=False); rawdir = directory / 'private-raw'; rawdir.mkdir()
    (rawdir / 'target-source.py').write_bytes(source.encode('utf-8'))
    helper = _helper
    if helper is None:
        path = BASE / 'host/device_probe.py'; code = read_pinned(path, PROBE_SHA)
        spec = importlib.util.spec_from_file_location('retained_readonly_fixed_probe', str(path)); helper = importlib.util.module_from_spec(spec)
        exec(compile(code, str(path), 'exec'), helper.__dict__)
    call = (_transport or transport_type)(helper, rawdir)
    try:
        call.select(); raw, echo = call.run(source)
        (rawdir / 'stdout.raw').write_bytes(raw['stdout']); (rawdir / 'stderr.raw').write_bytes(raw['stderr'])
        (rawdir / 'host-exit').write_text(str(raw['host_exit']), encoding='ascii')
        receipt = strict_receipt(raw, echo); public = dict(validate_public(receipt['public']))
        (rawdir / 'remote-exit').write_text('0', encoding='ascii')
        public.update({'target_selected': True, 'remote_reply_confirmed': True})
        result = {'source': checks, 'public': public}
        (directory / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        (directory / 'README.txt').write_text('Readonly retained-stage observations only. No recovery, RF, cleanup, fsync receipt or interface-state verification. Private raw is excluded.\n', encoding='utf-8')
        with zipfile.ZipFile(directory / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
            for name in ('result.json', 'README.txt'): archive.write(directory / name, name)
        return result, directory
    except BaseException:
        for name, key in (('stdout.raw', 'stdout'), ('stderr.raw', 'stderr')):
            value = call.raw.get(key)
            if type(value) is bytes: (rawdir / name).write_bytes(value)
        (rawdir / 'host-exit').write_text(str(call.raw.get('host_exit', 'UNKNOWN')), encoding='ascii')
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    args = parser.parse_args(argv)
    if args.execute_reviewed != bool(args.expected_driver_sha256): parser.error('explicit reviewed SHA pair required')
    if not args.execute_reviewed:
        print(json.dumps(source_check()[0], ensure_ascii=False, indent=2)); return 0
    result, directory = execute(args.expected_driver_sha256)
    print(json.dumps({'result': result, 'log_directory': str(directory)}, ensure_ascii=False, indent=2)); return 0 if not result['public']['resource_pending'] else 1


if __name__ == '__main__': sys.exit(main())
