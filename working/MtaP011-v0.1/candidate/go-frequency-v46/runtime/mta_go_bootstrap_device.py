"""One explicit actual P011 GO17 v46 frequency-source trial.

SOURCE-only v46: pinned Native observes station frequency from associated BSS.
Sixteen GO source identities and all Store/restore mechanics are unchanged.
The retained F diagnostics stay private, not an inventory or readiness claim.
Strict Snapshot decode/key compares stable live identities.
Raw R/S task states are retained, not mistaken for a stable identity change.
A reviewed exact HOST driver and explicit transport are needed.
Old readonly35 is solely this parent domain; exact GO17 is exec'ed separately.
No CLIENT scratch/PersistReceipt or fabricated GO parent device lease exists.
Original GO F creates its actual Store/OFD/marker/CAS and bound child sources.
This adapter stages only a new EXCL token, exact cfg, live Python identity and
supervises its one actual direct fork/argv, raw streams, journal and baseline.
Raw FD3 rows/internal native inventories are not emitted by fixed GO17 and
remain unverified. IP/DHCP/data/phone/production admission are all out of scope.
Outer180, once active45, existing native cleanup60, post-read30 are distinct.
There is no timeout kill, signal, retry, cleanup of old files or cap renewal.
"""
import errno
import hashlib
import math
import os
import re
import select
import stat
import struct
import threading
import time

import p011_json as json_codec
import mta_client_executor as executor
import mta_client_tmp_alias as tmp_alias
import mta_client_readonly_baseline as readonly
import mta_client_proc as proc
import mta_client_store as stores
import mta_p2p_client_init as core
import mta_client_journal_codec as parent_codec

SOURCE_MANIFEST_SHA = '090392942b3472e45b1eb5f3ccf8b06a236b273255ce510fe52efc0fd20bcc7e'
READONLY_MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
READONLY_LEAF_SHA = 'cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff'
STAGE_SECONDS = 180.0
GO_ACTIVE_SECONDS = 45.0
CLEANUP_SECONDS = 60.0
POST_READ_SECONDS = 30.0
GO_ROOT_NAME = 'p011-mta-go-session'
GO_ROOT = '/var/volatile/tmp/' + GO_ROOT_NAME
PYTHON = '/usr/bin/python3.5'
MAX_ROOT_ENTRIES = 4096
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
SOURCE_PINS = (
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_p2p_client_init', 69966, '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    ('mta_client_resource_budget', 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e'),
    ('mta_client_proc', 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_client_journal_codec', 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_client_coordination', 35591, '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f'),
    ('mta_client_files', 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864'),
    ('mta_client_pending', 42432, 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af'),
    ('mta_client_store', 71524, 'f328dcaa95ecfc5288c85a3715ecfdbdbdb8e83c83797b91cde3e334d188f4a2'),
    ('mta_go_process_owner', 42612, '78a480728a348e98e578acf4e7c778be50bfae3411ba5d34bb563493e1ba6583'),
    ('mta_go_deployment', 24306, '2922f16f8ca3d2e654b018ebf47a099e41680a4af2a6d6965a304a100c96f270'),
    ('mta_go_executor', 16874, '377bc1bf9376885213412805a121cc2774998992f532c257a536de9f9186b711'),
    ('mta_go_bootstrap_store', 65815, '7e10b8bba161b1d4035fffeb5e1d92eb3a6ad797111e60ab24b9d04d6130c228'),
    ('mta_go_native', 87772, '78e08414233e06f4100ebc318bb4d0d1996bd072caa77b2018a7035ec21b579a'),
    ('mta_go_bootstrap', 16859, '0b2960491717f0100882f5dac25df66669a53651adf813c0617726455b4471e7'),
)
PINS = tuple((name,pin) for name,size,pin in SOURCE_PINS)


class GoBootstrapDeviceError(ValueError):
    pass


def fail(code):
    raise GoBootstrapDeviceError(code) from None


def _same_tree(left,right):
    if type(left) is not type(right):return False
    if type(left) is dict:
        return set(left)==set(right) and all(_same_tree(left[key],right[key]) for key in left)
    if type(left) is list:
        return len(left)==len(right) and all(_same_tree(a,b) for a,b in zip(left,right))
    return left==right


def deployment_document(token, python_sha):
    if type(token) is not str or re.fullmatch('[0-9a-f]{32}',token) is None or type(python_sha) is not str or re.fullmatch('[0-9a-f]{64}',python_sha) is None:fail('stage_shape')
    return {'schema':'p011-go-bootstrap-v33','go':{
        'version':1,'run_token':token,'candidate_sha':SOURCE_MANIFEST_SHA,
        'task_id':'bootstrap-'+token,'ifname':'mta'+token[:8],'python_sha':python_sha,
        'sources':[[name,pin] for name,size,pin in SOURCE_PINS],
        'baseline_manifest':[[path,pin] for path,pin in readonly.BASELINE_MANIFEST]}}


class StageIo(object):
 def stat_root(self):return os.stat('/',follow_symlinks=False)
 def stat_at(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
 def fstat(self,fd):return os.fstat(fd)
 def readlink_at(self,fd,name):return os.readlink(name,dir_fd=fd)
class GoAppendOwner(object):
 def __init__(self,task):
  if type(task) is not GoBootstrapTask or task.phase!='write' or task.writer is not None:fail('stage_owner')
  self._task=task;self.clock=task._writer_clock;deadline=task.until
  if not callable(self.clock) or type(deadline) not in (int,float) or not math.isfinite(float(deadline)):fail('stage_budget')
  now=self.clock()
  if type(now) not in (int,float) or not math.isfinite(float(now)) or not 0<deadline-now<=180:fail('stage_budget')
  self.deadline=float(deadline);self.worker=threading.current_thread();self.pid=os.getpid();self.last=None;self.writes=[]
  self._io=StageIo();self._tmp_alias=None;self.rows=[];self.mutations=[]
  self.root=None;self.tmp=None;self.private_root=None;self.run=None;self.runtime=None;self.native=None;self.ctrl=None
  self.pending=True;self.close_attempted=False;self.python_rows=[];self.private_root_created=False
  self.entries_before=None;self.entries_after=None;self.run_name='go-'+task.token;self.stage_attempted=False
 def check(self):
  task=self._task
  if type(task) is not GoBootstrapTask or task.writer is not self or self.clock is not task._writer_clock or self.deadline is not task.until:fail('stage_owner')
  task._writer_gate(self)
  now=self.clock()
  if threading.current_thread() is not self.worker or os.getpid()!=self.pid or type(now) not in (int,float) or not 0<=now<1e12 or not math.isfinite(float(now)) or self.last is not None and now<self.last:fail('stage_budget')
  self.last=float(now)
  if now>=self.deadline:fail('stage_budget')
 def identity(self,value,mode=None):
  meta=executor._meta(value)
  if not stat.S_ISDIR(meta[2]) or meta[3:5]!=(0,0) or meta[5]<1:fail('stage_unknown')
  if mode is None:
   if stat.S_IMODE(meta[2])&0o022:fail('stage_unknown')
  elif stat.S_IMODE(meta[2])!=mode:fail('stage_unknown')
  return meta[:5]
 def fd_of(self,row):
  self.check()
  if not any(row is item for item in self.rows) or row['unknown'] or row['attempted'] or row['closed'] or type(row['fd']) is not int or row['fd']<0:fail('stage_unknown')
  if row['kind']!='directory' or self.identity(self._io.fstat(row['fd']),row['mode'])!=row['identity']:fail('stage_unknown')
  parent=row['parent']
  if parent is None:
   if self.identity(self._io.stat_root(),row['mode'])!=row['identity']:fail('stage_unknown')
  elif self.identity(self._io.stat_at(self.fd_of(parent),row['name']),row['mode'])!=row['identity']:fail('stage_unknown')
  return row['fd']
 def open_dir(self,parent,name,mode=None):
  self.check()
  row={'kind':'directory','parent':parent,'name':name,'fd':None,'metadata':None,'identity':None,'mode':mode,'unknown':True,'attempted':False,'closed':False}
  self.rows.append(row)
  parent_fd=None if parent is None else self.fd_of(parent)
  before=self.identity(self._io.stat_root() if parent is None else self._io.stat_at(parent_fd,name),mode)
  flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
  row['fd']=os.open('/',flags) if parent is None else os.open(name,flags,dir_fd=parent_fd)
  if type(row['fd']) is not int or row['fd']<0 or any(item is not row and item['fd']==row['fd'] and not item['closed'] for item in self.rows):fail('stage_unknown')
  row['metadata']=executor._meta(self._io.fstat(row['fd']));row['identity']=self.identity(self._io.fstat(row['fd']),mode);row['unknown']=False
  after=self.identity(self._io.stat_root() if parent is None else self._io.stat_at(parent_fd,name),mode)
  if before!=row['identity'] or after!=row['identity']:fail('stage_unknown')
  return row
 def open_prefix(self,parent,name):
  if parent is self.root and name=='var':return self.open_dir(parent,name,0o755)
  if self._tmp_alias is not None and any(parent is item for item in self._tmp_alias.prefix_tickets) and name=='volatile':return self.open_dir(parent,name,0o1777)
  fail('stage_unknown')
 def authenticate(self):
  if self._tmp_alias is None or self._tmp_alias.authenticate(self,self.root) is not self._tmp_alias:fail('stage_unknown')
  parent=self.fd_of(self.tmp);self.check()
  try:self._io.stat_at(parent,'p011-mta-p2p-device.pending')
  except OSError as error:
   self.check()
   if type(error.errno) is int and error.errno==errno.ENOENT:return
   raise
  fail('pending_exists')
 def prepare(self):
  self.root=self.open_dir(None,'/')
  self._tmp_alias=tmp_alias.FixedTmpAnchor(self,self._io,self.root,self.fd_of,self.open_prefix,self.check)
  if self._tmp_alias.prepare() is not self._tmp_alias:fail('stage_unknown')
  self.tmp=self.open_dir(self._tmp_alias.tmp_parent,'tmp',0o1777)
  if self._tmp_alias.bind_tmp(self.tmp) is not self._tmp_alias:fail('stage_unknown')
  self.authenticate()
 def directory(self,parent,name):
  if self._task.phase!='write' or not (
   parent is self.private_root and name==self.run_name or parent is self.run and name in ('runtime','native','ctrl')):fail('stage_owner')
  self.authenticate();parent_fd=self.fd_of(parent)
  op={'kind':'mkdir','name':name,'parent_fd':parent_fd,'attempted':True,'returned':False};self.mutations.append(op)
  self.check();os.mkdir(name,0o700,dir_fd=parent_fd);op['returned']=True;self.check()
  return self.open_dir(parent,name,0o700)
 def empty(self,row):
  self.authenticate()
  if os.listdir(self.fd_of(row)):fail('stage_exists')
 def entry_metadata(self,value):
  meta=executor._meta(value);times=tuple(getattr(value,key,None) for key in ('st_mtime_ns','st_ctime_ns'))
  if any(type(item) is not int or not -(1<<63)<=item<(1<<63) for item in times):fail('stage_unknown')
  return meta+times
 def root_entries(self):
  self.authenticate();parent=self.fd_of(self.private_root);names=os.listdir(parent)
  if type(names) is not list or len(names)>MAX_ROOT_ENTRIES or any(type(name) is not str or not name or name in ('.','..') or '/' in name or '\x00' in name for name in names) or len(set(names))!=len(names):fail('stage_entries')
  rows=[]
  for name in sorted(names):
   self.check();before=self.entry_metadata(self._io.stat_at(parent,name));self.fd_of(self.private_root)
   self.check();after=self.entry_metadata(self._io.stat_at(parent,name))
   if before!=after:fail('stage_changed')
   rows.append((name,before))
  self.check()
  if sorted(os.listdir(self.fd_of(self.private_root)))!=sorted(names):fail('stage_changed')
  return tuple(rows)
 def retained_entries(self):
  if type(self.entries_before) is not tuple:fail('stage_entries')
  actual=self.root_entries();original=dict(self.entries_before);current=dict(actual)
  if set(current)!=set(original)|{self.run_name} or any(current[name]!=meta for name,meta in self.entries_before):fail('stage_changed')
  if self.run is None or self.identity(self._io.stat_at(self.fd_of(self.private_root),self.run_name),0o700)!=self.run['identity']:fail('stage_changed')
  self.entries_after=actual
 def verify_static(self,completed=False):
  self.retained_entries()
  names=('runtime','native','ctrl','deployment.json','go.conf')
  if completed:names+=('go-journal.lock','go-journal.json')
  self.layout(self.run,names)
  self.layout(self.runtime,tuple(name+'.py' for name,pin in PINS));self.layout(self.native,('mta-wpa-supplicant',));self.empty(self.ctrl)
  for row in self.writes:
   self.authenticate()
   if row['closed'] is not True or row['unknown'] is not False or row.get('sealed_entry')!=self.entry_metadata(self._io.stat_at(self.fd_of(row['parent']),row['name'])):fail('stage_changed')
 def close_row(self,row):
  task=self._task
  if type(self) is not GoAppendOwner or type(task) is not GoBootstrapTask or task.writer is not self or task.writer_constructor_returned is not True or self.clock is not task._writer_clock or self.deadline is not task.until or task.until is not task._original_until or self.worker is not task.worker or self.pid!=task.pid or threading.current_thread() is not self.worker or os.getpid()!=self.pid or not any(row is item for item in self.rows):return False
  if row['attempted']:return row['closed']
  if row['unknown'] or type(row['fd']) is not int:return False
  row['attempted']=True
  try:
   actual=self._io.fstat(row['fd'])
   if row['kind']=='directory':
    if self.identity(actual,row['mode'])!=row['identity']:fail('stage_unknown')
   elif row['kind']=='python':
    if self.entry_metadata(actual)!=row['metadata']:fail('stage_unknown')
   elif row['kind']=='file':
    # Close-only: a partial write or attempted chmod can legitimately change
    # size/mode despite publication failure. Neither changes the original FD.
    meta=executor._meta(actual)
    identity=meta[:2]+(stat.S_IFMT(meta[2]),)+meta[3:6]
    if identity!=row['close_identity'] or row['mode']!=row['close_mode'] or row['close_mode'] not in (0o400,0o500) or not (
     stat.S_IMODE(meta[2])==0o600 or row['chmod_attempted'] is True and stat.S_IMODE(meta[2])==row['close_mode']):fail('stage_unknown')
    row['close_observed']=meta
   else:fail('stage_unknown')
   returned=os.close(row['fd'])
   try:self._io.fstat(row['fd'])
   except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
   if not row['closed']:row['unknown']=True
  except BaseException:row['unknown']=True
  return row['closed']
 def publish(self,parent,name,raw,mode):
  if self._task.phase!='write' or not (parent is self.runtime and name in tuple(item+'.py' for item,pin in PINS) and mode==0o400 or parent is self.native and name=='mta-wpa-supplicant' and mode==0o500 or parent is self.run and name in ('deployment.json','go.conf') and mode==0o400):fail('stage_owner')
  self.authenticate();parent_fd=self.fd_of(parent)
  row={'kind':'file','parent':parent,'name':name,'fd':None,'metadata':None,'identity':None,'mode':mode,'unknown':True,'attempted':False,'closed':False,
   'close_identity':None,'close_mode':mode,'close_observed':None,'chmod_attempted':False,'chmod_returned':False}
  self.rows.append(row);self.writes.append(row)
  try:
   self.check()
   row['fd']=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent_fd)
   if type(row['fd']) is not int or row['fd']<0 or any(item is not row and item['fd']==row['fd'] and not item['closed'] for item in self.rows):fail('stage_unknown')
   row['metadata']=executor._meta(self._io.fstat(row['fd']))
   if not stat.S_ISREG(row['metadata'][2]) or row['metadata'][3:6]!=(0,0,1) or stat.S_IMODE(row['metadata'][2])!=0o600:fail('stage_unknown')
   row['identity']=row['metadata'][:6];row['close_identity']=row['metadata'][:2]+(stat.S_IFMT(row['metadata'][2]),)+row['metadata'][3:6]
   row['unknown']=False;self.check();position=0
   while position<len(raw):
    self.authenticate();self.fd_of(parent);self.check()
    count=os.write(row['fd'],raw[position:position+65536])
    self.check()
    if type(count) is not int or not 1<=count<=min(65536,len(raw)-position):fail('stage_unknown')
    position+=count;actual=executor._meta(self._io.fstat(row['fd']))
    self.check()
    if actual[:6]!=row['identity'] or actual[6]!=position:fail('stage_unknown')
    row['metadata']=actual
   self.check();os.fsync(row['fd']);self.check()
   self.check();os.lseek(row['fd'],0,0);self.check();parts=[];size=0
   while size<=len(raw):
    self.check();part=os.read(row['fd'],min(65536,len(raw)+1-size))
    self.check()
    if type(part) is not bytes:fail('stage_unknown')
    parts.append(part);size+=len(part)
    if not part:break
   if b''.join(parts)!=raw or executor._meta(self._io.fstat(row['fd']))!=row['metadata']:fail('stage_unknown')
   self.check();row['chmod_attempted']=True
   os.fchmod(row['fd'],mode);row['chmod_returned']=True;self.check()
   self.check();os.fsync(row['fd']);self.check()
   actual=executor._meta(self._io.fstat(row['fd']));self.check()
   expected=row['identity'][:2]+(stat.S_IFREG|mode,)+row['identity'][3:]+(len(raw),)
   if actual!=expected:fail('stage_unknown')
   row['metadata']=actual
   self.authenticate()
   if row['metadata']!=executor._meta(self._io.stat_at(self.fd_of(parent),name)) or stat.S_IMODE(row['metadata'][2])!=mode:fail('stage_unknown')
   row['sealed_entry']=self.entry_metadata(self._io.fstat(row['fd']));row['content_sha256']=hashlib.sha256(raw).hexdigest()
   if self.entry_metadata(self._io.stat_at(self.fd_of(parent),name))!=row['sealed_entry']:fail('stage_changed')
  finally:
   if not self.close_row(row):self.pending=True
  if not row['closed']:fail('stage_unknown')
 def layout(self,row,names):
  self.authenticate()
  if sorted(os.listdir(self.fd_of(row)))!=sorted(names):fail('stage_unknown')
 def read_python(self,keep_open=False):
  self.authenticate();self.check()
  for path in ('/usr','/usr/bin'):
   meta=executor._meta(os.stat(path,follow_symlinks=False))
   if not stat.S_ISDIR(meta[2]) or meta[3:5]!=(0,0) or meta[2]&0o022:fail('python_anchor')
  before=self.entry_metadata(os.stat(PYTHON,follow_symlinks=False))
  if not stat.S_ISREG(before[2]) or before[3:5]!=(0,0) or before[5] not in (1,2) or before[2]&0o022 or not before[2]&0o111 or not 52<=before[6]<=67108864:fail('python_image')
  row={'kind':'python','name':PYTHON,'parent':None,'fd':None,'metadata':None,'mode':None,'unknown':True,'attempted':False,'closed':False}
  self.rows.append(row);self.python_rows.append(row)
  try:
   self.check();row['fd']=os.open(PYTHON,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   row['metadata']=self.entry_metadata(os.fstat(row['fd']))
   if type(row['fd']) is not int or row['fd']<3 or row['metadata']!=before:fail('python_image')
   row['unknown']=False;digest=hashlib.sha256();head=b'';total=0
   while True:
    self.check();part=os.read(row['fd'],min(65536,before[6]+1-total));self.check()
    if type(part) is not bytes:fail('python_image')
    total+=len(part);head=(head+part)[:52];digest.update(part)
    if total>before[6]:fail('python_image')
    if not part:break
   if total!=before[6] or self.entry_metadata(os.fstat(row['fd']))!=before or self.entry_metadata(os.stat(PYTHON,follow_symlinks=False))!=before:fail('python_image')
   if head[:7]!=b'\x7fELF\x01\x01\x01' or struct.unpack_from('<H',head,16)[0] not in (2,3) or struct.unpack_from('<H',head,18)[0]!=40 or struct.unpack_from('<I',head,20)[0]!=1 or struct.unpack_from('<H',head,40)[0]!=52 or struct.unpack_from('<I',head,36)[0]&0xff000600!=0x05000400:fail('python_image')
   row['sha256']=digest.hexdigest();self.check()
   return row if keep_open else row['sha256']
  finally:
   if not keep_open and not self.close_row(row):self.pending=True
 def stage(self,token,payloads,wpa):
  if self.stage_attempted or token!=self._task.token or self._task.phase!='write':fail('stage_owner')
  self.stage_attempted=True
  if type(payloads) is not dict or set(payloads)!=set(name for name,size,pin in SOURCE_PINS):fail('stage_shape')
  for name,size,pin in SOURCE_PINS:
   if type(payloads[name]) is not bytes or len(payloads[name])!=size or hashlib.sha256(payloads[name]).hexdigest()!=pin:fail('stage_shape')
  if type(wpa) is not bytes or len(wpa)!=WPA_BYTES or hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_shape')
  self.prepare();parent=self.fd_of(self.tmp);self.check()
  try:self._io.stat_at(parent,GO_ROOT_NAME)
  except OSError as error:
   self.check()
   if type(error.errno) is not int or error.errno!=errno.ENOENT:raise
   op={'kind':'mkdir','name':GO_ROOT_NAME,'parent_fd':parent,'attempted':True,'returned':False};self.mutations.append(op)
   self.check();os.mkdir(GO_ROOT_NAME,0o700,dir_fd=parent);op['returned']=True;self.private_root_created=True;self.check()
  self.private_root=self.open_dir(self.tmp,GO_ROOT_NAME,0o700)
  self.entries_before=self.root_entries()
  if len(self.entries_before)>=MAX_ROOT_ENTRIES or self.run_name in dict(self.entries_before):fail('stage_exists')
  self._task._before_original(True);self.authenticate()
  self.run=self.directory(self.private_root,self.run_name)
  self.runtime=self.directory(self.run,'runtime');self.native=self.directory(self.run,'native');self.ctrl=self.directory(self.run,'ctrl')
  python_sha=self.read_python()
  document=deployment_document(token,python_sha);raw=json_codec.dumps(document,sort_keys=True).encode('ascii')
  self._task.python_sha=python_sha;self._task.deployment_raw=raw;self._task.deployment_sha=hashlib.sha256(raw).hexdigest()
  for name,size,pin in SOURCE_PINS:self.publish(self.runtime,name+'.py',payloads[name],0o400)
  self.publish(self.native,'mta-wpa-supplicant',wpa,0o500)
  self.publish(self.run,'deployment.json',raw,0o400)
  cfg=(b'ctrl_interface='+self.run_path().encode('ascii')+b'/ctrl\n'+
   b'p2p_no_group_iface=1\nap_scan=2\ndevice_name=P011\ndevice_type=1-0050F204-1\n'+
   b'driver_param=mta_p2p_initial=1 control_port=0\n')
  self.publish(self.run,'go.conf',cfg,0o400)
  self.verify_static()
  for row in (self.runtime,self.native,self.ctrl,self.run,self.private_root,self.tmp):
   self.authenticate();fd=self.fd_of(row);self.check();os.fsync(fd);self.check();self.fd_of(row)
 def run_path(self):return GO_ROOT+'/go-'+self._task.token
 def close(self):
  if self.close_attempted:return not self.pending
  self.close_attempted=True
  good=True
  for row in reversed(self.rows):good=self.close_row(row) and good
  self.pending=not good
  return good
 def inventory(self):
  return tuple({key:row.get(key) for key in ('kind','name','fd','metadata','identity','mode','unknown','attempted','closed','close_identity','close_mode','close_observed','chmod_attempted','chmod_returned')} for row in self.rows)


class GoBootstrapTask(object):
    """Original same-worker180s parent, no parent GO grant or native substitute."""
    def __init__(self,run_token,original_until):
        if type(run_token) is not str or re.fullmatch('[0-9a-f]{32}',run_token) is None or type(original_until) not in (int,float) or not math.isfinite(float(original_until)):fail('stage_task')
        self.token=run_token;self.clock=time.monotonic;self.worker=threading.current_thread();self.pid=os.getpid()
        self.until=self._original_until=float(original_until);self.last=None;self.issued_at=self.now()
        if not 0<self.until-self.issued_at<=STAGE_SECONDS:fail('stage_budget')
        self._writer_clock=self.now;self.phase='new';self.readonly_rows=[]
        self.writer=None;self.writer_constructor_attempted=self.writer_constructor_returned=self.writer_closed=False
        self.attempted=self.ended=self.success=False;self.error=None;self.cleanup_errors=[]
        self.deployment_raw=self.deployment_sha=self.python_sha=None;self.before=self.after=None
        self.process_store=self.process_reader=None;self._process_original=None;self.process_observations=[]
        self.fd_rows=[];self.pipe_rows=[];self.raw_stdout=[];self.raw_stderr=[];self.raw_exec=[];self.wait_rows=[];self.stream_failure=None
        self.go_until=self.go_until_text=self.argv=self.argv_sha=None
        self.child_pid=None;self.child_actor=None;self.child_boot=None;self.parent_actor=None
        self.fork_requested=self.fork_returned=self.fork_negative=False
        self._fork_original=self._fork_registered=None;self.child_waited=self.child_absent=False
        self.child_status=self.child_exit=None;self.python_exec_row=None;self.journal_rows=[];self.journal=None
        self.journal_reconciled=self.baseline_restored=False
    def now(self):
        value=self.clock()
        if self.clock is not time.monotonic or self.until is not self._original_until or threading.current_thread() is not self.worker or os.getpid()!=self.pid or type(value) not in (int,float) or not math.isfinite(float(value)) or not 0<=value<1e12 or self.last is not None and value<self.last:fail('stage_task')
        self.last=float(value)
        if value>=self.until:fail('stage_budget')
        return float(value)
    def _active_now(self):
        now=self.now()
        if type(self.go_until) is not float or type(self.go_until_text) is not str or repr(self.go_until)!=self.go_until_text or now>=self.go_until:fail('go_original_until')
        return now
    def _writer_gate(self,writer):
        self.now()
        if type(writer) is not GoAppendOwner or writer is not self.writer or writer._task is not self or not self.writer_constructor_returned or self.phase not in ('write','launch','bootstrap','after_read','final_readback'):fail('stage_owner')
        if self.before is None or not self.before['returned'] or self.before['owner'].result is not self.before['value']:fail('stage_before')
        if self.phase=='launch':self._active_now()
    def _read_phase(self,phase):
        self.now();self.phase=phase;end=min(self.until,self.now()+readonly.MAX_SECONDS)
        row={'phase':phase,'until':end,'owner':None,'value':None,'constructor_attempted':True,'constructor_returned':False,'returned':False}
        self.readonly_rows.append(row)
        owner=readonly.ReadonlyBaselineOwner(self.token,end,_clock=self.clock);row['owner']=owner;row['constructor_returned']=True
        value=owner.collect();row['value']=value;row['returned']=True;self._original_read(row)
        return row
    def _original_read(self,row,fresh=False):
        self.now()
        if not any(row is item for item in self.readonly_rows) or row['constructor_returned'] is not True or row['returned'] is not True:fail('stage_read')
        owner=row['owner'];value=row['value']
        if type(owner) is not readonly.ReadonlyBaselineOwner or owner.worker is not self.worker or owner.pid!=self.pid or owner.token!=self.token or owner._clock is not self.clock or owner.until is not owner._original_until or owner.until!=row['until'] or owner.until>self.until or owner.identity.candidate_sha!=READONLY_MANIFEST_SHA or readonly.SOURCE_MANIFEST_SHA!=READONLY_MANIFEST_SHA or owner.result is not value or owner.error is not None or owner.attempted is not True or owner.ended is not True or owner.read_success is not True or owner.resource_pending is not False or owner.pending_before is not True or owner.pending_after is not True or owner._closed() is not True:fail('stage_read')
        if fresh:owner.now()
        return value
    def _before_original(self,fresh=False):
        if self.before is None or self.before is not self.readonly_rows[0] or self.before['phase']!='before_read':fail('stage_before')
        return self._original_read(self.before,fresh)
    def _process_neutral(self):
        self.now();store,reader,budget,mutex,epoch,clock,identity=self._process_original
        if (self.process_store is not store or self.process_reader is not reader or type(store) is not stores.DurableClientInitStore or type(reader) is not proc.ProcReader or
            store._identity is not identity or store._clock is not clock or reader._clock is not clock or store._mutex is not mutex or store._epoch is not epoch or
            store._resource_budget_v23 is not budget or budget._store is not store or budget._mutex is not mutex or budget._epoch is not epoch or budget._provider is not None or
            store._proc_reader is not reader or store._proc_reader_original_v24 is not reader or reader._bound_budget_v24 is not budget or reader._resource_budget_v24 is not budget or len(budget._readers)!=1 or budget._readers[0] is not reader or
            store._session_profile is not core.TRIAL_SESSION_PROFILE or store._session_profile_original_v28 is not core.TRIAL_SESSION_PROFILE or
            store._attempted or store._opened or store._unknown or store._current_locks is not None or store._canonical is not None or store._marker is not None or store._binding is not None or store._session_issued_v28 is not None or
            store._records or store._locksets or store._coordination._attempted or store._coordination._inventory or store._coordination._locks is not None or store._files._opened or store._files._inventory or store._files._publication_attempted):fail('process_accounting_changed')
        budget._context();return store
    def _process_slice(self,active=False):
        store=self._process_neutral();now=self._active_now() if active else self.now()
        store._io_deadline=min(self.go_until if active else self.until,now+3.0)
        return store._io_deadline
    def _observation(self,value):
        self.process_observations.append(value)
        if type(value) is not proc.ProcObservation or value.kind!='live_actor' or type(value.actor) is not core.Actor or not value.actor.live() or value.same_boot is not True or value.passes!=2 or value.resource_pending is not False or value.file_count!=value.closed_count or len(value.actor.tasks)!=1:fail('process_observation')
        return value.actor
    def _fd_meta(self,fd):
        value=os.fstat(fd);keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_rdev')
        row=tuple(getattr(value,key,None) for key in keys)
        if any(type(v) is not int or v<0 for v in row) or not stat.S_ISFIFO(row[2]) or row[3:5]!=(0,0):fail('pipe_identity')
        return row
    def _pipe(self,role):
        self._active_now()
        pair={'role':role,'called':False,'returned':False,'fds':None,'rows':[]};self.pipe_rows.append(pair)
        pair['called']=True;value=os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK);pair.update(returned=True,fds=value)
        if type(value) is not tuple or len(value)!=2 or any(type(fd) is not int or fd<3 for fd in value) or value[0]==value[1]:fail('pipe_unknown')
        for suffix,fd in zip(('read','write'),value):
            row={'role':role+'_'+suffix,'fd':fd,'metadata':None,'unknown':True,'close_called':False,'closed':False,'raw':[],'eof':False}
            self.fd_rows.append(row);pair['rows'].append(row);row['metadata']=self._fd_meta(fd);row['unknown']=False
        self._active_now();return tuple(pair['rows'])
    def _close_fd(self,row):
        if threading.current_thread() is not self.worker or os.getpid()!=self.pid or self.until is not self._original_until or not any(row is r for r in self.fd_rows):return False
        if row['close_called']:return row['closed']
        if row['unknown'] or type(row['fd']) is not int:return False
        row['close_called']=True
        try:
            if self._fd_meta(row['fd'])!=row['metadata']:fail('pipe_identity')
            returned=os.close(row['fd'])
            try:os.fstat(row['fd'])
            except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
            if not row['closed']:row['unknown']=True
        except BaseException:row['unknown']=True
        return row['closed']
    def _drain(self):
        self.now()
        for role,target,maximum in (('stdout_read',self.raw_stdout,262144),('stderr_read',self.raw_stderr,262144),('exec_read',self.raw_exec,16)):
            rows=[r for r in self.fd_rows if r['role']==role]
            if not rows:continue
            if len(rows)!=1:fail('pipe_identity')
            row=rows[0]
            if row['closed'] or row['eof']:continue
            if row['unknown'] or self._fd_meta(row['fd'])!=row['metadata']:fail('pipe_identity')
            try:raw=os.read(row['fd'],4096)
            except OSError as error:
                if type(error.errno) is int and error.errno in (errno.EAGAIN,errno.EWOULDBLOCK):continue
                row['unknown']=True;raise
            row['raw'].append(raw);target.append(raw)
            if type(raw) is not bytes or sum(len(v) for v in target if type(v) is bytes)>maximum:fail('pipe_output_budget')
            if raw==b'':row['eof']=True
            if self._fd_meta(row['fd'])!=row['metadata']:row['unknown']=True;fail('pipe_identity')
            self.now()
    def _fork_exact(self):
        self.now();original=self._fork_original
        if (original is None or original is not self._fork_registered or len(original)!=8 or original[0] is not self or original[1]!=self.child_pid or
            original[2] is not self.parent_actor or original[3]!=self.child_boot or original[4] is not self.argv or original[5] is not self.go_until or
            original[6] is not self.go_until_text or original[7] is not self._process_original or not self.fork_requested or not self.fork_returned or self.fork_negative or
            type(self.child_pid) is not int or self.child_pid<=0):fail('fork_owner')
        store,reader,budget,mutex,epoch,clock,identity=original[7]
        if (self.process_store is not store or self.process_reader is not reader or self._process_clock is not clock or
            store._resource_budget_v23 is not budget or store._mutex is not mutex or store._epoch is not epoch or store._identity is not identity or
            reader._bound_budget_v24 is not budget or reader._resource_budget_v24 is not budget or store._proc_reader is not reader):fail('fork_owner')
        return self.child_pid
    def _wait_child(self):
        if self.child_waited:return
        if self._fork_original is None:return
        while True:
            pid=self._fork_exact()
            row={'called':True,'returned':False,'pid':pid,'value':None};self.wait_rows.append(row)
            value=os.waitpid(pid,os.WNOHANG);row.update(returned=True,value=value)
            if type(value) is not tuple or len(value)!=2 or any(type(v) is not int for v in value) or not 0<=value[1]<=65535:fail('wait_unknown')
            if value[0]==pid:
                self.child_waited=True;self.child_status=value[1]
                self.child_exit=os.WEXITSTATUS(value[1]) if os.WIFEXITED(value[1]) else -os.WTERMSIG(value[1]) if os.WIFSIGNALED(value[1]) else None
                self.now()
                if self.stream_failure is None:
                    try:self._drain()
                    except BaseException as error:self.stream_failure=error;self.cleanup_errors.append(type(error).__name__)
                return
            if value!=(0,0):fail('wait_unknown')
            if self.stream_failure is None:
                try:self._drain()
                except BaseException as error:self.stream_failure=error;self.cleanup_errors.append(type(error).__name__)
            self.now()
            select.select((),(),(),min(.05,self.until-self.now()))
    def _child_exec(self,python_row,read_rows,write_rows):
        try:
            for row in read_rows:os.close(row['fd'])
            os.dup2(write_rows[0]['fd'],1);os.dup2(write_rows[1]['fd'],2)
            for row in write_rows[:2]:
                if row['fd'] not in (1,2):os.close(row['fd'])
            # Error writer stays CLOEXEC: actual EOF is distinct from exit/reap.
            os.execve(python_row['fd'],self.argv,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
        except BaseException:
            try:os.write(write_rows[2]['fd'],b'E')
            except BaseException:pass
            os._exit(126)
    def _run_bootstrap(self):
        now=self.now()
        if self.until-now<135.0:fail('bootstrap_preparation_late')
        self.go_until=min(now+GO_ACTIVE_SECONDS,self.until-CLEANUP_SECONDS-POST_READ_SECONDS)
        self.go_until_text=repr(float(self.go_until));self.phase='launch'
        self._process_clock=self.now;reader=proc.ProcReader(timeout=3.0,_clock=self._process_clock)
        identity=core.Identity(READONLY_MANIFEST_SHA)
        store=stores.DurableClientInitStore(self.token,identity,timeout=3.0,_clock=self._process_clock,_proc_reader=reader,_session_profile=core.TRIAL_SESSION_PROFILE)
        self.process_reader,self.process_store=reader,store
        self._process_original=(store,reader,store._resource_budget_v23,store._mutex,store._epoch,self._process_clock,identity)
        end=self._process_slice(True);observed=reader.read_self(_absolute_deadline=end);self.parent_actor=self._observation(observed);self.child_boot=observed.boot
        if self.parent_actor.pid!=self.pid:fail('fork_owner')
        python_row=self.writer.read_python(True);self.python_exec_row=python_row
        if python_row['sha256']!=self.python_sha:fail('python_changed')
        run=self.writer.run_path()
        self.argv=(PYTHON,'-B',run+'/runtime/mta_go_executor.py','--go-bootstrap','--run-token',self.token,'--manifest-sha256',self.deployment_sha,'--until',self.go_until_text)
        self.argv_sha=hashlib.sha256(b''.join(v.encode('ascii')+b'\0' for v in self.argv)).hexdigest()
        stdout_read,stdout_write=self._pipe('stdout');stderr_read,stderr_write=self._pipe('stderr');exec_read,exec_write=self._pipe('exec')
        self._active_now();self.fork_requested=True
        pid=os.fork();self.fork_returned=True
        if type(pid) is not int or pid<0:self.fork_negative=type(pid) is int and pid<0;fail('fork_unknown')
        if pid==0:self._child_exec(python_row,(stdout_read,stderr_read,exec_read),(stdout_write,stderr_write,exec_write))
        self.child_pid=pid
        self._fork_original=self._fork_registered=(self,pid,self.parent_actor,self.child_boot,self.argv,self.go_until,self.go_until_text,self._process_original)
        self.phase='bootstrap'
        for row in (stdout_write,stderr_write,exec_write):
            if not self._close_fd(row):fail('pipe_close')
        if not self.writer.close_row(python_row):fail('python_close')
        # Exact original positive fork, actual executable/argv/start/boot proof.
        for unused in range(32):
            end=self._process_slice();observed=reader.read_actor(pid,_absolute_deadline=end)
            self.process_observations.append(observed)
            if (type(observed) is proc.ProcObservation and observed.kind=='live_actor' and type(observed.actor) is core.Actor and observed.actor.live() and
                observed.actor.exe==PYTHON and observed.actor.argv_sha==self.argv_sha and observed.boot==self.child_boot and observed.same_boot is True and
                observed.passes==2 and observed.resource_pending is False and observed.file_count==observed.closed_count and len(observed.actor.tasks)==1):
                self.child_actor=observed.actor;break
            self._drain();self.now();select.select((),(),(),.01)
        if self.child_actor is None:fail('bootstrap_entry_unknown')
        self._wait_child()
        end=self._process_slice();observed=reader.read_absence(self.child_actor,self.child_boot,_absolute_deadline=end);self.process_observations.append(observed)
        if (type(observed) is not proc.ProcObservation or observed.kind!='absence' or observed.pid_path_absent is not True or observed.remaining_tasks or observed.same_boot is not True or observed.boot!=self.child_boot or observed.passes!=2 or observed.resource_pending is not False):fail('bootstrap_absence')
        self.child_absent=True
        self._drain()
        if self.child_exit!=0 or b''.join(self.raw_exec)!=b'' or exec_read['eof'] is not True:fail('bootstrap_exit')
        if not all(row['eof'] for row in (stdout_read,stderr_read,exec_read)):fail('bootstrap_stream_eof')
    def _journal_read(self):
        if self.journal_rows:return
        self.now();writer=self.writer;parent=writer.fd_of(writer.run)
        row={'name':'go-journal.json','fd':None,'metadata':None,'raw':None,'unknown':True,'close_called':False,'closed':False};self.journal_rows.append(row)
        try:
            before=writer.entry_metadata(os.stat(row['name'],dir_fd=parent,follow_symlinks=False))
            if not stat.S_ISREG(before[2]) or before[3:6]!=(0,0,1) or stat.S_IMODE(before[2])!=0o600 or not 1<=before[6]<=131072:fail('journal_shape')
            self.now();row['fd']=os.open(row['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            if type(row['fd']) is not int or row['fd']<3 or writer.entry_metadata(os.fstat(row['fd']))!=before:fail('journal_shape')
            row['metadata']=before;row['unknown']=False;parts=[];total=0
            while True:
                self.now();raw=os.read(row['fd'],min(65536,before[6]+1-total));parts.append(raw)
                if type(raw) is not bytes:fail('journal_shape')
                total+=len(raw)
                if total>before[6]:fail('journal_shape')
                if not raw:break
            row['raw']=b''.join(parts)
            if total!=before[6] or writer.entry_metadata(os.fstat(row['fd']))!=before or writer.entry_metadata(os.stat(row['name'],dir_fd=parent,follow_symlinks=False))!=before:fail('journal_changed')
            row['sha256']=hashlib.sha256(row['raw']).hexdigest()
            self.journal=json_codec.loads(row['raw'].decode('ascii'));self.now()
        finally:
            if row['fd'] is not None and not row['unknown']:
                row['close_called']=True
                try:
                    if writer.entry_metadata(os.fstat(row['fd']))!=row['metadata']:fail('journal_changed')
                    returned=os.close(row['fd'])
                    try:os.fstat(row['fd'])
                    except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
                except BaseException:row['unknown']=True
                if not row['closed']:row['unknown']=True
    def _journal_gate(self):
        # Readonly durable facts, never rehydrated as a continuing GO grant.
        record=self.journal
        expected={'schema','run_token','candidate_sha','task_id','boot_id','issued_at','until','phase','generation','baseline','interface_intent','owned','watchdog','controller','group_add','group_observed','cleanup_until','restored'}
        if type(record) is not dict or set(record)!=expected or record['schema']!='p011-go-bootstrap-v33-r2' or record['run_token']!=self.token or record['candidate_sha']!=SOURCE_MANIFEST_SHA or record['task_id']!='bootstrap-'+self.token or record['boot_id']!=self.child_boot or record['until']!=self.go_until or record['phase']!='reconciled' or type(record['generation']) is not int or record['generation']!=12:fail('journal_reconcile')
        if type(record['issued_at']) not in (int,float) or not self.issued_at<=record['issued_at']<self.go_until or type(record['cleanup_until']) not in (int,float) or not record['issued_at']<record['cleanup_until']<=self.until:fail('journal_original_until')
        before=self._before_original();original=parent_codec._snapshot_tree(before)
        # Pure strict Snapshot facts decode only, NOT a GoCanonical/issuer/grant.
        # Native key preserves all baseline identity/resources but excludes the
        # transient R/S task state already validated as live by Snapshot ctor.
        captured=parent_codec._snapshot(record['baseline']);restored=parent_codec._snapshot(record['restored'])
        if captured.key()!=before.key() or restored.key()!=before.key():fail('journal_baseline')
        if (type(record['interface_intent']) is not dict or type(record['owned']) is not dict or record['owned'].get('iftype')!=8 or record['owned'].get('name')!='mta'+self.token[:8] or
            type(record['group_add']) is not dict or type(record['group_observed']) is not dict or type(record['group_observed'].get('observed_origin')) is not dict or record['group_observed']['observed_origin'].get('iftype')!=9 or
            record['group_add'].get('frequency')!=original['station_frequency'] or record['group_observed'].get('frequency')!=original['station_frequency']):fail('journal_group')
        for role in ('watchdog','controller'):
            child=record[role]
            if type(child) is not dict or set(child)!={'phase','spec_sha','argv_sha','until','actor'} or child['phase']!='live' or child['until']!=self.go_until or type(child['actor']) is not dict or child['actor'].get('pid')==self.pid:fail('journal_child')
        if not all(row['closed'] and not row['unknown'] for row in self.journal_rows):fail('journal_close')
        self.journal_reconciled=True
    def _resources_closed(self):
        if threading.current_thread() is not self.worker or os.getpid()!=self.pid:return False
        for row in self.readonly_rows:
            owner=row['owner']
            if row['constructor_returned'] is not True or type(owner) is not readonly.ReadonlyBaselineOwner or owner.worker is not self.worker or owner.pid!=self.pid or owner._closed() is not True:return False
        if self.writer_constructor_attempted and (not self.writer_constructor_returned or type(self.writer) is not GoAppendOwner or self.writer._task is not self or not self.writer_closed or self.writer.pending or any(row['unknown'] or not row['closed'] for row in self.writer.rows)):return False
        if any(row['unknown'] or not row['closed'] for row in self.fd_rows):return False
        if any(row['unknown'] or not row['closed'] for row in self.journal_rows):return False
        if self.fork_requested and (not self.fork_returned or not self.fork_negative and not self.child_waited):return False
        if self.process_reader is not None and not self.process_reader.history_closed():return False
        return True
    def run(self,payloads,wpa):
        self.now()
        if self.attempted or self.ended:fail('stage_attempted')
        self.attempted=True
        try:
            if type(payloads) is not dict or set(payloads)!=set(n for n,z,h in SOURCE_PINS):fail('stage_shape')
            for name,size,pin in SOURCE_PINS:
                if type(payloads[name]) is not bytes or len(payloads[name])!=size or hashlib.sha256(payloads[name]).hexdigest()!=pin:fail('stage_shape')
            if type(wpa) is not bytes or len(wpa)!=WPA_BYTES or hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_shape')
            self.before=self._read_phase('before_read');self._before_original(True)
            self.phase='write';self.writer_constructor_attempted=True
            writer=GoAppendOwner(self);self.writer=writer;self.writer_constructor_returned=True;writer.stage(self.token,payloads,wpa)
            self._run_bootstrap();self._journal_read();self._journal_gate()
            self.after=self._read_phase('after_read')
            before=self._before_original();after=self._original_read(self.after,True)
            if before.key()!=after.key() or self.before['owner'].platform_before!=self.after['owner'].platform_after:fail('stage_baseline_changed')
            self.baseline_restored=True;self.phase='final_readback';writer.verify_static(True);self.now()
        except BaseException as error:self.error=error;raise
        finally:
            if self._fork_original is not None and not self.child_waited:
                try:self._wait_child()
                except BaseException as error:self.cleanup_errors.append(type(error).__name__)
            if self.writer is not None and self.writer.run is not None and not self.journal_rows and self.child_waited:
                try:self._journal_read()
                except BaseException as error:self.cleanup_errors.append(type(error).__name__)
            if self.after is None and self.before is not None and self.child_waited:
                try:
                    self.after=self._read_phase('after_read')
                    before=self._before_original();after=self._original_read(self.after,True)
                    self.baseline_restored=before.key()==after.key() and self.before['owner'].platform_before==self.after['owner'].platform_after
                except BaseException as error:self.cleanup_errors.append(type(error).__name__)
            for row in self.fd_rows:
                if not self._close_fd(row):self.cleanup_errors.append('pipe_close_unknown')
            if self.writer is not None:self.writer_closed=self.writer.close()
            self.ended=True;self.phase='ended'
        try:
            if not self._resources_closed() or not self.child_absent or not self.journal_reconciled or not self.baseline_restored or self.cleanup_errors:fail('stage_unclosed')
            self.now()
        except BaseException as error:self.error=error;raise
        self.success=True;return self
    def status(self):
        try:closed=self._resources_closed()
        except BaseException:closed=False
        return {'evidence':'GO_BOOTSTRAP_DEVICE_V46_FREQUENCY_SOURCE',
            'loaded_readonly_map_sha256':READONLY_MANIFEST_SHA,'staged_native_map_sha256':SOURCE_MANIFEST_SHA,'readonly_leaf_sha256':READONLY_LEAF_SHA,
            'attempted':self.attempted,'ended':self.ended,'staging_attempted':bool(self.writer is not None and self.writer.stage_attempted),
            'before_read_closed':bool(self.before is not None and self.before['returned']),'after_read_closed':bool(self.after is not None and self.after['returned']),
            'go_sources_staged':bool(self.writer is not None and len(self.writer.writes)==20 and all(r['closed'] and not r['unknown'] for r in self.writer.writes)),
            'bootstrap_entry_verified':self.child_actor is not None,'bootstrap_exit_verified':self.child_waited and self.child_exit==0,
            'bootstrap_absence_verified':self.child_absent,'journal_reconciled_verified':self.journal_reconciled,'baseline_restore_verified':self.baseline_restored,
            'go_bootstrap_verified':self.success,'resource_pending':not closed or not(self.child_absent and self.journal_reconciled and self.baseline_restored),
            'stage_native_files':len(self.writer.writes) if self.writer is not None else 0,
            'original_root_entries':len(self.writer.entries_before) if self.writer is not None and self.writer.entries_before is not None else 0,
            'rf_trial_requested':self.fork_requested,'rf_intent_observed':bool(type(self.journal) is dict and self.journal.get('interface_intent') is not None),
            'fd3_received':False,'raw_native_inventory_export':False,'source_factory_ready':False,
            'ip_ready':False,'dhcp_ready':False,'send_available':False,'receive_available':False,'phone_tested':False}
