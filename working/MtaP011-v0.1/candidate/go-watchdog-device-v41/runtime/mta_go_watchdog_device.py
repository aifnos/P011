"""Fixed GO append preparation and actual no-RF watchdog component.

SOURCE-only candidate: explicit reviewed HOST driver is required to run it.
Old CLIENT readonly definitions live only in this parent interpreter; the
unchanged GO17 graph loads in the exact separately exec'ed watchdog process.
No GoBootstrap/GoStore/GO parent issuer/controller/FD3/RF entry is invoked.
The private scratch flock proves only this one child's inherited OFD lifetime;
it is not the global device lock, RF permission or a durable launch receipt.
All append/FD inventories retain unknown outcomes and partial new files.
"""
import ctypes
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
import mta_client_process_owner as process
import mta_client_proc as proc
import mta_client_store as stores
import mta_p2p_client_init as core

SOURCE_MANIFEST_SHA = '491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296'
READONLY_MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
READONLY_LEAF_SHA = 'cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff'
STAGE_SECONDS = 120.0
WATCHDOG_SECONDS = 25.0
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
    ('mta_go_executor', 15277, '0b89d73417191cd19f5a04722019c7a2617febee416e7dd658b12fc032a17f11'),
    ('mta_go_bootstrap_store', 65815, '7e10b8bba161b1d4035fffeb5e1d92eb3a6ad797111e60ab24b9d04d6130c228'),
    ('mta_go_native', 86024, '839ea4dbde4e26e8387434af071b12ee0330ac653a4e043d452b78af7f28be6a'),
    ('mta_go_bootstrap', 16859, '0b2960491717f0100882f5dac25df66669a53651adf813c0617726455b4471e7'),
)
PINS = tuple((name,pin) for name,size,pin in SOURCE_PINS)


class GoWatchdogError(ValueError):
    pass


def fail(code):
    raise GoWatchdogError(code) from None


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
        'task_id':'watchdog-'+token,'ifname':'mta'+token[:8],'python_sha':python_sha,
        'sources':[[name,pin] for name,size,pin in SOURCE_PINS],
        'baseline_manifest':[[path,pin] for path,pin in readonly.BASELINE_MANIFEST]}}


class StageIo(object):
 def stat_root(self):return os.stat('/',follow_symlinks=False)
 def stat_at(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
 def fstat(self,fd):return os.fstat(fd)
 def readlink_at(self,fd,name):return os.readlink(name,dir_fd=fd)
class GoAppendOwner(object):
 def __init__(self,task):
  if type(task) is not GoWatchdogTask or task.phase!='write' or task.writer is not None:fail('stage_owner')
  self._task=task;self.clock=task._writer_clock;deadline=task.until
  if not callable(self.clock) or type(deadline) not in (int,float) or not math.isfinite(float(deadline)):fail('stage_budget')
  now=self.clock()
  if type(now) not in (int,float) or not math.isfinite(float(now)) or not 0<deadline-now<=120:fail('stage_budget')
  self.deadline=float(deadline);self.worker=threading.current_thread();self.pid=os.getpid();self.last=None;self.writes=[]
  self._io=StageIo();self._tmp_alias=None;self.rows=[];self.mutations=[]
  self.root=None;self.tmp=None;self.private_root=None;self.run=None;self.runtime=None;self.native=None;self.ctrl=None
  self.pending=True;self.close_attempted=False;self.python_rows=[];self.scratch=None;self.contender=None;self.flock_rows=[];self._flock=None;self.private_root_created=False
  self.entries_before=None;self.entries_after=None;self.run_name='go-'+task.token;self.stage_attempted=False
 def check(self):
  task=self._task
  if type(task) is not GoWatchdogTask or task.writer is not self or self.clock is not task._writer_clock or self.deadline is not task.until:fail('stage_owner')
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
 def verify_static(self):
  self.retained_entries()
  names=('runtime','native','ctrl','deployment.json')+('watchdog-device.lock',) if self.scratch is not None else ('runtime','native','ctrl','deployment.json')
  self.layout(self.run,names)
  self.layout(self.runtime,tuple(name+'.py' for name,pin in PINS));self.layout(self.native,('mta-wpa-supplicant',));self.empty(self.ctrl)
  for row in self.writes:
   self.authenticate()
   if row['closed'] is not True or row['unknown'] is not False or row.get('sealed_entry')!=self.entry_metadata(self._io.stat_at(self.fd_of(row['parent']),row['name'])):fail('stage_changed')
 def close_row(self,row):
  task=self._task
  if type(self) is not GoAppendOwner or type(task) is not GoWatchdogTask or task.writer is not self or task.writer_constructor_returned is not True or self.clock is not task._writer_clock or self.deadline is not task.until or task.until is not task._original_until or self.worker is not task.worker or self.pid!=task.pid or threading.current_thread() is not self.worker or os.getpid()!=self.pid or not any(row is item for item in self.rows):return False
  if row['attempted']:return row['closed']
  if row['unknown'] or type(row['fd']) is not int:return False
  row['attempted']=True
  try:
   actual=self._io.fstat(row['fd'])
   if row['kind']=='directory':
    if self.identity(actual,row['mode'])!=row['identity']:fail('stage_unknown')
   elif row['kind'] in ('scratch','contender'):
    if executor._meta(actual)!=row['metadata'] or not stat.S_ISREG(row['metadata'][2]) or row['metadata'][3:6]!=(0,0,1) or stat.S_IMODE(row['metadata'][2])!=0o600:fail('stage_unknown')
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
  if self._task.phase!='write' or not (parent is self.runtime and name in tuple(item+'.py' for item,pin in PINS) and mode==0o400 or parent is self.native and name=='mta-wpa-supplicant' and mode==0o500 or parent is self.run and name=='deployment.json' and mode==0o400):fail('stage_owner')
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
 def read_python(self):
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
   return row['sha256']
  finally:
   if not self.close_row(row):self.pending=True
 def scratch_open(self,contender=False):
  self.authenticate();parent_fd=self.fd_of(self.run);self.check()
  if contender:
   if self.scratch is None or not self.scratch['closed'] or self.contender is not None:fail('scratch_owner')
   role='contender';flags=os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC
  else:
   if self.scratch is not None:fail('scratch_owner')
   role='scratch';flags=os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC
  row={'kind':role,'name':'watchdog-device.lock','parent':self.run,'fd':None,'metadata':None,'mode':0o600,'unknown':True,'attempted':False,'closed':False}
  self.rows.append(row)
  if contender:self.contender=row
  else:self.scratch=row
  self.check();row['fd']=os.open(row['name'],flags,0o600,dir_fd=parent_fd)
  row['metadata']=executor._meta(os.fstat(row['fd']))
  if type(row['fd']) is not int or row['fd']<3 or not stat.S_ISREG(row['metadata'][2]) or row['metadata'][3:6]!=(0,0,1) or stat.S_IMODE(row['metadata'][2])!=0o600 or row['metadata'][6]!=0 or executor._meta(self._io.stat_at(parent_fd,row['name']))!=row['metadata']:fail('scratch_unknown')
  if contender and row['metadata']!=self.scratch['metadata']:fail('scratch_replaced')
  row['unknown']=False;self.check()
  return row
 def flock(self,row,expected):
  self.authenticate();self.check()
  if row not in (self.scratch,self.contender) or row['unknown'] or row['closed'] or row['attempted'] or executor._meta(os.fstat(row['fd']))!=row['metadata']:fail('scratch_unknown')
  if self._flock is None:
   self._flock=ctypes.CDLL(None,use_errno=True).flock
   self._flock.argtypes=(ctypes.c_int,ctypes.c_int);self._flock.restype=ctypes.c_int
  observed={'row':row,'called':True,'returned':False,'result':None,'errno':None}
  self.flock_rows.append(observed);ctypes.set_errno(0)
  value=self._flock(row['fd'],6);observed.update(returned=True,result=value,errno=ctypes.get_errno())
  self.check()
  if executor._meta(os.fstat(row['fd']))!=row['metadata']:fail('scratch_unknown')
  if expected=='acquired':
   if type(value) is not int or value!=0:fail('scratch_not_acquired')
  elif expected=='contended':
   if type(value) is not int or value!=-1 or observed['errno'] not in (errno.EAGAIN,errno.EWOULDBLOCK):fail('child_ofd_not_held')
  else:fail('scratch_owner')
  return observed
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
  self.verify_static()
  for row in (self.runtime,self.native,self.ctrl,self.run,self.private_root,self.tmp):
   self.authenticate();fd=self.fd_of(row);self.check();os.fsync(fd);self.check();self.fd_of(row)
 def close(self):
  if self.close_attempted:return not self.pending
  self.close_attempted=True
  good=True
  for row in reversed(self.rows):good=self.close_row(row) and good
  self.pending=not good
  return good
 def inventory(self):
  return tuple({key:row.get(key) for key in ('kind','name','fd','metadata','identity','mode','unknown','attempted','closed','close_identity','close_mode','close_observed','chmod_attempted','chmod_returned')} for row in self.rows)


class GoWatchdogTask(object):
    """Same-worker original120s GO append and one real watchdog component.

    No saved baseline or caller owner authorizes writes. The actual old35/leaf
    owners run independently before/after; a third pure accounting Store binds
    the real child Proc reader. No Store acquire, canonical, device-global
    lease, GO issuer/controller/FD3, user directories or RF operation exists.
    """
    def __init__(self, run_token, original_until):
        if type(run_token) is not str or re.fullmatch('[0-9a-f]{32}',run_token) is None or type(original_until) not in (int,float) or not math.isfinite(float(original_until)):
            fail('stage_task')
        self.token=run_token;self.clock=time.monotonic;self.worker=threading.current_thread();self.pid=os.getpid()
        self.until=self._original_until=float(original_until);self.last=None
        self.issued_at=self.now()
        if not 0<self.until-self.issued_at<=STAGE_SECONDS:fail('stage_budget')
        self._writer_clock=self.now;self.phase='new';self.readonly_rows=[]
        self.writer=None;self.writer_constructor_attempted=False;self.writer_constructor_returned=False
        self.writer_closed=False;self.attempted=False;self.ended=False;self.success=False;self.error=None
        self.deployment_raw=None;self.deployment_sha=None;self.python_sha=None;self.before=None;self.after=None
        self.process_owner=None;self.process_ticket=None;self.process_store=None;self.process_reader=None
        self.persist_rows=[];self.notify_rows=[];self.watchdog_until=None;self.watchdog_until_text=None
        self.watchdog_verified=False;self.ofd_verified=False;self.notify_eof=False;self.process_closed=False;self.cleanup_errors=[]
    def now(self):
        value=self.clock()
        if self.clock is not time.monotonic or self.until is not self._original_until or threading.current_thread() is not self.worker or os.getpid()!=self.pid or type(value) not in (int,float) or not math.isfinite(float(value)) or not 0<=value<1e12 or self.last is not None and value<self.last:
            fail('stage_task')
        self.last=float(value)
        if value>=self.until:fail('stage_budget')
        return float(value)
    def _writer_gate(self, writer):
        self.now()
        if type(writer) is not GoAppendOwner or writer is not self.writer or writer._task is not self or not self.writer_constructor_returned or self.phase not in ('write','watchdog','after_read','final_readback'):
            fail('stage_owner')
        if self.before is None or not self.before['returned'] or self.before['owner'].result is not self.before['value']:
            fail('stage_before')
    def _read_phase(self, phase):
        self.now();self.phase=phase
        phase_until=min(self.until,self.now()+readonly.MAX_SECONDS)
        row={'phase':phase,'until':phase_until,'owner':None,'value':None,'constructor_attempted':True,'constructor_returned':False,'returned':False}
        self.readonly_rows.append(row)
        owner=readonly.ReadonlyBaselineOwner(self.token,phase_until,_clock=self.clock)
        row['owner']=owner;row['constructor_returned']=True
        value=owner.collect();row['value']=value;row['returned']=True
        self._original_read(row)
        return row
    def _original_read(self, row, fresh=False):
        self.now()
        if not any(row is item for item in self.readonly_rows) or row['constructor_returned'] is not True or row['returned'] is not True:
            fail('stage_read')
        owner=row['owner'];value=row['value']
        if type(owner) is not readonly.ReadonlyBaselineOwner or owner.worker is not self.worker or owner.pid!=self.pid or owner.token!=self.token or owner._clock is not self.clock or owner.until is not owner._original_until or owner.until!=row['until'] or owner.until>self.until or owner.identity.candidate_sha!=READONLY_MANIFEST_SHA or readonly.SOURCE_MANIFEST_SHA!=READONLY_MANIFEST_SHA or owner.result is not value or owner.error is not None or owner.attempted is not True or owner.ended is not True or owner.read_success is not True or owner.resource_pending is not False or owner.pending_before is not True or owner.pending_after is not True or owner._closed() is not True:
            fail('stage_read')
        if fresh:owner.now()
        return value
    def _before_original(self, fresh=False):
        if self.before is None or self.before is not self.readonly_rows[0] or self.before['phase']!='before_read':fail('stage_before')
        return self._original_read(self.before,fresh)
    def _resources_closed(self):
        if threading.current_thread() is not self.worker or os.getpid()!=self.pid:return False
        for row in self.readonly_rows:
            owner=row['owner']
            if row['constructor_returned'] is not True or type(owner) is not readonly.ReadonlyBaselineOwner or owner.worker is not self.worker or owner.pid!=self.pid or owner._closed() is not True:return False
        if self.writer_constructor_attempted and (not self.writer_constructor_returned or type(self.writer) is not GoAppendOwner or self.writer._task is not self or not self.writer_closed or self.writer.pending or any(item['unknown'] or not item['closed'] for item in self.writer.rows)):
            return False
        return True
    def _process_neutral(self):
        self.now()
        row=self._process_original
        store,reader,budget,mutex,epoch,clock,identity=row
        if (self.process_store is not store or self.process_reader is not reader or
                type(store) is not stores.DurableClientInitStore or type(reader) is not proc.ProcReader or
                store._identity is not identity or store._clock is not clock or reader._clock is not clock or
                store._mutex is not mutex or store._epoch is not epoch or
                store._resource_budget_v23 is not budget or budget._store is not store or
                budget._mutex is not mutex or budget._epoch is not epoch or budget._provider is not None or
                store._proc_reader is not reader or store._proc_reader_original_v24 is not reader or
                reader._bound_budget_v24 is not budget or reader._resource_budget_v24 is not budget or
                len(budget._readers)!=1 or budget._readers[0] is not reader or
                store._session_profile is not core.TRIAL_SESSION_PROFILE or
                store._session_profile_original_v28 is not core.TRIAL_SESSION_PROFILE or
                store._attempted or store._opened or store._unknown or store._current_locks is not None or
                store._canonical is not None or store._marker is not None or store._binding is not None or
                store._session_issued_v28 is not None or store._records or store._locksets or
                store._coordination._attempted or store._coordination._inventory or
                store._coordination._locks is not None or store._files._opened or
                store._files._inventory or store._files._publication_attempted):
            fail('process_accounting_changed')
        budget._context()
        if self.process_owner is not None and (type(self.process_owner) is not process.DirectChildOwner or
                self.process_owner._reader is not reader or self.process_owner._clock is not clock or
                self.process_owner._os is not os or self.process_owner._host_seam):
            fail('process_owner_changed')
        return store
    def _process_slice(self):
        store=self._process_neutral()
        # A bounded observation slice only. No Journal/session/child original
        # until is changed or extended; this Store has no active publication.
        store._io_deadline=min(self.until,self.now()+10.0)
    def _persist_preexec(self,ticket,actor):
        self._process_neutral()
        if (ticket is not self.process_ticket or type(ticket) is not process.ChildTicket or
                ticket.owner is not self.process_owner or actor is not ticket.preexec or
                type(actor) is not core.Actor or not actor.live() or ticket.released or
                ticket.deadline!=self.watchdog_until or ticket.spec is not self._launch_spec):
            fail('process_preexec')
        row={'ticket':ticket,'actor':actor,'returned':None}
        self.persist_rows.append(row)
        # Only same-original in-memory callback linkage. NOT GoStore fsync,
        # a GO child intent, Parent admission or RF/durable launch permission.
        receipt=process.PersistReceipt(ticket,actor);row['returned']=receipt
        return receipt
    def _live_watchdog(self):
        self._process_slice()
        ticket=self.process_ticket
        value=self.process_reader.read_actor(ticket.pid,ticket.postexec,
            _absolute_deadline=min(self.until,self.now()+3.0))
        if (type(value) is not proc.ProcObservation or value.kind!='live_actor' or
                value.actor is None or value.actor.key()!=ticket.postexec.key() or
                value.boot!=ticket.boot or value.same_boot is not True or value.passes!=2 or
                value.resource_pending is not False):
            fail('watchdog_not_live')
        return value
    def _run_watchdog(self):
        self.phase='watchdog';self.now()
        self._process_clock=self.now
        reader=proc.ProcReader(timeout=3.0,_clock=self._process_clock)
        identity=core.Identity(READONLY_MANIFEST_SHA)
        store=stores.DurableClientInitStore(self.token,identity,timeout=3.0,
            _clock=self._process_clock,_proc_reader=reader,_session_profile=core.TRIAL_SESSION_PROFILE)
        self.process_reader,self.process_store=reader,store
        self._process_original=(store,reader,store._resource_budget_v23,
            store._mutex,store._epoch,self._process_clock,identity)
        self._process_neutral()
        self.process_owner=process.DirectChildOwner(_reader=reader,_clock=self._process_clock)
        now=self.now()
        if self.until-now<45.0:fail('watchdog_preparation_late')
        # One original issuance before child resource creation; never reset.
        self.watchdog_until=min(self.until-20.0,now+WATCHDOG_SECONDS)
        self.watchdog_until_text=repr(float(self.watchdog_until))
        run=GO_ROOT+'/go-'+self.token
        argv=(PYTHON,'-B',run+'/runtime/mta_go_executor.py','--go-watchdog',
            '--run-token',self.token,'--manifest-sha256',self.deployment_sha,
            '--until',self.watchdog_until_text)
        self._launch_spec=process.LaunchSpec('watchdog',PYTHON,argv,
            (('PATH','/usr/sbin:/usr/bin:/sbin:/bin'),('LANG','C')),self.python_sha)
        writer=self.writer;scratch=writer.scratch_open()
        writer.flock(scratch,'acquired')
        self.process_ticket=self.process_owner.register(self._launch_spec,scratch['fd'],self.watchdog_until)
        ticket=self.process_ticket;owner=self.process_owner
        self._process_slice();owner.launch(ticket,_absolute_deadline=self.watchdog_until)
        self._process_slice();owner.release(ticket,self._persist_preexec,_absolute_deadline=self.watchdog_until)
        while ticket.postexec is None:
            self._process_slice();owner.resolve(ticket,_absolute_deadline=self.watchdog_until)
            if ticket.postexec is None:
                self.now()
                if time.monotonic()>=self.watchdog_until:fail('watchdog_exec_unknown')
                time.sleep(.01)
        self._live_watchdog()
        devices=tuple(row for row in ticket.fds if row.role=='inherited_device')
        if len(devices)!=1 or devices[0].metadata!=process._meta(os.fstat(scratch['fd'])):fail('scratch_unknown')
        # Close BOTH parent references to this flock's same OFD. Independent
        # open below, not dup, can then prove the actual child alone owns it.
        if owner._close_fd(ticket,devices[0]) is not True or writer.close_row(scratch) is not True:fail('scratch_parent_close')
        contender=writer.scratch_open(True)
        self._live_watchdog();writer.flock(contender,'contended');self._live_watchdog()
        notify=next(row for row in ticket.fds if row.role=='notify_read')
        while ticket.notify_requests==0:
            self._process_slice()
            wait=min(.05,self.until-self.now())
            selected=select.select((notify.fd,),(),(),wait)[0]
            if selected:
                returned=owner.read_requests(ticket,_absolute_deadline=self.until)
                self.notify_rows.append({'kind':'native_requests','returned':returned,
                    'requests':ticket.notify_requests,'at':self.now()})
                if returned is not True:fail('watchdog_notify_eof_before_r')
        if ticket.notify_requests!=1:fail('watchdog_notify_count')
        self._process_slice()
        if owner.wait_reap(ticket,timeout=10.0,_absolute_deadline=self.until) is not True or ticket.exit_code!=0:fail('watchdog_exit')
        self._process_slice()
        if owner.fresh_exit(ticket,_absolute_deadline=self.until) is not True:fail('watchdog_absence')
        self._process_slice();owner._single(ticket,deadline=min(self.until,self.now()+3.0))
        if notify.closed or notify.unknown or process._meta(os.fstat(notify.fd))!=notify.metadata:fail('watchdog_notify_unknown')
        row={'kind':'actual_eof','called':True,'returned':False,'raw':None}
        self.notify_rows.append(row)
        raw=os.read(notify.fd,17);row.update(returned=True,raw=raw)
        if type(raw) is not bytes or raw!=b'' or process._meta(os.fstat(notify.fd))!=notify.metadata:fail('watchdog_eof_unknown')
        self.notify_eof=True
        writer.flock(contender,'acquired')
        if not writer.close_row(contender):fail('scratch_contender_close')
        self.ofd_verified=True
        self._process_slice()
        self.process_closed=owner.close_inventory(ticket,_absolute_deadline=self.until)
        if not self.process_closed or ticket.unknown or not self.process_reader.history_closed():fail('watchdog_parent_unclosed')
        self.watchdog_verified=True
    def _close_process(self):
        if self.process_ticket is None:return
        owner,ticket=self.process_owner,self.process_ticket
        # Known gate close releases an unreleased child to deterministic EOF.
        # Released watchdog exits at its own original until; no signal/restart.
        for row in ticket.fds:
            if row.role=='gate_write' and not row.closed:
                if not owner._close_fd(ticket,row):self.cleanup_errors.append('gate_close_unknown')
        try:
            if not ticket.waited and ticket.pid is not None:
                self._process_slice()
                if not owner.wait_reap(ticket,timeout=20.0,_absolute_deadline=self.until):fail('watchdog_wait_unknown')
            if ticket.waited and not ticket.exit_verified:
                self._process_slice()
                if not owner.fresh_exit(ticket,_absolute_deadline=self.until):fail('watchdog_absence')
        except BaseException as error:self.cleanup_errors.append(type(error).__name__)
        # Close each retained known original once even if the task is late.
        good=True
        for row in ticket.fds:good=owner._close_fd(ticket,row) and good
        self.process_closed=good and not ticket.unknown and ticket.waited and ticket.exit_verified
    def run(self,payloads,wpa):
        self.now()
        if self.attempted or self.ended:fail('stage_attempted')
        self.attempted=True
        try:
            if type(payloads) is not dict or set(payloads)!=set(name for name,size,pin in SOURCE_PINS):fail('stage_shape')
            for name,size,pin in SOURCE_PINS:
                raw=payloads[name]
                if type(raw) is not bytes or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=pin:fail('stage_shape')
            if type(wpa) is not bytes or len(wpa)!=WPA_BYTES or hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_shape')
            self.before=self._read_phase('before_read');self._before_original(True)
            self.phase='write';self.writer_constructor_attempted=True
            writer=GoAppendOwner(self);self.writer=writer;self.writer_constructor_returned=True
            writer.stage(self.token,payloads,wpa)
            self._run_watchdog()
            self.after=self._read_phase('after_read')
            before=self._before_original();after=self._original_read(self.after,True)
            if before.key()!=after.key() or self.before['owner'].platform_before!=self.after['owner'].platform_after:fail('stage_baseline_changed')
            self.phase='final_readback';writer.verify_static();self.now()
        except BaseException as error:
            self.error=error;raise
        finally:
            self._close_process()
            if self.writer is not None:self.writer_closed=self.writer.close()
            self.ended=True;self.phase='ended'
        try:
            if not self._resources_closed() or not self.process_closed or not self.watchdog_verified or not self.ofd_verified or not self.notify_eof:fail('stage_unclosed')
            self.now()
        except BaseException as error:self.error=error;raise
        self.success=True
        return self
    def status(self):
        try:
            closed=self._resources_closed()
            if self.process_owner is not None:
                closed=closed and self.process_closed and self.process_reader.history_closed() and not self.cleanup_errors
        except BaseException:closed=False
        return {'evidence':'GO_WATCHDOG_DEVICE_V41_COMPONENT_ONLY',
            'loaded_readonly_map_sha256':READONLY_MANIFEST_SHA,'staged_native_map_sha256':SOURCE_MANIFEST_SHA,
            'readonly_leaf_sha256':READONLY_LEAF_SHA,'attempted':self.attempted,'ended':self.ended,
            'staging_attempted':bool(self.writer is not None and self.writer.stage_attempted),
            'before_read_closed':bool(self.before is not None and self.before['returned']),
            'after_read_closed':bool(self.after is not None and self.after['returned']),
            'go_sources_staged':self.success,'resource_pending':not closed,
            'watchdog_verified':self.success and self.watchdog_verified,
            'child_exit_verified':bool(self.process_ticket is not None and self.process_ticket.waited and self.process_ticket.exit_verified and self.process_ticket.exit_code==0),
            'notify_eof_verified':self.notify_eof,'child_ofd_verified':self.ofd_verified,
            'stage_native_files':len(self.writer.writes) if self.writer is not None else 0,
            'original_root_entries':len(self.writer.entries_before) if self.writer is not None and self.writer.entries_before is not None else 0,
            'device_exclusive_lease':False,'rf_admission':False,'source_factory_ready':False,
            'rf_requested':False,'go_parent_started':False,'go_store_opened':False,'fd3_verified':False,
            'controller_started':False,'send_available':False,'receive_available':False,
            'phone_tested':False,'restoration_verified':False}
