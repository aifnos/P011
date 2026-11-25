"""Append-only static source staging; never a CLIENT/RF deployment.

Original readonly definitions use the verified v37 graph and unmodified v39
leaf. The newer v38 candidate is only fixed bytes, not executed definitions.
Only a new client token directory is written; retained root entries are never
opened as subtrees, removed, renamed or chmoded. No global/device lock is held.
Pending/baseline/entry checks observe changes, not atomicity or RF admission.
"""
import errno
import hashlib
import math
import os
import re
import stat
import threading
import time

import p011_json as json_codec
import mta_client_executor as executor
import mta_client_tmp_alias as tmp_alias
import mta_client_readonly_baseline as readonly

SOURCE_MANIFEST_SHA = '0ea4db9b3ac41d1036d5796602db48b7740f6c51f1f0281604d6d8ebeb19319c'
READONLY_MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
READONLY_LEAF_SHA = 'cd4c3ef940ef12783dd0b91aba2805a4f4cbe50f2fe2bdccbddaa1db32f4b7ff'
STAGE_SECONDS = 120.0
MAX_ROOT_ENTRIES = 4096
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
SOURCE_PINS = (
    ("p011_json", 8061, "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88"),
    ("mta_ip", 22049, "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5"),
    ("mta_client_tmp_alias", 8827, "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f"),
    ("mta_p2p_client_init", 71315, "d3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa"),
    ("mta_client_resource_budget", 16215, "56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e"),
    ("mta_client_proc", 39384, "ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6"),
    ("mta_client_caps", 11821, "c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c"),
    ("mta_client_caps_transport", 19614, "df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420"),
    ("mta_client_baseline", 29510, "b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf"),
    ("mta_client_journal_codec", 17450, "2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a"),
    ("mta_client_coordination", 36295, "5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3"),
    ("mta_client_files", 28938, "30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864"),
    ("mta_client_pending", 57246, "14e85b8297868a7a07d964a598bc3cbc665e1e6cf19d615466e165386a27f524"),
    ("mta_client_store", 74676, "bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63"),
    ("mta_client_process_owner", 34361, "c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb"),
    ("mta_client_launch_registration", 21679, "833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0"),
    ("mta_client_two_phase_lease", 27606, "c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5"),
    ("mta_p2p_client_ctrl", 18712, "793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5"),
    ("mta_client_wpa_status", 39133, "47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269"),
    ("mta_protocol", 17958, "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57"),
    ("mta_client_control_frame", 20942, "d1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278"),
    ("mta_client_kernel_proof", 23702, "4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede"),
    ("mta_client_connection", 22494, "ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159"),
    ("mta_client_linux_provider", 174220, "5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba"),
    ("mta_client_executor", 105182, "f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e"),
    ("mta_dhcp", 15719, "631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176"),
    ("mta_dhcp_client_core", 12362, "13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa"),
    ("mta_dhcp_client", 24670, "794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0"),
    ("mta_client_dora", 48149, "f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e"),
    ("mta_client_dynamic_ip", 32427, "01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a"),
    ("mta_client_peer", 31242, "f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9"),
    ("mta_scoped_sockets", 26339, "b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8"),
    ("mta_storage", 14335, "3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6"),
    ("mta_transport", 35209, "77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa"),
    ("mta_client_transfer", 30747, "8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184"),
)
PINS = tuple((name,pin) for name,size,pin in SOURCE_PINS)


class StaticStageError(ValueError):
    pass


def fail(code):
    raise StaticStageError(code) from None


def _same_tree(left,right):
    if type(left) is not type(right):return False
    if type(left) is dict:
        return set(left)==set(right) and all(_same_tree(left[key],right[key]) for key in left)
    if type(left) is list:
        return len(left)==len(right) and all(_same_tree(a,b) for a,b in zip(left,right))
    return left==right


def candidate_document():
    return {'version':1,'kind':'client-static-source-v40',
        'staged_native_map_sha256':SOURCE_MANIFEST_SHA,
        'loaded_readonly_map_sha256':READONLY_MANIFEST_SHA,
        'readonly_leaf_sha256':READONLY_LEAF_SHA,
        'files':[['runtime/'+name+'.py',size,pin] for name,size,pin in SOURCE_PINS]+
                [['native/mta-wpa-supplicant',WPA_BYTES,WPA_SHA]]}


def source_record(token,candidate_sha):
    # Data provenance only, not an admission ticket or pre-existing close fact.
    if type(token) is not str or re.fullmatch('[0-9a-f]{32}',token) is None or \
            type(candidate_sha) is not str or re.fullmatch('[0-9a-f]{64}',candidate_sha) is None:fail('stage_shape')
    return {'version':1,'kind':'static-source-not-ready','run_token':token,
        'staged_native_map_sha256':SOURCE_MANIFEST_SHA,
        'loaded_readonly_map_sha256':READONLY_MANIFEST_SHA,
        'readonly_leaf_sha256':READONLY_LEAF_SHA,'candidate_sha256':candidate_sha,
        'sources':[[name,size,pin] for name,size,pin in SOURCE_PINS],
        'native_sha256':WPA_SHA,'deployment_available':False,'source_factory_ready':False,
        'device_exclusive_lease':False,'rf_admission':False,
        'rf_requested':False,'send_available':False,'receive_available':False,'phone_tested':False}


class StageIo(object):
 def stat_root(self):return os.stat('/',follow_symlinks=False)
 def stat_at(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
 def fstat(self,fd):return os.fstat(fd)
 def readlink_at(self,fd,name):return os.readlink(name,dir_fd=fd)
class StageOwner(object):
 def __init__(self,task):
  if type(task) is not StaticStagingTask or task.phase!='write' or task.writer is not None:fail('stage_owner')
  self._task=task;self.clock=task._writer_clock;deadline=task.until
  if not callable(self.clock) or type(deadline) not in (int,float) or not math.isfinite(float(deadline)):fail('stage_budget')
  now=self.clock()
  if type(now) not in (int,float) or not math.isfinite(float(now)) or not 0<deadline-now<=120:fail('stage_budget')
  self.deadline=float(deadline);self.worker=threading.current_thread();self.pid=os.getpid();self.last=None;self.writes=[]
  self._io=StageIo();self._tmp_alias=None;self.rows=[];self.mutations=[]
  self.root=None;self.tmp=None;self.private_root=None;self.run=None;self.runtime=None;self.native=None;self.ctrl=None
  self.pending=True;self.close_attempted=False
  self.entries_before=None;self.entries_after=None;self.run_name='client-'+task.token;self.stage_attempted=False
 def check(self):
  task=self._task
  if type(task) is not StaticStagingTask or task.writer is not self or self.clock is not task._writer_clock or self.deadline is not task.until:fail('stage_owner')
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
  os.mkdir(name,0o700,dir_fd=parent_fd);op['returned']=True
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
  self.retained_entries();self.layout(self.run,('runtime','native','ctrl','candidate.json','static-source.json'))
  self.layout(self.runtime,tuple(name+'.py' for name,pin in PINS));self.layout(self.native,('mta-wpa-supplicant',));self.empty(self.ctrl)
  for row in self.writes:
   self.authenticate()
   if row['closed'] is not True or row['unknown'] is not False or row.get('sealed_entry')!=self.entry_metadata(self._io.stat_at(self.fd_of(row['parent']),row['name'])):fail('stage_changed')
 def close_row(self,row):
  if threading.current_thread() is not self.worker or os.getpid()!=self.pid:return False
  if row['attempted']:return row['closed']
  if row['unknown'] or type(row['fd']) is not int:return False
  row['attempted']=True
  try:
   actual=self._io.fstat(row['fd'])
   if row['kind']=='directory':
    if self.identity(actual,row['mode'])!=row['identity']:fail('stage_unknown')
   elif executor._meta(actual)!=row['metadata']:fail('stage_unknown')
   returned=os.close(row['fd'])
   try:self._io.fstat(row['fd'])
   except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
  except BaseException:pass
  return row['closed']
 def publish(self,parent,name,raw,mode):
  if self._task.phase!='write' or not (parent is self.runtime and name in tuple(item+'.py' for item,pin in PINS) and mode==0o400 or parent is self.native and name=='mta-wpa-supplicant' and mode==0o500 or parent is self.run and name in ('candidate.json','static-source.json') and mode==0o400):fail('stage_owner')
  self.authenticate();parent_fd=self.fd_of(parent)
  row={'kind':'file','parent':parent,'name':name,'fd':None,'metadata':None,'identity':None,'mode':mode,'unknown':True,'attempted':False,'closed':False}
  self.rows.append(row);self.writes.append(row)
  try:
   row['fd']=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent_fd)
   if type(row['fd']) is not int or row['fd']<0 or any(item is not row and item['fd']==row['fd'] and not item['closed'] for item in self.rows):fail('stage_unknown')
   row['metadata']=executor._meta(self._io.fstat(row['fd']))
   if not stat.S_ISREG(row['metadata'][2]) or row['metadata'][3:6]!=(0,0,1) or stat.S_IMODE(row['metadata'][2])!=0o600:fail('stage_unknown')
   row['identity']=row['metadata'][:6];row['unknown']=False;position=0
   while position<len(raw):
    self.authenticate();self.fd_of(parent);self.check()
    count=os.write(row['fd'],raw[position:position+65536])
    if type(count) is not int or not 1<=count<=min(65536,len(raw)-position):fail('stage_unknown')
    position+=count;actual=executor._meta(self._io.fstat(row['fd']))
    if actual[:6]!=row['identity'] or actual[6]!=position:fail('stage_unknown')
    row['metadata']=actual
   os.fsync(row['fd']);os.lseek(row['fd'],0,0);parts=[];size=0
   while size<=len(raw):
    self.check();part=os.read(row['fd'],min(65536,len(raw)+1-size))
    if type(part) is not bytes:fail('stage_unknown')
    parts.append(part);size+=len(part)
    if not part:break
   if b''.join(parts)!=raw or executor._meta(self._io.fstat(row['fd']))!=row['metadata']:fail('stage_unknown')
   os.fchmod(row['fd'],mode);os.fsync(row['fd']);actual=executor._meta(self._io.fstat(row['fd']))
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
 def stage(self,token,payloads,wpa,candidate_raw,record_raw):
  if self.stage_attempted or token!=self._task.token or self._task.phase!='write':fail('stage_owner')
  self.stage_attempted=True
  if type(token) is not str or re.fullmatch('[0-9a-f]{32}',token) is None:fail('stage_shape')
  if type(payloads) is not dict or set(payloads)!=set(name for name,size,pin in SOURCE_PINS):fail('stage_shape')
  for name,size,pin in SOURCE_PINS:
   if type(payloads[name]) is not bytes or len(payloads[name])!=size or hashlib.sha256(payloads[name]).hexdigest()!=pin:fail('stage_shape')
  if type(wpa) is not bytes or len(wpa)!=WPA_BYTES or hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_shape')
  if type(candidate_raw) is not bytes or not 1<=len(candidate_raw)<=65536 or type(record_raw) is not bytes or not 1<=len(record_raw)<=65536:fail('stage_shape')
  candidate=candidate_document();candidate_sha=hashlib.sha256(candidate_raw).hexdigest()
  if not _same_tree(json_codec.loads(candidate_raw.decode('utf-8')),candidate):fail('stage_shape')
  if not _same_tree(json_codec.loads(record_raw.decode('utf-8')),source_record(token,candidate_sha)):fail('stage_shape')
  run_name='client-'+token
  self.prepare();self.private_root=self.open_dir(self.tmp,'p011-mta-client-rfinit',0o700)
  self.entries_before=self.root_entries()
  if len(self.entries_before)>=MAX_ROOT_ENTRIES:fail('stage_entries')
  if run_name in dict(self.entries_before):fail('stage_exists')
  self._task._before_original(True);self.authenticate()
  self.run=self.directory(self.private_root,run_name)
  self.runtime=self.directory(self.run,'runtime');self.native=self.directory(self.run,'native');self.ctrl=self.directory(self.run,'ctrl')
  for name,pin in PINS:
   if hashlib.sha256(payloads[name]).hexdigest()!=pin:fail('stage_unknown')
   self.publish(self.runtime,name+'.py',payloads[name],0o400)
  if hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_unknown')
  self.publish(self.native,'mta-wpa-supplicant',wpa,0o500)
  self.publish(self.run,'candidate.json',candidate_raw,0o400);self.publish(self.run,'static-source.json',record_raw,0o400)
  self.retained_entries();self.layout(self.run,('runtime','native','ctrl','candidate.json','static-source.json'))
  self.layout(self.runtime,tuple(name+'.py' for name,pin in PINS));self.layout(self.native,('mta-wpa-supplicant',));self.empty(self.ctrl)
  for row in (self.runtime,self.native,self.ctrl,self.run,self.private_root):
   self.authenticate();os.fsync(self.fd_of(row));self.fd_of(row)
  self.authenticate()
 def close(self):
  if self.close_attempted:return not self.pending
  self.close_attempted=True
  good=True
  for row in reversed(self.rows):good=self.close_row(row) and good
  self.pending=not good
  return good
 def inventory(self):
  return tuple({key:row.get(key) for key in ('kind','name','fd','metadata','identity','mode','unknown','attempted','closed')} for row in self.rows)


class StaticStagingTask(object):
    """One original same-worker 120s static write task, no RF lease.

    The task creates its own two original readonly owners. No saved snapshot,
    boolean, caller owner, manifest path or arbitrary clock can grant writes.
    The 4b9 readonly definitions/leaf stay original; 0ea4 sources are only bytes.
    No Store/Coord acquire, F/Parent/watchdog, deployment or user-directory IO.
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
        self.candidate_sha=None;self.before=None;self.after=None
    def now(self):
        value=self.clock()
        if self.clock is not time.monotonic or self.until is not self._original_until or threading.current_thread() is not self.worker or os.getpid()!=self.pid or type(value) not in (int,float) or not math.isfinite(float(value)) or not 0<=value<1e12 or self.last is not None and value<self.last:
            fail('stage_task')
        self.last=float(value)
        if value>=self.until:fail('stage_budget')
        return float(value)
    def _writer_gate(self, writer):
        self.now()
        if type(writer) is not StageOwner or writer is not self.writer or writer._task is not self or not self.writer_constructor_returned or self.phase not in ('write','after_read','final_readback'):
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
        if self.writer_constructor_attempted and (not self.writer_constructor_returned or type(self.writer) is not StageOwner or self.writer._task is not self or not self.writer_closed or self.writer.pending or any(item['unknown'] or not item['closed'] for item in self.writer.rows)):
            return False
        return True
    def run(self, payloads, wpa):
        self.now()
        if self.attempted or self.ended:fail('stage_attempted')
        self.attempted=True
        try:
            if type(payloads) is not dict or set(payloads)!=set(name for name,size,pin in SOURCE_PINS):fail('stage_shape')
            for name,size,pin in SOURCE_PINS:
                raw=payloads[name]
                if type(raw) is not bytes or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=pin:fail('stage_shape')
            if type(wpa) is not bytes or len(wpa)!=WPA_BYTES or hashlib.sha256(wpa).hexdigest()!=WPA_SHA:fail('stage_shape')
            candidate_raw=json_codec.dumps(candidate_document(),sort_keys=True).encode('utf-8')
            self.candidate_sha=hashlib.sha256(candidate_raw).hexdigest()
            record_raw=json_codec.dumps(source_record(self.token,self.candidate_sha),sort_keys=True).encode('utf-8')
            self.before=self._read_phase('before_read');self._before_original(True)
            self.phase='write';self.writer_constructor_attempted=True
            writer=StageOwner(self);self.writer=writer;self.writer_constructor_returned=True
            writer.stage(self.token,payloads,wpa,candidate_raw,record_raw)
            self.after=self._read_phase('after_read')
            before=self._before_original();after=self._original_read(self.after,True)
            if before.key()!=after.key() or self.before['owner'].platform_before!=self.after['owner'].platform_after:
                fail('stage_baseline_changed')
            self.phase='final_readback';writer.verify_static();self.now()
        except BaseException as error:
            self.error=error;raise
        finally:
            # Only original retained known FDs are closed, once, even if late.
            # Partial new directory/file results remain; no delete or retry.
            if self.writer is not None:self.writer_closed=self.writer.close()
            self.ended=True;self.phase='ended'
        try:
            if not self._resources_closed():fail('stage_unclosed')
            self.now()
        except BaseException as error:
            self.error=error;raise
        self.success=True
        return self
    def status(self):
        try:closed=self._resources_closed()
        except BaseException:closed=False
        return {'evidence':'CLIENT_STATIC_STAGE_V40_ONLY',
            'loaded_readonly_map_sha256':READONLY_MANIFEST_SHA,'staged_native_map_sha256':SOURCE_MANIFEST_SHA,
            'readonly_leaf_sha256':READONLY_LEAF_SHA,'attempted':self.attempted,'ended':self.ended,
            'staging_attempted':bool(self.writer is not None and self.writer.stage_attempted),
            'before_read_closed':bool(self.before is not None and self.before['returned']),
            'after_read_closed':bool(self.after is not None and self.after['returned']),
            'static_sources_staged':self.success,'resource_pending':not closed,
            'stage_native_files':len(self.writer.writes) if self.writer is not None else 0,
            'original_root_entries':len(self.writer.entries_before) if self.writer is not None and self.writer.entries_before is not None else 0,
            'device_exclusive_lease':False,'rf_admission':False,'deployment_available':False,
            'source_factory_ready':False,'rf_requested':False,'parent_started':False,
            'send_available':False,'receive_available':False,'phone_tested':False,'restoration_verified':False}
