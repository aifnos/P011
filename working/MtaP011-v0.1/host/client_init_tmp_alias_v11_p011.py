"""Fixed tmp-alias v11 CLIENT init/restore; default source-only, no RF.

This new entry reuses SHA-protected v10 HOST infrastructure. Only the fixed
20-source graph, candidate/log labels and FD-relative TARGET staging differ.
No fallback, old-stage cleanup, alias replacement or production gate exists.
"""
import hashlib
from pathlib import Path

_INFRA_SHA = 'cb50e2a92b669b64061f9872bcbb27265d3b3818517cc95cfabeaef3f8e714df'
_INFRA_PATH = Path(__file__).absolute().parent / 'client_init_prepare_v10_p011.py'
_INFRA_RAW = _INFRA_PATH.read_bytes()
if hashlib.sha256(_INFRA_RAW).hexdigest() != _INFRA_SHA:
    raise ValueError('infra_pin')


def _replace_once(value, before, after):
    if value.count(before) != 1: raise ValueError('infra_delta')
    return value.replace(before, after, 1)


_INFRA_CODE = _replace_once(_INFRA_RAW,
    b"if __name__ == '__main__': sys.exit(main())", b'')
_INFRA_CODE = _replace_once(_INFRA_CODE,
    b"'kind': 'client-init-prepare-v10'", b"'kind': 'client-init-tmp-alias-v11'")
_INFRA_CODE = _replace_once(_INFRA_CODE,
    b"'MtaP011-ClientInitPrepareV10-'", b"'MtaP011-ClientInitTmpAliasV11-'")
# Preserve this entry's __file__: the inherited source check hashes THIS driver.
exec(compile(_INFRA_CODE, '<sha-protected-prepare-v10-host-infrastructure>', 'exec'), globals())
__doc__ = 'Fixed tmp-alias v11 CLIENT init/restore; default source-only, no RF.'

_V10_PINS, _V10_LOCATIONS, _V10_TARGET = PINS, dict(SOURCE_LOCATIONS), TARGET
# These five SOURCE pins were supplied after their owners stopped writing.
EXECUTOR_SHA = '1e8e1632b9170964f8471f106a50988e2d75ccfba7b1c5ed49a604323d481e43'
PROVIDER_SHA = '4f4cec03ddec5ec8e91f9f04ccdc91beb7e54a725a1481ba73c7045338883df6'
_ALIAS_SHA = '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'
_COORD_SHA = '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f'
_FILES_SHA = '8bb891db2ec7d34a40420aef9633ef1c6798f93788bbe240732b1a0c4624b1f6'
_NEW_PINS = {'mta_client_tmp_alias': _ALIAS_SHA,
    'mta_client_coordination': _COORD_SHA, 'mta_client_files': _FILES_SHA,
    'mta_client_executor': EXECUTOR_SHA, 'mta_client_linux_provider': PROVIDER_SHA}
PINS = tuple(row for name, pin in _V10_PINS for row in
    (((name, _NEW_PINS.get(name, pin)), ('mta_client_tmp_alias', _ALIAS_SHA))
     if name == 'mta_ip' else ((name, _NEW_PINS.get(name, pin)),)))
SOURCE_LOCATIONS.update({name: BASE / ('candidate/client-tmp-alias-v11/runtime/' + name + '.py')
    for name in _NEW_PINS})
_FROZEN = all(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) for pin in _NEW_PINS.values())
_source_check_v10 = source_check


def source_check():
    if not _FROZEN:
        return ({'source_check_pass': False, 'provider_stable': False, 'stage': 'unavailable',
            'reason': 'unavailable', 'source_count': 0, 'send_available': False,
            'receive_available': False, 'phone_tested': False,
            'driver_sha256': _hash(_read(Path(__file__).absolute(), None))}, [], b'', {}, None)
    return _source_check_v10()


_STAGE_OWNER = r'''
class StageIo(object):
 def stat_root(self):return os.stat('/',follow_symlinks=False)
 def stat_at(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
 def fstat(self,fd):return os.fstat(fd)
 def readlink_at(self,fd,name):return os.readlink(name,dir_fd=fd)
class StageOwner(object):
 def __init__(self):
  self._io=StageIo();self._tmp_alias=None;self.rows=[];self.mutations=[]
  self.root=None;self.tmp=None;self.private_root=None;self.run=None;self.runtime=None;self.native=None;self.ctrl=None
  self.pending=True;self.close_attempted=False
 def check(self):check()
 def identity(self,value,mode=None):
  meta=f._meta(value)
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
  row['metadata']=f._meta(self._io.fstat(row['fd']));row['identity']=self.identity(self._io.fstat(row['fd']),mode);row['unknown']=False
  after=self.identity(self._io.stat_root() if parent is None else self._io.stat_at(parent_fd,name),mode)
  if before!=row['identity'] or after!=row['identity']:fail('stage_unknown')
  return row
 def open_prefix(self,parent,name):
  if parent is self.root and name=='var':return self.open_dir(parent,name,0o755)
  if self._tmp_alias is not None and any(parent is item for item in self._tmp_alias.prefix_tickets) and name=='volatile':return self.open_dir(parent,name,0o1777)
  fail('stage_unknown')
 def authenticate(self):
  if self._tmp_alias is None or self._tmp_alias.authenticate(self,self.root) is not self._tmp_alias:fail('stage_unknown')
  self.fd_of(self.tmp)
 def prepare(self):
  self.root=self.open_dir(None,'/')
  self._tmp_alias=ta.FixedTmpAnchor(self,self._io,self.root,self.fd_of,self.open_prefix,self.check)
  if self._tmp_alias.prepare() is not self._tmp_alias:fail('stage_unknown')
  self.tmp=self.open_dir(self._tmp_alias.tmp_parent,'tmp',0o1777)
  if self._tmp_alias.bind_tmp(self.tmp) is not self._tmp_alias:fail('stage_unknown')
  self.authenticate()
 def directory(self,parent,name,existing=False):
  self.authenticate();parent_fd=self.fd_of(parent);present=False
  if existing:
   try:self._io.stat_at(parent_fd,name);present=True
   except OSError as error:
    if type(error.errno) is not int or error.errno!=errno.ENOENT:raise
  if not present:
   op={'kind':'mkdir','name':name,'parent_fd':parent_fd,'attempted':True,'returned':False};self.mutations.append(op)
   os.mkdir(name,0o700,dir_fd=parent_fd);op['returned']=True
  return self.open_dir(parent,name,0o700)
 def empty(self,row):
  self.authenticate()
  if os.listdir(self.fd_of(row)):fail('stage_exists')
 def close_row(self,row):
  if row['attempted']:return row['closed']
  if row['unknown'] or type(row['fd']) is not int:return False
  row['attempted']=True
  try:
   actual=self._io.fstat(row['fd'])
   if row['kind']=='directory':
    if self.identity(actual,row['mode'])!=row['identity']:fail('stage_unknown')
   elif f._meta(actual)!=row['metadata']:fail('stage_unknown')
   returned=os.close(row['fd'])
   try:self._io.fstat(row['fd'])
   except OSError as error:row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
  except BaseException:pass
  return row['closed']
 def publish(self,parent,name,raw,mode):
  self.authenticate();parent_fd=self.fd_of(parent)
  row={'kind':'file','parent':parent,'name':name,'fd':None,'metadata':None,'identity':None,'mode':mode,'unknown':True,'attempted':False,'closed':False}
  self.rows.append(row);private['writes'].append(row)
  try:
   row['fd']=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent_fd)
   if type(row['fd']) is not int or row['fd']<0 or any(item is not row and item['fd']==row['fd'] and not item['closed'] for item in self.rows):fail('stage_unknown')
   row['metadata']=f._meta(self._io.fstat(row['fd']))
   if not stat.S_ISREG(row['metadata'][2]) or row['metadata'][3:6]!=(0,0,1) or stat.S_IMODE(row['metadata'][2])!=0o600:fail('stage_unknown')
   row['identity']=row['metadata'][:6];row['unknown']=False;position=0
   while position<len(raw):
    self.authenticate();self.fd_of(parent);self.check()
    count=os.write(row['fd'],raw[position:position+65536])
    if type(count) is not int or not 1<=count<=min(65536,len(raw)-position):fail('stage_unknown')
    position+=count;actual=f._meta(self._io.fstat(row['fd']))
    if actual[:6]!=row['identity'] or actual[6]!=position:fail('stage_unknown')
    row['metadata']=actual
   os.fsync(row['fd']);os.lseek(row['fd'],0,0);parts=[];size=0
   while size<=len(raw):
    self.check();part=os.read(row['fd'],min(65536,len(raw)+1-size))
    if type(part) is not bytes:fail('stage_unknown')
    parts.append(part);size+=len(part)
    if not part:break
   if b''.join(parts)!=raw or f._meta(self._io.fstat(row['fd']))!=row['metadata']:fail('stage_unknown')
   os.fchmod(row['fd'],mode);os.fsync(row['fd']);actual=f._meta(self._io.fstat(row['fd']))
   expected=row['identity'][:2]+(stat.S_IFREG|mode,)+row['identity'][3:]+(len(raw),)
   if actual!=expected:fail('stage_unknown')
   row['metadata']=actual
   self.authenticate()
   if row['metadata']!=f._meta(self._io.stat_at(self.fd_of(parent),name)) or stat.S_IMODE(row['metadata'][2])!=mode:fail('stage_unknown')
  finally:
   if not self.close_row(row):self.pending=True;public['resource_pending']=True
  if not row['closed']:fail('stage_unknown')
 def layout(self,row,names):
  self.authenticate()
  if sorted(os.listdir(self.fd_of(row)))!=sorted(names):fail('stage_unknown')
 def stage(self,run_name,payloads,wpa,candidate_raw,deployment_raw):
  self.prepare();self.private_root=self.directory(self.tmp,'p011-mta-client-rfinit',True);self.empty(self.private_root)
  self.run=self.directory(self.private_root,run_name)
  self.runtime=self.directory(self.run,'runtime');self.native=self.directory(self.run,'native');self.ctrl=self.directory(self.run,'ctrl')
  for name,pin in PINS:
   if hashlib.sha256(payloads[name]).hexdigest()!=pin:fail('stage_unknown')
   self.publish(self.runtime,name+'.py',payloads[name],0o400)
  if hashlib.sha256(wpa).hexdigest()!=WPA_SHA or hashlib.sha256(candidate_raw).hexdigest()!=CANDIDATE_SHA:fail('stage_unknown')
  self.publish(self.native,'mta-wpa-supplicant',wpa,0o500)
  self.publish(self.run,'candidate.json',candidate_raw,0o400);self.publish(self.run,'deployment.json',deployment_raw,0o400)
  self.layout(self.private_root,(run_name,));self.layout(self.run,('runtime','native','ctrl','candidate.json','deployment.json'))
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
'''

_DIRECTORY_OLD = _V10_TARGET[_V10_TARGET.index('def directory('):_V10_TARGET.index('def read_proc(')]
_PUBLISH_OLD = _V10_TARGET[_V10_TARGET.index('def publish('):_V10_TARGET.index('before=after=None;')]
_STAGING_OLD = _V10_TARGET[_V10_TARGET.index(" pending_absent();public['stage']='stage'"):
    _V10_TARGET.index(' loader=f.DeploymentLoader')]
_STAGING_NEW = r'''
 pending_absent();public['stage']='stage';public['staging_attempted']=True
 stage_owner=StageOwner();private['owners'].append(stage_owner)
 stage_row={'kind':'stage','owner':stage_owner,'unknown':False};private['reads'].append(stage_row)
 try:
  wpa=base64.b64decode(WPA_ENCODED.encode('ascii'),validate=True)
  candidate_raw=base64.b64decode(CANDIDATE_ENCODED.encode('ascii'),validate=True)
  if codec.loads(candidate_raw.decode('utf-8'))!=codec.loads(codec.dumps(CANDIDATE)):fail('stage_unknown')
  stage_owner.stage('client-'+TOKEN,payloads,wpa,candidate_raw,deployment_raw)
 finally:
  if not stage_owner.close():public['resource_pending']=True
  private['stage_inventory']=stage_owner.inventory();private['stage_mutations']=tuple(stage_owner.mutations)
 if stage_owner.pending:fail('stage_unknown')
'''
TARGET = _replace_once(_V10_TARGET,
    "pm=modules['mta_client_linux_provider'];codec=modules['p011_json']",
    "pm=modules['mta_client_linux_provider'];codec=modules['p011_json'];ta=modules['mta_client_tmp_alias']")
TARGET = _replace_once(TARGET, _DIRECTORY_OLD, '')
TARGET = _replace_once(TARGET, _PUBLISH_OLD, _STAGE_OWNER)
TARGET = _replace_once(TARGET, 'before=after=None;provider=None;parent=None',
    'before=after=None;provider=None;parent=None;stage_owner=None')
TARGET = _replace_once(TARGET, "'wpa_exe':run+'/native/mta-wpa-supplicant'",
    "'wpa_exe':f.PHYSICAL_ROOT+'/client-'+TOKEN+'/native/mta-wpa-supplicant'")
TARGET = _replace_once(TARGET, _STAGING_OLD, _STAGING_NEW)


if __name__ == '__main__': sys.exit(main())
