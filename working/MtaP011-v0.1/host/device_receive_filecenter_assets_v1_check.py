"""Fixed FileCenter and MTA UI assets: PC-only by default, not a UI launch.

Only explicit --stage-device may exclusively create the absent fixed UI bundle
and run the pinned ui_assets.validate_assets(until). Existing complete exact
assets are accepted; partial/unknown/conflicting session entries stay untouched.
Other mta-ui sessions are preserved without traversal or authentication.
No Qt, Boot, Owner, credentials, RF, receive/send, old pending or process action.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import types
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
SESSION = 'b6a84fe755092535bb996f40'
BUNDLE = 'out/mta-ui-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
VALIDATOR = ('candidate/receive-filecenter-v1/runtime/ui_assets.py', 12509,
             '63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
STOCK_PINS = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
)
ELF_BYTES = 4103844
PINS = (
    ('Bridge.qml', 1007, '73454ae237dcfc75cac8f82045bde9fbf24339797ece9def1dc7b972cc0c96ae'),
    ('FormalEntry.qml', 4079, '2310e99d70e53903e390598a82f9d2c46ae03c1621bc0fa4505c39349830cb3d'),
    ('ReceiveComposition.qml', 401, '6f1701b31faa62822dcf3e51afd74e001c000d588c6df1cba8b6700e8320ac39'),
    ('Z03.mta-ui-candidate', 4103844, '6e8d5aab7a9c0af6e83ba2d4eb09c37054f175de294169c099357f300aef985c'),
    ('mta/MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('mta/MtaHost.qml', 6341, 'e610b343fe4058bb89d45ee65cb14bdd4471363b56a737d85ab5c51297e42f11'),
    ('mta/MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('mta/MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('mta/MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('mta/MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
    ('toolbox/Button.qml', 665, 'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('toolbox/ExtensionPage.qml', 10109, 'e2ea4ac96acda29509df272001599be9410d5989a2400bfaef73901378062093'),
    ('toolbox/FilesPage.qml', 11639, '5f1b4255211f4369f64dfc24eddcc565d6e6a64f708e181e15b68828376bd1e1'),
    ('toolbox/Label.qml', 269, '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    ('toolbox/MtaEmbedded.qml', 6543, 'cf5e0c34eae957e8f6ebd5c0641ff7d6d177cb8407db3957049255e6e94e095b'),
    ('toolbox/NativeIcon.qml', 1999, '08baa5b5b7176fc5abaa59c5ef261f0474c05565838a68fa6c110aed80867f4d'),
    ('toolbox/Theme.js', 244, '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
    ('toolbox/VideoPane.qml', 705, 'e09873e298aa6b762051ab866ca82ea5b44f0d2988ab97e6ad6719c947934651'),
)
MANIFEST = ('SOURCE.sha256', 1603, 'b334d5ebc0598ca0583406efed9c063894e30c97186e12b28846545a8600ad24')
ASSET_PINS = PINS + (MANIFEST,)
ROOT_NAMES = ('Bridge.qml', 'FormalEntry.qml', 'ReceiveComposition.qml', 'SOURCE.sha256',
              'Z03.mta-ui-candidate', 'mta', 'toolbox')
MTA_NAMES = ('MtaButton.qml', 'MtaHost.qml', 'MtaKeyboard.qml', 'MtaLabel.qml', 'MtaPage.qml', 'MtaTheme.js')
TOOLBOX_NAMES = ('Button.qml', 'ExtensionPage.qml', 'FilesPage.qml', 'Label.qml',
                 'MtaEmbedded.qml', 'NativeIcon.qml', 'Theme.js', 'VideoPane.qml')
BOOL_FIELDS = ('platform_validated', 'payload_validated', 'before_observed', 'after_observed',
               'payload_framed_end_verified',
               'stock_before_observed', 'stock_after_observed', 'stock_hashes_match', 'stock_unchanged',
               'existing_assets_unchanged', 'stage_verified', 'validator_called', 'assets_verified',
               'inventory_verified', 'credentials_absent_verified', 'original_fds_closed',
               'validator_fds_closed', 'resource_pending', 'staging_pending', 'complete')
COUNT_FIELDS = ('created_directory_count', 'created_file_count', 'original_opened_fd_count',
                'original_closed_fd_count', 'validator_opened_fd_count', 'validator_closed_fd_count',
                'validator_files_verified', 'validator_readback_passes')
REASONS = ('not_started', 'complete', 'unsupported_platform', 'payload', 'deadline', 'unsafe_anchor',
           'payload_wire', 'stock_baseline', 'stock_changed', 'asset_conflict', 'asset_changed', 'stage_io',
           'namespace_busy', 'validator', 'close', 'unexpected')
FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS + ('reason',))
HOST_ERROR_CODES = ('fixed_path', 'fixed_ancestor', 'fixed_link', 'fixed_file', 'fixed_identity',
                    'fixed_changed', 'fixed_pin', 'payload_budget', 'manifest_bytes',
                    'target_source_budget', 'payload_wire_budget', 'transport_identity',
                    'remote_result_unknown', 'result_fields', 'zip_readback')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def host_metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    # The one fixed ELF is larger than the old generic 2 MiB helper ceiling.
    # No supplied path or file can exceed its actual pinned 4,103,844 bytes.
    if (type(name) is not str or not name or '\\' in name or PurePosixPath(name).is_absolute() or
            re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))): raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode): raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= ELF_BYTES: raise ValueError('fixed_file')
    before = host_metadata(value)
    with path.open('rb') as handle:
        opened = host_metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(ELF_BYTES + 1)
        if host_metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if host_metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin: raise ValueError('fixed_pin')
    return raw


def chunks(raw):
    encoded = base64.b64encode(zlib.compress(raw)).decode('ascii')
    return '\n'.join('    ' + repr(encoded[index:index + 1024]) for index in range(0, len(encoded), 1024))


def payload_frame(raw):
    encoded = base64.b64encode(zlib.compress(raw))
    return b''.join(encoded[index:index + 1024] + b'\n' for index in range(0, len(encoded), 1024))


TARGET = r'''
import base64,errno,hashlib,math,os,re,signal,stat,sys,threading,time,types,zlib
_RETAINED=None

class UiStageError(ValueError):
 def __init__(self,code):
  self.code=code
  ValueError.__init__(self,code)

def need(condition,code):
 if not condition:raise UiStageError(code)

def input_deadline(signum,frame):
 raise UiStageError('deadline')

def meta(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
         value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def fixed_decode(encoded,size,sha):
 need(type(size) is int and 0<size<=4103844,'payload')
 decoder=zlib.decompressobj();raw=decoder.decompress(base64.b64decode(encoded,validate=True),size+1)
 need(len(raw)==size and not decoder.unconsumed_tail and not decoder.unused_data and
      decoder.eof and hashlib.sha256(raw).hexdigest()==sha,'payload')
 return raw

class UiStage(object):
 def __init__(self):
  self.pid=os.getpid();self.worker=threading.current_thread()
  self.last=time.monotonic();self.until=self.last+60.0;self.in_cleanup=False
  self.outer_handler=signal.getsignal(signal.SIGALRM)
  outer_timer=signal.getitimer(signal.ITIMER_REAL)
  self.outer_until=self.last+outer_timer[0];self.outer_interval=outer_timer[1]
  self.rows=[];self.edges=[];self.file_edges=[];self.creations=[];self.failures=[]
  self.first_error=None;self.validator=None;self.validator_error=None;self.validator_facts=None
  self.artifacts={};self.root=None;self.mount=None;self.data=None;self.area=None
  self.ui_root=None;self.session=None;self.mta=None;self.toolbox=None
  self.before=None;self.after=None;self.stock_before=None;self.stock_after=None
  self.result=dict((key,False) for key in BOOL_FIELDS)
  self.result.update(dict((key,0) for key in COUNT_FIELDS));self.result['reason']='not_started'

 def check(self):
  now=time.monotonic()
  need(os.getpid()==self.pid and threading.current_thread() is self.worker and
       math.isfinite(now) and now>=self.last and now<(self.until+60.0 if self.in_cleanup else self.until),'deadline')
  self.last=now

 def platform(self):
  need(sys.platform=='linux' and os.geteuid()==0 and sys.byteorder=='little' and
       os.uname()[4]=='armv7l' and sys.version_info[:3]==(3,5,5) and
       os.O_NOFOLLOW==0x8000 and os.O_CLOEXEC==0x80000,'unsupported_platform')
  need(self.outer_handler==signal.SIG_DFL and self.outer_interval==0.0 and
       math.isfinite(self.outer_until) and self.outer_until>=self.until+60.0,'deadline')
  self.result['platform_validated']=True

 def payload(self):
  need(type(ARTIFACT_ROWS) is tuple and len(ARTIFACT_ROWS)==19 and
       sum(pin[1] for pin in ASSET_PINS)==4182249 and sum(pin[1] for pin in ASSET_PINS)<4*1024*1024,'payload')
  need(type(WIRE_PIN) is tuple and len(WIRE_PIN)==2 and type(WIRE_PIN[0]) is int and
       0<WIRE_PIN[0]<=6*1024*1024 and type(WIRE_PIN[1]) is str and
       re.fullmatch(r'[0-9a-f]{64}',WIRE_PIN[1]) is not None,'payload_wire')
  need(type(TRAILER_EXPECTED) is bytes and
       re.fullmatch(b'MTA_RECEIVE_FILECENTER_ASSETS_V1_END [0-9a-f]{64}\n',TRAILER_EXPECTED) is not None,'payload_wire')
  total=0
  for row,pin in zip(ARTIFACT_ROWS,ASSET_PINS):
   need(type(row) is tuple and len(row)==4 and row[:3]==pin and
        type(row[3]) is int and 0<row[3]<=6*1024*1024,'payload_wire')
   total+=row[3]
  need(total==WIRE_PIN[0]-len(TRAILER_EXPECTED),'payload_wire')
  wire_hasher=hashlib.sha256()
  for row,pin in zip(ARTIFACT_ROWS,ASSET_PINS):
   need(pin[0] not in self.artifacts,'payload')
   frame=self.read_frame(row[3]);wire_hasher.update(frame)
   self.artifacts[pin[0]]=fixed_decode(frame.replace(b'\n',b''),pin[1],pin[2])
  self.check()
  need(TRAILER_EXPECTED==b'MTA_RECEIVE_FILECENTER_ASSETS_V1_END '+wire_hasher.hexdigest().encode('ascii')+b'\n','payload_wire')
  trailer_parts=[];trailer_count=0
  while trailer_count<len(TRAILER_EXPECTED):
   raw=self.read_stdin(len(TRAILER_EXPECTED)-trailer_count)
   need(type(raw) is bytes and 0<len(raw)<=len(TRAILER_EXPECTED)-trailer_count,'payload_wire')
   trailer_parts.append(raw);trailer_count+=len(raw)
  trailer=b''.join(trailer_parts);wire_hasher.update(trailer);self.check()
  need(trailer==TRAILER_EXPECTED and wire_hasher.hexdigest()==WIRE_PIN[1],'payload_wire')
  self.result['payload_framed_end_verified']=True
  expected=''.join(sha+' '+str(size)+' '+path+'\n' for path,size,sha in ASSET_PINS[:-1]).encode('ascii')
  need(self.artifacts['SOURCE.sha256']==expected,'payload')
  self.validator_raw=fixed_decode(VALIDATOR_ENCODED,VALIDATOR_PIN[0],VALIDATOR_PIN[1])
  need(VALIDATOR_PIN==(12509,'63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5'),'payload')
  self.result['payload_validated']=True

 def read_frame(self,length):
  need(type(length) is int and 0<length<=6*1024*1024,'payload_wire')
  pieces=[];count=0
  while count<length:
   self.check();raw=self.read_stdin(min(65536,length-count))
   need(type(raw) is bytes and 0<len(raw)<=min(65536,length-count),'payload_wire')
   pieces.append(raw);count+=len(raw)
  self.check();frame=b''.join(pieces)
  need(frame.endswith(b'\n') and re.fullmatch(b'[A-Za-z0-9+/=\n]+',frame) is not None,'payload_wire')
  lines=frame.split(b'\n')
  need(lines[-1]==b'' and len(lines)>=2 and 0<len(lines[-2])<=1024 and
       all(len(line)==1024 for line in lines[:-2]),'payload_wire')
  return frame

 def restore_input_timer(self):
  # Restore the original absolute outer deadline, never renew its 180 seconds.
  signal.setitimer(signal.ITIMER_REAL,0.0)
  signal.signal(signal.SIGALRM,self.outer_handler)
  remaining=self.outer_until-time.monotonic()
  need(math.isfinite(remaining) and remaining>0.0,'deadline')
  signal.setitimer(signal.ITIMER_REAL,remaining)

 def read_stdin(self,length):
  self.check();need(type(length) is int and 0<length<=65536,'payload_wire')
  remaining=self.until-time.monotonic()
  need(math.isfinite(remaining) and remaining>0.0 and
       signal.getsignal(signal.SIGALRM)==self.outer_handler,'deadline')
  try:
   signal.signal(signal.SIGALRM,input_deadline)
   signal.setitimer(signal.ITIMER_REAL,remaining)
   return sys.stdin.buffer.read(length)
  finally:self.restore_input_timer()

 def open_fd(self,name,parent=None,flags=None,mode=0o400):
  self.check()
  row=dict(fd=None,original_fd=None,metadata=None,closed=False,unknown=True,
           close_called=False,close_error=None,open_error=None)
  self.rows.append(row)
  try:
   value=os.open(name,(os.O_RDONLY if flags is None else flags)|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,
                 mode,**({} if parent is None else {'dir_fd':parent}))
   row['fd']=row['original_fd']=value
   need(type(value) is int and 0<=value<=0x7fffffff,'stage_io')
   row['metadata']=meta(os.fstat(value));row['unknown']=False
   self.check()
   return row
  except BaseException as error:
   row['open_error']=error
   if (row['fd'] is None and isinstance(error,OSError) and
       type(error.errno) is int and 1<=error.errno<=4095):
    row['unknown']=False;row['closed']=True
   raise

 def close_fd(self,row):
  if row['closed'] or row['close_called']:return row['closed'] and not row['unknown']
  row['close_called']=True
  try:
   need(os.getpid()==self.pid and threading.current_thread() is self.worker,'close')
   need(type(row['fd']) is int and row['fd']==row['original_fd'] and not row['unknown'] and
        row['metadata'] is not None,'close')
   observed=meta(os.fstat(row['fd']))
   width=5 if stat.S_ISDIR(row['metadata'][2]) else 9
   need(observed[:width]==row['metadata'][:width],'close')
   returned=os.close(row['fd'])
   try:os.fstat(row['fd'])
   except OSError as error:
    row['closed']=returned is None and type(error.errno) is int and error.errno==errno.EBADF
   need(row['closed'],'close')
  except BaseException as error:
   row['unknown']=True;row['close_error']=error;self.failures.append(error)
  return row['closed'] and not row['unknown']

 def directory(self,name,parent,policy):
  row=self.open_fd(name,parent,os.O_RDONLY|os.O_DIRECTORY)
  value=row['metadata']
  need(stat.S_ISDIR(value[2]) and value[5]>=1,'unsafe_anchor')
  if policy=='data':
   need(value[:5]==(66328,21,stat.S_IFDIR|0o755,1000,1000),'unsafe_anchor')
  else:
   need(value[2:5]==(stat.S_IFDIR|(0o700 if policy=='private' else 0o755),0,0),'unsafe_anchor')
  named=meta(os.stat(name,follow_symlinks=False,**({} if parent is None else {'dir_fd':parent})))
  need(named[:5]==value[:5],'unsafe_anchor')
  self.edges.append((parent,name,row));self.bindings_current()
  return row

 def bindings_current(self):
  self.check()
  for parent,name,row in self.edges:
   need(not row['closed'] and not row['unknown'],'asset_changed')
   named=meta(os.stat(name,follow_symlinks=False,**({} if parent is None else {'dir_fd':parent})))
   need(meta(os.fstat(row['fd']))[:5]==row['metadata'][:5]==named[:5],'asset_changed')
  for parent,name,row in self.file_edges:
   need(not row['closed'] and not row['unknown'],'asset_changed')
   named=meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
   need(meta(os.fstat(row['fd']))==row['metadata']==named,'asset_changed')

 def present(self,name,parent):
  self.bindings_current()
  try:return meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
  except OSError as error:
   if type(error.errno) is int and error.errno==errno.ENOENT:return None
   raise

 def inventory(self,row):
  self.bindings_current()
  need(os.lseek(row['fd'],0,os.SEEK_SET)==0,'asset_conflict')
  return tuple(sorted(os.listdir(row['fd'])))

 def read_file(self,parent,name,pin):
  self.bindings_current()
  initial=meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
  mode=0o500 if pin[0]=='Z03.mta-ui-candidate' else 0o400
  need(initial[2:7]==(stat.S_IFREG|mode,0,0,1,pin[1]),'asset_conflict')
  row=self.open_fd(name,parent)
  need(row['metadata']==initial,'asset_conflict')
  self.file_edges.append((parent,name,row))
  for turn in range(2):
   self.bindings_current();need(os.lseek(row['fd'],0,os.SEEK_SET)==0,'asset_conflict')
   hasher=hashlib.sha256();count=0
   while count<pin[1]:
    self.check();raw=os.read(row['fd'],min(65536,pin[1]-count))
    need(type(raw) is bytes and 0<len(raw)<=min(65536,pin[1]-count),'asset_conflict')
    hasher.update(raw);count+=len(raw)
   need(os.read(row['fd'],1)==b'' and hasher.hexdigest()==pin[2],'asset_conflict')
   self.bindings_current()
  return row['metadata']

 def stock_observation(self):
  # This is only the current stock-file identity, never a process/radio check.
  observed=[]
  for path,pinned_sha in STOCK_PINS:
   self.check();initial=meta(os.lstat(path))
   need(stat.S_ISREG(initial[2]) and not initial[2]&0o022 and initial[3:6]==(0,0,1) and
        0<initial[6]<=4103844,'stock_baseline')
   row=self.open_fd(path)
   need(row['metadata']==initial,'stock_changed')
   hasher=hashlib.sha256();count=0
   while count<initial[6]:
    self.check();raw=os.read(row['fd'],min(65536,initial[6]-count))
    need(type(raw) is bytes and 0<len(raw)<=min(65536,initial[6]-count),'stock_baseline')
    hasher.update(raw);count+=len(raw)
   actual=hasher.hexdigest()
   need(os.read(row['fd'],1)==b'' and meta(os.fstat(row['fd']))==initial==meta(os.lstat(path)),
        'stock_changed')
   self.file_edges.append((None,path,row));observed.append((path,initial,actual))
  return tuple(observed)

 def anchors(self):
  root=self.directory('/',None,'public')
  mount=self.directory('mnt',root['fd'],'public')
  data=self.directory('data',mount['fd'],'data')
  self.root,self.mount,self.data=root,mount,data
  self.area=self.directory('p011-toolbox',data['fd'],'private')
  if self.present('mta-ui',self.area['fd']) is not None:
   self.ui_root=self.directory('mta-ui',self.area['fd'],'private')
  # Other sessions below mta-ui are never traversed, read or authenticated.

 def asset_location(self,pin,session,mta,toolbox):
  path=pin[0]
  if path.startswith('mta/'):parent,name=mta['fd'],path[4:]
  elif path.startswith('toolbox/'):parent,name=toolbox['fd'],path[8:]
  else:parent,name=session['fd'],path
  need(type(name) is str and '/' not in name and name not in ('','.','..'),'payload')
  return parent,name

 def inspect_complete(self):
  if self.ui_root is None:return None
  if self.present(SESSION,self.ui_root['fd']) is None:return None
  session=self.directory(SESSION,self.ui_root['fd'],'private')
  need(self.inventory(session)==ROOT_NAMES,'asset_conflict')
  mta=self.directory('mta',session['fd'],'private')
  toolbox=self.directory('toolbox',session['fd'],'private')
  need(self.inventory(mta)==MTA_NAMES and self.inventory(toolbox)==TOOLBOX_NAMES,'asset_conflict')
  files=[]
  for pin in ASSET_PINS:
   parent,name=self.asset_location(pin,session,mta,toolbox)
   files.append((pin[0],self.read_file(parent,name,pin)))
  self.bindings_current()
  need(self.inventory(session)==ROOT_NAMES and self.inventory(mta)==MTA_NAMES and
       self.inventory(toolbox)==TOOLBOX_NAMES,'asset_changed')
  self.session,self.mta,self.toolbox=session,mta,toolbox
  return (session['metadata'][:5],mta['metadata'][:5],toolbox['metadata'][:5],tuple(files))

 def new_directory(self,parent,name):
  self.bindings_current()
  creation=dict(kind='directory',parent=parent,name=name,attempted=True,returned=False,error=None)
  self.creations.append(creation)
  try:
   os.mkdir(name,0o700,dir_fd=parent);creation['returned']=True
   self.result['created_directory_count']+=1
   row=self.directory(name,parent,'private');self.bindings_current()
   os.fsync(parent)
   return row
  except BaseException as error:
   creation['error']=error;raise

 def new_file(self,parent,name,pin):
  self.bindings_current()
  creation=dict(kind='file',parent=parent,name=name,attempted=True,returned=False,error=None)
  self.creations.append(creation)
  try:
   mode=0o500 if pin[0]=='Z03.mta-ui-candidate' else 0o400
   row=self.open_fd(name,parent,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
   creation['returned']=True;self.result['created_file_count']+=1
   initial=row['metadata']
   need(initial[2:7]==(stat.S_IFREG|mode,0,0,1,0),'stage_io')
   data=self.artifacts[pin[0]];offset=0
   while offset<len(data):
    self.bindings_current()
    need(meta(os.fstat(row['fd']))==row['metadata']==
         meta(os.stat(name,dir_fd=parent,follow_symlinks=False)),'asset_changed')
    written=os.write(row['fd'],data[offset:offset+65536])
    need(type(written) is int and 0<written<=min(65536,len(data)-offset),'stage_io')
    offset+=written;row['metadata']=meta(os.fstat(row['fd']))
    need(row['metadata'][:6]==initial[:6] and row['metadata'][6]==offset and
         meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==row['metadata'],'stage_io')
    self.bindings_current()
   os.fsync(row['fd']);row['metadata']=meta(os.fstat(row['fd']))
   need(row['metadata'][:6]==initial[:6] and row['metadata'][6]==len(data) and
        meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==row['metadata'],'stage_io')
   # Keep the original WRONLY FD strong; readback uses another original FD.
   observed=self.read_file(parent,name,pin)
   need(observed==row['metadata'],'asset_changed')
   self.file_edges.append((parent,name,row));self.bindings_current()
  except BaseException as error:
   creation['error']=error;raise

 def stage(self):
  self.bindings_current()
  # Repeat the complete preflight before the first exclusive creation.
  current=self.inspect_complete()
  need(current==self.before,'asset_changed')
  if current is not None:return
  if self.ui_root is None:
   need(self.present('mta-ui',self.area['fd']) is None,'asset_changed')
   self.ui_root=self.new_directory(self.area['fd'],'mta-ui')
  need(self.present(SESSION,self.ui_root['fd']) is None,'asset_changed')
  self.session=self.new_directory(self.ui_root['fd'],SESSION)
  self.mta=self.new_directory(self.session['fd'],'mta')
  self.toolbox=self.new_directory(self.session['fd'],'toolbox')
  for pin in ASSET_PINS:
   parent,name=self.asset_location(pin,self.session,self.mta,self.toolbox)
   self.new_file(parent,name,pin)
  os.fsync(self.mta['fd']);os.fsync(self.toolbox['fd'])
  os.fsync(self.session['fd']);os.fsync(self.ui_root['fd'])
  self.bindings_current()

 def validate(self):
  self.bindings_current();need('ui_assets' not in sys.modules,'namespace_busy')
  self.validator=types.ModuleType('ui_assets');self.validator.__file__='<fixed-ui-assets-stdin>'
  sys.modules['ui_assets']=self.validator
  exec(self.validator_raw,self.validator.__dict__)
  need(self.validator.SESSION==SESSION and self.validator.REMOTE==REMOTE and
       self.validator.PINS==ASSET_PINS[:-1] and self.validator.MANIFEST_PIN==ASSET_PINS[-1][1:] and
       self.validator.ROOT_NAMES==ROOT_NAMES and self.validator.MTA_NAMES==MTA_NAMES and
       self.validator.TOOLBOX_NAMES==TOOLBOX_NAMES,'validator')
  self.result['validator_called']=True
  try:self.validator_facts=self.validator.validate_assets(self.until)
  except BaseException as error:
   self.validator_error=error
   self.validator_facts=getattr(error,'facts',None)
   raise
  facts=self.validator_facts
  expected={'session','remote','assets_verified','files_verified','readback_passes','inventory_verified',
            'fds_opened','fds_closed','resource_pending','credentials_absent_verified','device_runtime_verified',
            'service_connected','radio_admission','directory_bindings','credential_directory_bindings','file_bindings'}
  need(type(facts) is dict and set(facts)==expected and facts['session']==SESSION and
       facts['remote']==REMOTE and all(facts[key] is True for key in
       ('assets_verified','inventory_verified','credentials_absent_verified')) and
       all(facts[key] is False for key in ('resource_pending','device_runtime_verified','service_connected','radio_admission')) and
       type(facts['files_verified']) is int and facts['files_verified']==19 and
       type(facts['readback_passes']) is int and facts['readback_passes']==38 and
       type(facts['fds_opened']) is int and type(facts['fds_closed']) is int and
       facts['fds_opened']==facts['fds_closed']==27 and
       type(facts['directory_bindings']) is tuple and len(facts['directory_bindings'])==8 and
       type(facts['credential_directory_bindings']) is tuple and len(facts['credential_directory_bindings'])==6 and
       type(facts['file_bindings']) is tuple and len(facts['file_bindings'])==19,'validator')
  expected_credentials=tuple((name,row['metadata'][:5]) for name,row in
    (('/',self.root),('mnt',self.mount),('data',self.data),('p011-toolbox',self.area),
     ('mta-ui',self.ui_root),(SESSION,self.session)))
  expected_directories=expected_credentials+(('mta',self.mta['metadata'][:5]),
                                              ('toolbox',self.toolbox['metadata'][:5]))
  observed_files=dict(self.after[3])
  expected_files=tuple((pin[0],observed_files[pin[0]]) for pin in (MANIFEST,)+PINS)
  need(facts['credential_directory_bindings']==expected_credentials and
       facts['directory_bindings']==expected_directories and facts['file_bindings']==expected_files,'validator')
  self.result['assets_verified']=True;self.result['inventory_verified']=True
  self.result['credentials_absent_verified']=True
  self.result['validator_files_verified']=facts['files_verified']
  self.result['validator_readback_passes']=facts['readback_passes']
  self.bindings_current()
  need(self.inventory(self.session)==ROOT_NAMES and self.inventory(self.mta)==MTA_NAMES and
       self.inventory(self.toolbox)==TOOLBOX_NAMES,'asset_changed')

 def run(self):
  try:
   self.platform();self.payload()
   self.stock_before=self.stock_observation();self.result['stock_before_observed']=True
   self.result['stock_hashes_match']=tuple((row[0],row[2]) for row in self.stock_before)==STOCK_PINS
   need(self.result['stock_hashes_match'],'stock_baseline')
   self.anchors()
   self.before=self.inspect_complete();self.result['before_observed']=True
   self.stage();self.after=self.inspect_complete();self.result['after_observed']=True
   need(self.after is not None,'asset_changed')
   self.result['existing_assets_unchanged']=self.before is None or self.before==self.after
   need(self.result['existing_assets_unchanged'],'asset_changed')
   self.result['stage_verified']=True
   self.validate()
  except BaseException as error:
   self.first_error=error;self.failures.append(error)
  finally:
   # The same original worker performs the last file-only stock observation.
   # It has a separate bounded cleanup window; close is not deadline-truncated.
   self.in_cleanup=True
   try:self.restore_input_timer()
   except BaseException as error:self.failures.append(error)
   if self.result['platform_validated'] and self.result['payload_validated']:
    try:
     self.stock_after=self.stock_observation();self.result['stock_after_observed']=True
     self.result['stock_hashes_match']=(self.result['stock_hashes_match'] and
       tuple((row[0],row[2]) for row in self.stock_after)==STOCK_PINS)
     self.result['stock_unchanged']=self.stock_before is not None and self.stock_before==self.stock_after
     need(self.result['stock_hashes_match'],'stock_baseline')
     need(self.result['stock_unchanged'],'stock_changed')
    except BaseException as error:self.failures.append(error)
   for row in reversed(self.rows):self.close_fd(row)
   self.result['original_opened_fd_count']=sum(row['fd'] is not None for row in self.rows)
   self.result['original_closed_fd_count']=sum(row['fd'] is not None and row['closed'] and not row['unknown'] for row in self.rows)
   self.result['original_fds_closed']=all(row['closed'] and not row['unknown'] for row in self.rows)
   facts=self.validator_facts
   if type(facts) is dict:
    for field,key in (('validator_opened_fd_count','fds_opened'),('validator_closed_fd_count','fds_closed')):
     value=facts.get(key)
     if type(value) is int and 0<=value<=8192:self.result[field]=value
    self.result['validator_fds_closed']=(facts.get('resource_pending') is False and
      type(facts.get('fds_opened')) is int and type(facts.get('fds_closed')) is int and
      facts['fds_opened']==facts['fds_closed']==27)
   self.result['resource_pending']=(not self.result['original_fds_closed'] or
      self.result['validator_called'] and not self.result['validator_fds_closed'])
   self.result['staging_pending']=bool(self.creations and not self.result['stage_verified'])
  if self.first_error is None and self.failures:self.first_error=self.failures[0]
  if self.first_error is not None:
   code=getattr(self.first_error,'code',None)
   self.result['reason']=code if code in REASONS else 'validator' if self.validator_error is self.first_error else 'unexpected'
  needed=tuple(key for key in BOOL_FIELDS if key not in ('complete','resource_pending','staging_pending'))
  self.result['complete']=(not self.failures and all(self.result[key] for key in needed) and
                          not self.result['resource_pending'] and not self.result['staging_pending'])
  if self.result['complete']:self.result['reason']='complete'
  return self.result

 def error_detail(self):
  error=self.first_error
  if error is None:return None
  kind=type(error).__name__
  if re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$',kind) is None:kind='unclassified'
  code=getattr(error,'code',None)
  if type(code) is not str or re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$',code) is None:code=None
  native_errno=getattr(error,'errno',None)
  if type(native_errno) is not int or not 1<=native_errno<=4095:native_errno=None
  trace=[];cursor=error.__traceback__
  for turn in range(32):
   if cursor is None:break
   frame=cursor.tb_frame;module=frame.f_globals.get('__name__');function=frame.f_code.co_name
   if (module in ('__main__','ui_assets') and type(function) is str and
       re.match(r'^[A-Za-z_<>][A-Za-z0-9_<>]{0,95}$',function) is not None and
       type(cursor.tb_lineno) is int and 0<cursor.tb_lineno<1000000):
    trace.append((module,function,cursor.tb_lineno))
   cursor=cursor.tb_next
  return {'kind':kind,'code':code,'errno':native_errno,'trace':tuple(trace)}

os.umask(0o077)
_RETAINED=UiStage()
component=_RETAINED.run()
detail=_RETAINED.error_detail()
if detail is not None:print('ERROR_DETAIL='+repr(detail))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def make_source(inputs):
    frames = tuple(payload_frame(inputs[BUNDLE + '/' + name]) for name, size, sha in ASSET_PINS)
    framed_assets = b''.join(frames)
    trailer = b'MTA_RECEIVE_FILECENTER_ASSETS_V1_END ' + digest(framed_assets).encode('ascii') + b'\n'
    wire = framed_assets + trailer
    lines = ['SESSION=' + repr(SESSION), 'REMOTE=' + repr(REMOTE), 'ASSET_PINS=' + repr(ASSET_PINS),
             'STOCK_PINS=' + repr(STOCK_PINS),
             'ROOT_NAMES=' + repr(ROOT_NAMES), 'MTA_NAMES=' + repr(MTA_NAMES),
             'TOOLBOX_NAMES=' + repr(TOOLBOX_NAMES), 'PINS=' + repr(PINS), 'MANIFEST=' + repr(MANIFEST),
             'BOOL_FIELDS=' + repr(BOOL_FIELDS), 'COUNT_FIELDS=' + repr(COUNT_FIELDS),
             'REASONS=' + repr(REASONS), 'VALIDATOR_PIN=' + repr(VALIDATOR[1:]),
             'WIRE_PIN=' + repr((len(wire), digest(wire))),
             'TRAILER_EXPECTED=' + repr(trailer),
             'VALIDATOR_ENCODED=(\n' + chunks(inputs[VALIDATOR[0]]) + '\n)', 'ARTIFACT_ROWS=(']
    for pin, frame in zip(ASSET_PINS, frames):
        lines.append('    ' + repr(pin + (len(frame),)) + ',')
    lines.append(')')
    source = '\n'.join(lines) + '\n' + TARGET
    return source, wire


def host_error_code(error):
    if (isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str and
            error.args[0] in HOST_ERROR_CODES): return error.args[0]
    if isinstance(error, SyntaxError): return 'syntax'
    if isinstance(error, OSError): return 'host_io'
    if isinstance(error, RuntimeError): return 'host_runtime'
    return 'unexpected'


def load_transport(raw):
    value = types.ModuleType('receive_filecenter_assets_host_transport')
    value.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    if Path(value.ADB).resolve() != Path('C:/Program Files/ADB/adb.exe').resolve():
        raise ValueError('transport_identity')
    return value


def parse_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
    if len(remote) != 1 or derived.splitlines().count('MTA_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('remote_result_unknown')
    component = ast.literal_eval(rows[0])
    if (type(component) is not dict or set(component) != FIELDS or
            any(type(component[key]) is not bool for key in BOOL_FIELDS) or
            any(type(component[key]) is not int or not 0 <= component[key] <= 8192 for key in COUNT_FIELDS) or
            component['reason'] not in REASONS): raise ValueError('result_fields')
    return int(remote[0]), component


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-device', action='store_true')
    args = parser.parse_args()
    mode = 'stage' if args.stage_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('receive-filecenter-assets-' + mode + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'; private.mkdir(parents=True, exist_ok=False)
    inputs = {}; data = wire = None
    report = dict(schema='p011-receive-filecenter-assets-v1', mode=mode, passed=False,
        source_preserved=False, source_check_complete=False, host_error=None, host_error_code=None,
        device_invoked=False, host_exit=None, remote_exit=None, remote_status_known=False,
        stdout_bytes=None, stdout_sha256=None, stderr_bytes=None, stderr_sha256=None,
        component_result=None, device_file_writes_requested=args.stage_device,
        qt_started=False, boot_started=False, owner_started=False, credentials_read=False,
        stock_processes_verified=False,
        physical_stdin_eof_verified=False, payload_end_mode='fixed-sha-trailer',
        rf_requested=False, pending_removed=False, receive_admission=False, send_admission=False,
        phone_tested=False, full_network_restore_verified=False, other_ui_sessions_preserved=True,
        whole_tree_atomicity_claimed=False)
    label = 'receive-filecenter-assets'
    try:
        if sum(pin[1] for pin in ASSET_PINS) != 4182249 or sum(pin[1] for pin in ASSET_PINS) >= 4 * 1024 * 1024:
            raise ValueError('payload_budget')
        for path, size, sha in (VALIDATOR, TRANSPORT): inputs[path] = read_fixed(path, (size, sha))
        for name, size, sha in ASSET_PINS: inputs[BUNDLE + '/' + name] = read_fixed(BUNDLE + '/' + name, (size, sha))
        checker = 'host/device_receive_filecenter_assets_v1_check.py'; inputs[checker] = read_fixed(checker)
        expected = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in PINS).encode('ascii')
        if inputs[BUNDLE + '/SOURCE.sha256'] != expected: raise ValueError('manifest_bytes')
        for path, raw in inputs.items():
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as handle: handle.write(raw)
        # Only this new assembled envelope gets the target Python 3.5 AST check.
        # No old component/model/Qt test is repeated; ui_assets stays fixed.
        program, wire = make_source(inputs)
        data = program.encode('ascii')
        with (out / 'private-target-source.py').open('xb') as handle: handle.write(data)
        with (out / 'private-payload-wire.raw').open('xb') as handle: handle.write(wire)
        report.update(target_source_bytes=len(data), target_source_sha256=digest(data),
                      payload_wire_bytes=len(wire), payload_wire_sha256=digest(wire),
                      source_count=len(inputs), asset_count=len(ASSET_PINS), payload_bytes=4182249,
                      validator_source_bytes=VALIDATOR[1], per_file_byte_limit=ELF_BYTES,
                      raw_payload_byte_limit=4 * 1024 * 1024, compressed_source_byte_limit=2 * 1024 * 1024,
                      payload_wire_byte_limit=6 * 1024 * 1024, payload_wire_line_byte_limit=1024)
        if len(data) > 2 * 1024 * 1024 or any(len(line) > 2048 for line in data.splitlines()):
            raise ValueError('target_source_budget')
        if len(wire) > 6 * 1024 * 1024: raise ValueError('payload_wire_budget')
        ast.parse(program, feature_version=(3, 5))
        report['source_check_complete'] = True
        if args.stage_device:
            transport = load_transport(inputs[TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(180);'
                'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-receive-filecenter-assets; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=210, input_data=data + wire)
            remote, component = parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, component_result=component)
    except Exception as error:
        report['host_error'] = type(error).__name__
        report['host_error_code'] = host_error_code(error)
    finally:
        prefix = private / ('01-' + label)
        host_path = Path(str(prefix) + '.host-exit')
        if host_path.exists():
            raw = host_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(raw) if re.fullmatch(r'-?\d+', raw) else 'TIMEOUT'
        stdout_path = Path(str(prefix) + '.stdout.raw'); stderr_path = Path(str(prefix) + '.stderr.raw')
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream + '_bytes'] = len(original); report[stream + '_sha256'] = digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            found = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'] = int(found[0]); report['remote_status_known'] = True; marker = found[0]
        with Path(str(prefix) + '.remote-exit').open('x', encoding='ascii') as handle: handle.write(marker + '\n')
        try:
            report['source_preserved'] = (len(inputs) == 22 and type(data) is bytes and type(wire) is bytes and
                (out / 'private-target-source.py').read_bytes() == data and
                (out / 'private-payload-wire.raw').read_bytes() == wire and all(read_fixed(path) == raw and
                (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items()))
        except (OSError, ValueError): report['source_preserved'] = False
    component = report['component_result']
    if not args.stage_device:
        report['passed'] = report['host_error'] is None and report['source_check_complete'] and report['source_preserved']
    else:
        report['passed'] = (report['host_error'] is None and report['source_check_complete'] and
            report['source_preserved'] and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
            report['remote_status_known'] and report['remote_exit'] == 0 and type(component) is dict and
            component['complete'] is True and component['reason'] == 'complete' and
            component['resource_pending'] is False and component['staging_pending'] is False and
            all(component[key] for key in BOOL_FIELDS if key not in ('resource_pending', 'staging_pending')) and
            component['created_file_count'] in (0, 19) and component['created_directory_count'] in (0, 3, 4) and
            component['original_opened_fd_count'] == component['original_closed_fd_count'] > 0 and
            component['validator_opened_fd_count'] == component['validator_closed_fd_count'] == 27 and
            component['validator_files_verified'] == 19 and component['validator_readback_passes'] == 38)
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Fixed FileCenter and MTA UI asset staging/validation only, not a UI or service launch. '
        b'Default source mode does not access ADB. Explicit --stage-device uses the fixed 19 assets and '
        b'pinned ui_assets.validate_assets. The exact session/mta/toolbox inventories, original parent/name '
        b'bindings, file metadata/pins and original FD once-close/readback are required. '
        b'The current three stock files must match fixed hashes before any target write and after '
        b'the operation, with the same actual file metadata; this does not authenticate stock processes. '
        b'Only absent mta-ui/session/mta/toolbox project directories and absent files inside the new fixed session are '
        b'exclusively created, without overwrite/chmod/cleanup. Existing partial/conflicting sessions '
        b'are retained and refused. Other mta-ui sessions are preserved, not traversed or authenticated. '
        b'Individual creates are exclusive, not a whole-tree atomic transaction. Validator SOURCE runs '
        b'in a fresh worker from stdin; it is not installed as an extra bundle asset. No stdlib json is '
        b'used on P011. The small ASCII program is limited to 2 MiB; its following stdin payload wire '
        b'is limited to 6 MiB, contains only these 19 fixed assets as strict base64/LF frames with '
        b'lines at most 1024 ASCII bytes, and requires exact lengths, pins and a fixed SHA-bearing '
        b'trailer after the nineteen frames; its whole-wire pin includes that trailer. The raw '
        b'asset budget remains 4 MiB. Program and vendor payload wire stay separate/local/private, '
        b'never in the public ZIP. PTY newline conversion fails frame checks. Bytes beyond the fixed '
        b'framed end are not read or executed; their absence is not claimed. Physical stdin EOF is '
        b'not read or verified, and physical_stdin_eof_verified is false. Every stdin read, including '
        b'the fixed trailer, shares the original 60-second deadline via a '
        b'temporary SIGALRM timer. Its finally restores the original absolute outer deadline, '
        b'not a renewed timeout; cleanup cancels the read timer before stock readback/closure. '
        b'Single alarm180/host210, activity60/stock-cleanup60; closure is not activity-deadline truncated. '
        b'Timeouts/missing markers never prove closure. PASS proves only fixed UI assets and resource '
        b'closure, not Qt visuals, touchscreen, service connection, credentials, receive/send, phone '
        b'interoperability, radio admission/restoration or old-record terminalization. Raw outputs, '
        b'fixed snapshots and the assembled source remain local/private.\n')
    with (out / 'result.json').open('xb') as handle: handle.write(public)
    with (out / 'README.txt').open('xb') as handle: handle.write(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme): raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out), result_zip=str(archive),
                         zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

