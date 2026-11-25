"""Fixed original WPA daemon/endpoint facts; default source-only, never STATUS.

Explicit execution is ROOT-reviewed read-only Python, not namespace/RF admission.
Only the pinned selector and Adb.run are reused, never its old PROBE/python.
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
import sys
import types
import zlib
import zipfile

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
ADB_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
PINS = (
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
    ('mta_client_proc', '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'))
MAX_SOURCE, MAX_OUTPUT = 262144, 16 * 1024 * 1024
BOOLS = ('facts_complete', 'wlan_observed', 'wlan_present', 'daemon_stable', 'image_stable',
         'namespaces_equal', 'endpoint_stable', 'files_closed', 'resource_pending')
COUNTS = {'daemon_count': 128, 'endpoint_count': 128, 'file_count': 1024, 'closed_count': 1024,
          'proc_file_count': 560, 'proc_closed_count': 560}
_EXECUTIONS = []
STAGES = ('not_started', 'platform', 'selection', 'actor_before', 'identity_before',
          'endpoint_before', 'actor_after', 'identity_after', 'endpoint_after', 'readback', 'complete')
REASONS = ('not_recorded', 'platform', 'budget', 'already_attempted', 'read_limit',
    'fd_limit', 'fd_unknown', 'file_changed', 'close_unknown', 'daemon_selection',
    'actor_unknown', 'image_invalid', 'argv_invalid', 'uid_gid_invalid',
    'namespace_invalid', 'namespace_mismatch', 'unix_invalid', 'fd_table_invalid',
    'endpoint_selection', 'endpoint_abstract', 'endpoint_path', 'endpoint_metadata',
    'identity_changed', 'wlan_absent', 'os_error', 'unexpected', 'interrupted')
CLASSES = ('none', 'value_error', 'os_error', 'unexpected', 'interrupted')

REMOTE_CORE = r'''
import errno,hashlib,math,os,re,stat,time,traceback
def fail(code):raise ValueError(code)
def uint(v,maximum=(1<<64)-1):return type(v) is int and 0<=v<=maximum
def meta(s):
 names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 row=tuple(getattr(s,n,None) for n in names)
 if any(not uint(v) for v in row[:7]) or any(type(v) is not int or not -(1<<63)<=v<(1<<63) for v in row[7:]):fail('fd_unknown')
 return row
def private(v):
 if v is None or type(v) in (bytes,str,int,float,bool):return v
 if type(v) in (list,tuple):return tuple(private(x) for x in v)
 if type(v) is dict:return {k:private(x) for k,x in v.items()}
 if hasattr(v,'__slots__'):return {k:private(getattr(v,k)) for k in v.__slots__ if not k.startswith('_')}
 fail('fd_unknown')
def observation(v,proc,core):
 if (type(v) is not proc.ProcObservation or v.kind!='live_actor' or type(v.actor) is not core.Actor or not v.actor.live()
     or v.same_boot is not True or type(v.passes) is not int or v.passes!=2 or v.resource_pending is not False
     or type(v.file_count) is not int or v.file_count<=0 or type(v.closed_count) is not int or v.closed_count!=v.file_count
     or type(v.task_count) is not int or v.task_count!=len(v.actor.tasks)):fail('actor_unknown')
 return v.actor
def options(raw):
 if type(raw) is not bytes or not 1<=len(raw)<=32768 or not raw.endswith(b'\0') or b'\0\0' in raw:fail('argv_invalid')
 try:args=tuple(x.decode('utf-8','strict') for x in raw[:-1].split(b'\0'))
 except UnicodeError:fail('argv_invalid')
 out={};i=1
 while i<len(args):
  token=args[i]
  if token[:2] in ('-i','-C','-O','-g'):
   key=token[:2]
   if key in out:fail('argv_invalid')
   if len(token)>2:value=token[2:]
   else:
    i+=1
    if i==len(args):fail('argv_invalid')
    value=args[i]
   if not value or value.startswith('-') or len(value)>4096:fail('argv_invalid')
   out[key]=value
  i+=1
 if out.get('-i')!='wlan0':fail('argv_invalid')
 return out
def uid_gid(raw):
 if type(raw) is not bytes or len(raw)>32768:fail('uid_gid_invalid')
 rows={}
 for line in raw.splitlines():
  key=line.split(b':',1)[0]
  if key not in (b'Uid',b'Gid'):continue
  if key in rows or line.count(b':')!=1:fail('uid_gid_invalid')
  values=line.split(b':',1)[1].split()
  if len(values)!=4 or any(re.match(br'^(0|[1-9][0-9]{0,9})\Z',v) is None or int(v)>0xffffffff for v in values):fail('uid_gid_invalid')
  rows[key]=tuple(int(v) for v in values)
 if set(rows)!={b'Uid',b'Gid'} or rows[b'Uid']!=(0,0,0,0) or rows[b'Gid']!=(0,0,0,0):fail('uid_gid_invalid')
 return rows[b'Uid'],rows[b'Gid']
def unix_rows(raw):
 if type(raw) is not bytes or len(raw)>1048576 or not raw.endswith(b'\n'):fail('unix_invalid')
 lines=raw.splitlines()
 if not lines or lines[0].split()!=[b'Num',b'RefCount',b'Protocol',b'Flags',b'Type',b'St',b'Inode',b'Path'] or len(lines)>4097:fail('unix_invalid')
 rows=[];seen=set()
 for line in lines[1:]:
  p=line.split(None,7)
  if len(p) not in (7,8) or re.match(br'^[0-9a-fA-F]{8,16}:\Z',p[0]) is None:fail('unix_invalid')
  if any(re.match(br'^[0-9a-fA-F]{8}\Z',p[n]) is None for n in (1,2,3)) or re.match(br'^[0-9a-fA-F]{4}\Z',p[4]) is None or re.match(br'^[0-9a-fA-F]{2}\Z',p[5]) is None:fail('unix_invalid')
  if re.match(br'^(0|[1-9][0-9]{0,19})\Z',p[6]) is None or int(p[6])>(1<<64)-1:fail('unix_invalid')
  inode=int(p[6]);path=p[7] if len(p)==8 else b''
  if inode and inode in seen:fail('unix_invalid')
  seen.add(inode);rows.append((inode,int(p[4],16),path,tuple(p[:7])))
 return tuple(rows)
class ReadFiles(object):
 def __init__(self,fs,clock,end):
  self.fs,self.clock,self.end=fs,clock,end
  self.refs=[];self.raw=[];self.pending=False;self.total=0;self.last=None
 def check(self):
  now=self.clock()
  if type(now) not in (int,float) or not math.isfinite(float(now)) or self.last is not None and now<self.last or now>=self.end:fail('budget')
  self.last=now
 def read(self,path,limit,follow=False,capture=True):
  if self.pending:fail('close_unknown')
  self.check()
  if len(self.refs)>=1024:fail('fd_limit')
  row={'fs':self.fs,'path':path,'fd':None,'metadata':None,'unknown':True,'attempted':False,'closed':False}
  self.refs.append(row);data=b'';failed=False
  try:
   flags=self.fs.O_RDONLY|self.fs.O_CLOEXEC|self.fs.O_NONBLOCK
   if not follow:flags|=self.fs.O_NOFOLLOW
   try:row['fd']=self.fs.open(path,flags)
   except OSError as e:
    if type(e.errno) is int and 1<=e.errno<=4095 and row['fd'] is None:row['unknown'],row['closed']=False,True
    else:self.pending=True
    raise
   if not uint(row['fd'],0x7fffffff) or any(x is not row and x['fd']==row['fd'] and not x['closed'] for x in self.refs):fail('fd_unknown')
   row['metadata']=meta(self.fs.fstat(row['fd']));row['unknown']=False
   if not stat.S_ISREG(row['metadata'][2]):fail('fd_unknown')
   while True:
    self.check();amount=min(65536,limit+1-len(data));chunk=self.fs.read(row['fd'],amount)
    if type(chunk) is not bytes or len(chunk)>amount:fail('read_limit')
    data+=chunk
    if len(data)>limit:fail('read_limit')
    if not chunk:break
   self.total+=len(data)
   if self.total>8*1024*1024:fail('read_limit')
   if meta(self.fs.fstat(row['fd']))!=row['metadata']:fail('file_changed')
   return data
  except BaseException:
   failed=True
   if row['unknown']:self.pending=True
   raise
  finally:
   try:self.raw.append((path,data if capture else {'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)},row['metadata']))
   finally:
    self.close(row)
    if not failed and not row['closed']:fail('close_unknown')
 def close(self,row):
  if row['attempted'] or row['closed']:return
  if row['unknown'] or row['metadata'] is None or not uint(row['fd'],0x7fffffff):self.pending=True;return
  row['attempted']=True;returned=False
  try:
   if meta(self.fs.fstat(row['fd']))!=row['metadata']:fail('file_changed')
   returned=self.fs.close(row['fd']) is None
  except BaseException:self.pending=True
  try:self.fs.fstat(row['fd'])
  except OSError as e:
   if returned and type(e.errno) is int and e.errno==errno.EBADF:row['closed']=True;return
  except BaseException:pass
  self.pending=True
 def status(self):
  return len([r for r in self.refs if r['fd'] is not None]),len([r for r in self.refs if r['fd'] is not None and r['closed']]),self.pending or any(r['unknown'] or not r['closed'] for r in self.refs)
class Collector(object):
 def __init__(self,proc,core,fs=None,clock=None,reader=None):
  self.proc,self.core=proc,core;self.fs=fs if fs is not None else os;self.clock=clock if clock is not None else time.monotonic
  self.reader=reader;self.files=None;self.attempted=False;self.private={};self.stage='not_started'
 def names(self,path,maximum):
  self.files.check();rows=self.fs.listdir(path)
  if type(rows) is not list or len(rows)>maximum or any(type(x) is not str for x in rows):fail('read_limit')
  self.private.setdefault('directories',[]).append((path,tuple(rows)))
  return rows
 def link(self,path):
  self.files.check();value=self.fs.readlink(path)
  if type(value) is not str or not 1<=len(value)<=4096:fail('fd_unknown')
  self.private.setdefault('links',[]).append((path,value));return value
 def actor(self,pid,expected=None):
  value=self.reader.read_actor(pid,expected);self.private.setdefault('actors',[]).append(value)
  return value,observation(value,self.proc,self.core)
 def identity(self,actor):
  root='/proc/'+str(actor.pid);argv=self.files.read(root+'/cmdline',32768)
  if hashlib.sha256(argv).hexdigest()!=actor.argv_sha:fail('identity_changed')
  opts=options(argv);ids=uid_gid(self.files.read(root+'/status',32768));ns=[]
  for name in ('mnt','net','pid','user'):
   pair=(self.link(root+'/ns/'+name),self.link('/proc/self/ns/'+name))
   if any(re.match('^'+name+r':\[[1-9][0-9]{0,19}\]\Z',v) is None for v in pair):fail('namespace_invalid')
   ns.append((name,pair))
  path=root+'/exe';link=self.link(path)
  if link!=actor.exe or not link.startswith('/') or link.endswith(' (deleted)'):fail('image_invalid')
  data=self.files.read(path,67108864,True,False);row=self.files.refs[-1]
  if not data.startswith(b'\x7fELF') or row['metadata'][3]!=0 or row['metadata'][2]&0o022 or not row['metadata'][2]&0o111:fail('image_invalid')
  return {'argv':argv,'options':opts,'uid_gid':ids,'namespaces':tuple(ns),'image_sha':hashlib.sha256(data).hexdigest(),'image_metadata':row['metadata']}
 def endpoint(self,pid,opts):
  root='/proc/'+str(pid)+'/fd';names=self.names(root,1024);fds=[]
  for name in names:
   if re.match(r'^(0|[1-9][0-9]{0,9})\Z',name) is None or int(name)>0x7fffffff:fail('fd_table_invalid')
   value=self.link(root+'/'+name);match=re.match(r'^socket:\[([1-9][0-9]{0,19})\]\Z',value)
   if match:fds.append((int(name),int(match.group(1))))
  raw=self.files.read('/proc/net/unix',1048576);rows=unix_rows(raw)
  owned=set(n for unused,n in fds);candidates=[]
  for row in rows:
   if row[0] not in owned or row[1]!=2 or not row[2]:continue
   if row[2].startswith(b'@'):fail('endpoint_abstract')
   try:path=row[2].decode('utf-8','strict')
   except UnicodeError:fail('endpoint_path')
   if path==opts.get('-g'):continue
   if not path.startswith('/') or len(row[2])>108 or '\0' in path:fail('endpoint_path')
   if path.rsplit('/',1)[-1]!='wlan0':continue
   if '-C' in opts and path!=opts['-C'].rstrip('/')+'/wlan0':fail('endpoint_path')
   candidates.append((row,path))
  self.private.setdefault('endpoint_candidates',[]).append((tuple(fds),tuple(candidates)))
  if len(candidates)!=1:fail('endpoint_selection')
  row,path=candidates[0];chain=[];parts=path.split('/')
  if any(x in ('','.','..') for x in parts[1:]):fail('endpoint_path')
  for index in range(len(parts)):
   part='/' if index==0 else '/'.join(parts[:index+1]);s=self.fs.lstat(part);m=meta(s)
   self.private.setdefault('path_observations',[]).append((part,m))
   if index<len(parts)-1:
    if not stat.S_ISDIR(m[2]) or m[3]!=0 or m[2]&0o022:fail('endpoint_metadata')
   elif not stat.S_ISSOCK(m[2]) or m[3]!=0 or m[2]&0o002:fail('endpoint_metadata')
   chain.append((part,m))
  # Filesystem inode is deliberately NOT compared with sock_i_ino/socket:[inode].
  return {'row':row,'path':path,'fd_inodes':tuple(sorted(fds)),'chain':tuple(chain)}
 def collect(self):
  if self.attempted:fail('already_attempted')
  self.attempted=True;summary={k:False for k in BOOLS};summary.update({k:0 for k in COUNTS})
  failure={'stage':'complete','class':'none','reason':'not_recorded','errno':0};trace=None
  try:
   self.stage='platform'
   if self.fs.geteuid()!=0 or self.fs.uname()[4]!='armv7l':fail('platform')
   self.files=ReadFiles(self.fs,self.clock,self.clock()+20.0)
   if self.reader is None:self.reader=self.proc.ProcReader(timeout=3.0)
   self.stage='selection';pids=[]
   for name in self.names('/proc',8192):
    if re.match(r'^[1-9][0-9]{0,9}\Z',name) is None:continue
    if int(name)>0x7fffffff:fail('daemon_selection')
    try:raw=self.files.read('/proc/'+name+'/comm',64)
    except OSError as e:
     if type(e.errno) is int and e.errno==errno.ENOENT:continue
     raise
    if raw==b'wpa_supplicant\n':pids.append(int(name))
   summary['daemon_count']=len(pids)
   if len(pids)!=1:fail('daemon_selection')
   self.stage='actor_before';before,actor=self.actor(pids[0]);self.files.check()
   self.stage='identity_before';first=self.identity(actor);self.private['identity_before']=first
   self.stage='endpoint_before';endpoint=self.endpoint(actor.pid,first['options']);self.private['endpoint_before']=endpoint;summary['endpoint_count']=1
   self.stage='identity_after';last=self.identity(actor);self.private['identity_after']=last
   self.stage='endpoint_after';end=self.endpoint(actor.pid,last['options']);self.private['endpoint_after']=end
   self.stage='actor_after';after,current=self.actor(actor.pid,actor);self.files.check()
   self.stage='readback';interfaces=self.names('/sys/class/net',64);summary['wlan_observed']=True;summary['wlan_present']='wlan0' in interfaces
   summary['daemon_stable']=before.boot==after.boot and actor.key()==current.key()
   summary['image_stable']=first==last;summary['endpoint_stable']=endpoint==end
   summary['namespaces_equal']=all(pair[0]==pair[1] for unused,pair in first['namespaces'])
   if not summary['daemon_stable'] or not summary['image_stable'] or not summary['endpoint_stable']:fail('identity_changed')
   if not summary['namespaces_equal']:fail('namespace_mismatch')
   if not summary['wlan_present']:fail('wlan_absent')
   self.files.check();summary['facts_complete']=True;self.stage='complete'
  except BaseException as e:
   trace=traceback.format_exc();reason=str(e) if type(e) is ValueError and str(e) in REASONS else 'os_error' if isinstance(e,OSError) else 'interrupted' if not isinstance(e,Exception) else 'unexpected'
   number=getattr(e,'errno',0);failure={'stage':self.stage,'class':'value_error' if isinstance(e,ValueError) else 'os_error' if isinstance(e,OSError) else 'interrupted' if not isinstance(e,Exception) else 'unexpected','reason':reason,'errno':number if uint(number,4095) else 0}
  finally:
   if self.files is not None:
    count,closed,pending=self.files.status();summary.update(file_count=count,closed_count=closed,resource_pending=pending,files_closed=not pending and count==closed)
    self.private['reads']=tuple(self.files.raw);self.private['fd_records']=tuple({k:r[k] for k in ('path','fd','metadata','unknown','attempted','closed')} for r in self.files.refs)
   if any(v.resource_pending is not False for v in self.private.get('actors',())):summary['resource_pending']=True;summary['files_closed']=False
   summary['proc_file_count']=sum(v.file_count for v in self.private.get('actors',()))
   summary['proc_closed_count']=sum(v.closed_count for v in self.private.get('actors',()))
   if summary['resource_pending'] or not summary['files_closed']:summary['facts_complete']=False
  self.private['traceback']=trace
  return {'summary':summary,'failure':failure,'private':private(self.private)}
'''

REMOTE_ENTRY = r'''
import sys
if sys.flags.optimize or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_version')
collector=Collector(modules['mta_client_proc'],modules['mta_p2p_client_init'])
OWNERS=[collector]  # Keep exact IO/module/reader refs until this process exits; never auto-close unknown.
print('RESULT='+repr(collector.collect()))
'''


def _read(path, pin=None):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)): raise ValueError('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_SOURCE: raise ValueError('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno()); data = handle.read(MAX_SOURCE + 1)
    after = path.stat()
    if any(getattr(before,k)!=getattr(opened,k) or getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns')): raise ValueError('source_changed')
    if len(data)!=before.st_size or pin is not None and hashlib.sha256(data).hexdigest()!=pin: raise ValueError('source_pin')
    return data


def source_check():
    _read(BASE/'host/device_probe.py', ADB_PIN)
    data = tuple((name,pin,_read(BASE/'runtime'/(name+'.py'),pin)) for name,pin in PINS)
    chunks=[]
    for name,pin,raw in data:
        encoded=base64.b64encode(raw).decode('ascii')
        chunks.append('(%r,%r,\n%s),\n'%(name,pin,'\n'.join(repr(encoded[i:i+1000]) for i in range(0,len(encoded),1000))))
    loader = '''import base64,builtins,hashlib,types
modules={};original=builtins.__import__
def pinned_import(name,globals=None,locals=None,fromlist=(),level=0):
 if name in dict(PINS):
  if level or name not in modules:raise ValueError('memory_order')
  return modules[name]
 if name.startswith('mta_') or name.startswith('p011_') or level:raise ValueError('memory_import')
 return original(name,globals,locals,fromlist,level)
for name,pin,encoded in ENCODED:
 raw=base64.b64decode(encoded.encode('ascii'),validate=True)
 if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('memory_pin')
 module=types.ModuleType(name);module.__file__='<pinned-wpa-daemon-readonly>'
 module.__dict__['__builtins__']=dict(vars(builtins),__import__=pinned_import)
 exec(raw,module.__dict__);modules[name]=module
'''
    source='PINS='+repr(PINS)+'\nENCODED=(\n'+''.join(chunks)+')\n'+loader+'BOOLS='+repr(BOOLS)+'\nCOUNTS='+repr(COUNTS)+'\nREASONS='+repr(REASONS)+'\n'+REMOTE_CORE+REMOTE_ENTRY
    for raw in (source.encode('utf-8'),)+tuple(raw for _,_,raw in data):
        tree=ast.parse(raw.decode('utf-8'),feature_version=(3,5))
        if any(isinstance(n,ast.Assert) for n in ast.walk(tree)): raise ValueError('source_assert')
    if len(source.encode('utf-8'))>MAX_SOURCE or max(map(len,source.splitlines()))>2048: raise ValueError('source_budget')
    return {'source_check_pass':True,'checker_sha256':hashlib.sha256(_read(Path(__file__).absolute())).hexdigest(),'adb_helper_sha256':ADB_PIN,'source_sha256':dict(PINS)},source


def _transport(source):
    data=(source+"\nprint('MTA_REMOTE_OK')\n").encode('utf-8'); encoded=base64.b64encode(zlib.compress(data)).decode('ascii')
    command=('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\''+encoded+'\')))"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    if len(command)<=3500:return command,None,None
    return ('python3 -B -c "import sys;exec(sys.stdin.buffer.read('+str(len(data))+'))" p011-wpa-daemon-facts; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"'),data,data


def _parse(raw,echo=None):
    if type(raw) is not bytes or len(raw)>MAX_OUTPUT:raise ValueError('remote_frame')
    value=raw.decode('utf-8','strict').replace('\r\r\n','\n').replace('\r\n','\n')
    if echo is not None:
        prefix=echo.decode('utf-8','strict').replace('\r\r\n','\n').replace('\r\n','\n')
        if value.startswith(prefix):value=value[len(prefix):]
    lines=[line for line in value.split('\n') if line]
    if len(lines)!=3 or not lines[0].startswith('RESULT=') or lines[1:]!=['MTA_REMOTE_OK','MTA_REMOTE_EXIT=0']:raise ValueError('remote_frame')
    return ast.literal_eval(lines[0][7:])


def _project(value):
    if type(value) is not dict or set(value)!={'summary','failure','private'}:raise ValueError('result_shape')
    summary,failure,private=value['summary'],value['failure'],value['private']
    if type(summary) is not dict or set(summary)!=set(BOOLS)|set(COUNTS):raise ValueError('summary_shape')
    if any(type(summary[k]) is not bool for k in BOOLS) or any(type(summary[k]) is not int or not 0<=summary[k]<=v for k,v in COUNTS.items()):raise ValueError('summary_values')
    if summary['wlan_present'] and not summary['wlan_observed']:raise ValueError('wlan_shape')
    if summary['closed_count']>summary['file_count'] or summary['proc_closed_count']>summary['proc_file_count'] or summary['files_closed'] and (summary['resource_pending'] or summary['closed_count']!=summary['file_count'] or summary['proc_closed_count']!=summary['proc_file_count']):raise ValueError('closure_shape')
    if type(failure) is not dict or set(failure)!={'stage','class','reason','errno'} or type(failure['stage']) is not str or failure['stage'] not in STAGES or type(failure['class']) is not str or failure['class'] not in CLASSES or type(failure['reason']) is not str or failure['reason'] not in REASONS or type(failure['errno']) is not int or not 0<=failure['errno']<=4095:raise ValueError('failure_shape')
    if type(private) is not dict or 'traceback' not in private or private['traceback'] is not None and (type(private['traceback']) is not str or len(private['traceback'].encode('utf-8'))>65536):raise ValueError('private_shape')
    good=summary['facts_complete'] and all(summary[k] for k in ('wlan_observed','wlan_present','daemon_stable','image_stable','namespaces_equal','endpoint_stable','files_closed')) and not summary['resource_pending'] and summary['daemon_count']==1 and summary['endpoint_count']==1 and summary['file_count']>0 and summary['proc_file_count']>0 and failure=={'stage':'complete','class':'none','reason':'not_recorded','errno':0}
    if summary['facts_complete'] and not good:raise ValueError('false_complete')
    return dict(summary,pass_value=bool(good),failure=failure)


def _remote(adb, source, _owner=None):
    command,data,echo=_transport(source)
    raw=None;first_error=None
    try:
        raw=adb.run('original-wpa-identity',['shell',command],timeout=30,input_data=data)
        value=_parse(raw,echo)
        captured=Path(str(adb.directory/('%02d-original-wpa-identity'%adb.index))+'.stderr.raw')
        with captured.open('rb') as handle:stderr=handle.read(MAX_OUTPUT+1)
        if stderr:raise ValueError('host_stderr')
        return value
    except BaseException as e:
        first_error=e
        if _owner is not None:_owner['remote_first_error']=e
        raise
    finally:
        try:
            stem=adb.directory/('%02d-original-wpa-identity'%adb.index)
            if raw is None:
                captured=Path(str(stem)+'.stdout.raw')
                if captured.exists():
                    with captured.open('rb') as handle:raw=handle.read(MAX_OUTPUT+1)
            exits=re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)',raw) if type(raw) is bytes else []
            Path(str(stem)+'.remote-exit').write_text(exits[0].decode('ascii') if len(exits)==1 else 'INVALID' if raw is not None else 'NOT_RECORDED',encoding='ascii')
        except BaseException as e:
            if _owner is not None:_owner['remote_exit_record_error']=e
            if first_error is None:raise


def run_readonly(expected, _adb_factory=None, _output=None):
    checks,source=source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}',expected) is None or expected!=checks['checker_sha256']:raise ValueError('reviewed_pin')
    if _EXECUTIONS:raise ValueError('already_attempted')
    execution={'source':source,'adb':None};_EXECUTIONS.append(execution)
    out=_output if _output is not None else ROOT/'logs'/('MtaP011-WpaDaemonIdentityReadOnly-'+datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex())
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    report=dict(checks,evidence='P011_READONLY_WPA_IDENTITY_FACTS',**{'pass':False,'target_selected':False,'device_command_attempted':False,'device_reply_confirmed':False,'device_writes':False,'rf_operations':False,'status_sent':False,'socket_created':False,'daemon_manifest_authenticated':False,'namespace_authenticated':False,'network_restoration':'NOT_EVALUATED','receive_available':False,'send_available':False,'selector_raw_captured':False})
    try:
        if _adb_factory is None:
            helper=types.ModuleType('p011_pinned_wpa_adb');helper.__file__=str(BASE/'host/device_probe.py')
            exec(_read(BASE/'host/device_probe.py',ADB_PIN),helper.__dict__);_adb_factory=helper.Adb
        adb=_adb_factory(out/'private-raw');execution['adb']=adb;report['target_selected']=True
        report['device_command_attempted']=True
        value=_remote(adb,source,execution);report['device_reply_confirmed']=True;facts=_project(value)
        report.update(facts);report['pass']=report.pop('pass_value')
    except Exception as e:
        execution['first_error']=e
        report['error_class']='os_error' if isinstance(e,OSError) else 'value_error' if isinstance(e,ValueError) else 'runtime_error' if isinstance(e,RuntimeError) else 'unexpected'
        report['errno']=getattr(e,'errno',0) if type(getattr(e,'errno',0)) is int and 0<=getattr(e,'errno',0)<=4095 else 0
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('One pinned read-only original WPA daemon/endpoint fact collection.\nNo CLI/STATUS/socket/RF/network/pending/staging/repair operation.\nActor/image/argv/UID/GID/namespaces/Unix rows/FD association/path metadata remain private raw.\nNo production daemon manifest or namespace/reply authentication; no restoration or interop acceptance.\nExact known original FD closure only, not process-global FD closure.\nUnmodified pinned selector enumeration raw is not independently captured.\n',encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    return report,out


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only',action='store_true');modes.add_argument('--execute-readonly',action='store_true')
    parser.add_argument('--expected-checker-sha256');args=parser.parse_args(argv)
    if args.execute_readonly!=(args.expected_checker_sha256 is not None):parser.error('Explicit read-only execution and exact checker SHA required together')
    try:
        report=run_readonly(args.expected_checker_sha256)[0] if args.execute_readonly else source_check()[0]
        print(json.dumps(report,indent=2));return 0 if report.get('source_check_pass') and not args.execute_readonly or report.get('pass') else 1
    except Exception:
        print(json.dumps({'pass':False,'error_class':'source_or_output','device_command_attempted':'NOT_RECORDED','device_reply_confirmed':False}));return 1


if __name__=='__main__':sys.exit(main())
