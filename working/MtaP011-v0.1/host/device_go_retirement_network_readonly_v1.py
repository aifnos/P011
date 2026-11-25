"""Fixed GO64 network DATA diagnostic; default is PC-only SOURCE preparation.

--read-current performs exactly one bounded, read-only target session. It does
not acquire locks, start an old runner, change records, or issue any authority.
Private inputs/source/output retain identifiers; the ZIP contains scalars only.
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
import zipfile

BASE = Path(__file__).resolve().parents[1]
OLD = BASE / 'results/go-active-budget-v64-20261002-213823-170ca3c0/private-raw/native-private.json'
FIRST = BASE / 'results/device-state-readonly-20261004-005134-3391c163/private-raw/01-current-state-first.stdout.raw'
SECOND = BASE / 'results/device-state-readonly-20261004-005134-3391c163/private-raw/02-current-state-second.stdout.raw'
INPUTS = (
    (OLD, 2812086, '8b263eeea803b39d04699a3b57c41582722be9b2a2bcd763f721229ffdbc629e'),
    (FIRST, 4953, 'b843527be7d8476f2a65a7ac58dc57001432e3c001dac10d32a0fd161d821536'),
    (SECOND, 4953, '7956b8a7a99172a8af74490c242496a593732cda63ca69f83ef5222922a001a2'),
    (BASE / 'runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    (BASE / 'runtime/mta_ip.py', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    (BASE / 'host/device_probe.py', 8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
)
PENDING_SHA = '80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818'
JOURNAL_SHA = '01c200261bae27578881dd3ef97e165e848a14b877b883405a017bc298d210c6'
BASELINE_FIELDS = ('boot', 'stock_hashes', 'stock_actors', 'station', 'station_state_sha',
                   'station_frequency', 'interfaces', 'ipv4', 'ipv6_addresses',
                   'ipv6_routes', 'station_completed')
CODES = ('ok', 'platform', 'source_pin', 'config', 'deadline', 'file_shape', 'file_limit',
         'file_changed', 'file_pin', 'open_unknown', 'close_unknown', 'proc_format',
         'proc_inventory', 'proc_changed', 'stock_identity', 'parent_loop', 'socket_shape',
         'kernel_peer', 'netlink_format', 'netlink_limit', 'netlink_done', 'netlink_ack',
         'kernel_error', 'interface_format', 'interface_inventory', 'ipv6_format',
         'status_failed', 'status_format', 'child_unknown', 'record_changed',
         'baseline_changed', 'unexpected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_inputs():
    rows = {}
    for path, size, pin in INPUTS:
        raw = path.read_bytes()
        if len(raw) != size or sha(raw) != pin:
            raise ValueError('fixed_input_changed')
        rows[path] = raw
    return rows


def configuration(inputs):
    original = json.loads(inputs[OLD].decode('ascii'))
    process = original['process']
    journal = process['journal']
    if (journal['schema'] != 'p011-go-bootstrap-v33-r2' or journal['phase'] != 'restore_intent' or
            type(journal['generation']) is not int or journal['generation'] != 4 or
            any(journal[key] is not None for key in ('interface_intent', 'owned', 'controller', 'group_add', 'group_observed', 'restored')) or
            not re.fullmatch('[0-9a-f]{32}', journal['run_token']) or
            set(journal['baseline']) != set(BASELINE_FIELDS)):
        raise ValueError('fixed_journal_shape')
    rows = process['journal_rows']
    if type(rows) is not list or len(rows) != 1:
        raise ValueError('fixed_journal_rows')
    raw = base64.b64decode(rows[0]['raw']['bytes_b64'], validate=True)
    if (len(raw) != 7138 or sha(raw) != JOURNAL_SHA or rows[0]['sha256'] != JOURNAL_SHA or
            json.loads(raw.decode('ascii')) != journal or rows[0]['closed'] is not True or rows[0]['unknown'] is not False):
        raise ValueError('fixed_journal_bytes')
    markers = []
    for path in (FIRST, SECOND):
        found = re.findall(r"b'(\{[^']*\})'", inputs[path].decode('ascii'))
        found = [row for row in found if 'p011-go-bootstrap-v33-r2' in row]
        if len(found) != 1 or '\\' in found[0]:
            raise ValueError('fixed_pending_literal')
        markers.append(found[0].encode('ascii'))
    identity = ('schema', 'run_token', 'candidate_sha', 'task_id', 'boot_id', 'issued_at', 'until')
    marker = json.loads(markers[0].decode('ascii'))
    if (markers[0] != markers[1] or len(markers[0]) != 340 or sha(markers[0]) != PENDING_SHA or
            set(marker) != set(identity) or any(marker[key] != journal[key] for key in identity)):
        raise ValueError('fixed_pending_identity')
    return dict(run_token=journal['run_token'], boot=journal['boot_id'],
                pending_b64=base64.b64encode(markers[0]).decode('ascii'),
                journal_b64=base64.b64encode(raw).decode('ascii'),
                historical=journal['baseline'])


BODY = r'''
import errno,hashlib,math,os,re,signal,socket,stat,struct,subprocess,sys,time,types
class ReadError(ValueError):
 def __init__(self,code,number=0):
  self.code,self.errno=code,number;ValueError.__init__(self,code)
def fail(code,number=0):raise ReadError(code,number)
if (os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5) or
 os.O_NOFOLLOW!=0x8000 or os.O_CLOEXEC!=0x80000 or os.O_NONBLOCK!=0x800):fail('platform')
start=None;until=None;last=None;observation_called=False
def alarm(signum,frame):fail('deadline')
def check():
 global last
 value=time.monotonic()
 if type(value)is not float or not math.isfinite(value) or value<last or value>=until:fail('deadline')
 last=value;return value
def fixed_module(raw_b64,pin,name):
 raw=base64.b64decode(raw_b64.encode('ascii'),validate=True)
 if (len(raw),hashlib.sha256(raw).hexdigest())!=pin:fail('source_pin')
 module=types.ModuleType(name);exec(compile(raw,'<fixed-'+name+'>','exec'),module.__dict__)
 return module
codec=fixed_module(CODEC_B64,CODEC_PIN,'p011_json_network_data')
ip=fixed_module(IP_B64,IP_PIN,'mta_ip_network_data')
cfg=codec.loads(base64.b64decode(CONFIG_B64.encode('ascii'),validate=True).decode('ascii'))
if (type(cfg)is not dict or set(cfg)!={'run_token','boot','pending_b64','journal_b64','historical'} or
 not re.fullmatch('[0-9a-f]{32}',cfg['run_token']) or
 not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',cfg['boot']) or
 type(cfg['historical'])is not dict or set(cfg['historical'])!=set(BASELINE_FIELDS)):fail('config')
expected_pending=base64.b64decode(cfg['pending_b64'].encode('ascii'),validate=True)
expected_journal=base64.b64decode(cfg['journal_b64'].encode('ascii'),validate=True)
if (len(expected_pending)!=340 or hashlib.sha256(expected_pending).hexdigest()!=PENDING_SHA or
 len(expected_journal)!=7138 or hashlib.sha256(expected_journal).hexdigest()!=JOURNAL_SHA):fail('config')
STOCK=(('/usr/bin/Z03','cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
 ('/usr/bin/control_engine','364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
 ('/usr/bin/zyb_z03_launch.sh','7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'))
CLI='/usr/sbin/wpa_cli';CLI_SHA='e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849'
TRACKED=('Z03','control_engine','weston','connmand','bluetoothd','wpa_supplicant')
RFLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
fd_rows=[];socket_rows=[];child_rows=[];raw_rows=[];passes=[];errors=[];close_errors=[]
raw_bytes=0;sequence=0;stage='begin';first_error=None;cli_row=None
def error_data(error):
 code=getattr(error,'code',None);number=getattr(error,'errno',None)
 return dict(code=code if code in CODES else 'unexpected',kind=type(error).__name__,
  errno=number if type(number)is int and 0<=number<=4095 else None)
def meta(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def retain(role,value):
 global raw_bytes
 size=len(value) if type(value)is bytes else 0
 raw_bytes+=size
 if raw_bytes>8388608 or len(raw_rows)>=8192:fail('file_limit')
 raw_rows.append((role,value))
def ebadf(number):
 try:os.fstat(number)
 except OSError as error:return error.errno==errno.EBADF
 return False
def open_row(path,role,directory=False,optional=False):
 check()
 if len(fd_rows)>=8192:fail('file_limit')
 row=dict(path=path,role=role,fd=None,called=True,returned=False,metadata=None,
  attempted=False,closed=False,unknown=True,error=None,close_error=None)
 fd_rows.append(row)
 try:row['fd']=os.open(path,RFLAGS|(os.O_DIRECTORY if directory else 0))
 except OSError as error:
  row['error']=error;row['unknown']=False;row['closed']=True
  if optional and type(error.errno)is int and error.errno in (errno.ENOENT,errno.ESRCH):return None
  raise
 row['returned']=True;row['unknown']=False;row['metadata']=meta(os.fstat(row['fd']))
 m=row['metadata']
 if (role!='proc_stat' and m[3:5]!=(0,0)) or not (stat.S_ISDIR(m[2]) if directory else stat.S_ISREG(m[2])):fail('file_shape')
 return row
def close_fd(row):
 if not row['returned']:return
 if row['attempted']:return
 row['attempted']=True
 try:os.close(row['fd']);row['closed']=ebadf(row['fd']);row['unknown']=not row['closed']
 except BaseException as error:row['close_error']=error;row['unknown']=True;raise
def read_file(path,maximum,role,optional=False,keep=False,binary=False):
 row=open_row(path,role,optional=optional)
 if row is None:return None,None
 parts=[];total=0;h=hashlib.sha256()
 try:
  while True:
   check();block=os.read(row['fd'],min(65536,maximum+1-total))
   if type(block)is not bytes:fail('file_shape')
   total+=len(block)
   if total>maximum:fail('file_limit')
   h.update(block)
   if not binary:parts.append(block)
   if not block:break
  if meta(os.fstat(row['fd']))!=row['metadata'] or meta(os.stat(path,follow_symlinks=False))!=row['metadata']:fail('file_changed')
  value=h.hexdigest() if binary else b''.join(parts)
  retain(role,value);check();return value,row
 finally:
  if not keep:close_fd(row)
def proc_stat(pid,optional=False):
 raw,row=read_file('/proc/'+str(pid)+'/stat',4096,'proc_stat',optional)
 if raw is None:return None
 match=re.fullmatch(b'([1-9][0-9]*) \((.*)\) ([A-Za-z]) (.*)\n',raw)
 if match is None or int(match.group(1))!=pid:fail('proc_format')
 f=match.group(4).split()
 if len(f)<36 or any(re.fullmatch(b'-?[0-9]+',v)is None for v in f[:19]):fail('proc_format')
 parent,flags,count,born=int(f[0]),int(f[5]),int(f[16]),int(f[18])
 if not 0<=parent<=0x7fffffff or not 0<=flags<=0xffffffff or not 1<=count<=128 or not 1<=born<2**64:fail('proc_format')
 try:name=match.group(2).decode('ascii');state=match.group(3).decode('ascii')
 except UnicodeError:fail('proc_format')
 if state not in ('R','S','D','T','t','Z','X','I','P'):fail('proc_format')
 return (pid,parent,born,name,flags,count,state,row['metadata'][3],row['metadata'][4])
def identity(pid):
 first=proc_stat(pid)
 if first[4]&0x200000 or first[6] in ('Z','X') or first[7:9]!=(0,0):fail('proc_inventory')
 path='/proc/'+str(pid);exe=os.readlink(path+'/exe')
 if type(exe)is not str or not exe.startswith('/') or exe.endswith(' (deleted)'):fail('proc_inventory')
 command,unused=read_file(path+'/cmdline',16384,'proc_cmdline')
 if not command or not command.endswith(b'\0'):fail('proc_inventory')
 directory=open_row(path+'/task','task_directory',directory=True)
 try:
  names=os.listdir(directory['fd'])
  if len(names)!=first[5] or len(names)>128 or any(re.fullmatch('[1-9][0-9]*',n)is None for n in names):fail('proc_inventory')
  tasks=[]
  for name in sorted(names,key=int):
   tid=int(name);raw,unused=read_file(path+'/task/'+name+'/stat',4096,'task_stat')
   match=re.fullmatch(b'([1-9][0-9]*) \((.*)\) ([A-Za-z]) (.*)\n',raw)
   if match is None or int(match.group(1))!=tid:fail('proc_format')
   f=match.group(4).split()
   if len(f)<36 or re.fullmatch(b'[0-9]+',f[18])is None:fail('proc_format')
   state=match.group(3).decode('ascii')
   if state not in ('R','S','D','T','t','I','P') or not 1<=int(f[18])<2**64:fail('proc_inventory')
   tasks.append([tid,int(f[18]),state])
  if sorted(os.listdir(directory['fd']),key=int)!=sorted(names,key=int):fail('proc_changed')
 finally:close_fd(directory)
 second=proc_stat(pid)
 if first[:4]!=second[:4] or bool(first[4]&0x200000)!=bool(second[4]&0x200000) or first[5]!=second[5] or first[7:9]!=second[7:9] or exe!=os.readlink(path+'/exe'):fail('proc_changed')
 if not any(row[0]==pid and row[1]==first[2] for row in tasks):fail('proc_inventory')
 return dict(pid=pid,start=first[2],exe=exe,argv_sha=hashlib.sha256(command).hexdigest(),tasks=tasks),first,command
def actor_key(actor):return (actor['pid'],actor['start'],actor['exe'],actor['argv_sha'],tuple(sorted((r[0],r[1]) for r in actor['tasks'])))
def actors():
 root=open_row('/proc','proc_directory',directory=True)
 try:names=os.listdir(root['fd'])
 finally:close_fd(root)
 if len(names)>4096:fail('proc_inventory')
 expected={name:[] for name in TRACKED};values=[];parents=[]
 for old in cfg['historical']['stock_actors']:
  name=old['exe'].rsplit('/',1)[-1]
  if name not in expected:fail('config')
  expected[name].append(old['exe'])
 for text in sorted((n for n in names if re.fullmatch('[1-9][0-9]*',n)),key=int):
  pid=int(text)
  if pid>0x7fffffff:fail('proc_format')
  current=proc_stat(pid,optional=True)
  if current is None or current[3]not in TRACKED:continue
  actor,facts,command=identity(pid)
  if actor['exe']not in expected[facts[3]]:fail('stock_identity')
  values.append(actor)
  if facts[3]in ('Z03','control_engine'):
   parent,pfacts,pcmd=identity(facts[1]);parents.append((facts[3],parent,pfacts[:6],pcmd))
   if facts[3]=='Z03' and b'/usr/bin/zyb_z03_launch.sh' not in pcmd.split(b'\0'):fail('parent_loop')
 for name in TRACKED:
  if not expected[name] or sum(v['exe'].rsplit('/',1)[-1]==name for v in values)!=len(expected[name]):fail('stock_identity')
 return sorted(values,key=lambda a:a['pid']),parents
NL=struct.Struct('<IHHII');GENL=struct.Struct('<BBH');ATTR=struct.Struct('<HH')
def nextseq():
 global sequence
 sequence+=1
 if sequence>0xffffffff:fail('netlink_limit')
 return sequence
def sock(protocol):
 row=dict(value=None,fd=None,called=True,returned=False,port=None,attempted=False,closed=False,unknown=True,error=None)
 socket_rows.append(row)
 value=socket.socket.__new__(socket.socket);row['value']=value
 try:
  socket.socket.__init__(value,socket.AF_NETLINK,socket.SOCK_RAW,protocol)
  row['fd']=value.fileno();row['returned']=True;row['unknown']=False
  value.bind((0,0));endpoint=value.getsockname()
  if type(endpoint)is not tuple or len(endpoint)!=2 or type(endpoint[0])is not int or not 1<=endpoint[0]<=0xffffffff or endpoint[1]!=0:fail('socket_shape')
  row['port']=endpoint[0];check();return row
 except BaseException as error:row['error']=error;raise
def close_socket(row):
 if row['attempted']:return
 row['attempted']=True
 try:
  if row['value']is None:fail('close_unknown')
  row['value'].close()
  row['closed']=row['value'].fileno()==-1 and (row['fd']is None or ebadf(row['fd']))
  row['unknown']=not row['closed']
 except BaseException as error:row['error']=error;row['unknown']=True;raise
def send(row,request):
 check();row['value'].settimeout(until-check());retain('netlink_request',request)
 if row['value'].sendto(request,(0,0))!=len(request):fail('netlink_format')
def receive(row):
 check();row['value'].settimeout(until-check())
 packet,ancillary,bits,peer=row['value'].recvmsg(65537,256,0)
 retain('netlink_packet',(packet,ancillary,bits,peer));retain('netlink_bytes',packet)
 if type(packet)is not bytes or not 16<=len(packet)<=65536 or ancillary or bits!=0:fail('netlink_format')
 if type(peer)is not tuple or peer!=(0,0):fail('kernel_peer')
 check();return packet
def attrs(body):
 fields={};at=0
 while at<len(body):
  if len(body)-at<4:fail('netlink_format')
  size,kind=ATTR.unpack_from(body,at);step=(size+3)&~3
  if size<4 or step>len(body)-at or any(body[at+size:at+step]) or not kind&0x3fff or kind&0x3fff in fields:fail('netlink_format')
  fields[kind&0x3fff]=(kind&0xc000,body[at+4:at+size]);at+=step
  if len(fields)>256:fail('netlink_limit')
 return fields
def integer(fields,kind,width,optional=False):
 if kind not in fields:
  if optional:return None
  fail('interface_format')
 flags,value=fields[kind]
 if flags or len(value)!=width:fail('interface_format')
 return struct.unpack('<H' if width==2 else '<I' if width==4 else '<Q',value)[0]
def exchange(row,family,command,dump=False):
 q=nextseq();data=ATTR.pack(12,2)+b'nl80211\0' if family==16 else b''
 request=NL.pack(20+len(data),family,1|(0x300 if dump else 0),q,row['port'])+GENL.pack(command,1 if dump else 2,0)+data
 send(row,request);values=[];done=False;packets=0;total=0
 while not done:
  packet=receive(row);packets+=1;total+=len(packet);at=0
  if packets>256 or total>2097152:fail('netlink_limit')
  while at<len(packet):
   if done or len(packet)-at<16:fail('netlink_format')
   size,kind,bits,seq,port=NL.unpack_from(packet,at);step=(size+3)&~3
   if size<16 or step>len(packet)-at or any(packet[at+size:at+step]) or seq!=q or port!=row['port']:fail('netlink_format')
   payload=packet[at+16:at+size];at+=step
   if bits&0x30:fail('netlink_done')
   if kind==2:
    if len(payload)<20:fail('netlink_format')
    number=struct.unpack_from('<i',payload)[0]
    if not -4095<=number<=0 or payload[4:20]!=request[:16]:fail('netlink_format')
    if number==0:fail('netlink_ack')
    fail('kernel_error',-number)
   if kind==3:
    if not dump or bits not in (0,2) or payload!=b'\0'*4:fail('netlink_done')
    done=True;continue
   if kind!=family or bits!=(2 if dump else 0) or len(payload)<4:fail('netlink_format')
   cmd,version,reserved=GENL.unpack_from(payload)
   if cmd!=(7 if dump else 1) or version!=(1 if dump else 2) or reserved:fail('netlink_format')
   values.append(payload[4:])
   if len(values)>128:fail('netlink_limit')
   if not dump:done=True
 if not dump and len(values)!=1:fail('netlink_format')
 return values
def wireless():
 row=sock(16)
 try:
  fields=attrs(exchange(row,16,3)[0]);family=integer(fields,1,2)
  if family<=16 or fields.get(2)!=(0,b'nl80211\0'):fail('interface_format')
  values=[]
  for raw in exchange(row,family,5,True):
   fields=attrs(raw);phy=integer(fields,1,4);wdev=integer(fields,153,8);iftype=integer(fields,5,4)
   index=integer(fields,3,4,True);name=None
   if 4 in fields:
    flags,value=fields[4]
    if flags or not 2<=len(value)<=16 or value[-1:]!=b'\0' or b'\0' in value[:-1]:fail('interface_format')
    try:name=value[:-1].decode('ascii')
    except UnicodeError:fail('interface_format')
    if not re.fullmatch('[A-Za-z0-9_.-]{1,15}',name):fail('interface_format')
   if not wdev or not 0<=iftype<=12 or (index is None)!=(name is None) or index is not None and index<=0:fail('interface_format')
   values.append(dict(phy=phy,wdev=wdev,ifindex=index,name=name,iftype=iftype))
  if len({v['wdev'] for v in values})!=len(values) or len({v['ifindex'] for v in values if v['ifindex']is not None})!=sum(v['ifindex']is not None for v in values):fail('interface_inventory')
  if len({v['name'] for v in values if v['name']is not None})!=sum(v['name']is not None for v in values):fail('interface_inventory')
  return sorted(values,key=lambda v:(v['phy'],v['wdev']))
 finally:close_socket(row)
def ipv4():
 row=sock(0);dumps=[]
 try:
  for kind in ('addresses','routes','rules'):
   collector=ip.DumpCollector(kind,nextseq(),row['port']);send(row,collector.request)
   while not collector.complete:collector.feed(receive(row))
   dumps.append(collector)
  return ip.snapshot_from_dumps(*dumps)
 finally:close_socket(row)
def ip_data(value):
 result={}
 for kind in ('addresses','routes','rules'):
  rows=[]
  for record in getattr(value,kind):
   item=dict(zip(record._fields,record))
   if kind=='addresses':
    label=item.pop('label');item['label_hex']=None if label is None else label.hex()
    if item['cacheinfo']is not None:item['cacheinfo']=list(item['cacheinfo'])
   if kind=='routes':item['metrics']=[list(r) for r in item['metrics']]
   rows.append(item)
  result[kind]=sorted(rows,key=lambda r:codec.dumps(r,sort_keys=True,separators=(',',':')))
 return result
def ipv6(path,widths):
 raw,unused=read_file(path,1048576,'ipv6');rows=[line.split() for line in raw.decode('ascii').splitlines()]
 if len(rows)>4096 or path!='/proc/net/ipv6_route' and len({tuple(r) for r in rows})!=len(rows):fail('ipv6_format')
 for row in rows:
  if len(row)!=len(widths)+1 or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',row[-1]):fail('ipv6_format')
  for index,width in enumerate(widths):
   pattern='[0-9a-f]{'+str(width)+'}'
   if not re.fullmatch(pattern,row[index]):fail('ipv6_format')
 return sorted(rows)
def status():
 check();row=dict(process=None,called=True,returned=False,streams=[],pipe_rows=[],ended=False,closed=False,unknown=True,error=None,close_error=None,out=None,err=None,code=None)
 child_rows.append(row);proc=subprocess.Popen.__new__(subprocess.Popen);row['process']=proc
 try:
  subprocess.Popen.__init__(proc,[CLI,'-i','wlan0','status'],executable='/proc/self/fd/'+str(cli_row['fd']),
   pass_fds=(cli_row['fd'],),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,
   env=dict(os.environ,LC_ALL='C'))
  row['returned']=True;row['unknown']=False;row['streams']=[proc.stdout,proc.stderr]
  for stream in row['streams']:
   pipe=dict(value=stream,value_original=stream,fd=None,metadata=None,attempted=False,closed=False,unknown=True,error=None)
   row['pipe_rows'].append(pipe);pipe['fd']=stream.fileno();pipe['metadata']=meta(os.fstat(pipe['fd']));pipe['unknown']=False
   if not stat.S_ISFIFO(pipe['metadata'][2]) or pipe['metadata'][3:5]!=(0,0):fail('child_unknown')
  out,err=proc.communicate(timeout=min(8.0,until-check()))
  row['out'],row['err'],row['code']=out,err,proc.returncode;row['ended']=proc.poll()is not None
  retain('wpa_stdout',out);retain('wpa_stderr',err)
  if type(proc.returncode)is not int or proc.returncode!=0 or err or not 0<len(out)<=65536:fail('status_failed')
  fields={}
  for line in out.splitlines():
   if not line or b'='not in line:fail('status_format')
   key,value=line.split(b'=',1)
   if key in fields or not re.fullmatch(b'[a-zA-Z0-9_]+',key):fail('status_format')
   fields[key]=value
  if fields.get(b'wpa_state')!=b'COMPLETED' or re.fullmatch(b'[0-9]{4}',fields.get(b'freq',b''))is None:fail('status_format')
  frequency=int(fields[b'freq'])
  if not 2412<=frequency<=2484:fail('status_format')
  check();return hashlib.sha256(out).hexdigest(),frequency
 except BaseException as error:
  row['error']=error
  for key,role in (('output','wpa_partial_stdout'),('stderr','wpa_partial_stderr')):
   value=getattr(error,key,None)
   if type(value)is bytes:retain(role,value)
  raise
 finally:
  try:close_child(row)
  except BaseException as error:close_errors.append(error)
def close_child(row):
 if row['closed'] and not row['unknown']:return
 proc=row['process']
 if not row['returned']:row['unknown']=True;return
 try:
  if proc.poll()is None:
   proc.terminate()
   try:proc.wait(timeout=2)
   except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
  row['ended']=proc.poll()is not None
  for pipe in row['pipe_rows']:
   if pipe['closed']:continue
   if pipe['value']is not pipe['value_original']:fail('child_unknown')
   pipe['attempted']=True
   try:
    if not pipe['value'].closed:pipe['value'].close()
    pipe['closed']=pipe['value'].closed and ebadf(pipe['fd']);pipe['unknown']=not pipe['closed']
   except BaseException as error:pipe['error']=error;pipe['unknown']=True;raise
  row['closed']=row['ended'] and len(row['pipe_rows'])==2 and all(p['closed'] and not p['unknown'] for p in row['pipe_rows'])
  row['unknown']=not row['closed']
 except BaseException as error:row['unknown']=True;row['close_error']=error;raise
def records():
 root='/var/volatile/tmp';path=root+'/p011-mta-go-session/go-'+cfg['run_token']+'/go-journal.json'
 pending,p=read_file(root+'/p011-mta-p2p-device.pending',131072,'old_pending')
 journal,j=read_file(path,131072,'old_journal')
 if pending!=expected_pending or journal!=expected_journal:fail('record_changed')
 return (p['metadata'],j['metadata'],hashlib.sha256(pending).hexdigest(),hashlib.sha256(journal).hexdigest())
def baseline():
 boot,unused=read_file('/proc/sys/kernel/random/boot_id',128,'boot')
 if boot.strip().decode('ascii')!=cfg['boot']:fail('record_changed')
 pins=[];pin_meta=[]
 for path,pin in STOCK:
  digest,row=read_file(path,134217728,'stock_image',binary=True)
  if digest!=pin:fail('file_pin')
  pins.append([path,digest]);pin_meta.append((path,row['metadata']))
 actor_rows,parents=actors();interfaces=wireless()
 station=[v for v in interfaces if v['name']=='wlan0' and v['iftype']==2]
 if len(station)!=1:fail('interface_inventory')
 state_sha,frequency=status();view=ipv4()
 value=dict(boot=cfg['boot'],stock_hashes=sorted(pins),stock_actors=actor_rows,station=station[0],
  station_state_sha=state_sha,station_frequency=frequency,interfaces=interfaces,ipv4=ip_data(view),
  ipv6_addresses=ipv6('/proc/net/if_inet6',(32,'2,8',2,2,2)),
  ipv6_routes=ipv6('/proc/net/ipv6_route',(32,2,32,2,32,8,8,8,8)),station_completed=True)
 return dict(data=value,parents=parents,pin_metadata=pin_meta,ipv4_structural=view.structural_key())
def data_key(value):
 data=dict(value)
 data['stock_actors']=sorted([list(actor_key(a)) for a in value['stock_actors']],key=repr)
 data['stock_hashes']=sorted(value['stock_hashes'])
 data['interfaces']=sorted(value['interfaces'],key=lambda r:(r['phy'],r['wdev']))
 for kind in ('addresses','routes','rules'):
  data['ipv4']=dict(data['ipv4'])
  data['ipv4'][kind]=sorted(value['ipv4'][kind],key=lambda r:codec.dumps(r,sort_keys=True,separators=(',',':')))
 data['ipv6_addresses']=sorted(value['ipv6_addresses']);data['ipv6_routes']=sorted(value['ipv6_routes'])
 return data
def parent_key(values):
 return tuple(sorted((name,actor_key(actor),facts[:4],facts[5],command) for name,actor,facts,command in values))
def observe_current(original_until):
 global start,until,last,observation_called,stage,first_error,cli_row
 # This single original worker cap may only be shortened, never renewed.
 if observation_called:fail('config')
 observation_called=True;start=time.monotonic();last=start
 if type(original_until)is not float or not math.isfinite(original_until) or original_until<=start:fail('deadline')
 until=min(original_until,start+60.0)
 old_handler=signal.getsignal(signal.SIGALRM);old_timer=signal.getitimer(signal.ITIMER_REAL)
 old_alarm_until=None if old_timer[0]<=0 else start+old_timer[0]
 if old_alarm_until is not None:until=min(until,old_alarm_until)
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,until-start)
 historical_compare={key:False for key in BASELINE_FIELDS};stable=False;record_stable=False
 try:
  stage='single_worker';tasks=open_row('/proc/self/task','self_task_directory',directory=True)
  try:
   names=os.listdir(tasks['fd'])
   if names!=[str(os.getpid())]:fail('proc_inventory')
  finally:close_fd(tasks)
  stage='cli_pin';digest,cli_row=read_file(CLI,16777216,'wpa_cli_image',keep=True,binary=True)
  if digest!=CLI_SHA or not cli_row['metadata'][2]&0o111:fail('file_pin')
  stage='old_record_before';before_record=records()
  stage='first_baseline';passes.append(baseline())
  stage='second_baseline';passes.append(baseline())
  first,second=passes
  stable=data_key(first['data'])==data_key(second['data']) and parent_key(first['parents'])==parent_key(second['parents']) and first['pin_metadata']==second['pin_metadata']
  current=data_key(second['data']);historical=data_key(cfg['historical'])
  historical_compare={key:current[key]==historical[key] for key in BASELINE_FIELDS}
  stage='old_record_after';after_record=records();record_stable=after_record==before_record
  boot,unused=read_file('/proc/sys/kernel/random/boot_id',128,'final_boot')
  if boot.strip().decode('ascii')!=cfg['boot']:fail('record_changed')
  digest,last_cli=read_file(CLI,16777216,'wpa_cli_image_after',binary=True)
  if digest!=CLI_SHA or last_cli['metadata']!=cli_row['metadata'] or meta(os.fstat(cli_row['fd']))!=cli_row['metadata']:fail('file_changed')
  if not stable:fail('baseline_changed')
  if not record_stable:fail('record_changed')
  check();stage='complete'
 except BaseException as error:first_error=error;errors.append(error)
 finally:
  # Closing originals is separate from activity. An expired cap never forbids a close.
  signal.setitimer(signal.ITIMER_REAL,30.0)
  for row in reversed(child_rows):
   try:close_child(row)
   except BaseException as error:close_errors.append(error)
  for row in reversed(socket_rows):
   try:close_socket(row)
   except BaseException as error:close_errors.append(error)
  for row in reversed(fd_rows):
   try:close_fd(row)
   except BaseException as error:close_errors.append(error)
  signal.setitimer(signal.ITIMER_REAL,0.0);signal.signal(signal.SIGALRM,old_handler)
  if old_alarm_until is not None:
   signal.setitimer(signal.ITIMER_REAL,max(0.000001,old_alarm_until-time.monotonic()),old_timer[1])
 closed=(not close_errors and all(r['closed'] and not r['unknown'] for r in fd_rows+socket_rows+child_rows))
 if first_error is None and not closed:
  first_error=close_errors[0] if close_errors else ReadError('close_unknown');errors.append(first_error)
 return dict(complete=first_error is None and stage=='complete' and closed,stage=stage,
  reason='ok' if first_error is None else error_data(first_error)['code'],
  error=None if first_error is None else error_data(first_error),close_errors=[error_data(e) for e in close_errors],
  current_baseline_stable=stable,old_record_unchanged=record_stable,historical_data_comparison=historical_compare,
  passes=passes,fd_rows=[dict((k,r[k]) for k in ('path','role','fd','called','returned','metadata','attempted','closed','unknown')) for r in fd_rows],
  socket_rows=[dict((k,r[k]) for k in ('fd','called','returned','port','attempted','closed','unknown')) for r in socket_rows],
  child_rows=[dict((k,r[k]) for k in ('called','returned','ended','closed','unknown','out','err','code')) for r in child_rows],
  pipe_rows=[dict((k,p[k]) for k in ('fd','metadata','attempted','closed','unknown')) for r in child_rows for p in r['pipe_rows']],
  raw=raw_rows,resource_inventory_closed=closed,raw_bytes=raw_bytes)
if __name__=='__main__':
 result=observe_current(time.monotonic()+60.0)
 print('RESULT='+repr(result))
 if result['complete']is not True:raise SystemExit(1)
'''


def literal(name, raw):
    value = base64.b64encode(raw).decode('ascii')
    return name + '=(\n' + ''.join(repr(value[i:i + 1024]) + '\n' for i in range(0, len(value), 1024)) + ')\n'


def make_source(inputs, config):
    raw = json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    source = ('import base64\n' + literal('CODEC_B64', inputs[BASE / 'runtime/p011_json.py']) +
              'CODEC_PIN=' + repr((INPUTS[3][1], INPUTS[3][2])) + '\n' +
              literal('IP_B64', inputs[BASE / 'runtime/mta_ip.py']) +
              'IP_PIN=' + repr((INPUTS[4][1], INPUTS[4][2])) + '\n' +
              literal('CONFIG_B64', raw) + 'BASELINE_FIELDS=' + repr(BASELINE_FIELDS) + '\n' +
              'CODES=' + repr(CODES) + '\nPENDING_SHA=' + repr(PENDING_SHA) + '\nJOURNAL_SHA=' + repr(JOURNAL_SHA) + '\n' + BODY)
    if len(source.encode('ascii')) > 131072 or any(len(line.encode('ascii')) > 2048 for line in source.splitlines()):
        raise ValueError('source_budget')
    return source


def projection(value, source_ok, transport_ok, remote_exit, remote_ok):
    available = type(value) is dict
    data = value if available else {}
    passes = data.get('passes', [])
    comparison = data.get('historical_data_comparison', {})
    rows = passes[-1]['data'] if len(passes) == 2 else {}
    interfaces = rows.get('interfaces', [])
    complete = (source_ok and transport_ok and remote_exit == 0 and remote_ok and
                data.get('complete') is True and data.get('resource_inventory_closed') is True)
    return dict(schema='p011-go-retirement-network-readonly-v1', diagnostic_complete=complete,
                pc_source_verified=source_ok, transport_unchanged=transport_ok,
                target_result_observed=available, target_exit_zero=remote_exit == 0,
                current_baseline_stable=data.get('current_baseline_stable') is True,
                old_record_unchanged=data.get('old_record_unchanged') is True,
                original_resource_inventory_closed=data.get('resource_inventory_closed') is True,
                reason=data.get('reason') if data.get('reason') in CODES else 'unexpected',
                baseline_pass_count=len(passes), interface_count=len(interfaces),
                non_netdev_wdev_count=sum(row.get('ifindex') is None for row in interfaces),
                stock_actor_count=len(rows.get('stock_actors', [])),
                ipv4_address_count=len(rows.get('ipv4', {}).get('addresses', [])),
                ipv4_route_count=len(rows.get('ipv4', {}).get('routes', [])),
                ipv4_rule_count=len(rows.get('ipv4', {}).get('rules', [])),
                ipv6_address_count=len(rows.get('ipv6_addresses', [])),
                ipv6_route_count=len(rows.get('ipv6_routes', [])),
                fd_count=len(data.get('fd_rows', [])), socket_count=len(data.get('socket_rows', [])),
                child_count=len(data.get('child_rows', [])), cleanup_error_count=len(data.get('close_errors', [])),
                historical_data_comparison={key:comparison.get(key) is True for key in BASELINE_FIELDS},
                historical_snapshot_data_equal=all(comparison.get(key) is True for key in BASELINE_FIELDS),
                device_file_writes=False, lock_operations=False, radio_mutations=False,
                old_session_terminalized=False, restoration_grant_issued=False,
                receive_available=False, send_available=False, phone_tested=False,
                private_raw_included=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-current', action='store_true')
    args = parser.parse_args()
    inputs = fixed_inputs()
    config = configuration(inputs)
    source = make_source(inputs, config)
    ast.parse(source, filename='<fixed-go-retirement-network-readonly-v1>', feature_version=(3, 5))
    ast.parse(inputs[BASE / 'runtime/mta_ip.py'].decode('ascii'), feature_version=(3, 5))
    own = Path(__file__).read_bytes()
    out = BASE / 'results' / ('go-retirement-network-readonly-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    snapshots = out / 'private-inputs'
    private.mkdir(parents=True, exist_ok=False)
    snapshots.mkdir(exist_ok=False)
    (private / 'target-source.py').write_bytes(source.encode('ascii'))
    (private / 'configuration.json').write_text(json.dumps(config, ensure_ascii=True, indent=2) + '\n', encoding='ascii')
    (snapshots / 'host-source.py').write_bytes(own)
    snapshot_rows = []
    for index, (path, size, pin) in enumerate(INPUTS):
        name = '%02d-%s' % (index, path.name)
        (snapshots / name).write_bytes(inputs[path])
        snapshot_rows.append(dict(name=name, bytes=size, sha256=pin))
    (private / 'inputs.json').write_text(json.dumps(snapshot_rows, ensure_ascii=True, indent=2) + '\n', encoding='ascii')
    value = None
    remote_exit = None
    remote_ok = False
    transport_ok = False
    host_error = None
    if args.read_current:
        try:
            # This fixed transport is imported only after its actual source pin check.
            from device_probe import Adb, ADB
            adb_raw = ADB.read_bytes()
            adb = Adb(private)
            payload = source.encode('ascii')
            command = ('python3 -B -c "import signal,sys;signal.alarm(15);s=sys.stdin.buffer.read(' + str(len(payload)) +
                       ');signal.alarm(0);exec(compile(s,\'<fixed-go-retirement-network-readonly-v1>\',\'exec\'));print(\'MTA_REMOTE_OK\')" '
                       'mta-go-network-readonly-v1; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            raw = adb.run('go-retirement-network-readonly', ['shell', command], timeout=125, input_data=payload)
            text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            values = [line[7:] for line in text.splitlines() if line.startswith('RESULT=')]
            exits = re.findall(r'^MTA_REMOTE_EXIT=([0-9]+)$', text, re.M)
            markers = [line for line in text.splitlines() if line == 'MTA_REMOTE_OK']
            if len(values) != 1 or len(exits) != 1 or len(markers) > 1:
                raise ValueError('target_marker_shape')
            value = ast.literal_eval(values[0])
            remote_exit = int(exits[0])
            remote_ok = markers == ['MTA_REMOTE_OK']
            transport_ok = ADB.read_bytes() == adb_raw
            (private / 'remote-result.json').write_text(json.dumps(value, ensure_ascii=True, indent=2,
                default=lambda item: {'bytes':len(item), 'bytes_b64':base64.b64encode(item).decode('ascii')} if type(item) is bytes else None) + '\n', encoding='ascii')
        except BaseException as error:
            host_error = type(error).__name__
            (private / 'host-error.txt').write_text(host_error + '\n', encoding='ascii')
    source_ok = False
    try:
        source_ok = fixed_inputs() == inputs and Path(__file__).read_bytes() == own
    except BaseException:
        pass
    public = projection(value, source_ok, transport_ok, remote_exit, remote_ok)
    public['device_requested'] = args.read_current
    public['source_only_complete'] = not args.read_current and source_ok
    public['host_error_observed'] = host_error is not None
    public['target_source_bytes'] = len(source.encode('ascii'))
    public['target_source_sha256'] = sha(source.encode('ascii'))
    if host_error is not None:
        public['diagnostic_complete'] = False
    result = (json.dumps(public, ensure_ascii=True, indent=2) + '\n').encode('ascii')
    readme = (b'Fixed GO64 network DATA observation only. Default PC-only source preparation; --read-current performs one bounded session.\n'
              b'Two complete GET_INTERFACE dumps include non-netdev WDEVs; three complete original mta_ip IPv4 dumps, proc IPv6 tables, six daemon identities, parent loop and fixed wpa_cli STATUS. ACK0 is rejected, never dump completion.\n'
              b'Historical field equality and current file/process/network observations are DATA, not original Snapshot/Native/Proc CloseProof, restore or permission. No locks, RF/scan/SET, record edits, legacy runner or reboot.\n'
              b'Only original private diagnostic wpa_cli children may be terminated during bounded cleanup. All raw identifiers/source/records/packet/child output stay outside this ZIP.\n')
    (out / 'result.json').write_bytes(result)
    (out / 'README.txt').write_bytes(readme)
    with zipfile.ZipFile(out / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'public-result.zip', 'r') as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or archive.read('result.json') != result or archive.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(directory=str(out), result=public), ensure_ascii=True))
    return 0 if public['diagnostic_complete'] or public['source_only_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
