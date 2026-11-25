"""Pinned read-only CLIENT caps checker; default does not initialize ADB.

Only ROOT may run the explicitly hash-reviewed entry. No device staging,
native program, scan, RF, interface/IP write, lock, pending or owner action.
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
import secrets
import stat
import sys
import time
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
ADB_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
MODULE_PINS = (
    ('mta_client_caps', 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'))
STOCK_PINS = {
    '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
MAX_SOURCE, MAX_OUTPUT, MAX_TRACEBACK = 262144, 16 * 1024 * 1024, 65536
STATUS_BOOLS = frozenset(('attempted', 'finished', 'read_success', 'socket_closed',
                         'resource_pending', 'has_unassessed_fields'))
STATUS_COUNTS = {'datagram_count': 129, 'message_count': 257, 'unassessed_count': 4096}
REASONS = frozenset(('not_started', 'read_closed', 'truncated_attribute', 'nonzero_attribute_padding',
    'attribute_budget', 'attribute_flags', 'scalar_format', 'family_attribute', 'family_name',
    'family_nested_index', 'family_nested_attribute', 'family_group_name', 'family_operation',
    'family_group_id', 'family_nested_duplicate', 'family_missing_attribute', 'family_abi',
    'invalid_phy', 'invalid_timeout', 'invalid_factory', 'invalid_clock', 'invalid_clock_value',
    'clock_regressed', 'deadline', 'timeout_readback', 'short_send', 'invalid_receive',
    'receive_budget', 'receive_truncated', 'receive_control', 'not_kernel_peer',
    'message_after_terminal', 'truncated_message', 'message_budget', 'message_identity',
    'dump_interrupted', 'message_flags', 'netlink_error', 'netlink_overrun', 'invalid_done',
    'wrong_family', 'generic_header', 'fragment_budget', 'unreviewed_top_attribute',
    'duplicate_top_attribute', 'wiphy_name_format', 'binary_format', 'wiphy_identity',
    'wiphy_generation_changed', 'caps_schema', 'missing_caps_fields', 'already_attempted',
    'unsupported_platform', 'socket_contract', 'inheritable_readback', 'bound_port',
    'protocol_features_format', 'split_not_supported', 'os_error', 'unexpected_read_error',
    'interrupted', 'socket_close_unverified'))
CAP_BOOLS = frozenset(('iftypes_present', 'software_iftypes_present', 'combinations_present', 'commands_present'))
CAP_COUNTS = {'phy_count': 1, 'combination_count': 16, 'limit_count': 256, 'command_count': 256,
    'beacon_match_present_count': 16, 'radar_widths_present_count': 16,
    'radar_regions_present_count': 16, 'bi_min_gcd_present_count': 16}
TYPE_SETS = frozenset(('iftypes', 'software_iftypes', 'limit_iftypes'))

PHY = r'''
def phy_name(names):
 if type(names) is not list or len(names)!=1 or type(names[0]) is not str or re.match(r'^phy(0|[1-9][0-9]{0,9})\Z',names[0]) is None:raise ValueError('phy_selection')
 if int(names[0][3:])>0xffffffff:raise ValueError('phy_selection')
 return names[0]
def phy_index(name,raw):
 if type(raw) is not bytes or re.match(br'^(0|[1-9][0-9]{0,9})\n?\Z',raw) is None:raise ValueError('phy_index')
 value=int(raw)
 if value!=int(name[3:]) or not 0<=value<=0xffffffff:raise ValueError('phy_identity')
 return value
'''

COMMON = r'''
import hashlib,math,os,re,sys,time
if sys.flags.optimize:raise ValueError('optimized')
if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target')
end=time.monotonic()+5.0
def budget():
 value=end-time.monotonic()
 if not math.isfinite(value) or value<=0:raise ValueError('deadline')
 return value
def bounded(path,limit):
 budget()
 with open(path,'rb') as handle:raw=handle.read(limit+1)
 if len(raw)>limit:raise ValueError('read_limit')
 return raw
'''

BASELINE = r'''
def digest(path):
 value=hashlib.sha256();total=0
 with open(path,'rb') as handle:
  while True:
   budget();block=handle.read(65536)
   if not block:break
   total+=len(block)
   if total>67108864:raise ValueError('file_limit')
   value.update(block)
 return value.hexdigest()
def process_stat(path):
 raw=bounded(path,8192).decode('ascii','strict');at=raw.rindex(')');head=raw[:at]
 fields=raw[at+2:].split()
 if len(fields)<20 or fields[0] in ('Z','X','x'):raise ValueError('actor_state')
 pid=int(head.split('(',1)[0].strip());start=int(fields[19])
 if pid<=0 or start<=0:raise ValueError('actor_stat')
 return pid,start,head.split('(',1)[1]
def actor(pid):
 folder='/proc/'+str(pid);first=process_stat(folder+'/stat')
 args=bounded(folder+'/cmdline',16384)
 if not args or args[-1:]!=b'\0':raise ValueError('actor_args')
 exe=os.readlink(folder+'/exe')
 if not exe.startswith('/') or len(exe)>4096:raise ValueError('actor_exe')
 names=os.listdir(folder+'/task')
 if not 1<=len(names)<=256 or any(re.match(r'^[1-9][0-9]*\Z',n) is None for n in names):raise ValueError('tasks')
 tasks=[]
 for tid in sorted(names,key=int):
  row=process_stat(folder+'/task/'+tid+'/stat')
  if row[0]!=int(tid):raise ValueError('task_identity')
  tasks.append((row[0],row[1]))
 if sorted(os.listdir(folder+'/task'),key=int)!=sorted(names,key=int) or process_stat(folder+'/stat')!=first:raise ValueError('actor_changed')
 return {'name':first[2],'pid':first[0],'start':first[1],'exe':exe,'argv':args,'tasks':tuple(tasks)}
names=('Z03','control_engine','weston','wpa_supplicant','connmand','bluetoothd');actors=[]
entries=os.listdir('/proc')
if len(entries)>8192:raise ValueError('process_budget')
for entry in entries:
 if not entry.isdigit():continue
 try:comm=bounded('/proc/'+entry+'/comm',64).decode('ascii','strict').rstrip('\n')
 except (OSError,UnicodeError):continue
 if comm in names:
  row=actor(int(entry))
  if row['name']!=comm:raise ValueError('actor_changed')
  actors.append(row)
  if len(actors)>128:raise ValueError('actor_budget')
for name in ('Z03','control_engine','weston'):
 rows=[r for r in actors if r['name']==name]
 if len(rows)!=1 or rows[0]['exe']!='/usr/bin/'+name:raise ValueError('stock_actor')
hashes={p:digest(p) for p in STOCK_PINS}
if hashes!=STOCK_PINS:raise ValueError('stock_pin')
interfaces=[];names=os.listdir('/sys/class/net')
if not 1<=len(names)<=64:raise ValueError('interface_count')
for name in sorted(names):
 if name in ('.','..') or re.match(r'^[A-Za-z0-9_.:-]{1,15}\Z',name) is None:raise ValueError('interface_name')
 folder='/sys/class/net/'+name
 identity=tuple(bounded(folder+'/'+field,256) for field in ('ifindex','iflink','type','flags','operstate','address'))
 link=os.readlink(folder)
 if not link or len(link)>4096:raise ValueError('interface_origin')
 interfaces.append((name,identity,link))
result={'hashes':hashes,'actors':sorted(actors,key=lambda r:r['pid']),'interfaces':interfaces,
 'boot':bounded('/proc/sys/kernel/random/boot_id',128),'route4':bounded('/proc/net/route',1048576),
 'address6':bounded('/proc/net/if_inet6',1048576),'route6':bounded('/proc/net/ipv6_route',1048576)}
budget();print('RESULT='+repr(result))
'''

CAPS_BODY = r'''
import base64,types
stage='modules';reader=None;decoded=None;traceback_text=None;failure={'stage':'complete','class':'none','errno':0}
def private(value):
 if isinstance(value,tuple):return tuple(private(v) for v in value)
 if type(value) is list:return [private(v) for v in value]
 if type(value) is dict:return {k:private(v) for k,v in value.items()}
 if value is None or type(value) in (bool,int,float,str,bytes):return value
 raise ValueError('private_type')
summary={k:False for k in CAP_BOOLS};summary.update({k:0 for k in CAP_COUNTS});summary.update({k:[] for k in TYPE_SETS})
try:
 for name,pin,encoded in PINNED_MODULES:
  raw=base64.b64decode(encoded.encode('ascii'),validate=True)
  if hashlib.sha256(raw).hexdigest()!=pin or name in sys.modules:raise ValueError('memory_pin')
  module=types.ModuleType(name);module.__file__='<p011-caps-pinned-memory>';sys.modules[name]=module
  exec(raw,module.__dict__)
 stage='phy';budget();name=phy_name(os.listdir('/sys/class/ieee80211'))
 index=phy_index(name,bounded('/sys/class/ieee80211/'+name+'/index',32))
 stage='read';reader=sys.modules['mta_client_caps_transport'].ClientCapsReader(index,timeout=5.0)
 decoded=reader.read()  # Exactly one fixed three-request operation; never retry.
 phy=decoded.phys[0]
 summary.update({'phy_count':len(decoded.phys),'iftypes':list(phy.iftypes),'software_iftypes':list(phy.software_iftypes),
  'limit_iftypes':sorted(set(t for combo in phy.combinations for limit in combo.limits for t in limit.types)),
  'combination_count':len(phy.combinations),'limit_count':sum(len(x.limits) for x in phy.combinations),'command_count':len(phy.commands)})
 for field in CAP_BOOLS:summary[field]=getattr(phy,field)
 for field in ('beacon_match','radar_widths','radar_regions','bi_min_gcd'):
  summary[field+'_present_count']=sum(getattr(x,field+'_present') for x in phy.combinations)
except BaseException as error:
 import traceback
 traceback_text=traceback.format_exc()  # PTY may merge stderr; keep complete text in private RESULT only.
 kind='os_error' if isinstance(error,OSError) else 'value_error' if isinstance(error,ValueError) else 'interrupted' if not isinstance(error,Exception) else 'unexpected'
 number=getattr(error,'errno',0)
 failure={'stage':stage,'class':kind,'errno':number if type(number) is int and 0<=number<=4095 else 0}
payload={'datagrams':(),'requests':(),'wiphy_messages':(),'unassessed':(),'decoded':None,'traceback':traceback_text}
if reader is not None:
 payload.update({'datagrams':private(reader.raw_datagrams),'requests':private(reader.raw_requests),
  'wiphy_messages':private(reader.raw_wiphy_messages),'unassessed':private(reader.unprojected_attributes),'decoded':private(decoded)})
print('RESULT='+repr({'status':None if reader is None else reader.status(),'caps':summary,'failure':failure,'private':payload}))
'''


def _read(path, pin=None):
    path=Path(path)
    if any(p.is_symlink() for p in (path,)+tuple(path.parents)):raise ValueError('source_link')
    first=path.stat()
    if not stat.S_ISREG(first.st_mode) or not 0<first.st_size<=MAX_SOURCE:raise ValueError('source_size')
    with path.open('rb') as handle:
        opened=os.fstat(handle.fileno());data=handle.read(MAX_SOURCE+1)
    last=path.stat()
    for field in ('st_dev','st_ino','st_size','st_mtime_ns'):
        if getattr(first,field)!=getattr(opened,field) or getattr(first,field)!=getattr(last,field):raise ValueError('source_changed')
    if len(data)!=first.st_size or pin is not None and hashlib.sha256(data).hexdigest()!=pin:raise ValueError('source_pin')
    return data


def source_check():
    modules=[(name,pin,_read(BASE/'runtime'/(name+'.py'),pin)) for name,pin in MODULE_PINS]
    helper=_read(BASE/'host/device_probe.py',ADB_PIN);checker=_read(Path(__file__))
    header='STOCK_PINS='+repr(STOCK_PINS)+'\n'
    encoded=['PINNED_MODULES=(\n']
    for name,pin,data in modules:
        payload=base64.b64encode(data).decode('ascii')
        encoded.append('('+repr(name)+','+repr(pin)+',\n')
        encoded.extend(repr(payload[i:i+256])+'\n' for i in range(0,len(payload),256))
        encoded.append('),\n')
    encoded.append(')\n')
    definitions='CAP_BOOLS='+repr(tuple(sorted(CAP_BOOLS)))+'\nCAP_COUNTS='+repr(CAP_COUNTS)+'\nTYPE_SETS='+repr(tuple(sorted(TYPE_SETS)))+'\n'
    sources=(header+COMMON+BASELINE,header+COMMON+PHY+''.join(encoded)+definitions+CAPS_BODY)
    for source in sources+tuple(data.decode('utf-8') for _,_,data in modules):
        tree=ast.parse(source,feature_version=(3,5))
        if any(isinstance(n,ast.Assert) for n in ast.walk(tree)):raise ValueError('source_assert')
    if any(len(s.encode('utf-8'))>MAX_SOURCE or max(map(len,s.splitlines()))>2048 for s in sources):raise ValueError('source_budget')
    return {'source_check_pass':True,'checker_sha256':hashlib.sha256(checker).hexdigest(),
        'adb_helper_sha256':hashlib.sha256(helper).hexdigest(),'decoder_sha256':MODULE_PINS[0][1],
        'transport_sha256':MODULE_PINS[1][1]},sources


def _transport(source):
    data=(source+"\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    if not 0<len(data)<=MAX_SOURCE:raise ValueError('source_budget')
    payload=base64.b64encode(zlib.compress(data)).decode('ascii')
    command=('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\''+payload+'\')))"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    if len(command)<=3500:return command,None,None
    command=('python3 -B -c "import sys;exec(sys.stdin.buffer.read('+str(len(data))+'))" p011-client-caps-readonly; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    return command,data,data


def _parse(raw,echo=None):
    if type(raw) is not bytes or len(raw)>MAX_OUTPUT:raise ValueError('output_budget')
    value=raw.decode('utf-8','strict').replace('\r\r\n','\n').replace('\r\n','\n')
    if echo is not None:
        expected=echo.decode('utf-8','strict').replace('\r\r\n','\n').replace('\r\n','\n')
        if value.startswith(expected):value=value[len(expected):]
    lines=[line for line in value.split('\n') if line]
    if len(lines)!=3 or not lines[0].startswith('RESULT=') or lines[1:]!=['MTA_REMOTE_OK','MTA_REMOTE_EXIT=0']:raise ValueError('remote_frame')
    return ast.literal_eval(lines[0][7:])


def _remote(adb,label,source,timeout):
    command,data,echo=_transport(source)
    try:raw=adb.run(label,['shell',command],timeout=timeout,input_data=data)
    except BaseException:
        stem=adb.directory/('%02d-%s'%(adb.index,label))
        captured=Path(str(stem)+'.stdout.raw')
        if captured.exists():
            with captured.open('rb') as handle:partial=handle.read(MAX_OUTPUT+1)
            exits=re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)',partial)
            exit_value=exits[0].decode('ascii') if len(exits)==1 else 'INVALID'
        else:exit_value='NOT_RECORDED'
        Path(str(stem)+'.remote-exit').write_text(exit_value,encoding='ascii')
        raise
    exits=re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)',raw)
    value=exits[0].decode('ascii') if len(exits)==1 else 'INVALID'
    (adb.directory/('%02d-%s.remote-exit'%(adb.index,label))).write_text(value,encoding='ascii')
    return _parse(raw,echo)


def _baseline(value):
    if type(value) is not dict or set(value)!={'hashes','actors','interfaces','boot','route4','address6','route6'} or value['hashes']!=STOCK_PINS:raise ValueError('baseline_schema')
    for name,limit in (('boot',128),('route4',1048576),('address6',1048576),('route6',1048576)):
        if type(value[name]) is not bytes or len(value[name])>limit:raise ValueError('baseline_raw')
    if re.fullmatch(br'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n?',value['boot']) is None:raise ValueError('baseline_boot')
    rows=value['actors']
    if type(rows) is not list or not 3<=len(rows)<=128:raise ValueError('baseline_actors')
    for row in rows:
        if type(row) is not dict or set(row)!={'name','pid','start','exe','argv','tasks'}:raise ValueError('baseline_actor')
        if row['name'] not in ('Z03','control_engine','weston','wpa_supplicant','connmand','bluetoothd') or type(row['name']) is not str:raise ValueError('baseline_actor_name')
        if any(type(row[k]) is not int or not 0<row[k]<=2**63-1 for k in ('pid','start')) or type(row['exe']) is not str or not row['exe'].startswith('/') or len(row['exe'])>4096:raise ValueError('baseline_actor_identity')
        if type(row['argv']) is not bytes or not 1<=len(row['argv'])<=16384 or row['argv'][-1:]!=b'\0':raise ValueError('baseline_argv')
        tasks=row['tasks']
        if type(tasks) is not tuple or not 1<=len(tasks)<=256 or any(type(t) is not tuple or len(t)!=2 or any(type(v) is not int or not 0<v<=2**63-1 for v in t) for t in tasks):raise ValueError('baseline_tasks')
        if tasks!=tuple(sorted(set(tasks))) or (row['pid'],row['start']) not in tasks or len({t[0] for t in tasks})!=len(tasks):raise ValueError('baseline_task_identity')
    if [r['pid'] for r in rows]!=sorted(set(r['pid'] for r in rows)):raise ValueError('baseline_actor_order')
    for name in ('Z03','control_engine','weston'):
        selected=[r for r in rows if r['name']==name]
        if len(selected)!=1 or selected[0]['exe']!='/usr/bin/'+name:raise ValueError('baseline_stock_actor')
    interfaces=value['interfaces']
    if type(interfaces) is not list or not 1<=len(interfaces)<=64:raise ValueError('baseline_interfaces')
    for row in interfaces:
        if type(row) is not tuple or len(row)!=3 or type(row[0]) is not str or re.fullmatch('[A-Za-z0-9_.:-]{1,15}',row[0]) is None or row[0] in ('.','..'):raise ValueError('baseline_interface')
        if type(row[1]) is not tuple or len(row[1])!=6 or any(type(v) is not bytes or not 0<len(v)<=256 for v in row[1]) or type(row[2]) is not str or not 0<len(row[2])<=4096:raise ValueError('baseline_interface_identity')
        index,link,kind,flags,state,address=row[1]
        if re.fullmatch(br'[1-9][0-9]{0,9}\n?',index) is None or not 0<int(index)<=0x7fffffff or re.fullmatch(br'(0|[1-9][0-9]{0,9})\n?',link) is None or not 0<=int(link)<=0x7fffffff:raise ValueError('baseline_interface_index')
        if re.fullmatch(br'[0-9]{1,5}\n?',kind) is None or re.fullmatch(br'0x[0-9a-f]{1,8}\n?',flags) is None or state.rstrip(b'\n') not in (b'unknown',b'notpresent',b'down',b'lowerlayerdown',b'testing',b'dormant',b'up'):raise ValueError('baseline_interface_flags')
        if re.fullmatch(br'(?:[0-9a-f]{2}(?::[0-9a-f]{2}){0,31})?\n?',address) is None:raise ValueError('baseline_interface_address')
    names=[r[0] for r in interfaces]
    if names!=sorted(set(names)) or 'lo' not in names:raise ValueError('baseline_interface_order')
    return value


def _caps_result(value):
    if type(value) is not dict or set(value)!={'status','caps','failure','private'}:raise ValueError('caps_result')
    status,summary,failure,private=value['status'],value['caps'],value['failure'],value['private']
    if type(summary) is not dict or set(summary)!=CAP_BOOLS|set(CAP_COUNTS)|TYPE_SETS:raise ValueError('caps_fields')
    if any(type(summary[k]) is not bool for k in CAP_BOOLS) or any(type(summary[k]) is not int or not 0<=summary[k]<=v for k,v in CAP_COUNTS.items()):raise ValueError('caps_types')
    for k in TYPE_SETS:
        v=summary[k]
        if type(v) is not list or any(type(t) is not int or not 1<=t<=12 for t in v) or v!=sorted(set(v)):raise ValueError('caps_iftypes')
    if not set(summary['software_iftypes'])<=set(summary['iftypes']) or not set(summary['limit_iftypes'])<=set(summary['iftypes']):raise ValueError('caps_iftype_coverage')
    if type(failure) is not dict or set(failure)!={'stage','class','errno'} or failure['stage'] not in ('modules','phy','read','complete') or failure['class'] not in ('none','value_error','os_error','unexpected','interrupted') or type(failure['errno']) is not int or not 0<=failure['errno']<=4095:raise ValueError('caps_failure')
    if type(private) is not dict or set(private)!={'datagrams','requests','wiphy_messages','unassessed','decoded','traceback'} or any(type(private[k]) is not tuple for k in ('datagrams','requests','wiphy_messages','unassessed')):raise ValueError('caps_private')
    trace=private['traceback']
    if trace is not None and (type(trace) is not str or len(trace)>MAX_TRACEBACK or len(trace.encode('utf-8','strict'))>MAX_TRACEBACK):raise ValueError('caps_traceback')
    if status is not None:
        if type(status) is not dict or set(status)!=STATUS_BOOLS|set(STATUS_COUNTS)|{'reason'} or any(type(status[k]) is not bool for k in STATUS_BOOLS):raise ValueError('status_fields')
        if any(type(status[k]) is not int or not 0<=status[k]<=v for k,v in STATUS_COUNTS.items()) or type(status['reason']) is not str or status['reason'] not in REASONS:raise ValueError('status_values')
        if len(private['datagrams'])!=status['datagram_count'] or len(private['unassessed'])!=status['unassessed_count'] or not 0<=len(private['requests'])<=3 or not 0<=len(private['wiphy_messages'])<=64:raise ValueError('private_counts')
        if status['has_unassessed_fields']!=(status['unassessed_count']>0):raise ValueError('unassessed_presence')
    if any(summary[k]>summary['combination_count'] for k in ('beacon_match_present_count','radar_widths_present_count','radar_regions_present_count','bi_min_gcd_present_count')):raise ValueError('caps_presence_count')
    good=bool(status is not None and all(status[k] for k in ('attempted','finished','read_success','socket_closed')) and not status['resource_pending'] and status['reason']=='read_closed' and status['datagram_count']>=3 and status['message_count']>=4 and failure=={'stage':'complete','class':'none','errno':0} and len(private['requests'])==3 and private['wiphy_messages'] and private['decoded'] is not None and summary['phy_count']==1 and all(summary[k] for k in CAP_BOOLS) and summary['combination_count']>0 and summary['iftypes'])
    if status is not None and status['read_success'] and not good:raise ValueError('false_reader_success')
    return {'pass':good,'status':status,'caps':summary,'failure':failure}


def _classify(error):
    code='timeout' if isinstance(error,TimeoutError) else 'os_error' if isinstance(error,OSError) else 'value_error' if isinstance(error,ValueError) else 'runtime_error' if isinstance(error,RuntimeError) else 'unexpected'
    number=getattr(error,'errno',0)
    return code,number if type(number) is int and 0<=number<=4095 else 0


def run_reviewed(expected_checker,output=None,adb_factory=None):
    checks,sources=source_check()
    if type(expected_checker) is not str or re.fullmatch('[0-9a-f]{64}',expected_checker) is None or expected_checker!=checks['checker_sha256']:raise ValueError('reviewed_checker_pin')
    if adb_factory is None:
        raw=_read(BASE/'host/device_probe.py',ADB_PIN)
        helper=types.ModuleType('p011_reviewed_adb');helper.__file__=str(BASE/'host/device_probe.py')
        exec(raw,helper.__dict__);adb_factory=helper.Adb  # selector/Adb unmodified
    out=Path(output) if output is not None else ROOT/'logs'/('MtaP011-ClientCapsReadOnly-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True,exist_ok=False)
    report=dict(checks,evidence_level='P011_READONLY_CLIENT_CAPS')
    report.update({'pass':False,'caps_read_requested':False,'caps_read_invoked':False,'rf_operations':False,'device_configuration_writes':False,
        'before_stock_verified':False,'after_stock_verified':False,'limited_baseline_equal':False,'all_ipv4_tables_rules':'NOT_EVALUATED',
        'p2p_restoration':'NOT_EVALUATED','client_initialization':'NOT_TESTED','association':'NOT_TESTED','phone_interop':'NOT_TESTED',
        'receive_available':False,'send_available':False,'selector_raw_captured':False})
    adb=before=after=caps=None;stage='target';deadline=time.monotonic()+25.0
    def budget(maximum):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('host_deadline')
        return min(maximum,remaining)
    try:
        adb=adb_factory(out/'private-raw')
        stage='before';before=_baseline(_remote(adb,'before-client-caps',sources[0],budget(7.0)));report['before_stock_verified']=True
        if budget(25.0)<14.0:raise TimeoutError('caps_budget_admission')
        stage='caps';report['caps_read_requested']=True;report['caps_read_invoked']='NOT_RECORDED'
        caps=_caps_result(_remote(adb,'fixed-client-caps',sources[1],budget(7.0)));report['caps']=caps
        report['caps_read_invoked']=bool(caps['status'] is not None and caps['status']['attempted'])
    except Exception as error:
        report['error_stage']=stage;report['error_class'],report['errno']=_classify(error)
    finally:
        if adb is not None:
            try:
                after=_baseline(_remote(adb,'after-client-caps',sources[0],budget(7.0)));report['after_stock_verified']=True
            except Exception as error:report['after_error_class'],report['after_errno']=_classify(error)
        if before is not None and after is not None:
            report['limited_baseline_equal']=before==after
            report['station_present_before']=any(r[0]=='wlan0' for r in before['interfaces'])
            report['station_present_after']=any(r[0]=='wlan0' for r in after['interfaces'])
        report['pass']=bool(caps is not None and caps['pass'] and report['limited_baseline_equal'] and report['before_stock_verified'] and report['after_stock_verified'] and 'error_class' not in report and 'after_error_class' not in report)
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('Read-only pinned nl80211 caps: one shared five-second socket; three fixed GET requests.\nNo RF, staging, native executable, IP/network/sysctl/lock/pending/owner action.\nIndependent limited boot/stock/known actors+whole task IDs/sysfs identity/main IPv4 route/full IPv6 raw comparison.\nAll IPv4 addresses/all tables/policy rules NOT_EVALUATED. Missing wlan0 never proves restoration.\nNo CLIENT initialization, association, phone acceptance or receive/send availability.\nADB command stdout/stderr/host+remote exits and complete caps datagrams/messages/requests/unassessed attributes remain private.\nOriginal approved selector is unchanged; its enumeration raw is not independently captured.\n',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    return report,out,archive


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--source-check-only',action='store_true');modes.add_argument('--execute-reviewed',action='store_true')
    parser.add_argument('--expected-checker-sha256');args=parser.parse_args(argv)
    if not args.execute_reviewed and args.expected_checker_sha256 is not None:parser.error('Checker pin requires explicit execution')
    if args.execute_reviewed and args.expected_checker_sha256 is None:parser.error('Explicit current checker SHA-256 required')
    try:
        if not args.execute_reviewed:
            checks,_=source_check();print(json.dumps(checks,indent=2));return 0
        report,out,archive=run_reviewed(args.expected_checker_sha256)
        print(json.dumps(report,indent=2));print('RESULT_DIRECTORY='+str(out));print('RESULT_ZIP='+str(archive))
        return 0 if report['pass'] else 1
    except Exception as error:
        kind,number=_classify(error)
        print(json.dumps({'pass':False,'error_stage':'source_or_output','error_class':kind,'errno':number,'caps_read_invocation':'NOT_RECORDED'}))
        return 1


if __name__=='__main__':sys.exit(main())
