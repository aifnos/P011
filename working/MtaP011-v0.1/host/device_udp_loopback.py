"""Reviewed, bounded synthetic loopback UDP check; default is HOST source only.

Never uses DHCP ports, arbitrary interfaces/addresses, a candidate import or a
radio/network configuration operation. Raw ADB output remains local/private.
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
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
SAFETY_PIN = '03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81'
ADB_HELPER_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
STOCK_PINS = {
    '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
MAX_SOURCE = 128 * 1024
MAX_OUTPUT = 256 * 1024
ERROR_CLASSES = frozenset(('none', 'value_error', 'os_error', 'timeout', 'runtime_error', 'unexpected'))
STAGES = frozenset(('not_recorded', 'target', 'api', 'interface', 'create', 'options',
                    'bind', 'send', 'receive', 'readback', 'close', 'complete'))
COUNTS = frozenset(('sockets_created', 'datagrams_sent', 'datagrams_received',
                   'close_attempts', 'closed_readbacks', 'close_failures'))
BOOLEANS = frozenset(('pass', 'loopback_index_checked', 'initial_fds_checked',
    'pktinfo_option_readback', 'device_binding_readback', 'ephemeral_ports_checked',
    'send_interface_source_checked', 'receive_interface_destination_checked',
    'source_peer_checked', 'ancillary_exact', 'no_truncation', 'budget_checked',
    'all_sockets_closed'))
BODY_FIELDS = COUNTS | BOOLEANS | {'error_stage', 'error_class', 'errno'}

BASELINE_BODY = r'''
import math,subprocess,sys,time
if sys.flags.optimize:raise ValueError('baseline_optimized')
if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('baseline_target')
end=time.monotonic()+4.0
def budget():
 value=end-time.monotonic()
 if not math.isfinite(value) or value<=0:raise ValueError('baseline_deadline')
 return value
def bounded(path,limit):
 budget()
 with open(path,'rb') as f:raw=f.read(limit+1)
 if len(raw)>limit:raise ValueError('baseline_limit')
 return raw
def fingerprint(raw):return hashlib.sha256(raw).hexdigest()
snapshot=stock_snapshot();require_stock(snapshot);budget()
network=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 try:row=identity(pid)
 except (OSError,ValueError):continue
 if row['name'] in ('wpa_supplicant','connmand','bluetoothd'):
  row['args_digest']=fingerprint(bounded('/proc/'+pid+'/cmdline',16384));network.append(row)
 if row['name'].startswith('mta-wpa'):raise ValueError('baseline_project_actor')
interfaces=[]
names=os.listdir('/sys/class/net')
if not 1<=len(names)<=64:raise ValueError('baseline_interfaces')
for name in sorted(names):
 if re.match(r'^[A-Za-z0-9_.:-]{1,15}\Z',name) is None or re.match(r'^mta[0-9a-f]{8}\Z',name):raise ValueError('baseline_interface')
 folder='/sys/class/net/'+name
 interfaces.append((name,tuple(bounded(folder+'/'+field,128) for field in ('ifindex','type','flags','operstate'))))
if os.path.lexists('/tmp/p011-mta-p2p-device.pending'):raise ValueError('baseline_pending')
def owned_status():
 child=None;cleanup_ok=True
 try:
  child=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  output,error=child.communicate(timeout=min(2.0,budget()))
  if child.returncode!=0 or len(output)>16384 or len(error)>16384:raise ValueError('baseline_wpa_status')
  return output
 finally:
  if child is not None:
   try:
    if child.poll() is None:
     child.kill();child.wait(timeout=0.5)
    exited=child.poll()
    if type(exited) is not int:cleanup_ok=False
   except Exception:cleanup_ok=False
   for stream in (child.stdout,child.stderr):
    try:stream.close()
    except Exception:cleanup_ok=False
   if not cleanup_ok:raise ValueError('baseline_child_cleanup')
output=owned_status()
fields=dict(line.split('=',1) for line in output.decode('utf-8','strict').splitlines() if '=' in line)
if fields.get('wpa_state')!='COMPLETED':raise ValueError('baseline_wpa_state')
result={'stock':snapshot,'network_processes':sorted(network,key=lambda r:r['pid']),
 'interfaces':interfaces,'station_state_digest':fingerprint(output),
 'main_ipv4_route_digest':fingerprint(bounded('/proc/net/route',1048576)),
 'ipv6_address_digest':fingerprint(bounded('/proc/net/if_inet6',1048576)),
 'ipv6_route_digest':fingerprint(bounded('/proc/net/ipv6_route',1048576)),
 'boot_digest':fingerprint(bounded('/proc/sys/kernel/random/boot_id',128))}
budget()
print('RESULT='+repr(result))
'''

BODY = r'''
import math,socket,struct,sys,time
result={'pass':False,'loopback_index_checked':False,'initial_fds_checked':False,
 'pktinfo_option_readback':False,'device_binding_readback':False,'ephemeral_ports_checked':False,
 'send_interface_source_checked':False,'receive_interface_destination_checked':False,
 'source_peer_checked':False,'ancillary_exact':False,'no_truncation':False,'budget_checked':False,
 'all_sockets_closed':False,'sockets_created':0,'datagrams_sent':0,'datagrams_received':0,
 'close_attempts':0,'closed_readbacks':0,'close_failures':0,
 'error_stage':'not_recorded','error_class':'none','errno':0}
stage='target';resources=[];fds=[];success=False
def classify(error):
 if isinstance(error,socket.timeout):return 'timeout'
 if isinstance(error,OSError):return 'os_error'
 if isinstance(error,ValueError):return 'value_error'
 if isinstance(error,RuntimeError):return 'runtime_error'
 return 'unexpected'
def failure(error,where):
 if result['error_class']=='none':
  result['error_stage']=where;result['error_class']=classify(error)
  number=getattr(error,'errno',None)
  result['errno']=number if type(number) is int and 1<=number<=4095 else 0
def clock():
 value=time.monotonic()
 if type(value) not in (int,float) or not 0<=value<=2**53 or not math.isfinite(value):raise ValueError('clock')
 return value
def remaining():
 value=end-clock()
 if value<=0:raise ValueError('deadline')
 return value
def index():
 with open('/sys/class/net/lo/ifindex','rb') as f:value=f.read(33)
 if re.match(br'^[1-9][0-9]{0,9}\n?\Z',value) is None:raise ValueError('index')
 number=int(value)
 if not 0<number<=0x7fffffff:raise ValueError('index')
 return number
try:
 if sys.flags.optimize:raise ValueError('optimized')
 require_stock(stock_snapshot())
 if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target')
 end=clock()+3.0
 stage='api'
 if (socket.AF_INET!=2 or socket.SOCK_DGRAM!=2 or socket.IPPROTO_IP!=0 or
     socket.SOL_SOCKET!=1 or socket.SO_BINDTODEVICE!=25 or socket.MSG_TRUNC!=32 or socket.MSG_CTRUNC!=8 or
     not callable(getattr(socket.socket,'recvmsg',None)) or not callable(getattr(socket.socket,'sendmsg',None)) or
     not callable(getattr(socket,'CMSG_SPACE',None))):raise ValueError('api')
 pktinfo=struct.Struct('I4s4s')
 if pktinfo.size!=12:raise ValueError('pktinfo_layout')
 stage='interface';lo=index();local=b'\x7f\x00\x00\x01';destination=('127.0.0.1',0)
 endpoints=[]
 for unused in range(2):
  remaining();stage='create';connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)
  resources.append(connection);result['sockets_created']+=1
  fd=connection.fileno()
  if type(fd) is not int or fd<0 or fd in fds:raise ValueError('initial_fd')
  fds.append(fd);stage='options';connection.settimeout(remaining())
  connection.setsockopt(socket.IPPROTO_IP,8,1)
  option=connection.getsockopt(socket.IPPROTO_IP,8)
  if type(option) is not int or option!=1:raise ValueError('pktinfo_readback')
  connection.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'lo\0')
  if connection.getsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,16)!=b'lo\0':raise ValueError('device_readback')
  stage='bind';connection.bind(destination);peer=connection.getsockname()
  if type(peer) is not tuple or len(peer)!=2 or peer[0]!='127.0.0.1' or type(peer[1]) is not int or not 1024<=peer[1]<=65535:raise ValueError('bound_endpoint')
  if peer in endpoints:raise ValueError('duplicate_endpoint')
  endpoints.append(peer)
 result['initial_fds_checked']=len(fds)==2
 result['pktinfo_option_readback']=True;result['device_binding_readback']=True;result['ephemeral_ports_checked']=True
 for round_number in range(2):
  for sender,receiver in ((0,1),(1,0)):
   payload=b'MTA_UDP_LOOPBACK_'+bytes(bytearray((65+round_number,65+sender)))
   if not 1<=len(payload)<=64 or result['datagrams_sent']>=4 or result['datagrams_received']>=16:raise ValueError('message_budget')
   stage='send';resources[sender].settimeout(remaining())
   ancillary=[(socket.IPPROTO_IP,8,pktinfo.pack(lo,local,b'\0'*4))]
   sent=resources[sender].sendmsg([payload],ancillary,0,endpoints[receiver])
   if type(sent) is not int or sent!=len(payload):raise ValueError('short_send')
   result['datagrams_sent']+=1
   stage='receive';resources[receiver].settimeout(remaining())
   data,anc,flags,peer=resources[receiver].recvmsg(64,socket.CMSG_SPACE(12))
   result['datagrams_received']+=1
   if type(data) is not bytes or data!=payload or type(flags) is not int or flags!=0 or type(peer) is not tuple or peer!=endpoints[sender]:raise ValueError('envelope')
   if type(anc) is not list or len(anc)!=1 or type(anc[0]) is not tuple or len(anc[0])!=3:raise ValueError('ancillary')
   level,kind,blob=anc[0]
   if type(level) is not int or type(kind) is not int or level!=socket.IPPROTO_IP or kind!=8 or type(blob) is not bytes or len(blob)!=12:raise ValueError('ancillary')
   actual,spec,dst=pktinfo.unpack(blob)
   if actual!=lo or spec!=local or dst!=local:raise ValueError('pktinfo')
 stage='readback';remaining()
 if index()!=lo:raise ValueError('interface_changed')
 for i,connection in enumerate(resources):
  if type(connection.fileno()) is not int or connection.fileno()!=fds[i] or connection.getsockname()!=endpoints[i]:raise ValueError('socket_changed')
  if connection.getsockopt(socket.IPPROTO_IP,8)!=1 or connection.getsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,16)!=b'lo\0':raise ValueError('options_changed')
 result['loopback_index_checked']=True;result['send_interface_source_checked']=True
 result['receive_interface_destination_checked']=True;result['source_peer_checked']=True
 result['ancillary_exact']=True;result['no_truncation']=True;result['budget_checked']=True;success=True
except Exception as error:failure(error,stage)
finally:
 for i,connection in enumerate(resources):
  result['close_attempts']+=1
  try:connection.close()
  except Exception as error:
   result['close_failures']+=1;failure(error,'close')
  try:
   closed=connection.fileno()
   if type(closed) is not int or closed!=-1 or i>=len(fds):raise ValueError('closed_fd')
   result['closed_readbacks']+=1
  except Exception as error:
   result['close_failures']+=1;failure(error,'close')
 result['all_sockets_closed']=(result['sockets_created']==2 and result['close_attempts']==2 and
  result['closed_readbacks']==2 and result['close_failures']==0)
 result['pass']=success and result['all_sockets_closed'] and result['error_class']=='none'
 if result['pass']:result['error_stage']='complete'
print('RESULT='+repr(result))
'''


def _read(path, pin=None):
    path = Path(path)
    for parent in (path,) + tuple(path.parents):
        if parent.is_symlink():
            raise ValueError('source_link')
    first = path.stat()
    if not stat.S_ISREG(first.st_mode) or not 0 < first.st_size <= MAX_SOURCE:
        raise ValueError('source_size')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        data = handle.read(MAX_SOURCE + 1)
    last = path.stat()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
    if (any(getattr(first, k) != getattr(opened, k) or getattr(first, k) != getattr(last, k) for k in keys)
            or len(data) != first.st_size or len(data) > MAX_SOURCE):
        raise ValueError('source_changed')
    if pin is not None and hashlib.sha256(data).hexdigest() != pin:
        raise ValueError('source_pin')
    return data


def source_check():
    safety = _read(BASE / 'runtime/mta_safety.py', SAFETY_PIN).decode('utf-8')
    _read(BASE / 'host/device_probe.py', ADB_HELPER_PIN)
    checker = _read(Path(__file__))
    sources = (safety + '\n' + BASELINE_BODY, safety + '\n' + BODY)
    for source in sources:
        tree = ast.parse(source, feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('optimized_assert')
    return {'source_check_pass': True, 'checker_sha256': hashlib.sha256(checker).hexdigest(),
            'safety_sha256': SAFETY_PIN, 'adb_helper_sha256': ADB_HELPER_PIN,
            'baseline_source_sha256': hashlib.sha256(sources[0].encode('utf-8')).hexdigest(),
            'udp_source_sha256': hashlib.sha256(sources[1].encode('utf-8')).hexdigest()}, sources


def _error(error):
    import subprocess
    if isinstance(error, subprocess.TimeoutExpired) or isinstance(error, TimeoutError):
        kind = 'timeout'
    elif isinstance(error, OSError):
        kind = 'os_error'
    elif isinstance(error, ValueError):
        kind = 'value_error'
    elif isinstance(error, RuntimeError):
        kind = 'runtime_error'
    else:
        kind = 'unexpected'
    number = getattr(error, 'errno', None)
    return kind, number if type(number) is int and 1 <= number <= 4095 else 0


def _normalized(raw):
    return raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')


def _parse(raw, expected_echo=None):
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
        raise ValueError('output_limit')
    derived = _normalized(raw)
    if expected_echo is not None:
        if type(expected_echo) is not bytes or not 0 < len(expected_echo) <= MAX_SOURCE:
            raise ValueError('echo_source_limit')
        expected = _normalized(expected_echo)
        # ADB PTY may echo stdin verbatim. Strip only THIS complete source as
        # the exact normalized prefix, never a partial or unknown echo line.
        if derived.startswith(expected):
            derived = derived[len(expected):]
    exits = re.findall(r'^MTA_REMOTE_EXIT=([0-9]{1,3})$', derived, re.M)
    lines = [line for line in derived.split('\n') if line]
    if (exits != ['0'] or len(lines) != 3 or not lines[0].startswith('RESULT=') or
            lines[1:] != ['MTA_REMOTE_OK', 'MTA_REMOTE_EXIT=0']):
        raise ValueError('remote_exit_or_result')
    return ast.literal_eval(lines[0][7:])


def _compressed_command(data):
    payload = base64.b64encode(zlib.compress(data)).decode('ascii')
    return ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
        payload + '\')))"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')


def _transport(source):
    if type(source) is not str:
        raise ValueError('transport_source')
    data = (source + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    if not 0 < len(data) <= MAX_SOURCE:
        raise ValueError('transport_limit')
    compressed = _compressed_command(data)
    if len(compressed) <= 3500:
        return compressed, None, None
    command = ('python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(data)) +
               '))" p011-udp-loopback; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    return command, data, data


def _remote(adb, label, source, timeout):
    command, data, expected_echo = _transport(source)
    raw = adb.run(label, ['shell', command], timeout=timeout, input_data=data)
    matches = re.findall(rb'(?:^|\n)MTA_REMOTE_EXIT=([0-9]{1,3})\r?\r?(?:\n|$)', raw)
    recorded = matches[0].decode('ascii') if len(matches) == 1 else 'INVALID'
    stem = '%02d-%s' % (adb.index, label)
    (adb.directory / (stem + '.remote-exit')).write_text(recorded, encoding='ascii')
    return _parse(raw, expected_echo)


def _udp_fields(value):
    if type(value) is not dict or set(value) != BODY_FIELDS:
        raise ValueError('body_fields')
    if any(type(value[key]) is not bool for key in BOOLEANS):
        raise ValueError('body_bool')
    bounds = {'sockets_created': 2, 'datagrams_sent': 4, 'datagrams_received': 16,
              'close_attempts': 2, 'closed_readbacks': 2, 'close_failures': 4}
    if any(type(value[key]) is not int or not 0 <= value[key] <= high for key, high in bounds.items()):
        raise ValueError('body_count')
    if (type(value['errno']) is not int or not 0 <= value['errno'] <= 4095 or
            type(value['error_class']) is not str or value['error_class'] not in ERROR_CLASSES or
            type(value['error_stage']) is not str or value['error_stage'] not in STAGES):
        raise ValueError('body_error')
    if value['pass'] and (not all(value[key] for key in BOOLEANS) or value['error_class'] != 'none' or
            value['error_stage'] != 'complete' or value['errno'] != 0 or any(value[key] != n for key, n in
            (('sockets_created', 2), ('datagrams_sent', 4), ('datagrams_received', 4),
             ('close_attempts', 2), ('closed_readbacks', 2), ('close_failures', 0)))):
        raise ValueError('body_false_pass')
    return dict(value)


def _baseline(value):
    fields = {'stock', 'network_processes', 'interfaces', 'station_state_digest',
              'main_ipv4_route_digest', 'ipv6_address_digest', 'ipv6_route_digest', 'boot_digest'}
    if type(value) is not dict or set(value) != fields or type(value['stock']) is not dict:
        raise ValueError('baseline_schema')
    if any(type(value[key]) is not str or re.fullmatch('[0-9a-f]{64}', value[key]) is None
           for key in fields - {'stock', 'network_processes', 'interfaces'}):
        raise ValueError('baseline_digest')
    if type(value['network_processes']) is not list or type(value['interfaces']) is not list:
        raise ValueError('baseline_rows')
    if len(value['network_processes']) > 128 or not 1 <= len(value['interfaces']) <= 64:
        raise ValueError('baseline_bounds')
    stock = value['stock']
    if set(stock) != {'hashes', 'processes'} or stock['hashes'] != STOCK_PINS or type(stock['processes']) is not list:
        raise ValueError('baseline_stock')
    if not 3 <= len(stock['processes']) <= 128:
        raise ValueError('baseline_stock_count')
    for name in ('Z03', 'control_engine', 'weston'):
        rows = [row for row in stock['processes'] if type(row) is dict and row.get('name') == name]
        if len(rows) != 1 or (name != 'weston' and rows[0].get('exe') != '/usr/bin/' + name):
            raise ValueError('baseline_stock_identity')
    def identity_row(row):
        if (type(row) is not dict or type(row.get('pid')) is not int or row['pid'] <= 0 or
                type(row.get('parent')) is not int or row['parent'] < 0 or
                type(row.get('starttime')) is not str or re.fullmatch('[0-9]{1,20}', row['starttime']) is None or
                type(row.get('name')) is not str or not 1 <= len(row['name']) <= 15 or
                type(row.get('exe')) is not str or not row['exe'].startswith('/') or len(row['exe']) > 4096):
            raise ValueError('baseline_process_identity')
    identity_fields = {'pid', 'parent', 'starttime', 'name', 'exe'}
    for row in stock['processes']:
        identity_row(row)
        required = identity_fields | ({'parent_identity'} if row['name'] in ('Z03', 'control_engine') else set())
        if set(row) != required or row['name'] not in ('Z03', 'control_engine', 'weston', 'connmand', 'bluetoothd'):
            raise ValueError('baseline_stock_process_fields')
        if 'parent_identity' in row:
            identity_row(row['parent_identity'])
            if set(row['parent_identity']) != identity_fields or row['parent_identity']['pid'] != row['parent']:
                raise ValueError('baseline_parent_identity')
    for row in value['network_processes']:
        identity_row(row)
        if (set(row) != identity_fields | {'args_digest'} or row['name'] not in ('wpa_supplicant', 'connmand', 'bluetoothd') or
                type(row['args_digest']) is not str or re.fullmatch('[0-9a-f]{64}', row['args_digest']) is None):
            raise ValueError('baseline_network_process_fields')
    if sum(row['name'] == 'wpa_supplicant' for row in value['network_processes']) != 1:
        raise ValueError('baseline_station_process')
    for rows in (stock['processes'], value['network_processes']):
        pids = [row['pid'] for row in rows]
        if pids != sorted(set(pids)):
            raise ValueError('baseline_process_order')
    names = []
    for row in value['interfaces']:
        if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str or
                re.fullmatch('[A-Za-z0-9_.:-]{1,15}', row[0]) is None or
                re.fullmatch('mta[0-9a-f]{8}', row[0]) is not None or
                type(row[1]) is not tuple or len(row[1]) != 4 or any(type(v) is not bytes for v in row[1])):
            raise ValueError('baseline_interface_fields')
        index, kind, flags, state = row[1]
        if (re.fullmatch(br'[1-9][0-9]{0,9}\n?', index) is None or not 0 < int(index) <= 0x7fffffff or
                re.fullmatch(br'[0-9]{1,5}\n?', kind) is None or
                re.fullmatch(br'0x[0-9a-f]{1,8}\n?', flags) is None or state.rstrip(b'\n') not in
                (b'unknown', b'notpresent', b'down', b'lowerlayerdown', b'testing', b'dormant', b'up')):
            raise ValueError('baseline_interface_values')
        names.append(row[0])
    if names != sorted(set(names)) or not {'lo', 'wlan0'} <= set(names):
        raise ValueError('baseline_interface_set')
    return value


def run_reviewed(expected_checker, output=None):
    checks, sources = source_check()  # Must finish before importing/initializing Adb.
    if type(expected_checker) is not str or re.fullmatch('[0-9a-f]{64}', expected_checker) is None or expected_checker != checks['checker_sha256']:
        raise ValueError('reviewed_checker_pin')
    from device_probe import Adb
    _read(BASE / 'host/device_probe.py', ADB_HELPER_PIN)
    out = Path(output) if output is not None else ROOT / 'logs' / (
        'MtaP011-UdpLoopback-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    report = {'evidence_level': 'P011_UDP_LOOPBACK_ONLY', 'pass': False,
        'checker_sha256': checks['checker_sha256'], 'safety_sha256': SAFETY_PIN,
        'adb_helper_sha256': ADB_HELPER_PIN, 'radio_operations': False,
        'network_configuration': False, 'dhcp_ports_used': False,
        'p2p_interface_binding': 'NOT_TESTED', 'dhcp_exchange': 'NOT_TESTED',
        'phone_interop': 'NOT_TESTED', 'udp_trial_invoked': False,
        'independent_stock_unchanged': False, 'independent_baseline_unchanged': False,
        'ipv4_all_tables_verified': False}
    before = after = udp = adb = None
    deadline = time.monotonic() + 20.0
    stage = 'target'
    def budget(maximum):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('host_deadline')
        return min(maximum, remaining)
    try:
        adb = Adb(out / 'private-raw')
        stage = 'before'
        before = _baseline(_remote(adb, 'before-loopback', sources[0], budget(5.0)))
        stage = 'udp'
        if budget(20.0) < 8.0:
            raise TimeoutError('insufficient_before_udp_budget')
        report['udp_trial_invoked'] = True
        udp = _udp_fields(_remote(adb, 'fixed-loopback-only', sources[1], budget(5.0)))
        report['udp'] = udp
    except Exception as error:
        report['host_error_stage'] = stage
        report['host_error_class'], report['host_errno'] = _error(error)
    finally:
        if adb is not None:
            try:
                after = _baseline(_remote(adb, 'after-loopback', sources[0], budget(5.0)))
            except Exception as error:
                report['after_error_class'], report['after_errno'] = _error(error)
        if before is not None and after is not None:
            report['independent_stock_unchanged'] = before['stock'] == after['stock']
            report['independent_baseline_unchanged'] = before == after
        report['pass'] = bool(udp is not None and udp['pass'] and report['independent_baseline_unchanged'] and
                              'host_error_class' not in report and 'after_error_class' not in report)
    (out / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text(
        'Bounded synthetic loopback UDP only: max two sockets/four datagrams, shared three-second UDP budget.\n'
        'Numeric Linux IP_PKTINFO, sendmsg/recvmsg, lo bind/readback and actual ancillary origin checked only if PASS.\n'
        'No UDP 67/68, RF, STA/IP/route/DNS/sysctl write, P2P binding, DHCP, association or phone acceptance.\n'
        'Before/after independent stock/process/interface/STA/boot + main IPv4 route/full IPv6 fingerprints.\n'
        'Not a full IPv4 all-table/address/policy snapshot. All raw stdout/stderr and host/remote exits stay private.\n', encoding='utf-8')
    archive = out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json', 'README.txt'):
            bundle.write(out / name, name)
    return report, out, archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only', action='store_true')
    modes.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--expected-checker-sha256')
    args = parser.parse_args(argv)
    if not args.execute_reviewed:
        if args.expected_checker_sha256 is not None:
            parser.error('Expected checker pin is only for reviewed execution')
        checks, _ = source_check()
        print(json.dumps(checks, indent=2))
        return 0
    if args.expected_checker_sha256 is None:
        parser.error('Explicit reviewed checker SHA-256 required')
    report, out, archive = run_reviewed(args.expected_checker_sha256)
    print(json.dumps(report, indent=2))
    print('RESULT_DIRECTORY=' + str(out))
    print('RESULT_ZIP=' + str(archive))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
