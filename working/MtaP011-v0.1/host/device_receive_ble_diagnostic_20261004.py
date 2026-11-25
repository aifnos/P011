"""Independent finite BLE component diagnostic, not an admitted file receiver.

Explicit read-only capabilities or one listen/DIAG advertisement, never both.
No State, PrivateHelper, Factory, scan, Connect, Wi-Fi, file commit or recovery.
Existing same-boot GO pending bytes are observed, never removed or admitted.
Inbound connections are observed, not disconnected; changed peers fail closure.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]

SOURCE_PINS = {
    'host/device_probe.py': (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    'host/device_receive_prerequisite_20261004.py': (12429, 'f91ecb38d82b3d18a0decf4f3ab729e62f3dc0ec7eebba66bdc3893fcb1d8876'),
    'runtime/p011_json.py': (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    'native/mta_bluez_helper.c': (55158, '38a2ce2e7ab967ed2c296d4ccff8ebdfe71331325a65e403df2f4766c48ce289'),
    'native/mta_core.c': (10215, 'c9fe71f0e0db4720d2a0a6eca508a3ab292aa38a81357d9b223647b8731a65ed'),
    'native/mta_core.h': (1924, '0f55b11a6e05b0ce0d90a916454e2eea0c95048dcc90b3cfc0a4b429d3743533'),
    'out/native/mta-bluez-helper': (65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
}
HELPER = '/mnt/data/p011-toolbox/candidates/mta-01-0507562a70a02b1a/native/mta-bluez-helper'
HELPER_PIN = SOURCE_PINS['out/native/mta-bluez-helper']
PENDING_PIN = (340, '80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818')
BOOL_FIELDS = frozenset(('complete', 'initial_observations_consistent', 'helper_authenticated',
    'stock_hashes_match', 'stock_processes_match', 'stock_unchanged', 'network_unchanged',
    'interfaces_unchanged', 'routes_unchanged', 'boot_unchanged', 'pending_bytes_unchanged',
    'pending_same_boot', 'project_resources_clear', 'bluez_owner_unchanged',
    'discovering_initially_false', 'discovering_unchanged', 'capabilities_read',
    'capabilities_unchanged', 'component_baseline_eligible', 'original_children_closed',
    'retained_fds_closed', 'powered', 'mgmt_info', 'features', 'bredr_enabled', 'le_enabled',
    'global_advertising', 'bluez_advertising_known', 'bluez_advertising_active',
    'connectable_advert', 'rf_executed', 'gatt_registered', 'advertisement_started',
    'receive_available', 'send_available', 'full_network_restore_verified',
    'discoverable_initially_false', 'discoverable_unchanged', 'connected_peers_unchanged',
    'bluez_gatt_manager_present', 'bluez_advertising_manager_present', 'helper_ready',
    'listen_command_sent', 'advertisement_command_sent', 'stop_command_sent', 'stdin_eof_sent',
    'helper_exit_observed', 'helper_output_eof', 'helper_exit_zero', 'helper_forced_termination',
    'helper_command_unknown', 'helper_stream_unknown', 'advertisement_expired_or_removed',
    'gatt_unregistered', 'hci_lock_owned_observed', 'hci_lock_created_by_component',
    'hci_lock_retained_empty', 'hci_lock_released_observed', 'hci_lock_transition_verified',
    'rf_may_have_executed', 'rf_execution_unknown'))
COUNT_FIELDS = frozenset(('active_instances', 'max_instances', 'max_adv', 'max_scan',
    'original_child_count', 'p2p_payload_count', 'public_helper_event_count',
    'connected_peers_first', 'connected_peers_after'))
REASONS = frozenset(('not_started', 'readonly_complete', 'target_identity', 'invalid',
    'helper_path', 'helper_identity', 'pending_identity', 'pending_boot', 'project_resources',
    'stock_baseline', 'initial_changed', 'readonly_child', 'child_unclosed', 'child_identity',
    'child_timeout', 'child_reply', 'bluez_reply', 'capability_reply', 'post_changed',
    'fd_unclosed', 'remote_budget', 'rf_mode_not_admitted', 'ble_component_complete',
    'ble_baseline', 'ble_event', 'ble_ready_timeout', 'ble_listen_timeout',
    'ble_advert_timeout', 'ble_pipe', 'ble_lock', 'ble_cleanup', 'connected_peers_changed'))
FIELDS = BOOL_FIELDS | COUNT_FIELDS | {'reason'}

CAP_BODY = r'''
import errno,re,subprocess,types,ctypes,select
end=time.monotonic()+(90 if RF_MODE else 45)
codec_raw=base64.b64decode(CODEC_B64.encode('ascii'),validate=True)
if (len(codec_raw),hashlib.sha256(codec_raw).hexdigest())!=CODEC_PIN:raise ValueError('invalid')
codec=types.ModuleType('p011_ble_diagnostic_codec')
exec(compile(codec_raw,'<reviewed-p011-json>','exec'),codec.__dict__)
children=[];held=[]

def signature(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink)
def asset_meta(value):return meta(value)+(value.st_gid,)
def physical_close(fd):
 os.close(fd)
 try:os.fstat(fd)
 except OSError as error:
  if error.errno==errno.EBADF:return True
 return False
def file_fd(path,pin=None,expected_inode=None,expected_identity=None):
 if time.monotonic()>=end:raise ValueError('remote_budget')
 row=os.lstat(path)
 if (os.path.realpath(path)!=path or not stat.S_ISREG(row.st_mode) or row.st_uid!=0 or row.st_gid!=0 or
     row.st_nlink!=1 or row.st_mode&0o022 or not 0<row.st_size<=134217728):raise ValueError('helper_path')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 saved={'fd':fd,'closed':False,'path':path,'asset_meta':asset_meta(row)};held.append(saved)
 if asset_meta(os.fstat(fd))!=asset_meta(row):raise ValueError('helper_identity')
 h=hashlib.sha256();count=0
 while True:
  if time.monotonic()>=end:raise ValueError('remote_budget')
  block=os.read(fd,65536)
  if not block:break
  count+=len(block);h.update(block)
 if count!=row.st_size or asset_meta(os.fstat(fd))!=asset_meta(row) or asset_meta(os.lstat(path))!=asset_meta(row):raise ValueError('helper_identity')
 if pin is not None and (count,h.hexdigest())!=pin:raise ValueError('helper_identity')
 if expected_inode is not None and (row.st_ino!=expected_inode or row.st_mode&0o777!=0o700):raise ValueError('helper_identity')
 if expected_identity is not None and (row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode&0o777,row.st_size)!=expected_identity:raise ValueError('helper_identity')
 return (fd,asset_meta(row),h.hexdigest())
def helper_asset():
 components=HELPER.strip('/').split('/');current='';rows=[]
 for part in components[:-1]:
  current+='/'+part;row=os.lstat(current)
  if not stat.S_ISDIR(row.st_mode) or row.st_mode&0o022 or os.path.realpath(current)!=current:raise ValueError('helper_path')
  if current=='/mnt/data':
   if (row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode&0o777)!=(66328,21,1000,1000,0o755):raise ValueError('helper_path')
  elif row.st_uid!=0 or row.st_gid!=0:raise ValueError('helper_path')
  if current==A:
   if (row.st_dev,row.st_ino,row.st_mode&0o777)!=(66328,32850,0o700):raise ValueError('helper_path')
  elif current.startswith(A+'/') and row.st_mode&0o777!=0o700:raise ValueError('helper_path')
  fd=os.open(current,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECTORY)
  held.append({'fd':fd,'closed':False,'path':current,'asset_meta':asset_meta(row)})
  if asset_meta(os.fstat(fd))!=asset_meta(row):raise ValueError('helper_path')
  rows.append((current,asset_meta(row)))
 return (tuple(rows),file_fd(HELPER,HELPER_PIN,33987))
def pending_snapshot(boot):
 path='/tmp/p011-mta-p2p-device.pending';row=os.lstat(path)
 if not stat.S_ISREG(row.st_mode) or row.st_uid!=0 or row.st_nlink!=1 or row.st_mode&0o077:raise ValueError('pending_identity')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 saved={'fd':fd,'closed':False};held.append(saved)
 if meta(os.fstat(fd))!=meta(row):raise ValueError('pending_identity')
 raw=os.read(fd,65537)
 if len(raw)>65536 or meta(os.fstat(fd))!=meta(row) or meta(os.lstat(path))!=meta(row):raise ValueError('pending_identity')
 if (len(raw),hashlib.sha256(raw).hexdigest())!=PENDING_PIN:raise ValueError('pending_identity')
 value=codec.loads(raw.decode('utf-8'))
 if type(value) is not dict or value.get('schema')!='p011-go-bootstrap-v33-r2' or value.get('boot_id')!=boot.decode('ascii').strip():raise ValueError('pending_boot')
 return (raw,meta(row))
def hci_lock_snapshot():
 path='/run/p011-mta-hci0.lock'
 if not exists(path):return (None,True)
 row=os.lstat(path)
 if not stat.S_ISREG(row.st_mode) or row.st_uid!=0 or row.st_gid!=0 or row.st_nlink!=1 or row.st_mode&0o777!=0o600 or row.st_size!=0:raise ValueError('project_resources')
 raw=read('/proc/locks',1048576)
 key='%02x:%02x:%d'%(os.major(row.st_dev),os.minor(row.st_dev),row.st_ino)
 for line in raw.decode('ascii').splitlines():
  fields=line.split()
  if len(fields)<6:raise ValueError('project_resources')
  if key in fields:return (asset_meta(row),False)
 if asset_meta(os.lstat(path))!=asset_meta(row):raise ValueError('project_resources')
 return (asset_meta(row),True)
def observation():
 value=snapshot();pending=pending_snapshot(value[3]);hci=hci_lock_snapshot()
 return (value,pending,hci)
def resource_clear(observed):
 value=observed[0];gate=value[0]
 return (gate[1] and gate[2]==0 and not any(gate[3:6]) and gate[6] and
         not value[1][0] and not value[1][1] and value[2][1]==0 and observed[2][1])
def actor_current(row):
 p=row['process']
 try:return row['identity'] is not None and identity(str(p.pid))==row['identity']
 except (OSError,ValueError):return False
def close_pipe(pipe):
 if pipe['close_attempted']:return
 pipe['close_attempted']=True;handle=pipe['handle'];fd=pipe['fd']
 if handle is None:return
 try:
  if not handle.closed:
   if pipe['probed'] and signature(os.fstat(fd))!=pipe['signature']:pipe['unknown']=True
   handle.close()
  if fd is None:return
  try:os.fstat(fd)
  except OSError as error:
   if error.errno==errno.EBADF:pipe['physical_closed']=True
 except (OSError,ValueError):pipe['unknown']=True
def close_child_pipes(row):
 if row['pipes_closed']:return
 for pipe in row['pipes']:close_pipe(pipe)
 row['pipes_closed']=(len(row['pipes'])==3 and all(pipe['handle'] is not None and
  pipe['probed'] and not pipe['unknown'] and pipe['physical_closed'] and
  pipe['handle'].closed for pipe in row['pipes']))
def cleanup_child(row):
 p=row['process']
 if p is None:return
 if p.poll() is not None:row['exited']=True;return
 if not row['term_attempted'] and time.monotonic()<end and actor_current(row):
  row['term_attempted']=True;row['term_unknown']=True
  try:p.terminate();row['term_unknown']=False
  except Exception:pass
 remaining=end-time.monotonic()
 if not row['wait_attempted'] and not row['term_unknown'] and row['term_attempted'] and remaining>0:
  row['wait_attempted']=True;row['wait_unknown']=True
  try:p.wait(timeout=min(3,remaining));row['wait_unknown']=False
  except subprocess.TimeoutExpired:row['wait_unknown']=False
  except Exception:pass
 row['exited']=p.poll() is not None
def run_child(asset,args):
 if end-time.monotonic()<=3:raise ValueError('remote_budget')
 fd,expected,digest=asset
 if asset_meta(os.fstat(fd))!=expected:raise ValueError('child_identity')
 row={'process':None,'identity':None,'pipes':[],'pipes_closed':False,'exited':False,
      'spawn_unknown':True,'term_attempted':False,'term_unknown':False,
      'wait_attempted':False,'wait_unknown':False};children.append(row)
 try:
  p=subprocess.Popen(['/proc/self/fd/'+str(fd)]+args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,pass_fds=(fd,))
  row['process']=p;row['spawn_unknown']=False
  # Retain ALL original handles before the first fallible fileno/fstat call.
  row['pipes']=[{'handle':handle,'fd':None,'signature':None,'probed':False,'unknown':True,
                 'close_attempted':False,'physical_closed':False} for handle in (p.stdin,p.stdout,p.stderr)]
  for pipe in row['pipes']:
   if pipe['handle'] is None:raise ValueError('child_identity')
   pipe['fd']=pipe['handle'].fileno();pipe['signature']=signature(os.fstat(pipe['fd']))
   pipe['probed']=True;pipe['unknown']=False
  try:row['identity']=identity(str(p.pid))
  except OSError:
   if p.poll() is None:raise ValueError('child_identity')
  remaining=end-time.monotonic()-3
  if remaining<=0:raise ValueError('remote_budget')
  try:out,err=p.communicate(timeout=min(12,remaining))
  except subprocess.TimeoutExpired:
   raise ValueError('child_timeout')
  if p.returncode!=0 or len(out)>16384 or len(err)>16384:raise ValueError('child_reply')
  if asset_meta(os.fstat(fd))!=expected:raise ValueError('child_identity')
  return out
 finally:
  cleanup_child(row)
  close_child_pipes(row)
def bus_observation(dbus_asset):
 common=['--system','--print-reply']
 owner=run_child(dbus_asset,common+['--dest=org.freedesktop.DBus','/org/freedesktop/DBus',
  'org.freedesktop.DBus.GetNameOwner','string:org.bluez'])
 found=re.findall(br'string "(:[0-9]+\.[0-9]+)"',owner)
 if len(found)!=1:raise ValueError('bluez_reply')
 raw=run_child(dbus_asset,common+['--dest=org.bluez','/',
  'org.freedesktop.DBus.ObjectManager.GetManagedObjects'])
 # Parse only this observed dbus-send indentation ABI. Nested property object
 # paths are not top-level objects; identifiers remain private local values.
 if len(raw)>16384:raise ValueError('bluez_reply')
 objects={};path=None;interface=None;object_pending=False;interface_pending=False;wanted=None
 for line in raw.decode('utf-8').splitlines():
  if not line.strip():continue
  indent=len(line)-len(line.lstrip(' '));text=line.strip()
  if '\t' in line or len(line)>2048:raise ValueError('bluez_reply')
  if wanted is not None:
   match=re.match(r'^variant\s+boolean (true|false)$',text)
   if indent!=21 or match is None:raise ValueError('bluez_reply')
   fields=objects[path][interface]
   if wanted in fields:raise ValueError('bluez_reply')
   fields[wanted]=match.group(1)=='true';wanted=None;continue
  if indent==6 and text=='dict entry(':
   path=None;interface=None;object_pending=True;interface_pending=False;continue
  if indent==9 and text.startswith('object path '):
   match=re.match(r'^object path "(/org/bluez(?:/[A-Za-z0-9_]+)*)"$',text)
   if not object_pending or match is None:raise ValueError('bluez_reply')
   path=match.group(1)
   if path in objects or len(objects)>=128:raise ValueError('bluez_reply')
   objects[path]={};object_pending=False;continue
  if indent==12 and text=='dict entry(':
   if path is None:raise ValueError('bluez_reply')
   interface=None;interface_pending=True;continue
  if indent==15 and text.startswith('string '):
   match=re.match(r'^string "([A-Za-z0-9_.]+)"$',text)
   if not interface_pending or match is None:raise ValueError('bluez_reply')
   interface=match.group(1)
   if interface in objects[path] or len(objects[path])>=32:raise ValueError('bluez_reply')
   objects[path][interface]={};interface_pending=False;continue
  if indent==21 and text in ('string "Connected"','string "Discovering"','string "Discoverable"'):
   name=text[8:-1]
   if interface=='org.bluez.Device1' and name=='Connected':wanted=name
   elif path=='/org/bluez/hci0' and interface=='org.bluez.Adapter1' and name in ('Discovering','Discoverable'):wanted=name
  if indent==6 and text==')':path=None;interface=None
 if wanted is not None or object_pending or interface_pending:raise ValueError('bluez_reply')
 adapter=objects.get('/org/bluez/hci0',{});properties=adapter.get('org.bluez.Adapter1',{})
 if set(properties)!=set(('Discovering','Discoverable')):raise ValueError('bluez_reply')
 connected=[]
 for path,interfaces_map in objects.items():
  if 'org.bluez.Device1' not in interfaces_map:continue
  if re.match(r'^/org/bluez/hci[0-9]+/dev_(?:[0-9A-Fa-f]{2}_){5}[0-9A-Fa-f]{2}$',path) is None:raise ValueError('bluez_reply')
  fields=interfaces_map['org.bluez.Device1']
  if set(fields)!=set(('Connected',)):raise ValueError('bluez_reply')
  if fields['Connected']:connected.append(path)
 if len(connected)>64:raise ValueError('bluez_reply')
 peers=tuple(sorted(connected));peer_hash=hashlib.sha256('\0'.join(peers).encode('ascii')).hexdigest()
 return (found[0],properties['Discovering'],properties['Discoverable'],peers,peer_hash,
         'org.bluez.GattManager1' in adapter,'org.bluez.LEAdvertisingManager1' in adapter)
def capabilities(asset):
 raw=run_child(asset,['--capabilities','hci0'])
 value=codec.loads(raw.decode('utf-8'))
 booleans=('powered','mgmt_info','features','bluez_advertising_known','bluez_advertising_active',
           'bredr_enabled','le_enabled','global_advertising','connectable_advert')
 counts=('max_adv','max_scan','max_instances','active_instances')
 if type(value) is not dict or set(value)!=set(booleans+counts+('event',)) or value['event']!='capabilities':raise ValueError('capability_reply')
 if any(type(value[k]) is not bool for k in booleans) or any(type(value[k]) is not int or not 0<=value[k]<=254 for k in counts):raise ValueError('capability_reply')
 return value

RF_CODES={
 'helper':('ready_no_radio_change',),
 'listen':('ready','lease_expired','register_failed_exit_releases_owner','already_active',
           'adapter_mismatch','bluetooth_off_or_unavailable','invalid_utf8','ownership_lock_unavailable'),
 'advert':('ready','gatt_not_ready','adapter_mismatch','already_active_stop_first','bluetooth_off_or_unavailable',
           'controller_read_failed','powered_or_le_unavailable','raw_layout_requires_existing_bredr_enabled',
           'global_advertising_active_refused','external_advertisement_or_unknown','external_advertisement_refused',
           'unsupported_capability','concurrent_mutation_ownership_unknown_ttl_retained',
           'outcome_unknown_kernel_ttl_retained','add_failed'),
 'advertisement':('expired_or_removed','ownership_lost'),
 'cleanup':('advertisement_removed','advertisement_readback_failed_ttl_retained',
            'advertisement_remove_failed_ttl_retained','gatt_unregistered',
            'gatt_unregister_failed_connection_exit_will_release','async_completion_timeout_owner_exit'),
 'stop':('pending_cleanup','resources_released_or_cleanup_reported'),
 'peer':('fragment_or_session_timeout','disconnected'),
 'error':('invalid_command','cleanup_pending','line_limit_exit','mgmt_socket_closed','bluez_owner_changed_exit')}
def pipe_nonblocking(fd):
 # The P011 Python omits fcntl. Use the existing Linux libc pattern, confined
 # to an already-retained original PIPE FD: F_GETFL=3 and F_SETFL=4.
 library=ctypes.CDLL(None,use_errno=True)
 command=library.fcntl;command.argtypes=(ctypes.c_int,ctypes.c_int);command.restype=ctypes.c_int
 ctypes.set_errno(0);flags=command(fd,3)
 if type(flags) is not int or flags<0:raise ValueError('ble_pipe')
 desired=flags|os.O_NONBLOCK
 ctypes.set_errno(0)
 if command(fd,4,ctypes.c_int(desired))!=0:raise ValueError('ble_pipe')
 ctypes.set_errno(0);observed=command(fd,3)
 if type(observed) is not int or observed<0 or observed!=desired:raise ValueError('ble_pipe')
def start_ble(asset):
 if end-time.monotonic()<30:raise ValueError('remote_budget')
 fd,expected,digest=asset
 if asset_meta(os.fstat(fd))!=expected:raise ValueError('child_identity')
 row={'process':None,'identity':None,'pipes':[],'pipes_closed':False,'exited':False,
      'spawn_unknown':True,'term_attempted':False,'term_unknown':False,'wait_attempted':False,'wait_unknown':False,
      'serve':True,'commands':{},'stream_unknown':False,'cleanup_attempted':False,'cleanup_unknown':False,
      'eof':[False,False],'buffer':b'','output_bytes':0,'error_bytes':0,'live_lock':None,'events':{}}
 children.append(row)
 p=subprocess.Popen(['/proc/self/fd/'+str(fd),'--serve','hci0'],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,))
 row['process']=p;row['spawn_unknown']=False
 row['pipes']=[{'handle':handle,'fd':None,'signature':None,'probed':False,'unknown':True,
                'close_attempted':False,'physical_closed':False} for handle in (p.stdin,p.stdout,p.stderr)]
 for pipe in row['pipes']:
  if pipe['handle'] is None:raise ValueError('ble_pipe')
  pipe['fd']=pipe['handle'].fileno();status=os.fstat(pipe['fd'])
  pipe['signature']=signature(status)
  if not stat.S_ISFIFO(status.st_mode):raise ValueError('ble_pipe')
  pipe_nonblocking(pipe['fd'])
  if signature(os.fstat(pipe['fd']))!=pipe['signature']:raise ValueError('ble_pipe')
  pipe['probed']=True;pipe['unknown']=False
 row['identity']=identity(str(p.pid))
 if row['identity'][4]!=HELPER or not actor_current(row):raise ValueError('child_identity')
 return row
def ble_command(row,name,value):
 if name in row['commands']:raise ValueError('ble_pipe')
 p=row['process'];pipe=row['pipes'][0]
 if time.monotonic()>=end or p.poll() is not None or not pipe['probed'] or pipe['unknown'] or pipe['handle'].closed:raise ValueError('ble_pipe')
 if signature(os.fstat(pipe['fd']))!=pipe['signature']:raise ValueError('ble_pipe')
 data=(codec.dumps(value)+'\n').encode('ascii')
 if len(data)>512:raise ValueError('ble_pipe')
 row['commands'][name]={'attempted':True,'unknown':True,'written':False}
 if name in ('listen','advert'):result['rf_may_have_executed']=True;result['rf_execution_unknown']=True
 count=os.write(pipe['fd'],data)
 if count!=len(data):raise ValueError('ble_pipe')
 row['commands'][name]['unknown']=False;row['commands'][name]['written']=True
 if name=='listen':result['listen_command_sent']=True
 elif name=='advert':result['advertisement_command_sent']=True
 elif name=='stop':result['stop_command_sent']=True
def ble_event(row,line):
 value=codec.loads(line.decode('utf-8'))
 if type(value) is not dict:raise ValueError('ble_event')
 if value.get('event')=='p2p':
  if (set(value)!=set(('event','session','payload_b64')) or type(value['session']) is not int or
      not 1<=value['session']<=4294967295 or type(value['payload_b64']) is not str or len(value['payload_b64'])>3072):raise ValueError('ble_event')
  # No decoding/decryption/handoff or logging. Count and discard this private payload.
  if result['p2p_payload_count']>=254:raise ValueError('ble_event')
  result['p2p_payload_count']+=1;return
 name=value.get('event');code=value.get('code')
 if name not in RF_CODES or code not in RF_CODES[name]:raise ValueError('ble_event')
 fields=set(('event','code','instance','ttl')) if name=='advert' and code=='ready' else set(('event','code'))
 if set(value)!=fields:raise ValueError('ble_event')
 if len(fields)>2 and (type(value['instance']) is not int or not 1<=value['instance']<=254 or value['ttl']!=5 or type(value['ttl']) is not int):raise ValueError('ble_event')
 if result['public_helper_event_count']>=254:raise ValueError('ble_event')
 result['public_helper_event_count']+=1;row['events'][(name,code)]=True
 if (name,code)==('helper','ready_no_radio_change'):result['helper_ready']=True
 elif (name,code)==('listen','ready'):
  if not result['helper_ready'] or not result['listen_command_sent']:raise ValueError('ble_event')
  result['gatt_registered']=True;result['rf_executed']=True;result['rf_execution_unknown']=False
 elif (name,code)==('advert','ready'):
  if not result['gatt_registered'] or not result['advertisement_command_sent']:raise ValueError('ble_event')
  result['advertisement_started']=True
 elif (name,code) in (('advertisement','expired_or_removed'),('cleanup','advertisement_removed')):
  result['advertisement_expired_or_removed']=True
 elif (name,code)==('cleanup','gatt_unregistered'):result['gatt_unregistered']=True
 if name=='error' or code in ('ownership_lost','concurrent_mutation_ownership_unknown_ttl_retained',
     'outcome_unknown_kernel_ttl_retained','async_completion_timeout_owner_exit'):
  row['stream_unknown']=True
def drain_ble(row,until,wanted=None):
 while time.monotonic()<min(end,until):
  if wanted is not None and row['events'].get(wanted):return True
  readers=[row['pipes'][i+1]['fd'] for i in range(2) if not row['eof'][i]]
  if not readers:return wanted is None
  remaining=min(end,until)-time.monotonic()
  if remaining<=0:break
  readable,unused,failed=select.select(readers,[],readers,min(.2,remaining))
  if failed:row['stream_unknown']=True;raise ValueError('ble_pipe')
  for fd in readable:
   which=0 if fd==row['pipes'][1]['fd'] else 1
   try:data=os.read(fd,4096)
   except OSError as error:
    if error.errno in (errno.EAGAIN,errno.EINTR):continue
    row['stream_unknown']=True;raise ValueError('ble_pipe')
   if not data:
    row['eof'][which]=True
    if which==0 and row['buffer']:row['stream_unknown']=True
    continue
   field='output_bytes' if which==0 else 'error_bytes';row[field]+=len(data)
   if row[field]>65536:row['stream_unknown']=True;raise ValueError('ble_pipe')
   if which==1:continue # Private stderr is consumed, never copied to an artifact.
   row['buffer']+=data
   if len(row['buffer'])>8192:row['stream_unknown']=True;raise ValueError('ble_pipe')
   while b'\n' in row['buffer']:
    line,row['buffer']=row['buffer'].split(b'\n',1)
    if len(line)>4096:row['stream_unknown']=True;raise ValueError('ble_event')
    if not row['stream_unknown']:
     try:ble_event(row,line)
     except Exception:row['stream_unknown']=True;raise ValueError('ble_event')
  if row['process'].poll() is not None and all(row['eof']):break
 return wanted is None or bool(row['events'].get(wanted))
def live_ble_lock(row,before_lock):
 path='/run/p011-mta-hci0.lock';status=os.lstat(path)
 if not stat.S_ISREG(status.st_mode) or status.st_uid!=0 or status.st_gid!=0 or status.st_nlink!=1 or status.st_mode&0o777!=0o600 or status.st_size!=0:raise ValueError('ble_lock')
 observed=asset_meta(status)
 if before_lock[0] is not None and before_lock[0]!=observed:raise ValueError('ble_lock')
 key='%02x:%02x:%d'%(os.major(status.st_dev),os.minor(status.st_dev),status.st_ino)
 matches=[]
 for line in read('/proc/locks',1048576).decode('ascii').splitlines():
  fields=line.split()
  if key in fields:matches.append(fields)
 if (len(matches)!=1 or len(matches[0])!=8 or matches[0][1:4]!=['FLOCK','ADVISORY','WRITE'] or
     matches[0][4]!=str(row['process'].pid) or matches[0][5]!=key or matches[0][6:]!=['0','EOF'] or
     asset_meta(os.lstat(path))!=observed or not actor_current(row)):raise ValueError('ble_lock')
 row['live_lock']=observed;result['hci_lock_owned_observed']=True
 result['hci_lock_created_by_component']=before_lock[0] is None
def finish_ble(row):
 if row['cleanup_attempted']:return
 row['cleanup_attempted']=True;row['cleanup_unknown']=True
 try:
  p=row['process']
  if p is None:return
  if p.poll() is None:
   try:ble_command(row,'stop',{'cmd':'stop'})
   except Exception:pass
  if row['pipes']:
   close_pipe(row['pipes'][0])
   result['stdin_eof_sent']=row['pipes'][0]['physical_closed'] and not row['pipes'][0]['unknown']
  if len(row['pipes'])==3 and all(pipe['probed'] for pipe in row['pipes']):
   try:drain_ble(row,min(end,time.monotonic()+18))
   except Exception:row['stream_unknown']=True
  if p.poll() is None:
   result['helper_forced_termination']=True;cleanup_child(row)
  remaining=end-time.monotonic()
  if p.poll() is not None and not row['wait_attempted'] and remaining>0:
   row['wait_attempted']=True;row['wait_unknown']=True
   try:p.wait(timeout=remaining);row['wait_unknown']=False
   except Exception:pass
  if len(row['pipes'])==3 and all(pipe['probed'] for pipe in row['pipes']) and not all(row['eof']):
   try:drain_ble(row,min(end,time.monotonic()+1))
   except Exception:row['stream_unknown']=True
  row['exited']=p.poll() is not None
  result['helper_exit_observed']=row['exited']
  result['helper_exit_zero']=row['exited'] and p.returncode==0
  result['helper_output_eof']=all(row['eof'])
  result['helper_command_unknown']=any(value['unknown'] for value in row['commands'].values())
  result['helper_stream_unknown']=row['stream_unknown']
  row['cleanup_unknown']=not (row['exited'] and all(row['eof']) and result['stdin_eof_sent'])
 finally:close_child_pipes(row)
def rf_trial(helper,before_lock):
 row=None
 try:
  row=start_ble(helper)
  if not drain_ble(row,time.monotonic()+7,('helper','ready_no_radio_change')):raise ValueError('ble_ready_timeout')
  ble_command(row,'listen',{'cmd':'listen','adapter':'hci0','status_b64':'e30='})
  if not drain_ble(row,time.monotonic()+7,('listen','ready')):raise ValueError('ble_listen_timeout')
  live_ble_lock(row,before_lock)
  adv=bytes.fromhex('02010611078967452381000080001000003133000009160000000100000000')
  scan=bytes.fromhex('1e16ffff000000000000000000014449414700000000000000000000000000')
  if len(adv)!=31 or len(scan)!=31:raise ValueError('ble_pipe')
  ble_command(row,'advert',{'cmd':'advert','adapter':'hci0','adv_b64':base64.b64encode(adv).decode('ascii'),
              'scan_b64':base64.b64encode(scan).decode('ascii'),'ttl':5})
  if not drain_ble(row,time.monotonic()+7,('advert','ready')):raise ValueError('ble_advert_timeout')
  drain_ble(row,time.monotonic()+7,('advertisement','expired_or_removed'))
 finally:
  if row is not None:finish_ble(row)
 return row
result={key:False for key in BOOL_FIELDS};result.update({key:0 for key in COUNT_FIELDS});result['reason']='not_started'
before=None;after=None;caps_before=None;bus_before=None;asset_before=None;ble_row=None;rf_failure=None
try:
 first=observation();second=observation();before=second
 result['initial_observations_consistent']=first==second
 result['pending_same_boot']=True
 result['stock_hashes_match']=first[0][5]==PINS and second[0][5]==PINS
 result['stock_processes_match']=stock_ok(first[0][1][2]) and stock_ok(second[0][1][2])
 result['project_resources_clear']=resource_clear(first) and resource_clear(second)
 if not result['initial_observations_consistent']:raise ValueError('initial_changed')
 if not result['stock_hashes_match'] or not result['stock_processes_match']:raise ValueError('stock_baseline')
 if not result['project_resources_clear']:raise ValueError('project_resources')
 asset_before=helper_asset();helper=asset_before[1];result['helper_authenticated']=True
 dbus=file_fd('/usr/bin/dbus-send',expected_identity=(66317,3579,0,0,0o755,22192))
 bus_before=bus_observation(dbus);result['discovering_initially_false']=bus_before[1] is False
 result['discoverable_initially_false']=bus_before[2] is False
 result['connected_peers_first']=len(bus_before[3])
 result['bluez_gatt_manager_present']=bus_before[5];result['bluez_advertising_manager_present']=bus_before[6]
 caps_before=capabilities(helper);result['capabilities_read']=True
 for name in ('powered','mgmt_info','features','bredr_enabled','le_enabled','global_advertising',
              'bluez_advertising_known','bluez_advertising_active','connectable_advert',
              'active_instances','max_instances','max_adv','max_scan'):result[name]=caps_before[name]
 result['component_baseline_eligible']=(all(caps_before[k] for k in ('powered','mgmt_info','features',
   'bredr_enabled','le_enabled','bluez_advertising_known','connectable_advert')) and
   not caps_before['global_advertising'] and not caps_before['bluez_advertising_active'] and
   caps_before['active_instances']==0 and caps_before['max_instances']>0 and
   caps_before['max_adv']>=31 and caps_before['max_scan']>=31 and bus_before[1] is False and
   bus_before[2] is False and not bus_before[3] and bus_before[5] and bus_before[6])
 if RF_MODE:
  if not result['component_baseline_eligible']:raise ValueError('ble_baseline')
  try:ble_row=rf_trial(helper,before[2])
  except Exception as error:
   code=str(error);rf_failure=code if code in REASONS else 'invalid'
  finally:
   for row in children:
    if row.get('serve'):
     ble_row=row;finish_ble(row)
  # Continue independent after-observations even after an RF stage failure.
 caps_after=capabilities(helper);bus_after=bus_observation(dbus);after=observation();asset_after=helper_asset()
 result['capabilities_unchanged']=caps_before==caps_after
 result['bluez_owner_unchanged']=bus_before[0]==bus_after[0]
 result['discovering_unchanged']=bus_before[1]==bus_after[1]
 result['discoverable_unchanged']=bus_before[2]==bus_after[2]
 result['connected_peers_after']=len(bus_after[3])
 result['connected_peers_unchanged']=bus_before[3:5]==bus_after[3:5]
 result['helper_authenticated']=asset_before[0]==asset_after[0] and asset_before[1][1:]==asset_after[1][1:]
 result['stock_unchanged']=before[0][5]==after[0][5] and before[0][1][2]==after[0][1][2]
 result['network_unchanged']=before[0][1][3]==after[0][1][3]
 result['interfaces_unchanged']=before[0][2]==after[0][2]
 result['routes_unchanged']=before[0][4]==after[0][4]
 result['boot_unchanged']=before[0][3]==after[0][3]
 result['pending_bytes_unchanged']=before[1]==after[1]
 if not result['connected_peers_unchanged']:raise ValueError('connected_peers_changed')
 if RF_MODE:
  if ble_row is not None and ble_row['live_lock'] is not None:
   result['hci_lock_released_observed']=after[2][1]
   result['hci_lock_retained_empty']=after[2][0]==ble_row['live_lock'] and after[2][1]
   result['hci_lock_transition_verified']=(result['hci_lock_retained_empty'] and
    (before[2][0] is None or before[2][0]==ble_row['live_lock']))
  if before[:2]!=after[:2] or not result['hci_lock_transition_verified']:raise ValueError('post_changed')
 elif before!=after:raise ValueError('post_changed')
 if not all(result[k] for k in ('capabilities_unchanged','bluez_owner_unchanged',
     'discovering_unchanged','discoverable_unchanged','helper_authenticated')) or bus_before[5:]!=bus_after[5:]:raise ValueError('post_changed')
 if RF_MODE:
  if rf_failure is not None:raise ValueError(rf_failure)
  required=('helper_ready','listen_command_sent','gatt_registered','advertisement_command_sent',
    'advertisement_started','advertisement_expired_or_removed','stop_command_sent','stdin_eof_sent',
    'gatt_unregistered','helper_exit_observed','helper_output_eof','helper_exit_zero',
    'hci_lock_owned_observed','hci_lock_transition_verified')
  if not all(result[k] for k in required) or any(result[k] for k in ('helper_forced_termination',
    'helper_command_unknown','helper_stream_unknown')):raise ValueError('ble_cleanup')
 result['complete']=True;result['reason']='ble_component_complete' if RF_MODE else 'readonly_complete'
except Exception as error:
 code=str(error)
 result['reason']=code if code in REASONS else 'invalid'
finally:
 for row in children:
  if row.get('serve'):finish_ble(row)
  cleanup_child(row)
  close_child_pipes(row)
 result['original_child_count']=len(children)
 result['original_children_closed']=all(row['process'] is not None and not row['spawn_unknown'] and
  row['exited'] and row['pipes_closed'] and not row['term_unknown'] and not row['wait_unknown'] for row in children)
 closed=True
 for row in reversed(held):
  if not row['closed']:
   if 'asset_meta' in row:
    try:
     if asset_meta(os.fstat(row['fd']))!=row['asset_meta'] or asset_meta(os.lstat(row['path']))!=row['asset_meta']:
      result['helper_authenticated']=False;result['complete']=False;result['reason']='helper_identity'
    except OSError:
     result['helper_authenticated']=False;result['complete']=False;result['reason']='helper_identity'
   try:row['closed']=physical_close(row['fd'])
   except OSError:row['closed']=False
  closed=closed and row['closed']
 result['retained_fds_closed']=closed
 if not result['original_children_closed']:result['complete']=False;result['reason']='child_unclosed'
 if not closed:result['complete']=False;result['reason']='fd_unclosed'
 if result['rf_may_have_executed']:
  result['rf_execution_unknown']=(not result['gatt_registered'] or not result['advertisement_started'] or
    result['helper_command_unknown'] or result['helper_stream_unknown'] or not result['helper_exit_observed'] or
    not result['helper_output_eof'] or not result['original_children_closed'])
print('RESULT='+repr(result))
'''


def checked_sources():
    rows = {}
    for name, pin in SOURCE_PINS.items():
        raw = (BASE / name).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
            raise ValueError('reviewed_source_changed: ' + name)
        rows[name] = raw
    return rows


def source(rows, pins, rf_mode=False):
    # Extract only the immutable literal, never import or execute the old probe.
    tree = ast.parse(rows['host/device_receive_prerequisite_20261004.py'].decode('utf-8'))
    values = [node.value.value for node in tree.body if isinstance(node, ast.Assign) and
              any(isinstance(target, ast.Name) and target.id == 'BODY' for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    marker = 'result={key:False for key in BOOL_FIELDS}'
    if len(values) != 1 or values[0].count(marker) != 1:
        raise ValueError('prerequisite_prefix_changed')
    prefix = values[0].split(marker)[0]
    codec = rows['runtime/p011_json.py']
    encoded_codec = base64.b64encode(codec).decode('ascii')
    # adb shell's PTY fallback must not receive one 10 KiB canonical line.
    # Python implicit literal concatenation preserves the exact codec bytes.
    codec_literals = '\n'.join('    ' + repr(encoded_codec[offset:offset + 1024])
                               for offset in range(0, len(encoded_codec), 1024))
    def literal_tuple(names):
        return '(\n' + ''.join('    ' + repr(name) + ',\n' for name in sorted(names)) + ')'
    header = ('import base64\nPINS=' + repr(pins) + '\nRF_MODE=' + repr(bool(rf_mode)) + '\nHELPER=' + repr(HELPER) +
        '\nHELPER_PIN=' + repr(HELPER_PIN) + '\nPENDING_PIN=' + repr(PENDING_PIN) +
        '\nCODEC_PIN=' + repr(SOURCE_PINS['runtime/p011_json.py']) +
        '\nCODEC_B64=(\n' + codec_literals + '\n)'+
        '\nBOOL_FIELDS=' + literal_tuple(BOOL_FIELDS) +
        '\nCOUNT_FIELDS=' + literal_tuple(COUNT_FIELDS) +
        '\nREASONS=' + literal_tuple(REASONS) + '\n')
    program = header + prefix + CAP_BODY
    raw = program.encode('utf-8')
    # Controlled diagnostic SOURCE budget, not a production IPC/protocol limit.
    if len(raw) > 65536:
        raise ValueError('target_source_budget')
    if any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('target_source_line_budget')
    ast.parse(program, feature_version=(3, 5))
    return program


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities-readonly', action='store_true')
    mode.add_argument('--listen-advertise', action='store_true')
    args = parser.parse_args()
    rows = checked_sources()
    # Execute only already-hash-checked transport bytes, not a path re-import.
    transport = types.ModuleType('p011_reviewed_device_probe')
    transport.__file__ = str(BASE / 'host/device_probe.py')
    exec(compile(rows['host/device_probe.py'], transport.__file__, 'exec'), transport.__dict__)
    own = Path(__file__).read_bytes()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('receive-ble-component-' + stamp)
    out.mkdir()
    (out / 'private-source.py').write_bytes(own)
    report = {'schema': 'p011-receive-ble-component-20261004', 'device_invoked': False,
        'rf_requested': bool(args.listen_advertise), 'rf_executed': False,
        'rf_may_have_executed': False, 'rf_execution_unknown': False,
        'state_executed': False, 'network_mutations': False, 'device_installations': False,
        'pending_removed': False, 'receive_available': False, 'send_available': False,
        'full_network_restore_verified': False, 'host_or_parse_error': False,
        'source_sha256': hashlib.sha256(own).hexdigest(), 'sources_preserved': False}
    try:
        program = source(rows, transport.PINS, args.listen_advertise)
        (out / 'private-target-source.py').write_bytes(program.encode('utf-8'))
        report['target_source_sha256'] = hashlib.sha256(program.encode('utf-8')).hexdigest()
        adb = transport.Adb(out / 'private-raw')
        report['device_invoked'] = True
        # An invoked RF payload with missing/invalid reply is unknown, not false.
        report['rf_may_have_executed'] = bool(args.listen_advertise)
        report['rf_execution_unknown'] = bool(args.listen_advertise)
        if args.listen_advertise:report['rf_executed'] = None
        label = 'receive-ble-single-component' if args.listen_advertise else 'receive-ble-capabilities-readonly'
        value = adb.python(label, program, timeout=105 if args.listen_advertise else 60)
        if type(value) is not dict or set(value) != FIELDS or value['reason'] not in REASONS:
            raise ValueError('target_fixed_fields')
        if any(type(value[k]) is not bool for k in BOOL_FIELDS) or any(
            type(value[k]) is not int or not 0 <= value[k] <= 254 for k in COUNT_FIELDS):
            raise ValueError('target_fixed_types')
        if any(value[k] for k in ('receive_available','send_available','full_network_restore_verified')):
            raise ValueError('target_scope_changed')
        if not args.listen_advertise and any(value[k] for k in ('rf_executed','gatt_registered',
                'advertisement_started','rf_may_have_executed','rf_execution_unknown')):
            raise ValueError('target_scope_changed')
        report.update(value)
    except Exception:
        report.update(complete=False, host_or_parse_error=True, reason='invalid')
    report['sources_preserved'] = (Path(__file__).read_bytes() == own and all(
        (BASE / name).read_bytes() == raw for name, raw in rows.items()))
    raw = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Explicit original native capabilities or one finite BLE listen/DIAG advertisement. '
        b'No State/PrivateHelper/Factory, scan, Connect, Wi-Fi, file commit or recovery. '
        b'Same-boot GO pending bytes are retained and compared; this does not grant receive admission. '
        b'{} and DIAG packets are component fixtures, never DeviceInfo or authenticated receiver readiness. '
        b'Kernel advertisement TTL is not GATT cleanup: STOP plus original stdin EOF, output drain, process exit and FD closure are checked. '
        b'A new empty hci lock is retained and separately compared through the original helper PID/inode. '
        b'Inbound connected peers are observed, never disconnected; changes prevent component completion. '
        b'RF invocation without a valid remote reply is explicitly unknown, not proved false. '
        b'Component completion is not phone interoperability, production readiness or full radio/network restoration. '
        b'Private source/stdout/stderr and host/remote exits remain local. '
        b'No private helper PIPE contents are printed or archived.\n')
    (out / 'result.json').write_bytes(raw)
    (out / 'README.txt').write_bytes(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', raw)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != ['result.json','README.txt'] or bundle.testzip() is not None or (
                bundle.read('result.json') != raw or bundle.read('README.txt') != readme):
            raise ValueError('public_archive_changed')
    print(json.dumps({'directory': str(out), 'result': report,
        'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, sort_keys=True))
    return 0 if report.get('complete') is True and report['sources_preserved'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
