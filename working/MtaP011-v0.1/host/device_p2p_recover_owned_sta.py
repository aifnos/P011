"""One reviewed failed-trial STA cleanup, not a general network repair tool.

Default is read-only. Only the exact owned lease below is eligible; no name-only
fallback, retries, firmware changes, stock signals or arbitrary command support.
The old failed report stays unchanged. New result records the cleanup separately.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import zipfile

from device_probe import Adb,BASE,ROOT

CANDIDATE='d7abc84e38e44a51'
RUN='/mnt/data/p011-toolbox/sessions/mta-p2p-20260930-205426-c3ac37fe'
FROZEN=ROOT/'logs/MtaP011-P2pFreeze-20260930-204808-5a08fe44/private-candidate'
OWNED={'name':'mtacd152130','phy':0,'wdev':2,'ifindex':23,'iftype':8}

BODY=r'''
import stat,struct,subprocess,socket
import p011_json as json
from mta_send_wifi import LinuxBackend,GoLease,JournalLock,_proc_identity,_attr,CMD_DEL_INTERFACE,A_WDEV
result={'evidence_level':'P011_EXACT_OWNED_STA_CLEANUP','executed':False,'pass':False,
        'delete_attempted':False,'global_network_changes':False,'stock_processes_signalled':False}
owned_directory(RUN);path=RUN+'/p2p-lease.json'
value=os.lstat(path)
assert stat.S_ISREG(value.st_mode) and value.st_uid==os.getuid() and not value.st_mode&0o077 and value.st_size<=65536
backend=LinuxBackend(BASE+'/native/mta-wpa-supplicant',BASE+'/native/mta-wifi-caps',RUN,allow_rf=False)
def current_wifi_fingerprint():
 p=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:out,err=p.communicate(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.communicate();raise ValueError('readonly_status_timeout')
 assert p.returncode==0 and len(out)<=16384 and b'wpa_state=COMPLETED' in out.splitlines()
 return hashlib.sha256(out).hexdigest()
def no_data_network_address(name):
 executable=next((p for p in ('/sbin/ip','/usr/sbin/ip','/bin/ip','/usr/bin/ip') if os.path.isfile(p)),None)
 if executable is None:return False
 for family in ('-4','-6'):
  p=subprocess.Popen([executable,'-o',family,'addr','show','dev',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:out,err=p.communicate(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.communicate();return False
  if p.returncode or len(out)>8192:return False
  if family=='-4' and out.strip():return False
  if family=='-6':
   # WPA brought the link UP; Linux generated FE80 link-local IPv6 only.
   # Reject a routable/data address. Do not remove/flush any address separately.
   for line in out.decode('ascii','strict').splitlines():
    fields=line.split()
    if not fields:continue
    if len(fields)>32 or 'inet6' not in fields or 'scope' not in fields:return False
    address=fields[fields.index('inet6')+1].split('/')
    if len(address)!=2 or address[1]!='64' or fields[fields.index('scope')+1]!='link':return False
    raw=socket.inet_pton(socket.AF_INET6,address[0])
    if raw[0]!=0xfe or raw[1]&0xc0!=0x80:return False
 return True
def original_ipv6_routes():
 with open('/proc/net/ipv6_route','rb') as h:raw=h.read(262145)
 assert len(raw)<=262144
 rows=[line for line in raw.splitlines() if line.split() and line.split()[-1]!=OWNED['name'].encode('ascii')]
 return hashlib.sha256(b'\n'.join(rows)).hexdigest()
def no_owned_data_ipv6_route():
 with open('/proc/net/ipv6_route','rb') as h:raw=h.read(262145)
 if len(raw)>262144:return False
 for line in raw.decode('ascii','strict').splitlines():
  fields=line.split()
  if not fields or fields[-1]!=OWNED['name']:continue
  if len(fields)!=10 or not re.match(r'^[0-9a-fA-F]{32}$',fields[0]):return False
  address=bytes.fromhex(fields[0]);prefix=int(fields[1],16)
  link=address[0]==0xfe and address[1]&0xc0==0x80 and 10<=prefix<=128
  multicast=address[0]==0xff and 8<=prefix<=128
  if not (link or multicast):return False
 return True
def no_private_actor():
 for token in os.listdir('/proc'):
  if not token.isdigit():continue
  try:
   executable=os.readlink('/proc/'+token+'/exe')
   if executable.startswith(AREA+'/candidates/') and executable.endswith('/native/mta-wpa-supplicant'):return False
   with open('/proc/'+token+'/cmdline','rb') as h:args=h.read(16385).split(b'\0')
   if RUN.encode('ascii') in args and (BASE+'/runtime/mta_send_wifi.py').encode('ascii') in args:return False
  except OSError:pass
 return True
def read_gates(record):
 rows=backend.interfaces();owned=record.get('owned');process=record.get('process')
 with open('/proc/sys/kernel/random/boot_id') as h:boot=h.read(128).strip()
 original=record.get('baseline',{}).get('station',{})
 named=[r for r in rows if r.get('name')==OWNED['name']]
 unique=all(len([r for r in rows if r.get(k)==OWNED[k]])==1 for k in ('name','wdev','ifindex'))
 same=len(named)==1 and all(named[0].get(k)==OWNED[k] for k in ('name','phy','wdev','ifindex'))
 inactive=False;empty=False
 if same:
  with open('/sys/class/net/'+OWNED['name']+'/flags') as h:down=not (int(h.read(32).strip(),16)&1)
  with open('/sys/class/net/'+OWNED['name']+'/operstate') as h:oper=h.read(32).strip()
  inactive=down or oper=='dormant'
  empty=no_data_network_address(OWNED['name'])
 current=stock_snapshot();require_stock(current)
 return {'journal_schema_verified':record.get('version')==1 and record.get('stage') in ('recovery_required','cleanup_intent'),
         'journal_owned_identity_verified':owned==OWNED,
         'same_boot':record.get('baseline',{}).get('boot_id')==boot==backend.boot_id,
         'not_original_station':all(original.get(k)!=OWNED[k] for k in ('name','wdev','ifindex')),
         'kernel_identity_exact_and_unique':same and unique,
         'current_type_is_station':len(named)==1 and named[0].get('iftype')==2,
         'only_original_station_and_owned_interface':len(rows)==2 and sum(r==original for r in rows)==1,
         'no_private_trial_watchdog_or_wpa_actor':no_private_actor(),
         'interface_down_or_dormant':inactive,'no_ipv4_or_routable_ipv6':empty,
         'no_owned_default_or_global_ipv6_route':no_owned_data_ipv6_route(),
         'recorded_private_process_gone':bool(process and process.get('exe')==BASE+'/native/mta-wpa-supplicant'
                                            and _proc_identity(process.get('pid',0)) is None),
         'original_baseline_equal':backend.snapshot()==record.get('baseline')},rows,current
try:
 with JournalLock(path+'.lock'):
  with open(path) as h:record=json.loads(h.read(65537))
  result['journal_sha256']=digest(path)
  gates,rows,before=read_gates(record);result.update(gates)
  result['eligible']=all(gates.values())
  if EXECUTE:
   assert EXPECTED_SHA==result['journal_sha256'] and result['eligible']
   before_wifi=current_wifi_fingerprint()
   before_ipv6_routes=original_ipv6_routes()
   # Repeat all gates immediately before the one WDEV-scoped delete.
   gates2,rows2,stock2=read_gates(record)
   assert all(gates2.values()) and rows2==rows and stock2==before and current_wifi_fingerprint()==before_wifi
   lease=GoLease(backend,path);lease.state=record
   record['stage']='cleanup_intent';record['explicit_sta_cleanup_reviewed']=True;lease._save(locked=True)
   result['executed']=True;result['delete_attempted']=True
   backend.nl._request(backend.nl.family,CMD_DEL_INTERFACE,_attr(A_WDEV,struct.pack('Q',OWNED['wdev'])),4)
   after=backend.interfaces()
   result['owned_interface_removed']=not any(r.get(k)==OWNED[k] for r in after for k in ('name','wdev','ifindex'))
   expected=[r for r in rows if r.get('wdev')!=OWNED['wdev']]
   key=lambda r:(r.get('phy',-1),r.get('wdev',-1),r.get('name',''))
   result['only_owned_interface_changed']=sorted(after,key=key)==sorted(expected,key=key)
   result['stock_hashes_and_processes_unchanged']=stock_snapshot()==before
   result['stock_network_baseline_equal']=backend.snapshot()==record['baseline']
   result['wifi_status_fingerprint_unchanged']=current_wifi_fingerprint()==before_wifi
   result['original_ipv6_routes_unchanged_by_cleanup']=original_ipv6_routes()==before_ipv6_routes
   result['pass']=all(result.get(k) is True for k in ('owned_interface_removed','only_owned_interface_changed',
                'stock_hashes_and_processes_unchanged','stock_network_baseline_equal','wifi_status_fingerprint_unchanged',
                'original_ipv6_routes_unchanged_by_cleanup'))
   record['stage']='reconciled' if result['pass'] else 'recovery_required'
   record['cleanup_result']={'event':'private_go_cleanup','owned_process_removed':True,
                            'owned_interface_removed':result['owned_interface_removed'],
                            'stock_baseline_equal':result['stock_network_baseline_equal'],'complete':result['pass']}
   lease._save(locked=True)
  else:result['pass']=result['eligible']
finally:backend.close()
print('RESULT='+repr(result))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-reviewed',action='store_true')
    parser.add_argument('--expected-journal-sha256')
    args=parser.parse_args()
    if args.execute_reviewed and re.fullmatch(r'[0-9a-f]{64}',args.expected_journal_sha256 or '') is None:
        parser.error('Explicit current journal digest is required')
    sys.path.insert(0,str(BASE/'host'))
    import device_p2p
    device_p2p.verify_frozen(FROZEN,CANDIDATE)
    remote='/mnt/data/p011-toolbox/candidates/mta-01-'+CANDIDATE
    safety=(FROZEN/'runtime/mta_safety.py').read_text(encoding='utf-8')
    source='import sys\nsys.path.insert(0,'+repr(remote+'/runtime')+')\n'+safety
    source+='\nverify_candidate('+repr(remote)+')\nBASE='+repr(remote)+'\nRUN='+repr(RUN)+'\nOWNED='+repr(OWNED)
    source+='\nEXECUTE='+repr(args.execute_reviewed)+'\nEXPECTED_SHA='+repr(args.expected_journal_sha256)+'\n'+BODY
    ast.parse(source,feature_version=(3,5))
    out=ROOT/'logs'/('MtaP011-OwnedStaRecovery-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True);adb=Adb(out/'private-raw')
    report={'pass':False,'executed':None if args.execute_reviewed else False,
            'delete_attempted':None if args.execute_reviewed else False,
            'remote_execution_outcome':'UNKNOWN' if args.execute_reviewed else 'READONLY_PENDING',
            'evidence_level':'P011_EXACT_OWNED_STA_CLEANUP',
            'phase':'EXACT_OWNED_DELETE' if args.execute_reviewed else 'READONLY_ELIGIBILITY'}
    try:
        report.update(adb.python('exact-owned-sta-cleanup' if args.execute_reviewed else 'readonly-eligibility',source,timeout=45))
        report['remote_execution_outcome']='REPORTED_PASS' if report.get('pass') else 'REPORTED_FAILURE'
    except Exception as error:report['error_class']=type(error).__name__
    if args.execute_reviewed:
        try:after=adb.python('after-independent',device_p2p.remote_source(remote,safety,device_p2p.PROBE))
        except Exception as error:after={};report['after_check_error_class']=type(error).__name__
        report['independent_stock_valid']=after.get('stock_valid') is True
        report['independent_wifi_completed']=after.get('wifi',{}).get('completed') is True
        report['independent_no_p2p_or_private_wpa']=after.get('no_p2p_interfaces') is True and after.get('no_private_wpa_processes') is True
        report['independent_only_original_station']=after.get('station_identity_ok') is True and len(after.get('interfaces',[]))==1
        report['pass']=report.get('pass') is True and all(report.get(k) is True for k in ('independent_stock_valid',
                'independent_wifi_completed','independent_no_p2p_or_private_wpa','independent_only_original_station'))
    report['cleanup_verified']=args.execute_reviewed and report.get('pass') is True
    report['original_trial_result']='FAIL_PRESERVED';report['phone_interop']='NOT_TESTED'
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('仅特定失败试验的owned接口归属审查/清理，不是通用修复工具。\n默认只读，显式execute和当前journal SHA后仅按已核实WDEV删除。\n原P2P FAIL保留，不说明GO可用或互传完成。private-raw不入ZIP。',encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_DIR='+str(out))
    return 0 if report.get('pass') else 1


if __name__=='__main__':sys.exit(main())
