"""Current read-only identity/radio snapshot. No candidate, RF or recovery.

Only local raw files are written. Explicit P011 transport selection is reused
from device_probe. Public output contains counts and comparisons, no identities.
This is not a netlink, Wi-Fi connectivity, restoration or interoperability test.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import zipfile

from device_probe import Adb, ADB, BASE, PINS

SOURCE = r'''
import hashlib,os,stat,sys,time
if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):
 raise ValueError('target_identity')
end=time.monotonic()+15.0
def budget():
 if time.monotonic()>=end:raise ValueError('read_deadline')
def read(path,limit):
 budget()
 with open(path,'rb') as f:value=f.read(limit+1)
 if len(value)>limit:raise ValueError('read_limit')
 budget();return value
def entries(path):
 budget()
 try:value=tuple(sorted(os.listdir(path)))
 except OSError as e:
  if e.errno==2:return ()
  raise
 if len(value)>1024:raise ValueError('entry_limit')
 return value
def digest(path):return hashlib.sha256(read(path,16777216)).hexdigest()
def pending(path):
 budget()
 try:s=os.lstat(path)
 except OSError as e:
  if e.errno==2:return None
  raise
 if not stat.S_ISREG(s.st_mode):return {'regular':False,'bytes':None}
 return {'regular':True,'bytes':read(path,32768)}
def observation():
 boot=read('/proc/sys/kernel/random/boot_id',128)
 actors=[]
 for pid in entries('/proc'):
  if not pid.isdigit():continue
  budget();p='/proc/'+pid
  try:
   comm=read(p+'/comm',256)
   if comm.strip() not in (b'Z03',b'control_engine',b'connmand',b'bluetoothd',b'wpa_supplicant',b'zyb_z03_launch.'):
    continue
   actors.append((pid,comm,read(p+'/stat',8192),os.readlink(p+'/exe')))
  except OSError as e:
   if e.errno not in (2,3):raise
   actors.append((pid,b'disappeared',None,None))
 net=entries('/sys/class/net');interfaces=[]
 for name in net:
  interfaces.append((name,read('/sys/class/net/'+name+'/ifindex',128),
   read('/sys/class/net/'+name+'/operstate',128),read('/sys/class/net/'+name+'/flags',128)))
 result={'boot':boot,'os_release':read('/etc/os-release',8192),'actors':tuple(actors),
  'stock':tuple((p,digest(p)) for p in ('/usr/bin/Z03','/usr/bin/control_engine','/usr/bin/zyb_z03_launch.sh')),
  'interfaces':tuple(interfaces),'phys':entries('/sys/class/ieee80211'),
  'bluetooth':entries('/sys/class/bluetooth'),
  'pending':pending('/tmp/p011-mta-p2p-device.pending'),
  'ipv4_routes':read('/proc/net/route',65536),'ipv6_routes':read('/proc/net/ipv6_route',65536)}
 budget();return result
print('RESULT='+repr(observation()))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-current', action='store_true', required=True)
    parser.parse_args()
    out = BASE / 'results' / ('device-state-readonly-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    (out / 'source.py').write_bytes(Path(__file__).read_bytes())
    adb = Adb(out / 'private-raw')
    first = adb.python('current-state-first', SOURCE, timeout=25)
    second = adb.python('current-state-second', SOURCE, timeout=25)
    # Keep exact originals in private; public facts intentionally omit names,
    # boot/process identities, pending content and both route tables.
    public = {'schema': 'p011-current-readonly-20261002', 'observations': 2,
        'target_linux_armv7_python355_root': True,
        'stock_pins_match': all(dict(row['stock']) == PINS for row in (first, second)),
        'same_boot': first['boot'] == second['boot'],
        'same_stock': first['stock'] == second['stock'],
        'stock_processes_observed': all(all(any(c.strip() == expected and s is not None for p,c,s,e in row['actors']) for expected in (b'Z03', b'control_engine')) for row in (first, second)),
        'network_process_counts': [sum(c.strip() in (b'connmand', b'bluetoothd', b'wpa_supplicant') and s is not None for p,c,s,e in row['actors']) for row in (first, second)],
        'same_process_identity': tuple((p,c,s.split(b') ',1)[1].split()[19] if s else None,e) for p,c,s,e in first['actors']) == tuple((p,c,s.split(b') ',1)[1].split()[19] if s else None,e) for p,c,s,e in second['actors']),
        'same_interfaces': first['interfaces'] == second['interfaces'],
        'wifi_interface_present': all(any(name == 'wlan0' for name, index, state, flags in row['interfaces']) for row in (first, second)),
        'phy_counts': [len(row['phys']) for row in (first, second)],
        'bluetooth_adapter_counts': [len(row['bluetooth']) for row in (first, second)],
        'pending_present': [row['pending'] is not None for row in (first, second)],
        'same_pending_bytes': first['pending'] == second['pending'],
        'same_ipv4_main_routes': first['ipv4_routes'] == second['ipv4_routes'],
        'same_ipv6_routes': first['ipv6_routes'] == second['ipv6_routes'],
        'adb_exe_sha256': hashlib.sha256(ADB.read_bytes()).hexdigest(),
        'network_mutations': False, 'candidate_started': False, 'recovery_invoked': False,
        'reboot_invoked': False, 'wifi_connected': None, 'full_network_restore_verified': False,
        'pending_schema_or_owner_verified': False, 'send_available': False,
        'receive_available': False, 'phone_tested': False, 'private_raw_included': False}
    raw = (json.dumps(public, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    (out / 'result.json').write_bytes(raw)
    with zipfile.ZipFile(out / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw)
        archive.writestr('README.txt', 'Two current read-only observations only. No candidate, RF, recovery or reboot. No pending ownership/schema or complete network-restoration assertion. Raw outputs remain private.\n')
    print(json.dumps({'directory': str(out), 'result': public}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
