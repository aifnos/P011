"""Finite Bluetooth bridge trial using an already verified immutable candidate.

The trial registers only its own GATT owner/short-lived advertisement and one
discovery session. It does not pair/connect or act on incoming credentials.
Wi-Fi is never changed. Abort refuses unknown initial advertisements; no
global reset/stop or permanent firmware mutation is available.
"""
import argparse
import datetime
import json
from pathlib import Path
import sys
import zipfile
from device_probe import Adb, BASE, ROOT


TRIAL=r'''
import base64,queue,subprocess,sys,time
verify_candidate(BASE)
sys.path.insert(0,BASE+'/runtime')
from mta_service import PrivateHelper,capability
from mta_crypto import OpenSslCrypto
from mta_protocol import DeviceInfo,encode_advertisement

def discovery():
 p=subprocess.Popen(['dbus-send','--system','--print-reply','--dest=org.bluez','/org/bluez/hci0','org.freedesktop.DBus.Properties.Get','string:org.bluez.Adapter1','string:Discovering'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:out,err=p.communicate(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.communicate();raise ValueError('Readonly discovery timed out')
 if p.returncode or (b'boolean true' not in out and b'boolean false' not in out):raise ValueError('Discovering unavailable')
 return b'boolean true' in out

names=('powered','bredr_enabled','le_enabled','global_advertising','active_instances','bluez_advertising_active')
native=BASE+'/native/mta-bluez-helper'
before=stock_snapshot();require_stock(before)
caps=capability(native,['--capabilities','hci0']);initial_discovery=discovery()
if not (caps.get('powered') and caps.get('features') and caps.get('bredr_enabled') is True and caps.get('le_enabled') is True and
        caps.get('global_advertising') is False and caps.get('active_instances')==0 and
        caps.get('bluez_advertising_known') and caps.get('bluez_advertising_active') is False):raise ValueError('Initial radio state refuses trial')
result={'evidence_level':'P011_BLUETOOTH_OWNED_TRIAL','paired_or_connected':False,'wifi_modified':False,'phone_interop':'NOT_TESTED'}
events=queue.Queue(maxsize=128);helper=None;key=None
def receive(event):
 # IPC is not logged. Keep only protocol stage/code; discard identity/credentials.
 public={'event':event.get('event'),'code':event.get('code')}
 try:events.put_nowait(public)
 except queue.Full:pass
def wait_ready(name,seconds=7):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  try:event=events.get(timeout=.2)
  except queue.Empty:continue
  if event['event']==name:
   if event['code']=='ready':return True
   if event['code'] not in ('pending_cleanup',):result[name+'_reason']=event['code'];return False
 return False
try:
 crypto=OpenSslCrypto('/usr/bin/openssl',crypto_library='/usr/lib/libcrypto.so.1.0.2');key=crypto.generate_keypair()
 with open('/sys/class/net/wlan0/address') as f:mac=f.read(64).strip()
 wire=DeviceInfo(mac,key.public_key).to_bytes()
 helper=PrivateHelper(native,receive);helper.start()
 helper.send({'cmd':'listen','adapter':'hci0','status_b64':base64.b64encode(wire).decode('ascii')})
 result['gatt_registered']=wait_ready('listen')
 if result['gatt_registered']:
  packet=encode_advertisement(b'\x71\x01',1,'P011-MTA-TEST',False)
  helper.send({'cmd':'advert','adapter':'hci0','adv_b64':base64.b64encode(packet['adv_data']).decode('ascii'),
               'scan_b64':base64.b64encode(packet['scan_rsp']).decode('ascii'),'ttl':5})
  result['advert_ready']=wait_ready('advert')
  active=capability(native,['--capabilities','hci0'])
  result['own_instance_observed']=active.get('active_instances')==1
finally:
 if helper:result['advert_helper_closed']=helper.close() is not False
 if key:key.close()
 after_advert=capability(native,['--capabilities','hci0'])
 result['after_advert_matches']=all(after_advert.get(k)==caps.get(k) for k in names)

# Scan is a separate unique owner. It never connects a peer or uses its name.
if result.get('after_advert_matches'):
 helper=None
 try:
  helper=PrivateHelper(native,receive);helper.start()
  helper.send({'cmd':'scan','adapter':'hci0','ttl':3})
  result['scan_ready']=wait_ready('scan')
  time.sleep(1)
 finally:
  if helper:result['scan_helper_closed']=helper.close() is not False
after_caps=capability(native,['--capabilities','hci0'])
after=stock_snapshot()
result['radio_restored']=all(after_caps.get(k)==caps.get(k) for k in names) and discovery()==initial_discovery
result['stock_unchanged']=before==after
result['pass']=all(result.get(k) is True for k in ('gatt_registered','advert_ready','own_instance_observed','advert_helper_closed','after_advert_matches','scan_ready','scan_helper_closed','radio_restored','stock_unchanged'))
print('RESULT='+repr(result))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',required=True,help='16 hex identity of an immutable mta-01 candidate')
    args=parser.parse_args()
    if len(args.candidate)!=16 or any(c not in '0123456789abcdef' for c in args.candidate):raise ValueError('Candidate identity required')
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out=ROOT/'logs'/('MtaP011-BluezTrial-'+stamp);out.mkdir(parents=True)
    adb=Adb(out/'private-raw')
    safety=(BASE/'runtime/mta_safety.py').read_text(encoding='utf-8')
    gate=safety+"\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    before=adb.python('before',gate);after=None;result=None;failure=None
    target='/mnt/data/p011-toolbox/candidates/mta-01-'+args.candidate
    try:result=adb.python('owned-bluetooth-trial',safety+'\nBASE='+repr(target)+'\n'+TRIAL,timeout=75)
    except Exception as e:failure=type(e).__name__;print('TRIAL_ERROR='+str(e))
    finally:
        try:after=adb.python('after-independent',gate)
        except Exception:failure=failure or 'INDEPENDENT_CHECK_FAILED'
    report={'evidence_level':'P011_BLUETOOTH_OWNED_TRIAL','candidate_identity':args.candidate,
            'tests':result,'stock_independent_unchanged':before==after,
            'phone_interop':'NOT_TESTED','paired_or_connected':False,'wifi_modified':False,
            'pass':failure is None and before==after and bool(result and result.get('pass'))}
    if failure:report['error']=failure
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('仅自有GATT/5秒广播/3秒扫描及独立恢复核验。没有配对、连接对端、Wi-Fi切换或手机互传。\nprivate-raw保留本地，不进入ZIP。',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
