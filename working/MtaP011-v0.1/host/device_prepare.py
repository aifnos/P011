"""P011 read-only network lease preparation and cancel; never calls Connect.

Uses the immutable current candidate. No scan/agent/credentials are supplied.
Only a project-owned 600 journal is created and then removed after verification.
"""
import argparse
import datetime
import json
import sys
import zipfile
from device_probe import Adb, BASE, ROOT

TRIAL=r'''
import hashlib,subprocess,sys
verify_candidate(BASE)
sys.path.insert(0,BASE+'/runtime')
from mta_wifi import WifiBackend

def wifi_fingerprint():
 p=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:out,err=p.communicate(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.communicate();raise ValueError('Readonly status timeout')
 if p.returncode:raise ValueError('Readonly Wi-Fi status unavailable')
 return hashlib.sha256(out).digest(),b'wpa_state=COMPLETED' in out

before=stock_snapshot();require_stock(before);original=wifi_fingerprint()
backend=WifiBackend(BASE+'/native/mta-network-helper')
initial=backend.status()
if initial.get('restorePending') or initial.get('recoveryLocked'):raise ValueError('Existing journal requires inspection')
result={'evidence_level':'P011_NETWORK_PREPARE_ONLY','network_connect_called':False,'scan_or_agent_started':False,'credentials_supplied':False}
try:
 caps=backend.capabilities();result['unverified_receive_disabled']=caps.get('receive') is False
 lease=backend.prepare(timeout=20)
 result['prepared']=lease.prepared is True and lease.gateway is None and lease.local_ip is None
 result['journal_present_while_prepared']=bool(backend._pending or __import__('os').listdir(backend.journal_dir))
finally:
 result['owned_prepare_closed']=backend.restore_active()
 status=backend.status()
 result['journal_cleared']=not status.get('restorePending') and not status.get('recoveryLocked') and not __import__('os').listdir(backend.journal_dir)
 result['wifi_unchanged']=original==wifi_fingerprint()
 result['stock_unchanged']=before==stock_snapshot()
result['pass']=all(result.get(k) is True for k in ('unverified_receive_disabled','prepared','journal_present_while_prepared','owned_prepare_closed','journal_cleared','wifi_unchanged','stock_unchanged'))
print('RESULT='+repr(result))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate',required=True)
    args=parser.parse_args()
    if len(args.candidate)!=16 or any(c not in '0123456789abcdef' for c in args.candidate):raise ValueError('Candidate identity required')
    out=ROOT/'logs'/('MtaP011-NetworkPrepare-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir(parents=True)
    adb=Adb(out/'private-raw');safety=(BASE/'runtime/mta_safety.py').read_text(encoding='utf-8')
    gate=safety+"\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    before=adb.python('before',gate);after=None;result=None;failure=None
    try:result=adb.python('prepare-only',safety+'\nBASE='+repr('/mnt/data/p011-toolbox/candidates/mta-01-'+args.candidate)+'\n'+TRIAL,timeout=60)
    except Exception as e:failure=type(e).__name__;print('PREPARE_ERROR='+str(e))
    finally:
        try:after=adb.python('after-independent',gate)
        except Exception:failure=failure or 'INDEPENDENT_STOCK_CHECK_FAILED'
    report={'evidence_level':'P011_NETWORK_PREPARE_ONLY','candidate_identity':args.candidate,'tests':result,
            'stock_independent_unchanged':before==after,'wifi_connection_or_radio_operations':False,'phone_interop':'NOT_TESTED',
            'pass':failure is None and before==after and bool(result and result.get('pass'))}
    if failure:report['error']=failure
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('仅准备/取消只读网络基线，核验自有journal清理；未调用Connect/Scan或注册凭据Agent。\n与原厂状态、当前Wi-Fi指纹作独立对照；无手机互传验收。private-raw不打包。',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
