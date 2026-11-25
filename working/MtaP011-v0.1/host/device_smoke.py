"""Install an isolated candidate and run capability/runtime tests without RF actions.

No advertising, scanning, pairing, Wi-Fi connection or original UI replacement.
Candidate and raw logs stay for attribution. A sanitized ZIP excludes secrets.
"""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import zipfile
from device_probe import Adb, BASE, ROOT, PINS, source


def main():
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out=ROOT/'logs'/('MtaP011-RuntimeSmoke-'+stamp);out.mkdir(parents=True)
    adb=Adb(out/'private-raw')
    safety=(ROOT/'working/ToolboxNext-v0.5.1-native/runtime/native_safety.py').read_text(encoding='utf-8')
    gate=safety+"\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    before=adb.python('before',gate)
    files=sorted((BASE/'runtime').glob('*.py'))+sorted((BASE/'out/native').glob('mta-*-helper'))
    if not files or not any(f.name=='mta-bluez-helper' for f in files):raise RuntimeError('Build native helpers first')
    manifest=[{'name':f.name,'size':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]
    identity=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode('ascii')).hexdigest()[:16]
    target='/mnt/data/p011-toolbox/candidates/mta-smoke-'+identity
    create=safety+"\np="+repr(target)+"\nowned_directory(p,True)\nprint('RESULT='+repr({'candidate':p,'already_present':bool(os.listdir(p))}))"
    current=adb.python('candidate-directory',create)
    if not current['already_present']:
        for file in files:adb.run('push-candidate',['push',str(file),target+'/'+file.name])
    code=safety+'\nBASE='+repr(target)+'\nMANIFEST='+repr(manifest)+'\n'+SMOKE
    try:result=adb.python('runtime-smoke',code)
    finally:after=adb.python('after',gate)
    report={'evidence_level':'P011_RUNTIME_NO_RADIO_ACTIONS','candidate_identity':identity,
            'stock_unchanged':before==after,'candidate_files_verified':True,
            'system_files_modified':False,'candidate_files_written':not current['already_present'],
            'radio_operations':False,'phone_interop':'NOT_TESTED','tests':result}
    report['pass']=before==after and all(v for k,v in result.items() if k.endswith('_pass'))
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('仅候选目录安装、原生只读能力及Python运行测试。没有广播/扫描/切换Wi-Fi。\n不证明原厂手机互传。private-raw不进入脱敏ZIP。',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ['result.json','README.txt']:bundle.write(out/name,name)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


SMOKE=r'''
import base64,hashlib,os,subprocess,sys,tempfile,zipfile
for row in MANIFEST:
 p=BASE+'/'+row['name']
 if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p)!=row['size'] or digest(p)!=row['sha256']:raise ValueError('Candidate differs')
 if row['name'].endswith('-helper'):os.chmod(p,0o700)
sys.path.insert(0,BASE)
import p011_json as J
from mta_protocol import encode_advertisement,decode_advertisement,WsMessage,P2pInfo
from mta_crypto import OpenSslCrypto
from mta_storage import SafeZipReceiver
from mta_service import State,capability
packet=encode_advertisement(b'\x12\x34',1,'HOST测试',False)
adv=decode_advertisement(packet['adv_data'],packet['scan_rsp'])
result={'protocol_pass':adv['sender_id']=='1234' and WsMessage.parse(WsMessage('action',1,'versionNegotiation',{'version':1}).serialize()).payload['version']==1,
 'json_pass':J.loads(J.dumps({'test':'中文','value':[1,True,None]}))=={'test':'中文','value':[1,True,None]}}
crypto=OpenSslCrypto('/usr/bin/openssl',crypto_library='/usr/lib/libcrypto.so.1.0.2')
with crypto.generate_keypair() as a:
 with crypto.generate_keypair() as b:
  one=crypto.derive_shared(a,b.public_key);two=crypto.derive_shared(b,a.public_key)
  plain=P2pInfo('HOST-SYNTHETIC','HOST-TEST-PSK','02:00:00:00:00:01',12345)
  encrypted=crypto.encrypt_credentials(plain,a,b.public_key)
  recovered=crypto.decrypt_credentials(encrypted,b)
  result['crypto_pass']=one==two and len(one)==32 and recovered.ssid==plain.ssid and recovered.psk==plain.psk
owned_directory('/mnt/data/p011-toolbox/sessions',True)
session=tempfile.mkdtemp(prefix='mta-smoke-',dir='/mnt/data/p011-toolbox/sessions')
os.mkdir(session+'/Received',0o700)
with zipfile.ZipFile(session+'/input.zip','w',zipfile.ZIP_STORED) as z:z.writestr('fixture.txt',b'P011 HOST FIXTURE')
storage=SafeZipReceiver(session+'/Received')
saved=storage.receive(session+'/input.zip','smoke',expected_files=1,expected_bytes=17)
result['storage_pass']=saved['fileCount']==1 and saved['totalSize']==17
state=State(session,BASE+'/mta-bluez-helper',BASE+'/mta-network-helper')
status=state.status()
result['service_pass']=status['discoverable']==False and status['scanning']==False and status['capabilities']['send']['available']==False
result['bluetooth_capabilities']=state.bluetooth_caps
result['network_capabilities']=state.network_caps
result['native_readonly_pass']=bool(state.bluetooth_caps.get('mgmt_info') and state.network_caps.get('ok'))
result['service_close_pass']=state.close()
print('RESULT='+repr(result))
'''


if __name__=='__main__':sys.exit(main())
