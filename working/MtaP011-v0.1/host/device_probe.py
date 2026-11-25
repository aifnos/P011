"""Read-only P011 capability/stock probe; never starts archived candidates.

Raw outputs are private. Public results contain no serial/MAC/SSID/IP/name.
The target is selected by its observed P011 ADB product, not the default device.
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
import subprocess
import sys
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
ADB = Path('C:/Program Files/ADB/adb.exe')
PINS = {
 '/usr/bin/Z03':'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
 '/usr/bin/control_engine':'364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
 '/usr/bin/zyb_z03_launch.sh':'7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}


def select_target():
    process = subprocess.run([str(ADB), 'devices', '-l'], capture_output=True, timeout=15)
    if process.returncode:
        raise RuntimeError('ADB enumeration failed')
    targets = []
    for line in process.stdout.decode('utf-8','replace').splitlines():
        if re.search(r'\sdevice\s', line) and 'product:sprdtrum' in line and 'model:sprdisk' in line:
            match = re.search(r'transport_id:([0-9]+)',line)
            if match: targets.append(match.group(1))
    if len(targets) != 1:
        raise RuntimeError('Expected exactly one identified P011; found '+str(len(targets)))
    return targets[0]


class Adb:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        self.transport = select_target()
        self.index = 0

    def run(self, label, arguments, timeout=30, input_data=None):
        self.index += 1
        stem = '%02d-%s' % (self.index,label)
        try:
            process = subprocess.run([str(ADB),'-t',self.transport]+arguments,
                                     input=input_data,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (self.directory/(stem+'.stdout.raw')).write_bytes(error.stdout or b'')
            (self.directory/(stem+'.stderr.raw')).write_bytes(error.stderr or b'')
            (self.directory/(stem+'.host-exit')).write_text('TIMEOUT',encoding='ascii')
            raise RuntimeError('ADB command timed out; retained partial raw output: '+label) from error
        (self.directory/(stem+'.stdout.raw')).write_bytes(process.stdout)
        (self.directory/(stem+'.stderr.raw')).write_bytes(process.stderr)
        (self.directory/(stem+'.host-exit')).write_text(str(process.returncode),encoding='ascii')
        if process.returncode: raise RuntimeError('ADB host command failed: '+label)
        return process.stdout

    def python(self, label, source, timeout=45):
        payload = base64.b64encode(zlib.compress(source.encode('utf-8'))).decode('ascii')
        command = ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\''+
                   payload+'\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        if len(command)>3500:
            data=(source+"\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
            command=('python3 -B -c "import sys;exec(sys.stdin.buffer.read('+str(len(data))+'))" mta-readonly-probe; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            raw=self.run(label,['shell',command],timeout,input_data=data)
        else:
            raw = self.run(label,['shell',command],timeout)
        derived = raw.decode('utf-8','replace').replace('\r\r\n','\n').replace('\r\n','\n')
        if 'MTA_REMOTE_OK' not in derived or not re.search(r'^MTA_REMOTE_EXIT=0$',derived,re.M):
            raise RuntimeError('Remote Python failed: '+label)
        result = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
        if len(result)!=1: raise RuntimeError('Expected exactly one remote result')
        return ast.literal_eval(result[0])


PROBE = r'''
import ctypes,glob,hashlib,os,re,subprocess,time
def command(argv):
 try:
  p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  out,err=p.communicate(timeout=8)
  return p.returncode,out.decode('utf-8','replace')
 except (OSError,subprocess.TimeoutExpired):
  try:p.kill();p.communicate()
  except Exception:pass
  return -1,''
def digest(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def identity(pid):
 raw=open('/proc/'+str(pid)+'/stat').read(4096);end=raw.rindex(')');f=raw[end+2:].split()
 return {'pid':int(pid),'name':raw[raw.index('(')+1:end],'parent':int(f[1]),'starttime':f[19],'exe':os.readlink('/proc/'+str(pid)+'/exe')}
rows=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 try:
  row=identity(pid)
  if row['name'] in ('Z03','control_engine','weston','connmand','bluetoothd','wpa_supplicant'):
   if row['name'] in ('Z03','control_engine'):row['parent_identity']=identity(row['parent'])
   rows.append(row)
 except (OSError,ValueError):pass
stock={'hashes':{p:digest(p) for p in PINS},'processes':sorted(rows,key=lambda r:r['pid'])}
code,status=command(['/usr/sbin/wpa_cli','-i','wlan0','status'])
fields=dict(line.split('=',1) for line in status.splitlines() if '=' in line)
mode_code,modes=command(['/usr/sbin/wpa_cli','-i','wlan0','get_capability','modes'])
iw_code,iw=command(['iw','list'])
dbus_code,dbus=command(['dbus-send','--system','--print-reply','--dest=org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus.ListNames'])
cap={'wpa_status_ok':code==0,'wifi_connected':fields.get('wpa_state')=='COMPLETED',
 'wpa_modes':modes.strip().split() if mode_code==0 else [],
 'p2p_reported_by_iw':iw_code==0 and any(s in iw for s in ['P2P-client','P2P-GO']),
 'iw_available':iw_code==0,'p2p_socket_present':any('p2p' in p for p in glob.glob('/run/wpa_supplicant/*')),
 'bluez_bus_owner':dbus_code==0 and 'org.bluez' in dbus,
 'connman_bus_owner':dbus_code==0 and 'net.connman' in dbus,
 'nm_bus_owner':dbus_code==0 and 'org.freedesktop.NetworkManager' in dbus,
 'crypto_evp_available':False,'standard_json_available':False,'python_version':tuple(__import__('sys').version_info[:3]),
 'architecture':os.uname()[4],'temporary_menu_present':os.path.lexists('/mnt/data/p011-menu')}
try:
 lib=ctypes.CDLL('/usr/lib/libcrypto.so.1.0.2')
 cap['crypto_evp_available']=all(hasattr(lib,n) for n in ['EVP_CIPHER_CTX_new','EVP_aes_256_ctr','EVP_EncryptInit_ex','EVP_EncryptUpdate','EVP_EncryptFinal_ex'])
except OSError:pass
try:import json;cap['standard_json_available']=True
except ImportError:pass
print('RESULT='+repr({'stock':stock,'capabilities':cap}))
'''


def source():
    return 'PINS='+repr(PINS)+'\n'+PROBE


def run_probe(output=None):
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = Path(output) if output else ROOT/'logs'/('MtaP011-Readonly-'+stamp)
    output.mkdir(parents=True,exist_ok=False)
    adb = Adb(output/'private-raw')
    before=adb.python('before',source())
    after=adb.python('after',source())
    expected_names=['Z03','control_engine','weston']
    stock_ok=before['stock']['hashes']==PINS and all(len([r for r in before['stock']['processes'] if r['name']==n])==1 for n in expected_names)
    stock_ok=stock_ok and all(r['exe']=='/usr/bin/'+r['name'] for r in before['stock']['processes'] if r['name'] in ('Z03','control_engine'))
    stable=before['stock']==after['stock']
    report={'evidence_level':'P011_READONLY','device_writes':False,
            'stock_identity_ok':stock_ok,'stock_unchanged':stable,
            'capabilities':after['capabilities'],
            'radio_operations':False,'phone_interop':'NOT_TESTED',
            'pass':stock_ok and stable and not after['capabilities']['temporary_menu_present']}
    (output/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (output/'README.txt').write_text('只读能力检查。private-raw 保留本地原始stdout/stderr与exit，不进入脱敏ZIP。\n不代表互传实际成功。',encoding='utf-8')
    archive=output.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ['result.json','README.txt']:bundle.write(output/name,name)
    return report,output,archive


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    report,output,archive=run_probe(args.output)
    print(json.dumps(report,ensure_ascii=False,indent=2))
    print('RESULT_DIR='+str(output));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
