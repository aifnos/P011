"""Private, explicit-transport P011 account verification and raw evidence capture."""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
ADB = r'C:\Program Files\ADB\adb.exe'
PINS = {
    '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b',
}

BASELINE = r'''
import os,sys,time,hashlib,platform
def identity(pid):
 raw=open('/proc/'+str(pid)+'/stat').read(4096)
 end=raw.rindex(')'); parts=raw[end+2:].split()
 return dict(pid=int(pid),name=raw[raw.index('(')+1:end],parent=int(parts[1]),starttime=parts[19],exe=os.readlink('/proc/'+str(pid)+'/exe'))
processes=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 try:
  row=identity(pid)
  if row['name'] in ('Z03','control_engine','weston','connmand','bluetoothd'):
   if row['name'] in ('Z03','control_engine'):row['parent_identity']=identity(row['parent'])
   processes.append(row)
 except (OSError,ValueError):pass
hashes={p:hashlib.sha256(open(p,'rb').read()).hexdigest() for p in PINS}
files={}
for folder in ('/home/userdata','/mnt/data/p011-toolbox/bili-formal','/mnt/data/p011-toolbox/bili-formal/releases'):
 if os.path.isdir(folder):
  files[folder]=[dict(name=n,bytes=os.lstat(folder+'/'+n).st_size,directory=os.path.isdir(folder+'/'+n),link=os.path.islink(folder+'/'+n)) for n in sorted(os.listdir(folder))[:120]]
print('RESULT='+repr(dict(uid=os.getuid(),machine=platform.machine(),firmware=open('/etc/os-release').read(4096),hashes=hashes,processes=processes,paths=files,epoch=time.time(),boot_id=open('/proc/sys/kernel/random/boot_id').read().strip(),uptime_seconds=float(open('/proc/uptime').read().split()[0]),userdata_realpath=os.path.realpath('/home/userdata'))))
'''


class Evidence:
    def __init__(self, transport, output=None):
        self.transport = transport
        self.output = Path(output) if output else ROOT / 'results' / (
            datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y%m%d-%H%M%S')
            + '-' + secrets.token_hex(4))
        self.output.mkdir(parents=True, exist_ok=False)
        self.seq = 0

    def command(self, label, arguments, timeout=30):
        self.seq += 1
        name = '%02d-%s' % (self.seq, label)
        try:
            p = subprocess.run([ADB, '-t', str(self.transport)] + arguments,
                               capture_output=True, timeout=timeout)
            raw, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            raw, err, code = exc.stdout or b'', exc.stderr or b'', None
        (self.output / (name + '.stdout.raw')).write_bytes(raw)
        (self.output / (name + '.stderr.raw')).write_bytes(err)
        clean = raw.decode('utf8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
        import re
        markers = re.findall(r'^__REMOTE_EXIT__=(\d+)\s*$', clean, re.M)
        status = dict(host_exit=code, remote_exit=int(markers[-1]) if markers else None,
                      timeout=code is None)
        (self.output / (name + '.status.json')).write_text(json.dumps(status, indent=2), encoding='utf8')
        if code != 0 or (arguments[0] == 'shell' and markers != ['0']):
            raise RuntimeError('Command failed: ' + name + '; inspect saved raw evidence')
        return clean

    def python(self, label, source, timeout=30):
        encoded = base64.b64encode(zlib.compress(source.encode('utf8'), 9)).decode('ascii')
        loader = 'import base64,zlib;exec(zlib.decompress(base64.b64decode(' + repr(encoded) + ')))'
        command = '(python3 -B -c ' + shlex.quote(loader) + '); rc=$?; printf "\n__REMOTE_EXIT__=%s\n" "$rc"'
        if len(command.encode()) >= 4096:
            raise ValueError('Remote command exceeds verified ADB length')
        clean = self.command(label, ['shell', command], timeout)
        rows = [line[7:] for line in clean.splitlines() if line.startswith('RESULT=')]
        if len(rows) != 1:
            raise ValueError('Expected one structured result')
        return ast.literal_eval(rows[0])

    def baseline(self, label):
        result = self.python(label, 'PINS=' + repr(PINS) + '\n' + BASELINE)
        if result['hashes'] != PINS or result['uid'] != 0 or result['machine'] != 'armv7l':
            raise ValueError('Wrong device or firmware')
        if 'z031_v2.4.0-20251128_174826-user' not in result['firmware']:
            raise ValueError('Wrong firmware version')
        for name in ('Z03', 'control_engine', 'weston'):
            rows = [r for r in result['processes'] if r['name'] == name]
            if len(rows) != 1:
                raise ValueError('Expected one stock process: ' + name)
            if name != 'weston' and rows[0]['exe'] != '/usr/bin/' + name:
                raise ValueError('Unexpected running executable: ' + name)
        (self.output / (label + '.json')).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf8')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport', type=int, required=True)
    parser.add_argument('action', choices=('inspect','state','verify'))
    parser.add_argument('--execute-logout', action='store_true')
    args = parser.parse_args()
    evidence = Evidence(args.transport)
    print('EVIDENCE=' + str(evidence.output), flush=True)
    result = evidence.baseline('baseline')
    if args.action == 'inspect':
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    stage(evidence, result, args.action, args.execute_logout)


def stage(evidence, baseline, action, execute):
    source = ROOT / 'device_account.py'
    codec = ROOT.parents[1] / 'working/MtaP011-v0.1/runtime/p011_json.py'
    sources = {'device_account.py':source.read_bytes(),'p011_json.py':codec.read_bytes()}
    runid = evidence.output.name
    folder = '/mnt/data/p011-toolbox/account-check/' + runid
    manifest = {name:hashlib.sha256(data).hexdigest() for name,data in sources.items()}
    prepare = r'''
import os,stat
area='/mnt/data/p011-toolbox'
for path in ('/mnt','/mnt/data',area):
 if not os.path.isdir(path) or os.path.islink(path):raise ValueError('Unsafe parent')
base=area+'/account-check'
if not os.path.lexists(base):os.mkdir(base,0o700)
if not os.path.isdir(base) or os.path.islink(base):raise ValueError('Unsafe task directory')
os.mkdir(FOLDER,0o700)
print('RESULT='+repr({'created':True}))
'''
    evidence.python('prepare-private-helper', 'FOLDER='+repr(folder)+'\n'+prepare)
    for name in sources:
        evidence.command('stage-'+name.replace('.','-'), ['push',str(source if name=='device_account.py' else codec),folder+'/'+name])
    check = r'''
import os,hashlib
for name,value in MANIFEST.items():
 path=FOLDER+'/'+name
 if os.path.islink(path) or hashlib.sha256(open(path,'rb').read()).hexdigest()!=value:raise ValueError('Helper mismatch')
 os.chmod(path,0o600)
print('RESULT='+repr({'source_verified':True}))
'''
    evidence.python('verify-staged-source','FOLDER='+repr(folder)+'\nMANIFEST='+repr(manifest)+'\n'+check)
    stock = [r for r in baseline['processes'] if r['name']=='Z03'][0]
    arguments = ['python3','-B',folder+'/device_account.py',action,'--pid',str(stock['pid']),'--starttime',stock['starttime']]
    if execute:
        arguments.append('--execute-logout')
    command = '('+' '.join(shlex.quote(x) for x in arguments)+'); rc=$?; printf "\n__REMOTE_EXIT__=%s\n" "$rc"'
    clean = evidence.command('account-'+action,['shell',command],timeout=140)
    rows = [line[7:] for line in clean.splitlines() if line.startswith('RESULT=')]
    if len(rows)!=1:
        raise ValueError('Missing helper result; do not repeat an unlink request')
    result = ast.literal_eval(rows[0])
    (evidence.output/'account-result.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf8')
    (evidence.output/'run.json').write_text(json.dumps(dict(folder=folder,source_sha256=manifest,execute_logout=execute),indent=2),encoding='utf8')
    after = evidence.baseline('after')
    print(json.dumps(dict(account=result,stock_hashes_unchanged=after['hashes']==baseline['hashes'],
                         stock_processes_unchanged=after['processes']==baseline['processes']),indent=2,ensure_ascii=False))


if __name__ == '__main__':
    main()
