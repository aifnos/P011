"""Read-only aggregate /proc ownership diagnosis for the actual startup failure.

No actor identity, admission or restoration certificate. No process name,
PID, UID/GID, cmdline, SSID, address or raw /proc data is exported.
"""
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
TRANSPORT_SHA = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
SOURCE = r'''
import errno,os,stat,sys,time
if sys.version_info[:3]!=(3,5,5) or os.uname()[4]!='armv7l' or os.geteuid()!=0:raise ValueError('platform')
deadline=time.monotonic()+5.0
rows=[]
result={'numeric_entries':0,'stable_root_owned':0,'stable_nonroot_owned':0,'stable_writable':0,'changed':0,'open_errors':0,'all_held_fds_closed':False}
def check():
 if time.monotonic()>=deadline:raise ValueError('deadline')
def meta(v):return(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)
def close(row):
 if row['attempted']:return row['closed']
 row['attempted']=True
 if meta(os.fstat(row['fd']))!=row['original']:raise ValueError('close_identity')
 returned=os.close(row['fd'])
 try:os.fstat(row['fd'])
 except OSError as e:row['closed']=returned is None and type(e.errno) is int and e.errno==errno.EBADF
 if not row['closed']:raise ValueError('close_unknown')
try:
 check();fd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 root={'fd':fd,'original':meta(os.fstat(fd)),'attempted':False,'closed':False};rows.append(root)
 if not stat.S_ISDIR(root['original'][2]) or root['original'][3:]!=(0,0):raise ValueError('proc_anchor')
 names=os.listdir(fd)
 if len(names)>4096:raise ValueError('entries')
 pids=sorted(n for n in names if n.isdigit())
 if len(pids)>512:raise ValueError('entries')
 result['numeric_entries']=len(pids)
 for name in pids:
  check()
  try:child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  except OSError as e:
   if type(e.errno) is not int or not 1<=e.errno<=4095:raise
   result['open_errors']+=1;continue
  row={'fd':child,'original':meta(os.fstat(child)),'attempted':False,'closed':False};rows.append(row)
  try:
   value=row['original'];named=meta(os.stat(name,dir_fd=fd,follow_symlinks=False))
   if not stat.S_ISDIR(value[2]) or named!=value or meta(os.fstat(child))!=value:
    result['changed']+=1;continue
   if value[3:]==(0,0):result['stable_root_owned']+=1
   else:result['stable_nonroot_owned']+=1
   if value[2]&0o022:result['stable_writable']+=1
  finally:close(row)
 check()
finally:
 failures=[]
 for row in reversed(rows):
  try:close(row)
  except BaseException as e:failures.append(e)
 result['all_held_fds_closed']=bool(rows) and not failures and all(r['closed'] for r in rows)
 if failures:raise ValueError('close_unknown')
print('RESULT='+repr(result))
'''


def main():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('startup-proc-ownership-' + stamp + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    raw = (BASE / 'host/device_probe.py').read_bytes()
    if len(raw) != 8759 or hashlib.sha256(raw).hexdigest() != TRANSPORT_SHA:
        raise ValueError('transport_changed')
    transport = types.ModuleType('fixed_readonly_transport')
    transport.__file__ = str(BASE / 'host/device_probe.py')
    exec(compile(raw, transport.__file__, 'exec'), transport.__dict__)
    with (out / 'private-transport.py').open('xb') as handle:
        handle.write(raw)
    with (out / 'private-probe-source.py').open('x', encoding='ascii', newline='\n') as handle:
        handle.write(SOURCE)
    report = {'schema': 'p011-startup-proc-ownership-v1', 'passed': False,
        'device_writes': False, 'rf_requested': False, 'actor_authenticated': False,
        'receive_admission': False, 'full_restoration_verified': False, 'observations': None}
    try:
        value = transport.Adb(out / 'private-raw').python('proc-ownership', SOURCE, timeout=20)
        fields = {'numeric_entries', 'stable_root_owned', 'stable_nonroot_owned',
            'stable_writable', 'changed', 'open_errors', 'all_held_fds_closed'}
        if (type(value) is not dict or set(value) != fields or
                type(value['all_held_fds_closed']) is not bool or
                any(type(value[k]) is not int or not 0 <= value[k] <= 512
                    for k in fields - {'all_held_fds_closed'})):
            raise ValueError('result_fields')
        report['observations'] = value
        report['passed'] = value['all_held_fds_closed'] is True
    except Exception as error:
        report['host_error'] = type(error).__name__
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = b'Read-only aggregate /proc directory ownership observation. No actor authentication, receive, radio operation, device write or restoration claim. Raw and exact probe/transport remain local/private.\n'
    for name, value in (('result.json', public), ('README.txt', readme)):
        with (out / name).open('xb') as handle:
            handle.write(value)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps({'passed': report['passed'], 'result_dir': str(out),
        'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
