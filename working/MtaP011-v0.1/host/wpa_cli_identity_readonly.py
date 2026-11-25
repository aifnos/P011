"""One bounded file-only P011 observation; never execute wpa_cli or alter radio."""
import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import time

BASE = Path(__file__).absolute().parents[1]
HELPER_SHA = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
SOURCE = r'''
import errno,hashlib,os,stat,time
def meta(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def one(path):
 fd=None; close_returned=False; closed=False; stable=False; result=''; error='not_recorded'
 try:
  before=os.lstat(path)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode & 0o022 or not 0 < before.st_size <= 16777216:
   raise ValueError('file_shape')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  opened=os.fstat(fd)
  if meta(before)!=meta(opened):raise ValueError('file_changed')
  h=hashlib.sha256(); count=0; deadline=time.monotonic()+10
  while True:
   if time.monotonic()>deadline:raise ValueError('deadline')
   data=os.read(fd,65536)
   if not data:break
   count+=len(data)
   if count>16777216:raise ValueError('file_bound')
   h.update(data)
  stable=count==before.st_size and meta(os.fstat(fd))==meta(before) and meta(os.lstat(path))==meta(before)
  if not stable:raise ValueError('file_changed')
  result=h.hexdigest()
 except Exception as exc:
  error='os_error' if isinstance(exc,OSError) else str(exc) if isinstance(exc,ValueError) else 'unexpected'
 finally:
  if fd is not None:
   try:close_returned=os.close(fd) is None
   except Exception:pass
   try:os.fstat(fd)
   except OSError as exc:closed=close_returned and exc.errno==errno.EBADF
 return {'sha256':result,'stable':stable,'original_fd_closed':closed,'error':error}
paths=('/usr/sbin/wpa_cli','/usr/bin/Z03','/usr/bin/control_engine','/usr/bin/zyb_z03_launch.sh')
print('RESULT='+repr({'uid_root':os.geteuid()==0,'architecture':os.uname()[4], 'files':dict((p,one(p)) for p in paths)}))
'''


def helper():
    path = BASE / 'host/device_probe.py'
    if hashlib.sha256(path.read_bytes()).hexdigest() != HELPER_SHA:
        raise ValueError('helper_source_changed')
    spec = importlib.util.spec_from_file_location('p011_fileonly_probe_transport', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute():
    module = helper()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = BASE.parents[1] / 'logs' / ('MtaP011-WpaCliFileOnly-' + stamp)
    output.mkdir(parents=True, exist_ok=False)
    adb = module.Adb(output / 'private-raw')
    started = time.monotonic()
    observed = adb.python('file-only', SOURCE, timeout=45)
    elapsed = time.monotonic() - started
    raw = (output / 'private-raw/01-file-only.stdout.raw').read_bytes()
    lines = raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n').splitlines()
    stderr = (output / 'private-raw/01-file-only.stderr.raw').read_bytes()
    markers = (sum(v == 'MTA_REMOTE_OK' for v in lines) == 1 and
               sum(v == 'MTA_REMOTE_EXIT=0' for v in lines) == 1 and
               sum(v.startswith('RESULT=') for v in lines) == 1)
    files = observed['files']
    stock = all(files[path]['sha256'] == pin for path, pin in module.PINS.items())
    stable = all(row['stable'] and row['original_fd_closed'] and row['error'] == 'not_recorded' for row in files.values())
    result = {'evidence': 'P011_FILE_ONLY_READONLY', 'pass': markers and not stderr and stock and stable and observed['uid_root'],
              'wpa_cli_sha256': files['/usr/sbin/wpa_cli']['sha256'], 'stock_file_hashes_match': stock,
              'files_stable_and_original_fds_closed': stable, 'host_exit': 0, 'remote_exit': 0,
              'exact_markers': markers, 'stderr_bytes': len(stderr), 'elapsed_seconds': elapsed,
              'architecture': observed['architecture'], 'file_observations': files,
              'wpa_cli_executed': False, 'network_operations': False, 'reboot': False,
              'pending_read_or_clear': False, 'production_manifest_authenticated': False,
              'baseline_collector_executed': False, 'phone_tested': False,
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'transport_helper_sha256': HELPER_SHA}
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (output / 'README.txt').write_text('P011 fixed-file read-only SHA observation. No CLI execution, RF, reboot, pending access or repair.\nStock file hashes alone do not prove process/UI/network restoration. Raw stays private.\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('RESULT_DIR=' + str(output))
    return 0 if result['pass'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly', action='store_true')
    args = parser.parse_args()
    ast.parse(SOURCE, feature_version=(3, 5))
    if not args.execute_readonly:
        print('SOURCE_ONLY: file-only fixed source; explicit --execute-readonly required.')
        return 0
    return execute()


if __name__ == '__main__':
    raise SystemExit(main())
