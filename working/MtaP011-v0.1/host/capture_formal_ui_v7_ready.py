"""Read-only fixed UI-v7 readiness watch, immediately followed by DRM capture.

Does not launch UI, inject input, grant closure, or use a stale ready marker
without the exact candidate being live. The root operator starts the unique
new trial separately. Logs/images remain private; no public account data.
"""
import argparse
import ast
import datetime
from pathlib import Path
import secrets
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'host'))
from device_probe import Adb

WATCH = r'''
import os,signal,stat,time
signal.alarm(70)
root='/var/volatile/tmp/p011-mta-ui-session-a44b98dd639095d9063c9e1a-formal-send-filecenter-ui-v7'
candidate='/mnt/data/p011-toolbox/mta-ui/a44b98dd639095d9063c9e1a/Z03.mta-ui-candidate'
path=root+'/candidate.stderr.raw'
until=time.monotonic()+65.0
fd=None
ready=False
live=False
closed=False
size=0
tail=b''
def current_candidate():
 rows=[]
 for name in os.listdir('/proc'):
  if not name.isdigit():continue
  try:
   if os.readlink('/proc/'+name+'/exe')!=candidate:continue
   with open('/proc/'+name+'/stat','rb') as stream:raw=stream.read(8192)
   rest=raw[raw.rfind(b')')+2:].split()
   if len(rest)>19 and rest[0] not in (b'Z',b'X'):rows.append((name,rest[19]))
  except OSError:pass
 return rows
try:
 while time.monotonic()<until:
  if fd is None:
   try:
    directory=os.lstat(root)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=0 or stat.S_IMODE(directory.st_mode)!=0o700:raise ValueError('directory_unknown')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    first=os.fstat(fd)
    if not stat.S_ISREG(first.st_mode) or first.st_uid!=0 or stat.S_IMODE(first.st_mode)!=0o600 or first.st_nlink!=1:raise ValueError('log_unknown')
   except FileNotFoundError:
    time.sleep(.1)
    continue
  chunk=os.read(fd,65536)
  size+=len(chunk)
  if size>4194304:raise ValueError('log_bound')
  tail=(tail+chunk)[-65536:]
  if b'P011_MTA FORMAL_UI_READY' in tail:
   before=current_candidate()
   linked=os.lstat(path)
   if (first.st_dev,first.st_ino)!=(linked.st_dev,linked.st_ino):raise ValueError('log_changed')
   after=current_candidate()
   live=len(before)==1 and before==after
   if live:
    ready=True
    break
  time.sleep(.05)
finally:
 if fd is not None:
  os.close(fd)
  closed=True
print('RESULT='+repr(dict(ready=ready,candidate_live=live,watch_fd_closed=closed,read_bytes=size,readonly=True)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    ast.parse(WATCH, feature_version=(3, 5))
    if not args.check_device:
        print('READY_WATCH_SOURCE_ONLY; device_not_invoked', flush=True)
        return 0
    out = BASE / 'results' / ('ui-v7-ready-readonly-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    adb = Adb(private)
    facts = adb.python('fixed-v7-ui-ready-readonly', WATCH, timeout=75)
    if not (type(facts) is dict and facts.get('ready') is True and
            facts.get('candidate_live') is True and facts.get('watch_fd_closed') is True):
        print('UI_V7_CURRENT_READY_NOT_OBSERVED', flush=True)
        return 1
    # No user/model round-trip between readiness and the existing DRM reader.
    result = subprocess.run([sys.executable, '-I', '-B',
        str(BASE / 'host/capture_ui_scanout_v1.py'), '--check-device'], cwd=str(BASE))
    print('READY_WATCH_PRIVATE=' + str(out), flush=True)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
