"""Scoped native input and read-only framebuffer capture after legacy install."""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import zlib

from audit_device import Adb, WORKSPACE, archive


def guard(snapshot):
    core = []
    for row in snapshot['processes']:
        if row['comm'] in ('Z03', 'control_engine', 'weston'):
            core.append(row)
    if len(core) != 3:
        raise ValueError('Expected exactly three installed core identities')
    return r'''
import os,stat,struct,ctypes as c,hashlib,time
EXPECTED=''' + repr({'boot_id': snapshot['boot_id'], 'hashes': snapshot['hashes'], 'processes': core}) + r'''
assert os.getuid()==0
assert open('/proc/sys/kernel/random/boot_id').read().strip()==EXPECTED['boot_id']
for path,checksum in EXPECTED['hashes'].items():
 assert hashlib.sha256(open(path,'rb').read()).hexdigest()==checksum
def check_pid(row):
 pid=row['pid'];raw=open('/proc/'+str(pid)+'/stat').read();fields=raw[raw.rindex(')')+2:].split()
 assert int(fields[19])==int(row['starttime']) and int(fields[1])==int(row['ppid'])
 assert os.readlink('/proc/'+str(pid)+'/exe')==row['exe']
for row in EXPECTED['processes']:
 check_pid(row)
 if isinstance(row.get('parent'),dict):check_pid(row['parent'])
assert open('/sys/class/input/event2/device/name').read().strip()=='cst1xx'
assert stat.S_ISCHR(os.stat('/dev/input/event2').st_mode)
'''


INPUT = r'''
libc=c.CDLL(None,use_errno=True)
probe=os.open('/dev/input/event2',os.O_RDONLY|os.O_NONBLOCK)
try:
 for code,maximum in ((0x35,480),(0x36,800)):
  data=c.create_string_buffer(24)
  assert libc.ioctl(probe,0x80184540+code,data)==0
  values=struct.unpack('<6i',data.raw)
  assert values[1]==0 and values[2]==maximum
finally:os.close(probe)
fd=os.open('/dev/input/event2',os.O_WRONLY|os.O_NONBLOCK)
def event(kind,code,value):
 assert os.write(fd,struct.pack('<llHHi',0,0,kind,code,value))==16
def position(x,y):
 event(3,0x35,y);event(3,0x36,800-x);event(0,0,0)
try:
 event(3,0x2f,0);event(3,0x39,321);event(1,0x14a,1)
 position(POINTS[0],POINTS[1])
 if ACTION=='swipe':
  for i in range(1,17):
   time.sleep(.018)
   position(round(POINTS[0]+(POINTS[2]-POINTS[0])*i/16),round(POINTS[1]+(POINTS[3]-POINTS[1])*i/16))
 else:time.sleep(.08)
finally:
 try:event(3,0x39,-1);event(1,0x14a,0);event(0,0,0)
 finally:os.close(fd)
time.sleep(.35)
print('RESULT='+repr({'native_input_injected':True,'action':ACTION,'logical_points':POINTS}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'tap', 'swipe'))
    parser.add_argument('--transport', type=int, required=True)
    parser.add_argument('--expected-snapshot', type=Path, required=True)
    parser.add_argument('--points', type=int, nargs='+')
    args = parser.parse_args()
    if args.action != 'capture':
        required = 2 if args.action == 'tap' else 4
        if not args.points or len(args.points) != required:
            parser.error('Explicit observed logical coordinates required')
        if any(not 0 <= args.points[i] <= 800 or not 106 <= args.points[i+1] <= 373
               for i in range(0, required, 2)):
            parser.error('Input must stay inside the observed 800x268 content region')
    snapshot = json.loads(args.expected_snapshot.read_text(encoding='utf-8-sig'))
    if snapshot['hashes']['/usr/bin/Z03'] != 'b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8':
        raise ValueError('Only the installed legacy settings candidate is supported')
    stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out = WORKSPACE / 'logs' / ('BrowserP011-LegacyUI-' + args.action + '-' + stamp)
    out.mkdir()
    adb = Adb(args.transport, out)
    code = guard(snapshot)
    if args.action == 'capture':
        path = WORKSPACE / 'working/BiliP011-v0.1/host/capture_drm_scanout.py'
        sys.path.insert(0, str(path.parent))
        spec = importlib.util.spec_from_file_location('p011_readonly_drm', path)
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        result, _ = adb.python('readonly-framebuffer', code + '\n' + capture.PROBE, timeout=20)
        from PIL import Image
        for row in result['rows']:
            packed = row.pop('pixels_zlib_b64', None)
            if packed:
                raw = zlib.decompress(base64.b64decode(packed))
                image = Image.frombytes('RGB', (row['fb_width'], row['fb_height']), raw, 'raw', 'BGRX', row['pitch'], 1)
                image.save(out / 'scanout-native.png')
                logical = image.transpose(Image.Transpose.ROTATE_270)
                logical.save(out / 'screen-landscape.png')
                if logical.size != (800, 480):
                    raise ValueError('Unexpected current framebuffer size')
                logical.crop((0, 106, 800, 374)).save(out / 'screen-visible.png')
                row['visible_crop'] = [0, 106, 800, 374]
        result['evidence_scope'] = 'read_only_scanout_visible_crop'
    else:
        result, _ = adb.python('native-' + args.action,
            code + '\nPOINTS=' + repr(args.points) + '\nACTION=' + repr(args.action) + '\n' + INPUT)
    (out / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    target, checksum = archive(out)
    print('LOG_DIR=' + str(out))
    print('RESULT_ZIP=' + str(target))
    print('SHA256=' + checksum)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
