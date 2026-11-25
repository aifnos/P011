"""Finite native EGL initialization comparison, without Qt, windows or webpages."""
from __future__ import annotations
import argparse
import datetime as dt
import json
from pathlib import Path
import re
from audit_device import Adb, SNAPSHOT, WORKSPACE, archive
from gui_trial import anchor


CHILD = r'''
import os,ctypes
E=ctypes.CDLL('/usr/lib/libmali.so.0',use_errno=True)
W=ctypes.CDLL('libwayland-client.so.0',use_errno=True)
W.wl_display_connect_to_fd.argtypes=[ctypes.c_int];W.wl_display_connect_to_fd.restype=ctypes.c_void_p
W.wl_display_disconnect.argtypes=[ctypes.c_void_p]
E.eglGetDisplay.argtypes=[ctypes.c_void_p];E.eglGetDisplay.restype=ctypes.c_void_p
E.eglGetProcAddress.argtypes=[ctypes.c_char_p];E.eglGetProcAddress.restype=ctypes.c_void_p
E.eglInitialize.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_int),ctypes.POINTER(ctypes.c_int)];E.eglInitialize.restype=ctypes.c_uint
E.eglGetError.restype=ctypes.c_uint
E.eglQueryString.argtypes=[ctypes.c_void_p,ctypes.c_int];E.eglQueryString.restype=ctypes.c_char_p
E.eglTerminate.argtypes=[ctypes.c_void_p];E.eglTerminate.restype=ctypes.c_uint
def query(display,key):
 raw=E.eglQueryString(display,key)
 return raw.decode('ascii','replace')[:2048] if raw else None
result={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'method':os.environ['P011_EGL_METHOD'],'private_wayland':os.environ['P011_PRIVATE_WL']=='1','qt_tested':False,'window_created':False,'webengine_tested':False}
display=W.wl_display_connect_to_fd(int(os.environ['WAYLAND_SOCKET']))
result['wayland_connected']=bool(display)
result['client_extensions']=query(None,0x3055)
E.eglGetError()
native=None
if display:
 if result['method']=='legacy':native=E.eglGetDisplay(display)
 else:
  address=E.eglGetProcAddress(b'eglGetPlatformDisplayEXT')
  result['platform_ext_available']=bool(address)
  if address:
   function=ctypes.CFUNCTYPE(ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int))(address)
   native=function(0x31D8,display,None)
 result['get_display_error']=int(E.eglGetError());result['egl_display_nonnull']=bool(native)
 if native:
  major=ctypes.c_int();minor=ctypes.c_int();ctypes.set_errno(0)
  ok=E.eglInitialize(native,ctypes.byref(major),ctypes.byref(minor))
  result['initialize_errno']=ctypes.get_errno();result['initialize_error']=int(E.eglGetError());result['initialized']=bool(ok)
  if ok:
   result.update(egl_version=[major.value,minor.value],vendor=query(native,0x3053),version=query(native,0x3054),display_extensions=query(native,0x3055))
   result['terminated']=bool(E.eglTerminate(native));result['terminate_error']=int(E.eglGetError())
 W.wl_display_disconnect(display)
print('NATIVE_RESULT='+repr(result))
'''

LIB_VERIFY = r'''
import os,stat,hashlib
for row in FILES:
 if not row['path'].startswith('lib/'):continue
 p=PAYLOAD+'/'+row['path'];s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Private library metadata differs')
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   b=f.read(262144)
   if not b:break
   h.update(b)
 if s.st_size!=row['bytes'] or h.hexdigest()!=row['sha256']:raise ValueError('Private library identity differs')
print('RESULT='+repr({'private_libraries_verified':True}))
'''

REMOTE = r'''
import os,socket,subprocess
rows=[]
for uid,gid in IDENTITIES:
 for method in ['legacy','ext']:
  connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(2);connection.connect('/run/user/0/wayland-0');connection.settimeout(None)
  env={'PATH':'/usr/bin:/bin','LANG':'C','EGL_PLATFORM':'wayland','WAYLAND_SOCKET':str(connection.fileno()),'P011_EGL_METHOD':method,'P011_PRIVATE_WL':'1' if PRIVATE else '0'}
  if PRIVATE:env['LD_LIBRARY_PATH']=PAYLOAD+'/lib'
  def low():
   import ctypes
   class Limit(ctypes.Structure):_fields_=[('cur',ctypes.c_ulong),('max',ctypes.c_ulong)]
   libc=ctypes.CDLL(None)
   if libc.setrlimit(4,ctypes.byref(Limit(0,0)))!=0:os._exit(125)
   os.setgroups([]);os.setgid(gid);os.setuid(uid)
  p=subprocess.Popen(['/usr/bin/python3','-B','-c',CHILD],cwd='/',env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,pass_fds=(connection.fileno(),),preexec_fn=low)
  connection.close();timed_out=False
  try:a,b=p.communicate(timeout=5)
  except subprocess.TimeoutExpired:
   timed_out=True;p.kill();a,b=p.communicate(timeout=2)
  rows.append({'uid':uid,'gid':gid,'method':method,'child_exit':p.returncode,'timed_out':timed_out,'stdout':a.decode('utf-8','replace'),'stderr':b.decode('utf-8','replace')})
print('RESULT='+repr(rows))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--transport', required=True, type=int)
    p.add_argument('--gui-run', required=True, type=Path)
    p.add_argument('--expected-snapshot', required=True, type=Path)
    p.add_argument('--system-wayland', action='store_true')
    args = p.parse_args()
    origin = args.gui_run.resolve()
    if not origin.is_relative_to((WORKSPACE / 'logs').resolve()):
        raise ValueError('GUI run must be in this workspace logs')
    state = json.loads((origin / 'state.json').read_text())
    remote = state['remote']
    if not re.fullmatch(r'/mnt/data/p011-browser/gui/[a-f0-9]{16}-[0-9]{8}-[0-9]{6}-[0-9]{6}', remote):
        raise ValueError('Invalid fixed GUI library path')
    manifest = json.loads((origin / 'manifest.json').read_text())
    expected = json.loads(args.expected_snapshot.read_text())
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d-%H%M%S-%f')
    out = WORKSPACE / 'logs' / ('BrowserP011-NativeEGL-' + stamp)
    out.mkdir()
    (out / 'native-child.py').write_text(CHILD, encoding='utf-8')
    print('LOG_DIR=' + str(out), flush=True)
    adb = Adb(args.transport, out)
    summary = {'scope': 'DEVICE_NATIVE_EGL_INIT_ONLY_NO_WINDOW_NO_QT_NO_WEBENGINE', 'filesystem_writes': False}
    try:
        before, _ = adb.python('before', SNAPSHOT)
        if anchor(before) != anchor(expected):
            raise ValueError('Current selected device identity differs')
        # Root is used only for this fixed trusted native initializer comparison;
        # neither a browser nor a window is started, and no page/URL exists.
        identities = [(0, 0)] if args.system_wayland else [(0, 0), (65534, 65534), (65534, 44)]
        libraries = [row for row in manifest['files'] if row['path'].startswith('lib/')]
        adb.python('verify-owned-library-identities', 'PAYLOAD=' + repr(remote + '/payload')
                   + '\nFILES=' + repr(libraries) + '\n' + LIB_VERIFY)
        source = ('PAYLOAD=' + repr(remote + '/payload')
                  + '\nIDENTITIES=' + repr(identities) + '\nPRIVATE=' + repr(not args.system_wayland)
                  + '\nCHILD=' + repr(CHILD) + '\n' + REMOTE)
        rows, _ = adb.python('native-egl-comparison', source, timeout=30)
        after, _ = adb.python('after', SNAPSHOT)
        summary.update(rows=rows, before=before, after=after,
                       stock_identity_unchanged=anchor(before) == anchor(after), completed=True)
    except Exception as exc:
        summary.update(completed=False, error=type(exc).__name__ + ': ' + str(exc))
        try:
            after, _ = adb.python('failure-after', SNAPSHOT)
            summary['after'] = after
            summary['stock_identity_unchanged'] = anchor(after) == anchor(expected)
        except Exception as failure:
            summary['failure_snapshot_error'] = type(failure).__name__
    finally:
        (out / 'result.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        target, checksum = archive(out)
        print(json.dumps({k: v for k, v in summary.items() if k not in ('before', 'after')}))
        print('RESULT_ZIP=' + str(target)); print('ZIP_SHA256=' + checksum)
    if not summary.get('completed'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
