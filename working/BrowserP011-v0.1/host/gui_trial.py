"""Finite, low-UID Qt 6 GUI / Wayland / GLES device trial.

Import and --prepare-only are HOST ONLY. Device actions always require an
explicit ADB transport and a previously selected current-device snapshot.
This probe does not contain Qt WebEngine and does not test webpages.
"""
from __future__ import annotations

import argparse
import ast
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import time
import zlib

from audit_device import Adb, SNAPSHOT, WORKSPACE, archive

AREA = "/mnt/data/p011-browser"
BINARY = "bin/p011-browser-gui-probe"
RESERVE = 128 * 1024 * 1024
CORE = ("Z03", "control_engine", "weston", "connmand", "bluetoothd", "ofonod", "adbd")
REMOTE_PATTERN = re.compile(re.escape(AREA) + r"/gui/[a-f0-9]{16}-[0-9]{8}-[0-9]{6}-[0-9]{6}\Z")


def anchor(snapshot):
    def ident(row):
        if not row:
            return None
        return {key: row[key] for key in ("pid", "ppid", "starttime", "exe", "comm")}
    rows = []
    for row in snapshot["processes"]:
        if row["comm"] in CORE:
            item = ident(row)
            item["parent"] = ident(row.get("parent"))
            rows.append(item)
    for name in ("Z03", "control_engine", "weston", "adbd"):
        if len([row for row in rows if row["comm"] == name]) != 1:
            raise ValueError("Expected exactly one current " + name)
    if not re.fullmatch(r"[a-f0-9-]{36}", snapshot["boot_id"]):
        raise ValueError("Missing boot identity")
    return {"boot_id": snapshot["boot_id"], "hashes": snapshot["hashes"],
            "processes": sorted(rows, key=lambda row: row["pid"])}


def source_manifest(payload):
    payload = payload.absolute()
    for path in reversed((payload,) + tuple(payload.parents)):
        check_plain(path, directory=True)
    files = []
    for directory, dirs, names in os.walk(payload, followlinks=False):
        dirs.sort()
        for name in dirs:
            check_plain(Path(directory) / name, directory=True)
        for name in sorted(names):
            path = Path(directory) / name
            info = check_plain(path)
            relative = path.relative_to(payload).as_posix()
            if not re.fullmatch(r"[A-Za-z0-9_.+@/-]+", relative) or any(
                    part in ("", ".", "..") or part.endswith(".") for part in relative.split("/")):
                raise ValueError("Unsafe payload path")
            if path.suffix.lower() in (".ttf", ".otf", ".woff", ".woff2"):
                raise ValueError("Bundled fonts are prohibited")
            value = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    value.update(chunk)
            after = check_plain(path)
            if (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Payload changed during hashing")
            files.append({"path": relative, "bytes": info.st_size, "sha256": value.hexdigest(),
                          "mode": 0o755 if relative == BINARY else 0o644})
    if not 2 <= len(files) <= 512 or BINARY not in {row["path"] for row in files}:
        raise ValueError("GUI payload lacks the exact executable or exceeds file bound")
    if not any(row["path"].startswith("lib/") for row in files):
        raise ValueError("GUI payload lacks private Qt libraries")
    files.sort(key=lambda row: row["path"])
    return {"schema": "p011.gui.payload.v1", "files": files,
            "bytes": sum(row["bytes"] for row in files)}


def check_plain(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Payload symlink/reparse point refused")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("Payload is not an ordinary file/directory")
    return info


def transfer_timeout(size):
    return min(180, max(30, 30 + (size + 1048575) // 1048576))


def remote_command(source):
    packed = base64.b64encode(zlib.compress(source.encode("utf-8"), 9)).decode("ascii")
    loader = "import base64,zlib;exec(zlib.decompress(base64.b64decode(%r)))" % packed
    command = "python3 -B -c " + shlex.quote(loader)
    if len(("(" + command + "); rc=$?; printf '\\n__REMOTE_EXIT__=%s\\n' \"$rc\"").encode()) >= 4096:
        raise ValueError("GUI remote command exceeds legacy ADB limit")
    return command


# One frozen snapshot implementation is embedded in the guardian and in the
# first-write gate. It reads only fixed stock files and process identities.
_snapshot_body = SNAPSHOT.replace("print('RESULT='+repr(result))", "return result")
DEVICE_COMMON = "import os,stat,ast,hashlib,time,signal,subprocess,socket,ctypes\n" + \
    "def snapshot():\n" + "\n".join(" " + line for line in _snapshot_body.splitlines()) + "\n" + r'''
CORE=('Z03','control_engine','weston','connmand','bluetoothd','ofonod','adbd')
def anchor(value):
 def ident(row):
  if not row:return None
  return {key:row[key] for key in ('pid','ppid','starttime','exe','comm')}
 rows=[]
 for row in value['processes']:
  if row['comm'] in CORE:
   item=ident(row);item['parent']=ident(row.get('parent'));rows.append(item)
 for name in ('Z03','control_engine','weston','adbd'):
  if len([r for r in rows if r['comm']==name])!=1:raise ValueError('Core identity missing')
 return {'boot_id':value['boot_id'],'hashes':value['hashes'],'processes':sorted(rows,key=lambda r:r['pid'])}
def regular(path,mode=None):
 s=os.lstat(path)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Unsafe control file')
 if mode is not None and stat.S_IMODE(s.st_mode)!=mode:raise ValueError('Control mode differs')
 return s
def directory(path):
 current=''
 for part in path.strip('/').split('/'):
  current+='/'+part;s=os.lstat(current)
  if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):raise ValueError('Redirected directory')
  if current.startswith('/mnt/data/p011-browser') and (s.st_uid!=0 or s.st_mode&0o022):raise ValueError('Unsafe control directory')
def read_literal(path):
 s=regular(path)
 if s.st_size>262144:raise ValueError('Control file too large')
 with open(path,'r') as f:return ast.literal_eval(f.read())
def new(path,body):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:f.write(body);f.flush();os.fsync(f.fileno())
def area():
 directory('/mnt/data/p011-browser')
 regular('/mnt/data/p011-browser/.area-owner',0o600)
 with open('/mnt/data/p011-browser/.area-owner','rb') as f:
  if f.read(128)!=b'p011.browser.area.v1\n':raise ValueError('Area owner differs')
'''

PREPARE = r'''
if os.geteuid()!=0:raise ValueError('Root control required')
if anchor(snapshot())!=EXPECTED:raise ValueError('Device identity changed before first write')
area()
space=os.statvfs('/mnt/data');free=space.f_bavail*space.f_frsize
if free<PAYLOAD_BYTES+134217728:raise ValueError('Insufficient space with reserve')
base='/mnt/data/p011-browser/gui'
if not os.path.lexists(base):os.mkdir(base,0o755)
directory(base)
if os.path.lexists(REMOTE):raise ValueError('New GUI run path exists; preserve it')
os.mkdir(REMOTE,0o755);os.mkdir(REMOTE+'/control',0o700);os.mkdir(REMOTE+'/payload',0o700)
print('RESULT='+repr({'remote':REMOTE,'free_bytes':free,'reserve_bytes':134217728}))
'''

UPLOAD_DIRS = r'''
area();directory(REMOTE);directory(REMOTE+'/payload')
for rel in DIRS:
 p=REMOTE+'/payload/'+rel
 if not os.path.lexists(p):os.mkdir(p,0o755)
 directory(p)
print('RESULT='+repr({'directories':len(DIRS)}))
'''

STAGING_VERIFY = r'''
area();directory(REMOTE);directory(REMOTE+'/control');directory(REMOTE+'/payload')
if set(os.listdir(REMOTE))!={'control','payload'} or set(os.listdir(REMOTE+'/control'))!={'config.literal','guardian.py'}:raise ValueError('Staging already used or contains launch records')
for p in [REMOTE+'/control',REMOTE+'/payload']:
 if stat.S_IMODE(os.lstat(p).st_mode)!=0o700:raise ValueError('Upload staging is no longer private')
def uploaded(p,binding):
 s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_size!=binding['bytes']:raise ValueError('Uploaded file type/owner/size differs')
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   b=f.read(262144)
   if not b:break
   h.update(b)
 if h.hexdigest()!=binding['sha256']:raise ValueError('Uploaded checksum differs')
for name,binding in CONTROL_BINDINGS.items():uploaded(REMOTE+'/control/'+name,binding)
with open(REMOTE+'/control/config.literal','r') as f:config=ast.literal_eval(f.read(262144))
if anchor(snapshot())!=config['expected']:raise ValueError('Device identity changed before staging mode repair')
found=[]
for base,dirs,names in os.walk(REMOTE+'/payload',followlinks=False):
 directory(base)
 for name in dirs:directory(base+'/'+name)
 found.extend(os.path.relpath(base+'/'+name,REMOTE+'/payload') for name in names)
if set(found)!={row['path'] for row in config['manifest']['files']}:raise ValueError('Staged payload file set differs')
for row in config['manifest']['files']:uploaded(REMOTE+'/payload/'+row['path'],row)
for row in config['manifest']['files']:os.chmod(REMOTE+'/payload/'+row['path'],row['mode'])
for name in CONTROL_BINDINGS:os.chmod(REMOTE+'/control/'+name,0o600);regular(REMOTE+'/control/'+name,0o600)
new(REMOTE+'/control/STAGING_VERIFIED.literal',repr(CONTROL_BINDINGS)+'\n')
print('RESULT='+repr({'upload_integrity_verified':True,'control_mode':0o600,'payload_still_private':True}))
'''

VERIFY_START = r'''
area();directory(REMOTE);directory(REMOTE+'/control');directory(REMOTE+'/payload')
if set(os.listdir(REMOTE))!={'control','payload'} or set(os.listdir(REMOTE+'/control'))!={'config.literal','guardian.py','STAGING_VERIFIED.literal'}:raise ValueError('Staging already launched or contains unknown controls')
if stat.S_IMODE(os.lstat(REMOTE+'/payload').st_mode)!=0o700:raise ValueError('Payload staging no longer private')
config=read_literal(REMOTE+'/control/config.literal');binding=read_literal(REMOTE+'/control/STAGING_VERIFIED.literal')
for name,item in binding.items():
 p=REMOTE+'/control/'+name;regular(p,0o600)
 with open(p,'rb') as f:
  if hashlib.sha256(f.read()).hexdigest()!=item['sha256']:raise ValueError('Verified control changed')
if anchor(snapshot())!=config['expected']:raise ValueError('Device identity changed before launch')
os.chmod(REMOTE+'/payload',0o755)
app=REMOTE+'/app';os.mkdir(app,0o700);os.chown(app,config['uid'],config['gid'])
for name in ['tmp','cache','config','data','runtime']:
 p=app+'/'+name;os.mkdir(p,0o700);os.chown(p,config['uid'],config['gid'])
stdout=os.open(REMOTE+'/control/guardian.stdout.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
stderr=os.open(REMOTE+'/control/guardian.stderr.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
 new(REMOTE+'/control/LAUNCH_REQUESTED','')
 p=subprocess.Popen(['/usr/bin/python3','-B',REMOTE+'/control/guardian.py',REMOTE],cwd='/',env={'PATH':'/usr/bin:/bin','LANG':'C','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,close_fds=True)
finally:os.close(stdout);os.close(stderr)
print('RESULT='+repr({'guardian_pid':p.pid,'remote':REMOTE,'requested':True}))
'''

GUARDIAN = DEVICE_COMMON + r'''
import sys
remote=sys.argv[1];area();directory(remote);directory(remote+'/control');directory(remote+'/payload')
control=remote+'/control';config=read_literal(control+'/config.literal')
binary=remote+'/payload/bin/p011-browser-gui-probe';uid=config['uid'];gid=config['gid']
def ident(pid):
 try:
  base='/proc/'+str(pid)
  with open(base+'/stat') as f:raw=f.read(8192)
  fields=raw[raw.rfind(')')+2:].split()
  return {'pid':int(pid),'parent':int(fields[1]),'group':int(fields[2]),'session':int(fields[3]),'start':fields[19],'exe':os.readlink(base+'/exe'),'uid':os.stat(base).st_uid}
 except (OSError,ValueError,IndexError):return None
def private():
 rows=[]
 for n in os.listdir('/proc'):
  if n.isdigit():
   row=ident(int(n))
   if row and row['exe'].startswith(remote+'/payload/'):rows.append(row)
 return rows
tracked={};leader=None
def track():
 rows=private()
 for unused in range(4):
  for row in rows:
   key=(row['pid'],row['start'],row['exe'],row['uid'])
   if row['exe']!=binary or row['uid']!=uid:continue
   linked=leader and (row['pid']==leader['pid'] and row['start']==leader['start'] or row['group']==leader['pid'] and row['session']==leader['pid'])
   if not linked:
    for known in list(tracked.values()):
     parent=ident(known['pid'])
     if row['parent']==known['pid'] and parent and (parent['start'],parent['exe'],parent['uid'])==(known['start'],known['exe'],known['uid']):linked=True;break
   if linked:tracked[key]=row
 return rows
def stop_owned(signum):
 sent=[]
 for key,row in list(tracked.items()):
  current=ident(row['pid'])
  if not current:continue
  if (current['pid'],current['start'],current['exe'],current['uid'])!=key:raise ValueError('PID identity changed; refuse signal')
  try:os.kill(current['pid'],signum);sent.append(current['pid'])
  except OSError as e:
   if e.errno!=3:raise
 return sent
def low():
 class Limit(ctypes.Structure):_fields_=[('cur',ctypes.c_ulong),('max',ctypes.c_ulong)]
 libc=ctypes.CDLL(None,use_errno=True)
 for resource,value in [(4,0),(1,16777216)]:
  limit=Limit(value,value)
  if libc.setrlimit(resource,ctypes.byref(limit))!=0:raise OSError(ctypes.get_errno(),'setrlimit')
 os.setgroups([]);os.setgid(gid);os.setuid(uid)
result={'schema':'p011.gui.device.v1','scope':'DEVICE_QT_GUI_WAYLAND_GLES_ONLY','physical_display_verified':False,'webengine_tested':False,'cleanup_verified':False,'complete':False,'deadline_seconds':10,'uid':uid,'gid':gid}
child=None;wayland=None;appout=None;apperr=None
try:
 if anchor(snapshot())!=config['expected']:raise ValueError('Stock identity differs at guardian start')
 if private():raise ValueError('Unexpected existing private process')
 app=remote+'/app'
 for p in [app]+[app+'/'+x for x in ['tmp','cache','config','data','runtime']]:
  s=os.lstat(p)
  if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=uid or s.st_gid!=gid or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('Private app directory differs')
 wayland=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);wayland.settimeout(2);wayland.connect('/run/user/0/wayland-0');wayland.settimeout(None)
 env={'PATH':'/usr/bin:/bin','LANG':'C','HOME':app,'TMPDIR':app+'/tmp','XDG_CACHE_HOME':app+'/cache','XDG_CONFIG_HOME':app+'/config','XDG_DATA_HOME':app+'/data','XDG_RUNTIME_DIR':app+'/runtime','WAYLAND_SOCKET':str(wayland.fileno()),'QT_QPA_PLATFORM':'wayland','QT_WAYLAND_SHELL_INTEGRATION':'wl-shell','LD_LIBRARY_PATH':remote+'/payload/lib','QT_PLUGIN_PATH':remote+'/payload/plugins','PYTHONDONTWRITEBYTECODE':'1'}
 appout=os.open(control+'/app.stdout.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);apperr=os.open(control+'/app.stderr.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 started=time.monotonic()
 child=subprocess.Popen([binary],cwd='/',env=env,stdin=subprocess.DEVNULL,stdout=appout,stderr=apperr,close_fds=True,pass_fds=(wayland.fileno(),),start_new_session=True,preexec_fn=low)
 wayland.close();wayland=None
 leader=ident(child.pid)
 if not leader or leader['exe']!=binary or leader['uid']!=uid or leader['group']!=child.pid or leader['session']!=child.pid:raise ValueError('GUI leader identity not established')
 result['leader']=leader;new(control+'/child.literal',repr(leader)+'\n');timed_out=False
 while child.poll() is None:
  track()
  if time.monotonic()-started>=10:timed_out=True;break
  time.sleep(0.1)
 result['timed_out']=timed_out
 track()
 for signum,wait in [(signal.SIGTERM,2),(signal.SIGKILL,2)]:
  if not private():break
  sent=stop_owned(signum);result.setdefault('signals',[]).append({'signal':signum,'pids':sent})
  until=time.monotonic()+wait
  while time.monotonic()<until:
   child.poll();track()
   if not private():break
   time.sleep(0.1)
 result['child_exit']=child.poll();result['elapsed_seconds']=round(time.monotonic()-started,3)
 result['remaining_private_processes']=private();result['cleanup_verified']=not result['remaining_private_processes'] and child.poll() is not None
except BaseException as exc:
 result['error']=type(exc).__name__+': '+str(exc)
 if child is not None and leader is not None:
  try:
   track();stop_owned(signal.SIGTERM);until=time.monotonic()+2
   while child.poll() is None and time.monotonic()<until:track();time.sleep(0.1)
   track();stop_owned(signal.SIGKILL);until=time.monotonic()+2
   while child.poll() is None and time.monotonic()<until:time.sleep(0.1)
  except BaseException as cleanup:result['cleanup_error']=type(cleanup).__name__+': '+str(cleanup)
 if child is not None:result['child_exit']=child.poll()
 result['remaining_private_processes']=private();result['cleanup_verified']=not result['remaining_private_processes'] and (child is None or child.poll() is not None)
finally:
 if wayland is not None:wayland.close()
 for fd in [appout,apperr]:
  if fd is not None:os.close(fd)
 try:
  result['after']=snapshot();result['stock_identity_unchanged']=anchor(result['after'])==config['expected']
 except BaseException as exc:result['snapshot_error']=type(exc).__name__+': '+str(exc);result['stock_identity_unchanged']=False
 result['lifecycle_passed']=result.get('child_exit')==0 and not result.get('timed_out',False) and not result.get('error') and result['cleanup_verified'] and result['stock_identity_unchanged']
 result['complete']=True;new(control+'/result.literal',repr(result)+'\n');new(control+'/COMPLETE','')
'''

COLLECT_STATUS = r'''
area();directory(REMOTE);directory(REMOTE+'/control')
control=REMOTE+'/control';names=['guardian.stdout.raw','guardian.stderr.raw','app.stdout.raw','app.stderr.raw','child.literal','result.literal','COMPLETE']
available=[];evidence={}
for name in names:
 p=control+'/'+name
 if os.path.lexists(p):
  s=regular(p)
  if s.st_size>33554432:raise ValueError('Evidence file exceeds bound')
  h=hashlib.sha256()
  with open(p,'rb') as f:
   while True:
    b=f.read(65536)
    if not b:break
    h.update(b)
  evidence[name]={'bytes':s.st_size,'sha256':h.hexdigest()}
  available.append(name)
print('RESULT='+repr({'available':available,'evidence':evidence,'complete':'COMPLETE' in available}))
'''


def page_free_gui_events(stdout):
    expected = ["browser685.qt_gui", "browser685.qt_gles", "browser685.qt_gui_done"]
    rows, nonstructured, other_structured = [], 0, 0
    for line in stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            nonstructured += 1
            continue
        if isinstance(row, dict) and row.get("event") in expected:
            rows.append(row)
        else:
            other_structured += 1
    metadata = {"events": rows, "nonstructured_line_count": nonstructured,
                "other_structured_line_count": other_structured}
    if len(rows) != 3 or [row.get("event") for row in rows] != expected:
        return dict(metadata, passed=False, reason="Unexpected fixed GUI event sequence")
    gui, gl, done = rows
    passed = (gui.get("qt_version") == "6.8.5" and gui.get("platform") == "wayland"
              and gui.get("surface_exposed") is True and gl.get("context_created") is True
              and gl.get("make_current") is True and gl.get("gl_error") == 0
              and gl.get("swap_called") is True and done.get("rendered") is True
              and done.get("expose_attempted") is True)
    return dict(metadata, passed=passed, application_gl_frame_reported=passed,
                swap_called=gl.get("swap_called") is True, swap_success_verified=False,
                physical_display_verified=False, webengine_tested=False)


def collect(adb, state, wait_seconds):
    remote = state["remote"]
    if not REMOTE_PATTERN.fullmatch(remote):
        raise ValueError("Unexpected GUI remote path")
    deadline = time.monotonic() + wait_seconds
    while True:
        status, _ = adb.python("gui-status", "REMOTE=" + repr(remote) + "\n" + DEVICE_COMMON + COLLECT_STATUS)
        if status["complete"] or time.monotonic() >= deadline:
            break
        time.sleep(1)
    for name in status["available"]:
        adb.run("collect-" + name.replace(".", "-"), ["pull", remote + "/control/" + name,
                                                     str(adb.out / ("device-" + name))])
        local = adb.out / ("device-" + name)
        bound = status["evidence"][name]
        if local.stat().st_size != bound["bytes"] or hashlib.sha256(local.read_bytes()).hexdigest() != bound["sha256"]:
            raise ValueError("Collected GUI evidence size/checksum differs: " + name)
    (adb.out / "evidence-bindings.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    after, _ = adb.python("after", SNAPSHOT)
    (adb.out / "after.json").write_text(json.dumps(after, indent=2), encoding="utf-8")
    unchanged = anchor(after) == state["expected"]
    result_path = adb.out / "device-result.literal"
    device = ast.literal_eval(result_path.read_text(encoding="utf-8")) if result_path.is_file() else None
    stdout = adb.out / "device-app.stdout.raw"
    events = page_free_gui_events(stdout.read_bytes()) if stdout.is_file() else {"passed": False, "reason": "No application stdout"}
    summary = {"scope": "DEVICE_QT_GUI_WAYLAND_GLES_ONLY", "remote": remote, "transport": state["transport"],
            "manifest_sha256": state["manifest_sha256"], "complete": status["complete"],
            "stock_identity_unchanged": unchanged, "device": device, "gui_events": events,
            "physical_display_verified": False, "webengine_tested": False,
            "passed": bool(status["complete"] and device and device.get("lifecycle_passed")
                           and unchanged and events.get("passed")), "candidate_retained": True}
    for key in ("origin_log", "resume_upload", "origin_transport"):
        if key in state:
            summary[key] = state[key]
    return summary


def bind_collect_target(state, transport, current):
    if transport < 1 or anchor(current) != state["expected"]:
        raise ValueError("Collect target boot/files/core identities differ from recorded device")
    selected = dict(state)
    selected.setdefault("origin_transport", state["transport"])
    selected["transport"] = transport
    return selected


def control_bindings(out):
    return {name: {"bytes": (out / name).stat().st_size,
                   "sha256": hashlib.sha256((out / name).read_bytes()).hexdigest()}
            for name in ("guardian.py", "config.literal")}


def load_resume_upload(saved, payload, expected, transport, out, uid, gid):
    if not (1 <= uid <= 65534 and 1 <= gid <= 65534):
        raise ValueError("Resume GUI user/group must remain non-root")
    saved = saved.resolve()
    if not saved.is_relative_to((WORKSPACE / "logs").resolve()):
        raise ValueError("Resume origin must be in workspace logs")
    state = json.loads((saved / "state.json").read_text(encoding="utf-8"))
    if state.get("schema") != "p011.gui.host.v1" or not REMOTE_PATTERN.fullmatch(state["remote"]):
        raise ValueError("Unexpected resume origin state")
    if state["expected"] != anchor(expected) or state["uid"] != uid or state["gid"] != gid:
        raise ValueError("Resume device baseline or low user differs from origin")
    manifest = source_manifest(payload)
    original = json.loads((saved / "manifest.json").read_text(encoding="utf-8"))
    checksum = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    if manifest != original or checksum != state["manifest_sha256"]:
        raise ValueError("Resume host payload differs from original upload")
    guardian = (saved / "guardian.py").read_bytes()
    config_bytes = (saved / "config.literal").read_bytes()
    config = ast.literal_eval(config_bytes.decode("utf-8"))
    if guardian != GUARDIAN.encode("utf-8"):
        raise ValueError("Resume guardian differs from reviewed exact source")
    if (config["manifest"] != manifest or config["expected"] != state["expected"]
            or config["uid"] != uid or config["gid"] != gid
            or config["controls"] != {"guardian.py": hashlib.sha256(guardian).hexdigest()}):
        raise ValueError("Resume original config binding differs")
    (out / "guardian.py").write_bytes(guardian)
    (out / "config.literal").write_bytes(config_bytes)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    state = dict(state, origin_log=str(saved), resume_upload=True,
                 origin_transport=state.get("origin_transport", state["transport"]), transport=transport)
    (out / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    remote_command("REMOTE=" + repr(state["remote"]) + "\nCONTROL_BINDINGS=" + repr(control_bindings(out))
                   + "\n" + DEVICE_COMMON + STAGING_VERIFY)
    return manifest, state


def prepare_only(source, out, expected, transport, uid=65534, gid=65534):
    if not (1 <= uid <= 65534 and 1 <= gid <= 65534):
        raise ValueError("GUI user/group must be non-root numeric IDs")
    manifest = source_manifest(source)
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    checksum = hashlib.sha256(body).hexdigest()
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S-%f")
    remote = AREA + "/gui/" + checksum[:16] + "-" + stamp
    frozen = anchor(expected)
    controls = {"guardian.py": hashlib.sha256(GUARDIAN.encode("utf-8")).hexdigest()}
    config = {"schema": "p011.gui.config.v1", "expected": frozen, "manifest": manifest,
              "uid": uid, "gid": gid, "controls": controls}
    state = {"schema": "p011.gui.host.v1", "remote": remote, "transport": transport,
             "manifest_sha256": checksum, "expected": frozen, "uid": uid, "gid": gid}
    (out / "guardian.py").write_text(GUARDIAN, encoding="utf-8", newline="\n")
    (out / "config.literal").write_text(repr(config) + "\n", encoding="utf-8", newline="\n")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    # Exercise actual compression and shell escaping before any ADB mutation.
    for snippet in (DEVICE_COMMON + "REMOTE=" + repr(remote) + "\nEXPECTED=" + repr(frozen)
                    + "\nPAYLOAD_BYTES=" + repr(manifest["bytes"]) + "\n" + PREPARE,
                    "REMOTE=" + repr(remote) + "\nCONTROL_BINDINGS=" + repr(control_bindings(out))
                    + "\n" + DEVICE_COMMON + STAGING_VERIFY,
                    "REMOTE=" + repr(remote) + "\n" + DEVICE_COMMON + VERIFY_START,
                    "REMOTE=" + repr(remote) + "\n" + DEVICE_COMMON + COLLECT_STATUS):
        remote_command(snippet)
    return manifest, state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", required=True, type=int)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--payload", type=Path)
    group.add_argument("--collect", type=Path, help="Prior GUI run log directory containing state.json")
    parser.add_argument("--resume-upload", type=Path, help="Explicit prior unlaunched root-0700 GUI upload log")
    parser.add_argument("--expected-snapshot", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--uid", type=int, default=65534)
    parser.add_argument("--gid", type=int, default=65534)
    args = parser.parse_args()
    if args.transport < 1:
        parser.error("An explicit positive transport is required")
    if args.resume_upload and (not args.payload or args.prepare_only):
        parser.error("--resume-upload requires --payload, --expected-snapshot and an actual trial")
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S-%f")
    out = WORKSPACE / "logs" / ("BrowserP011-GUI-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    print("LOG_DIR=" + str(out), flush=True)
    summary = {"scope": "HOST_ONLY_PREPARE" if args.prepare_only else "DEVICE_QT_GUI_WAYLAND_GLES_ONLY", "passed": False}
    adb = None
    state = None
    try:
        if args.collect:
            if args.prepare_only:
                raise ValueError("--collect cannot use --prepare-only")
            saved = args.collect.resolve()
            if not saved.is_relative_to((WORKSPACE / "logs").resolve()):
                raise ValueError("Collect state must be in this workspace logs directory")
            state = json.loads((saved / "state.json").read_text(encoding="utf-8"))
            (out / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
            adb = Adb(args.transport, out)
            current, _ = adb.python("collect-current-device", SNAPSHOT)
            (out / "collect-before.json").write_text(json.dumps(current, indent=2), encoding="utf-8")
            state = bind_collect_target(state, args.transport, current)
            (out / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
            summary = collect(adb, state, 20)
        else:
            if not args.expected_snapshot:
                raise ValueError("--expected-snapshot is required for a new GUI trial")
            expected = json.loads(args.expected_snapshot.read_text(encoding="utf-8"))
            if args.resume_upload:
                manifest, state = load_resume_upload(args.resume_upload, args.payload, expected,
                                                    args.transport, out, args.uid, args.gid)
            else:
                manifest, state = prepare_only(args.payload, out, expected, args.transport, args.uid, args.gid)
            if args.prepare_only:
                summary.update(passed=True, remote_planned=state["remote"], payload_bytes=manifest["bytes"],
                               manifest_sha256=state["manifest_sha256"], device_tested=False)
            else:
                adb = Adb(args.transport, out)
                before, _ = adb.python("before", SNAPSHOT)
                (out / "before.json").write_text(json.dumps(before, indent=2), encoding="utf-8")
                if anchor(before) != state["expected"]:
                    raise ValueError("Current boot/files/core identities differ from selected snapshot")
                if any(row["exe"].startswith(AREA + "/") for row in before["processes"]):
                    raise ValueError("Another browser trial process exists; no automatic takeover")
                remote = state["remote"]
                if not args.resume_upload:
                    adb.python("gui-prepare", DEVICE_COMMON + "REMOTE=" + repr(remote) + "\nEXPECTED="
                               + repr(state["expected"]) + "\nPAYLOAD_BYTES=" + repr(manifest["bytes"]) + "\n" + PREPARE)
                    dirs = sorted({str(Path(row["path"]).parent).replace("\\", "/") for row in manifest["files"]
                                   if "/" in row["path"]}, key=lambda item: (item.count("/"), item))
                    all_dirs = set()
                    for rel in dirs:
                        parts = rel.split("/")
                        all_dirs.update("/".join(parts[:n]) for n in range(1, len(parts) + 1))
                    dirs = sorted(all_dirs, key=lambda item: (item.count("/"), item))
                    # Keep directory batches below the legacy command limit.
                    for offset in range(0, len(dirs), 40):
                        adb.python("gui-dirs", "REMOTE=" + repr(remote) + "\nDIRS=" + repr(dirs[offset:offset + 40])
                                   + "\n" + DEVICE_COMMON + UPLOAD_DIRS)
                    for row in manifest["files"]:
                        adb.run("push-" + row["path"].replace("/", "-"), ["push", str(args.payload / row["path"]),
                                remote + "/payload/" + row["path"]], timeout=transfer_timeout(row["bytes"]))
                    for name in ("guardian.py", "config.literal"):
                        adb.run("push-" + name, ["push", str(out / name), remote + "/control/" + name])
                adb.python("gui-verify-upload", "REMOTE=" + repr(remote) + "\nCONTROL_BINDINGS="
                           + repr(control_bindings(out)) + "\n" + DEVICE_COMMON + STAGING_VERIFY)
                adb.python("gui-verify-start", "REMOTE=" + repr(remote) + "\n" + DEVICE_COMMON + VERIFY_START)
                summary = collect(adb, state, 25)
    except BaseException as exc:
        summary.update(error=type(exc).__name__ + ": " + str(exc), passed=False)
        if adb is not None:
            try:
                final, _ = adb.python("failure-after", SNAPSHOT)
                (out / "failure-after.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
                summary["stock_identity_unchanged"] = bool(state and anchor(final) == state["expected"])
            except BaseException as followup:
                summary["failure_snapshot_error"] = type(followup).__name__ + ": " + str(followup)
        if isinstance(exc, KeyboardInterrupt):
            summary["interrupted"] = True
    finally:
        (out / "result.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        target, checksum = archive(out)
        print(json.dumps(summary, ensure_ascii=False))
        print("RESULT_ZIP=" + str(target))
        print("ZIP_SHA256=" + checksum)
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
