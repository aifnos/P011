"""Transport-pinned, isolated P011 browser trial. Never edits factory paths.

No device access occurs on import, during --prepare-only, or in host tests.
The runtime guardian owns browser signalling; this controller only writes its
own empty STOP request and gathers immutable session evidence.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import struct
import sys
import time
import uuid
import zlib

from audit_device import Adb, SNAPSHOT, WORKSPACE, archive

AREA = "/mnt/data/p011-browser"
AREA_MARKER = "p011.browser.area.v1\n"
RESERVE_BYTES = 128 * 1024 * 1024
SESSION_PATTERN = re.compile(r"\A[0-9]{8}-[0-9]{6}-[a-f0-9]{8}\Z")
CANDIDATE_PATTERN = re.compile(r"\Abrowser-685-[a-f0-9]{16}\Z")
REQUIRED_FILES = {
    "bin/p011-browser-probe", "libexec/QtWebEngineProcess",
    "runtime/supervisor.py", "runtime/guardian.py", "runtime/safety.py",
    "runtime/snapshot.py", "runtime/p011_json.py",
    "plugins/platforms/libqwayland-generic.so",
    "plugins/wayland-shell-integration/libwl-shell-plugin.so",
    "plugins/wayland-graphics-integration-client/libqt-plugin-wayland-egl.so",
    "resources/qtwebengine_resources.pak", "resources/qtwebengine_resources_100p.pak",
    "resources/qtwebengine_resources_200p.pak",
    "translations/qtwebengine_locales/en-US.pak",
}
REQUIRED_QT_LIBRARIES = ("Core", "Gui", "Network", "Qml", "Quick", "WebEngineCore",
                         "WebEngineQuick", "WaylandClient")
REQUIRED_QML_MODULES = ("QML", "QtQml", "QtQuick", "QtQuick.Window", "QtWebEngine")
STOCK_PATHS = ("/usr/bin/Z03", "/usr/bin/control_engine", "/usr/bin/zyb_z03_launch.sh")
RESERVED_NAMES = {".candidate-manifest.py", ".candidate-complete", ".manifest-upload.py"}
PUBLIC_SITES = {"baidu": "https://www.baidu.com/", "bilibili": "https://www.bilibili.com/"}


def validate_mode(public_site=None, public_no_sandbox=False, offline_no_sandbox=False):
    if not isinstance(public_no_sandbox, bool) or not isinstance(offline_no_sandbox, bool):
        raise ValueError("Trial sandbox modes must be explicit booleans")
    if public_site is not None and public_site not in PUBLIC_SITES:
        raise ValueError("Only the fixed baidu and bilibili public sites are supported")
    if (public_site is not None) != public_no_sandbox:
        raise ValueError("--public-site and --public-no-sandbox must be supplied together")
    if offline_no_sandbox and public_no_sandbox:
        raise ValueError("Offline fixture and public-site experiments are mutually exclusive")
    return {"public_site": public_site, "public_no_sandbox": public_no_sandbox,
            "offline_no_sandbox": offline_no_sandbox}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise ValueError("Unsafe payload relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") or not re.fullmatch(r"[A-Za-z0-9_.+@-]+", part)
           or part.endswith((".", " ")) for part in parts):
        raise ValueError("Unsafe payload relative path")
    if PurePosixPath(value).is_absolute() or parts[0] in RESERVED_NAMES:
        raise ValueError("Reserved or absolute payload path")
    return value


def no_link(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Payload symlinks and reparse points must be flattened before review")
    return info


def validate_runtime_layout(payload: Path, files: list[dict]):
    """Check the paths consumed by the fixed runtime environment before ADB.

    This validates the deployed layout, not ELF ABI or Qt/QML execution. The
    separate cross-build audit must still verify the actual binary closure.
    """
    sizes = {row["path"]: row["size"] for row in files}
    required = REQUIRED_FILES | {"lib/libQt6" + module + ".so.6" for module in REQUIRED_QT_LIBRARIES}
    missing = sorted(path for path in required if sizes.get(path, 0) <= 0)
    if missing:
        raise ValueError("Payload lacks nonempty runtime artifacts: " + ", ".join(missing))
    # A copied top-level QtWebEngine module is insufficient: QtQuick imports
    # QtQml, whose own imports need Models and WorkerScript. Follow the actual
    # installed qmldir declarations instead of guessing a fixed transitive set.
    pending, visited = list(REQUIRED_QML_MODULES), set()
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", module):
            raise ValueError("Invalid QML module name")
        directory = "qml/" + module.replace(".", "/")
        descriptor = directory + "/qmldir"
        if sizes.get(descriptor, 0) <= 0:
            raise ValueError("Payload lacks QML module descriptor: " + descriptor)
        if sizes[descriptor] > 1024 * 1024:
            raise ValueError("QML module descriptor exceeds size budget")
        declared = None
        for line in payload.joinpath(*descriptor.split("/")).read_text(encoding="utf-8-sig").splitlines():
            fields = line.split("#", 1)[0].split()
            if not fields:
                continue
            optional = fields[0] == "optional"
            if optional:
                fields = fields[1:]
            if not fields:
                continue
            if fields[0] == "module":
                if len(fields) != 2 or declared is not None:
                    raise ValueError("Ambiguous QML module declaration: " + descriptor)
                declared = fields[1]
            elif fields[0] == "plugin":
                if len(fields) not in (2, 3) or not re.fullmatch(r"[A-Za-z0-9_+-]+", fields[1]):
                    raise ValueError("Unsupported QML plugin declaration: " + descriptor)
                subpath = "" if len(fields) == 2 else safe_relative(fields[2]) + "/"
                plugin = directory + "/" + subpath + "lib" + fields[1] + ".so"
                if sizes.get(plugin, 0) <= 0:
                    raise ValueError("Payload lacks declared QML plugin: " + plugin)
            elif fields[0] in ("import", "depends"):
                if len(fields) < 2:
                    raise ValueError("Invalid QML import declaration: " + descriptor)
                dependency = fields[1]
                # Optional imports genuinely may be absent in a minimal build.
                if optional and "qml/" + dependency.replace(".", "/") + "/qmldir" not in sizes:
                    continue
                pending.append(dependency)
        if declared != module:
            raise ValueError("QML module identity differs: " + descriptor)
        visited.add(module)
    return {"required_artifacts": len(required), "qml_modules": sorted(visited),
            "scope": "HOST_ONLY_LAYOUT_NO_ELF_OR_QML_EXECUTION"}


def source_manifest(payload: Path) -> dict:
    # Resolve only after checking each supplied ancestor, so a reparse point is
    # never silently converted into an apparently ordinary payload directory.
    payload = payload.absolute()
    for path in reversed((payload,) + tuple(payload.parents)):
        no_link(path)
    if not payload.is_dir():
        raise ValueError("Payload is not a directory")
    files = []
    for directory, dirs, names in os.walk(payload, followlinks=False):
        dirs.sort()
        for name in dirs:
            folder = Path(directory) / name
            no_link(folder)
            safe_relative(folder.relative_to(payload).as_posix())
        for name in sorted(names):
            path = Path(directory) / name
            before = no_link(path)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Payload contains a non-regular file")
            relative = safe_relative(path.relative_to(payload).as_posix())
            checksum = digest(path)
            after = no_link(path)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Payload changed while hashing")
            mode = 0o755 if relative.startswith(("bin/", "libexec/")) else 0o644
            files.append({"path": relative, "size": before.st_size, "sha256": checksum, "mode": mode})
    files.sort(key=lambda row: row["path"])
    if not 1 <= len(files) <= 20000:
        raise ValueError("Payload file-count limit exceeded")
    validate_runtime_layout(payload, files)
    return {"schema": "p011.browser.payload.v1", "files": files,
            "total_bytes": sum(row["size"] for row in files)}


def manifest_identity(manifest: dict) -> tuple[str, str]:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    checksum = hashlib.sha256(canonical).hexdigest()
    return "browser-685-" + checksum[:16], checksum


def space_budget(bundle_bytes: int, available_bytes: int) -> dict:
    if (isinstance(bundle_bytes, bool) or isinstance(available_bytes, bool)
            or not isinstance(bundle_bytes, int) or not isinstance(available_bytes, int)
            or bundle_bytes < 0 or available_bytes < 0):
        raise ValueError("Invalid space budget")
    required = bundle_bytes + RESERVE_BYTES
    return {"bundle_bytes": bundle_bytes, "available_bytes": available_bytes,
            "reserve_bytes": RESERVE_BYTES, "required_bytes": required,
            "passed": available_bytes >= required}


def transfer_timeout(file_bytes: int) -> int:
    if isinstance(file_bytes, bool) or not isinstance(file_bytes, int) or file_bytes < 0:
        raise ValueError("Invalid payload transfer size")
    # Legacy USB can spend more than 30 seconds on WebEngineCore alone. This
    # budget applies only to payload bytes, never status or device snippets.
    return min(180, max(30, 30 + (file_bytes + 1024 * 1024 - 1) // (1024 * 1024)))


def validate_baseline(value: dict) -> dict:
    # The current three stock hashes are frozen as evidence. No archived Z03
    # hash or firmware version is accepted as an implicit current-device pin.
    if not isinstance(value, dict) or value.get("schema") != "p011.browser.baseline.v1":
        raise ValueError("Unexpected current-device baseline")
    if not re.fullmatch(r"[a-f0-9-]{36}", value.get("boot_id", "")):
        raise ValueError("Missing boot identity")
    hashes = value.get("hashes")
    if not isinstance(hashes, dict) or set(hashes) != set(STOCK_PATHS):
        raise ValueError("Incomplete current stock hashes")
    if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in hashes.values()):
        raise ValueError("Invalid current stock hash")
    rows = value.get("processes")
    if not isinstance(rows, list):
        raise ValueError("Missing stock process identities")
    for name in ("Z03", "control_engine", "weston"):
        matching = [row for row in rows if row.get("name") == name]
        if len(matching) != 1:
            raise ValueError("Ambiguous current stock process")
        row = matching[0]
        if not isinstance(row.get("pid"), int) or row["pid"] <= 0 or not re.fullmatch(r"[0-9]+", str(row.get("starttime", ""))):
            raise ValueError("Missing stock PID/starttime")
        if name in ("Z03", "control_engine"):
            if row.get("exe") != "/usr/bin/" + name or not isinstance(row.get("parent_identity"), dict):
                raise ValueError("Missing exact factory process ancestry")
    return value


def normalize_preflight(value: dict) -> dict:
    def identity(row):
        parent = row.get("parent")
        parent_pid = row.get("ppid") if isinstance(parent, dict) or parent is None else parent
        return {"pid": row.get("pid"), "name": row.get("name", row.get("comm")),
                "parent": parent_pid, "starttime": str(row.get("starttime", "")), "exe": row.get("exe")}
    if not isinstance(value, dict) or value.get("schema") not in ("p011.browser.readonly.v1", "p011.browser.baseline.v1"):
        raise ValueError("Unexpected expected/prewrite snapshot schema")
    rows = []
    for source in value.get("processes", []):
        row = identity(source)
        if row["name"] not in ("Z03", "control_engine", "weston", "connmand", "bluetoothd"):
            continue
        if row["name"] in ("Z03", "control_engine"):
            parent = source.get("parent_identity", source.get("parent"))
            if not isinstance(parent, dict):
                raise ValueError("Expected snapshot lacks exact stock parent identity")
            row["parent_identity"] = identity(parent)
        rows.append(row)
    return validate_baseline({"schema": "p011.browser.baseline.v1", "boot_id": value.get("boot_id"),
                              "hashes": value.get("hashes"), "processes": sorted(rows, key=lambda row: row["pid"])})


def read_expected_snapshot(path: Path) -> dict:
    if path.is_dir():
        path = path / "snapshot.json"
    raw = path.read_text(encoding="utf-8-sig")
    try:
        value = json.loads(raw)
    except ValueError:
        value = ast.literal_eval(raw)
    return normalize_preflight(value)


def remote_names(candidate: str, session: str) -> tuple[str, str]:
    if not CANDIDATE_PATTERN.fullmatch(candidate) or not SESSION_PATTERN.fullmatch(session):
        raise ValueError("Invalid candidate or session identity")
    return AREA + "/candidates/" + candidate, AREA + "/sessions/" + session


# Device snippets use only Python 3.5 stdlib and Python literals. This device's
# stdlib json is unavailable. Every snippet is run through Adb.python raw logs.
REMOTE_COMMON = r'''
import os,stat,ast,hashlib
os.umask(0o077)
AREA='/mnt/data/p011-browser'
MARKER='p011.browser.area.v1\n'
def regular(path,maximum=10485760,private=True):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or (private and info.st_mode&0o022) or info.st_size>maximum:raise ValueError('Unsafe control file')
 return info
def directory(path,private=True):
 if os.path.normpath(path)!=path or not (path==AREA or path.startswith(AREA+'/')):raise ValueError('Outside area')
 current=''
 for part in path.strip('/').split('/'):
  current+='/'+part; info=os.lstat(current)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):raise ValueError('Redirected directory')
  if (current==AREA or current.startswith(AREA+'/')) and private and (info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o755):raise ValueError('Area ownership or directory mode differs')
 if os.path.realpath(path)!=path:raise ValueError('Canonical directory differs')
def newfile(path,raw,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def literal(path):
 regular(path)
 with open(path,'r',encoding='utf-8') as f:return ast.literal_eval(f.read(10485761))
def sha(path):
 value=hashlib.sha256()
 with open(path,'rb') as f:
  while True:
   data=f.read(262144)
   if not data:break
   value.update(data)
 return value.hexdigest()
def area():
 if os.geteuid()!=0:raise ValueError('Root control required; browser itself remains low privilege')
 directory(AREA)
 regular(AREA+'/.area-owner',4096)
 with open(AREA+'/.area-owner','r') as f:
  if f.read()!=MARKER:raise ValueError('Area marker differs')
'''

REMOTE_PREPARE = r'''
if os.geteuid()!=0:raise ValueError('Root control required')
before=CONFIG['prewrite_baseline']
with open('/proc/sys/kernel/random/boot_id','r') as f:boot=f.read(64).strip()
if boot!=before['boot_id'] or any(sha(path)!=checksum for path,checksum in before['hashes'].items()):raise ValueError('Prewrite boot or stock hashes differ from selected device')
def current_identity(pid):
 with open('/proc/'+str(pid)+'/stat','r') as f:raw=f.read(8192)
 fields=raw[raw.rindex(')')+2:].split()
 return {'pid':pid,'name':raw[raw.index('(')+1:raw.rindex(')')],'parent':int(fields[1]),'starttime':fields[19],'exe':os.readlink('/proc/'+str(pid)+'/exe')}
for source in before['processes']:
 current=current_identity(source['pid']);expected=dict(source);parent=expected.pop('parent_identity',None)
 if current!=expected:raise ValueError('Prewrite process PID/starttime differs')
 if parent is not None and current_identity(parent['pid'])!=parent:raise ValueError('Prewrite parent identity differs')
for parent in ('/mnt','/mnt/data'):
 info=os.lstat(parent)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):raise ValueError('Redirected mount path')
if not os.path.lexists(AREA):
 os.mkdir(AREA,0o755);os.chmod(AREA,0o755);newfile(AREA+'/.area-owner',MARKER.encode('ascii'))
area()
for name in ('candidates','sessions'):
 path=AREA+'/'+name
 if not os.path.lexists(path):os.mkdir(path,0o755);os.chmod(path,0o755)
 directory(path)
available=os.statvfs(AREA).f_bavail*os.statvfs(AREA).f_frsize
candidate=CONFIG['candidate']
existing=os.path.lexists(candidate)
required=128*1024*1024 if existing else CONFIG['required_bytes']
if available<required:raise ValueError('Insufficient free space including 128MiB reserve')
if existing:
 directory(candidate)
 regular(candidate+'/.candidate-complete',0)
 stored=literal(candidate+'/.candidate-manifest.py')
 if stored.get('sha256')!=CONFIG['manifest_sha256']:raise ValueError('Existing candidate identity conflicts')
else:os.mkdir(candidate,0o700);os.chmod(candidate,0o700)
print('RESULT='+repr({'candidate_existing':existing,'available_bytes':available,'required_bytes':required}))
'''

REMOTE_VERIFY = r'''
area();candidate=CONFIG['candidate']
if CONFIG['existing']:directory(candidate)
else:
 directory(candidate,False)
 if os.stat(candidate).st_uid!=0 or stat.S_IMODE(os.stat(candidate).st_mode)!=0o700:raise ValueError('New candidate staging must remain root-private')
manifest_path=candidate+'/.candidate-manifest.py'
if not CONFIG['existing']:
 regular(candidate+'/.manifest-upload.py')
 if sha(candidate+'/.manifest-upload.py')!=CONFIG['literal_sha256']:raise ValueError('Uploaded manifest checksum differs')
 stored=literal(candidate+'/.manifest-upload.py')
else:
 if sha(manifest_path)!=CONFIG['literal_sha256']:raise ValueError('Existing full manifest differs')
 stored=literal(manifest_path)
if stored.get('sha256')!=CONFIG['manifest_sha256']:raise ValueError('Manifest identity differs')
manifest=stored['manifest'];expected={row['path']:row for row in manifest['files']}
seen=set()
for folder,dirs,files in os.walk(candidate,followlinks=False):
 if not CONFIG['existing']:
  directory(folder,False)
  if os.stat(folder).st_uid!=0:raise ValueError('Candidate directory owner differs')
  if folder!=candidate:os.chmod(folder,0o755)
 else:directory(folder)
 for name in dirs:
  path=folder+'/'+name;directory(path,CONFIG['existing'])
  if not CONFIG['existing']:
   if os.stat(path).st_uid!=0:raise ValueError('Candidate directory owner differs')
   os.chmod(path,0o755)
 for name in files:
  path=folder+'/'+name;relative=os.path.relpath(path,candidate)
  if relative in ('.candidate-manifest.py','.candidate-complete','.manifest-upload.py'):
   if CONFIG['existing'] and relative=='.manifest-upload.py':raise ValueError('Existing candidate has stale upload metadata')
   if not CONFIG['existing'] and relative!='.manifest-upload.py':raise ValueError('Candidate completion metadata appeared before verification')
   continue
  if relative not in expected:raise ValueError('Unexpected candidate file')
  row=expected[relative];info=regular(path,1<<40,CONFIG['existing'])
  if info.st_size!=row['size'] or sha(path)!=row['sha256']:raise ValueError('Candidate file integrity differs')
  if CONFIG['existing']:
   if stat.S_IMODE(info.st_mode)!=row['mode']:raise ValueError('Existing candidate mode differs')
  else:os.chmod(path,row['mode'])
  seen.add(relative)
if seen!=set(expected):raise ValueError('Candidate file set differs')
if not CONFIG['existing']:
 os.rename(candidate+'/.manifest-upload.py',manifest_path)
 os.chmod(candidate,0o755)
 newfile(candidate+'/.candidate-complete',b'')
print('RESULT='+repr({'verified':True,'files':len(seen),'total_bytes':manifest['total_bytes']}))
'''

REMOTE_UPLOAD_DIRS = r'''
area();candidate=CONFIG['candidate'];directory(candidate,False)
info=os.stat(candidate)
if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Upload target must remain root-private')
path=candidate+'/.manifest-upload.py'
regular(path,private=False);os.chmod(path,0o600)
if sha(path)!=CONFIG['literal_sha256']:raise ValueError('Upload manifest checksum differs')
stored=literal(path)
if stored.get('sha256')!=CONFIG['manifest_sha256']:raise ValueError('Upload manifest identity differs')
parents=set()
for row in stored['manifest']['files']:
 relative=row['path']
 if relative.startswith('/') or '\\' in relative or any(p in ('','.', '..') for p in relative.split('/')):raise ValueError('Unsafe manifest relative path')
 parts=relative.split('/')[:-1]
 for count in range(1,len(parts)+1):parents.add('/'.join(parts[:count]))
for relative in sorted(parents,key=lambda value:(value.count('/'),value)):
 path=candidate+'/'+relative
 if not os.path.lexists(path):os.mkdir(path,0o755)
 directory(path,False)
 if os.stat(path).st_uid!=0:raise ValueError('Upload directory owner differs')
 os.chmod(path,0o755)
print('RESULT='+repr({'directories_ready':len(parents)}))
'''

REMOTE_FREEZE = r'''
import subprocess,sys
area();candidate=CONFIG['candidate'];directory(candidate)
regular(candidate+'/.candidate-complete',0)
session=CONFIG['session']
if os.path.lexists(session):raise ValueError('Refusing to reuse a session')
os.mkdir(session,0o755);os.chmod(session,0o755);directory(session)
for suffix in ('app','app/tmp','app/cache','app/config','app/data','app/runtime'):
 path=session+'/'+suffix;os.mkdir(path,0o700);os.chown(path,CONFIG['uid'],CONFIG['gid']);os.chmod(path,0o700)
raw=subprocess.check_output([sys.executable,'-B',candidate+'/runtime/snapshot.py'])
values=[line[7:] for line in raw.decode('utf-8').splitlines() if line.startswith('RESULT=')]
if len(values)!=1:raise ValueError('Missing unique frozen baseline')
baseline=ast.literal_eval(values[0])
newfile(session+'/baseline.py',(repr(baseline)+'\n').encode('utf-8'))
meta={'schema':'p011.browser.session.v1','session':session,'candidate':candidate,'manifest_sha256':CONFIG['manifest_sha256'],'boot_id':baseline['boot_id'],'hashes':baseline['hashes'],'seconds':CONFIG['seconds'],'uid':CONFIG['uid'],'gid':CONFIG['gid'],'offline_no_sandbox':CONFIG['offline_no_sandbox'],'public_site':CONFIG['public_site'],'public_no_sandbox':CONFIG['public_no_sandbox']}
newfile(session+'/session-meta.py',(repr(meta)+'\n').encode('utf-8'))
print('RESULT='+repr({'baseline':baseline,'metadata':meta}))
'''

REMOTE_SESSION = r'''
area();session=CONFIG['session'];candidate=CONFIG['candidate'];directory(session);directory(candidate)
meta=literal(session+'/session-meta.py');baseline=literal(session+'/baseline.py')
if meta!=CONFIG['metadata'] or baseline!=CONFIG['baseline']:raise ValueError('Saved session binding differs')
with open('/proc/sys/kernel/random/boot_id','r') as f:boot=f.read(64).strip()
if boot!=baseline['boot_id']:raise ValueError('Device boot identity differs; refusing cross-boot control')
if any(sha(path)!=checksum for path,checksum in baseline['hashes'].items()):raise ValueError('Current stock hashes differ; refusing cross-device control')
stored=literal(candidate+'/.candidate-manifest.py')
if stored.get('sha256')!=meta['manifest_sha256']:raise ValueError('Candidate manifest changed')
'''

REMOTE_LAUNCH = r'''
import subprocess,sys
sys.path.insert(0,candidate+'/runtime')
from safety import identity,same_stock,stock_snapshot,private_processes
if not same_stock(baseline,stock_snapshot()):raise ValueError('Current PID/starttime differs from frozen baseline')
if private_processes(candidate):raise ValueError('Candidate already has live processes')
for name in ('launch.py','supervisor.stdout.raw','supervisor.stderr.raw','COMPLETE','STOP'):
 if os.path.lexists(session+'/'+name):raise ValueError('Session already launched or stopped')
args=[sys.executable,'-B',candidate+'/runtime/supervisor.py','--candidate',candidate,'--session',session,'--baseline',session+'/baseline.py','--seconds',str(CONFIG['metadata']['seconds']),'--uid',str(CONFIG['metadata']['uid']),'--gid',str(CONFIG['metadata']['gid']),'--shell-integration',CONFIG['shell_integration']]
if CONFIG['metadata']['offline_no_sandbox']:args.append('--offline-no-sandbox')
if CONFIG['metadata'].get('public_site') is not None:
 args.extend(['--public-site',CONFIG['metadata']['public_site'],'--public-no-sandbox'])
with open(session+'/supervisor.stdout.raw','xb') as out,open(session+'/supervisor.stderr.raw','xb') as err:
 child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True)
 launch={'owner':identity(child.pid),'boot_id':baseline['boot_id'],'candidate':candidate,'session':session}
newfile(session+'/launch.py',(repr(launch)+'\n').encode('utf-8'))
print('RESULT='+repr({'launched':True,'launch':launch}))
'''

REMOTE_STATUS = r'''
complete=os.path.lexists(session+'/COMPLETE')
result=None
if complete:
 regular(session+'/COMPLETE',0)
 result=literal(session+'/result.py')
 regular(session+'/result.json')
 if result.get('schema')!='p011.browser.runtime-result.v1' or result.get('session')!=session or result.get('candidate')!=candidate:raise ValueError('Completed result binding differs')
launch=literal(session+'/launch.py') if os.path.lexists(session+'/launch.py') else None
finished=launch is None
if launch is not None:
 try:
  with open('/proc/'+str(launch['owner']['pid'])+'/stat','r') as f:raw=f.read(8192)
  fields=raw[raw.rindex(')')+2:].split()
  finished=fields[0]=='Z' or fields[19]!=str(launch['owner']['starttime'])
 except (IOError,OSError):finished=True
print('RESULT='+repr({'complete':complete,'result':result,'launch':launch,'supervisor_finished':finished}))
'''

REMOTE_STOP = r'''
if not os.path.lexists(session+'/COMPLETE'):
 path=session+'/STOP'
 if not os.path.lexists(path):newfile(path,b'')
 regular(path,0)
print('RESULT='+repr({'stop_requested':not os.path.lexists(session+'/COMPLETE')}))
'''

REMOTE_EVIDENCE = r'''
fixed=('baseline.py','session-meta.py','launch.py','started.py','supervisor-owner.py','guardian-owner.py','guardian-launch.py','supervisor.stdout.raw','supervisor.stderr.raw','guardian.stdout.raw','guardian.stderr.raw','browser.stdout.raw','browser.stderr.raw','result.py','result.json','STOP','COMPLETE')
complete=os.path.lexists(session+'/COMPLETE')
rows=[]
for name in fixed:
 path=session+'/'+name
 if not os.path.lexists(path):continue
 if name.endswith('.raw') and (not complete or (name.startswith('supervisor.') and not CONFIG['supervisor_finished'])):continue
 info=regular(path,64*1024*1024)
 rows.append({'path':name,'size':info.st_size,'sha256':sha(path),'root_owned':True})
capture_name={None:'local-fixture-window.png','baidu':'public-baidu-window.png','bilibili':'public-bilibili-window.png'}[meta.get('public_site')]
capture=session+'/app/captures/'+capture_name
if complete and os.path.lexists(capture):
 directory(session+'/app',False);directory(session+'/app/captures',False)
 info=os.lstat(capture)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=meta['uid'] or info.st_size>8*1024*1024:raise ValueError('Unsafe application capture')
 rows.append({'path':'app/captures/'+capture_name,'size':info.st_size,'sha256':sha(capture),'root_owned':False})
print('RESULT='+repr({'complete':complete,'files':rows}))
'''


def device_call(adb: Adb, label: str, source: str, config: dict, session_guard=False, timeout=30):
    code = REMOTE_COMMON + "\nCONFIG=" + repr(config) + "\n"
    if session_guard:
        code += REMOTE_SESSION
    return adb.python(label, code + "\n" + source, timeout=min(30, max(0.1, timeout)))[0]


def write_json(path: Path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def prepare_payload(payload: Path, out: Path):
    manifest = source_manifest(payload)
    candidate_name, checksum = manifest_identity(manifest)
    write_json(out / "payload-manifest.json", manifest)
    write_json(out / "runtime-layout.json", validate_runtime_layout(payload, manifest["files"]))
    control = {"sha256": checksum, "manifest": manifest}
    path = out / "candidate-manifest.py"
    path.write_text(repr(control) + "\n", encoding="utf-8")
    return manifest, candidate_name, checksum, path


def install_payload(adb: Adb, payload: Path, manifest: dict, candidate: str, checksum: str, manifest_path: Path, prewrite: dict):
    config = {"candidate": candidate, "required_bytes": manifest["total_bytes"] + RESERVE_BYTES,
              "manifest_sha256": checksum, "prewrite_baseline": prewrite}
    prepared = device_call(adb, "area-and-space-gate", REMOTE_PREPARE, config)
    existing = prepared["candidate_existing"]
    # Re-hash the complete source just before upload. The installation verifier
    # also rejects an altered upload; no unverified candidate can be launched.
    if source_manifest(payload) != manifest:
        raise ValueError("Payload changed after source manifest was frozen")
    if not existing:
        adb.run("push-manifest", ["push", str(manifest_path), candidate + "/.manifest-upload.py"], timeout=30)
        config["literal_sha256"] = digest(manifest_path)
        device_call(adb, "prepare-root-private-upload-directories", REMOTE_UPLOAD_DIRS, config)
        for row in manifest["files"]:
            local = payload.joinpath(*row["path"].split("/"))
            adb.run("push-payload-file", ["push", str(local), candidate + "/" + row["path"]],
                    timeout=transfer_timeout(row["size"]))
    config.update({"existing": existing, "literal_sha256": digest(manifest_path)})
    verification = device_call(adb, "verify-every-payload-file", REMOTE_VERIFY, config)
    return {"preparation": prepared, "verification": verification}


def state_config(state: dict) -> dict:
    if state.get("schema") != "p011.browser.host-run.v1":
        raise ValueError("Unexpected saved run schema")
    candidate, session = remote_names(state["candidate_name"], state["session_name"])
    baseline = validate_baseline(state["baseline"])
    metadata = state["metadata"]
    validate_mode(metadata.get("public_site"), metadata.get("public_no_sandbox", False),
                  metadata.get("offline_no_sandbox", False))
    if metadata.get("session") != session or metadata.get("candidate") != candidate or metadata.get("boot_id") != baseline["boot_id"] or metadata.get("hashes") != baseline["hashes"]:
        raise ValueError("Saved run metadata differs")
    if not re.fullmatch(r"[a-f0-9]{64}", metadata.get("manifest_sha256", "")) or state["candidate_name"] != "browser-685-" + metadata["manifest_sha256"][:16]:
        raise ValueError("Saved candidate identity differs")
    return {"candidate": candidate, "session": session, "baseline": baseline, "metadata": metadata}


def validate_png(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > 8 * 1024 * 1024 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Invalid capture PNG signature or size")
    offset, dimensions, ended, channels = 8, None, False, None
    image_chunks = []
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise ValueError("Truncated PNG chunk")
        size = struct.unpack_from(">I", raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        if offset + 12 + size > len(raw):
            raise ValueError("Truncated PNG payload")
        data = raw[offset + 8:offset + 8 + size]
        crc = struct.unpack_from(">I", raw, offset + 8 + size)[0]
        if zlib.crc32(kind + data) & 0xffffffff != crc:
            raise ValueError("Capture PNG CRC differs")
        if kind == b"IHDR":
            if dimensions is not None or offset != 8 or size != 13:
                raise ValueError("Invalid PNG header")
            dimensions = struct.unpack_from(">II", data)
            depth, color, compression, filtering, interlace = data[8:13]
            if depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
                raise ValueError("Unsupported capture PNG pixel format")
            channels = 3 if color == 2 else 4
        if kind == b"IDAT":
            image_chunks.append(data)
        offset += 12 + size
        if kind == b"IEND":
            ended = size == 0 and offset == len(raw)
            break
    if dimensions != (800, 480) or not ended or not image_chunks:
        raise ValueError("Capture dimensions or PNG structure differ")
    expected_size = (800 * channels + 1) * 480
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(b"".join(image_chunks), expected_size + 1)
    except zlib.error as exc:
        raise ValueError("Invalid compressed capture PNG stream") from exc
    if (len(decoded) != expected_size or not decoder.eof or decoder.unused_data
            or decoder.unconsumed_tail or any(decoded[row * (800 * channels + 1)] > 4 for row in range(480))):
        raise ValueError("Capture PNG image stream differs")
    return {"width": dimensions[0], "height": dimensions[1], "sha256": hashlib.sha256(raw).hexdigest(),
            "png_structure_verified": True, "visual_reviewed": False, "physical_scanout_verified": False}


def public_metrics_evidence(value):
    booleans = ("ready_complete", "body_present")
    numbers = ("viewport_width", "viewport_height", "scroll_width", "scroll_height",
               "image_count", "loaded_image_count", "text_length")
    if not isinstance(value, dict) or set(value) != set(booleans + numbers):
        return None
    if any(value[key] is not True for key in booleans):
        return None
    if any(isinstance(value[key], bool) or not isinstance(value[key], int)
           or not 0 <= value[key] <= 100000000 for key in numbers):
        return None
    if not (100 <= value["viewport_width"] <= 1600 and 50 <= value["viewport_height"] <= 1000
            and value["scroll_width"] >= value["viewport_width"]
            and value["scroll_height"] >= value["viewport_height"]
            and 0 <= value["loaded_image_count"] <= value["image_count"]
            and (value["image_count"] == 0 or value["loaded_image_count"] > 0)
            and value["text_length"] >= 20):
        return None
    return {key: value[key] for key in booleans + numbers}


def page_evidence(local: Path, status: dict, evidence: dict, public_site=None) -> dict:
    if public_site is not None and public_site not in PUBLIC_SITES:
        raise ValueError("Unknown fixed public-site evidence selector")
    runtime = status.get("result") or {}
    result = {"page_passed": False, "public_site_passed": False, "selected_page_passed": False,
              "public_site": public_site, "lifecycle_passed": runtime.get("passed") is True,
              "physical_display_verified": False, "real_site_compatibility_verified": False,
              "capture_visual_reviewed": False, "physical_input_verified": False,
              "video_playback_verified": False}
    if not status.get("complete"):
        return dict(result, reason="Guardian completion marker absent")
    stdout = local / "browser.stdout.raw"
    if not stdout.is_file():
        return dict(result, reason="Browser stdout unavailable")
    clean = stdout.read_bytes().decode("utf-8", "replace").replace("\r\r\n", "\n").replace("\r\n", "\n")
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", clean)
    events = []
    for line in clean.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(event, dict) and event.get("component") == "p011-browser-probe" and event.get("schema") == 1:
            events.append(event)
    identities = [row for row in events if row.get("event") == "runtime_identity"]
    identity_ok = (len(identities) == 1 and identities[0].get("qt") == "6.8.5"
                   and identities[0].get("webengine") == "6.8.5"
                   and re.fullmatch(r"122\.[0-9]+\.[0-9]+\.[0-9]+", identities[0].get("chromium", "")) is not None
                   and identities[0].get("local_probe") is (public_site is None)
                   and (public_site is None or identities[0].get("public_site") == public_site))
    failed_names = {"render_process_terminated", "qml_creation_failed", "load_failed", "local_capture_failed",
                    "public_capture_failed", "public_metrics_rejected", "certificate_denied"}
    if public_site is not None:
        failed_names.add("navigation_denied")
    failures = [row["event"] for row in events if row.get("event") in failed_names]
    loaded = any(row.get("event") == "load_succeeded" for row in events)
    probes = [row for row in events if row.get("event") == "dom_probe_result"]
    probe_ok = len(probes) == 1 and probes[0].get("detail") == 31
    metrics_rows = [row for row in events if row.get("event") == "public_page_metrics"]
    public_metrics = None
    if len(metrics_rows) == 1 and metrics_rows[0].get("public_site") == public_site:
        public_metrics = public_metrics_evidence(metrics_rows[0].get("metrics"))
    trial_mode_bound = (public_site is None or (runtime.get("public_site") == public_site
                        and runtime.get("public_no_sandbox") is True
                        and runtime.get("offline_local_fixture_only") is False
                        and runtime.get("sandbox_enabled") is False))
    capture_event = "local_capture_saved" if public_site is None else "public_capture_saved"
    captures = [row for row in events if row.get("event") == capture_event]
    capture_event_ok = (len(captures) == 1 and captures[0].get("width") == 800
                        and captures[0].get("height") == 480
                        and captures[0].get("evidence_kind") == "application-window"
                        and captures[0].get("physical_scanout_verified") is False
                        and (public_site is None or captures[0].get("public_site") == public_site))
    png = None
    capture_name = "local-fixture-window.png" if public_site is None else "public-" + public_site + "-window.png"
    capture_relative = "app/captures/" + capture_name
    capture_rows = [row for row in evidence["files"] if row["path"] == capture_relative]
    if len(capture_rows) == 1:
        try:
            png = validate_png(local / "app" / "captures" / capture_name)
            if png["sha256"] != capture_rows[0]["sha256"]:
                png = None
        except (ValueError, OSError):
            pass
    common_passed = bool(identity_ok and loaded and not failures and capture_event_ok and png)
    local_passed = public_site is None and common_passed and probe_ok
    public_passed = public_site is not None and common_passed and public_metrics is not None and trial_mode_bound
    result.update({"identity_verified": identity_ok, "load_succeeded": loaded, "dom_mask_31": probe_ok,
                   "failure_events": failures, "capture_event_verified": capture_event_ok, "capture": png,
                   "page_passed": local_passed, "public_site_passed": public_passed,
                   "selected_page_passed": local_passed or public_passed,
                   "public_metrics": public_metrics, "trial_mode_bound": trial_mode_bound})
    return result


def collect_session(adb: Adb, state: dict, out: Path, deadline=None):
    config = state_config(state)
    def remaining():
        if deadline is None:
            return 30
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("Host trial collection deadline reached; use --collect saved run")
        return min(30, value)
    status = device_call(adb, "collect-session-status", REMOTE_STATUS, config, True, remaining())
    write_json(out / "collected-status.json", status)
    local = out / "device-session"
    local.mkdir()
    config["supervisor_finished"] = status.get("supervisor_finished") is True
    evidence = device_call(adb, "freeze-evidence-file-list", REMOTE_EVIDENCE, config, True, remaining())
    write_json(out / "evidence-manifest.json", evidence)
    for row in evidence["files"]:
        relative = safe_relative(row["path"])
        target = local.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        adb.run("pull-owned-evidence", ["pull", config["session"] + "/" + relative, str(target)], timeout=remaining())
        if target.stat().st_size != row["size"] or digest(target) != row["sha256"]:
            raise ValueError("Pulled evidence differs from frozen device SHA/size")
    status["validation"] = page_evidence(local, status, evidence, config["metadata"].get("public_site"))
    write_json(out / "validation.json", status["validation"])
    return status


def run_trial(adb: Adb, args, out: Path):
    payload = args.payload.absolute()
    manifest, name, checksum, manifest_path = prepare_payload(payload, out)
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    session_name = stamp + "-" + uuid.uuid4().hex[:8]
    candidate, session = remote_names(name, session_name)
    observed, _ = adb.python("readonly-before-any-device-write", SNAPSHOT, timeout=30)
    write_json(out / "prewrite-observed.json", observed)
    prewrite = normalize_preflight(observed)
    write_json(out / "prewrite-baseline.json", prewrite)
    if args.expected_snapshot and read_expected_snapshot(args.expected_snapshot) != prewrite:
        raise ValueError("Selected transport does not match the explicitly expected boot/hash/PID snapshot; no device write performed")
    install = install_payload(adb, payload, manifest, candidate, checksum, manifest_path, prewrite)
    write_json(out / "installation.json", install)
    config = {"candidate": candidate, "session": session, "manifest_sha256": checksum,
              "seconds": args.seconds, "uid": args.uid, "gid": args.gid,
              **validate_mode(args.public_site, args.public_no_sandbox, args.offline_no_sandbox)}
    frozen = device_call(adb, "freeze-current-runtime-baseline", REMOTE_FREEZE, config)
    write_json(out / "runtime-frozen-observed.json", frozen)
    baseline = validate_baseline(frozen["baseline"])
    if normalize_preflight(baseline) != prewrite:
        raise ValueError("Factory identity changed while preparing the isolated candidate; browser not launched")
    state = {"schema": "p011.browser.host-run.v1", "transport_id": args.transport,
             "candidate_name": name, "session_name": session_name,
             "baseline": baseline, "metadata": frozen["metadata"]}
    write_json(out / "run-state.json", state)
    (out / "baseline.literal").write_text(repr(baseline) + "\n", encoding="utf-8")
    guarded = state_config(state)
    guarded["shell_integration"] = args.shell_integration
    deadline = time.monotonic() + args.seconds + 40
    launched = device_call(adb, "launch-detached-supervisor", REMOTE_LAUNCH, guarded, True)
    write_json(out / "launch.json", launched)
    status = None
    requested_stop = False
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 8 and not requested_stop:
                device_call(adb, "deadline-request-own-stop", REMOTE_STOP, guarded, True, remaining)
                requested_stop = True
            status = device_call(adb, "poll-own-session", REMOTE_STATUS, guarded, True,
                                 deadline - time.monotonic())
            if status["complete"] and status["supervisor_finished"]:
                break
            # Each remote request is bounded by 30 seconds; polling never uses a
            # blocking sleep over one second and never starts a second browser.
            time.sleep(min(1.0, max(0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            device_call(adb, "request-own-stop", REMOTE_STOP, guarded, True,
                        deadline - time.monotonic())
            requested_stop = True
    if status is None or not status.get("complete"):
        return {"scope": "DEVICE_TRIAL_COMPLETION_UNCONFIRMED", "passed": False,
                "state_path": str(out / "run-state.json"), "status": status,
                "own_stop_requested": requested_stop, "collect_later_required": True}
    status = collect_session(adb, state, out, deadline)
    validation = status["validation"]
    return {"scope": "DEVICE_LOCAL_FIXTURE_TRIAL" if args.public_site is None else "DEVICE_FIXED_PUBLIC_SITE_TRIAL",
            "passed": validation["lifecycle_passed"] and validation["selected_page_passed"],
            "lifecycle_passed": validation["lifecycle_passed"], "page_passed": validation["page_passed"],
            "public_site": args.public_site, "public_site_passed": validation["public_site_passed"],
            "state_path": str(out / "run-state.json"), "status": status,
            "physical_display_verified": False, "real_site_compatibility_verified": False}


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", type=int, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--payload", type=Path)
    group.add_argument("--collect", type=Path, metavar="SAVED_RUN")
    group.add_argument("--stop", type=Path, metavar="SAVED_RUN", help="Write only this session's owned STOP flag")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--uid", type=int, default=65534)
    parser.add_argument("--gid", type=int, default=65534)
    parser.add_argument("--offline-no-sandbox", action="store_true",
                        help="Explicit offline qrc-only experiment; never automatic fallback")
    parser.add_argument("--public-site", choices=tuple(PUBLIC_SITES),
                        help="Explicit fixed public-site experiment; requires --public-no-sandbox")
    parser.add_argument("--public-no-sandbox", action="store_true",
                        help="Explicit sandbox-disabled public-site trial; never automatic fallback")
    parser.add_argument("--shell-integration", choices=("wl-shell", "xdg-shell-v6", "xdg-shell"), default="wl-shell")
    parser.add_argument("--prepare-only", action="store_true", help="Host-only manifest; no ADB")
    parser.add_argument("--expected-snapshot", type=Path,
                        help="Explicit current-run snapshot JSON/literal to match before any device write")
    args = parser.parse_args(argv)
    if args.transport < 1 or not 1 <= args.seconds <= 120 or args.uid < 1 or args.gid < 1:
        parser.error("Positive transport/uid/gid and seconds 1..120 are required")
    if args.prepare_only and args.payload is None:
        parser.error("--prepare-only requires --payload")
    try:
        validate_mode(args.public_site, args.public_no_sandbox, args.offline_no_sandbox)
    except ValueError as exc:
        parser.error(str(exc))
    if args.payload is None and (args.public_site or args.public_no_sandbox or args.offline_no_sandbox):
        parser.error("Saved-run collection/stop uses its frozen mode; do not supply new trial modes")
    return args


def main(argv=None):
    args = arguments(argv)
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    out = WORKSPACE / "logs" / ("BrowserP011-Trial-" + stamp + "-" + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    print("LOG_DIR=" + str(out), flush=True)
    code = 1
    summary = {"scope": "HOST_PREPARATION_FAILED", "passed": False, "transport_id": args.transport}
    try:
        if args.prepare_only:
            manifest, name, checksum, _ = prepare_payload(args.payload.absolute(), out)
            summary = {"scope": "HOST_ONLY_PAYLOAD_MANIFEST", "passed": True,
                       "candidate_name": name, "manifest_sha256": checksum,
                       "space_requirement_bytes": manifest["total_bytes"] + RESERVE_BYTES,
                       "device_accessed": False}
        else:
            adb = Adb(args.transport, out)
            if args.collect or args.stop:
                supplied = args.collect or args.stop
                saved = supplied / "run-state.json" if supplied.is_dir() else supplied
                state = json.loads(saved.read_text(encoding="utf-8-sig"))
                if state.get("transport_id") != args.transport:
                    raise ValueError("Saved transport differs; no automatic device retargeting")
                if args.stop:
                    stop = device_call(adb, "request-saved-own-stop", REMOTE_STOP, state_config(state), True)
                    summary = {"scope": "DEVICE_OWN_STOP_REQUEST_ONLY", "passed": False,
                               "stop": stop, "restoration_or_exit_verified": False,
                               "collect_later_required": True}
                    code = 0
                else:
                    status = collect_session(adb, state, out)
                    validation = status["validation"]
                    summary = {"scope": "DEVICE_COLLECT_ONLY_NO_RESTART",
                               "collection_passed": True,
                               "passed": validation["lifecycle_passed"] and validation["selected_page_passed"],
                               "lifecycle_passed": validation["lifecycle_passed"],
                               "page_passed": validation["page_passed"],
                               "public_site_passed": validation["public_site_passed"],
                               "public_site": state["metadata"].get("public_site"), "status": status}
            else:
                summary = run_trial(adb, args, out)
        code = 0 if summary.get("passed") is True or summary.get("scope") == "DEVICE_OWN_STOP_REQUEST_ONLY" else 1
    except (Exception, KeyboardInterrupt) as exc:
        if (out / "run-state.json").is_file():
            summary["scope"] = "DEVICE_TRIAL_CONTROL_FAILED_COMPLETION_UNCONFIRMED"
            summary["state_path"] = str(out / "run-state.json")
        summary.update({"error_type": type(exc).__name__, "error": str(exc),
                        "completion_unconfirmed": True,
                        "collect_hint": "Use --collect with run-state.json if the run reached baseline freeze"})
    write_json(out / "summary.json", summary)
    target, checksum = archive(out)
    print(json.dumps(summary, ensure_ascii=False))
    print("RESULT_ZIP=" + str(target))
    print("ZIP_SHA256=" + checksum)
    return code


if __name__ == "__main__":
    sys.exit(main())
