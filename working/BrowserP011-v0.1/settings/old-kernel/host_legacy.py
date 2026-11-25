"""Transport-pinned legacy settings inspect/install/restore with private evidence."""
from __future__ import annotations
import argparse
import ast
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import sys

HERE = Path(__file__).resolve().parent
BROWSER = HERE.parents[1]
WORKSPACE = BROWSER.parents[1]
sys.path.insert(0, str(BROWSER / "host"))
from audit_device import Adb, SNAPSHOT, archive

AREA = "/mnt/data/p011-browser"
ADMIN = AREA + "/settings/legacy/_install"
OLD = "3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896"
NEW = "b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8"
PROTECTED = {"/usr/bin/control_engine": "364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d",
             "/usr/bin/zyb_z03_launch.sh": "7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b"}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_package(path):
    if path is None:
        pointer = HERE / "selected-package.txt"
        if not pointer.is_file():
            raise ValueError("Build and select a legacy package first")
        path = Path(pointer.read_text(encoding="utf-8").strip())
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Expected the immutable local legacy package")
    manifest = ast.literal_eval((path / "package-manifest.py").read_text(encoding="utf-8"))
    if manifest.get("schema") != "p011.browser.legacy-package.v1":
        raise ValueError("Legacy package schema differs")
    expected = manifest["files"]
    seen = set()
    for source in path.rglob("*"):
        if source.is_symlink():
            raise ValueError("Package symlink refused")
        if source.is_dir():
            continue
        name = source.relative_to(path).as_posix()
        if name == "package-manifest.py":
            continue
        if name not in expected or source.stat().st_size != expected[name]["bytes"] or sha(source) != expected[name]["sha256"]:
            raise ValueError("Local legacy package integrity differs")
        seen.add(name)
    if seen != set(expected) or sha(path / "Z03.patched") != NEW:
        raise ValueError("Local legacy package member set differs")
    return path, manifest


def snapshot_gate(snapshot, action, expected=None):
    hashes = snapshot.get("hashes", {})
    if snapshot.get("uid") != 0 or "z031_v2.4.0-20251128_174826-user" not in (snapshot.get("firmware") or ""):
        raise ValueError("Not the supported root P011 target")
    allowed = (OLD,) if action == "install" else (OLD, NEW)
    if hashes.get("/usr/bin/Z03") not in allowed or any(hashes.get(path) != value for path, value in PROTECTED.items()):
        raise ValueError("Current firmware identity differs")
    for name in ("Z03", "control_engine", "weston"):
        if len([row for row in snapshot["processes"] if row.get("comm") == name]) != 1:
            raise ValueError("Current core process is not unique")
    if expected is not None:
        before = json.loads(expected.read_text(encoding="utf-8"))
        if before.get("boot_id") != snapshot.get("boot_id") or before.get("hashes") != hashes:
            raise ValueError("Selected baseline boot or hashes changed")
        for name in ("Z03", "control_engine", "weston"):
            left = [row for row in before["processes"] if row.get("comm") == name]
            right = [row for row in snapshot["processes"] if row.get("comm") == name]
            if len(left) != 1 or any(left[0].get(key) != right[0].get(key) for key in ("pid", "ppid", "starttime", "exe", "parent")):
                raise ValueError("Selected baseline process binding changed")


PREPARE = r'''
import os,stat,re
root='/mnt/data/p011-browser'
def directory(path):
 if os.path.realpath(path)!=path:raise ValueError('Redirected staging directory')
 info=os.lstat(path)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe staging directory')
directory(root)
marker=root+'/.area-owner';info=os.lstat(marker)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Area marker differs')
with open(marker,'rb') as handle:
 if handle.read(128)!=b'p011.browser.area.v1\n':raise ValueError('Area marker differs')
parent=root+'/legacy-packages'
if not os.path.lexists(parent):os.mkdir(parent,0o700);os.chmod(parent,0o700)
directory(parent)
target=CONFIG['remote']
if not re.fullmatch(re.escape(parent)+r'/legacy-[a-f0-9]{16}-[a-f0-9]{8}',target):raise ValueError('Unexpected stage path')
if os.path.lexists(target):raise ValueError('Stage already exists; no takeover')
space=os.statvfs(root)
if space.f_bavail*space.f_frsize<CONFIG['bytes']+128*1024*1024+8388608:raise ValueError('Storage reserve would be violated')
os.mkdir(target,0o700);os.chmod(target,0o700)
for relative in CONFIG['directories']:
 path=target+'/'+relative
 os.mkdir(path,0o700);os.chmod(path,0o700)
print('RESULT='+repr({'stage':target,'created':True}))
'''

SEAL = r'''
import os,stat,hashlib
root=CONFIG['remote']
if os.path.realpath(root)!=root:raise ValueError('Stage redirected')
info=os.lstat(root)
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Stage not private')
expected=CONFIG['files'];seen=set()
for folder,dirs,files in os.walk(root,followlinks=False):
 for name in dirs:
  info=os.lstat(folder+'/'+name)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Stage ancestor differs')
 for name in files:
  path=folder+'/'+name;relative=os.path.relpath(path,root)
  info=os.lstat(path)
  if relative not in expected or not stat.S_ISREG(info.st_mode) or info.st_uid!=0:raise ValueError('Unexpected stage member')
  with open(path,'rb') as handle:checksum=hashlib.sha256(handle.read()).hexdigest()
  if info.st_size!=expected[relative]['bytes'] or checksum!=expected[relative]['sha256']:raise ValueError('Stage readback differs')
  seen.add(relative)
if seen!=set(expected):raise ValueError('Stage member set differs')
# Old Windows ADB pushes 0666. Only after every byte has been verified inside
# this new root-private staging directory do we restrict the uploaded files.
for relative in expected:os.chmod(root+'/'+relative,0o600)
print('RESULT='+repr({'stage_verified':True,'files':len(seen)}))
'''

COLLECT = r'''
import os,stat,hashlib,re
root='/mnt/data/p011-browser/settings/legacy/_install'
result=[]
if os.path.isdir(root) and not os.path.islink(root):
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:
   if os.path.islink(folder+'/'+name):raise ValueError('Redirected admin evidence')
  for name in files:
   if not (name.endswith('.py') or name.endswith('.original') or name.endswith('.qmlc')):continue
   path=folder+'/'+name;info=os.lstat(path)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_size>16777216:raise ValueError('Unsafe admin evidence')
   with open(path,'rb') as handle:checksum=hashlib.sha256(handle.read()).hexdigest()
   result.append({'path':path,'bytes':info.st_size,'sha256':checksum})
 if len(result)>100:raise ValueError('Evidence count exceeds bound')
print('RESULT='+repr({'files':result}))
'''


def device_call(adb, label, source, config):
    return adb.python(label, "CONFIG=" + repr(config) + "\n" + source)[0]


def perform(args, out):
    adb = Adb(args.transport, out)
    before = adb.python("read-current-identity", SNAPSHOT)[0]
    write_json(out / "before.json", before)
    snapshot_gate(before, args.action, args.expected_snapshot)
    if args.action == "inspect":
        return {"scope": "DEVICE_READ_ONLY_LEGACY_INSPECT", "passed": True, "snapshot": before}
    package, manifest = local_package(args.package)
    if args.action == "install":
        identity = sha(package / "package-manifest.py")
        remote = AREA + "/legacy-packages/legacy-" + identity[:16] + "-" + secrets.token_hex(4)
        files = dict(manifest["files"])
        files["package-manifest.py"] = {"bytes": (package / "package-manifest.py").stat().st_size,
                                         "sha256": identity}
        directories = sorted({str(Path(name).parent).replace("\\", "/") for name in files if "/" in name},
                             key=lambda value: (value.count("/"), value))
        # Include all ancestors for payload subdirectories.
        directories = sorted({"/".join(name.split("/")[:index]) for name in files
                              for index in range(1, len(name.split("/")))}, key=lambda value: (value.count("/"), value))
        config = {"remote": remote, "bytes": sum(row["bytes"] for row in files.values()),
                  "directories": directories, "files": files}
        write_json(out / "stage.json", config)
        device_call(adb, "create-private-legacy-stage", PREPARE, config)
        for name in sorted(files):
            adb.run("push-legacy-member", ["push", str(package / name), remote + "/" + name], timeout=45)
        device_call(adb, "verify-all-stage-bytes-before-chmod", SEAL, config)
        command = "cd " + shlex.quote(remote) + " && python3 -B device_install.py install --package " + shlex.quote(remote)
    else:
        expected = manifest["files"]["device_install.py"]["sha256"]
        source = ("import hashlib,os,stat\np=" + repr(ADMIN + "/device_install.py") +
                  "\ni=os.lstat(p)\nassert stat.S_ISREG(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o600\n" +
                  "assert os.path.realpath(p)==p\nwith open(p,'rb') as f:h=hashlib.sha256(f.read()).hexdigest()\n" +
                  "assert h==" + repr(expected) + "\nprint('RESULT='+repr({'installed_installer_sha256':h}))\n")
        adb.python("bind-installed-legacy-restore-code", source)
        command = "cd " + shlex.quote(ADMIN) + " && python3 -B device_install.py restore"
    output, status = adb.shell("explicit-legacy-" + args.action, command, timeout=100, require=False)
    matches = re.findall(r"^RESULT=(.*)$", output, re.M)
    operation = ast.literal_eval(matches[-1]) if len(matches) == 1 else None
    write_json(out / "operation.json", {"status": status, "result": operation})
    evidence = adb.python("freeze-owned-legacy-evidence", COLLECT)[0]
    write_json(out / "device-evidence-manifest.json", evidence)
    for row in evidence["files"]:
        relative = row["path"][len(ADMIN) + 1:]
        target = out / "device-admin" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        adb.run("pull-owned-admin-evidence", ["pull", row["path"], str(target)], timeout=30)
        if target.stat().st_size != row["bytes"] or sha(target) != row["sha256"]:
            raise ValueError("Pulled legacy evidence differs")
    after = adb.python("read-post-install-identity", SNAPSHOT)[0]
    write_json(out / "after.json", after)
    snapshot_gate(after, "inspect")
    expected_z03 = NEW if args.action == "install" else OLD
    passed = bool(status["host_exit"] == status["remote_exit"] == 0 and operation and operation.get("passed") is True
                  and after["hashes"].get("/usr/bin/Z03") == expected_z03)
    return {"scope": "DEVICE_EXPLICIT_LEGACY_" + args.action.upper(), "passed": passed,
            "operation": operation, "remote_status": status,
            "physical_acceptance": False, "settings_navigation_verified": False,
            "current_z03_sha256": after["hashes"]["/usr/bin/Z03"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("inspect", "install", "restore"), required=True)
    parser.add_argument("--transport", type=int, required=True)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--expected-snapshot", type=Path)
    args = parser.parse_args()
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S-%f")
    out = WORKSPACE / "logs" / ("BrowserP011-LegacySettings-" + args.action + "-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    result = {"scope": "HOST_CONTROL_FAILED", "passed": False}
    try:
        result = perform(args, out)
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        write_json(out / "summary.json", result)
        archive(out)
    print(json.dumps({"log_dir": str(out), **result}, ensure_ascii=False))
    return 0 if result.get("passed") is True else 1


if __name__ == "__main__":
    sys.exit(main())
