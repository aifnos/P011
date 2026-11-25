"""Read-only, transport-pinned P011 browser preflight. Never changes the device."""
from __future__ import annotations

import argparse
import ast
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


class Adb:
    def __init__(self, transport: int, out: Path):
        executable = shutil.which("adb")
        if not executable or transport < 1:
            raise ValueError("An explicit positive ADB transport is required")
        self.prefix = [executable, "-t", str(transport)]
        self.out, self.sequence = out, 0

    def run(self, label, args, timeout=30, require=True):
        self.sequence += 1
        tag = "%02d-%s" % (self.sequence, label)
        try:
            p = subprocess.run(self.prefix + args, capture_output=True, timeout=timeout)
            stdout, stderr, host_exit = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, host_exit = exc.stdout or b"", exc.stderr or b"", None
        (self.out / (tag + ".stdout.raw")).write_bytes(stdout)
        (self.out / (tag + ".stderr.raw")).write_bytes(stderr)
        clean = stdout.decode("utf-8", "replace").replace("\r\r\n", "\n").replace("\r\n", "\n")
        matches = re.findall(r"^__REMOTE_EXIT__=(\d+)\s*$", clean, re.M) if args[0] == "shell" else []
        status = {"host_exit": host_exit, "remote_exit": int(matches[-1]) if len(matches) == 1 else None,
                  "timeout": host_exit is None, "raw_stderr_bytes": len(stderr)}
        (self.out / (tag + ".status.json")).write_text(json.dumps(status, indent=2), encoding="utf-8")
        if require and (host_exit != 0 or (args[0] == "shell" and matches != ["0"])):
            raise RuntimeError("%s failed; inspect %s" % (label, self.out))
        return clean, status

    def shell(self, label, command, timeout=30, require=True):
        wrapped = "(" + command + "); rc=$?; printf '\n__REMOTE_EXIT__=%s\n' \"$rc\""
        if len(wrapped.encode("utf-8")) >= 4096:
            raise ValueError("Remote shell exceeds the legacy ADB bound")
        return self.run(label, ["shell", wrapped], timeout, require)

    def python(self, label, source, timeout=30):
        packed = base64.b64encode(zlib.compress(source.encode("utf-8"), 9)).decode("ascii")
        loader = "import base64,zlib;exec(zlib.decompress(base64.b64decode(%r)))" % packed
        text, status = self.shell(label, "python3 -B -c " + shlex.quote(loader), timeout)
        values = re.findall(r"^RESULT=(.*)$", text, re.M)
        if len(values) != 1:
            raise ValueError("Missing unique device RESULT")
        return ast.literal_eval(values[0]), status


SNAPSHOT = r'''
import os,sys,hashlib,platform
def text(path,n=65536):
 try:
  with open(path,'r') as f:return f.read(n).strip()
 except (IOError,OSError):return None
def identity(pid):
 try:
  base='/proc/'+str(pid)
  stat=text(base+'/stat')
  if not stat:return None
  rest=stat[stat.rfind(')')+2:].split()
  return {'pid':int(pid),'ppid':int(rest[1]),'starttime':int(rest[19]),'exe':os.readlink(base+'/exe'),'comm':text(base+'/comm')}
 except (IOError,OSError,ValueError,TypeError):return None
files={}
for p in ['/usr/bin/Z03','/usr/bin/control_engine','/usr/bin/zyb_z03_launch.sh']:
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   b=f.read(262144)
   if not b:break
   h.update(b)
 files[p]=h.hexdigest()
processes=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 item=identity(pid)
 if not item:continue
 if item['comm'] in ['Z03','control_engine','weston','connmand','bluetoothd','ofonod','adbd','QtWebEngineProc','QtWebEngineProcess'] or item['exe'].startswith('/mnt/data/p011-browser/'):
  parent=identity(item['ppid']);item['parent']=parent
  if parent:item['grandparent']=identity(parent['ppid'])
  processes.append(item)
mem={}
for line in (text('/proc/meminfo') or '').splitlines():
 k,v=line.split(':',1)
 if k in ['MemTotal','MemAvailable','MemFree','SwapTotal','SwapFree']:mem[k]=v.strip()
caps={p:os.path.exists(p) for p in ['/dev/dri/card0','/dev/dri/renderD128','/usr/lib/libEGL.so','/usr/lib/libGLESv2.so','/usr/lib/libgbm.so.1','/usr/bin/weston-info','/usr/bin/wayland-info','/usr/bin/unshare']}
mounts=[]
for line in (text('/proc/mounts') or '').splitlines():
 fields=line.split()
 if fields[1] in ['/','/mnt/data','/mnt/userdata','/run','/tmp']:mounts.append(fields[:4])
result={'schema':'p011.browser.readonly.v1','boot_id':text('/proc/sys/kernel/random/boot_id'),
 'firmware':text('/etc/os-release'),'uid':os.getuid(),'uname':tuple(os.uname()),
 'python':sys.version.split()[0],'libc':os.confstr('CS_GNU_LIBC_VERSION'),
 'libc_source':'os.confstr(CS_GNU_LIBC_VERSION)','hashes':files,'processes':processes,
 'memory':mem,'caps':caps,'mounts':mounts,'wlan0_operstate':text('/sys/class/net/wlan0/operstate'),
 'unprivileged_userns_clone':text('/proc/sys/kernel/unprivileged_userns_clone'),
 'cpu_features':[l for l in (text('/proc/cpuinfo') or '').splitlines() if l.startswith('Features')][:1],
 'passwd_nobody':[l for l in (text('/etc/passwd') or '').splitlines() if l.startswith('nobody:')],
 'toolbox_menu_link':os.path.lexists('/mnt/data/p011-menu'),'toolbox_lock':os.path.lexists('/tmp/p011-menutest.lock')}
print('RESULT='+repr(result))
'''


def archive(out):
    import zipfile
    target = out.with_suffix(".private.zip")
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(out.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(out).as_posix())
    with zipfile.ZipFile(target) as bundle:
        if bundle.testzip() is not None:
            raise ValueError("Archive CRC failure")
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix + ".sha256").write_text(checksum + "  " + target.name + "\n", encoding="ascii")
    return target, checksum


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", type=int, required=True)
    args = parser.parse_args()
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S-%f")
    out = WORKSPACE / "logs" / ("BrowserP011-Preflight-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    print("LOG_DIR=" + str(out), flush=True)
    adb = Adb(args.transport, out)
    snapshot, _ = adb.python("snapshot", SNAPSHOT)
    (out / "snapshot.json").write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "snapshot.literal").write_text(repr(snapshot), encoding="utf-8")
    for name, cmd in [
        ("space", "df -k /mnt/data /tmp"),
        ("wayland", "XDG_RUNTIME_DIR=/run/user/0 WAYLAND_DISPLAY=wayland-0 weston-info"),
        ("connman-owner", "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetNameOwner string:net.connman"),
        ("bluez-owner", "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetNameOwner string:org.bluez"),
        ("kernel-browser-features", "if test -r /proc/config.gz; then zcat /proc/config.gz | grep -E '^CONFIG_(NAMESPACES|USER_NS|PID_NS|NET_NS|SECCOMP|SECCOMP_FILTER|SYSVIPC|SHMEM)='; else printf 'kernel_config_unavailable\\n'; fi"),
    ]:
        adb.shell(name, cmd, require=False)
    summary = {"transport_id": args.transport, "scope": "DEVICE_READ_ONLY_NO_CANDIDATE_STARTED",
               "firmware": snapshot["firmware"], "hashes": snapshot["hashes"], "memory": snapshot["memory"],
               "core_process_count": len(snapshot["processes"]), "out": str(out)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    target, checksum = archive(out)
    print(json.dumps(summary, ensure_ascii=False))
    print("RESULT_ZIP=" + str(target))
    print("ZIP_SHA256=" + checksum)


if __name__ == "__main__":
    main()
