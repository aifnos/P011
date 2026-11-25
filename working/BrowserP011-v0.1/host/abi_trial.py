"""Run the owned tiny ARM C++ ABI probe as uid 65534, with no browser/network."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from audit_device import Adb, SNAPSHOT, archive

AREA = "/mnt/data/p011-browser"
OWNER = "p011.browser.area.v1\n"
ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def anchor(value):
    return {k: value[k] for k in ("boot_id", "hashes", "processes")}


def probe_events(stdout):
    rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    expected = ["browser685.abi_probe", "browser685.libstdcxx_runtime"]
    if len(rows) == 3:
        expected.append("browser685.cpp_threads")
    if len(rows) not in (2, 3) or [r.get("event") for r in rows] != expected:
        raise ValueError("Expected the fixed ABI probe events")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", required=True, type=int)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--expected-snapshot", required=True, type=Path)
    parser.add_argument("--require-threads", action="store_true")
    args = parser.parse_args()
    source = args.payload.resolve()
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    required = {"browser685-abi-probe", "lib/libstdc++.so.6", "lib/libgcc_s.so.1"}
    if set(manifest["files"]) != required:
        raise ValueError("Unexpected ABI payload")
    for name, item in manifest["files"].items():
        path = source / name
        if path.is_symlink() or path.stat().st_size != item["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("ABI source integrity differs")
    if "Shared library: [libstdc++.so.6]" not in (source / "probe-elf.txt").read_text(encoding="utf-8"):
        raise ValueError("Probe does not actually link the rebuilt C++ library")
    checksum = hashlib.sha256(json.dumps(manifest["files"], sort_keys=True).encode()).hexdigest()
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d-%H%M%S-%f")
    remote = AREA + "/abi/abi685-" + checksum[:16] + "-" + stamp
    out = WORKSPACE / "logs" / ("BrowserP011-ABI-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    (out / "input-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("LOG_DIR=" + str(out), flush=True)
    adb = Adb(args.transport, out)
    expected = json.loads(args.expected_snapshot.read_text(encoding="utf-8"))
    before, _ = adb.python("before", SNAPSHOT)
    if anchor(before) != anchor(expected):
        raise ValueError("Device boot/files/processes changed since the selected preflight")
    init = r'''
import os,stat
AREA='/mnt/data/p011-browser'; marker=AREA+'/.area-owner'
if not os.path.lexists(AREA):
 os.mkdir(AREA,0o755)
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.write(fd,b'p011.browser.area.v1\n');os.close(fd)
for p in ['/mnt','/mnt/data',AREA]:
 st=os.lstat(p)
 if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):raise ValueError('Redirected area')
s=os.lstat(marker)
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077:raise ValueError('Unsafe area marker')
with open(marker,'rb') as f:
 if f.read(128)!=b'p011.browser.area.v1\n':raise ValueError('Area ownership differs')
if os.path.lexists(REMOTE):raise ValueError('ABI run path already exists; preserve it')
for p in [AREA+'/abi',REMOTE,REMOTE+'/lib']:
 if not os.path.lexists(p):os.mkdir(p,0o755)
 s=os.lstat(p)
 if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Unsafe ABI directory')
print('RESULT='+repr({'area_verified':True,'remote':REMOTE}))
'''
    adb.python("create-owned-area", "REMOTE=" + repr(remote) + "\n" + init)
    for name in sorted(required):
        adb.run("push-" + name.replace("/", "-"), ["push", str(source / name), remote + "/" + name])
    verify = r'''
import os,hashlib,stat,subprocess
for name,item in FILES.items():
 p=REMOTE+'/'+name;s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_size!=item['bytes'] or s.st_uid!=0:raise ValueError('ABI file differs')
 with open(p,'rb') as f:h=hashlib.sha256(f.read()).hexdigest()
 if h!=item['sha256']:raise ValueError('ABI hash differs')
 os.chmod(p,0o755 if name=='browser685-abi-probe' else 0o644)
def low():
 os.setgroups([]);os.setgid(65534);os.setuid(65534)
p=subprocess.Popen([REMOTE+'/browser685-abi-probe'],cwd='/',env={'PATH':'/usr/bin:/bin','LANG':'C','LD_LIBRARY_PATH':REMOTE+'/lib'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=low)
try:a,b=p.communicate(timeout=5)
except subprocess.TimeoutExpired:
 p.kill();a,b=p.communicate(timeout=2)
print('RESULT='+repr({'child_exit':p.returncode,'stdout':a.decode('utf-8','replace'),'stderr':b.decode('utf-8','replace'),'uid':65534,'gid':65534,'remote':REMOTE}))
'''
    result, _ = adb.python("execute-low-uid-abi", "REMOTE=" + repr(remote) + "\nFILES=" + repr(manifest["files"]) + "\n" + verify)
    after, _ = adb.python("after", SNAPSHOT)
    events = probe_events(result["stdout"]) if result["child_exit"] == 0 else [{}, {}]
    payload, dynamic = events[:2]
    threads = events[2] if len(events) == 3 else None
    threads_passed = bool(threads and threads.get("thread_join") is True
                          and threads.get("future_value") == 685 and threads.get("async_value") == 685)
    passed = (result["child_exit"] == 0 and not result["stderr"] and payload.get("glibc") == "2.27"
              and payload.get("pointer_bytes") == 4 and payload.get("cpp17_optional_charconv") is True
              and dynamic.get("iostream") is True and dynamic.get("allocated_string_bytes", 0) > 128
              and (not args.require_threads or threads_passed)
              and anchor(before) == anchor(after))
    summary = {"scope": "DEVICE_CPP_ABI_ONLY_NO_QT_NO_CHROMIUM_NO_NETWORK", "passed": passed,
               "transport": args.transport, "manifest_sha256": checksum, "result": result,
               "threads_required": args.require_threads, "threads_passed": threads_passed,
               "stock_identity_unchanged": anchor(before) == anchor(after), "candidate_retained": remote,
               "before": before, "after": after}
    (out / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    target, sha = archive(out)
    print(json.dumps({k: v for k, v in summary.items() if k not in ("before", "after")}, ensure_ascii=False))
    print("RESULT_ZIP=" + str(target))
    print("ZIP_SHA256=" + sha)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
