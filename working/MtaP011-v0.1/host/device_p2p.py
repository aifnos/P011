"""Review-gated, finite owned P011 P2P-GO trial; never run on import.

First --freeze-only on HOST, review that exact immutable snapshot, then use
--execute-reviewed --frozen ... --expected-candidate ... . This script never
recovers, retries, reboots or cleans global resources. Timeout raw is retained.
Only symbolic results enter the public ZIP; private logs contain owned paths.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys
import zipfile

from device_probe import Adb, BASE, ROOT

NATIVE_PINS = {
    "mta-wpa-supplicant": "010f119b3cb9a8d7720e1ee57d83a92158628a68520d2010adde7bbe4b64518f",
    "mta-wifi-caps": "9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
}
SOURCE_NAMES = ("mta_send_wifi.py", "p011_json.py", "mta_safety.py")
EXPECTED_FILES = frozenset(["SOURCE.sha256"] + ["runtime/" + n for n in SOURCE_NAMES] +
                           ["native/" + n for n in NATIVE_PINS])
MAX_FILES = 5
MAX_MANIFEST_BYTES = 32768
MAX_SOURCE_BYTES = 512 * 1024
MAX_BINARY_BYTES = 32 * 1024 * 1024
STAGES = frozenset(("create_intent", "interface_created", "private_process_pre_exec",
                    "group_add_intent", "go_ready", "cleanup_intent",
                    "reconciled", "recovery_required"))


def _data(path, maximum):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or path.is_symlink() or value.st_size > maximum:
        raise ValueError("Unsafe or oversized local snapshot input")
    first = path.read_bytes()
    second = path.read_bytes()
    if first != second or len(first) != value.st_size:
        raise ValueError("Snapshot input changed while reading")
    return first


def freeze(destination):
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for name in sorted(SOURCE_NAMES):
        raw = _data(BASE / "runtime" / name, MAX_SOURCE_BYTES)
        tree = ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
        if name == "mta_send_wifi.py":
            pins = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "WPA_SHA256"
                            for target in node.targets) and isinstance(node.value, ast.Constant)]
            if pins != [NATIVE_PINS["mta-wpa-supplicant"]]:
                raise ValueError("Runtime private WPA pin changed; review required")
        records.append(("runtime/" + name, raw))
    for name, pin in sorted(NATIVE_PINS.items()):
        raw = _data(BASE / "native/private-p2p-candidate-20260930" / name, MAX_BINARY_BYTES)
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Native candidate differs from reviewed stable hash")
        if len(raw) < 20 or raw[:6] != b"\x7fELF\x01\x01" or raw[18:20] != b"\x28\x00":
            raise ValueError("Native candidate is not a little-endian ARM ELF32")
        records.append(("native/" + name, raw))
    if len(records) != MAX_FILES:
        raise ValueError("Unexpected candidate file count")
    lines = []
    for relative, raw in sorted(records):
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(raw)
        lines.append("%s %d %s\n" % (hashlib.sha256(raw).hexdigest(), len(raw), relative))
    manifest = "".join(lines).encode("ascii")
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("Candidate manifest limit")
    (destination / "SOURCE.sha256").write_bytes(manifest)
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    directory = Path(directory).resolve(strict=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Explicit frozen snapshot required")
    # This verifies files, byte sizes, exact set, source syntax and native pins.
    manifest = _data(directory / "SOURCE.sha256", MAX_MANIFEST_BYTES)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and expected != identity:
        raise ValueError("Reviewed candidate identity mismatch")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != MAX_FILES:
        raise ValueError("Candidate file count limit")
    seen = {"SOURCE.sha256"}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,9}) ((?:runtime|native)/[A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError("Invalid manifest")
        pin, length, relative = match.groups()
        if relative not in EXPECTED_FILES or relative in seen:
            raise ValueError("Unexpected or duplicated manifest file")
        seen.add(relative)
        raw = _data(directory / relative, MAX_SOURCE_BYTES if relative.startswith("runtime/") else MAX_BINARY_BYTES)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Frozen candidate content changed")
        if relative.startswith("runtime/"):
            ast.parse(raw.decode("utf-8"), filename=relative, feature_version=(3, 5))
        elif NATIVE_PINS.get(relative.split("/", 1)[1]) != pin:
            raise ValueError("Native binary is not the reviewed candidate")
    observed = set()
    for folder, directories, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in directories):
            raise ValueError("Linked candidate directory")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:
        raise ValueError("Unlisted frozen candidate files")
    return identity


PROBE = r'''
import hashlib,os,stat,subprocess,sys
from mta_send_wifi import ReadWriteNetlink,TRACKED,_proc_identity
def digest_bytes(value):return hashlib.sha256(value).hexdigest()
def status():
 process=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:
  output,error=process.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  process.kill();process.communicate();raise ValueError('readonly_status_timeout')
 if process.returncode or len(output)>16384:raise ValueError('readonly_status_failed')
 fields=dict(line.split('=',1) for line in output.decode('utf-8','replace').splitlines() if '=' in line)
 return {'completed':fields.get('wpa_state')=='COMPLETED','fingerprint':digest_bytes(output),
         'same_channel_2ghz':fields.get('freq') in [str(v) for v in range(2412,2473,5)]}
def network_processes():
 rows=[]
 for token in os.listdir('/proc'):
  if not token.isdigit():continue
  try:
   with open('/proc/'+token+'/comm') as handle:name=handle.read(128).strip()
   if name in TRACKED:
    row=_proc_identity(int(token))
    if row is not None:row['name']=name;rows.append(row)
  except OSError:pass
 return sorted(rows,key=lambda row:row['pid'])
def private_wpa_processes():
 rows=[]
 for token in os.listdir('/proc'):
  if not token.isdigit():continue
  row=_proc_identity(int(token))
  if row and row.get('exe','').startswith(AREA+'/candidates/') and row['exe'].endswith('/native/mta-wpa-supplicant'):
   rows.append(row)
 return sorted(rows,key=lambda row:row['pid'])
value={'target_ok':os.geteuid()==0 and os.uname()[4]=='armv7l' and tuple(sys.version_info[:3])==(3,5,5),
       'stock':stock_snapshot(),'stock_valid':False,'query_ok':False}
try:require_stock(value['stock']);value['stock_valid']=True
except Exception:pass
connection=None
try:
 value['wifi']=status();value['route_digest']=digest('/proc/net/route')
 value['network_processes']=network_processes()
 value['private_wpa_processes']=private_wpa_processes()
 value['no_private_wpa_processes']=not value['private_wpa_processes']
 with open('/proc/sys/kernel/random/boot_id') as handle:value['boot_id']=handle.read(128).strip()
 connection=ReadWriteNetlink()
 value['interfaces']=sorted(connection.interfaces(),key=lambda row:(row.get('phy',-1),row.get('wdev',-1),row.get('name','')))
 value['no_p2p_interfaces']=not any(row.get('iftype') in (8,9,10) for row in value['interfaces'])
 stations=[row for row in value['interfaces'] if row.get('name')=='wlan0']
 value['station_identity_ok']=len(stations)==1 and stations[0].get('iftype')==2
 value['query_ok']=True
except Exception as error:value['probe_error_class']=type(error).__name__
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(value))
'''


JOURNAL = r'''
import os,stat,sys
import p011_json as json
from mta_send_wifi import ReadWriteNetlink,_proc_identity,_owned_match
result={'present':False,'safe':False,'ownership_verified':False,'stage':'absent',
 'complete':False,'owned_process_gone':False,'owned_interface_gone':False,
 'identity_mismatch':False,'recover_review_ready':False}
path=RUN+'/p2p-lease.json';connection=None
try:
 owned_directory(RUN)
 if os.path.lexists(path):
  result['present']=True;value=os.lstat(path)
  if not stat.S_ISREG(value.st_mode) or os.path.islink(path) or value.st_uid!=os.getuid() or value.st_mode&0o077 or value.st_size>65536:
   raise ValueError('unsafe_journal')
  with open(path) as handle:record=json.loads(handle.read(65537))
  with open('/proc/sys/kernel/random/boot_id') as handle:boot=handle.read(128).strip()
  stage=record.get('stage')
  if record.get('version')!=1 or stage not in STAGES or not re.match(r'^mta[0-9a-f]{8}$',record.get('name','')):
   raise ValueError('invalid_journal_schema')
  if record.get('baseline',{}).get('boot_id')!=boot:raise ValueError('journal_boot_mismatch')
  owned=record.get('owned');process=record.get('process')
  def number(value,positive=False):return isinstance(value,int) and not isinstance(value,bool) and value>=(1 if positive else 0)
  if owned is not None:
   if not isinstance(owned,dict) or owned.get('name')!=record['name'] or owned.get('iftype')!=8 or any(not number(owned.get(k)) for k in ('phy','ifindex','wdev')):
    raise ValueError('invalid_owned_interface')
  if process is not None:
   if not isinstance(process,dict) or process.get('exe')!=BINARY or any(not number(process.get(k),True) for k in ('pid','starttime')):
    raise ValueError('invalid_owned_process')
  result['safe']=True;result['stage']=stage;result['ownership_verified']=True
  actual=_proc_identity(process['pid']) if process else None
  result['owned_process_gone']=actual is None
  if actual is not None and actual!=process:result['identity_mismatch']=True
  connection=ReadWriteNetlink();rows=connection.interfaces()
  named=[row for row in rows if row.get('name')==record['name']]
  result['owned_interface_gone']=not named
  if named and (owned is None or len(named)!=1 or not _owned_match(owned,named[0])):result['identity_mismatch']=True
  cleanup=record.get('cleanup_result',{})
  result['complete']=stage=='reconciled' and cleanup.get('complete') is True and result['owned_process_gone'] and result['owned_interface_gone']
  result['recover_review_ready']=not result['complete'] and not result['identity_mismatch']
except Exception as error:result['inspection_error_class']=type(error).__name__
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(result))
'''


PRIOR_JOURNALS = r'''
import os,stat
import p011_json as json
from mta_send_wifi import _proc_identity
root=AREA+'/sessions';blocked=0;seen=0;unsafe=0
if os.path.isdir(root):
 owned_directory(root)
 names=os.listdir(root)
 if len(names)>512:raise ValueError('session_directory_limit')
 for name in names:
  if not re.match(r'^mta-p2p-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$',name):continue
  seen+=1
  if seen>128:raise ValueError('prior_journal_limit')
  folder=root+'/'+name;path=folder+'/p2p-lease.json'
  try:
   owned_directory(folder)
   if not os.path.lexists(path):
    # Empty/host-aborted directories are harmless only if still empty.
    if os.listdir(folder):blocked+=1
    continue
   value=os.lstat(path)
   if not stat.S_ISREG(value.st_mode) or os.path.islink(path) or value.st_uid!=os.getuid() or value.st_mode&0o077 or value.st_size>65536:raise ValueError('unsafe_prior_journal')
   with open(path) as handle:record=json.loads(handle.read(65537))
   if record.get('version')!=1 or record.get('stage')!='reconciled' or record.get('cleanup_result',{}).get('complete') is not True:
    blocked+=1;continue
   process=record.get('process')
   if process and _proc_identity(process.get('pid',0)) is not None:blocked+=1
  except Exception:unsafe+=1
print('RESULT='+repr({'clear':blocked==0 and unsafe==0,'blocked_count':blocked,'unsafe_count':unsafe,'inspected_count':seen}))
'''


def remote_source(directory, safety, body, extra=""):
    source = "import sys\nsys.path.insert(0," + repr(directory + "/runtime") + ")\n" + safety
    source += "\nverify_candidate(" + repr(directory) + ")\n" + extra + "\n" + body
    ast.parse(source, feature_version=(3, 5))
    return source


def preflight_ok(value):
    return (isinstance(value, dict) and value.get("target_ok") is True and
            value.get("stock_valid") is True and value.get("query_ok") is True and
            value.get("no_private_wpa_processes") is True and
            value.get("no_p2p_interfaces") is True and value.get("station_identity_ok") is True and
            value.get("wifi", {}).get("completed") is True and
            value.get("wifi", {}).get("same_channel_2ghz") is True)


def parse_trial(raw):
    derived = raw.decode("utf-8", "replace").replace("\r\r\n", "\n").replace("\r\n", "\n")
    if len(raw) > 32768:
        raise ValueError("Trial output limit")
    matches = re.findall(r"^MTA_REMOTE_EXIT=([0-9]{1,3})$", derived, re.M)
    if len(matches) != 1:
        raise ValueError("Missing unique remote exit")
    events = []
    for line in derived.splitlines():
        if line.startswith("MTA_REMOTE_EXIT=") or not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or value.get("event") not in (
                "private_go_ready", "private_go_cleanup", "private_go_trial_failed"):
            raise ValueError("Unexpected trial event")
        events.append(value)
    if not 1 <= len(events) <= 4:
        raise ValueError("Trial event count")
    # Expose only fixed symbols/booleans, not arbitrary error or payload text.
    ready = [v for v in events if v["event"] == "private_go_ready"]
    cleanup = [v for v in events if v["event"] == "private_go_cleanup"]
    return {"remote_exit_zero": matches[0] == "0",
            "go_ready_event": len(ready) == 1 and ready[0].get("ttl") == 20,
            "cleanup_event": len(cleanup) == 1,
            "cleanup_complete": bool(cleanup and cleanup[-1].get("complete") is True),
            "owned_process_removed_reported": bool(cleanup and cleanup[-1].get("owned_process_removed") is True),
            "owned_interface_removed_reported": bool(cleanup and cleanup[-1].get("owned_interface_removed") is True),
            "stock_baseline_equal_reported": bool(cleanup and cleanup[-1].get("stock_baseline_equal") is True),
            "trial_failed_event": any(v["event"] == "private_go_trial_failed" for v in events)}


def run_reviewed(frozen, expected, output=None):
    identity = verify_frozen(frozen, expected)
    frozen = Path(frozen).resolve()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-DeviceP2p-" + stamp + "-" + suffix)
    out.mkdir(parents=True, exist_ok=False)
    safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8")
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    run = "/mnt/data/p011-toolbox/sessions/mta-p2p-" + stamp + "-" + suffix
    report = {"evidence_level": "P011_PRIVATE_P2P_GO_TRIAL", "pass": False,
              "candidate_identity": identity, "ttl_seconds": 20, "rf_trial_invoked": False,
              "global_service_changes": False, "recovery_invoked": False, "retry_invoked": False,
              "dhcp_or_ip_configuration": False, "phone_interop": "NOT_TESTED",
              "ui_started": False, "user_files_accessed": False,
              "next_step": "REVIEW_RESULT_BEFORE_ANY_NEW_TRIAL"}
    adb = None
    before = None
    after = None
    journal = None
    stage = "target"
    try:
        adb = Adb(out / "private-raw")
        # First gate uses inline frozen safety; no candidate or run directory yet.
        initial = adb.python("initial-stock", safety + "\ns=stock_snapshot();require_stock(s);print('RESULT=True')")
        if initial is not True:
            raise ValueError("Initial stock gate failed")
        stage = "candidate"
        create = safety + "\np=" + repr(target) + "\nowned_directory(p,True)\nprint('RESULT='+repr(bool(os.listdir(p))))"
        present = adb.python("candidate-directory", create)
        if not present:
            for folder in ("runtime", "native"):
                adb.python("candidate-subdir", safety + "\nowned_directory(" + repr(target + "/" + folder) + ",True)\nprint('RESULT=True')")
            for relative in sorted(EXPECTED_FILES):
                adb.run("push-candidate", ["push", str(frozen / relative), target + "/" + relative])
        # Never overwrite old candidates; verify before chmod or any RF.
        candidate_check = safety + "\nbase=" + repr(target) + "\nverify_candidate(base)\n"
        candidate_check += "assert digest(base+'/SOURCE.sha256')==" + repr(hashlib.sha256((frozen / "SOURCE.sha256").read_bytes()).hexdigest()) + "\n"
        candidate_check += "pins=" + repr(NATIVE_PINS) + "\n"
        candidate_check += "for name,pin in pins.items():\n assert digest(base+'/native/'+name)==pin\n os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        adb.python("verify-pinned-candidate", candidate_check)
        stage = "prior_journals"
        prior = adb.python("prior-journals-readonly", remote_source(target, safety, PRIOR_JOURNALS))
        report["prior_journals_clear"] = prior.get("clear") is True
        if not report["prior_journals_clear"]:
            report["next_step"] = "REVIEW_PRIVATE_PRIOR_JOURNAL_BEFORE_NEW_TRIAL"
            raise ValueError("Prior journal blocks a new trial")
        stage = "network_baseline"
        before = adb.python("before-independent", remote_source(target, safety, PROBE))
        report["preflight_passed"] = preflight_ok(before)
        if not report["preflight_passed"]:
            raise ValueError("P011 network preflight failed")
        stage = "owned_run_directory"
        create_run = safety + "\np=" + repr(run) + "\nassert not os.path.lexists(p)\nowned_directory(p,True)\n"
        create_run += "assert os.stat(p).st_mode&0o777==0o700\nprint('RESULT=True')"
        adb.python("new-owned-run-directory", create_run)
        stage = "trial"
        argv = ["python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial",
                "--run-dir", run, "--binary", target + "/native/mta-wpa-supplicant",
                "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20"]
        command = " ".join(shlex.quote(v) for v in argv)
        command += "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
        report["rf_trial_invoked"] = True
        raw = adb.run("finite-owned-p2p-trial", ["shell", command], timeout=55)
        report.update(parse_trial(raw))
    except Exception as error:
        report["error_stage"] = stage
        report["error_class"] = type(error).__name__
    finally:
        if adb is not None:
            try:
                after = adb.python("after-independent", remote_source(target, safety, PROBE))
            except Exception as error:
                report["after_check_error_class"] = type(error).__name__
            try:
                extra = "RUN=" + repr(run) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\nSTAGES=" + repr(tuple(sorted(STAGES))) + "\n"
                journal = adb.python("owned-journal-readonly", remote_source(target, safety, JOURNAL, extra))
                # No paths, addresses, original names, PSK or raw text are public.
                for name in ("present", "safe", "ownership_verified", "complete", "owned_process_gone",
                             "owned_interface_gone", "identity_mismatch", "recover_review_ready"):
                    report["journal_" + name] = journal.get(name) is True
                report["journal_stage"] = journal.get("stage") if journal.get("stage") in STAGES else "absent_or_invalid"
                if report["rf_trial_invoked"] and not journal.get("complete"):
                    report["next_step"] = ("REVIEW_OWNED_JOURNAL_FOR_EXPLICIT_RECOVERY" if journal.get("recover_review_ready")
                                           else "READONLY_OWNERSHIP_REVIEW_REQUIRED")
            except Exception as error:
                report["journal_check_error_class"] = type(error).__name__
                if report["rf_trial_invoked"]:
                    report["next_step"] = "READONLY_OWNERSHIP_REVIEW_REQUIRED"
        report["stock_independent_unchanged"] = bool(before and after and before.get("stock") == after.get("stock") and
                                                     before.get("stock_valid") and after.get("stock_valid"))
        report["wifi_completed_after"] = bool(after and after.get("wifi", {}).get("completed"))
        queries_ok = bool(before and after and before.get("query_ok") is True and after.get("query_ok") is True)
        report["wifi_state_fingerprint_unchanged"] = queries_ok and before.get("wifi") == after.get("wifi")
        report["route_digest_unchanged"] = queries_ok and before.get("route_digest") == after.get("route_digest")
        report["network_processes_unchanged"] = queries_ok and before.get("network_processes") == after.get("network_processes")
        report["interface_identities_unchanged"] = queries_ok and before.get("interfaces") == after.get("interfaces")
        report["no_p2p_interfaces_after"] = bool(after and after.get("no_p2p_interfaces") is True)
        report["no_private_wpa_processes_after"] = bool(after and after.get("no_private_wpa_processes") is True)
        gates = ("rf_trial_invoked", "preflight_passed", "remote_exit_zero", "go_ready_event", "cleanup_event",
                 "cleanup_complete", "owned_process_removed_reported", "owned_interface_removed_reported",
                 "stock_baseline_equal_reported", "stock_independent_unchanged", "wifi_completed_after",
                 "wifi_state_fingerprint_unchanged", "route_digest_unchanged", "network_processes_unchanged",
                 "interface_identities_unchanged", "no_p2p_interfaces_after", "no_private_wpa_processes_after", "journal_complete",
                 "journal_owned_process_gone", "journal_owned_interface_gone")
        report["pass"] = all(report.get(name) is True for name in gates) and "error_class" not in report
        if report["pass"]:
            report["next_step"] = "REVIEW_GO_ONLY_EVIDENCE_DHCP_AND_PHONE_NOT_TESTED"
        if journal and journal.get("recover_review_ready"):
            # This command is private and advisory only; it is NEVER executed.
            recovery = " ".join(shlex.quote(v) for v in (
                "python3", "-B", target + "/runtime/mta_send_wifi.py", "--recover", "--run-dir", run,
                "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps"))
            (out / "private-next-steps.txt").write_text(
                "Review raw/journal ownership before authorizing this explicit owned-only recovery.\n"
                "Do not start another trial or use global cleanup. This script did not recover.\n" + recovery + "\n", encoding="utf-8")
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text(
        "有限 P011 owned P2P GO 试验，TTL20秒；需显式review后执行，非正式发送功能。\n"
        "原厂hash/进程、wlan0状态指纹、路由、GET_INTERFACE及owned journal独立核验。\n"
        "失败或超时只保留私有原始输出并只读检查；不重启、自动恢复、重试或全局清理。\n"
        "无 DHCP/IP 配置、BLE/UI/用户文件/手机互传。sanitized.zip白名单只result.json与README.txt。\n"
        "路径、SSID/MAC/IP/PSK与private-next-steps/private-raw绝不入ZIP。\n", encoding="utf-8")
    archive = out.with_suffix(".sanitized.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):
            bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true", help="HOST-only freeze, no ADB or device access")
    mode.add_argument("--execute-reviewed", action="store_true", help="Explicit finite RF action after snapshot review")
    parser.add_argument("--frozen", type=Path)
    parser.add_argument("--expected-candidate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:
            parser.error("freeze-only does not accept an execution snapshot")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False)
        frozen = out / "private-candidate"
        identity = freeze(frozen)
        safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8")
        for body in (PROBE, PRIOR_JOURNALS):
            remote_source("/mnt/data/p011-toolbox/candidates/mta-01-" + identity, safety, body)
        remote_source("/mnt/data/p011-toolbox/candidates/mta-01-" + identity, safety, JOURNAL,
                      "RUN='/mnt/data/p011-toolbox/sessions/mta-p2p-20000101-000000-00000000'\nBINARY='fixture'\nSTAGES=" + repr(tuple(STAGES)))
        print("HOST_ONLY_FREEZE_PASS")
        print("CANDIDATE_ID=" + identity)
        print("FROZEN_DIRECTORY=" + str(frozen))
        print("No ADB or RF operation was performed. Review the frozen sources before --execute-reviewed.")
        return 0
    if args.frozen is None or not re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or ""):
        parser.error("execute-reviewed requires --frozen and its reviewed --expected-candidate")
    report, out, archive = run_reviewed(args.frozen, args.expected_candidate, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("RESULT_DIR=" + str(out))
    print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
