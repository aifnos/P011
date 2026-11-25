"""Explicit V2 frozen owned P011 GO trial; importing/freezing performs no ADB/RF.

This separate entry point never changes the V1 script/candidate or old FAILs.
Only root may execute a reviewed immutable identity. No retry/recover/reboot or
global cleanup is implemented; all raw/IPv6/journal information stays private.
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
from device_p2p import _data, remote_source, STAGES

RUNTIME_SHA256 = "e7222f0ed14589789faf0fc7d6857269a664264ade9ccf0b46d2c991e9b8b3c6"
NATIVE_DIRECTORY = "native/private-p2p-candidate-20261001-v2"
NATIVE_PINS = {
    "mta-wpa-supplicant": "e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
    "mta-wifi-caps": "9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
}
SOURCE_NAMES = ("mta_send_wifi.py", "p011_json.py", "mta_safety.py")
PAYLOAD_FILES = frozenset(["runtime/" + n for n in SOURCE_NAMES] + ["native/" + n for n in NATIVE_PINS])
EXPECTED_FILES = PAYLOAD_FILES | {"SOURCE.sha256"}
MAX_MANIFEST_BYTES = 32768
MAX_SOURCE_BYTES = 512 * 1024
MAX_BINARY_BYTES = 32 * 1024 * 1024
DIAGNOSTIC_STAGES = {1: "init_enter", 2: "capability", 3: "early_param", 4: "initial_type_gate",
                     5: "initial_mode", 6: "interface_up", 7: "driver_finish", 8: "driver_failed",
                     9: "driver_deinit", 10: "go_deinit_preserved", 11: "client_deinit_preserved",
                     12: "driver_init_result", 13: "wps_init", 14: "eapol_init",
                     15: "control_init", 16: "p2p_init"}
INIT_REQUIRED = frozenset(DIAGNOSTIC_STAGES[n] for n in (1, 3, 4, 5, 6, 7, 12, 16))


def _source_checks(name, raw):
    tree = ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
    if name == "mta_send_wifi.py":
        if hashlib.sha256(raw).hexdigest() != RUNTIME_SHA256:
            raise ValueError("Runtime V2 source differs from stable reviewed hash")
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("WPA_SHA256", "DEVICE_LOCK", "DEVICE_PENDING"):
                        constants[target.id] = ast.literal_eval(node.value)
        if constants != {"WPA_SHA256": NATIVE_PINS["mta-wpa-supplicant"],
                         "DEVICE_LOCK": "/tmp/p011-mta-p2p-device.lock",
                         "DEVICE_PENDING": "/tmp/p011-mta-p2p-device.pending"}:
            raise ValueError("Runtime V2 ownership pins do not match")


def _plain_directory(directory):
    directory = Path(directory).absolute()
    for parent in [directory] + list(directory.parents):
        if parent.is_symlink():
            raise ValueError("Linked frozen ancestor")
    if not directory.is_dir():
        raise ValueError("Explicit frozen directory required")
    return directory.resolve(strict=True)


def freeze(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for name in sorted(SOURCE_NAMES):
        raw = _data(BASE / "runtime" / name, MAX_SOURCE_BYTES)
        _source_checks(name, raw)
        if name == "mta_send_wifi.py" and raw != _data(BASE / NATIVE_DIRECTORY / "runtime" / name, MAX_SOURCE_BYTES):
            raise ValueError("Runtime candidate copy is not the stable V2 source")
        records.append(("runtime/" + name, raw))
    for name, pin in sorted(NATIVE_PINS.items()):
        raw = _data(BASE / NATIVE_DIRECTORY / name, MAX_BINARY_BYTES)
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Native V2 differs from reviewed stable hash")
        if len(raw) < 20 or raw[:6] != b"\x7fELF\x01\x01" or raw[18:20] != b"\x28\x00":
            raise ValueError("Native V2 is not ARM ELF32 little endian")
        records.append(("native/" + name, raw))
    if len(records) != 5:
        raise ValueError("V2 payload count")
    lines = []
    for relative, raw in sorted(records):
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(raw)
        lines.append("%s %d %s\n" % (hashlib.sha256(raw).hexdigest(), len(raw), relative))
    (destination / "SOURCE.sha256").write_bytes("".join(lines).encode("ascii"))
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    directory = _plain_directory(directory)
    manifest = _data(directory / "SOURCE.sha256", MAX_MANIFEST_BYTES)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and expected != identity:
        raise ValueError("Reviewed V2 identity mismatch")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != 5:
        raise ValueError("V2 exact five payloads required")
    seen = {"SOURCE.sha256"}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,9}) ((?:runtime|native)/[A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError("V2 manifest format")
        pin, length, relative = match.groups()
        if relative not in PAYLOAD_FILES or relative in seen:
            raise ValueError("Unexpected or duplicate V2 payload")
        seen.add(relative)
        raw = _data(directory / relative, MAX_SOURCE_BYTES if relative.startswith("runtime/") else MAX_BINARY_BYTES)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("V2 frozen content changed")
        if relative.startswith("runtime/"):
            _source_checks(relative.split("/", 1)[1], raw)
        elif NATIVE_PINS[relative.split("/", 1)[1]] != pin:
            raise ValueError("V2 native pin")
    observed = set()
    for folder, directories, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in directories):
            raise ValueError("Linked V2 folder")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:
        raise ValueError("V2 unlisted files")
    return identity


# No LinuxBackend/DeviceGuard/JournalLock construction: these independent probes
# do not create/acquire a lock or pending marker, or invoke any write operation.
READ_HELPERS = r'''
import hashlib,os,re,stat,subprocess,sys
import p011_json as json
from mta_send_wifi import ReadWriteNetlink,TRACKED,_proc_identity,DEVICE_LOCK,DEVICE_PENDING
def bounded(path,maximum=1048576):
 with open(path,'rb') as handle:blob=handle.read(maximum+1)
 if len(blob)>maximum:raise ValueError('readonly_byte_limit')
 return blob
def hashbytes(blob):return hashlib.sha256(blob).hexdigest()
def private_folder(path):
 owned_directory(path);value=os.lstat(path)
 if not stat.S_ISDIR(value.st_mode) or value.st_uid!=os.getuid() or value.st_mode&0o077:raise ValueError('unsafe_private_folder')
def private_record(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>65536:
   raise ValueError('unsafe_private_record')
  with os.fdopen(fd,'r') as handle:
   fd=None;record=json.loads(handle.read(65537))
  if not isinstance(record,dict):raise ValueError('invalid_private_record')
  return record
 finally:
  if fd is not None:os.close(fd)
def numbers(row,fields,positive=False):
 return isinstance(row,dict) and all(isinstance(row.get(k),int) and not isinstance(row[k],bool) and row[k]>=(1 if positive else 0) for k in fields)
def pending_readonly():
 result={'present':os.path.lexists(DEVICE_PENDING),'safe':True,'valid':True}
 if result['present']:
  result['safe']=False;result['valid']=False
  record=private_record(DEVICE_PENDING);result['safe']=True
  with open('/proc/sys/kernel/random/boot_id') as handle:boot=handle.read(128).strip()
  result['valid']=set(record)=={'version','journal','boot_id','candidate_sha256'} and isinstance(record.get('version'),int) and not isinstance(record['version'],bool) and record['version']==2 and record.get('boot_id')==boot and record.get('candidate_sha256')==WPA_PIN and isinstance(record.get('journal'),str) and re.match('^'+re.escape(AREA)+r'/sessions/mta-p2p-v2-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}/p2p-lease[.]json\Z',record['journal']) is not None
 if os.path.lexists(DEVICE_LOCK):
  value=os.lstat(DEVICE_LOCK)
  result['lock_safe']=stat.S_ISREG(value.st_mode) and not os.path.islink(DEVICE_LOCK) and value.st_uid==os.getuid() and value.st_mode&0o077==0
 else:result['lock_safe']=True
 return result
def actors_and_network():
 network=[];private=[];actors=[]
 for token in os.listdir('/proc'):
  if not token.isdigit():continue
  try:
   row=_proc_identity(int(token))
   if row is None:continue
   with open('/proc/'+token+'/comm') as handle:name=handle.read(128).strip()
   args=bounded('/proc/'+token+'/cmdline',65536).split(b'\0')
   if name in TRACKED:
    row['name']=name;row['cmdline_digest']=hashbytes(b'\0'.join(args));network.append(row)
   exe=row.get('exe','').replace(' (deleted)','')
   if exe.startswith(AREA+'/candidates/') and exe.endswith('/native/mta-wpa-supplicant'):private.append(row)
   if any(v.startswith((AREA+'/candidates/').encode('ascii')) and v.endswith(b'/runtime/mta_send_wifi.py') for v in args) and (b'--trial' in args or b'--recover' in args):actors.append(row)
  except OSError:pass
 return sorted(network,key=lambda v:v['pid']),private,actors
'''

PROBE = READ_HELPERS + r'''
value={'target_ok':os.geteuid()==0 and os.uname()[4]=='armv7l' and tuple(sys.version_info[:3])==(3,5,5),
 'stock':stock_snapshot(),'stock_valid':False,'query_ok':False}
try:require_stock(value['stock']);value['stock_valid']=True
except Exception:pass
connection=None
try:
 process=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:output,error=process.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  process.kill();process.communicate();raise ValueError('readonly_status_timeout')
 if process.returncode or len(output)>16384:raise ValueError('readonly_status_failed')
 fields=dict(line.split('=',1) for line in output.decode('utf-8','replace').splitlines() if '=' in line)
 value['wifi']={'completed':fields.get('wpa_state')=='COMPLETED','fingerprint':hashbytes(output),
  'same_channel_2ghz':fields.get('freq') in [str(v) for v in range(2412,2473,5)]}
 value['route_digest']=hashbytes(bounded('/proc/net/route'))
 value['ipv6_addresses_raw']=bounded('/proc/net/if_inet6');value['ipv6_routes_raw']=bounded('/proc/net/ipv6_route')
 value['ipv6_address_digest']=hashbytes(value['ipv6_addresses_raw']);value['ipv6_route_digest']=hashbytes(value['ipv6_routes_raw'])
 value['network_processes'],value['private_wpa_processes'],value['project_trial_actors']=actors_and_network()
 value['no_private_wpa_processes']=not value['private_wpa_processes'];value['no_project_trial_actors']=not value['project_trial_actors']
 with open('/proc/sys/kernel/random/boot_id') as handle:value['boot_id']=handle.read(128).strip()
 value['pending']=pending_readonly()
 connection=ReadWriteNetlink();value['interfaces']=sorted(connection.interfaces(),key=lambda row:(row.get('phy',-1),row.get('wdev',-1),row.get('name','')))
 value['no_p2p_interfaces']=not any(row.get('iftype') in (8,9,10) for row in value['interfaces'])
 value['no_project_mta_interfaces']=not any(re.match(r'^mta[0-9a-f]{8}\Z',row.get('name','')) for row in value['interfaces'])
 stations=[row for row in value['interfaces'] if row.get('name')=='wlan0']
 value['station_identity_ok']=len(stations)==1 and stations[0].get('iftype')==2
 value['query_ok']=True
except Exception:value['probe_failed']=True
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(value))
'''

PRIOR_JOURNALS = READ_HELPERS + r'''
root=AREA+'/sessions';blocked=0;seen=0;unsafe=0
pending=pending_readonly()
if os.path.isdir(root):
 private_folder(root);names=os.listdir(root)
 if len(names)>512:raise ValueError('session_directory_limit')
 for name in names:
  if not re.match(r'^mta-p2p-(?:v2-)?[0-9]{8}-[0-9]{6}-[0-9a-f]{8}\Z',name):continue
  seen+=1
  if seen>128:raise ValueError('prior_journal_limit')
  folder=root+'/'+name;path=folder+'/p2p-lease.json'
  try:
   private_folder(folder)
   if not os.path.lexists(path):
    if os.listdir(folder):blocked+=1
    continue
   record=private_record(path)
   if not isinstance(record.get('version'),int) or record['version'] not in (1,2) or isinstance(record['version'],bool) or record.get('stage')!='reconciled' or record.get('cleanup_result',{}).get('complete') is not True:
    blocked+=1;continue
   if not re.match(r'^mta[0-9a-f]{8}\Z',record.get('name','')):raise ValueError('prior_name_invalid')
   owned=record.get('owned');process=record.get('process')
   if owned is not None and (not numbers(owned,('phy','ifindex','wdev')) or owned.get('name')!=record['name'] or owned.get('iftype')!=8):raise ValueError('prior_owned_invalid')
   if process is not None:
    if not numbers(process,('pid','starttime'),True) or not isinstance(process.get('exe'),str) or not process['exe'].startswith(AREA+'/candidates/') or not process['exe'].endswith('/native/mta-wpa-supplicant'):raise ValueError('prior_process_invalid')
    if _proc_identity(process['pid']) is not None:blocked+=1
   if record['version']==2:
    baseline=record.get('baseline',{})
    if not isinstance(baseline.get('interfaces'),list) or any(not isinstance(baseline.get(k),str) or re.match(r'^[0-9a-f]{64}\Z',baseline[k]) is None for k in ('route_digest','ipv6_route_digest','ipv6_address_digest')):raise ValueError('prior_v2_baseline_invalid')
  except Exception:unsafe+=1
print('RESULT='+repr({'clear':blocked==0 and unsafe==0 and not pending['present'] and pending['safe'] and pending['lock_safe'],
 'blocked_count':blocked,'unsafe_count':unsafe,'inspected_count':seen,'global_pending_clear':not pending['present']}))
'''

JOURNAL = READ_HELPERS + r'''
result={'present':False,'safe':False,'ownership_verified':False,'stage':'absent','complete':False,
 'owned_process_gone':False,'owned_interface_gone':False,'identity_mismatch':False,'recover_review_ready':False,
 'version2':False,'ipv6_baseline_present':False,'pending_clear':False,'baseline_independent_match':False}
path=RUN+'/p2p-lease.json';connection=None
try:
 private_folder(RUN);pending=pending_readonly();result['pending_clear']=not pending['present'] and pending['safe'] and pending['lock_safe']
 if os.path.lexists(path):
  result['present']=True;record=private_record(path)
  with open('/proc/sys/kernel/random/boot_id') as handle:boot=handle.read(128).strip()
  stage=record.get('stage');baseline=record.get('baseline',{})
  if not isinstance(record.get('version'),int) or record['version']!=2 or isinstance(record['version'],bool) or stage not in STAGES or not re.match(r'^mta[0-9a-f]{8}\Z',record.get('name','')):raise ValueError('invalid_v2_journal')
  result['version2']=True
  if baseline.get('boot_id')!=boot or not isinstance(baseline.get('interfaces'),list) or any(not isinstance(baseline.get(k),str) or re.match(r'^[0-9a-f]{64}\Z',baseline[k]) is None for k in ('route_digest','ipv6_route_digest','ipv6_address_digest')):raise ValueError('invalid_v2_baseline')
  result['ipv6_baseline_present']=True
  owned=record.get('owned');process=record.get('process')
  if owned is not None and (not numbers(owned,('phy','ifindex','wdev')) or owned.get('name')!=record['name'] or owned.get('iftype')!=8):raise ValueError('invalid_owned')
  if process is not None and (not numbers(process,('pid','starttime'),True) or process.get('exe')!=BINARY):raise ValueError('invalid_process')
  result['safe']=True;result['stage']=stage;result['ownership_verified']=True
  actual=_proc_identity(process['pid']) if process else None;result['owned_process_gone']=actual is None
  if actual is not None and actual!=process:result['identity_mismatch']=True
  connection=ReadWriteNetlink();rows=connection.interfaces()
  matched=[r for r in rows if r.get('name')==record['name'] or owned is not None and r.get('wdev')==owned['wdev']]
  result['owned_interface_gone']=not matched
  if matched and (owned is None or len(matched)!=1 or not all(matched[0].get(k)==owned.get(k) for k in ('name','ifindex','wdev','phy')) or matched[0].get('iftype') not in (2,8,9)):result['identity_mismatch']=True
  network,private,actors=actors_and_network()
  for row in network:row.pop('name',None)
  result['baseline_independent_match']=not private and not actors and baseline.get('processes')==network and baseline['interfaces']==sorted(rows,key=lambda r:r['wdev']) and baseline['route_digest']==hashbytes(bounded('/proc/net/route')) and baseline['ipv6_route_digest']==hashbytes(bounded('/proc/net/ipv6_route')) and baseline['ipv6_address_digest']==hashbytes(bounded('/proc/net/if_inet6'))
  result['complete']=stage=='reconciled' and record.get('cleanup_result',{}).get('complete') is True and result['owned_process_gone'] and result['owned_interface_gone'] and result['pending_clear'] and result['baseline_independent_match']
  result['recover_review_ready']=not result['complete'] and not result['identity_mismatch'] and result['owned_process_gone']
except Exception:result['inspection_failed']=True
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(result))
'''


def probe_source(target, safety, body, extra=""):
    return remote_source(target, safety, body, "WPA_PIN=" + repr(NATIVE_PINS["mta-wpa-supplicant"]) + "\n" + extra)


def preflight_ok(value):
    if not isinstance(value, dict):
        return False
    flags = ("target_ok", "stock_valid", "query_ok", "no_private_wpa_processes", "no_project_trial_actors",
             "no_p2p_interfaces", "no_project_mta_interfaces", "station_identity_ok")
    return (all(value.get(k) is True for k in flags) and value.get("wifi", {}).get("completed") is True and
            value.get("wifi", {}).get("same_channel_2ghz") is True and value.get("pending", {}).get("present") is False and
            value.get("pending", {}).get("safe") is True and value.get("pending", {}).get("lock_safe") is True)


def _strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate trial JSON field")
        out[key] = value
    return out


def parse_trial(raw):
    if not isinstance(raw, bytes) or len(raw) > 32768:
        raise ValueError("V2 trial output limit")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    matches = re.findall(r"^MTA_REMOTE_EXIT=([0-9]{1,3})$", derived, re.M)
    if len(matches) != 1:
        raise ValueError("Unique V2 remote exit required")
    events = []
    for line in derived.splitlines():
        if line.startswith("MTA_REMOTE_EXIT=") or not line.strip():
            continue
        value = json.loads(line, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or value.get("event") not in ("private_go_ready", "private_go_cleanup", "private_go_trial_failed"):
            raise ValueError("Unexpected V2 trial event")
        events.append(value)
    if not 1 <= len(events) <= 4:
        raise ValueError("V2 event count")
    ready = [v for v in events if v["event"] == "private_go_ready"]
    cleanup = [v for v in events if v["event"] == "private_go_cleanup"]
    failed = [v for v in events if v["event"] == "private_go_trial_failed"]
    final = events[-1]
    diagnostics = final.get("diagnostics")
    if not isinstance(diagnostics, dict) or set(diagnostics) != {"events", "diagnostic_invalid", "raw_diagnostics_not_logged"} or not isinstance(diagnostics["diagnostic_invalid"], bool) or diagnostics["raw_diagnostics_not_logged"] is not True:
        raise ValueError("V2 diagnostic envelope")
    rows = diagnostics["events"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("V2 diagnostic count")
    safe_rows = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"stage", "code"} or row["stage"] not in DIAGNOSTIC_STAGES.values() or isinstance(row["code"], bool) or not isinstance(row["code"], int) or not -4095 <= row["code"] <= 4095:
            raise ValueError("V2 diagnostic whitelist")
        safe_rows.append({"stage": row["stage"], "code": row["code"]})
    for item in ready:
        if set(item) != {"event", "ttl", "credentials_not_logged"} or isinstance(item["ttl"], bool) or item["ttl"] != 20 or item["credentials_not_logged"] is not True:
            raise ValueError("V2 ready fields")
    for item in cleanup:
        required = {"event", "owned_process_removed", "owned_interface_removed", "stock_baseline_equal", "complete"}
        if not required.issubset(item) or set(item) - required - {"diagnostics", "independent_readback"} or any(not isinstance(item[k], bool) for k in required - {"event"}):
            raise ValueError("V2 cleanup fields")
    for item in failed:
        # Error details stay private; only the fixed trial_failed boolean is public.
        if set(item) != {"event", "reason", "cleanup", "complete", "diagnostics"} or item["complete"] is not False or not isinstance(item["reason"], str) or len(item["reason"]) > 256 or not isinstance(item["cleanup"], dict):
            raise ValueError("V2 failure fields")
    zeros = {row["stage"] for row in safe_rows if row["code"] == 0}
    init_ok = INIT_REQUIRED.issubset(zeros) and all(row["code"] == 0 for row in safe_rows if row["stage"] in INIT_REQUIRED)
    return {"remote_exit_zero": matches[0] == "0", "go_ready_event": len(ready) == 1,
            "cleanup_event": len(cleanup) == 1, "cleanup_complete": bool(cleanup and cleanup[-1]["complete"] is True),
            "owned_process_removed_reported": bool(cleanup and cleanup[-1]["owned_process_removed"] is True),
            "owned_interface_removed_reported": bool(cleanup and cleanup[-1]["owned_interface_removed"] is True),
            "stock_baseline_equal_reported": bool(cleanup and cleanup[-1]["stock_baseline_equal"] is True),
            "trial_failed_event": bool(failed), "diagnostics_valid": diagnostics["diagnostic_invalid"] is False,
            "early_init_success_reported": init_ok, "diagnostic_events": safe_rows}


def add_independent_gates(report, before, after, journal):
    ok = bool(before and after and before.get("query_ok") is True and after.get("query_ok") is True)
    report["stock_independent_unchanged"] = bool(ok and before.get("stock_valid") is True and after.get("stock_valid") is True and before.get("stock") == after.get("stock"))
    mapping = {"wifi_state_fingerprint_unchanged": "wifi", "route_digest_unchanged": "route_digest",
               "ipv6_address_digest_unchanged": "ipv6_address_digest", "ipv6_route_digest_unchanged": "ipv6_route_digest",
               "network_processes_unchanged": "network_processes", "interface_identities_unchanged": "interfaces", "same_boot": "boot_id"}
    for flag, field in mapping.items():
        report[flag] = bool(ok and field in before and field in after and before[field] == after[field])
    report["full_ipv6_readback_unchanged"] = bool(ok and all(isinstance(before.get(k), bytes) and isinstance(after.get(k), bytes) and before[k] == after[k] for k in ("ipv6_addresses_raw", "ipv6_routes_raw")))
    report["wifi_completed_after"] = bool(after and after.get("wifi", {}).get("completed") is True)
    for field in ("no_p2p_interfaces", "no_project_mta_interfaces", "no_private_wpa_processes", "no_project_trial_actors"):
        report[field + "_after"] = bool(after and after.get(field) is True)
    pending = after.get("pending", {}) if after else {}
    report["global_pending_clear_independent"] = pending.get("present") is False and pending.get("safe") is True and pending.get("lock_safe") is True
    for name in ("present", "safe", "ownership_verified", "complete", "owned_process_gone", "owned_interface_gone", "identity_mismatch", "recover_review_ready", "version2", "ipv6_baseline_present", "pending_clear", "baseline_independent_match"):
        report["journal_" + name] = bool(journal and journal.get(name) is True)
    report["journal_stage"] = journal.get("stage") if journal and journal.get("stage") in STAGES else "absent_or_invalid"
    gates = ("rf_trial_invoked", "preflight_passed", "prior_journals_clear", "remote_exit_zero", "go_ready_event", "cleanup_event", "cleanup_complete",
             "owned_process_removed_reported", "owned_interface_removed_reported", "stock_baseline_equal_reported", "diagnostics_valid", "early_init_success_reported",
             "stock_independent_unchanged", "wifi_completed_after", "wifi_state_fingerprint_unchanged", "route_digest_unchanged", "ipv6_address_digest_unchanged", "ipv6_route_digest_unchanged",
             "full_ipv6_readback_unchanged", "same_boot", "network_processes_unchanged", "interface_identities_unchanged", "no_p2p_interfaces_after", "no_project_mta_interfaces_after",
             "no_private_wpa_processes_after", "no_project_trial_actors_after", "global_pending_clear_independent", "journal_complete", "journal_version2", "journal_ipv6_baseline_present", "journal_pending_clear", "journal_baseline_independent_match",
             "journal_owned_process_gone", "journal_owned_interface_gone")
    report["pass"] = all(report.get(k) is True for k in gates) and report.get("trial_failed_event") is False and not report.get("host_or_parse_error")


def run_reviewed(frozen, expected, output=None):
    identity = verify_frozen(frozen, expected)
    frozen = _plain_directory(frozen)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); suffix = secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-DeviceP2pV2-" + stamp + "-" + suffix)
    out.mkdir(parents=True, exist_ok=False)
    safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8")
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    run = "/mnt/data/p011-toolbox/sessions/mta-p2p-v2-" + stamp + "-" + suffix
    report = {"evidence_level": "P011_PRIVATE_P2P_V2_GO_TRIAL", "pass": False, "candidate_identity": identity,
              "journal_version": 2, "ttl_seconds": 20, "rf_trial_invoked": False, "global_service_changes": False,
              "recovery_invoked": False, "retry_invoked": False, "dhcp_or_ip_configuration": False,
              "phone_interop": "NOT_TESTED", "ui_started": False, "user_files_accessed": False,
              "historical_v1_unchanged": True, "next_step": "REVIEW_RESULT_BEFORE_ANY_NEW_TRIAL"}
    adb = None; before = None; after = None; journal = None; stage = "target"
    try:
        adb = Adb(out / "private-raw")  # Constructor selects exactly observed P011; never default ADB.
        if adb.python("initial-stock", safety + "\ns=stock_snapshot();require_stock(s);print('RESULT=True')") is not True:
            raise ValueError("Initial stock gate")
        stage = "candidate"
        present = adb.python("candidate-directory", safety + "\np=" + repr(target) + "\nowned_directory(p,True)\nprint('RESULT='+repr(bool(os.listdir(p))))")
        if not present:
            for folder in ("runtime", "native"):
                adb.python("candidate-subdir", safety + "\nowned_directory(" + repr(target + "/" + folder) + ",True)\nprint('RESULT=True')")
            for relative in sorted(EXPECTED_FILES):
                adb.run("push-v2-candidate", ["push", str(frozen / relative), target + "/" + relative])
        check = safety + "\nbase=" + repr(target) + "\nverify_candidate(base)\nassert digest(base+'/SOURCE.sha256')==" + repr(hashlib.sha256((frozen / "SOURCE.sha256").read_bytes()).hexdigest()) + "\n"
        check += "assert digest(base+'/runtime/mta_send_wifi.py')==" + repr(RUNTIME_SHA256) + "\npins=" + repr(NATIVE_PINS) + "\n"
        check += "for name,pin in pins.items():\n assert digest(base+'/native/'+name)==pin\n os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        if adb.python("verify-pinned-v2-candidate", check) is not True:
            raise ValueError("Candidate gate")
        stage = "prior_journals"
        prior = adb.python("prior-journals-v2-readonly", probe_source(target, safety, PRIOR_JOURNALS))
        report["prior_journals_clear"] = isinstance(prior, dict) and prior.get("clear") is True and prior.get("global_pending_clear") is True
        if not report["prior_journals_clear"]:
            report["next_step"] = "REVIEW_PRIVATE_PRIOR_JOURNAL_AND_PENDING_BEFORE_NEW_TRIAL"
            raise ValueError("Prior ownership gate")
        stage = "network_baseline"
        before = adb.python("before-independent-v2", probe_source(target, safety, PROBE))
        report["preflight_passed"] = preflight_ok(before)
        if not report["preflight_passed"]:
            raise ValueError("V2 P011 preflight")
        stage = "owned_run_directory"
        if adb.python("new-owned-v2-run-directory", safety + "\np=" + repr(run) + "\nassert not os.path.lexists(p)\nowned_directory(p,True)\nassert os.stat(p).st_mode&0o777==0o700\nprint('RESULT=True')") is not True:
            raise ValueError("Owned run gate")
        stage = "trial"
        argv = ["python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
                "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20"]
        command = " ".join(shlex.quote(v) for v in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
        report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v2-trial", ["shell", command], timeout=55)))
    except Exception:
        report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = adb.python("after-independent-v2", probe_source(target, safety, PROBE))
            except Exception:report["after_check_failed"] = True
            try:
                extra = "RUN=" + repr(run) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\nSTAGES=" + repr(tuple(sorted(STAGES))) + "\n"
                journal = adb.python("owned-journal-v2-readonly", probe_source(target, safety, JOURNAL, extra))
            except Exception:report["journal_check_failed"] = True
        add_independent_gates(report, before, after, journal)
        if report["pass"]:
            report["next_step"] = "REVIEW_V2_GO_ONLY_EVIDENCE_DHCP_AND_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:
            report["next_step"] = "REVIEW_OWNED_V2_JOURNAL_FOR_EXPLICIT_RECOVERY" if journal and journal.get("recover_review_ready") is True else "READONLY_OWNERSHIP_AND_PENDING_REVIEW_REQUIRED"
        # Advisory only: no recovery command is run, even after timeout/parse failure.
        if journal and journal.get("recover_review_ready") is True:
            recovery = " ".join(shlex.quote(v) for v in ("python3", "-B", target + "/runtime/mta_send_wifi.py", "--recover", "--run-dir", run,
                                                          "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps"))
            (out / "private-next-steps.txt").write_text("Read-only review of exact journal/pending/boot/interfaces/processes first; root must explicitly review any recovery.\nNo retry/global cleanup was performed.\n" + recovery + "\n", encoding="utf-8")
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("V2 explicit owned P011 GO-only finite TTL20 trial; old V1 script/candidate/FAIL unchanged.\n"
        "Independent stock/process/interface/IPv4+full IPv6/pending+journal readback; numeric diagnostics allowlist.\n"
        "No DHCP/IP setup, BLE/UI/files/PHONE claim, retries, recovery, reboot or global service changes.\n"
        "Only result.json and README.txt are public ZIP members; raw/IPv6/paths/credentials/advisory stay private.\n", encoding="utf-8")
    archive = out.with_suffix(".sanitized.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true")
    mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:parser.error("freeze-only does not accept an execution snapshot")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV2Freeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8"); target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
        for body in (PROBE, PRIOR_JOURNALS):probe_source(target, safety, body)
        probe_source(target, safety, JOURNAL, "RUN='/mnt/data/p011-toolbox/sessions/mta-p2p-v2-20000101-000000-00000000'\nBINARY='fixture'\nSTAGES=" + repr(tuple(sorted(STAGES))) + "\n")
        print("HOST_ONLY_V2_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen))
        print("No ADB or RF operation performed. Root must review this immutable V2 snapshot before execution.")
        return 0
    if args.frozen is None or not re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or ""):
        parser.error("execute-reviewed requires a frozen V2 and its reviewed identity")
    report, out, archive = run_reviewed(args.frozen, args.expected_candidate, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out)); print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
