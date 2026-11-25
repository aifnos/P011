"""Independent reviewed P011 V6diag GO+IPv4-only harness, not a sender.

Import and freeze-only are HOST-only. All seven source/native pins are fixed to
the owner's stable reviewed bytes; this cannot execute a half-written build.
No legacy harness globals are changed and no automatic recovery/retry exists.
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
import sys
import zipfile

from device_probe import Adb, BASE, ROOT
from device_p2p import _data, STAGES
from device_p2p_v2 import DIAGNOSTIC_STAGES, INIT_REQUIRED, _plain_directory, _strict_object
from device_p2p_v4 import FAILURE_PHASES as V4_FAILURE_PHASES, NETLINK_COMMANDS, FAILURE_REASONS


RUNTIME_DIRECTORY = "native/private-p2p-runtime-candidate-20261001-v6diag/runtime"
NATIVE_DIRECTORY = "native/private-p2p-candidate-20261001-v2"
RUNTIME_MARKER = "p011-go-ip-only-v6diag-1"
JOURNAL_KIND = "go_ip_only"
# Prior-only allowlist. It cannot authorize mutation/recovery or current records.
PRIOR_CANDIDATES = {
    "0f2a45489fd3e03b": {
        "manifest_sha256": "0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8",
        "identity": {"version": 3, "kind": "go_ip_only", "runtime_marker": "p011-go-ip-only-v5-1",
                     "wpa_sha256": "e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
                     "codec_sha256": "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5",
                     "helper_sha256": "39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c"},
        "pins": {
            "native/mta-wifi-caps": "9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
            "native/mta-wpa-supplicant": "e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
            "runtime/mta_ip.py": "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5",
            "runtime/mta_ip_lease.py": "39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c",
            "runtime/mta_safety.py": "03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81",
            "runtime/mta_send_wifi.py": "96f808a9ef7cbaf011bb3254a23c01cbda6d7e09e016ad948c5dba89b671bd87",
            "runtime/p011_json.py": "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88",
        },
    },
}
SOURCE_PINS = {
    "mta_send_wifi.py": "82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa",
    "mta_ip_lease.py": "39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c",
    "mta_ip.py": "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5",
    "mta_safety.py": "03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81",
    "p011_json.py": "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88",
}
NATIVE_PINS = {
    "mta-wpa-supplicant": "e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
    "mta-wifi-caps": "9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
}
FAILURE_PHASES = V4_FAILURE_PHASES | {"ip_create", "ip_cleanup"}
IP_STAGES = frozenset(("none", "create_intent", "receipt_recorded", "confirmed",
                       "delete_intent", "restored"))
IP_CREATION_REASONS = frozenset(("not_recorded", "journal", "process", "interface_carrier", "interface_identity",
                                "interface_l3", "original_baseline", "expiry", "ip_transaction", "unexpected_gate_read"))
IP_CREATION_GATES = IP_CREATION_REASONS - {"unexpected_gate_read"}
IP_CREATION_OBSERVATIONS = frozenset(("flags_read_valid", "flags_up", "carrier_read_valid", "carrier_is_up",
                                     "sysfs_identity_match", "go_identity_match"))
SOURCE_NAMES = tuple(SOURCE_PINS)
PAYLOAD_FILES = frozenset(["runtime/" + n for n in SOURCE_NAMES] + ["native/" + n for n in NATIVE_PINS])
EXPECTED_FILES = PAYLOAD_FILES | {"SOURCE.sha256"}
MAX_SOURCE_BYTES = 512 * 1024
MAX_BINARY_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 32768


def _review_pins():
    if any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in SOURCE_PINS.values()):
        raise ValueError("V6diag final source pins are not yet reviewed")


def _source_checks(name, raw):
    _review_pins()
    ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
    if name not in SOURCE_PINS or hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:
        raise ValueError("V6diag reviewed source pin differs")


def _native_check(name, raw):
    if (hashlib.sha256(raw).hexdigest() != NATIVE_PINS[name] or len(raw) < 20 or
            raw[:6] != b"\x7fELF\x01\x01" or raw[18:20] != b"\x28\x00"):
        raise ValueError("V6diag fixed ARM ELF32 native pin differs")


def freeze(destination):
    _review_pins()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for name in sorted(SOURCE_NAMES):
        directory = BASE / RUNTIME_DIRECTORY if name == "mta_send_wifi.py" else BASE / "runtime"
        raw = _data(directory / name, MAX_SOURCE_BYTES)
        _source_checks(name, raw)
        records.append(("runtime/" + name, raw))
    for name in sorted(NATIVE_PINS):
        raw = _data(BASE / NATIVE_DIRECTORY / name, MAX_BINARY_BYTES)
        _native_check(name, raw)
        records.append(("native/" + name, raw))
    lines = []
    for relative, raw in sorted(records):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        lines.append("%s %d %s\n" % (hashlib.sha256(raw).hexdigest(), len(raw), relative))
    (destination / "SOURCE.sha256").write_bytes("".join(lines).encode("ascii"))
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    _review_pins()
    directory = _plain_directory(directory)
    manifest = _data(directory / "SOURCE.sha256", MAX_MANIFEST_BYTES)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and expected != identity:
        raise ValueError("V6diag reviewed frozen identity mismatch")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != 7:
        raise ValueError("V6diag requires exactly seven payloads")
    seen = {"SOURCE.sha256"}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,9}) ((?:runtime|native)/[A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError("V6diag manifest syntax")
        pin, size, relative = match.groups()
        if relative not in PAYLOAD_FILES or relative in seen:
            raise ValueError("V6diag unexpected or duplicate payload")
        seen.add(relative)
        is_source = relative.startswith("runtime/")
        raw = _data(directory / relative, MAX_SOURCE_BYTES if is_source else MAX_BINARY_BYTES)
        if len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("V6diag frozen content changed")
        name = relative.split("/", 1)[1]
        _source_checks(name, raw) if is_source else _native_check(name, raw)
    observed = set()
    for folder, directories, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in directories):
            raise ValueError("V6diag linked frozen directory")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:
        raise ValueError("V6diag unlisted files")
    return identity


def _creation_gate(row):
    if (type(row) is not dict or set(row) != {"reason", "gate", "observations"} or type(row["reason"]) is not str or
            row["reason"] not in IP_CREATION_REASONS or type(row["gate"]) is not str or row["gate"] not in IP_CREATION_GATES or
            type(row["observations"]) is not dict or set(row["observations"]) - IP_CREATION_OBSERVATIONS or
            any(type(value) is not bool for value in row["observations"].values())):
        raise ValueError("V6diag creation gate whitelist")
    values = row["observations"]
    if ("flags_up" in values and values.get("flags_read_valid") is not True or
            "carrier_is_up" in values and values.get("carrier_read_valid") is not True):
        raise ValueError("V6diag observations require successful read")
    return {"reason": row["reason"], "gate": row["gate"], "observations": dict(values)}


def _failure_cleanup(row):
    """Sanitize a FAILED trial's cleanup, without granting IP acceptance."""
    if type(row) is not dict:
        raise ValueError("V6diag failure cleanup object")
    flags = {"owned_process_removed", "owned_interface_removed", "stock_baseline_equal", "complete", "ip_restored"}
    normal = flags | {"event", "ip_stage"}
    kind = "cleanup_failed"
    if set(row) in (normal, normal | {"independent_readback"}):
        if (row["event"] != "private_go_ip_cleanup" or type(row["ip_stage"]) is not str or row["ip_stage"] not in IP_STAGES or
                any(type(row[key]) is not bool for key in flags) or "independent_readback" in row and type(row["independent_readback"]) is not bool):
            raise ValueError("V6diag failure normal cleanup whitelist")
        kind = "owned_cleanup"
    elif set(row) == {"complete", "no_radio_mutation"}:
        if row["complete"] is not True or row["no_radio_mutation"] is not True:
            raise ValueError("V6diag failure no-mutation cleanup whitelist")
        kind = "no_radio_mutation"
    elif set(row) != {"event", "complete"} or row.get("event") != "cleanup_failed" or row.get("complete") is not False:
        raise ValueError("V6diag failure cleanup whitelist")
    return {"failed_trial_cleanup_kind": kind, "failed_trial_cleanup_complete": row.get("complete") is True,
            "failed_trial_owned_process_removed_reported": row.get("owned_process_removed") is True,
            "failed_trial_owned_interface_removed_reported": row.get("owned_interface_removed") is True,
            "failed_trial_stock_baseline_equal_reported": row.get("stock_baseline_equal") is True,
            "failed_trial_ip_restored_reported": row.get("ip_restored") is True,
            "failed_trial_no_radio_mutation_reported": kind == "no_radio_mutation",
            "failed_trial_independent_readback_reported": row.get("independent_readback") is True,
            "failed_trial_ip_stage": row["ip_stage"] if kind == "owned_cleanup" else "none"}


def parse_trial(raw):
    if type(raw) is not bytes or len(raw) > 32768:
        raise ValueError("V6diag trial output size/type")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    matches = re.findall(r"^MTA_REMOTE_EXIT=([0-9]{1,3})$", derived, re.M)
    if len(matches) != 1:
        raise ValueError("V6diag unique remote exit required")
    allowed = {"private_go_ip_ready", "private_go_ip_cleanup", "private_go_ip_trial_failed"}
    events = []
    for line in derived.splitlines():
        if line.startswith("MTA_REMOTE_EXIT=") or not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=_strict_object)
        if type(row) is not dict or type(row.get("event")) is not str or row["event"] not in allowed:
            raise ValueError("V6diag unexpected event")
        events.append(row)
        _creation_gate(row.get("ip_creation_gate"))
    ready = [row for row in events if row["event"] == "private_go_ip_ready"]
    cleanup = [row for row in events if row["event"] == "private_go_ip_cleanup"]
    failed = [row for row in events if row["event"] == "private_go_ip_trial_failed"]
    if (not 1 <= len(events) <= 2 or len(ready) > 1 or len(cleanup) > 1 or len(failed) > 1 or
            bool(cleanup) == bool(failed) or ready and events[0] is not ready[0] or
            events[-1] not in cleanup + failed):
        raise ValueError("V6diag event order/multiplicity")
    diagnostic = events[-1].get("diagnostics")
    if (type(diagnostic) is not dict or set(diagnostic) != {"events", "diagnostic_invalid", "raw_diagnostics_not_logged"} or
            type(diagnostic["diagnostic_invalid"]) is not bool or diagnostic["raw_diagnostics_not_logged"] is not True or
            type(diagnostic["events"]) is not list or len(diagnostic["events"]) > 64):
        raise ValueError("V6diag diagnostic envelope")
    diagnostics = []
    for row in diagnostic["events"]:
        if (type(row) is not dict or set(row) != {"stage", "code"} or type(row["stage"]) is not str or
                row["stage"] not in DIAGNOSTIC_STAGES.values() or type(row["code"]) is not int or not -4095 <= row["code"] <= 4095):
            raise ValueError("V6diag diagnostic row whitelist")
        diagnostics.append(dict(row))
    for row in ready:
        if (set(row) != {"event", "ttl", "credentials_not_logged", "ip_ready", "dhcp_ready", "send_available", "ip_creation_gate"} or
                type(row["ttl"]) is not int or row["ttl"] != 20 or row["credentials_not_logged"] is not True or
                row["ip_ready"] is not True or row["dhcp_ready"] is not False or row["send_available"] is not False):
            raise ValueError("V6diag ready whitelist")
        if row["ip_creation_gate"] != {"reason": "not_recorded", "gate": "not_recorded", "observations": {}}:
            raise ValueError("V6diag ready default creation gate")
    for row in cleanup:
        fields = {"event", "owned_process_removed", "owned_interface_removed", "stock_baseline_equal",
                  "complete", "diagnostics", "ip_restored", "ip_stage", "ip_control_socket_closed", "ip_creation_gate"}
        if (not fields.issubset(row) or set(row) - fields - {"independent_readback"} or
                any(type(row[key]) is not bool for key in fields - {"event", "diagnostics", "ip_stage", "ip_creation_gate"}) or
                type(row["ip_stage"]) is not str or row["ip_stage"] not in IP_STAGES or
                "independent_readback" in row and type(row["independent_readback"]) is not bool):
            raise ValueError("V6diag cleanup whitelist")
    public_failure = {}
    for row in failed:
        fields = {"event", "reason", "cleanup", "complete", "diagnostics", "failure_phase", "failure_errno", "netlink_command", "ip_creation_gate"}
        if (set(row) - {"ip_control_socket_closed"} != fields or row["complete"] is not False or type(row["cleanup"]) is not dict or
                type(row["reason"]) is not str or row["reason"] not in FAILURE_REASONS or
                type(row["failure_phase"]) is not str or row["failure_phase"] not in FAILURE_PHASES or
                type(row["failure_errno"]) is not int or not 0 <= row["failure_errno"] <= 4095 or
                type(row["netlink_command"]) is not str or row["netlink_command"] not in NETLINK_COMMANDS):
            raise ValueError("V6diag failure whitelist")
        if ("ip_control_socket_closed" in row and type(row["ip_control_socket_closed"]) is not bool or
                row["failure_phase"] != "backend_construct" and "ip_control_socket_closed" not in row):
            raise ValueError("V6diag failure socket closure field")
        public_failure = {"failure_phase": row["failure_phase"], "failure_errno": row["failure_errno"],
                          "netlink_command": row["netlink_command"], "failure_reason": row["reason"]}
        public_failure.update(_failure_cleanup(row["cleanup"]))
        public_failure["failed_trial_socket_closed_reported"] = row.get("ip_control_socket_closed") is True
    zeros = {row["stage"] for row in diagnostics if row["code"] == 0}
    result = {"remote_exit_zero": matches[0] == "0", "go_ip_ready_event": len(ready) == 1,
              "cleanup_event": len(cleanup) == 1, "cleanup_complete": bool(cleanup and cleanup[0]["complete"] is True),
              "owned_process_removed_reported": bool(cleanup and cleanup[0]["owned_process_removed"] is True),
              "owned_interface_removed_reported": bool(cleanup and cleanup[0]["owned_interface_removed"] is True),
              "stock_baseline_equal_reported": bool(cleanup and cleanup[0]["stock_baseline_equal"] is True),
              "ip_restored_reported": bool(cleanup and cleanup[0]["ip_restored"] is True),
              "ip_control_socket_closed_reported": bool(cleanup and cleanup[0]["ip_control_socket_closed"] is True),
              "ip_stage_reported": cleanup[0]["ip_stage"] if cleanup else "none",
              "trial_failed_event": bool(failed), "diagnostics_valid": diagnostic["diagnostic_invalid"] is False,
              "early_init_success_reported": INIT_REQUIRED.issubset(zeros) and all(row["code"] == 0 for row in diagnostics if row["stage"] in INIT_REQUIRED),
              "diagnostic_events": diagnostics, "ip_creation_gate": _creation_gate(events[-1]["ip_creation_gate"])}
    result.update(public_failure)
    return result


# Standalone V6diag namespace: no legacy parser is patched or given V3 records.
# These programs only import definitions, read files/process identities and send
# GET_INTERFACE / GETADDR / GETROUTE(all tables) / GETRULE requests.
READ_HELPERS = r'''
import hashlib,os,re,socket,stat,subprocess,sys,time
import p011_json as json
import mta_ip as ip
from mta_send_wifi import ReadWriteNetlink,TRACKED,_proc_identity,DEVICE_LOCK,DEVICE_PENDING
if sys.flags.optimize:raise ValueError('optimized_readonly_interpreter')
def bounded(path,maximum=1048576):
 with open(path,'rb') as handle:value=handle.read(maximum+1)
 if len(value)>maximum:raise ValueError('readonly_byte_limit')
 return value
def hashbytes(value):return hashlib.sha256(value).hexdigest()
def private_folder(path):
 owned_directory(path);value=os.lstat(path)
 if not stat.S_ISDIR(value.st_mode) or value.st_uid!=os.getuid() or value.st_mode&0o077:raise ValueError('unsafe_private_folder')
def private_record(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  value=os.fstat(fd)
  if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.getuid() or value.st_mode&0o077 or value.st_size>65536:
   raise ValueError('unsafe_private_record')
  with os.fdopen(fd,'r') as handle:fd=None;record=json.loads(handle.read(65537))
  if type(record) is not dict:raise ValueError('invalid_private_record')
  return record
 finally:
  if fd is not None:os.close(fd)
def plain(value):
 if type(value) is bytes:return value.hex()
 if isinstance(value,(tuple,list)):return [plain(item) for item in value]
 if value is None or type(value) in (int,bool,str):return value
 raise ValueError('unknown_readonly_record_type')
def canonical_ipv4(snapshot):
 return {'version':1,'addresses':sorted([plain(tuple(row)) for row in snapshot.addresses],key=repr),
  'routes':sorted([plain(tuple(row)) for row in snapshot.routes],key=repr),
  'rules':sorted([plain(tuple(row)) for row in snapshot.rules],key=repr)}
def normalize_ipv4(value):
 if type(value) is not dict or set(value)!={'version','addresses','routes','rules'} or type(value['version']) is not int or value['version']!=1:
  raise ValueError('invalid_ipv4_baseline')
 result={'version':1}
 for kind,width in (('addresses',9),('routes',12),('rules',2)):
  rows=value[kind]
  if type(rows) is not list or len(rows)>4096 or any(type(row) is not list or len(row)!=width for row in rows):
   raise ValueError('invalid_ipv4_baseline_rows')
  for row in rows:
   if kind=='addresses':
    if any(type(number) is not int for number in row[:6]) or not 0<row[0]<=0x7fffffff or any(not 0<=number<=ip.UINT_MAX for number in row[1:3]) or not 0<=row[3]<=32 or row[4]!=128 or row[5] not in (0,253,254):raise ValueError('invalid_ipv4_address')
    if row[6] is not None:
     if type(row[6]) is not str or re.match(r'^(?:[0-9a-f]{2}){2,16}\Z',row[6]) is None:raise ValueError('invalid_ipv4_label')
     label=bytes.fromhex(row[6])
     if label[-1:]!=b'\0' or b'\0' in label[:-1]:raise ValueError('invalid_ipv4_label')
    if row[7] is not None and (type(row[7]) is not int or not 0<=row[7]<=ip.UINT_MAX):raise ValueError('invalid_ipv4_broadcast')
    if type(row[8]) is not list or len(row[8])!=4 or any(type(number) is not int or not 0<=number<=ip.UINT_MAX for number in row[8]) or row[8][:2]!=[ip.UINT_MAX,ip.UINT_MAX]:raise ValueError('invalid_ipv4_lifetime')
   elif kind=='routes':
    if any(type(number) is not int for number in row[:7]) or not 0<=row[0]<=ip.UINT_MAX or not 0<=row[1]<=32 or row[0]&((ip.UINT_MAX<<(32-row[1]))&ip.UINT_MAX if row[1] else 0)!=row[0] or not 0<row[2]<=ip.UINT_MAX or not 0<=row[3]<=255 or row[4] not in (0,253,254) or row[5] not in (1,2,3) or row[6]&~0x19 or row[6]<0:raise ValueError('invalid_ipv4_route')
    if any(number is not None and (type(number) is not int or not 0<=number<=ip.UINT_MAX) for number in row[7:11]) or row[7] is not None and not 0<row[7]<=0x7fffffff:raise ValueError('invalid_ipv4_route_optional')
    metrics=row[11]
    if type(metrics) is not list or any(type(pair) is not list or len(pair)!=2 or any(type(number) is not int or not 0<=number<=ip.UINT_MAX for number in pair) or not 1<=pair[0]<=15 for pair in metrics) or len(set(pair[0] for pair in metrics))!=len(metrics) or metrics!=sorted(metrics):raise ValueError('invalid_ipv4_metrics')
   elif any(type(number) is not int or not 0<=number<=ip.UINT_MAX for number in row):raise ValueError('invalid_ipv4_rule')
  keys=[repr(row) for row in rows]
  if len(set(keys))!=len(keys):raise ValueError('duplicate_ipv4_baseline_record')
  result[kind]=sorted(rows,key=repr)
 if result['rules']!=[[0,255],[32766,254],[32767,253]]:raise ValueError('nondefault_ipv4_policy')
 return result
def ipv4_readonly():
 connection=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE)
 end=time.monotonic()+8;sequence=0
 try:
  connection.set_inheritable(False);connection.bind((0,0));port,groups=connection.getsockname()
  if type(port) is not int or port<=0 or groups!=0:raise ValueError('readonly_netlink_port')
  views=[]
  for unused in range(2):
   collectors=[]
   for kind in ('addresses','routes','rules'):
    sequence+=1;collector=ip.DumpCollector(kind,sequence,port)
    remaining=end-time.monotonic()
    if remaining<=0:raise ValueError('readonly_ip_deadline')
    connection.settimeout(remaining)
    sent=connection.sendto(collector.request,(0,0))
    if sent!=len(collector.request):raise ValueError('readonly_ip_short_send')
    while not collector.complete:
     remaining=end-time.monotonic()
     if remaining<=0:raise ValueError('readonly_ip_deadline')
     connection.settimeout(remaining);packet,ancillary,flags,peer=connection.recvmsg(ip.MAX_DATAGRAM_BYTES)
     if peer!=(0,0) or ancillary or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise ValueError('readonly_ip_sender')
     collector.feed(packet)
    collectors.append(collector)
   snapshot=ip.snapshot_from_dumps(*collectors);ip.require_default_rules(snapshot)
   if not all(row.flags==ip.IFA_F_PERMANENT and row.cacheinfo is not None and row.cacheinfo[:2]==(ip.UINT_MAX,ip.UINT_MAX) for row in snapshot.addresses):
    raise ValueError('readonly_ip_lifetime')
   views.append(canonical_ipv4(snapshot))
  if views[0]!=views[1]:raise ValueError('readonly_ip_views_changed')
  return views[1]
 finally:connection.close()
def numbers(value,fields,positive=False):
 return type(value) is dict and all(type(value.get(key)) is int and value[key]>=(1 if positive else 0) for key in fields)
def process_absent(process):
 if process is None:return True
 # An unreadable or nondumpable live PID is not proof of disappearance.
 path='/proc/'+str(process['pid'])
 for check in range(2):
  try:os.lstat(path)
  except OSError as error:
   if error.errno!=2:raise
  else:return False
  if check==0 and _proc_identity(process['pid']) is not None:return False
 return True
def origin(value):
 return (type(value) is dict and type(value.get('name')) is str and
  re.match(r'^mta[0-9a-f]{8}\Z',value['name']) is not None and numbers(value,('phy','ifindex','wdev')) and
  0<value['ifindex']<=0x7fffffff and 0<value['wdev']<=0xffffffffffffffff and value['phy']<=ip.UINT_MAX)
def identity3(value,expected=None):return type(value) is dict and value==(IDENTITY3 if expected is None else expected)
def pending_readonly():
 result={'present':os.path.lexists(DEVICE_PENDING),'safe':True,'valid':True}
 if result['present']:
  result['safe']=False;result['valid']=False;record=private_record(DEVICE_PENDING);result['safe']=True
  result['valid']=(set(record)==set(IDENTITY3)|{'journal','boot_id'} and
   identity3({key:record[key] for key in IDENTITY3}) and type(record.get('journal')) is str and
   re.match('^'+re.escape(AREA)+r'/sessions/mta-p2p-v2-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}/p2p-lease[.]json\Z',record['journal']) is not None and
   record.get('boot_id')==bounded('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip())
 if os.path.lexists(DEVICE_LOCK):
  value=os.lstat(DEVICE_LOCK);result['lock_safe']=stat.S_ISREG(value.st_mode) and not os.path.islink(DEVICE_LOCK) and value.st_uid==os.getuid() and value.st_mode&0o077==0
 else:result['lock_safe']=True
 return result
def actors_and_network():
 network=[];private=[];actors=[]
 for token in os.listdir('/proc'):
  if not token.isdigit():continue
  try:
   row=_proc_identity(int(token))
   if row is None:continue
   name=bounded('/proc/'+token+'/comm',128).decode('ascii').strip();args=bounded('/proc/'+token+'/cmdline',65536).split(b'\0')
   if name in TRACKED:row['name']=name;row['cmdline_digest']=hashbytes(b'\0'.join(args));network.append(row)
   exe=row.get('exe','').replace(' (deleted)','')
   if exe.startswith(AREA+'/candidates/') and exe.endswith('/native/mta-wpa-supplicant'):private.append(row)
   if any(item.startswith((AREA+'/candidates/').encode('ascii')) and item.endswith(b'/runtime/mta_send_wifi.py') for item in args) and (b'--trial' in args or b'--recover' in args):actors.append(row)
  except OSError:pass
 return sorted(network,key=lambda row:row['pid']),private,actors
def validate_ip_resource(value,owned):
 if value is None:return True
 if type(value) is not dict or value.get('stage') not in IP_STAGES or value['stage']=='none':raise ValueError('invalid_ip_stage')
 base={'stage','owned','spec','request'};receipt=value['stage']!='create_intent'
 if set(value)!=base|({'address','receipt_fsynced'} if receipt else set()):raise ValueError('invalid_ip_resource_keys')
 if not origin(value['owned']) or set(value['owned'])!={'name','ifindex','wdev','phy'} or owned is None or any(value['owned'][key]!=owned[key] for key in value['owned']):
  raise ValueError('ip_origin_mismatch')
 spec=value['spec']
 if type(spec) is not list or len(spec)!=3 or any(type(number) is not int for number in spec) or spec[0]!=owned['ifindex']:
  raise ValueError('invalid_ip_spec')
 intent=ip.AddressSpec(spec[0],ip.ipv4_text(spec[1]),spec[2]);request=value['request']
 if type(request) is not dict or set(request)!={'header','sequence','port_id'}:raise ValueError('invalid_ip_request')
 if type(request['header']) is not str or request['header']!=ip.encode_new_address(intent,request['sequence'],request['port_id'])[:16].hex():
  raise ValueError('ip_request_header_mismatch')
 if receipt:
  row=value['address']
  if type(value['receipt_fsynced']) is not bool or value['receipt_fsynced']!=(value['stage']!='receipt_recorded'):
   raise ValueError('invalid_ip_receipt_state')
  if type(row) is not list or len(row)!=9 or any(type(number) is not int for number in row[:6]) or row[:6]!=[intent.ifindex,intent.address,intent.address,24,128,0] or type(row[7]) is not int or row[7]!=intent.address|255:
   raise ValueError('invalid_ip_receipt_address')
  if row[6]!=(owned['name'].encode('ascii')+b'\0').hex() or type(row[8]) is not list or len(row[8])!=4 or any(type(number) is not int or not 0<=number<=ip.UINT_MAX for number in row[8]) or row[8][:2]!=[ip.UINT_MAX,ip.UINT_MAX]:
   raise ValueError('invalid_ip_receipt_label_lifetime')
 return True
def validate_journal3(record,expected_identity=None,expected_binary=None):
 expected_binary=BINARY if expected_binary is None else expected_binary
 fields={'version','kind','identity','stage','name','baseline','deadline','owned','process','ip'}
 if set(record)-{'cleanup_result'}!=fields or type(record.get('version')) is not int or record['version']!=3 or record.get('kind')!='go_ip_only' or not identity3(record.get('identity'),expected_identity):
  raise ValueError('invalid_journal3_identity')
 if record.get('stage') not in MAIN_STAGES or type(record.get('name')) is not str or re.match(r'^mta[0-9a-f]{8}\Z',record['name']) is None:
  raise ValueError('invalid_journal3_stage')
 owned=record['owned'];process=record['process'];baseline=record['baseline']
 if owned is not None and (set(owned)!={'name','ifindex','wdev','phy','iftype'} or not origin(owned) or owned['name']!=record['name'] or type(owned.get('iftype')) is not int or owned['iftype']!=8):raise ValueError('invalid_journal3_owned')
 if process is not None and (set(process)!={'pid','starttime','exe'} or not numbers(process,('pid','starttime'),True) or process['pid']>0x7fffffff or process['starttime']>0xffffffffffffffff or process.get('exe')!=expected_binary):raise ValueError('invalid_journal3_process')
 required={'boot_id','processes','station','interfaces','frequency','route_digest','ipv6_route_digest','ipv6_address_digest','station_state_digest','ipv4'}
 if type(baseline) is not dict or set(baseline)!=required:raise ValueError('invalid_journal3_baseline_keys')
 for key in ('route_digest','ipv6_route_digest','ipv6_address_digest','station_state_digest'):
  if type(baseline[key]) is not str or re.match(r'^[0-9a-f]{64}\Z',baseline[key]) is None:raise ValueError('invalid_journal3_digest')
 if type(baseline['boot_id']) is not str or type(baseline['interfaces']) is not list or type(baseline['processes']) is not list:
  raise ValueError('invalid_journal3_baseline')
 if type(record['deadline']) not in (int,float) or not 0<record['deadline']<1e12:raise ValueError('invalid_journal3_deadline')
 if type(baseline['frequency']) is not int or baseline['frequency'] not in range(2412,2473,5):raise ValueError('invalid_journal3_frequency')
 for row in baseline['interfaces']+[baseline['station']]:
  if type(row) is not dict or set(row)!={'name','ifindex','wdev','phy','iftype'} or type(row['name']) is not str or re.match(r'^[A-Za-z0-9_.-]{1,15}\Z',row['name']) is None or not numbers(row,('ifindex','wdev','phy','iftype')) or not 0<row['ifindex']<=0x7fffffff or row['phy']>ip.UINT_MAX or row['wdev']>0xffffffffffffffff or row['iftype']>12:raise ValueError('invalid_journal3_interface_baseline')
 if baseline['station']['name']!='wlan0' or baseline['station']['iftype']!=2 or baseline['station'] not in baseline['interfaces'] or len(set(row['ifindex'] for row in baseline['interfaces']))!=len(baseline['interfaces']) or len(set(row['wdev'] for row in baseline['interfaces']))!=len(baseline['interfaces']):raise ValueError('invalid_journal3_station_baseline')
 seen=set()
 for row in baseline['processes']:
  if type(row) is not dict or set(row)!={'pid','starttime','exe','cmdline_digest'} or not numbers(row,('pid','starttime'),True) or type(row['exe']) is not str or not row['exe'].startswith('/') or '\0' in row['exe'] or type(row['cmdline_digest']) is not str or re.match(r'^[0-9a-f]{64}\Z',row['cmdline_digest']) is None or row['pid'] in seen:raise ValueError('invalid_journal3_process_baseline')
  seen.add(row['pid'])
 if baseline['processes']!=sorted(baseline['processes'],key=lambda row:row['pid']):raise ValueError('invalid_journal3_process_baseline')
 if 'cleanup_result' in record:
  report=record['cleanup_result'];fields={'event','owned_process_removed','owned_interface_removed','stock_baseline_equal','complete','ip_restored','ip_stage'}
  if type(report) is not dict or set(report)-{'independent_readback'}!=fields or report['event']!='private_go_ip_cleanup' or report['ip_stage'] not in IP_STAGES or any(type(report[key]) is not bool for key in fields-{'event','ip_stage'}) or 'independent_readback' in report and type(report['independent_readback']) is not bool:raise ValueError('invalid_journal3_cleanup')
 normalize_ipv4(baseline['ipv4']);validate_ip_resource(record['ip'],owned)
 return True

def prior_ip_reconciled(record):
 resource=record['ip'];cleanup=record.get('cleanup_result',{})
 if cleanup.get('ip_restored') is not True:return False
 if resource is None:return cleanup.get('ip_stage')=='none'
 return resource['stage']=='restored' and cleanup.get('ip_stage')=='restored'

def station_readonly():
 process=subprocess.Popen(['/usr/sbin/wpa_cli','-i','wlan0','status'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:output,error=process.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  process.kill();process.communicate();raise ValueError('readonly_status_timeout')
 if process.returncode or len(output)>16384:raise ValueError('readonly_status_failed')
 fields=dict(line.split('=',1) for line in output.decode('utf-8','replace').splitlines() if '=' in line)
 return {'completed':fields.get('wpa_state')=='COMPLETED','fingerprint':hashbytes(output),
  'same_channel_2ghz':fields.get('freq') in [str(number) for number in range(2412,2473,5)]},int(fields.get('freq','0'))

def prior3_context(record):
 # Only PRIOR calls this. Current journal/pending and runtime recover never
 # receive a historical expected identity or executable path.
 if identity3(record.get('identity')):return None,None,False
 process=record.get('process')
 if type(process) is not dict:raise ValueError('historical_candidate_unproven')
 for candidate,known in PRIOR_CANDIDATES.items():
  base=AREA+'/candidates/mta-01-'+candidate;binary=base+'/native/mta-wpa-supplicant'
  if not identity3(record.get('identity'),known['identity']) or process.get('exe')!=binary:continue
  private_folder(base);private_folder(base+'/runtime');private_folder(base+'/native')
  manifest=os.lstat(base+'/SOURCE.sha256')
  if not stat.S_ISREG(manifest.st_mode) or manifest.st_uid!=os.getuid() or manifest.st_mode&0o022:
   raise ValueError('historical_manifest_permissions')
  verify_candidate(base)
  if digest(base+'/SOURCE.sha256')!=known['manifest_sha256']:raise ValueError('historical_manifest_pin')
  for relative,pin in known['pins'].items():
   path=base+'/'+relative;value=os.lstat(path)
   if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.getuid() or value.st_mode&0o022 or digest(path)!=pin:
    raise ValueError('historical_payload_pin')
  return known['identity'],binary,True
 raise ValueError('unknown_historical_candidate')

def prior_baseline_matches(record,interfaces):
 baseline=record['baseline'];network,private,actors=actors_and_network()
 for row in network:row.pop('name',None)
 wifi,frequency=station_readonly();stations=[row for row in interfaces if row.get('name')=='wlan0']
 return (baseline['boot_id']==bounded('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip() and
  not private and not actors and baseline['processes']==network and baseline['interfaces']==sorted(interfaces,key=lambda row:row['wdev']) and
  len(stations)==1 and baseline['station']==stations[0] and baseline['frequency']==frequency and wifi['completed'] and
  baseline['station_state_digest']==wifi['fingerprint'] and baseline['route_digest']==hashbytes(bounded('/proc/net/route')) and
  baseline['ipv6_route_digest']==hashbytes(bounded('/proc/net/ipv6_route')) and baseline['ipv6_address_digest']==hashbytes(bounded('/proc/net/if_inet6')) and
  normalize_ipv4(baseline['ipv4'])==normalize_ipv4(ipv4_readonly()))
'''


PROBE = READ_HELPERS + r'''
value={'target_ok':os.geteuid()==0 and os.uname()[4]=='armv7l' and tuple(sys.version_info[:3])==(3,5,5),
 'stock':stock_snapshot(),'stock_valid':False,'query_ok':False,'ipv4_complete':False}
try:require_stock(value['stock']);value['stock_valid']=True
except Exception:pass
connection=None
try:
 value['wifi'],value['frequency']=station_readonly();value['station_state_digest']=value['wifi']['fingerprint']
 value['route_digest']=hashbytes(bounded('/proc/net/route'))
 value['ipv6_addresses_raw']=bounded('/proc/net/if_inet6');value['ipv6_routes_raw']=bounded('/proc/net/ipv6_route')
 value['ipv6_address_digest']=hashbytes(value['ipv6_addresses_raw']);value['ipv6_route_digest']=hashbytes(value['ipv6_routes_raw'])
 value['network_processes'],value['private_wpa_processes'],value['project_trial_actors']=actors_and_network()
 value['no_private_wpa_processes']=not value['private_wpa_processes'];value['no_project_trial_actors']=not value['project_trial_actors']
 value['boot_id']=bounded('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip();value['pending']=pending_readonly()
 connection=ReadWriteNetlink();value['interfaces']=sorted(connection.interfaces(),key=lambda row:row['wdev'])
 value['no_p2p_interfaces']=not any(row.get('iftype') in (8,9,10) for row in value['interfaces'])
 value['no_project_mta_interfaces']=not any(re.match(r'^mta[0-9a-f]{8}\Z',row.get('name','')) for row in value['interfaces'])
 stations=[row for row in value['interfaces'] if row.get('name')=='wlan0']
 value['station_identity_ok']=len(stations)==1 and stations[0].get('iftype')==2
 value['ipv4']=normalize_ipv4(ipv4_readonly());value['ipv4_complete']=True;value['query_ok']=True
except Exception:value['probe_failed']=True
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(value))
'''


PRIOR_JOURNALS = READ_HELPERS + r'''
root=AREA+'/sessions';blocked=0;seen=0;unsafe=0;connection=None
try:
 pending=pending_readonly();connection=ReadWriteNetlink();interfaces=connection.interfaces()
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
    record=private_record(path);version=record.get('version')
    if type(version) is not int or version not in (1,2,3) or record.get('stage')!='reconciled' or record.get('cleanup_result',{}).get('complete') is not True:
     blocked+=1;continue
    if type(record.get('name')) is not str or re.match(r'^mta[0-9a-f]{8}\Z',record['name']) is None:raise ValueError('prior_name_invalid')
    if version==3:
     expected_identity,expected_binary,historical=prior3_context(record)
     validate_journal3(record,expected_identity,expected_binary)
     if historical and not prior_baseline_matches(record,interfaces):blocked+=1
    owned=record.get('owned');process=record.get('process')
    if owned is not None and (not origin(owned) or owned['name']!=record['name'] or type(owned.get('iftype')) is not int or owned['iftype']!=8):raise ValueError('prior_owned_invalid')
    if process is not None:
     if not numbers(process,('pid','starttime'),True) or type(process.get('exe')) is not str or not process['exe'].startswith(AREA+'/candidates/') or not process['exe'].endswith('/native/mta-wpa-supplicant'):raise ValueError('prior_process_invalid')
     if version==3 and not process_absent(process) or version!=3 and _proc_identity(process['pid']) is not None:blocked+=1
    if any(row.get('name')==record['name'] or owned is not None and row.get('wdev')==owned['wdev'] for row in interfaces):blocked+=1
    if version==2:
     baseline=record.get('baseline',{})
     if type(baseline.get('interfaces')) is not list or any(type(baseline.get(key)) is not str or re.match(r'^[0-9a-f]{64}\Z',baseline[key]) is None for key in ('route_digest','ipv6_route_digest','ipv6_address_digest')):raise ValueError('prior_v2_baseline_invalid')
    if version==3 and not prior_ip_reconciled(record):blocked+=1
   except Exception:unsafe+=1
 result={'clear':blocked==0 and unsafe==0 and not pending['present'] and pending['safe'] and pending['lock_safe'],
  'blocked_count':blocked,'unsafe_count':unsafe,'inspected_count':seen,'global_pending_clear':not pending['present']}
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(result))
'''


JOURNAL = READ_HELPERS + r'''
result={'present':False,'safe':False,'ownership_verified':False,'stage':'absent','complete':False,
 'owned_process_gone':False,'owned_interface_gone':False,'identity_mismatch':False,'recover_review_ready':False,
 'version3':False,'ipv6_baseline_present':False,'ipv4_baseline_present':False,'pending_clear':False,
 'baseline_independent_match':False,'ip_receipt_restored':False,'ip_stage':'none'}
path=RUN+'/p2p-lease.json';connection=None
try:
 private_folder(RUN);pending=pending_readonly();result['pending_clear']=not pending['present'] and pending['safe'] and pending['lock_safe']
 if os.path.lexists(path):
  result['present']=True;record=private_record(path);validate_journal3(record)
  boot=bounded('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip();baseline=record['baseline']
  if baseline['boot_id']!=boot:raise ValueError('journal3_boot_changed')
  result['version3']=True;result['ipv6_baseline_present']=True;result['ipv4_baseline_present']=True
  owned=record['owned'];process=record['process'];result['stage']=record['stage'];result['safe']=True;result['ownership_verified']=True
  actual=_proc_identity(process['pid']) if process else None;result['owned_process_gone']=process_absent(process)
  if actual is not None and actual!=process:result['identity_mismatch']=True
  connection=ReadWriteNetlink();rows=sorted(connection.interfaces(),key=lambda row:row['wdev'])
  matched=[row for row in rows if row.get('name')==record['name'] or owned is not None and row.get('wdev')==owned['wdev']]
  result['owned_interface_gone']=not matched
  if matched and (owned is None or len(matched)!=1 or any(matched[0].get(key)!=owned.get(key) for key in ('name','ifindex','wdev','phy')) or matched[0].get('iftype') not in (2,8,9)):result['identity_mismatch']=True
  network,private,actors=actors_and_network()
  for row in network:row.pop('name',None)
  wifi,frequency=station_readonly();stations=[row for row in rows if row.get('name')=='wlan0']
  ipv4=normalize_ipv4(ipv4_readonly())
  result['baseline_independent_match']=(not private and not actors and baseline['processes']==network and baseline['interfaces']==rows and
   len(stations)==1 and baseline['station']==stations[0] and baseline['frequency']==frequency and wifi['completed'] and
   baseline['station_state_digest']==wifi['fingerprint'] and baseline['route_digest']==hashbytes(bounded('/proc/net/route')) and
   baseline['ipv6_route_digest']==hashbytes(bounded('/proc/net/ipv6_route')) and baseline['ipv6_address_digest']==hashbytes(bounded('/proc/net/if_inet6')) and
   normalize_ipv4(baseline['ipv4'])==ipv4)
  resource=record['ip'];result['ip_stage']=resource['stage'] if resource else 'none'
  result['ip_receipt_restored']=bool(resource and resource['stage']=='restored' and resource['receipt_fsynced'] is True)
  result['complete']=(record['stage']=='reconciled' and record.get('cleanup_result',{}).get('complete') is True and
   record.get('cleanup_result',{}).get('ip_restored') is True and result['ip_receipt_restored'] and result['owned_process_gone'] and
   result['owned_interface_gone'] and result['pending_clear'] and result['baseline_independent_match'])
  # Advisory is intentionally withheld for uncertain intent/receipt stages. It
  # never grants deletion authority or invokes the recovery entry point.
  result['recover_review_ready']=not result['complete'] and not result['identity_mismatch'] and result['owned_process_gone'] and resource is not None and resource['stage'] in ('confirmed','delete_intent','restored')
except Exception:result['inspection_failed']=True
finally:
 if connection is not None:connection.close()
print('RESULT='+repr(result))
'''


def probe_source(target, safety, body, extra=""):
    _review_pins()
    identity = {"version": 3, "kind": JOURNAL_KIND, "runtime_marker": RUNTIME_MARKER,
                "wpa_sha256": NATIVE_PINS["mta-wpa-supplicant"], "codec_sha256": SOURCE_PINS["mta_ip.py"],
                "helper_sha256": SOURCE_PINS["mta_ip_lease.py"]}
    source = "import sys\nif sys.flags.optimize:raise ValueError('optimized_readonly_interpreter')\n"
    source += "sys.path.insert(0," + repr(target + "/runtime") + ")\n" + safety
    source += "\nverify_candidate(" + repr(target) + ")\nSOURCE_PINS=" + repr(SOURCE_PINS) + "\nNATIVE_PINS=" + repr(NATIVE_PINS) + "\n"
    source += "for name,pin in SOURCE_PINS.items():\n if digest(" + repr(target + "/runtime/") + "+name)!=pin:raise ValueError('source_pin_mismatch')\n"
    source += "for name,pin in NATIVE_PINS.items():\n if digest(" + repr(target + "/native/") + "+name)!=pin:raise ValueError('native_pin_mismatch')\n"
    source += "IDENTITY3=" + repr(identity) + "\nPRIOR_CANDIDATES=" + repr(PRIOR_CANDIDATES) + "\nIP_STAGES=" + repr(tuple(sorted(IP_STAGES))) + "\nMAIN_STAGES=" + repr(tuple(sorted(STAGES))) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\n" + extra + "\n" + body
    ast.parse(source, feature_version=(3, 5))
    return source


def preflight_ok(value):
    if type(value) is not dict:
        return False
    flags = ("target_ok", "stock_valid", "query_ok", "ipv4_complete", "no_private_wpa_processes",
             "no_project_trial_actors", "no_p2p_interfaces", "no_project_mta_interfaces", "station_identity_ok")
    return (all(value.get(key) is True for key in flags) and type(value.get("ipv4")) is dict and
            value.get("wifi", {}).get("completed") is True and value.get("wifi", {}).get("same_channel_2ghz") is True and
            value.get("pending", {}).get("present") is False and value.get("pending", {}).get("safe") is True and
            value.get("pending", {}).get("lock_safe") is True)


def add_independent_gates(report, before, after, journal):
    ok = bool(type(before) is dict and type(after) is dict and before.get("query_ok") is True and after.get("query_ok") is True)
    report["stock_independent_unchanged"] = bool(ok and before.get("stock_valid") is True and after.get("stock_valid") is True and before.get("stock") == after.get("stock"))
    mapping = {"wifi_state_fingerprint_unchanged": "wifi", "station_state_digest_unchanged": "station_state_digest",
               "frequency_unchanged": "frequency", "route_digest_unchanged": "route_digest",
               "ipv6_address_digest_unchanged": "ipv6_address_digest", "ipv6_route_digest_unchanged": "ipv6_route_digest",
               "network_processes_unchanged": "network_processes", "interface_identities_unchanged": "interfaces", "same_boot": "boot_id"}
    for flag, field in mapping.items():
        report[flag] = bool(ok and field in before and field in after and before[field] == after[field])
    complete_ipv4 = bool(ok and before.get("ipv4_complete") is True and after.get("ipv4_complete") is True and
                         type(before.get("ipv4")) is dict and type(after.get("ipv4")) is dict)
    for kind in ("addresses", "routes", "rules"):
        report["full_ipv4_" + kind + "_unchanged"] = bool(complete_ipv4 and type(before["ipv4"].get(kind)) is list and
                                                       type(after["ipv4"].get(kind)) is list and before["ipv4"][kind] == after["ipv4"][kind])
    report["full_ipv4_readback_unchanged"] = bool(complete_ipv4 and before["ipv4"] == after["ipv4"])
    report["full_ipv6_readback_unchanged"] = bool(ok and all(type(before.get(key)) is bytes and type(after.get(key)) is bytes and before[key] == after[key] for key in ("ipv6_addresses_raw", "ipv6_routes_raw")))
    report["wifi_completed_after"] = bool(after and after.get("wifi", {}).get("completed") is True)
    for field in ("no_p2p_interfaces", "no_project_mta_interfaces", "no_private_wpa_processes", "no_project_trial_actors"):
        report[field + "_after"] = bool(after and after.get(field) is True)
    pending = after.get("pending", {}) if after else {}
    report["global_pending_clear_independent"] = pending.get("present") is False and pending.get("safe") is True and pending.get("lock_safe") is True
    for name in ("present", "safe", "ownership_verified", "complete", "owned_process_gone", "owned_interface_gone",
                 "identity_mismatch", "recover_review_ready", "version3", "ipv6_baseline_present", "ipv4_baseline_present",
                 "pending_clear", "baseline_independent_match", "ip_receipt_restored"):
        report["journal_" + name] = bool(journal and journal.get(name) is True)
    report["journal_stage"] = journal.get("stage") if journal and journal.get("stage") in STAGES else "absent_or_invalid"
    report["journal_ip_stage"] = journal.get("ip_stage") if journal and journal.get("ip_stage") in IP_STAGES else "none"
    creation = report.get("ip_creation_gate", {})
    report["ip_creation_gate_no_rejection"] = bool(type(creation) is dict and creation.get("reason") == "not_recorded" and creation.get("gate") == "not_recorded")
    gates = ("rf_trial_invoked", "preflight_passed", "prior_journals_clear", "remote_exit_zero", "go_ip_ready_event", "cleanup_event",
             "cleanup_complete", "owned_process_removed_reported", "owned_interface_removed_reported", "stock_baseline_equal_reported",
             "ip_restored_reported", "ip_control_socket_closed_reported", "diagnostics_valid", "early_init_success_reported", "ip_creation_gate_no_rejection",
             "stock_independent_unchanged", "wifi_completed_after", "wifi_state_fingerprint_unchanged", "station_state_digest_unchanged",
             "frequency_unchanged", "route_digest_unchanged", "full_ipv4_addresses_unchanged", "full_ipv4_routes_unchanged",
             "full_ipv4_rules_unchanged", "full_ipv4_readback_unchanged", "full_ipv6_readback_unchanged", "ipv6_address_digest_unchanged",
             "ipv6_route_digest_unchanged", "same_boot", "network_processes_unchanged", "interface_identities_unchanged", "no_p2p_interfaces_after",
             "no_project_mta_interfaces_after", "no_private_wpa_processes_after", "no_project_trial_actors_after", "global_pending_clear_independent",
             "journal_present", "journal_safe", "journal_ownership_verified", "journal_complete", "journal_version3",
             "journal_ipv4_baseline_present", "journal_ipv6_baseline_present", "journal_pending_clear", "journal_baseline_independent_match",
             "journal_owned_process_gone", "journal_owned_interface_gone", "journal_ip_receipt_restored")
    report["pass"] = (all(report.get(key) is True for key in gates) and report.get("ip_stage_reported") == "restored" and
                      report["journal_ip_stage"] == "restored" and report.get("trial_failed_event") is False and
                      report["journal_identity_mismatch"] is False and not report.get("host_or_parse_error"))


def run_reviewed(frozen, expected, output=None):
    if type(expected) is not str or re.fullmatch(r"[0-9a-f]{16}", expected) is None:
        raise ValueError("Explicit reviewed V6diag identity required")
    identity = verify_frozen(frozen, expected)
    frozen = _plain_directory(frozen)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); suffix = secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-DeviceP2pV6Diag-" + stamp + "-" + suffix)
    out.mkdir(parents=True, exist_ok=False)
    safety = _data(frozen / "runtime/mta_safety.py", MAX_SOURCE_BYTES).decode("utf-8")
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    run = "/mnt/data/p011-toolbox/sessions/mta-p2p-v2-" + stamp + "-" + suffix
    report = {"evidence_level": "P011_PRIVATE_P2P_V6_DIAGNOSTIC_GO_IP_ONLY_TRIAL", "pass": False, "candidate_identity": identity,
              "journal_version": 3, "ttl_seconds": 20, "rf_trial_invoked": False, "ip_trial_requested": True,
              "global_service_changes": False, "recovery_invoked": False, "retry_invoked": False,
              "dhcp_configuration": False, "ip_application_sockets": False, "phone_interop": "NOT_TESTED",
              "send_available": False, "ui_started": False, "user_files_accessed": False,
              "historical_v1_v2_v3_v4_v5_unchanged": True, "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
              "next_step": "REVIEW_RESULT_BEFORE_ANY_NEW_TRIAL"}
    adb = None; before = None; after = None; journal = None; stage = "target"
    try:
        adb = Adb(out / "private-raw")
        initial = "import sys\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
        if adb.python("initial-stock", initial + "\ns=stock_snapshot();require_stock(s);print('RESULT=True')") is not True:
            raise ValueError("Initial stock gate")
        stage = "candidate"
        present = adb.python("candidate-directory", initial + "\np=" + repr(target) + "\nowned_directory(p,True)\nprint('RESULT='+repr(bool(os.listdir(p))))")
        if not present:
            for folder in ("runtime", "native"):
                adb.python("candidate-subdir", initial + "\nowned_directory(" + repr(target + "/" + folder) + ",True)\nprint('RESULT=True')")
            for relative in sorted(EXPECTED_FILES):
                adb.run("push-v6diag-candidate", ["push", str(frozen / relative), target + "/" + relative])
        check = initial + "\nbase=" + repr(target) + "\nverify_candidate(base)\n"
        check += "if digest(base+'/SOURCE.sha256')!=" + repr(hashlib.sha256(_data(frozen / "SOURCE.sha256", MAX_MANIFEST_BYTES)).hexdigest()) + ":raise ValueError('manifest_pin')\n"
        check += "source_pins=" + repr(SOURCE_PINS) + "\nnative_pins=" + repr(NATIVE_PINS) + "\n"
        check += "for name,pin in source_pins.items():\n if digest(base+'/runtime/'+name)!=pin:raise ValueError('source_pin')\n"
        check += "for name,pin in native_pins.items():\n if digest(base+'/native/'+name)!=pin:raise ValueError('native_pin')\n os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        if adb.python("verify-pinned-v6diag-candidate", check) is not True:
            raise ValueError("Candidate gate")
        stage = "prior_journals"
        prior = adb.python("prior-journals-v6diag-readonly", probe_source(target, safety, PRIOR_JOURNALS))
        report["prior_journals_clear"] = bool(type(prior) is dict and prior.get("clear") is True and prior.get("global_pending_clear") is True)
        if not report["prior_journals_clear"]:
            raise ValueError("Prior ownership gate")
        stage = "network_baseline"
        before = adb.python("before-independent-v6diag", probe_source(target, safety, PROBE))
        report["preflight_passed"] = preflight_ok(before)
        if not report["preflight_passed"]:
            raise ValueError("V6diag preflight")
        stage = "owned_run_directory"
        make_run = initial + "\np=" + repr(run) + "\nif os.path.lexists(p):raise ValueError('run_exists')\nowned_directory(p,True)\nif os.stat(p).st_mode&0o777!=0o700:raise ValueError('run_mode')\nprint('RESULT=True')"
        if adb.python("new-owned-v6diag-run-directory", make_run) is not True:
            raise ValueError("Owned run gate")
        stage = "trial"
        argv = ["python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
                "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20"]
        command = " ".join(shlex.quote(value) for value in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
        report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v6diag-trial", ["shell", command], timeout=55)))
    except Exception:
        report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = adb.python("after-independent-v6diag", probe_source(target, safety, PROBE))
            except Exception:report["after_check_failed"] = True
            try:journal = adb.python("owned-journal-v6diag-readonly", probe_source(target, safety, JOURNAL, "RUN=" + repr(run) + "\n"))
            except Exception:report["journal_check_failed"] = True
        add_independent_gates(report, before, after, journal)
        if report["pass"]:
            report["next_step"] = "REVIEW_V6diag_GO_IP_ONLY_EVIDENCE_DHCP_AND_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:
            report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
        elif report.get("error_stage") == "prior_journals":
            report["next_step"] = "REVIEW_PRIVATE_PRIOR_JOURNAL_AND_PENDING_BEFORE_NEW_TRIAL"
    # Public output is assembled exclusively from fixed booleans/enums/numbers;
    # private probe values, IPv4/IPv6 records, journal and raw stdout stay out.
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("V6diag P011 owned GO + IPv4-only finite TTL20 trial. Historical V1/V2/V3/V4/V5 unchanged.\n"
        "Independent full IPv4 addresses/all route tables/default policy rules, raw IPv6, tracked PID/exe/args, station status and stock gates.\n"
        "Strict new marker/current journal; fixed known V5 prior-only registry verifies full manifest, seven pins and fresh original baseline.\n"
        "Failed-trial nested cleanup is separately sanitized, never treated as successful IP acceptance.\n"
        "Journal/pending schema3 + exact address receipt/readback required; no automatic recovery/retry or cached-PASS shortcut.\n"
        "No DHCP, application IP sockets, BLE/UI/files/phone claim, reboot or global service changes. Production send stays false.\n"
        "This TTL exit is NOT proof of real parent-death watchdog recovery or SIPC command-pool health.\n"
        "Only result.json and README.txt are public ZIP members. Private raw/identifiers/IP records/journal stay local.\n", encoding="utf-8")
    archive = Path(str(out) + ".sanitized.zip")
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):
            bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true")
    mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:
            parser.error("freeze-only does not accept execution inputs")
        _review_pins()
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV6DiagFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        safety = _data(frozen / "runtime/mta_safety.py", MAX_SOURCE_BYTES).decode("utf-8")
        target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
        for body in (PROBE, PRIOR_JOURNALS):
            probe_source(target, safety, body)
        probe_source(target, safety, JOURNAL, "RUN='/mnt/data/p011-toolbox/sessions/mta-p2p-v2-20000101-000000-00000000'\n")
        print("HOST_ONLY_V6diag_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen))
        print("No ADB/RF operation performed. Root must review the immutable V6diag snapshot before execution.")
        return 0
    if args.frozen is None or re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or "") is None:
        parser.error("execute-reviewed requires an exact reviewed V6diag identity and frozen directory")
    report, out, archive = run_reviewed(args.frozen, args.expected_candidate, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out)); print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
