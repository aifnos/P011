"""Independent V7 L3 diagnostic harness. Import/freeze-only are HOST-only.

Explicit reviewed execution may create the GO and an owned IPv4 address if all
unchanged gates pass. It is NOT a read-only trial or a file-transfer acceptance.
No old runner/globals/candidate permissions are changed; no retry or recovery.
"""
import argparse
import ast
from collections import namedtuple
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys

from device_probe import Adb, BASE, ROOT
from device_p2p import _data
from device_p2p_v2 import _plain_directory, _strict_object
import device_p2p_v6diag as old
import device_p2p_v6diag_permissions as permissions
import device_prior_journal_readonly as remote_helper
import device_candidate_permissions_readonly as historical_files

AREA = "/mnt/data/p011-toolbox"
RUNTIME_DIRECTORY = "native/private-p2p-runtime-candidate-20261001-v7l3diag/runtime"
RUNTIME_MARKER = "p011-go-ip-only-v7l3diag-1"
SOURCE_PINS = dict(old.SOURCE_PINS, **{"mta_send_wifi.py": "fbf39cfed65400f656ede96be6b12925411c19f65ac1443838e781a1baff4e93"})
NATIVE_PINS = dict(old.NATIVE_PINS)
REFERENCE_PINS = {"harness": "97f00ca99947d284921a4f382ee7c47199e40bf8e5c8de5c7cf71a33e373a93c",
    "entry": "3ca859043bfb5853a9a9778c45ba35d9635a41fdc74ad0206a0ad93067179311",
    "prior": "3e8192c9396b50e5432e21bf1754ef7bc6e3104d45af215d6591a0a120c7e617",
    "files": "ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa"}
IDENTITY3 = {"version": 3, "kind": "go_ip_only", "runtime_marker": RUNTIME_MARKER,
    "wpa_sha256": NATIVE_PINS["mta-wpa-supplicant"], "codec_sha256": SOURCE_PINS["mta_ip.py"],
    "helper_sha256": SOURCE_PINS["mta_ip_lease.py"]}
PRIOR_CANDIDATES = copy.deepcopy(old.PRIOR_CANDIDATES)
PRIOR_CANDIDATES["916a02d44aeeaf0d"] = {
    "manifest_sha256": "916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf",
    "identity": dict(IDENTITY3, runtime_marker="p011-go-ip-only-v6diag-1"),
    "pins": {relative: pin for relative, pin in historical_files.CANDIDATES["v6"]["pins"].items()
             if relative != "SOURCE.sha256"}}
PAYLOAD_FILES = frozenset(["runtime/" + name for name in SOURCE_PINS] + ["native/" + name for name in NATIVE_PINS])
EXPECTED_FILES = PAYLOAD_FILES | {"SOURCE.sha256"}
MAX_SOURCE_BYTES, MAX_BINARY_BYTES, MAX_MANIFEST_BYTES = 256 * 1024, 32 * 1024 * 1024, 32768
L3_REASONS = frozenset(("not_recorded", "accepted", "address_family", "address_prefix", "address_scope", "address_length",
    "address_not_link_local", "route_shape", "route_prefix", "route_destination", "route_source", "route_source_prefix",
    "route_gateway", "route_hex_invalid", "unexpected_l3_read"))
L3_STAGES = frozenset(("not_recorded", "address_dump", "address_fields", "ipv6_routes", "route_shape", "route_destination",
                      "route_prefix", "route_source", "route_source_prefix", "route_gateway", "done"))
L3_COUNTS = frozenset(("ipv6_address_rows", "ipv6_address_rows_examined", "ipv6_route_rows_examined"))
L3_BOOLS = frozenset(("address_dump_complete", "addresses_accepted", "routes_accepted", "route_prefix_is_128", "count_saturated"))
FILE_GATES = frozenset(("not_recorded", "directory", "file_metadata", "file_identity", "file_pin", "file_set",
                       "fchmod", "descriptor_close", "deadline", "run_directory"))
FILE_FIELDS = frozenset(("complete", "file_count", "prevalidated_count", "fchmod_attempt_count", "readback_count",
                        "descriptors_closed", "identity_sha256", "gate"))
Capsule = namedtuple("Capsule", "identity target run records safety old_files old_baseline stage normalize files last_files prior baseline journal make_run command")


def verify_reference():
    for label, module in (("harness", old), ("entry", permissions), ("prior", remote_helper), ("files", historical_files)):
        if hashlib.sha256(_data(Path(module.__file__), MAX_SOURCE_BYTES)).hexdigest() != REFERENCE_PINS[label]:
            raise ValueError("V7 reviewed reference changed")
    safety = permissions.verify_reference()
    if set(PRIOR_CANDIDATES) != {"0f2a45489fd3e03b", "916a02d44aeeaf0d"}:
        raise ValueError("V7 historical registry set changed")
    for alias in ("v5", "v6"):
        known = historical_files.CANDIDATES[alias]
        registered = PRIOR_CANDIDATES[known["identity"]]
        expected_identity = dict(IDENTITY3, runtime_marker="p011-go-ip-only-" + alias + ("diag-1" if alias == "v6" else "-1"))
        if (registered["manifest_sha256"] != known["manifest"] or registered["identity"]["runtime_marker"] !=
                "p011-go-ip-only-" + alias + ("diag-1" if alias == "v6" else "-1") or
                registered["identity"] != expected_identity or
                registered["pins"] != {key: pin for key, pin in known["pins"].items() if key != "SOURCE.sha256"}):
            raise ValueError("V7 historical full pins changed")
    return safety


def _source_check(name, raw):
    if name not in SOURCE_PINS or hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:
        raise ValueError("V7 source pin changed")
    tree = ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
    if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
        raise ValueError("V7 optimized assert ambiguity")


def freeze(destination):
    verify_reference(); records = []
    for name in sorted(SOURCE_PINS):
        folder = BASE / RUNTIME_DIRECTORY if name == "mta_send_wifi.py" else BASE / "runtime"
        raw = _data(folder / name, MAX_SOURCE_BYTES); _source_check(name, raw)
        records.append(("runtime/" + name, raw))
    for name in sorted(NATIVE_PINS):
        raw = _data(BASE / old.NATIVE_DIRECTORY / name, MAX_BINARY_BYTES); old._native_check(name, raw)
        records.append(("native/" + name, raw))
    destination = Path(destination); destination.mkdir(parents=True, exist_ok=False)
    for relative, raw in records:
        path = destination / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    manifest = "".join("%s %d %s\n" % (hashlib.sha256(raw).hexdigest(), len(raw), relative) for relative, raw in sorted(records))
    (destination / "SOURCE.sha256").write_bytes(manifest.encode("ascii"))
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    verify_reference(); directory = _plain_directory(directory)
    manifest = _data(directory / "SOURCE.sha256", MAX_MANIFEST_BYTES)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and (type(expected) is not str or re.fullmatch(r"[0-9a-f]{16}", expected) is None or identity != expected):
        raise ValueError("V7 frozen identity mismatch")
    seen = {"SOURCE.sha256"}; lines = manifest.decode("ascii").splitlines(); canonical = []
    if len(lines) != 7 or len(manifest) != 654:raise ValueError("V7 exact seven payloads required")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,9}) ((?:runtime|native)/[A-Za-z0-9_.-]+)", line)
        if match is None:raise ValueError("V7 manifest syntax")
        pin, size, relative = match.groups()
        if relative not in PAYLOAD_FILES or relative in seen:raise ValueError("V7 payload set")
        seen.add(relative); name = relative.split("/", 1)[1]
        raw = _data(directory / relative, MAX_SOURCE_BYTES if relative.startswith("runtime/") else MAX_BINARY_BYTES)
        if len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != pin:raise ValueError("V7 frozen content changed")
        _source_check(name, raw) if relative.startswith("runtime/") else old._native_check(name, raw)
        canonical.append("%s %d %s\n" % (pin, len(raw), relative))
    if manifest != "".join(sorted(canonical, key=lambda line: line.split(" ", 2)[2])).encode("ascii"):
        raise ValueError("V7 noncanonical manifest")
    observed = set()
    for folder, dirs, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in dirs):raise ValueError("V7 linked frozen directory")
        if set(dirs) != ({"runtime", "native"} if Path(folder) == directory else set()):raise ValueError("V7 frozen directories")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:raise ValueError("V7 unlisted frozen files")
    return identity


def l3_diagnostic(value):
    if (type(value) is not dict or set(value) != {"reason", "stage", "counts", "observations"} or
            type(value["reason"]) is not str or value["reason"] not in L3_REASONS or
            type(value["stage"]) is not str or value["stage"] not in L3_STAGES or
            type(value["counts"]) is not dict or set(value["counts"]) - L3_COUNTS or
            any(type(number) is not int or not 0 <= number <= 4095 for number in value["counts"].values()) or
            type(value["observations"]) is not dict or set(value["observations"]) - L3_BOOLS or
            any(type(flag) is not bool for flag in value["observations"].values())):
        raise ValueError("V7 L3 whitelist")
    reason, stage, counts, flags = value["reason"], value["stage"], value["counts"], value["observations"]
    if (any(flags.get(key) is False for key in ("address_dump_complete", "addresses_accepted", "routes_accepted", "count_saturated")) or
            flags.get("count_saturated") is True and 4095 not in counts.values()):raise ValueError("V7 L3 boolean semantics")
    if reason == "not_recorded":
        if stage != "not_recorded" or counts or flags:raise ValueError("V7 unvisited L3 facts")
    elif reason == "unexpected_l3_read" and stage in ("not_recorded", "address_dump"):
        if counts or flags:raise ValueError("V7 unread L3 facts")
    else:
        if (flags.get("address_dump_complete") is not True or "ipv6_address_rows" not in counts or
                "ipv6_address_rows_examined" not in counts or counts["ipv6_address_rows_examined"] > counts["ipv6_address_rows"]):
            raise ValueError("V7 address visit semantics")
        if flags.get("addresses_accepted") is True and counts["ipv6_address_rows_examined"] != counts["ipv6_address_rows"]:
            raise ValueError("V7 accepted address count")
        if "ipv6_route_rows_examined" in counts or "route_prefix_is_128" in flags or "routes_accepted" in flags:
            if flags.get("addresses_accepted") is not True or "ipv6_route_rows_examined" not in counts:
                raise ValueError("V7 route short circuit")
        if reason.startswith("address_"):
            if (stage != "address_fields" or counts["ipv6_address_rows_examined"] < 1 or
                    "addresses_accepted" in flags or "ipv6_route_rows_examined" in counts or "route_prefix_is_128" in flags):
                raise ValueError("V7 address rejection stage")
        if reason.startswith("route_"):
            required = "route_" + reason[6:] if reason != "route_hex_invalid" else None
            if (flags.get("addresses_accepted") is not True or counts.get("ipv6_route_rows_examined", 0) < 1 or
                    "routes_accepted" in flags or required is not None and stage != required or
                    reason == "route_hex_invalid" and stage not in {"route_destination", "route_prefix", "route_source", "route_source_prefix", "route_gateway"}):
                raise ValueError("V7 route rejection stage")
            if (reason == "route_shape" and "route_prefix_is_128" in flags or
                    reason == "route_prefix" and "route_prefix_is_128" not in flags or
                    reason in {"route_destination", "route_source", "route_source_prefix", "route_gateway"} and flags.get("route_prefix_is_128") is not False):
                raise ValueError("V7 route observed prefix semantics")
            if reason == "route_hex_invalid" and (
                    stage in {"route_destination", "route_prefix"} and "route_prefix_is_128" in flags or
                    stage in {"route_source", "route_source_prefix", "route_gateway"} and flags.get("route_prefix_is_128") is not False):
                raise ValueError("V7 invalid hex visit semantics")
        if reason == "accepted" and (stage != "done" or flags.get("addresses_accepted") is not True or
                flags.get("routes_accepted") is not True or set(counts) != L3_COUNTS or
                counts["ipv6_route_rows_examined"] > 0 and flags.get("route_prefix_is_128") is not False or
                counts["ipv6_route_rows_examined"] == 0 and "route_prefix_is_128" in flags):
            raise ValueError("V7 accepted L3 semantics")
    return copy.deepcopy(value)


def parse_trial(raw):
    if type(raw) is not bytes or len(raw) > 32768:raise ValueError("V7 trial output bound")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    rows = []; reports = []; markers = []
    for line in derived.splitlines():
        if not line.strip():continue
        if re.fullmatch(r"MTA_REMOTE_EXIT=[0-9]{1,3}", line):markers.append(line); continue
        row = json.loads(line, object_pairs_hook=_strict_object)
        if type(row) is not dict or "ip_creation_l3" not in row:raise ValueError("V7 missing L3 event")
        report = l3_diagnostic(row["ip_creation_l3"])
        if row.get("event") == "private_go_ip_ready" and report["reason"] != "accepted":
            raise ValueError("V7 ready without observed L3 acceptance")
        if report["reason"] not in {"not_recorded", "accepted", "unexpected_l3_read"}:
            gate = old._creation_gate(row.get("ip_creation_gate"))
            if gate["gate"] != "interface_l3" or gate["reason"] != "interface_l3":raise ValueError("V7 conflicting L3 rejection")
        reports.append(report); clean = dict(row); clean.pop("ip_creation_l3"); rows.append(clean)
    if len(markers) != 1 or not 1 <= len(rows) <= 2:raise ValueError("V7 event/exit count")
    if len(rows) == 2 and reports[0] != reports[1]:raise ValueError("V7 terminal L3 observation changed")
    # Only the derived copy loses the new field; Adb.run retains original bytes.
    compatibility = ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n" + markers[0] + "\n").encode("utf-8")
    result = old.parse_trial(compatibility); result["ip_creation_l3"] = reports[-1]
    return result


def probe_source(target, safety, body, extra=""):
    source = "import sys\nif sys.flags.optimize:raise ValueError('optimized_readonly_interpreter')\n"
    source += "sys.path.insert(0," + repr(target + "/runtime") + ")\n" + safety
    source += "\nverify_candidate(" + repr(target) + ")\nSOURCE_PINS=" + repr(SOURCE_PINS) + "\nNATIVE_PINS=" + repr(NATIVE_PINS) + "\n"
    source += "for name,pin in SOURCE_PINS.items():\n if digest(" + repr(target + "/runtime/") + "+name)!=pin:raise ValueError('source_pin_mismatch')\n"
    source += "for name,pin in NATIVE_PINS.items():\n if digest(" + repr(target + "/native/") + "+name)!=pin:raise ValueError('native_pin_mismatch')\n"
    source += "IDENTITY3=" + repr(IDENTITY3) + "\nPRIOR_CANDIDATES=" + repr(PRIOR_CANDIDATES) + "\nIP_STAGES=" + repr(tuple(sorted(old.IP_STAGES)))
    source += "\nMAIN_STAGES=" + repr(tuple(sorted(old.STAGES))) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\n" + extra + "\n" + body
    return checked_program(source)


def checked_program(source):
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:raise ValueError("V7 remote program bound")
    tree = ast.parse(source, feature_version=(3, 5))
    if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):raise ValueError("V7 assert ambiguity")
    return source


# This program imports no candidate. Every new file is held open and fully
# prevalidated before any fchmod; MODE=False is an independent read-only pass.
FILES_BODY = r'''
import hashlib,os,stat,time
end=time.monotonic()+25;gate='directory';fds=[];fingerprint=hashlib.sha256()
result={'complete':False,'file_count':0,'prevalidated_count':0,'fchmod_attempt_count':0,'readback_count':0,
 'descriptors_closed':True,'identity_sha256':'0'*64,'gate':'not_recorded'}
def at(value):
 global gate
 gate=value
 if time.monotonic()>=end:gate='deadline';raise ValueError('new_file_deadline')
def metadata(row):return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
def stable(row):return (row.st_dev,row.st_ino,stat.S_IFMT(row.st_mode),row.st_uid,row.st_gid,row.st_nlink,row.st_size,row.st_mtime_ns)
def directory(path):
 at('directory');owned_directory(path);row=os.lstat(path)
 if not stat.S_ISDIR(row.st_mode) or row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700 or os.path.realpath(path)!=path:raise ValueError('new_private_directory')
def hash_fd(fd,size,pin):
 at('file_pin');os.lseek(fd,0,os.SEEK_SET);count=0;value=hashlib.sha256()
 while count<size:
  at('file_pin');blob=os.read(fd,min(65536,size-count))
  if not blob:break
  count+=len(blob);value.update(blob)
 at('file_pin')
 if count!=size or os.read(fd,1) or value.hexdigest()!=pin:raise ValueError('new_file_pin')
try:
 if os.getuid()!=0 or os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('new_target')
 for path in (AREA,AREA+'/candidates',AREA+'/sessions',TARGET,TARGET+'/runtime',TARGET+'/native'):directory(path)
 identities=set()
 for relative in sorted(RECORDS):
  pin,size=RECORDS[relative];path=TARGET+'/'+relative;mode=0o500 if relative.startswith('native/') else 0o400
  at('file_metadata');before=os.lstat(path)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_size!=size or before.st_mode&0o7000 or os.path.realpath(path)!=path:raise ValueError('new_file_metadata')
  if not MODE and before.st_mode&0o7777!=mode:raise ValueError('new_file_mode')
  key=(before.st_dev,before.st_ino)
  if key in identities:raise ValueError('new_duplicate_inode')
  identities.add(key);at('file_identity');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  entry=(fd,path,before,size,pin,mode);fds.append(entry);result['file_count']+=1;os.set_inheritable(fd,False)
  if metadata(os.fstat(fd))!=metadata(before):raise ValueError('new_fd_identity')
  hash_fd(fd,size,pin)
  at('file_identity')
  if metadata(os.fstat(fd))!=metadata(before) or metadata(os.lstat(path))!=metadata(before):raise ValueError('new_final_identity')
  result['prevalidated_count']+=1
 at('file_set');observed=set()
 for folder,dirs,files in os.walk(TARGET,followlinks=False):
  directory(folder)
  if set(dirs)!=({'runtime','native'} if folder==TARGET else set()):raise ValueError('new_directory_set')
  if len(dirs)+len(files)>32 or any(os.path.islink(folder+'/'+name) for name in dirs):raise ValueError('new_file_set')
  observed.update(os.path.relpath(folder+'/'+name,TARGET).replace(os.sep,'/') for name in files)
  if len(observed)>8:raise ValueError('new_file_set')
 if observed!=set(RECORDS) or len(fds)!=8 or result['prevalidated_count']!=8:raise ValueError('new_file_set')
 for fd,path,before,size,pin,mode in fds:
  at('file_identity')
  if metadata(os.fstat(fd))!=metadata(before) or metadata(os.lstat(path))!=metadata(before):raise ValueError('new_before_write_identity')
  if MODE:
   at('fchmod');result['fchmod_attempt_count']+=1;os.fchmod(fd,mode)
  at('file_identity');actual=os.fstat(fd)
  if stable(actual)!=stable(before) or metadata(os.lstat(path))!=metadata(actual) or actual.st_mode&0o7777!=mode:raise ValueError('new_readback_identity')
  hash_fd(fd,size,pin);at('file_identity')
  if metadata(os.fstat(fd))!=metadata(actual) or metadata(os.lstat(path))!=metadata(actual):raise ValueError('new_readback_changed')
  fingerprint.update(repr(metadata(actual)).encode('ascii'));result['readback_count']+=1
 if RUN is not None:
  directory(RUN);at('run_directory')
  if os.listdir(RUN):raise ValueError('new_run_not_empty')
 result['complete']=True;result['identity_sha256']=fingerprint.hexdigest()
except Exception:result['gate']=gate
finally:
 for fd,path,before,size,pin,mode in fds:
  try:os.close(fd)
  except Exception:result['complete']=False;result['descriptors_closed']=False;result['gate']='descriptor_close'
print('RESULT='+repr(result))
'''


def files_source(safety, target, records, normalize=False, run=None):
    return checked_program("import sys\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety +
        "\nAREA=" + repr(AREA) + "\nTARGET=" + repr(target) + "\nRECORDS=" + repr(records) + "\nMODE=" + repr(normalize) + "\nRUN=" + repr(run) + "\n" + FILES_BODY)


def validate_files(value, normalize=False):
    if (type(value) is not dict or set(value) != FILE_FIELDS or type(value["complete"]) is not bool or type(value["descriptors_closed"]) is not bool or
            any(type(value[key]) is not int or not 0 <= value[key] <= 8 for key in ("file_count", "prevalidated_count", "fchmod_attempt_count", "readback_count")) or
            type(value["identity_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["identity_sha256"]) is None or
            type(value["gate"]) is not str or value["gate"] not in FILE_GATES):raise ValueError("V7 file summary schema")
    if (value["prevalidated_count"] > value["file_count"] or value["readback_count"] > value["prevalidated_count"] or
            value["fchmod_attempt_count"] and (not normalize or value["prevalidated_count"] != 8) or
            value["complete"] and (any(value[key] != 8 for key in ("file_count", "prevalidated_count", "readback_count")) or
                value["fchmod_attempt_count"] != (8 if normalize else 0) or not value["descriptors_closed"] or value["gate"] != "not_recorded")):
        raise ValueError("V7 file summary completion")
    return value


def build_capsule(frozen, expected):
    safety = verify_reference(); identity = verify_frozen(frozen, expected); frozen = _plain_directory(frozen)
    target = AREA + "/candidates/mta-01-" + identity
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    run = AREA + "/sessions/mta-p2p-v2-" + stamp
    records = {}
    for name in sorted(EXPECTED_FILES):
        raw = _data(frozen / name, MAX_BINARY_BYTES)
        pin = hashlib.sha256(raw).hexdigest()
        if name == "SOURCE.sha256":
            if len(raw) != 654 or pin[:16] != identity:raise ValueError("V7 capsule manifest changed")
        elif name.startswith("runtime/"):_source_check(name.split("/", 1)[1], raw)
        else:old._native_check(name.split("/", 1)[1], raw)
        records[name] = (pin, len(raw))
    prefix = "import sys,stat\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
    stage = prefix + "\np=" + repr(target) + "\n"
    stage += "for folder in (AREA,AREA+'/candidates',AREA+'/sessions'):\n owned_directory(folder);row=os.lstat(folder)\n if not stat.S_ISDIR(row.st_mode) or row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('stage_parent')\n"
    stage += "if os.path.lexists(p):raise ValueError('stage_exists')\nfor folder in (p,p+'/runtime',p+'/native'):\n os.mkdir(folder,0o700);owned_directory(folder);row=os.lstat(folder)\n if row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('stage_mode')\nprint('RESULT=True')"
    make_run = prefix + "\np=" + repr(run) + "\nowned_directory(AREA+'/sessions')\n"
    make_run += "row=os.lstat(AREA+'/sessions')\nif row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('run_parent')\nif os.path.lexists(p):raise ValueError('run_exists')\nos.mkdir(p,0o700);owned_directory(p)\nrow=os.lstat(p)\nif row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('run_mode')\nprint('RESULT=True')"
    argv = ("python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
            "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20")
    command = " ".join(shlex.quote(item) for item in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
    return Capsule(identity, target, run, records, safety, permissions.file_source(safety), remote_helper.source(safety),
        checked_program(stage), files_source(safety, target, records, True), files_source(safety, target, records),
        files_source(safety, target, records, run=run), probe_source(target, safety, old.PRIOR_JOURNALS),
        probe_source(target, safety, old.PROBE), probe_source(target, safety, old.JOURNAL, "RUN=" + repr(run) + "\n"),
        checked_program(make_run), command)


def run_reviewed(frozen, expected, _output=None):
    capsule = build_capsule(frozen, expected); stamp = capsule.run.rsplit("/mta-p2p-v2-", 1)[1]
    out = Path(_output) if _output is not None else ROOT / "logs" / ("MtaP011-DeviceP2pV7L3Diag-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_PRIVATE_V7_L3_DIAGNOSTIC_GO_IP_ONLY_TRIAL", "pass": False,
        "candidate_identity": capsule.identity, "journal_version": 3, "ttl_seconds": 20,
        "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
        "reviewed_reference_pins": dict(REFERENCE_PINS), "old_reference_pins_verified": True,
        "rf_trial_invoked": False, "ip_trial_requested": True, "candidate_staging_requested": True,
        "candidate_staged": False, "new_candidate_permission_write_requested": True, "new_candidate_permissions_verified": False,
        "old_candidates_permissions_modified": False, "global_service_changes": False, "recovery_invoked": False,
        "retry_invoked": False, "dhcp_configuration": False, "ip_application_sockets": False, "phone_interop": "NOT_TESTED",
        "send_available": False, "ui_started": False, "user_files_accessed": False,
        "historical_v1_v2_v3_v4_v5_v6_unchanged": True, "remote_statuses": {},
        "next_step": "REVIEW_ALL_GATES_BEFORE_ANY_NEW_TRIAL"}
    adb = None; first = before = after = journal = None; verified = run_created = False; stage = "target"
    remote = lambda label, source: remote_helper.remote(adb, label, source, report["remote_statuses"])
    try:
        adb = Adb(out / "private-raw")
        stage = "old_permissions"; old_first = permissions.validate_files(remote("initial-fixed16-readonly", capsule.old_files))
        if not old_first["complete"]:raise ValueError("V7 old file gate")
        stage = "first_baseline"; first = remote("first-independent-baseline", capsule.old_baseline); before = first
        if not old.preflight_ok(first):raise ValueError("V7 first preflight")
        stage = "candidate_directory"
        if remote("new-fresh-v7-directory", capsule.stage) is not True:raise ValueError("V7 fresh candidate gate")
        for relative in sorted(EXPECTED_FILES):adb.run("push-new-v7-file", ["push", str(Path(frozen) / relative), capsule.target + "/" + relative])
        report["candidate_staged"] = True; stage = "normalize_new_files"
        normalized = validate_files(remote("new-eight-fd-normalize", capsule.normalize), True)
        report["new_file_normalization"] = normalized
        if not normalized["complete"]:raise ValueError("V7 new normalization gate")
        stage = "new_files_readback"; files = validate_files(remote("new-eight-independent-readback", capsule.files))
        if not files["complete"] or files["identity_sha256"] != normalized["identity_sha256"]:raise ValueError("V7 new full readback gate")
        verified = True; report["new_candidate_permissions_verified"] = True
        stage = "initial_prior_journals"
        report["initial_prior_journals_clear"] = permissions.prior_ok(remote("initial-v7-prior-journals", capsule.prior))
        if not report["initial_prior_journals_clear"]:raise ValueError("V7 first prior gate")
        stage = "owned_run_directory"
        if remote("new-owned-v7-run-directory", capsule.make_run) is not True:raise ValueError("V7 run gate")
        run_created = True; stage = "last_files"
        last_files = validate_files(remote("last-new-eight-readonly", capsule.last_files))
        report["candidate_metadata_unchanged"] = last_files["complete"] and last_files["identity_sha256"] == files["identity_sha256"]
        if not report["candidate_metadata_unchanged"]:raise ValueError("V7 final new file gate")
        old_last = permissions.validate_files(remote("last-fixed16-readonly", capsule.old_files))
        report["old_candidate_metadata_unchanged"] = old_last["complete"] and old_last["identity_sha256"] == old_first["identity_sha256"]
        if not report["old_candidate_metadata_unchanged"]:raise ValueError("V7 final old file gate")
        stage = "last_prior_journals"
        report["prior_journals_clear"] = permissions.prior_ok(remote("last-v7-prior-journals", capsule.prior))
        if not report["prior_journals_clear"]:raise ValueError("V7 final prior gate")
        stage = "last_baseline"; last = remote("last-independent-baseline", capsule.baseline)
        report["pre_rf_full_baseline_equal_first"] = old.preflight_ok(last) and last == first
        if not report["pre_rf_full_baseline_equal_first"]:raise ValueError("V7 final full baseline gate")
        before = last; report["preflight_passed"] = True
        stage = "trial"; report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v7-l3diag-trial", ["shell", capsule.command], timeout=55)))
    except Exception:report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = remote("after-independent-old-reference", capsule.old_baseline)
            except Exception:report["after_check_failed"] = True
            if verified and run_created:
                try:journal = remote("owned-v7-journal-readonly", capsule.journal)
                except Exception:report["journal_check_failed"] = True
        old.add_independent_gates(report, before, after, journal)
        extra = ("old_reference_pins_verified", "candidate_staged", "new_candidate_permissions_verified", "initial_prior_journals_clear",
                 "candidate_metadata_unchanged", "old_candidate_metadata_unchanged", "pre_rf_full_baseline_equal_first")
        report["pass"] = bool(report["pass"] and all(report.get(key) is True for key in extra) and
            report.get("ip_creation_l3", {}).get("reason") == "accepted" and not report.get("after_check_failed") and not report.get("journal_check_failed"))
        if report["pass"]:report["next_step"] = "REVIEW_GO_IP_ONLY_DHCP_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Independent V7 same-read L3 diagnostic finite GO+IPv4 TTL20 trial; NOT read-only if RF invoked.\n"
        "Fresh new candidate only; eight new FDs fully prevalidated before fchmod0400/0500, independent full reread before import/RF.\n"
        "Fixed V5/V6 sixteen files are read-only; prior registry is exact full manifests/seven pins, never recovery migration.\n"
        "First/final complete baseline equal; last metadata/prior gates; one RF call and independent final full IPv4/IPv6/stock/STA/journal readback.\n"
        "No prefix/gateway/carrier/receipt/restore gate relaxation, retry/recovery/reboot/global service change or transfer/phone claim.\n"
        "Raw stdout/stderr/host exits/network/journal identifiers stay private; this harness produces no ZIP.\n", encoding="utf-8")
    return report, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true"); mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:parser.error("HOST freeze-only does not accept execution inputs")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV7L3DiagFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        build_capsule(frozen, identity)
        print("HOST_ONLY_V7_L3_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen)); return 0
    if args.frozen is None or re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or "") is None or args.output is not None:
        parser.error("Reviewed execution requires exact frozen/candidate; no output/device path/command/TTL override")
    report, out = run_reviewed(args.frozen, args.expected_candidate)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":sys.exit(main())
