"""Explicit P011 IPv4 core read-only check; never configures an address or RF.

The codec is staged under an immutable manifest. Only NETLINK_ROUTE dump
requests are sent. Raw ADB data stays local/private; result fields are fixed.
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
import sys
import zipfile

from device_probe import Adb, BASE, ROOT
from device_p2p import _data
from device_p2p_v2 import PROBE, _plain_directory, preflight_ok
from device_p2p_v4 import probe_source

CORE_SHA256 = "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5"
V4_TARGET = "/mnt/data/p011-toolbox/candidates/mta-01-43a77d612f32fba5"
V4_MANIFEST_SHA256 = "43a77d612f32fba5ecbcddfe03be5e9aca2a81f1981e2790a099f8cca5e82ae5"
SOURCES = ("mta_ip.py", "mta_safety.py", "p011_json.py")
PAYLOAD_FILES = frozenset("runtime/" + name for name in SOURCES)
EXPECTED_FILES = PAYLOAD_FILES | {"SOURCE.sha256"}
MAX_SOURCE_BYTES = 128 * 1024

BODY = r'''
import socket,sys,time
if sys.flags.optimize:raise ValueError('readonly_optimized_not_supported')
sys.path.insert(0,IP_TARGET+'/runtime')
verify_candidate(IP_TARGET)
if digest(IP_TARGET+'/runtime/mta_ip.py')!=CORE_PIN:raise ValueError('readonly_codec_pin')
import mta_ip as ip
require_stock(stock_snapshot())
if os.geteuid()!=0 or os.uname()[4]!='armv7l':raise ValueError('readonly_target')
if tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('readonly_interpreter')
end=time.monotonic()+8
connection=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE)
sequence=0
def one_snapshot():
 global sequence
 dumps=[]
 for kind in ('addresses','routes','rules'):
  sequence+=1
  collector=ip.DumpCollector(kind,sequence,port)
  remaining=end-time.monotonic()
  if remaining<=0:raise ValueError('readonly_deadline')
  connection.settimeout(remaining)
  sent=connection.sendto(collector.request,(0,0))
  if sent!=len(collector.request):raise ValueError('readonly_short_send')
  while not collector.complete:
   remaining=end-time.monotonic()
   if remaining<=0:raise ValueError('readonly_deadline')
   connection.settimeout(remaining)
   packet,ancillary,flags,peer=connection.recvmsg(ip.MAX_DATAGRAM_BYTES)
   if peer!=(0,0) or ancillary or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):
    raise ValueError('readonly_sender_or_truncation')
   collector.feed(packet)
  dumps.append(collector)
 return ip.snapshot_from_dumps(*dumps)
try:
 connection.bind((0,0))
 port,groups=connection.getsockname()
 if type(port) is not int or port<=0 or groups!=0:raise ValueError('readonly_socket_port')
 first=one_snapshot();second=one_snapshot()
 for snapshot in (first,second):
  ip.require_default_rules(snapshot)
  if not all(row.flags==ip.IFA_F_PERMANENT and row.cacheinfo is not None and
             row.cacheinfo[:2]==(ip.UINT_MAX,ip.UINT_MAX) for row in snapshot.addresses):
   raise ValueError('readonly_lifetime')
 stable=first.structural_key()==second.structural_key()
 if not stable:raise ValueError('readonly_views_changed')
 choice=ip.select_subnet(second,('192.168.49.0/24','192.168.50.0/24','172.31.249.0/24'))
 if choice.prefixlen!=24:raise ValueError('readonly_subnet')
 result={'core_imported':True,'complete_dump_sets':2,'kernel_sender_checked':True,
         'socket_port_checked':True,'unique_monotonic_sequences':sequence==6,
         'addresses_count':len(second.addresses),'routes_count':len(second.routes),
         'rules_count':len(second.rules),'permanent_infinite_addresses':True,
         'default_rules':True,'stable_complete_views':stable,'subnet_candidate_available':True}
finally:
 connection.close()
result['netlink_socket_closed']=connection.fileno()==-1
print('RESULT='+repr(result))
'''

BODY_FIELDS = frozenset(("core_imported", "complete_dump_sets", "kernel_sender_checked",
    "socket_port_checked", "unique_monotonic_sequences", "addresses_count", "routes_count",
    "rules_count", "permanent_infinite_addresses", "default_rules", "stable_complete_views",
    "subnet_candidate_available", "netlink_socket_closed"))


def _check_source(name, raw):
    ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
    if name == "mta_ip.py" and hashlib.sha256(raw).hexdigest() != CORE_SHA256:
        raise ValueError("Codec differs from reviewed stable source")


def freeze(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    lines = []
    for name in sorted(SOURCES):
        raw = _data(BASE / "runtime" / name, MAX_SOURCE_BYTES)
        _check_source(name, raw)
        relative = "runtime/" + name
        output = destination / relative
        output.parent.mkdir(exist_ok=True)
        output.write_bytes(raw)
        lines.append("%s %d %s\n" % (hashlib.sha256(raw).hexdigest(), len(raw), relative))
    (destination / "SOURCE.sha256").write_bytes("".join(lines).encode("ascii"))
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    directory = _plain_directory(directory)
    manifest = _data(directory / "SOURCE.sha256", 32768)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and identity != expected:
        raise ValueError("Reviewed codec candidate identity differs")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != len(SOURCES):
        raise ValueError("Exact three readonly sources required")
    seen = {"SOURCE.sha256"}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,6}) (runtime/[A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError("Readonly manifest syntax")
        pin, length, relative = match.groups()
        if relative not in PAYLOAD_FILES or relative in seen:
            raise ValueError("Unexpected readonly payload")
        seen.add(relative)
        raw = _data(directory / relative, MAX_SOURCE_BYTES)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Readonly content differs")
        _check_source(relative.split("/", 1)[1], raw)
    observed = set()
    for folder, directories, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in directories):
            raise ValueError("Linked readonly folder")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:
        raise ValueError("Unlisted readonly files")
    return identity


def _baseline_equal(before, after):
    fields = ("stock", "wifi", "interfaces", "network_processes", "route_digest",
              "ipv6_addresses_raw", "ipv6_routes_raw", "boot_id")
    return (preflight_ok(before) and preflight_ok(after) and
            all(before.get(field) == after.get(field) for field in fields))


def _public_fields(value):
    if type(value) is not dict or set(value) != BODY_FIELDS:
        raise ValueError("Readonly result fields")
    counts = {"complete_dump_sets", "addresses_count", "routes_count", "rules_count"}
    if any(type(value[name]) is not int or not 0 <= value[name] <= 4096 for name in counts):
        raise ValueError("Readonly count bounds")
    if any(type(value[name]) is not bool for name in BODY_FIELDS - counts):
        raise ValueError("Readonly boolean fields")
    if value["complete_dump_sets"] != 2 or not all(value[name] for name in BODY_FIELDS - counts):
        raise ValueError("Readonly core gate")
    return value


def run_reviewed(frozen, expected, output=None):
    identity = verify_frozen(frozen, expected)
    frozen = _plain_directory(frozen)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-IpCoreReadOnly-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8")
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    before = after = None
    report = {"evidence_level": "P011_IPV4_CORE_READONLY", "pass": False,
              "candidate_identity": identity, "core_sha256": CORE_SHA256,
              "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
              "radio_operations": False, "network_configuration": False,
              "ip_installation": "NOT_TESTED", "phone_interop": "NOT_TESTED",
              "project_candidate_staged": False}
    adb = None
    stage = "target"
    try:
        adb = Adb(out / "private-raw")
        if adb.python("initial-stock", safety + "\ns=stock_snapshot();require_stock(s);print('RESULT=True')") is not True:
            raise ValueError("Stock gate")
        stage = "v4-readonly-reference"
        check = safety + "\nbase=" + repr(V4_TARGET) + "\nverify_candidate(base)\n"
        check += "if digest(base+'/SOURCE.sha256')!=" + repr(V4_MANIFEST_SHA256) + ":raise ValueError('readonly_reference_pin')\nprint('RESULT=True')"
        if adb.python("verify-v4-readonly-reference", check) is not True:
            raise ValueError("Reference pin gate")
        before = adb.python("before-independent-ip-readonly", probe_source(V4_TARGET, safety, PROBE))
        if not preflight_ok(before):
            raise ValueError("Readonly initial network gate")
        stage = "candidate"
        present = adb.python("readonly-candidate-directory", safety + "\np=" + repr(target) + "\nowned_directory(p,True)\nprint('RESULT='+repr(bool(os.listdir(p))))")
        if not present:
            adb.python("readonly-runtime-directory", safety + "\nowned_directory(" + repr(target + "/runtime") + ",True)\nprint('RESULT=True')")
            for relative in sorted(EXPECTED_FILES):
                adb.run("push-readonly-core", ["push", str(frozen / relative), target + "/" + relative])
            report["project_candidate_staged"] = True
        check = safety + "\nbase=" + repr(target) + "\nverify_candidate(base)\n"
        check += "if digest(base+'/SOURCE.sha256')!=" + repr(hashlib.sha256((frozen / "SOURCE.sha256").read_bytes()).hexdigest()) + ":raise ValueError('readonly_manifest_pin')\nprint('RESULT=True')"
        if adb.python("verify-readonly-core", check) is not True:
            raise ValueError("Readonly candidate gate")
        stage = "core-dumps"
        source = safety + "\nIP_TARGET=" + repr(target) + "\nCORE_PIN=" + repr(CORE_SHA256) + "\n" + BODY
        report.update(_public_fields(adb.python("complete-views-ip-core-readonly", source, timeout=25)))
    except Exception:
        report["error_stage"] = stage
        report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:
                after = adb.python("after-independent-ip-readonly", probe_source(V4_TARGET, safety, PROBE))
            except Exception:
                report["after_check_failed"] = True
        report["independent_baseline_unchanged"] = _baseline_equal(before, after) if before and after else False
        report["pass"] = bool(report["independent_baseline_unchanged"] and report.get("core_imported") is True and
                              "host_or_parse_error" not in report and "after_check_failed" not in report)
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("P011 IPv4 codec read-only: two complete address/all-table route/rule dumps.\n"
        "Actual kernel sender and bound netlink port/sequence checked; permanent/infinite/default-policy gate.\n"
        "No RF or network configuration, IP/DHCP/socket binding or phone interop. Project source staging only.\n"
        "Full IPv4 views compared during the core phase; separate before/after baseline uses main IPv4 routes plus full IPv6 and stock/interface/process/Wi-Fi.\n"
        "Only result/README public; original raw ADB outputs retained locally/private.\n", encoding="utf-8")
    archive = out.with_suffix(".sanitized.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):
            bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true")
    mode.add_argument("--check-readonly", action="store_true")
    mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path)
    parser.add_argument("--expected-candidate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only or args.check_readonly:
        if args.frozen or args.expected_candidate:
            parser.error("Current-source freeze does not accept another execution snapshot")
        if args.check_readonly and args.output:
            parser.error("One-click readonly uses separate fresh freeze/result directories")
        out = args.output or ROOT / "logs" / ("MtaP011-IpCoreFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False)
        frozen = out / "private-candidate"
        identity = freeze(frozen)
        ast.parse(BODY, feature_version=(3, 5))
        print("HOST_ONLY_IP_CORE_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen))
        if args.freeze_only:
            return 0
        report, out, archive = run_reviewed(frozen, identity)
    else:
        if args.frozen is None or not re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or ""):
            parser.error("Explicit reviewed frozen identity required")
        report, out, archive = run_reviewed(args.frozen, args.expected_candidate, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("RESULT_DIR=" + str(out));print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
