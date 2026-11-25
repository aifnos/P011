"""Independent V8 rejected-route diagnostic entry; import is HOST-only.

Only ROOT may freeze and explicitly execute a reviewed finite GO+IP candidate.
The V7 parser/file verifier are pinned references, never patched or run.
"""
import argparse
import ast
import copy
import datetime
import hashlib
import json
from collections import namedtuple
from pathlib import Path
import re
import secrets
import shlex
import sys

from device_probe import Adb, BASE, ROOT
from device_p2p import _data
from device_p2p_v2 import _plain_directory, _strict_object
import device_p2p_v7l3diag as reference


AREA = reference.AREA
RUNTIME_DIRECTORY = "native/private-p2p-runtime-candidate-20261001-v8routediag/runtime"
RUNTIME_MARKER = "p011-go-ip-only-v8routediag-1"
SOURCE_PINS = dict(reference.SOURCE_PINS,
    **{"mta_send_wifi.py": "83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89"})
NATIVE_PINS = dict(reference.NATIVE_PINS)
REFERENCE_PINS = {"v7_harness": "1354a0f3b51a511cdbf3affdedda2ea8aa50bcf24b8221c94475fe60aa068c51",
    "v7_tests": "0e5ae55fa9d0a4d2c1b1c657fe0e81464b6019e1cb5cd66716a8ad22bc731086"}
V7_MANIFEST = "3cbd5bf8e5c718b91443a111d94c4adae297b5d988bb332a820f9f696a1e7c0e"
V7_ID = V7_MANIFEST[:16]
V7_FROZEN = ROOT / "logs/MtaP011-P2pV7L3DiagFreeze-20261001-072118-29cffe87/private-candidate"
V7_TARGET = AREA + "/candidates/mta-01-" + V7_ID
V7_RECORDS = {relative: (pin, reference.historical_files.COMMON_SIZES[relative])
    for relative, pin in reference.historical_files.COMMON_PINS.items()}
V7_RECORDS.update({"SOURCE.sha256": (V7_MANIFEST, 654),
    "runtime/mta_send_wifi.py": ("fbf39cfed65400f656ede96be6b12925411c19f65ac1443838e781a1baff4e93", 85568)})
IDENTITY3 = dict(reference.IDENTITY3, runtime_marker=RUNTIME_MARKER)
PRIOR_CANDIDATES = copy.deepcopy(reference.PRIOR_CANDIDATES)
PRIOR_CANDIDATES[V7_ID] = {"manifest_sha256": V7_MANIFEST,
    "identity": dict(reference.IDENTITY3),
    "pins": {relative: pin for relative, (pin, unused) in V7_RECORDS.items() if relative != "SOURCE.sha256"}}
EXPECTED_FILES = frozenset(reference.EXPECTED_FILES)
MAX_SOURCE_BYTES = reference.MAX_SOURCE_BYTES
MAX_BINARY_BYTES = reference.MAX_BINARY_BYTES
MAX_MANIFEST_BYTES = reference.MAX_MANIFEST_BYTES
ROUTE_CLASSES = frozenset(("linklocal", "multicast", "zero", "other"))
ROUTE_FIELDS = frozenset(("shape", "destination", "prefix", "source", "source_prefix", "gateway", "flags"))
ROUTE_FLAG_BITS = (("flags_up", 0x1), ("flags_gateway", 0x2), ("flags_host", 0x4),
    ("flags_reject", 0x200), ("flags_default", 0x10000), ("flags_addrconf", 0x40000),
    ("flags_nonexthop", 0x200000), ("flags_expires", 0x400000),
    ("flags_cache", 0x1000000), ("flags_local", 0x80000000))
ROUTE_BOOLS = frozenset(("source_zero", "source_prefix_zero", "gateway_zero", "flags_other_bits_set")) | \
    frozenset(name for name, unused in ROUTE_FLAG_BITS)
Capsule = namedtuple("Capsule", reference.Capsule._fields + ("old_v7_files",))


def verify_reference():
    paths = {"v7_harness": Path(reference.__file__),
             "v7_tests": BASE / "tests/test_device_p2p_v7l3diag.py"}
    for label, path in paths.items():
        if hashlib.sha256(_data(path, MAX_SOURCE_BYTES)).hexdigest() != REFERENCE_PINS[label]:
            raise ValueError("V8 reviewed reference changed")
    safety = reference.verify_reference()
    expected = copy.deepcopy(reference.PRIOR_CANDIDATES)
    expected[V7_ID] = {"manifest_sha256": V7_MANIFEST, "identity": dict(reference.IDENTITY3),
        "pins": {relative: pin for relative, (pin, unused) in V7_RECORDS.items() if relative != "SOURCE.sha256"}}
    if set(PRIOR_CANDIDATES) != {"0f2a45489fd3e03b", "916a02d44aeeaf0d", V7_ID} or PRIOR_CANDIDATES != expected:
        raise ValueError("V8 historical registry changed")
    if reference.verify_frozen(V7_FROZEN, V7_ID) != V7_ID or set(V7_RECORDS) != EXPECTED_FILES:
        raise ValueError("V8 fixed V7 reference changed")
    for relative, (pin, size) in V7_RECORDS.items():
        raw = _data(V7_FROZEN / relative, MAX_BINARY_BYTES)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("V8 fixed V7 full pin changed")
    return safety


def _source_check(name, raw):
    if hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:raise ValueError("V8 source pin")
    tree = ast.parse(raw.decode("utf-8"), feature_version=(3, 5))
    if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):raise ValueError("V8 assert source")


def freeze(destination):
    verify_reference(); destination = Path(destination); destination.mkdir(parents=True, exist_ok=False)
    for name in sorted(SOURCE_PINS):
        folder = BASE / RUNTIME_DIRECTORY if name == "mta_send_wifi.py" else BASE / "runtime"
        raw = _data(folder / name, MAX_SOURCE_BYTES); _source_check(name, raw)
        target = destination / "runtime" / name; target.parent.mkdir(exist_ok=True); target.write_bytes(raw)
    for name in sorted(NATIVE_PINS):
        raw = _data(BASE / reference.old.NATIVE_DIRECTORY / name, MAX_BINARY_BYTES)
        reference.old._native_check(name, raw)
        target = destination / "native" / name; target.parent.mkdir(exist_ok=True); target.write_bytes(raw)
    lines = []
    for target in sorted(path for path in destination.rglob("*") if path.is_file()):
        raw = _data(target, MAX_BINARY_BYTES)
        lines.append(hashlib.sha256(raw).hexdigest() + " " + str(len(raw)) + " " + target.relative_to(destination).as_posix())
    (destination / "SOURCE.sha256").write_bytes(("\n".join(lines) + "\n").encode("ascii"))
    return verify_frozen(destination)


def verify_frozen(directory, expected=None):
    verify_reference(); directory = _plain_directory(directory)
    manifest = _data(directory / "SOURCE.sha256", MAX_MANIFEST_BYTES)
    identity = hashlib.sha256(manifest).hexdigest()[:16]
    if expected is not None and (type(expected) is not str or re.fullmatch(r"[0-9a-f]{16}", expected) is None or expected != identity):
        raise ValueError("V8 candidate identity")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != 7 or len(manifest) != 654:raise ValueError("V8 manifest fixed size")
    paths = set(); canonical = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([1-9][0-9]{0,8}) ((?:runtime|native)/[a-z0-9_.-]+)", line)
        if not match:raise ValueError("V8 manifest syntax")
        pin, size, relative = match.groups()
        if relative in paths or relative not in EXPECTED_FILES:raise ValueError("V8 manifest file set")
        paths.add(relative); canonical.append(line); raw = _data(directory / relative, MAX_BINARY_BYTES)
        if len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != pin:raise ValueError("V8 frozen payload")
        if relative.startswith("runtime/"):_source_check(relative.split("/", 1)[1], raw)
        else:reference.old._native_check(relative.split("/", 1)[1], raw)
    if paths != EXPECTED_FILES - {"SOURCE.sha256"} or manifest != ("\n".join(sorted(canonical, key=lambda line: line.split(" ", 2)[2])) + "\n").encode("ascii"):
        raise ValueError("V8 canonical manifest")
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():raise ValueError("V8 frozen symlink")
        if path.is_file():actual.add(path.relative_to(directory).as_posix())
        elif path.is_dir() and path.relative_to(directory).as_posix() not in {"runtime", "native"}:raise ValueError("V8 frozen extra directory")
    if actual != EXPECTED_FILES:raise ValueError("V8 frozen extra files")
    return identity


def route_details(value):
    if type(value) is not dict:raise ValueError("V8 route details type")
    if not value:return {}
    if (set(value) != {"values", "observations", "invalid_fields"} or type(value["values"]) is not dict or
            set(value["values"]) - {"prefix", "destination_class"} or type(value["observations"]) is not dict or
            set(value["observations"]) - ROUTE_BOOLS or any(type(flag) is not bool for flag in value["observations"].values()) or
            type(value["invalid_fields"]) is not list or len(value["invalid_fields"]) > len(ROUTE_FIELDS) or
            any(type(field) is not str or field not in ROUTE_FIELDS for field in value["invalid_fields"]) or
            value["invalid_fields"] != sorted(set(value["invalid_fields"]))):raise ValueError("V8 route details schema")
    values = value["values"]; facts = value["observations"]; invalid = set(value["invalid_fields"])
    if ("prefix" in values and (type(values["prefix"]) is not int or not 0 <= values["prefix"] <= 128) or
            "destination_class" in values and (type(values["destination_class"]) is not str or values["destination_class"] not in ROUTE_CLASSES)):
        raise ValueError("V8 route values")
    if ("prefix" in invalid and "prefix" in values or "destination" in invalid and "destination_class" in values or
            any(field in invalid and fact in facts for field, fact in
                (("source", "source_zero"), ("source_prefix", "source_prefix_zero"), ("gateway", "gateway_zero"))) or
            "flags" in invalid and any(key.startswith("flags_") for key in facts) or
            "shape" in invalid and (invalid != {"shape"} or values or facts)):
        raise ValueError("V8 route invalid facts conflict")
    if "shape" not in invalid:
        # The frozen _route_rejected visits all six fields of a shaped row.
        # Its formatter permits partial objects, but real rejected-row events
        # must partition every field into a complete fact or an invalid token.
        expected_values = {fact for field, fact in (("prefix", "prefix"), ("destination", "destination_class")) if field not in invalid}
        expected_facts = {fact for field, fact in (("source", "source_zero"), ("source_prefix", "source_prefix_zero"), ("gateway", "gateway_zero")) if field not in invalid}
        if "flags" not in invalid:expected_facts |= {name for name in ROUTE_BOOLS if name.startswith("flags_")}
        if set(values) != expected_values or set(facts) != expected_facts:
            raise ValueError("V8 rejected route summary incomplete")
    return copy.deepcopy(value)


def l3_diagnostic(value):
    if type(value) is not dict or set(value) != {"reason", "stage", "counts", "observations", "route_details"}:
        raise ValueError("V8 L3 schema")
    details = route_details(value["route_details"]); legacy = dict(value); legacy.pop("route_details")
    reference.l3_diagnostic(legacy)
    reason = legacy["reason"]
    if reason.startswith("route_"):
        if not details:raise ValueError("V8 missing rejected route details")
        if reason == "route_shape" and details != {"values": {}, "observations": {}, "invalid_fields": ["shape"]}:
            raise ValueError("V8 shape facts")
        if reason != "route_shape" and "shape" in details["invalid_fields"]:raise ValueError("V8 conflicting shape")
        prefix = details["values"].get("prefix")
        if prefix is not None and "route_prefix_is_128" in legacy["observations"] and \
                legacy["observations"]["route_prefix_is_128"] != (prefix == 128):raise ValueError("V8 prefix facts conflict")
    elif details:raise ValueError("V8 unvisited rejected route facts")
    return copy.deepcopy(value)


def parse_trial(raw):
    if type(raw) is not bytes or len(raw) > 32768:raise ValueError("V8 trial output bound")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    rows = []; reports = []; markers = []
    for line in derived.splitlines():
        if not line.strip():continue
        if re.fullmatch(r"MTA_REMOTE_EXIT=[0-9]{1,3}", line):markers.append(line); continue
        row = json.loads(line, object_pairs_hook=_strict_object)
        if type(row) is not dict or "ip_creation_l3" not in row:raise ValueError("V8 missing L3 event")
        report = l3_diagnostic(row["ip_creation_l3"]); reports.append(report)
        clean = copy.deepcopy(row); clean["ip_creation_l3"].pop("route_details"); rows.append(clean)
    if len(markers) != 1 or not 1 <= len(rows) <= 2:raise ValueError("V8 event/exit count")
    if len(rows) == 2 and reports[0] != reports[1]:raise ValueError("V8 terminal route observation changed")
    # Only a derived copy loses route_details; original Adb bytes remain private.
    compatible = ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n" + markers[0] + "\n").encode("utf-8")
    result = reference.parse_trial(compatible); result["ip_creation_l3"] = reports[-1]
    return result


def probe_source(target, safety, body, extra=""):
    source = "import sys\nif sys.flags.optimize:raise ValueError('optimized_readonly_interpreter')\n"
    source += "sys.path.insert(0," + repr(target + "/runtime") + ")\n" + safety
    source += "\nverify_candidate(" + repr(target) + ")\nSOURCE_PINS=" + repr(SOURCE_PINS) + "\nNATIVE_PINS=" + repr(NATIVE_PINS) + "\n"
    source += "for name,pin in SOURCE_PINS.items():\n if digest(" + repr(target + "/runtime/") + "+name)!=pin:raise ValueError('source_pin_mismatch')\n"
    source += "for name,pin in NATIVE_PINS.items():\n if digest(" + repr(target + "/native/") + "+name)!=pin:raise ValueError('native_pin_mismatch')\n"
    source += "IDENTITY3=" + repr(IDENTITY3) + "\nPRIOR_CANDIDATES=" + repr(PRIOR_CANDIDATES) + "\nIP_STAGES=" + repr(tuple(sorted(reference.old.IP_STAGES)))
    source += "\nMAIN_STAGES=" + repr(tuple(sorted(reference.old.STAGES))) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\n" + extra + "\n" + body
    return reference.checked_program(source)


def build_capsule(frozen, expected):
    safety = verify_reference(); identity = verify_frozen(frozen, expected); frozen = _plain_directory(frozen)
    target = AREA + "/candidates/mta-01-" + identity
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    run = AREA + "/sessions/mta-p2p-v2-" + stamp
    records = {}
    for relative in sorted(EXPECTED_FILES):
        raw = _data(frozen / relative, MAX_BINARY_BYTES); pin = hashlib.sha256(raw).hexdigest()
        if relative == "SOURCE.sha256":
            if len(raw) != 654 or pin[:16] != identity:raise ValueError("V8 capsule manifest changed")
        elif relative.startswith("runtime/"):_source_check(relative.split("/", 1)[1], raw)
        else:reference.old._native_check(relative.split("/", 1)[1], raw)
        records[relative] = (pin, len(raw))
    prefix = "import sys,stat\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
    stage = prefix + "\np=" + repr(target) + "\n"
    stage += "for folder in (AREA,AREA+'/candidates',AREA+'/sessions'):\n owned_directory(folder);row=os.lstat(folder)\n if not stat.S_ISDIR(row.st_mode) or row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('stage_parent')\n"
    stage += "if os.path.lexists(p):raise ValueError('stage_exists')\nfor folder in (p,p+'/runtime',p+'/native'):\n os.mkdir(folder,0o700);owned_directory(folder);row=os.lstat(folder)\n if row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('stage_mode')\nprint('RESULT=True')"
    make_run = prefix + "\np=" + repr(run) + "\nowned_directory(AREA+'/sessions')\n"
    make_run += "row=os.lstat(AREA+'/sessions')\nif row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('run_parent')\nif os.path.lexists(p):raise ValueError('run_exists')\nos.mkdir(p,0o700);owned_directory(p)\nrow=os.lstat(p)\nif row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:raise ValueError('run_mode')\nprint('RESULT=True')"
    argv = ("python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
        "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20")
    command = " ".join(shlex.quote(item) for item in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
    return Capsule(identity, target, run, records, safety, reference.permissions.file_source(safety), reference.remote_helper.source(safety),
        reference.checked_program(stage), reference.files_source(safety, target, records, True), reference.files_source(safety, target, records),
        reference.files_source(safety, target, records, run=run), probe_source(target, safety, reference.old.PRIOR_JOURNALS),
        probe_source(target, safety, reference.old.PROBE), probe_source(target, safety, reference.old.JOURNAL, "RUN=" + repr(run) + "\n"),
        reference.checked_program(make_run), command, reference.files_source(safety, V7_TARGET, V7_RECORDS))


def run_reviewed(frozen, expected, _output=None):
    capsule = build_capsule(frozen, expected); stamp = capsule.run.rsplit("/mta-p2p-v2-", 1)[1]
    out = Path(_output) if _output is not None else ROOT / "logs" / ("MtaP011-DeviceP2pV8RouteDiag-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_PRIVATE_V8_REJECTED_ROUTE_DIAGNOSTIC_GO_IP_ONLY_TRIAL", "pass": False,
        "candidate_identity": capsule.identity, "journal_version": 3, "ttl_seconds": 20,
        "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
        "reviewed_reference_pins": dict(REFERENCE_PINS), "old_reference_pins_verified": True,
        "rf_trial_invoked": False, "ip_trial_requested": True, "candidate_staging_requested": True,
        "candidate_staged": False, "new_candidate_permission_write_requested": True, "new_candidate_permissions_verified": False,
        "old_candidates_permissions_modified": False, "global_service_changes": False, "recovery_invoked": False,
        "retry_invoked": False, "dhcp_configuration": False, "ip_application_sockets": False, "phone_interop": "NOT_TESTED",
        "send_available": False, "ui_started": False, "user_files_accessed": False,
        "historical_v1_v2_v3_v4_v5_v6_v7_unchanged": True, "remote_statuses": {},
        "next_step": "REVIEW_ALL_GATES_BEFORE_ANY_NEW_TRIAL"}
    adb = None; first = before = after = journal = None; verified = run_created = False; stage = "target"
    remote = lambda label, source: reference.remote_helper.remote(adb, label, source, report["remote_statuses"])
    try:
        adb = Adb(out / "private-raw")
        stage = "old_permissions"; old_first = reference.permissions.validate_files(remote("initial-fixed16-readonly", capsule.old_files))
        if not old_first["complete"]:raise ValueError("V8 old16 file gate")
        stage = "old_v7_permissions"; v7_first = reference.validate_files(remote("initial-fixed-v7-eight-readonly", capsule.old_v7_files))
        report["historical_v7_files_verified"] = v7_first["complete"]
        if not v7_first["complete"]:raise ValueError("V8 old V7 eight file gate")
        stage = "first_baseline"; first = remote("first-independent-baseline", capsule.old_baseline); before = first
        if not reference.old.preflight_ok(first):raise ValueError("V8 first preflight")
        stage = "candidate_directory"
        if remote("new-fresh-v8-directory", capsule.stage) is not True:raise ValueError("V8 fresh candidate gate")
        for relative in sorted(EXPECTED_FILES):adb.run("push-new-v8-file", ["push", str(Path(frozen) / relative), capsule.target + "/" + relative])
        report["candidate_staged"] = True; stage = "normalize_new_files"
        normalized = reference.validate_files(remote("new-eight-fd-normalize", capsule.normalize), True)
        report["new_file_normalization"] = normalized
        if not normalized["complete"]:raise ValueError("V8 new normalization gate")
        stage = "new_files_readback"; files = reference.validate_files(remote("new-eight-independent-readback", capsule.files))
        if not files["complete"] or files["identity_sha256"] != normalized["identity_sha256"]:raise ValueError("V8 new full readback gate")
        verified = True; report["new_candidate_permissions_verified"] = True
        stage = "initial_prior_journals"
        report["initial_prior_journals_clear"] = reference.permissions.prior_ok(remote("initial-v8-prior-journals", capsule.prior))
        if not report["initial_prior_journals_clear"]:raise ValueError("V8 first prior gate")
        stage = "owned_run_directory"
        if remote("new-owned-v8-run-directory", capsule.make_run) is not True:raise ValueError("V8 run gate")
        run_created = True; stage = "last_files"
        last_files = reference.validate_files(remote("last-new-eight-readonly", capsule.last_files))
        report["candidate_metadata_unchanged"] = last_files["complete"] and last_files["identity_sha256"] == files["identity_sha256"]
        if not report["candidate_metadata_unchanged"]:raise ValueError("V8 final new file gate")
        stage = "last_old_files"; old_last = reference.permissions.validate_files(remote("last-fixed16-readonly", capsule.old_files))
        report["old_candidate_metadata_unchanged"] = old_last["complete"] and old_last["identity_sha256"] == old_first["identity_sha256"]
        if not report["old_candidate_metadata_unchanged"]:raise ValueError("V8 final old16 file gate")
        stage = "last_old_v7_files"; v7_last = reference.validate_files(remote("last-fixed-v7-eight-readonly", capsule.old_v7_files))
        report["historical_v7_metadata_unchanged"] = v7_last["complete"] and v7_last["identity_sha256"] == v7_first["identity_sha256"]
        if not report["historical_v7_metadata_unchanged"]:raise ValueError("V8 final old V7 file gate")
        stage = "last_prior_journals"
        report["prior_journals_clear"] = reference.permissions.prior_ok(remote("last-v8-prior-journals", capsule.prior))
        if not report["prior_journals_clear"]:raise ValueError("V8 final prior gate")
        stage = "last_baseline"; last = remote("last-independent-baseline", capsule.baseline)
        report["pre_rf_full_baseline_equal_first"] = reference.old.preflight_ok(last) and last == first
        if not report["pre_rf_full_baseline_equal_first"]:raise ValueError("V8 final full baseline gate")
        before = last; report["preflight_passed"] = True; stage = "trial"; report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v8-routediag-trial", ["shell", capsule.command], timeout=55)))
    except Exception:report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = remote("after-independent-old-reference", capsule.old_baseline)
            except Exception:report["after_check_failed"] = True
            if verified and run_created:
                try:journal = remote("owned-v8-journal-readonly", capsule.journal)
                except Exception:report["journal_check_failed"] = True
        reference.old.add_independent_gates(report, before, after, journal)
        extra = ("old_reference_pins_verified", "historical_v7_files_verified", "historical_v7_metadata_unchanged",
            "candidate_staged", "new_candidate_permissions_verified", "initial_prior_journals_clear",
            "candidate_metadata_unchanged", "old_candidate_metadata_unchanged", "pre_rf_full_baseline_equal_first")
        report["pass"] = bool(report["pass"] and all(report.get(key) is True for key in extra) and
            report.get("ip_creation_l3", {}).get("reason") == "accepted" and not report.get("after_check_failed") and not report.get("journal_check_failed"))
        if report["pass"]:report["next_step"] = "REVIEW_GO_IP_ONLY_DHCP_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Independent V8 same-read rejected-route diagnostic GO+IPv4 TTL20 trial; NOT read-only if RF invoked.\n"
        "Fresh new eight-file candidate only, all FDs prevalidated before fchmod0400/0500 and independent full reread.\n"
        "Fixed V5/V6 sixteen files PLUS fixed V7 eight files independently read-only; full manifests/seven payload pins per candidate.\n"
        "First/final complete baseline equal; final metadata/prior gates; one RF call and independent complete IPv4/IPv6/stock/STA/journal readback.\n"
        "route_details are rejected-row observations, not route authorization; no gate/receipt/restore relaxation, retry/recovery/reboot or phone claim.\n"
        "Raw stdout/stderr/exits/network/journal identifiers remain private; this entry creates no ZIP.\n", encoding="utf-8")
    return report, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true"); mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:parser.error("HOST freeze-only does not accept execution inputs")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV8RouteDiagFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        build_capsule(frozen, identity)
        print("HOST_ONLY_V8_ROUTE_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen)); return 0
    if args.frozen is None or re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or "") is None or args.output is not None:
        parser.error("Reviewed execution requires exact frozen/candidate; no output/device path/command/TTL override")
    report, out = run_reviewed(args.frozen, args.expected_candidate)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":sys.exit(main())
