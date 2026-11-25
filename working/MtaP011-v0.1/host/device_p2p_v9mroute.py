"""Independent functional V9 GO+IP entry; import is HOST-only.

ROOT alone may freeze/review/execute one TTL20 candidate. This is NOT merely
diagnostic: successful creation gates can install an owned IPv4 address.
No old runner/globals/permissions changes, retry/recovery or send unlock.
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
from device_p2p_v2 import _plain_directory
import device_p2p_v8routediag as reference

reader = reference.reference
AREA = reference.AREA
RUNTIME_DIRECTORY = "native/private-p2p-runtime-candidate-20261001-v9mroute/runtime"
RUNTIME_MARKER = "p011-go-ip-only-v9mroute-1"
SOURCE_PINS = dict(reference.SOURCE_PINS,
    **{"mta_send_wifi.py": "cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb"})
NATIVE_PINS = dict(reference.NATIVE_PINS)
REFERENCE_PINS = {"v8_harness": "1000b427c8df75891048b92f584ccf39f49f5f2bd679c2638d8d6f24ce3ac713",
    "v8_tests": "e7608005f0b58f7e9a32058f743af95185e2c8ab2cc3ba7f95b6b62a35690472",
    "v8_plan": "46766784b595085962ddc50d2f89a4fd887060b25942b2a0535e08223e8db02a"}
V8_MANIFEST = "7e98dbf4a03abcfaf2cbd38e5f4d95d51e2de2969166b2a3dc5557d606d03c29"
V8_ID = V8_MANIFEST[:16]
V8_FROZEN = ROOT / "logs/MtaP011-P2pV8RouteDiagFreeze-20261001-075316-238ce1ff/private-candidate"
V8_TARGET = AREA + "/candidates/mta-01-" + V8_ID
V8_RECORDS = {relative: (pin, reader.historical_files.COMMON_SIZES[relative])
    for relative, pin in reader.historical_files.COMMON_PINS.items()}
V8_RECORDS.update({"SOURCE.sha256": (V8_MANIFEST, 654),
    "runtime/mta_send_wifi.py": ("83770b7e9264dbcb8887d323e9b49771e3db46e8144a7325fccbaa8be8ba7e89", 90829)})
IDENTITY3 = dict(reference.IDENTITY3, runtime_marker=RUNTIME_MARKER)
PRIOR_CANDIDATES = copy.deepcopy(reference.PRIOR_CANDIDATES)
PRIOR_CANDIDATES[V8_ID] = {"manifest_sha256": V8_MANIFEST, "identity": dict(reference.IDENTITY3),
    "pins": {relative: pin for relative, (pin, unused) in V8_RECORDS.items() if relative != "SOURCE.sha256"}}
EXPECTED_FILES = frozenset(reference.EXPECTED_FILES)
MAX_SOURCE_BYTES = reference.MAX_SOURCE_BYTES
MAX_BINARY_BYTES = reference.MAX_BINARY_BYTES
MAX_MANIFEST_BYTES = reference.MAX_MANIFEST_BYTES
Capsule = namedtuple("Capsule", reference.Capsule._fields + ("old_v8_files",))


def verify_reference():
    paths = {"v8_harness": Path(reference.__file__), "v8_tests": BASE / "tests/test_device_p2p_v8routediag.py",
             "v8_plan": BASE / "docs/P2P_TRIAL_V8_ROUTE_PLAN.md"}
    for label, path in paths.items():
        if hashlib.sha256(_data(path, MAX_SOURCE_BYTES)).hexdigest() != REFERENCE_PINS[label]:
            raise ValueError("V9 reviewed reference changed")
    safety = reference.verify_reference()
    expected = copy.deepcopy(reference.PRIOR_CANDIDATES)
    expected[V8_ID] = {"manifest_sha256": V8_MANIFEST, "identity": dict(reference.IDENTITY3),
        "pins": {relative: pin for relative, (pin, unused) in V8_RECORDS.items() if relative != "SOURCE.sha256"}}
    if set(PRIOR_CANDIDATES) != {"0f2a45489fd3e03b", "916a02d44aeeaf0d", reference.V7_ID, V8_ID} or PRIOR_CANDIDATES != expected:
        raise ValueError("V9 historical registry changed")
    if reference.verify_frozen(V8_FROZEN, V8_ID) != V8_ID or set(V8_RECORDS) != EXPECTED_FILES:
        raise ValueError("V9 fixed V8 reference changed")
    for relative, (pin, size) in V8_RECORDS.items():
        raw = _data(V8_FROZEN / relative, MAX_BINARY_BYTES)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("V9 fixed V8 full pin changed")
    return safety


def _source_check(name, raw):
    if name not in SOURCE_PINS or hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:raise ValueError("V9 source pin")
    tree = ast.parse(raw.decode("utf-8"), feature_version=(3, 5))
    if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):raise ValueError("V9 assert source")


def freeze(destination):
    verify_reference(); destination = Path(destination); destination.mkdir(parents=True, exist_ok=False)
    for name in sorted(SOURCE_PINS):
        folder = BASE / RUNTIME_DIRECTORY if name == "mta_send_wifi.py" else BASE / "runtime"
        raw = _data(folder / name, MAX_SOURCE_BYTES); _source_check(name, raw)
        target = destination / "runtime" / name; target.parent.mkdir(exist_ok=True); target.write_bytes(raw)
    for name in sorted(NATIVE_PINS):
        raw = _data(BASE / reader.old.NATIVE_DIRECTORY / name, MAX_BINARY_BYTES)
        reader.old._native_check(name, raw)
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
        raise ValueError("V9 candidate identity")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != 7 or len(manifest) != 654:raise ValueError("V9 manifest fixed size")
    paths = set(); canonical = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([1-9][0-9]{0,8}) ((?:runtime|native)/[a-z0-9_.-]+)", line)
        if not match:raise ValueError("V9 manifest syntax")
        pin, size, relative = match.groups()
        if relative in paths or relative not in EXPECTED_FILES:raise ValueError("V9 manifest file set")
        paths.add(relative); canonical.append(line); raw = _data(directory / relative, MAX_BINARY_BYTES)
        if len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != pin:raise ValueError("V9 frozen payload")
        if relative.startswith("runtime/"):_source_check(relative.split("/", 1)[1], raw)
        else:reader.old._native_check(relative.split("/", 1)[1], raw)
    if paths != EXPECTED_FILES - {"SOURCE.sha256"} or manifest != ("\n".join(sorted(canonical, key=lambda line: line.split(" ", 2)[2])) + "\n").encode("ascii"):
        raise ValueError("V9 canonical manifest")
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():raise ValueError("V9 frozen symlink")
        if path.is_file():actual.add(path.relative_to(directory).as_posix())
        elif path.is_dir() and path.relative_to(directory).as_posix() not in {"runtime", "native"}:raise ValueError("V9 frozen extra directory")
    if actual != EXPECTED_FILES:raise ValueError("V9 frozen extra files")
    return identity


def parse_trial(raw):
    # Functional source preserves V8's exact public L3 schema; no rewrite of
    # raw bytes, event fields, failure or independent restoration facts.
    return reference.parse_trial(raw)


def probe_source(target, safety, body, extra=""):
    source = "import sys\nif sys.flags.optimize:raise ValueError('optimized_readonly_interpreter')\n"
    source += "sys.path.insert(0," + repr(target + "/runtime") + ")\n" + safety
    source += "\nverify_candidate(" + repr(target) + ")\nSOURCE_PINS=" + repr(SOURCE_PINS) + "\nNATIVE_PINS=" + repr(NATIVE_PINS) + "\n"
    source += "for name,pin in SOURCE_PINS.items():\n if digest(" + repr(target + "/runtime/") + "+name)!=pin:raise ValueError('source_pin_mismatch')\n"
    source += "for name,pin in NATIVE_PINS.items():\n if digest(" + repr(target + "/native/") + "+name)!=pin:raise ValueError('native_pin_mismatch')\n"
    source += "IDENTITY3=" + repr(IDENTITY3) + "\nPRIOR_CANDIDATES=" + repr(PRIOR_CANDIDATES) + "\nIP_STAGES=" + repr(tuple(sorted(reader.old.IP_STAGES)))
    source += "\nMAIN_STAGES=" + repr(tuple(sorted(reader.old.STAGES))) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\n" + extra + "\n" + body
    return reader.checked_program(source)


def build_capsule(frozen, expected):
    safety = verify_reference(); identity = verify_frozen(frozen, expected); frozen = _plain_directory(frozen)
    target = AREA + "/candidates/mta-01-" + identity
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    run = AREA + "/sessions/mta-p2p-v2-" + stamp
    records = {}
    for relative in sorted(EXPECTED_FILES):
        raw = _data(frozen / relative, MAX_BINARY_BYTES); pin = hashlib.sha256(raw).hexdigest()
        if relative == "SOURCE.sha256":
            if len(raw) != 654 or pin[:16] != identity:raise ValueError("V9 capsule manifest changed")
        elif relative.startswith("runtime/"):_source_check(relative.split("/", 1)[1], raw)
        else:reader.old._native_check(relative.split("/", 1)[1], raw)
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
    return Capsule(identity, target, run, records, safety, reader.permissions.file_source(safety), reader.remote_helper.source(safety),
        reader.checked_program(stage), reader.files_source(safety, target, records, True), reader.files_source(safety, target, records),
        reader.files_source(safety, target, records, run=run), probe_source(target, safety, reader.old.PRIOR_JOURNALS),
        probe_source(target, safety, reader.old.PROBE), probe_source(target, safety, reader.old.JOURNAL, "RUN=" + repr(run) + "\n"),
        reader.checked_program(make_run), command, reader.files_source(safety, reference.V7_TARGET, reference.V7_RECORDS),
        reader.files_source(safety, V8_TARGET, V8_RECORDS))


def run_reviewed(frozen, expected, _output=None):
    capsule = build_capsule(frozen, expected); stamp = capsule.run.rsplit("/mta-p2p-v2-", 1)[1]
    out = Path(_output) if _output is not None else ROOT / "logs" / ("MtaP011-DeviceP2pV9MRoute-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_PRIVATE_V9_FUNCTIONAL_GO_IP_ONLY_TRIAL", "pass": False,
        "candidate_identity": capsule.identity, "journal_version": 3, "ttl_seconds": 20,
        "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
        "reviewed_reference_pins": dict(REFERENCE_PINS), "old_reference_pins_verified": True,
        "rf_trial_invoked": False, "ip_trial_requested": True, "candidate_staging_requested": True,
        "candidate_staged": False, "new_candidate_permission_write_requested": True, "new_candidate_permissions_verified": False,
        "old_candidates_permissions_modified": False, "global_service_changes": False, "recovery_invoked": False,
        "retry_invoked": False, "dhcp_configuration": False, "ip_application_sockets": False, "phone_interop": "NOT_TESTED",
        "send_available": False, "ui_started": False, "user_files_accessed": False,
        "historical_v1_v2_v3_v4_v5_v6_v7_v8_unchanged": True, "remote_statuses": {},
        "next_step": "REVIEW_ALL_GATES_BEFORE_ANY_NEW_TRIAL"}
    adb = None; first = before = after = journal = None; verified = run_created = False; stage = "target"
    remote = lambda label, source: reader.remote_helper.remote(adb, label, source, report["remote_statuses"])
    try:
        adb = Adb(out / "private-raw")
        stage = "old_permissions"; old_first = reader.permissions.validate_files(remote("initial-fixed16-readonly", capsule.old_files))
        if not old_first["complete"]:raise ValueError("V9 old16 file gate")
        stage = "old_v7_permissions"; v7_first = reader.validate_files(remote("initial-fixed-v7-eight-readonly", capsule.old_v7_files))
        report["historical_v7_files_verified"] = v7_first["complete"]
        if not v7_first["complete"]:raise ValueError("V9 old V7 eight file gate")
        stage = "old_v8_permissions"; v8_first = reader.validate_files(remote("initial-fixed-v8-eight-readonly", capsule.old_v8_files))
        report["historical_v8_files_verified"] = v8_first["complete"]
        if not v8_first["complete"]:raise ValueError("V9 old V8 eight file gate")
        stage = "first_baseline"; first = remote("first-independent-baseline", capsule.old_baseline); before = first
        if not reader.old.preflight_ok(first):raise ValueError("V9 first preflight")
        stage = "candidate_directory"
        if remote("new-fresh-v9-directory", capsule.stage) is not True:raise ValueError("V9 fresh candidate gate")
        for relative in sorted(EXPECTED_FILES):adb.run("push-new-v9-file", ["push", str(Path(frozen) / relative), capsule.target + "/" + relative])
        report["candidate_staged"] = True; stage = "normalize_new_files"
        normalized = reader.validate_files(remote("new-eight-fd-normalize", capsule.normalize), True)
        report["new_file_normalization"] = normalized
        if not normalized["complete"]:raise ValueError("V9 new normalization gate")
        stage = "new_files_readback"; files = reader.validate_files(remote("new-eight-independent-readback", capsule.files))
        if not files["complete"] or files["identity_sha256"] != normalized["identity_sha256"]:raise ValueError("V9 new full readback gate")
        verified = True; report["new_candidate_permissions_verified"] = True
        stage = "initial_prior_journals"
        report["initial_prior_journals_clear"] = reader.permissions.prior_ok(remote("initial-v9-prior-journals", capsule.prior))
        if not report["initial_prior_journals_clear"]:raise ValueError("V9 first prior gate")
        stage = "owned_run_directory"
        if remote("new-owned-v9-run-directory", capsule.make_run) is not True:raise ValueError("V9 run gate")
        run_created = True; stage = "last_files"
        last_files = reader.validate_files(remote("last-new-eight-readonly", capsule.last_files))
        report["candidate_metadata_unchanged"] = last_files["complete"] and last_files["identity_sha256"] == files["identity_sha256"]
        if not report["candidate_metadata_unchanged"]:raise ValueError("V9 final new file gate")
        stage = "last_old_files"; old_last = reader.permissions.validate_files(remote("last-fixed16-readonly", capsule.old_files))
        report["old_candidate_metadata_unchanged"] = old_last["complete"] and old_last["identity_sha256"] == old_first["identity_sha256"]
        if not report["old_candidate_metadata_unchanged"]:raise ValueError("V9 final old16 file gate")
        for version, first_files, source in (("v7", v7_first, capsule.old_v7_files), ("v8", v8_first, capsule.old_v8_files)):
            stage = "last_old_" + version + "_files"
            last_files = reader.validate_files(remote("last-fixed-" + version + "-eight-readonly", source))
            key = "historical_" + version + "_metadata_unchanged"
            report[key] = last_files["complete"] and last_files["identity_sha256"] == first_files["identity_sha256"]
            if not report[key]:raise ValueError("V9 final historical eight file gate")
        stage = "last_prior_journals"
        report["prior_journals_clear"] = reader.permissions.prior_ok(remote("last-v9-prior-journals", capsule.prior))
        if not report["prior_journals_clear"]:raise ValueError("V9 final prior gate")
        stage = "last_baseline"; last = remote("last-independent-baseline", capsule.baseline)
        report["pre_rf_full_baseline_equal_first"] = reader.old.preflight_ok(last) and last == first
        if not report["pre_rf_full_baseline_equal_first"]:raise ValueError("V9 final full baseline gate")
        before = last; report["preflight_passed"] = True; stage = "trial"; report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v9-mroute-trial", ["shell", capsule.command], timeout=55)))
    except Exception:report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = remote("after-independent-old-reference", capsule.old_baseline)
            except Exception:report["after_check_failed"] = True
            if verified and run_created:
                try:journal = remote("owned-v9-journal-readonly", capsule.journal)
                except Exception:report["journal_check_failed"] = True
        reader.old.add_independent_gates(report, before, after, journal)
        extra = ("old_reference_pins_verified", "historical_v7_files_verified", "historical_v7_metadata_unchanged",
            "historical_v8_files_verified", "historical_v8_metadata_unchanged", "candidate_staged", "new_candidate_permissions_verified",
            "initial_prior_journals_clear", "candidate_metadata_unchanged", "old_candidate_metadata_unchanged", "pre_rf_full_baseline_equal_first")
        report["pass"] = bool(report["pass"] and all(report.get(key) is True for key in extra) and
            report.get("ip_creation_l3", {}).get("reason") == "accepted" and not report.get("after_check_failed") and not report.get("journal_check_failed"))
        if report["pass"]:report["next_step"] = "REVIEW_FUNCTIONAL_GO_IP_ONLY_DHCP_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Independent FUNCTIONAL V9 GO+owned IPv4 TTL20 trial; NOT read-only or diagnostic-only.\n"
        "Fresh new eight-file candidate only, all FDs prevalidated before fchmod0400/0500 and independent full reread.\n"
        "Fixed V5/V6 sixteen PLUS fixed V7 eight PLUS fixed V8 eight files independently read-only; each full manifest/seven payload pins.\n"
        "First/final complete baseline equal; final metadata/prior gates; one RF call and full IPv4/IPv6/stock/STA/receipt/journal readback.\n"
        "Only runtime's reviewed exact owned kernel ff00::/8 profile exception; no other restore/ownership relaxation or capability unlock.\n"
        "No retry/recovery/reboot/DHCP/BLE/UI/files/phone claim. Raw identifiers remain private; this entry creates no ZIP.\n", encoding="utf-8")
    return report, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true"); mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:parser.error("HOST freeze-only does not accept execution inputs")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV9MRouteFreeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        build_capsule(frozen, identity)
        print("HOST_ONLY_V9_FUNCTIONAL_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen)); return 0
    if args.frozen is None or re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or "") is None or args.output is not None:
        parser.error("Reviewed execution requires exact frozen/candidate; no output/device path/command/TTL override")
    report, out = run_reviewed(args.frozen, args.expected_candidate)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":sys.exit(main())
