"""Fixed staged V9 entry with bounded, semantically identical stdin programs.

Import/tests are HOST-only. ROOT must first prove the earlier readonly actor
has exited, review TTY evidence, then explicitly choose a no-RF preflight or
one FUNCTIONAL GO+IP TTL20 trial. No stage/push/chmod/freeze/old runner call.
"""
import argparse
import ast
from collections import namedtuple
import copy
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import sys

from device_probe import Adb, BASE, ROOT
from device_p2p import _data
import device_p2p_v9mroute as reference

reader = reference.reader
AREA = reference.AREA
CANDIDATE = "1d695a9e8056e11f"
MANIFEST_SHA256 = "1d695a9e8056e11f20039cd3f5b3f6982645a61993f7013fbd76d81064df8c06"
FROZEN = ROOT / "logs/MtaP011-P2pV9MRouteFreeze-20261001-082341-997751ed/private-candidate"
TARGET = AREA + "/candidates/mta-01-" + CANDIDATE
REFERENCE_PINS = {
    "v9_harness": "314d7c1db02cd6591d4b4ace5197923e21145df2d3226eee749e30d90c2b8ae6",
    "v9_tests": "da66ddb073e0dcd81d889084fd2dd78f8b61433ecda48bb3b91843ee69cb9ffe",
    "v9_plan": "2be9633f8ae7631f29b342238c0224d9ed20d9c1e39cd372ec3d0daa608b1bc5",
}
SOURCE_PINS = dict(reference.SOURCE_PINS)
NATIVE_PINS = dict(reference.NATIVE_PINS)
IDENTITY3 = dict(reference.IDENTITY3)
PRIOR_CANDIDATES = copy.deepcopy(reference.PRIOR_CANDIDATES)
RECORDS = {relative: (pin, reader.historical_files.COMMON_SIZES[relative])
           for relative, pin in reader.historical_files.COMMON_PINS.items()}
RECORDS.update({"SOURCE.sha256": (MANIFEST_SHA256, 654),
    "runtime/mta_send_wifi.py": ("cfe24fba81332082d4033e148578ac088e07e7efce0ab037f499a40e887901fb", 92153)})
MAX_SOURCE_BYTES = reference.MAX_SOURCE_BYTES
MAX_LINE_BYTES = 2048
LITERAL_ASSIGNMENTS = frozenset(("CANDIDATES", "PRIOR_CANDIDATES"))
RESTORE_GATES = ("stock_independent_unchanged", "wifi_state_fingerprint_unchanged",
    "station_state_digest_unchanged", "frequency_unchanged", "route_digest_unchanged",
    "ipv6_address_digest_unchanged", "ipv6_route_digest_unchanged", "network_processes_unchanged",
    "interface_identities_unchanged", "same_boot", "full_ipv4_addresses_unchanged",
    "full_ipv4_routes_unchanged", "full_ipv4_rules_unchanged", "full_ipv4_readback_unchanged",
    "full_ipv6_readback_unchanged", "wifi_completed_after", "no_p2p_interfaces_after",
    "no_project_mta_interfaces_after", "no_private_wpa_processes_after",
    "no_project_trial_actors_after", "global_pending_clear_independent")
Capsule = namedtuple("Capsule", "run records initial_files last_files old_baseline prior baseline journal make_run command")


def _literal(value, depth=0):
    """Deterministic literal only; preserve dict insertion/sequence order."""
    if depth > 16:raise ValueError("Bounded literal depth")
    if type(value) in (str, int, bool) or value is None:return repr(value)
    if type(value) is dict:
        if not value:return "{}"
        rows = []
        for key, item in value.items():
            if type(key) is not str:raise ValueError("Bounded literal key")
            rows.append(" " * (4 * (depth + 1)) + repr(key) + ": " + _literal(item, depth + 1) + ",")
        return "{\n" + "\n".join(rows) + "\n" + " " * (4 * depth) + "}"
    if type(value) in (tuple, list):
        left, right = ("(", ")") if type(value) is tuple else ("[", "]")
        if not value:return left + right
        return left + "\n" + "\n".join(" " * (4 * (depth + 1)) + _literal(item, depth + 1) + ","
            for item in value) + "\n" + " " * (4 * depth) + right
    raise ValueError("Bounded literal type")


def bounded_program(source):
    """Only two reviewed top-level literal assignments may change whitespace."""
    if type(source) is not str or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Bounded program size")
    tree = ast.parse(source, feature_version=(3, 5)); lines = source.splitlines(keepends=True)
    edits = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):continue
        if node.targets[0].id not in LITERAL_ASSIGNMENTS:continue
        value = ast.literal_eval(node.value)
        if type(value) is not dict:raise ValueError("Bounded registry type")
        literal = _literal(value)
        if ast.literal_eval(literal) != value:raise ValueError("Bounded literal mismatch")
        edits.append((node.lineno - 1, node.end_lineno, node.targets[0].id + "=" + literal + "\n"))
    for start, end, replacement in reversed(edits):lines[start:end] = [replacement]
    result = "".join(lines); changed = ast.parse(result, feature_version=(3, 5))
    if ast.dump(tree, include_attributes=False) != ast.dump(changed, include_attributes=False):
        raise ValueError("Bounded program AST mismatch")
    if any(isinstance(node, ast.Assert) for node in ast.walk(changed)):raise ValueError("Bounded program assert")
    payload = (result + "\nprint('MTA_READONLY_OK')\n").encode("utf-8")
    if len(payload) > MAX_SOURCE_BYTES or any(len(line) > MAX_LINE_BYTES for line in payload.splitlines()):
        raise ValueError("Bounded program line or total limit")
    return result


def verify_reference():
    paths = {"v9_harness": Path(reference.__file__), "v9_tests": BASE / "tests/test_device_p2p_v9mroute.py",
             "v9_plan": BASE / "docs/P2P_TRIAL_V9_MROUTE_PLAN.md"}
    for label, path in paths.items():
        if hashlib.sha256(_data(path, MAX_SOURCE_BYTES)).hexdigest() != REFERENCE_PINS[label]:
            raise ValueError("Bounded reviewed V9 reference changed")
    safety = reference.verify_reference()
    if (SOURCE_PINS != reference.SOURCE_PINS or NATIVE_PINS != reference.NATIVE_PINS or
            IDENTITY3 != reference.IDENTITY3 or PRIOR_CANDIDATES != reference.PRIOR_CANDIDATES or
            set(PRIOR_CANDIDATES) != {"0f2a45489fd3e03b", "916a02d44aeeaf0d", reference.reference.V7_ID, reference.V8_ID}):
        raise ValueError("Bounded fixed identity or registry changed")
    if reference.verify_frozen(FROZEN, CANDIDATE) != CANDIDATE or set(RECORDS) != reference.EXPECTED_FILES:
        raise ValueError("Bounded fixed current candidate")
    for relative, (pin, size) in RECORDS.items():
        raw = _data(FROZEN / relative, reference.MAX_BINARY_BYTES)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:raise ValueError("Bounded current full pin")
    if RECORDS["SOURCE.sha256"] != (MANIFEST_SHA256, 654):raise ValueError("Bounded current manifest identity")
    return safety


def remote(adb, label, source, statuses):
    # Preserve the fixed helper's exact raw retention, unique markers and 50s
    # timeout. Rechecking here protects every generated program, not just prior.
    return reader.remote_helper.remote(adb, label, bounded_program(source), statuses)


def build_capsule(readonly_only=False):
    if type(readonly_only) is not bool:raise ValueError("Bounded mode type")
    safety = verify_reference(); run = None
    if not readonly_only:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
        run = AREA + "/sessions/mta-p2p-v2-" + stamp
    initial = {"fixed16": reader.permissions.file_source(safety),
        "v7": reader.files_source(safety, reference.reference.V7_TARGET, reference.reference.V7_RECORDS),
        "v8": reader.files_source(safety, reference.V8_TARGET, reference.V8_RECORDS),
        "v9": reader.files_source(safety, TARGET, RECORDS)}
    last = dict(initial); last["v9"] = reader.files_source(safety, TARGET, RECORDS, run=run)
    prior = reference.probe_source(TARGET, safety, reader.old.PRIOR_JOURNALS)
    baseline = reference.probe_source(TARGET, safety, reader.old.PROBE)
    old_baseline = reader.remote_helper.source(safety)
    journal = make_run = command = None
    if run is not None:
        journal = reference.probe_source(TARGET, safety, reader.old.JOURNAL, "RUN=" + repr(run) + "\n")
        make_run = "import sys,stat\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
        make_run += ("\nparent=" + repr(AREA + "/sessions") + "\nowned_directory(parent)\nv=os.lstat(parent)\n" +
            "if not stat.S_ISDIR(v.st_mode) or v.st_uid!=os.geteuid() or v.st_mode&0o7777!=0o700:raise ValueError('run_parent_mode')\n" +
            "p=" + repr(run) + "\nif os.path.lexists(p):raise ValueError('run_exists')\nos.mkdir(p,0o700)\nowned_directory(p)\n" +
            "v=os.lstat(p)\nif not stat.S_ISDIR(v.st_mode) or v.st_uid!=os.geteuid() or v.st_mode&0o7777!=0o700:raise ValueError('run_mode')\nprint('RESULT=True')")
        argv = ("python3", "-B", TARGET + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
            "--binary", TARGET + "/native/mta-wpa-supplicant", "--caps-probe", TARGET + "/native/mta-wifi-caps", "--ttl", "20")
        command = " ".join(shlex.quote(item) for item in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
    initial = {name: bounded_program(source) for name, source in initial.items()}
    last = {name: bounded_program(source) for name, source in last.items()}
    return Capsule(run, dict(RECORDS), initial, last, bounded_program(old_baseline), bounded_program(prior),
        bounded_program(baseline), None if journal is None else bounded_program(journal),
        None if make_run is None else bounded_program(make_run), command)


def _files(remote_call, label, source, group):
    value = remote_call(label, source)
    return reader.permissions.validate_files(value) if group == "fixed16" else reader.validate_files(value)


def _label(phase, group):
    return phase + "-fixed16-readonly" if group == "fixed16" else phase + "-fixed-" + group + "-eight-readonly"


def run_reviewed(readonly_only=False, _output=None):
    """Fixed candidate only; _output supports private temporary HOST fixtures."""
    capsule = build_capsule(readonly_only)
    stamp = (datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)) if readonly_only else capsule.run.rsplit("/mta-p2p-v2-", 1)[1]
    out = Path(_output) if _output is not None else ROOT / "logs" / ("MtaP011-DeviceP2pV9Bounded-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_V9_BOUNDED_READONLY_PREFLIGHT" if readonly_only else "P011_V9_BOUNDED_FUNCTIONAL_GO_IP_ONLY_TRIAL",
        "pass": False, "readonly_only": readonly_only, "readonly_preflight_complete": False,
        "candidate_identity": CANDIDATE, "journal_version": 3, "ttl_seconds": 20,
        "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
        "reviewed_reference_pins": dict(REFERENCE_PINS), "old_reference_pins_verified": True,
        "bounded_line_bytes_limit": MAX_LINE_BYTES, "bounded_prior_checks": 0,
        "rf_trial_invoked": False, "ip_trial_requested": not readonly_only, "using_preexisting_staged_candidate": True,
        "candidate_staging_requested": False, "candidate_staged": False, "permissions_modified": False,
        "new_candidate_permission_write_requested": False, "old_candidates_permissions_modified": False,
        "global_service_changes": False, "recovery_invoked": False, "retry_invoked": False,
        "dhcp_configuration": False, "ip_application_sockets": False, "phone_interop": "NOT_TESTED",
        "send_available": False, "ui_started": False, "user_files_accessed": False,
        "go_ip_ready_event": False, "cleanup_complete": False,
        "historical_v1_v2_v3_v4_v5_v6_v7_v8_unchanged": True, "remote_statuses": {},
        "next_step": "REVIEW_RESULT_BEFORE_ANY_SEPARATE_TRIAL"}
    adb = None; first = before = after = journal = None; run_created = False; stage = "target"
    remote_call = lambda label, source: remote(adb, label, source, report["remote_statuses"])
    groups = ("fixed16", "v7", "v8", "v9"); initial_files = {}
    try:
        adb = Adb(out / "private-raw")
        for group in groups:
            stage = "initial_" + group + "_files"
            value = _files(remote_call, _label("initial", group), capsule.initial_files[group], group)
            report[group + "_files_verified"] = value["complete"]
            if not value["complete"]:raise ValueError("Bounded initial fixed file gate")
            initial_files[group] = value
        stage = "first_baseline"; first = remote_call("first-independent-baseline", capsule.old_baseline); before = first
        if not reader.old.preflight_ok(first):raise ValueError("Bounded initial full baseline gate")
        stage = "initial_prior_journals"; report["bounded_prior_checks"] += 1
        report["initial_prior_journals_clear"] = reader.permissions.prior_ok(remote_call("initial-v9-bounded-prior-journals", capsule.prior))
        if not report["initial_prior_journals_clear"]:raise ValueError("Bounded initial prior gate")
        if not readonly_only:
            stage = "owned_run_directory"
            if remote_call("new-owned-v9-bounded-run-directory", capsule.make_run) is not True:raise ValueError("Bounded owned run gate")
            run_created = True
        for group in groups:
            stage = "last_" + group + "_files"
            value = _files(remote_call, _label("last", group), capsule.last_files[group], group)
            key = group + "_metadata_unchanged"
            report[key] = value["complete"] and value["identity_sha256"] == initial_files[group]["identity_sha256"]
            if not report[key]:raise ValueError("Bounded last fixed file gate")
        report["prior_journals_clear"] = report["initial_prior_journals_clear"]
        if not readonly_only:
            stage = "last_prior_journals"; report["bounded_prior_checks"] += 1
            report["prior_journals_clear"] = reader.permissions.prior_ok(remote_call("last-v9-bounded-prior-journals", capsule.prior))
            if not report["prior_journals_clear"]:raise ValueError("Bounded final prior gate")
        stage = "last_baseline"; last = remote_call("last-independent-baseline", capsule.baseline)
        report["pre_rf_full_baseline_equal_first"] = reader.old.preflight_ok(last) and last == first
        if not report["pre_rf_full_baseline_equal_first"]:raise ValueError("Bounded final full baseline gate")
        before = last; report["preflight_passed"] = True
        if not readonly_only:
            stage = "trial"; report["rf_trial_invoked"] = True
            report.update(reference.parse_trial(adb.run("finite-owned-p2p-v9-bounded-trial", ["shell", capsule.command], timeout=55)))
    except Exception:report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = remote_call("after-independent-old-reference", capsule.old_baseline)
            except Exception:report["after_check_failed"] = True
            if run_created:
                try:journal = remote_call("owned-v9-bounded-journal-readonly", capsule.journal)
                except Exception:report["journal_check_failed"] = True
        reader.old.add_independent_gates(report, before, after, journal)
        common = ("old_reference_pins_verified", "initial_prior_journals_clear", "prior_journals_clear",
                  "preflight_passed", "pre_rf_full_baseline_equal_first")
        common += tuple(group + suffix for group in groups for suffix in ("_files_verified", "_metadata_unchanged"))
        complete = all(report.get(key) is True for key in common) and not report.get("host_or_parse_error") and not report.get("after_check_failed")
        if readonly_only:
            report["readonly_preflight_complete"] = bool(complete and all(report.get(key) is True for key in RESTORE_GATES)
                and report["bounded_prior_checks"] == 1 and report["rf_trial_invoked"] is False and not run_created
                and report["go_ip_ready_event"] is False and report["ip_trial_requested"] is False)
            report["pass"] = report["readonly_preflight_complete"]
        else:
            report["pass"] = bool(report["pass"] and complete and report["bounded_prior_checks"] == 2 and
                report.get("ip_creation_l3", {}).get("reason") == "accepted" and not report.get("journal_check_failed"))
        if report["pass"]:
            report["next_step"] = "READONLY_PREFLIGHT_ONLY_REVIEW_BEFORE_SEPARATE_RF" if readonly_only else "REVIEW_FUNCTIONAL_GO_IP_ONLY_DHCP_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Fixed staged 1d695a V9 bounded stdin entry; no staging/push/chmod/freeze/recovery/retry.\n"
        "READONLY mode performs one prior probe and complete before/after fixed old16/V7eight/V8eight/currentV9eight metadata and fresh full baseline checks; no run directory or RF.\n"
        "EXECUTE mode is FUNCTIONAL GO+owned IPv4, one TTL20 call only after first/last complete baseline, all file metadata and prior gates.\n"
        "Only multiline literal formatting changes; whole-program Python3.5 AST equal, every UTF8 input line <=2048; fixed remote helper timeout remains 50s.\n"
        "Unique RESULT/OK/remote-exit markers required; HOST timeout is not remote producer exit proof. ROOT must independently prove old actor gone before invoking either mode.\n"
        "Ready cannot mask receipt/journal/full IPv4/IPv6/stock/STA restoration. No send/DHCP/BLE/UI/user files/phone acceptance; raw remains private.\n", encoding="utf-8")
    return report, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--readonly-preflight", action="store_true")
    mode.add_argument("--execute-reviewed", action="store_true")
    args = parser.parse_args()
    report, out = run_reviewed(args.readonly_preflight)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":sys.exit(main())
