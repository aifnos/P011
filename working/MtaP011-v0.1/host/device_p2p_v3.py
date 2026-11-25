"""Independent V3 diagnostic-only frozen P011 GO harness.

Import and --freeze-only never call ADB/RF. V1/V2 source, candidates and FAILs
are immutable. Root alone executes an explicitly reviewed identity once.
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
from device_p2p import _data, remote_source, STAGES
# Reuse only unchanged readonly strings and pure gates. Never mutate V2 globals
# or call its freeze/verify/run: V3 owns its source identity and execution path.
from device_p2p_v2 import (PROBE, PRIOR_JOURNALS, JOURNAL, DIAGNOSTIC_STAGES,
                           INIT_REQUIRED, _plain_directory, _strict_object,
                           preflight_ok, add_independent_gates)

RUNTIME_SHA256 = "eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12"
RUNTIME_DIRECTORY = "native/private-p2p-runtime-candidate-20261001-v3/runtime"
NATIVE_DIRECTORY = "native/private-p2p-candidate-20261001-v2"
NATIVE_PINS = {
    "mta-wpa-supplicant": "e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
    "mta-wifi-caps": "9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
}
FAILURE_PHASES = frozenset(("not_started", "backend_construct", "input_gate", "device_lock", "baseline_snapshot",
    "capability_query", "capability_gate", "existing_interfaces", "random_name", "pending_prepare",
    "journal_prepare", "watchdog_start", "create_lock", "create_epoch_gate", "interface_create",
    "interface_journal", "spawn_epoch_gate", "private_spawn", "process_journal", "process_epoch_gate",
    "go_epoch_gate", "group_journal", "group_add", "group_frequency_gate", "go_identity_query",
    "go_identity_gate", "go_deadline_gate", "go_ready_journal", "trial_wait", "trial_stop", "recovery"))
NETLINK_COMMANDS = frozenset(("not_recorded", "family_resolve", "get_interface", "new_interface", "del_interface"))
FAILURE_REASONS = frozenset(("lease_error", "os_error", "unexpected_error"))
SOURCE_NAMES = ("mta_send_wifi.py", "p011_json.py", "mta_safety.py")
PAYLOAD_FILES = frozenset(["runtime/" + n for n in SOURCE_NAMES] + ["native/" + n for n in NATIVE_PINS])
EXPECTED_FILES = PAYLOAD_FILES | {"SOURCE.sha256"}
MAX_MANIFEST_BYTES = 32768
MAX_SOURCE_BYTES = 512 * 1024
MAX_BINARY_BYTES = 32 * 1024 * 1024


def _source_checks(name, raw):
    tree = ast.parse(raw.decode("utf-8"), filename=name, feature_version=(3, 5))
    if name != "mta_send_wifi.py":
        return
    if hashlib.sha256(raw).hexdigest() != RUNTIME_SHA256:
        raise ValueError("Runtime V3 source differs from stable reviewed hash")
    constants = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name) or target.id not in ("WPA_SHA256", "DEVICE_LOCK", "DEVICE_PENDING", "FAILURE_PHASES", "NETLINK_COMMANDS"):
                continue
            value = node.value
            if target.id in ("FAILURE_PHASES", "NETLINK_COMMANDS"):
                if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name) or value.func.id != "frozenset" or len(value.args) != 1 or value.keywords:
                    raise ValueError("Runtime V3 fixed enum shape changed")
                constants[target.id] = frozenset(ast.literal_eval(value.args[0]))
            else:
                constants[target.id] = ast.literal_eval(value)
    if constants != {"WPA_SHA256": NATIVE_PINS["mta-wpa-supplicant"], "DEVICE_LOCK": "/tmp/p011-mta-p2p-device.lock",
                     "DEVICE_PENDING": "/tmp/p011-mta-p2p-device.pending", "FAILURE_PHASES": FAILURE_PHASES,
                     "NETLINK_COMMANDS": NETLINK_COMMANDS}:
        raise ValueError("Runtime V3 ownership pins or diagnostic enums differ")


def freeze(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for name in sorted(SOURCE_NAMES):
        directory = BASE / RUNTIME_DIRECTORY if name == "mta_send_wifi.py" else BASE / "runtime"
        raw = _data(directory / name, MAX_SOURCE_BYTES)
        _source_checks(name, raw)
        records.append(("runtime/" + name, raw))
    for name, pin in sorted(NATIVE_PINS.items()):
        raw = _data(BASE / NATIVE_DIRECTORY / name, MAX_BINARY_BYTES)
        if hashlib.sha256(raw).hexdigest() != pin or len(raw) < 20 or raw[:6] != b"\x7fELF\x01\x01" or raw[18:20] != b"\x28\x00":
            raise ValueError("Native V3 stable ARM ELF32 pin differs")
        records.append(("native/" + name, raw))
    if len(records) != 5:
        raise ValueError("V3 exact five payloads required")
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
        raise ValueError("Reviewed V3 identity mismatch")
    lines = manifest.decode("ascii").splitlines()
    if len(lines) != 5:
        raise ValueError("V3 exact five payloads required")
    seen = {"SOURCE.sha256"}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([0-9]{1,9}) ((?:runtime|native)/[A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError("V3 manifest format")
        pin, length, relative = match.groups()
        if relative not in PAYLOAD_FILES or relative in seen:
            raise ValueError("Unexpected or duplicate V3 payload")
        seen.add(relative)
        raw = _data(directory / relative, MAX_SOURCE_BYTES if relative.startswith("runtime/") else MAX_BINARY_BYTES)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("V3 frozen content changed")
        if relative.startswith("runtime/"):
            _source_checks(relative.split("/", 1)[1], raw)
        elif NATIVE_PINS[relative.split("/", 1)[1]] != pin:
            raise ValueError("V3 native pin")
    observed = set()
    for folder, directories, files in os.walk(str(directory), followlinks=False):
        if any((Path(folder) / name).is_symlink() for name in directories):
            raise ValueError("Linked V3 folder")
        observed.update((Path(folder) / name).relative_to(directory).as_posix() for name in files)
    if seen != EXPECTED_FILES or observed != EXPECTED_FILES:
        raise ValueError("V3 unlisted files")
    return identity


def probe_source(target, safety, body, extra=""):
    return remote_source(target, safety, body, "WPA_PIN=" + repr(NATIVE_PINS["mta-wpa-supplicant"]) + "\n" + extra)


def parse_trial(raw):
    if not isinstance(raw, bytes) or len(raw) > 32768:
        raise ValueError("V3 trial output limit")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    matches = re.findall(r"^MTA_REMOTE_EXIT=([0-9]{1,3})$", derived, re.M)
    if len(matches) != 1:
        raise ValueError("Unique V3 remote exit required")
    events = []
    for line in derived.splitlines():
        if line.startswith("MTA_REMOTE_EXIT=") or not line.strip():
            continue
        value = json.loads(line, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or value.get("event") not in ("private_go_ready", "private_go_cleanup", "private_go_trial_failed"):
            raise ValueError("Unexpected V3 trial event")
        events.append(value)
    if not 1 <= len(events) <= 4:
        raise ValueError("V3 event count")
    ready = [v for v in events if v["event"] == "private_go_ready"]
    cleanup = [v for v in events if v["event"] == "private_go_cleanup"]
    failed = [v for v in events if v["event"] == "private_go_trial_failed"]
    # A trace is either ready -> cleanup/failure, or an immediate failure.
    if len(ready) > 1 or len(cleanup) > 1 or len(failed) > 1 or bool(cleanup) == bool(failed) or ready and events[0] is not ready[0] or events[-1] not in cleanup + failed:
        raise ValueError("V3 event order or terminal multiplicity")
    diagnostics = events[-1].get("diagnostics")
    if not isinstance(diagnostics, dict) or set(diagnostics) != {"events", "diagnostic_invalid", "raw_diagnostics_not_logged"} or not isinstance(diagnostics["diagnostic_invalid"], bool) or diagnostics["raw_diagnostics_not_logged"] is not True:
        raise ValueError("V3 diagnostic envelope")
    rows = diagnostics["events"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("V3 diagnostic count")
    safe_rows = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"stage", "code"} or row["stage"] not in DIAGNOSTIC_STAGES.values() or isinstance(row["code"], bool) or not isinstance(row["code"], int) or not -4095 <= row["code"] <= 4095:
            raise ValueError("V3 diagnostic whitelist")
        safe_rows.append({"stage": row["stage"], "code": row["code"]})
    for item in ready:
        if set(item) != {"event", "ttl", "credentials_not_logged"} or isinstance(item["ttl"], bool) or item["ttl"] != 20 or item["credentials_not_logged"] is not True:
            raise ValueError("V3 ready fields")
    for item in cleanup:
        required = {"event", "owned_process_removed", "owned_interface_removed", "stock_baseline_equal", "complete"}
        if not required.issubset(item) or set(item) - required - {"diagnostics", "independent_readback"} or any(not isinstance(item[k], bool) for k in required - {"event"}):
            raise ValueError("V3 cleanup fields")
    public_failure = {}
    for item in failed:
        fields = {"event", "reason", "cleanup", "complete", "diagnostics", "failure_phase", "failure_errno", "netlink_command"}
        if set(item) != fields or item["complete"] is not False or not isinstance(item["cleanup"], dict) or item["reason"] not in FAILURE_REASONS:
            raise ValueError("V3 failure fields")
        phase, number, command = item["failure_phase"], item["failure_errno"], item["netlink_command"]
        if not isinstance(phase, str) or phase not in FAILURE_PHASES or isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 4095 or not isinstance(command, str) or command not in NETLINK_COMMANDS:
            raise ValueError("V3 failure diagnostic whitelist")
        public_failure = {"failure_phase": phase, "failure_errno": number, "netlink_command": command, "failure_reason": item["reason"]}
    zeros = {row["stage"] for row in safe_rows if row["code"] == 0}
    init_ok = INIT_REQUIRED.issubset(zeros) and all(row["code"] == 0 for row in safe_rows if row["stage"] in INIT_REQUIRED)
    result = {"remote_exit_zero": matches[0] == "0", "go_ready_event": len(ready) == 1,
              "cleanup_event": len(cleanup) == 1, "cleanup_complete": bool(cleanup and cleanup[-1]["complete"] is True),
              "owned_process_removed_reported": bool(cleanup and cleanup[-1]["owned_process_removed"] is True),
              "owned_interface_removed_reported": bool(cleanup and cleanup[-1]["owned_interface_removed"] is True),
              "stock_baseline_equal_reported": bool(cleanup and cleanup[-1]["stock_baseline_equal"] is True),
              "trial_failed_event": bool(failed), "diagnostics_valid": diagnostics["diagnostic_invalid"] is False,
              "early_init_success_reported": init_ok, "diagnostic_events": safe_rows}
    result.update(public_failure)
    return result


def run_reviewed(frozen, expected, output=None):
    identity = verify_frozen(frozen, expected)
    frozen = _plain_directory(frozen)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); suffix = secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-DeviceP2pV3-" + stamp + "-" + suffix)
    out.mkdir(parents=True, exist_ok=False)
    safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8")
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    # V3 is diagnostics only; original journal v2 and namespace remain unchanged.
    run = "/mnt/data/p011-toolbox/sessions/mta-p2p-v2-" + stamp + "-" + suffix
    report = {"evidence_level": "P011_PRIVATE_P2P_V3_GO_TRIAL", "pass": False, "candidate_identity": identity,
              "journal_version": 2, "ttl_seconds": 20, "rf_trial_invoked": False, "global_service_changes": False,
              "recovery_invoked": False, "retry_invoked": False, "dhcp_or_ip_configuration": False,
              "phone_interop": "NOT_TESTED", "ui_started": False, "user_files_accessed": False,
              "historical_v1_v2_unchanged": True, "next_step": "REVIEW_RESULT_BEFORE_ANY_NEW_TRIAL"}
    adb = None; before = None; after = None; journal = None; stage = "target"
    try:
        adb = Adb(out / "private-raw")
        if adb.python("initial-stock", safety + "\ns=stock_snapshot();require_stock(s);print('RESULT=True')") is not True:
            raise ValueError("Initial stock gate")
        stage = "candidate"
        present = adb.python("candidate-directory", safety + "\np=" + repr(target) + "\nowned_directory(p,True)\nprint('RESULT='+repr(bool(os.listdir(p))))")
        if not present:
            for folder in ("runtime", "native"):
                adb.python("candidate-subdir", safety + "\nowned_directory(" + repr(target + "/" + folder) + ",True)\nprint('RESULT=True')")
            for relative in sorted(EXPECTED_FILES):
                adb.run("push-v3-candidate", ["push", str(frozen / relative), target + "/" + relative])
        check = safety + "\nbase=" + repr(target) + "\nverify_candidate(base)\nassert digest(base+'/SOURCE.sha256')==" + repr(hashlib.sha256((frozen / "SOURCE.sha256").read_bytes()).hexdigest()) + "\n"
        check += "assert digest(base+'/runtime/mta_send_wifi.py')==" + repr(RUNTIME_SHA256) + "\npins=" + repr(NATIVE_PINS) + "\n"
        check += "for name,pin in pins.items():\n assert digest(base+'/native/'+name)==pin\n os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        if adb.python("verify-pinned-v3-candidate", check) is not True:
            raise ValueError("Candidate gate")
        stage = "prior_journals"
        prior = adb.python("prior-journals-v3-readonly", probe_source(target, safety, PRIOR_JOURNALS))
        report["prior_journals_clear"] = isinstance(prior, dict) and prior.get("clear") is True and prior.get("global_pending_clear") is True
        if not report["prior_journals_clear"]:
            report["next_step"] = "REVIEW_PRIVATE_PRIOR_JOURNAL_AND_PENDING_BEFORE_NEW_TRIAL"
            raise ValueError("Prior ownership gate")
        stage = "network_baseline"
        before = adb.python("before-independent-v3", probe_source(target, safety, PROBE))
        report["preflight_passed"] = preflight_ok(before)
        if not report["preflight_passed"]:
            raise ValueError("V3 P011 preflight")
        stage = "owned_run_directory"
        if adb.python("new-owned-v3-run-directory", safety + "\np=" + repr(run) + "\nassert not os.path.lexists(p)\nowned_directory(p,True)\nassert os.stat(p).st_mode&0o777==0o700\nprint('RESULT=True')") is not True:
            raise ValueError("Owned run gate")
        stage = "trial"
        argv = ["python3", "-B", target + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
                "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps", "--ttl", "20"]
        command = " ".join(shlex.quote(v) for v in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
        report["rf_trial_invoked"] = True
        report.update(parse_trial(adb.run("finite-owned-p2p-v3-trial", ["shell", command], timeout=55)))
    except Exception:
        report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = adb.python("after-independent-v3", probe_source(target, safety, PROBE))
            except Exception:report["after_check_failed"] = True
            try:
                extra = "RUN=" + repr(run) + "\nBINARY=" + repr(target + "/native/mta-wpa-supplicant") + "\nSTAGES=" + repr(tuple(sorted(STAGES))) + "\n"
                journal = adb.python("owned-journal-v3-readonly", probe_source(target, safety, JOURNAL, extra))
            except Exception:report["journal_check_failed"] = True
        add_independent_gates(report, before, after, journal)
        if report["pass"]:
            report["next_step"] = "REVIEW_V3_GO_ONLY_EVIDENCE_DHCP_AND_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:
            report["next_step"] = "REVIEW_OWNED_V2_JOURNAL_FOR_EXPLICIT_RECOVERY" if journal and journal.get("recover_review_ready") is True else "READONLY_OWNERSHIP_AND_PENDING_REVIEW_REQUIRED"
        if journal and journal.get("recover_review_ready") is True:
            recovery = " ".join(shlex.quote(v) for v in ("python3", "-B", target + "/runtime/mta_send_wifi.py", "--recover", "--run-dir", run,
                                                          "--binary", target + "/native/mta-wpa-supplicant", "--caps-probe", target + "/native/mta-wifi-caps"))
            (out / "private-next-steps.txt").write_text("Exact journal/pending/boot/interface/process readonly review required before explicit root recovery.\nNo retry or global cleanup performed.\n" + recovery + "\n", encoding="utf-8")
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("V3 diagnostic-only explicit P011 owned GO TTL20 trial; V1/V2 source/candidates/FAILs unchanged.\n"
        "Strict fixed failure phase/errno/netlink command and native stage/code allowlists.\n"
        "Independent stock/process/interface/full IPv6/IPv4/pending/journal gates preserved.\n"
        "No DHCP/IP, BLE/UI/user files/PHONE success, retry/recover/reboot/global changes.\n"
        "Only result.json/README.txt public; all raw and private records excluded.\n", encoding="utf-8")
    archive = out.with_suffix(".sanitized.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-only", action="store_true"); mode.add_argument("--execute-reviewed", action="store_true")
    parser.add_argument("--frozen", type=Path); parser.add_argument("--expected-candidate"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.freeze_only:
        if args.frozen or args.expected_candidate:parser.error("freeze-only does not accept execution snapshot")
        out = args.output or ROOT / "logs" / ("MtaP011-P2pV3Freeze-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        out.mkdir(parents=True, exist_ok=False); frozen = out / "private-candidate"; identity = freeze(frozen)
        safety = (frozen / "runtime/mta_safety.py").read_text(encoding="utf-8"); target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
        for body in (PROBE, PRIOR_JOURNALS):probe_source(target, safety, body)
        probe_source(target, safety, JOURNAL, "RUN='/mnt/data/p011-toolbox/sessions/mta-p2p-v2-20000101-000000-00000000'\nBINARY='fixture'\nSTAGES=" + repr(tuple(sorted(STAGES))) + "\n")
        print("HOST_ONLY_V3_FREEZE_PASS\nCANDIDATE_ID=" + identity + "\nFROZEN_DIRECTORY=" + str(frozen))
        print("No ADB/RF performed. Root must review this independent immutable V3 before execution.")
        return 0
    if args.frozen is None or not re.fullmatch(r"[0-9a-f]{16}", args.expected_candidate or ""):
        parser.error("execute-reviewed requires frozen V3 and reviewed identity")
    report, out, archive = run_reviewed(args.frozen, args.expected_candidate, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out)); print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
