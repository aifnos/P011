"""Fixed permission-normalized V6diag entry; import/tests are HOST-only.

ROOT may explicitly invoke --execute-reviewed AFTER separately reviewing and
normalizing the exact V5/V6 files. This entry never stages, pushes, chmods,
retries or recovers. It retains the reviewed V6diag runtime and every RF/IP
acceptance gate. Public reports contain no raw file/process/network identity.
"""
import argparse
import ast
from collections import namedtuple
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import sys

from device_probe import Adb, ROOT
from device_p2p import _data
import device_p2p_v6diag as reference
import device_prior_journal_readonly as prior_checker
import device_candidate_permissions_readonly as permission_checker


CANDIDATE = "916a02d44aeeaf0d"
MANIFEST_SHA256 = "916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf"
RUNTIME_SHA256 = "82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa"
REFERENCE_PINS = {
    "harness": "97f00ca99947d284921a4f382ee7c47199e40bf8e5c8de5c7cf71a33e373a93c",
    "prior_readonly": "3e8192c9396b50e5432e21bf1754ef7bc6e3104d45af215d6591a0a120c7e617",
    "permissions_readonly": "ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa",
}
FROZEN = ROOT / "logs/MtaP011-P2pV6DiagFreeze-20261001-052956-51ad245f/private-candidate"
TARGET = "/mnt/data/p011-toolbox/candidates/mta-01-" + CANDIDATE
AREA = "/mnt/data/p011-toolbox"
MAX_SOURCE_BYTES = 256 * 1024
FILE_GATES = frozenset(("not_recorded", "directory", "file_metadata", "file_identity", "file_pin",
                        "file_set", "descriptor_close", "deadline", "run_directory"))
FILE_FIELDS = frozenset(("complete", "file_count", "pins_verified", "permissions_verified",
                         "descriptors_closed", "identity_sha256", "gate"))
Capsule = namedtuple("Capsule", "run file_program last_file_program prior_program baseline_program journal_program make_run_program command")


# Standalone bounded FD-only read. No imports from mutable remote candidates
# occur before this program verifies every one of the fixed sixteen files.
FILE_BODY = r'''
import hashlib,os,stat,time
end=time.monotonic()+25;gate='directory';fingerprint=hashlib.sha256()
value={'complete':False,'file_count':0,'pins_verified':False,'permissions_verified':False,
 'descriptors_closed':True,'identity_sha256':'0'*64,'gate':'not_recorded'}
def at(label):
 global gate
 gate=label
 if time.monotonic()>=end:
  gate='deadline';raise ValueError('fixed_file_deadline')
def metadata(row):
 return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
  row.st_size,row.st_mtime_ns,row.st_ctime_ns)
def private_directory(path):
 at('directory');owned_directory(path);row=os.lstat(path)
 if not stat.S_ISDIR(row.st_mode) or row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700 or os.path.realpath(path)!=path:
  raise ValueError('fixed_private_directory')
def file_read(path,size,pin,mode):
 at('file_metadata');before=os.lstat(path)
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_mode&0o7777!=mode or before.st_size!=size or os.path.realpath(path)!=path:
  raise ValueError('fixed_file_metadata')
 fd=None
 try:
  at('file_identity');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);os.set_inheritable(fd,False)
  if metadata(os.fstat(fd))!=metadata(before):raise ValueError('fixed_fd_identity')
  at('file_pin');count=0;digestvalue=hashlib.sha256()
  while count<size:
   at('file_pin');blob=os.read(fd,min(65536,size-count))
   if not blob:break
   count+=len(blob);digestvalue.update(blob)
  at('file_pin')
  if count!=size or os.read(fd,1) or digestvalue.hexdigest()!=pin:raise ValueError('fixed_file_pin')
  at('file_identity')
  if metadata(os.fstat(fd))!=metadata(before) or metadata(os.lstat(path))!=metadata(before) or os.path.realpath(path)!=path:
   raise ValueError('fixed_final_identity')
  fingerprint.update(repr(metadata(before)).encode('ascii'))
 finally:
  if fd is not None:
   try:os.close(fd)
   except Exception:
    gate='descriptor_close';value['descriptors_closed']=False;raise
 value['file_count']+=1
try:
 if os.geteuid()!=0 or os.getuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):
  raise ValueError('fixed_p011_target')
 for folder in (AREA,AREA+'/candidates',AREA+'/sessions'):private_directory(folder)
 for alias in ('v5','v6'):
  known=CANDIDATES[alias];base=AREA+'/candidates/mta-01-'+known['identity']
  for folder in (base,base+'/runtime',base+'/native'):private_directory(folder)
  for relative in sorted(known['pins']):
   mode=0o500 if relative.startswith('native/') else 0o400
   file_read(base+'/'+relative,known['sizes'][relative],known['pins'][relative],mode)
  at('file_set');observed=set()
  for folder,dirs,files in os.walk(base,followlinks=False):
   private_directory(folder)
   if len(dirs)+len(files)>32 or any(os.path.islink(folder+'/'+name) for name in dirs):raise ValueError('fixed_file_set')
   observed.update(os.path.relpath(folder+'/'+name,base).replace(os.sep,'/') for name in files)
   if len(observed)>8:raise ValueError('fixed_file_set')
  at('file_set')
  if observed!=set(known['pins']):raise ValueError('fixed_file_set')
 if RUN is not None:
  private_directory(RUN);at('run_directory')
  if os.listdir(RUN):raise ValueError('fixed_run_not_empty')
 if value['file_count']!=16 or not value['descriptors_closed']:raise ValueError('fixed_file_count')
 value.update(complete=True,pins_verified=True,permissions_verified=True,identity_sha256=fingerprint.hexdigest())
except Exception:value['gate']=gate
print('RESULT='+repr(value))
'''


def verify_reference():
    modules = {"harness": reference, "prior_readonly": prior_checker,
               "permissions_readonly": permission_checker}
    for label, module in modules.items():
        raw = _data(Path(module.__file__), MAX_SOURCE_BYTES)
        if hashlib.sha256(raw).hexdigest() != REFERENCE_PINS[label]:
            raise ValueError("Fixed reviewed reference changed")
    if (prior_checker.FROZEN != FROZEN or prior_checker.CANDIDATE != CANDIDATE or
            prior_checker.MANIFEST_SHA256 != MANIFEST_SHA256 or prior_checker.TARGET != TARGET or
            reference.SOURCE_PINS.get("mta_send_wifi.py") != RUNTIME_SHA256):
        raise ValueError("Fixed reference constants changed")
    safety = permission_checker.verify_reference()
    if reference.verify_frozen(FROZEN, CANDIDATE) != CANDIDATE or \
            hashlib.sha256(_data(FROZEN / "SOURCE.sha256", 32768)).hexdigest() != MANIFEST_SHA256 or \
            hashlib.sha256(_data(FROZEN / "runtime/mta_send_wifi.py", MAX_SOURCE_BYTES)).hexdigest() != RUNTIME_SHA256:
        raise ValueError("Fixed permission entry frozen reference changed")
    return safety


def file_source(safety, run=None):
    if run is not None and re.fullmatch(re.escape(AREA) + r"/sessions/mta-p2p-v2-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}", run) is None:
        raise ValueError("Fixed run namespace")
    source = "import sys\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
    source += "\nAREA=" + repr(AREA) + "\nCANDIDATES=" + repr(permission_checker.CANDIDATES) + "\nRUN=" + repr(run) + "\n" + FILE_BODY
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Fixed readonly source limit")
    ast.parse(source, feature_version=(3, 5))
    return source


def validate_files(value):
    if (type(value) is not dict or set(value) != FILE_FIELDS or
            any(type(value[key]) is not bool for key in ("complete", "pins_verified", "permissions_verified", "descriptors_closed")) or
            type(value["file_count"]) is not int or not 0 <= value["file_count"] <= 16 or
            type(value["identity_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["identity_sha256"]) is None or
            type(value["gate"]) is not str or value["gate"] not in FILE_GATES):
        raise ValueError("Fixed permission result schema")
    if value["complete"] and (value["file_count"] != 16 or value["gate"] != "not_recorded" or
            not value["pins_verified"] or not value["permissions_verified"] or not value["descriptors_closed"]):
        raise ValueError("Fixed permission completion mismatch")
    if not value["complete"] and (value["pins_verified"] or value["permissions_verified"]):
        raise ValueError("Incomplete permission evidence cannot authorize")
    return value


def prior_ok(value):
    fields = {"clear", "global_pending_clear", "blocked_count", "unsafe_count", "inspected_count"}
    return (type(value) is dict and set(value) == fields and value["clear"] is True and
            value["global_pending_clear"] is True and all(type(value[key]) is int and 0 <= value[key] <= 128
            for key in ("blocked_count", "unsafe_count", "inspected_count")) and value["blocked_count"] == value["unsafe_count"] == 0)


def build_capsule():
    safety = verify_reference()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    run = AREA + "/sessions/mta-p2p-v2-" + stamp
    first = file_source(safety); last = file_source(safety, run)
    prior = reference.probe_source(TARGET, safety, reference.PRIOR_JOURNALS)
    baseline = prior_checker.source(safety)
    journal = reference.probe_source(TARGET, safety, reference.JOURNAL, "RUN=" + repr(run) + "\n")
    make_run = "import sys,stat\nif sys.flags.optimize:raise ValueError('optimized_interpreter')\n" + safety
    make_run += ("\nparent=" + repr(AREA + "/sessions") + "\nowned_directory(parent)\nv=os.lstat(parent)\n" +
                 "if not stat.S_ISDIR(v.st_mode) or v.st_uid!=os.geteuid() or v.st_mode&0o7777!=0o700:" +
                 "raise ValueError('run_parent_mode')\np=" + repr(run) +
                 "\nif os.path.lexists(p):raise ValueError('run_exists')\nos.mkdir(p,0o700)\nowned_directory(p)\n" +
                 "v=os.lstat(p)\nif not stat.S_ISDIR(v.st_mode) or v.st_uid!=os.geteuid() or v.st_mode&0o7777!=0o700:" +
                 "raise ValueError('run_mode')\nprint('RESULT=True')")
    ast.parse(make_run, feature_version=(3, 5))
    argv = ("python3", "-B", TARGET + "/runtime/mta_send_wifi.py", "--trial", "--run-dir", run,
            "--binary", TARGET + "/native/mta-wpa-supplicant", "--caps-probe", TARGET + "/native/mta-wifi-caps", "--ttl", "20")
    command = " ".join(shlex.quote(value) for value in argv) + "; r=$?; printf '\\nMTA_REMOTE_EXIT=%s\\n' \"$r\""
    return Capsule(run, first, last, prior, baseline, journal, make_run, command)


def run_reviewed(_output=None):
    """No candidate/destination inputs; _output is private HOST-fixture support."""
    capsule = build_capsule()
    stamp = capsule.run.rsplit("/mta-p2p-v2-", 1)[1]
    out = Path(_output) if _output is not None else ROOT / "logs" / ("MtaP011-DeviceP2pV6DiagPermissions-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_PRIVATE_V6DIAG_PERMISSION_NORMALIZED_ENTRY", "pass": False,
              "candidate_identity": CANDIDATE, "journal_version": 3, "ttl_seconds": 20,
              "checker_sha256": hashlib.sha256(_data(Path(__file__), MAX_SOURCE_BYTES)).hexdigest(),
              "reviewed_reference_pins": dict(REFERENCE_PINS), "old_reference_pins_verified": True,
              "rf_trial_invoked": False, "ip_trial_requested": True, "candidate_staged": False,
              "permissions_modified": False, "global_service_changes": False,
              "recovery_invoked": False, "retry_invoked": False, "dhcp_configuration": False,
              "ip_application_sockets": False, "phone_interop": "NOT_TESTED", "send_available": False,
              "ui_started": False, "user_files_accessed": False, "historical_v1_v2_v3_v4_v5_v6_unchanged": True,
              "initial_permissions_gate_passed": False, "last_permissions_gate_passed": False,
              "candidate_metadata_unchanged": False, "pre_rf_full_baseline_equal_first": False,
              "remote_statuses": {}, "next_step": "REVIEW_FIXED_ENTRY_GATES_BEFORE_ANY_NEW_TRIAL"}
    adb = None; first = before = after = journal = None; stage = "target"
    try:
        adb = Adb(out / "private-raw")
        stage = "initial_permissions"
        initial_files = validate_files(prior_checker.remote(adb, "initial-fixed16-readonly", capsule.file_program, report["remote_statuses"]))
        report["initial_permissions_gate_passed"] = initial_files["complete"]
        if not initial_files["complete"]:raise ValueError("Initial fixed permissions gate")
        stage = "initial_prior_journals"
        report["initial_prior_journals_clear"] = prior_ok(prior_checker.remote(adb, "initial-prior-journals", capsule.prior_program, report["remote_statuses"]))
        if not report["initial_prior_journals_clear"]:raise ValueError("Initial prior ownership gate")
        stage = "initial_network_baseline"
        first = prior_checker.remote(adb, "first-independent-baseline", capsule.baseline_program, report["remote_statuses"])
        if not reference.preflight_ok(first):raise ValueError("Initial full preflight gate")
        before = first
        stage = "owned_run_directory"
        if prior_checker.remote(adb, "new-owned-permissions-run-directory", capsule.make_run_program, report["remote_statuses"]) is not True:
            raise ValueError("Owned run gate")
        stage = "last_permissions"
        last_files = validate_files(prior_checker.remote(adb, "last-fixed16-readonly", capsule.last_file_program, report["remote_statuses"]))
        report["last_permissions_gate_passed"] = last_files["complete"]
        report["candidate_metadata_unchanged"] = last_files["identity_sha256"] == initial_files["identity_sha256"]
        if not last_files["complete"] or not report["candidate_metadata_unchanged"]:raise ValueError("Final fixed permissions gate")
        stage = "last_prior_journals"
        report["prior_journals_clear"] = prior_ok(prior_checker.remote(adb, "last-prior-journals", capsule.prior_program, report["remote_statuses"]))
        if not report["prior_journals_clear"]:raise ValueError("Final prior ownership gate")
        stage = "last_network_baseline"
        last = prior_checker.remote(adb, "last-independent-baseline", capsule.baseline_program, report["remote_statuses"])
        report["pre_rf_full_baseline_equal_first"] = reference.preflight_ok(last) and last == first
        if not report["pre_rf_full_baseline_equal_first"]:raise ValueError("Final full baseline gate")
        before = last; report["preflight_passed"] = True
        stage = "trial"; report["rf_trial_invoked"] = True
        report.update(reference.parse_trial(adb.run("finite-owned-p2p-v6diag-trial", ["shell", capsule.command], timeout=55)))
    except Exception:
        report["error_stage"] = stage; report["host_or_parse_error"] = True
    finally:
        if adb is not None:
            try:after = prior_checker.remote(adb, "after-independent-permissions", capsule.baseline_program, report["remote_statuses"])
            except Exception:report["after_check_failed"] = True
            try:journal = prior_checker.remote(adb, "owned-journal-permissions-readonly", capsule.journal_program, report["remote_statuses"])
            except Exception:report["journal_check_failed"] = True
        reference.add_independent_gates(report, before, after, journal)
        extra = ("old_reference_pins_verified", "initial_permissions_gate_passed", "initial_prior_journals_clear",
                 "last_permissions_gate_passed", "candidate_metadata_unchanged", "pre_rf_full_baseline_equal_first")
        report["pass"] = bool(report["pass"] and all(report.get(key) is True for key in extra) and
                              not report.get("after_check_failed") and not report.get("journal_check_failed"))
        if report["pass"]:report["next_step"] = "REVIEW_V6DIAG_GO_IP_ONLY_DHCP_PHONE_NOT_TESTED"
        elif report["rf_trial_invoked"]:report["next_step"] = "READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED"
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Fixed 916a V6diag permission-normalized entry; no staging/push/chmod/recovery/retry.\n"
        "Two independent exact16 FD-only checks precede the sole TTL20 RF call; original prior/full network gates are retained.\n"
        "The last real pre-RF full baseline must equal the first; original parser/IP diagnostic/receipt/restoration gates remain unchanged.\n"
        "PASS, if obtained, means only the finite GO+IP experiment; not DHCP, BLE, transfer, real parent-death watchdog or phone acceptance.\n"
        "Private raw and identities remain local. This entry does not produce a ZIP.\n", encoding="utf-8")
    return report, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-reviewed", action="store_true", required=True)
    parser.parse_args()
    report, out = run_reviewed()
    print(json.dumps(report, ensure_ascii=False, indent=2)); print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":sys.exit(main())
