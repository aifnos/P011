"""Explicit fixed-candidate prior-journal diagnosis; no staging or mutation.

HOST import/tests do not construct ADB. Only --check-readonly dispatches three
fixed read-only programs against the already frozen V6diag reference. Raw ADB
stdout/stderr and host exits remain private; public output is allowlisted.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import zipfile

from device_probe import Adb, ROOT
from device_p2p import _data
import device_p2p_v6diag as reference


CANDIDATE = "916a02d44aeeaf0d"
MANIFEST_SHA256 = "916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf"
HARNESS_SHA256 = "97f00ca99947d284921a4f382ee7c47199e40bf8e5c8de5c7cf71a33e373a93c"
FROZEN = ROOT / "logs/MtaP011-P2pV6DiagFreeze-20261001-052956-51ad245f/private-candidate"
TARGET = "/mnt/data/p011-toolbox/candidates/mta-01-" + CANDIDATE
MAX_SOURCE_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
STAGES = frozenset(("not_recorded", "pending", "interfaces", "sessions", "private_folder", "private_record",
    "envelope", "name", "prior_context", "schema3", "historical_baseline", "owned", "process",
    "interface_absence", "schema2_baseline", "ip_reconciliation", "complete", "deadline", "close"))
CLASSES = frozenset(("none", "value_error", "os_error", "type_error", "key_error", "unexpected_exception"))
VALUE_REASONS = frozenset(("unsafe_private_folder", "unsafe_private_record", "invalid_private_record",
    "readonly_byte_limit", "unknown_readonly_record_type", "invalid_ipv4_baseline", "invalid_ipv4_baseline_rows",
    "invalid_ipv4_address", "invalid_ipv4_label", "invalid_ipv4_broadcast", "invalid_ipv4_lifetime", "invalid_ipv4_route",
    "invalid_ipv4_route_optional", "invalid_ipv4_metrics", "invalid_ipv4_rule", "duplicate_ipv4_baseline_record",
    "nondefault_ipv4_policy", "readonly_netlink_port", "readonly_ip_deadline", "readonly_ip_short_send",
    "readonly_ip_sender", "readonly_ip_lifetime", "readonly_ip_views_changed", "invalid_ip_stage",
    "invalid_ip_resource_keys", "ip_origin_mismatch", "invalid_ip_spec", "invalid_ip_request",
    "ip_request_header_mismatch", "invalid_ip_receipt_state", "invalid_ip_receipt_address",
    "invalid_ip_receipt_label_lifetime", "invalid_journal3_identity", "invalid_journal3_stage",
    "invalid_journal3_owned", "invalid_journal3_process", "invalid_journal3_baseline_keys",
    "invalid_journal3_digest", "invalid_journal3_baseline", "invalid_journal3_deadline",
    "invalid_journal3_frequency", "invalid_journal3_interface_baseline", "invalid_journal3_station_baseline",
    "invalid_journal3_process_baseline", "invalid_journal3_cleanup", "readonly_status_timeout", "readonly_status_failed",
    "historical_candidate_unproven", "historical_manifest_permissions", "historical_manifest_pin",
    "historical_payload_pin", "unknown_historical_candidate", "session_directory_limit", "prior_journal_limit",
    "prior_name_invalid", "prior_owned_invalid", "prior_process_invalid", "prior_v2_baseline_invalid",
    "readonly_diagnostic_deadline"))
REASONS = VALUE_REASONS | {"not_recorded", "unmapped_value_error", "os_error", "type_error", "key_error", "unexpected_exception"}
CLASSIFICATIONS = frozenset(("admitted", "blocked", "unsafe", "empty"))
ROW_BOOL_FIELDS = frozenset(("historical_v5_checked", "historical_v5_baseline_checked", "historical_v5_baseline_equal",
    "process_absence_checked", "process_gone", "interface_absence_checked", "interface_gone",
    "ip_reconciliation_checked", "ip_reconciled"))
ROW_FIELDS = ROW_BOOL_FIELDS | {"ordinal", "version", "classification", "rejected_stage", "reason", "error_class", "errno"}
RESULT_BOOL_FIELDS = frozenset(("diagnostic_complete", "clear", "global_pending_clear", "global_pending_safe", "lock_safe", "netlink_socket_closed"))
RESULT_FIELDS = RESULT_BOOL_FIELDS | {"records", "inspected_count", "blocked_count", "unsafe_count", "outer_stage", "outer_reason", "outer_error_class", "outer_errno"}

# Same PRIOR admission branches, with fixed-stage observation added. This body
# does not change a journal, recover a lease, create a lock, or configure RF/IP.
BODY = r'''
end=time.monotonic()+25
def at(stage):
 if time.monotonic()>=end:raise ValueError('readonly_diagnostic_deadline')
 return stage
def error_info(error):
 if isinstance(error,OSError):
  number=error.errno
  return 'os_error','os_error',number if type(number) is int and 1<=number<=4095 else 0
 if isinstance(error,ValueError):
  token=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
  return 'value_error',token if token in VALUE_REASONS else 'unmapped_value_error',0
 if isinstance(error,TypeError):return 'type_error','type_error',0
 if isinstance(error,KeyError):return 'key_error','key_error',0
 return 'unexpected_exception','unexpected_exception',0
def row_new(ordinal):
 value={key:False for key in ROW_BOOL_FIELDS}
 value.update(ordinal=ordinal,version=0,classification='admitted',rejected_stage='not_recorded',
  reason='not_recorded',error_class='none',errno=0)
 return value
def blocked(value,stage):
 value['classification']='blocked'
 if value['rejected_stage']=='not_recorded':value['rejected_stage']=stage
root=AREA+'/sessions';seen=0;connection=None;stage='pending'
result={'diagnostic_complete':False,'clear':False,'global_pending_clear':False,'global_pending_safe':False,
 'lock_safe':False,'netlink_socket_closed':False,'records':[],'inspected_count':0,'blocked_count':0,'unsafe_count':0,
 'outer_stage':'not_recorded','outer_reason':'not_recorded','outer_error_class':'none','outer_errno':0}
try:
 stage=at('pending');pending=pending_readonly()
 result['global_pending_clear']=not pending['present'];result['global_pending_safe']=pending['safe'];result['lock_safe']=pending['lock_safe']
 stage=at('interfaces');connection=ReadWriteNetlink();interfaces=connection.interfaces()
 stage=at('sessions')
 if os.path.isdir(root):
  private_folder(root);names=sorted(os.listdir(root))
  if len(names)>512:raise ValueError('session_directory_limit')
  for name in names:
   if not re.match(r'^mta-p2p-(?:v2-)?[0-9]{8}-[0-9]{6}-[0-9a-f]{8}\Z',name):continue
   seen+=1
   if seen>128:raise ValueError('prior_journal_limit')
   folder=root+'/'+name;path=folder+'/p2p-lease.json';value=row_new(seen)
   try:
    stage=at('private_folder');private_folder(folder)
    stage=at('private_record')
    if not os.path.lexists(path):
     value['classification']='empty'
     if os.listdir(folder):blocked(value,stage)
     result['records'].append(value);continue
    record=private_record(path);version=record.get('version')
    value['version']=version if type(version) is int and version in (1,2,3) else 0
    stage=at('envelope')
    if type(version) is not int or version not in (1,2,3) or record.get('stage')!='reconciled' or record.get('cleanup_result',{}).get('complete') is not True:
     blocked(value,stage);result['records'].append(value);continue
    stage=at('name')
    if type(record.get('name')) is not str or re.match(r'^mta[0-9a-f]{8}\Z',record['name']) is None:raise ValueError('prior_name_invalid')
    if version==3:
     stage=at('prior_context');expected_identity,expected_binary,historical=prior3_context(record)
     value['historical_v5_checked']=historical
     stage=at('schema3');validate_journal3(record,expected_identity,expected_binary)
     if historical:
      stage=at('historical_baseline');matched=prior_baseline_matches(record,interfaces)
      value['historical_v5_baseline_checked']=True;value['historical_v5_baseline_equal']=matched
      if not matched:blocked(value,stage)
    owned=record.get('owned');process=record.get('process')
    stage=at('owned')
    if owned is not None and (not origin(owned) or owned['name']!=record['name'] or type(owned.get('iftype')) is not int or owned['iftype']!=8):raise ValueError('prior_owned_invalid')
    stage=at('process')
    if process is not None:
     if not numbers(process,('pid','starttime'),True) or type(process.get('exe')) is not str or not process['exe'].startswith(AREA+'/candidates/') or not process['exe'].endswith('/native/mta-wpa-supplicant'):raise ValueError('prior_process_invalid')
     gone=process_absent(process) if version==3 else _proc_identity(process['pid']) is None
     value['process_absence_checked']=True;value['process_gone']=gone
     if not gone:blocked(value,stage)
    else:value['process_absence_checked']=True;value['process_gone']=True
    stage=at('interface_absence');gone=not any(row.get('name')==record['name'] or owned is not None and row.get('wdev')==owned['wdev'] for row in interfaces)
    value['interface_absence_checked']=True;value['interface_gone']=gone
    if not gone:blocked(value,stage)
    if version==2:
     stage=at('schema2_baseline');baseline=record.get('baseline',{})
     if type(baseline.get('interfaces')) is not list or any(type(baseline.get(key)) is not str or re.match(r'^[0-9a-f]{64}\Z',baseline[key]) is None for key in ('route_digest','ipv6_route_digest','ipv6_address_digest')):raise ValueError('prior_v2_baseline_invalid')
    if version==3:
     stage=at('ip_reconciliation');matched=prior_ip_reconciled(record)
     value['ip_reconciliation_checked']=True;value['ip_reconciled']=matched
     if not matched:blocked(value,stage)
   except Exception as error:
    value['classification']='unsafe';value['rejected_stage']=stage
    value['error_class'],value['reason'],value['errno']=error_info(error)
   result['records'].append(value)
 stage=at('complete');result['diagnostic_complete']=True
except Exception as error:
 result['outer_stage']=stage;result['outer_error_class'],result['outer_reason'],result['outer_errno']=error_info(error)
finally:
 try:
  if connection is not None:connection.close()
  result['netlink_socket_closed']=True
 except Exception as error:
  result['diagnostic_complete']=False;result['outer_stage']='close'
  result['outer_error_class'],result['outer_reason'],result['outer_errno']=error_info(error)
result['inspected_count']=len(result['records'])
result['blocked_count']=sum(row['classification']=='blocked' for row in result['records'])
result['unsafe_count']=sum(row['classification']=='unsafe' for row in result['records'])
result['clear']=(result['diagnostic_complete'] and result['blocked_count']==0 and result['unsafe_count']==0 and
 result['global_pending_clear'] and result['global_pending_safe'] and result['lock_safe'])
print('RESULT='+repr(result))
'''


def validate_result(value):
    if type(value) is not dict or set(value) != RESULT_FIELDS or any(type(value[name]) is not bool for name in RESULT_BOOL_FIELDS):
        raise ValueError("Readonly diagnostic result schema")
    if any(type(value[name]) is not int or not 0 <= value[name] <= 128 for name in ("inspected_count", "blocked_count", "unsafe_count")):
        raise ValueError("Readonly diagnostic counts")
    if (type(value["records"]) is not list or len(value["records"]) != value["inspected_count"] or
            type(value["outer_stage"]) is not str or value["outer_stage"] not in STAGES or
            type(value["outer_reason"]) is not str or value["outer_reason"] not in REASONS or
            type(value["outer_error_class"]) is not str or value["outer_error_class"] not in CLASSES or
            type(value["outer_errno"]) is not int or not 0 <= value["outer_errno"] <= 4095):
        raise ValueError("Readonly diagnostic outer fields")
    for ordinal, row in enumerate(value["records"], 1):
        if (type(row) is not dict or set(row) != ROW_FIELDS or any(type(row[name]) is not bool for name in ROW_BOOL_FIELDS) or
                type(row["ordinal"]) is not int or row["ordinal"] != ordinal or type(row["version"]) is not int or row["version"] not in (0,1,2,3) or
                type(row["classification"]) is not str or row["classification"] not in CLASSIFICATIONS or
                type(row["rejected_stage"]) is not str or row["rejected_stage"] not in STAGES or
                type(row["reason"]) is not str or row["reason"] not in REASONS or type(row["error_class"]) is not str or row["error_class"] not in CLASSES or
                type(row["errno"]) is not int or not 0 <= row["errno"] <= 4095):
            raise ValueError("Readonly diagnostic row fields")
        if (any(row[flag] and not row[checked] for flag,checked in (("historical_v5_baseline_equal","historical_v5_baseline_checked"),
                ("process_gone","process_absence_checked"),("interface_gone","interface_absence_checked"),("ip_reconciled","ip_reconciliation_checked"))) or
                row["historical_v5_baseline_checked"] and not row["historical_v5_checked"] or
                row["classification"] == "unsafe" and (row["error_class"] == "none" or row["reason"] == "not_recorded" or row["rejected_stage"] == "not_recorded") or
                row["classification"] != "unsafe" and (row["error_class"] != "none" or row["reason"] != "not_recorded" or row["errno"] != 0) or
                row["classification"] == "blocked" and row["rejected_stage"] == "not_recorded"):
            raise ValueError("Readonly diagnostic observation consistency")
    if (value["blocked_count"] != sum(row["classification"] == "blocked" for row in value["records"]) or
            value["unsafe_count"] != sum(row["classification"] == "unsafe" for row in value["records"])):
        raise ValueError("Readonly diagnostic count mismatch")
    clear = (value["diagnostic_complete"] and value["blocked_count"] == value["unsafe_count"] == 0 and
             value["global_pending_clear"] and value["global_pending_safe"] and value["lock_safe"])
    if value["clear"] != clear:
        raise ValueError("Readonly diagnostic clear mismatch")
    if value["diagnostic_complete"] and (not value["netlink_socket_closed"] or value["outer_error_class"] != "none" or value["outer_reason"] != "not_recorded" or value["outer_errno"] != 0):
        raise ValueError("Readonly diagnostic completion mismatch")
    return value


def verify_reference():
    if hashlib.sha256(_data(Path(reference.__file__), MAX_SOURCE_BYTES)).hexdigest() != HARNESS_SHA256:
        raise ValueError("Fixed readonly harness reference differs")
    if reference.verify_frozen(FROZEN, CANDIDATE) != CANDIDATE or hashlib.sha256(_data(FROZEN / "SOURCE.sha256", 32768)).hexdigest() != MANIFEST_SHA256:
        raise ValueError("Fixed readonly frozen reference differs")
    return _data(FROZEN / "runtime/mta_safety.py", MAX_SOURCE_BYTES).decode("utf-8")


def source(safety, diagnostic=False):
    body = (reference.READ_HELPERS + "\nVALUE_REASONS=" + repr(tuple(sorted(VALUE_REASONS))) +
            "\nROW_BOOL_FIELDS=" + repr(tuple(sorted(ROW_BOOL_FIELDS))) + "\n" + BODY) if diagnostic else reference.PROBE
    pin = "if digest(" + repr(TARGET + "/SOURCE.sha256") + ")!=" + repr(MANIFEST_SHA256) + ":raise ValueError('readonly_manifest_pin')\n"
    result = reference.probe_source(TARGET, safety, pin + body)
    if len(result.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Readonly program limit")
    ast.parse(result, feature_version=(3,5))
    return result


def remote(adb, label, program, statuses):
    """Use Adb.run raw retention, but require exact host/remote/result markers."""
    payload = (program + "\nprint('MTA_READONLY_OK')\n").encode("utf-8")
    command = ('python3 -B -c "import sys;exec(sys.stdin.buffer.read(' + str(len(payload)) +
               '))" mta-prior-readonly; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    status = {"host": "not_recorded", "host_exit": 0, "remote": "not_recorded", "remote_exit": 0, "result_valid": False}
    statuses[label] = status
    try:
        raw = adb.run(label, ["shell", command], timeout=50, input_data=payload)
        status["host"] = "zero"; status["host_exit"] = 0
    except Exception:
        # Actual Adb retains host exit separately even on error/timeout. Never
        # publish the exception text or infer a remote exit from a host failure.
        try:
            retained = _data(adb.directory / ("%02d-%s.host-exit" % (adb.index,label)), 32).decode("ascii")
            if retained == "TIMEOUT":status["host"] = "timeout"
            elif re.fullmatch(r"-?[0-9]{1,10}", retained) and -(2**31) <= int(retained) <= 2**32-1:
                status["host"] = "zero" if int(retained) == 0 else "nonzero"; status["host_exit"] = int(retained)
        except Exception:pass
        raise
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("Readonly output bound")
    derived = raw.decode("utf-8", "strict").replace("\r\r\n", "\n").replace("\r\n", "\n")
    exits = re.findall(r"^MTA_REMOTE_EXIT=([0-9]{1,3})$", derived, re.M)
    if len(exits) != 1 or not 0 <= int(exits[0]) <= 255:
        raise ValueError("Readonly unique remote exit")
    status["remote_exit"] = int(exits[0]); status["remote"] = "zero" if int(exits[0]) == 0 else "nonzero"
    if status["remote"] != "zero" or derived.splitlines().count("MTA_READONLY_OK") != 1:
        raise ValueError("Readonly remote completion")
    values = [line[7:] for line in derived.splitlines() if line.startswith("RESULT=")]
    if len(values) != 1:raise ValueError("Readonly unique result")
    result = ast.literal_eval(values[0]); status["result_valid"] = True
    return result


def run_check(output=None):
    safety = verify_reference()
    before_program = source(safety); diagnostic_program = source(safety, True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-PriorJournalReadOnly-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {"evidence_level": "P011_PRIOR_JOURNAL_READONLY_DIAGNOSTIC", "pass": False, "check_complete": False,
              "candidate_identity": CANDIDATE, "checker_sha256": hashlib.sha256(_data(Path(__file__),MAX_SOURCE_BYTES)).hexdigest(),
              "radio_operations": False, "network_configuration": False, "recovery_invoked": False, "retry_invoked": False,
              "candidate_staged": False, "device_writes": False, "send_available": False, "ip_installation": "NOT_TESTED",
              "phone_interop": "NOT_TESTED", "prior_admission_clear": False, "unsafe_exception_observed": False,
              "remote_statuses": {}, "next_step": "REVIEW_READONLY_EVIDENCE_NO_AUTO_TRIAL"}
    before = after = diagnostic = None; adb = None; stage = "target"
    try:
        adb = Adb(out / "private-raw")
        stage = "before"
        before = remote(adb, "before-prior-readonly", before_program, report["remote_statuses"])
        if not reference.preflight_ok(before):raise ValueError("Readonly preflight")
        stage = "prior_diagnostic"
        diagnostic = validate_result(remote(adb, "prior-journal-diagnostic-readonly", diagnostic_program, report["remote_statuses"]))
        report["diagnostic"] = diagnostic; report["prior_admission_clear"] = diagnostic["clear"]
        report["unsafe_exception_observed"] = diagnostic["unsafe_count"] > 0
    except Exception:
        report["host_or_parse_error"] = True; report["error_stage"] = stage
    finally:
        if adb is not None:
            try:after = remote(adb, "after-prior-readonly", before_program, report["remote_statuses"])
            except Exception:report["after_check_failed"] = True
        gates = {}; reference.add_independent_gates(gates, before, after, None)
        fields = ("stock_independent_unchanged", "wifi_state_fingerprint_unchanged", "station_state_digest_unchanged",
                  "frequency_unchanged", "route_digest_unchanged", "full_ipv4_addresses_unchanged", "full_ipv4_routes_unchanged",
                  "full_ipv4_rules_unchanged", "full_ipv4_readback_unchanged", "full_ipv6_readback_unchanged", "ipv6_address_digest_unchanged",
                  "ipv6_route_digest_unchanged", "same_boot", "network_processes_unchanged", "interface_identities_unchanged", "wifi_completed_after",
                  "no_p2p_interfaces_after", "no_project_mta_interfaces_after", "no_private_wpa_processes_after", "no_project_trial_actors_after", "global_pending_clear_independent")
        report.update({field:gates[field] for field in fields})
        report["check_complete"] = bool(diagnostic and diagnostic["diagnostic_complete"] and diagnostic["netlink_socket_closed"] and
                                        all(report[field] is True for field in fields) and not report.get("host_or_parse_error") and not report.get("after_check_failed"))
        # PASS is ONLY a completed, unchanged-state diagnostic, not admission or
        # GO/IP/transfer success. An identified unsafe journal still blocks RF.
        report["pass"] = report["check_complete"]
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("Fixed V6diag reference: read-only prior journal diagnosis; no staging/mutation/recover/retry.\n"
        "PASS/check_complete means diagnostic collection completed and full independent baseline stayed unchanged, NOT prior admission or IP/transfer success.\n"
        "prior_admission_clear remains separate; unsafe rows report only ordinal/version, fixed stages/reasons/classes/errno and bools.\n"
        "Private raw stdout/stderr, host exits, source echo and original identifiers remain local. Public ZIP contains result.json and README.txt only.\n", encoding="utf-8")
    archive = Path(str(out) + ".sanitized.zip")
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):bundle.write(out / name,name)
    return report,out,archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-readonly", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report,out,archive = run_check(args.output)
    print(json.dumps(report,ensure_ascii=False,indent=2));print("RESULT_DIR="+str(out));print("RESULT_ZIP="+str(archive))
    return 0 if report["check_complete"] else 1


if __name__ == "__main__":sys.exit(main())
