"""HOST-only fixed prior diagnosis tests; no ADB, RF or real network calls."""
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT / "host"))
sys.path.insert(0,str(PROJECT / "runtime"))
import device_prior_journal_readonly as checker
from tests import test_device_p2p_v6diag as fixtures


def body_fixture(action="good"):
    owner = fixtures.KnownPriorTests()
    namespace, record, probe = owner.baseline_namespace()
    names = ["mta-p2p-v2-20000101-00000%d-0000000%d" % (number,number) for number in range(6)]
    records = {}
    for index,name in enumerate(names):
        row = copy.deepcopy(record)
        if index < 5:
            row["version"] = 1 if index == 0 else 2
            row["ip"] = None
        records[name] = row
    if action == "schema":records[names[-1]]["cleanup_result"]["raw"] = "HOST_SECRET"
    elif action == "unknown":records[names[-1]]["identity"]["runtime_marker"] = "HOST_SECRET"
    elif action == "baseline":records[names[-1]]["baseline"]["station_state_digest"] = "0" * 64
    namespace["VALUE_REASONS"] = tuple(checker.VALUE_REASONS)
    namespace["ROW_BOOL_FIELDS"] = tuple(checker.ROW_BOOL_FIELDS)
    clock_calls=[]
    def monotonic():
        clock_calls.append(True)
        return 60 if action == "deadline" and len(clock_calls) > 1 else 1
    namespace["time"] = types.SimpleNamespace(monotonic=monotonic)
    namespace["pending_readonly"] = lambda: {"present": action == "pending", "safe": True, "lock_safe": True}
    closed = []
    def close():
        closed.append(True)
        if action == "close":raise OSError(5,"HOST_SECRET")
    namespace["ReadWriteNetlink"] = lambda: types.SimpleNamespace(interfaces=lambda: copy.deepcopy(probe["interfaces"]),close=close)
    namespace["_proc_identity"] = lambda unused: None
    namespace["os"].path = types.SimpleNamespace(isdir=lambda unused: True,lexists=lambda unused: True)
    namespace["os"].listdir = lambda path: names if path.endswith("/sessions") else ["p2p-lease.json"]
    def lstat(path):
        if path.startswith("/proc/"):
            if action == "process_permission":raise OSError(13,"HOST_SECRET")
            if action == "process_live":return types.SimpleNamespace(st_mode=0o040555,st_uid=0)
            raise OSError(2,"HOST_SECRET")
        return types.SimpleNamespace(st_mode=0o100622 if action == "manifest_permissions" and path.endswith("/SOURCE.sha256") else 0o100600,st_uid=0)
    namespace["os"].lstat = lstat
    def private_record(path):
        if action == "unmapped" and names[-1] in path:raise ValueError("HOST_SECRET_SESSION_IDENTIFIER")
        if action == "os_error" and names[-1] in path:raise OSError(5,"HOST_SECRET_SESSION_IDENTIFIER")
        if action == "key_error" and names[-1] in path:raise KeyError("HOST_SECRET_SESSION_IDENTIFIER")
        return copy.deepcopy(records[path.split("/")[-2]])
    namespace["private_record"] = private_record
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):exec(checker.BODY,namespace)
    value = ast.literal_eval(buffer.getvalue().split("RESULT=",1)[1].strip())
    checker.validate_result(value)
    return value,closed,names


class ProgramTests(unittest.TestCase):
    def test_fixed_actual_host_reference_full_hash_seven_pins_without_freeze(self):
        with mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")):
            safety = checker.verify_reference()
            self.assertEqual(hashlib.sha256((checker.FROZEN / "SOURCE.sha256").read_bytes()).hexdigest(),checker.MANIFEST_SHA256)
            for diagnostic in (False,True):
                program = checker.source(safety,diagnostic)
                tree = ast.parse(program,feature_version=(3,5))
                self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
                self.assertIn(checker.MANIFEST_SHA256,program)
                self.assertIn(checker.TARGET,program)
        tree = ast.parse(checker.BODY,feature_version=(3,5))
        forbidden = {"start","stop","restore","recover","create_group","chmod","unlink","remove","mkdir","sendto","bind","listen","connect"}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,forbidden)
        self.assertIn("end=time.monotonic()+25",checker.BODY)

    def test_reference_changes_block_before_adb_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "UNCREATED"
            with mock.patch.object(checker,"HARNESS_SHA256","0" * 64), \
                    mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")), self.assertRaises(ValueError):
                checker.run_check(destination)
            self.assertFalse(destination.exists())

    def test_six_valid_records_known_v5_checked_without_mutation(self):
        value,closed,names = body_fixture()
        self.assertTrue(value["diagnostic_complete"]); self.assertTrue(value["clear"])
        self.assertEqual(value["inspected_count"],6); self.assertEqual(value["unsafe_count"],0)
        self.assertEqual(len(closed),1)
        last = value["records"][-1]
        for key in ("historical_v5_checked","historical_v5_baseline_checked","historical_v5_baseline_equal","process_gone","interface_gone","ip_reconciled"):
            self.assertTrue(last[key])
        encoded = json.dumps(value)
        self.assertNotIn("HOST_SECRET",encoded)
        for name in names:self.assertNotIn(name,encoded)
        self.assertNotIn("exe",encoded);self.assertNotIn("pid",encoded)

    def test_exact_unsafe_schema_permissions_identity_and_os_class(self):
        cases = {"schema":("schema3","invalid_journal3_cleanup","value_error",0),
                 "manifest_permissions":("prior_context","historical_manifest_permissions","value_error",0),
                 "unknown":("prior_context","unknown_historical_candidate","value_error",0),
                 "os_error":("private_record","os_error","os_error",5),
                 "key_error":("private_record","key_error","key_error",0),
                 "unmapped":("private_record","unmapped_value_error","value_error",0)}
        for action,expected in cases.items():
            with self.subTest(action=action):
                value,closed,names = body_fixture(action)
                self.assertTrue(value["diagnostic_complete"]);self.assertFalse(value["clear"])
                self.assertEqual((value["unsafe_count"],value["blocked_count"],value["inspected_count"]),(1,0,6))
                row = value["records"][-1]
                self.assertEqual(tuple(row[field] for field in ("rejected_stage","reason","error_class","errno")),expected)
                self.assertNotIn("HOST_SECRET",json.dumps(value))

    def test_baseline_mismatch_or_live_process_block_not_unsafe(self):
        for action,stage in (("baseline","historical_baseline"),("process_live","process")):
            value,closed,names = body_fixture(action)
            self.assertFalse(value["clear"]);self.assertEqual(value["unsafe_count"],0)
            self.assertEqual(value["records"][-1]["classification"],"blocked")
            self.assertEqual(value["records"][-1]["rejected_stage"],stage)
        value,closed,names = body_fixture("process_permission")
        self.assertEqual(value["records"][-1]["rejected_stage"],"process")
        self.assertEqual(value["records"][-1]["errno"],13)

    def test_pending_and_close_failure_no_false_completion(self):
        value,closed,names = body_fixture("pending")
        self.assertFalse(value["global_pending_clear"]);self.assertFalse(value["clear"])
        value,closed,names = body_fixture("close")
        self.assertFalse(value["netlink_socket_closed"]);self.assertFalse(value["diagnostic_complete"])
        self.assertEqual((value["outer_stage"],value["outer_reason"],value["outer_errno"]),("close","os_error",5))

    def test_source_deadline_stops_before_additional_reads(self):
        value,closed,names = body_fixture("deadline")
        self.assertFalse(value["diagnostic_complete"]);self.assertEqual(value["inspected_count"],0)
        self.assertEqual((value["outer_stage"],value["outer_reason"]),("pending","readonly_diagnostic_deadline"))
        self.assertEqual(closed,[]);self.assertTrue(value["netlink_socket_closed"])

    def test_error_info_unknowns_do_not_disclose_text(self):
        namespace = {"time":types.SimpleNamespace(monotonic=lambda:1),"VALUE_REASONS":tuple(checker.VALUE_REASONS),"ROW_BOOL_FIELDS":tuple(checker.ROW_BOOL_FIELDS)}
        tree = ast.parse(checker.BODY)
        definitions = ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef)],type_ignores=[])
        exec(compile(definitions,"HOST_ONLY","exec"),namespace)
        for error in (ValueError("HOST_SECRET"),TypeError("HOST_SECRET"),KeyError("HOST_SECRET"),RuntimeError("HOST_SECRET"),OSError(None,"HOST_SECRET"),OSError(9999,"HOST_SECRET")):
            row = namespace["error_info"](error)
            self.assertNotIn("HOST_SECRET",repr(row));self.assertIn(row[0],checker.CLASSES);self.assertIn(row[1],checker.REASONS)
            self.assertTrue(type(row[2]) is int and 0 <= row[2] <= 4095)

    def test_result_strict_counts_enums_bools_and_no_private_extra(self):
        valid,closed,names = body_fixture("schema")
        variants=[]
        for field,value in (("clear",1),("inspected_count",True),("unsafe_count",0),("outer_stage","HOST_SECRET"),("outer_errno",True)):
            row=copy.deepcopy(valid);row[field]=value;variants.append(row)
        for field,value in (("ordinal",True),("version",True),("classification","HOST_SECRET"),("reason","HOST_SECRET"),("error_class","HOST_SECRET"),("errno",-1),("process_gone",1)):
            row=copy.deepcopy(valid);row["records"][-1][field]=value;variants.append(row)
        row=copy.deepcopy(valid);row["records"][-1]["path"]="HOST_SECRET";variants.append(row)
        row=copy.deepcopy(valid);row["raw"]="HOST_SECRET";variants.append(row)
        row=copy.deepcopy(valid);row["records"][-1]["error_class"]="none";variants.append(row)
        row=copy.deepcopy(valid);row["records"][-1]["process_gone"]=True;row["records"][-1]["process_absence_checked"]=False;variants.append(row)
        row=copy.deepcopy(valid);row["netlink_socket_closed"]=False;variants.append(row)
        for value in variants:
            with self.assertRaises(ValueError):checker.validate_result(value)


def wire(value,status=0,marker=True):
    return ("RESULT=" + repr(value) + ("\nMTA_READONLY_OK" if marker else "") + "\nMTA_REMOTE_EXIT=" + str(status) + "\n").encode("utf-8")


class FakeAdb:
    def __init__(self,directory,action="good"):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.index=0;self.calls=[];self.action=action
    def run(self,label,arguments,timeout=None,input_data=None):
        self.index+=1;self.calls.append((label,arguments,timeout,input_data))
        program=input_data.decode("utf-8")
        ast.parse(program,feature_version=(3,5))
        self.assert_readonly(arguments,program)
        if self.action == "timeout" and label == "prior-journal-diagnostic-readonly":
            (self.directory / ("%02d-%s.host-exit" % (self.index,label))).write_text("TIMEOUT")
            raise TimeoutError("HOST_SECRET_TIMEOUT")
        if label == "prior-journal-diagnostic-readonly":value=body_fixture("schema" if self.action == "unsafe" else "good")[0]
        else:
            value=fixtures.private_probe()
            if label == "after-prior-readonly" and self.action == "changed":value["ipv4"]["routes"][0][2]=200
        return wire(value,status=1 if self.action == "remote_failure" and label == "prior-journal-diagnostic-readonly" else 0)
    @staticmethod
    def assert_readonly(arguments,program):
        if arguments[0] != "shell" or "--trial" in arguments[1] or "--recover" in arguments[1]:raise AssertionError("Unexpected dispatch")


class RemoteAndHarnessTests(unittest.TestCase):
    def test_host_exit_negative_and_timeout_retained_not_remote_success(self):
        for retained,expected in (("-9","nonzero"),("TIMEOUT","timeout")):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory);(path / "01-fixed.host-exit").write_text(retained)
                def failed(*args,**kwargs):raise RuntimeError("HOST_SECRET")
                fake=types.SimpleNamespace(run=failed,directory=path,index=1);statuses={}
                with self.assertRaises(RuntimeError):checker.remote(fake,"fixed","pass",statuses)
                self.assertEqual(statuses["fixed"]["host"],expected)
                self.assertEqual(statuses["fixed"]["remote"],"not_recorded")
                if retained == "-9":self.assertEqual(statuses["fixed"]["host_exit"],-9)

    def test_remote_unique_exit_utf8_marker_result_and_status(self):
        values=[wire(True,1),wire(True,marker=False),wire(True)+b"MTA_REMOTE_EXIT=0\n",b"\xff\n",wire(True)+b"RESULT=True\n"]
        for raw in values:
            statuses={};fake=types.SimpleNamespace(run=lambda *args,**kwargs:raw)
            with self.assertRaises(ValueError):checker.remote(fake,"fixed", "pass",statuses)
            self.assertEqual(statuses["fixed"]["host"],"zero")
            self.assertFalse(statuses["fixed"]["result_valid"])
        statuses={};fake=types.SimpleNamespace(run=lambda *args,**kwargs:wire(True))
        self.assertTrue(checker.remote(fake,"fixed","pass",statuses));self.assertTrue(statuses["fixed"]["result_valid"])

    def invoke(self,directory,action):
        created=[]
        def factory(path):
            value=FakeAdb(path,action);created.append(value);return value
        with mock.patch.object(checker,"Adb",side_effect=factory):
            report,out,archive=checker.run_check(Path(directory)/"HOST_ONLY_RESULT")
        return report,out,archive,created[0]

    def test_unsafe_is_completed_diagnosis_not_admission_or_trial_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,archive,fake=self.invoke(directory,"unsafe")
            self.assertTrue(report["check_complete"]);self.assertTrue(report["pass"])
            self.assertFalse(report["prior_admission_clear"]);self.assertTrue(report["unsafe_exception_observed"])
            self.assertEqual([row[0] for row in fake.calls],["before-prior-readonly","prior-journal-diagnostic-readonly","after-prior-readonly"])
            for field in ("radio_operations","network_configuration","recovery_invoked","retry_invoked","candidate_staged","device_writes","send_available"):
                self.assertFalse(report[field])
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()),{"result.json","README.txt"})
                data=b"".join(bundle.read(name) for name in bundle.namelist())
                for token in (b"HOST_PRIVATE",b"HOST_SECRET",b"mta-p2p-v2-20000101",b"/proc/"):self.assertNotIn(token,data)
            self.assertEqual(report["remote_statuses"]["prior-journal-diagnostic-readonly"]["remote_exit"],0)

    def test_changed_full_route_remote_failure_and_timeout_fail_without_retry(self):
        for action in ("changed","remote_failure","timeout"):
            with tempfile.TemporaryDirectory() as directory:
                report,out,archive,fake=self.invoke(directory,action)
                self.assertFalse(report["check_complete"]);self.assertFalse(report["pass"])
                self.assertEqual([row[0] for row in fake.calls].count("prior-journal-diagnostic-readonly"),1)
                self.assertEqual(fake.calls[-1][0],"after-prior-readonly")
                self.assertFalse(report["retry_invoked"]);self.assertFalse(report["recovery_invoked"])
                self.assertNotIn("HOST_SECRET",(out / "result.json").read_text())
                if action == "timeout":self.assertEqual(report["remote_statuses"]["prior-journal-diagnostic-readonly"]["host"],"timeout")
                if action == "remote_failure":self.assertEqual(report["remote_statuses"]["prior-journal-diagnostic-readonly"]["remote_exit"],1)

    def test_explicit_cli_only_without_freeze_retry_arbitrary_inputs(self):
        for argv in (["program"],["program","--freeze-only"],["program","--check-readonly","--candidate","HOST_SECRET"],["program","--check-readonly","--recover"]):
            with mock.patch.object(sys,"argv",argv),mock.patch.object(checker,"Adb",side_effect=AssertionError("No ADB")), \
                    contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):checker.main()


if __name__ == "__main__":unittest.main()
