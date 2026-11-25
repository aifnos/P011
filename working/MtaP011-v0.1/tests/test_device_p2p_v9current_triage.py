"""Focused HOST fake /proc, sysfs, GET_INTERFACE and ADB; no real sockets."""
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

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/"host"))
import device_p2p_v9current_triage as entry
from tests import test_device_p2p_v9bounded as previous
from tests import test_device_prior_journal_readonly as wire


def fixture(action="good"):
    calls=[];owner={"name":"mta12345678","ifindex":9,"wdev":2,"phy":0,"iftype":8}
    record={"stage":"recovery_required","owned":owner,"process":{"pid":123},
        "baseline":{"boot_id":"HOST_BOOT"},"ip":{"stage":"confirmed"}}
    pending={"journal":entry.RUN+"/p2p-lease.json","boot_id":"HOST_BOOT"}
    rows=[{"name":"wlan0","ifindex":3,"wdev":1,"phy":0,"iftype":2},dict(owner,iftype=9)]
    if action=="absent":rows=[]
    if action=="collision":rows[1]["wdev"]=7
    if action=="type_changed":rows[1]["iftype"]=1
    if action=="duplicate":rows.append(dict(rows[1]))
    if action=="bad_interface":rows[1]["iftype"]=True
    fake=types.ModuleType("mta_send_wifi");fake._journal_envelope=lambda unused:None
    class Socket:
        def __init__(self):self.fd=91
        def fileno(self):return self.fd
        def close(self):
            calls.append("close")
            if action=="close_error":raise OSError(5,"HOST_PRIVATE")
            if action!="close_noeffect":self.fd=-1
    class Netlink:
        def __init__(self):
            calls.append("constructor");self.sock=Socket()
            if action=="constructor":raise OSError(5,"HOST_PRIVATE")
        def interfaces(self):calls.append("interfaces");return copy.deepcopy(rows)
        def close(self):self.sock.close()
    def listdir(path):
        calls.append("listdir:proc" if path=="/proc" else "listdir:task")
        if path.endswith("/task"):
            if action=="zombie_task_unknown":raise OSError(13,"HOST_PRIVATE")
            return ["100","101"]
        if action=="list_errno":raise OSError(13,"HOST_PRIVATE")
        return [str(n) for n in range(513)] if action=="many_pids" else ["42","100"]
    def bounded(path,maximum=1048576):
        if path.endswith("/boot_id"):return b"HOST_OTHER" if action=="boot_changed" else b"HOST_BOOT"
        if path.endswith("/cmdline"):
            calls.append("cmdline")
            if action=="cmdline_errno":raise OSError(13,"HOST_PRIVATE")
            if action in ("gone","gone_unknown","gone_errno"):raise OSError(2,"HOST_PRIVATE")
            if action=="byte_limit":raise ValueError("HOST_PRIVATE_BYTE_LIMIT")
            if action=="truncated":return b"HOST_PRIVATE"
            if action=="cmdline_type":return "HOST_PRIVATE"
            if action in ("kernel_empty","kernel_ticks","kernel_start","kernel_state","kernel_flags","stat_pid",
                          "zombie","zombie_task_unknown","empty_unknown","stat_errno","stat_shape","stat_flags","stat_gone"):return b""
            if action=="actor_present":return b"mta-prior-readonly\0"
            if action=="changed" and calls.count("cmdline")==2:return b"HOST_CHANGED\0"
            return b"HOST_OTHER\0"
        if path.endswith("/stat"):
            if action=="stat_errno":raise OSError(13,"HOST_PRIVATE")
            if action=="stat_gone":raise OSError(3,"HOST_PRIVATE")
            if action=="stat_shape":return b"HOST_SHORT"
            calls.append("stat")
            state=b"Z" if action in ("zombie","zombie_task_unknown") else b"R" if action=="kernel_state" and calls.count("stat")==2 else b"S"
            kernel=action in ("kernel_empty","kernel_ticks","kernel_start","kernel_state","kernel_flags","stat_pid")
            flags=b"2097153" if action=="kernel_flags" and calls.count("stat")==2 else b"2097152" if kernel else b"bad" if action=="stat_flags" else b"0"
            fields=[state]+[b"0"]*19;fields[6]=flags;fields[19]=b"100" if action=="kernel_start" and calls.count("stat")==2 else b"99"
            if action=="kernel_ticks":fields[11]=str(calls.count("stat")).encode("ascii")
            return (b"99" if action=="stat_pid" else b"100")+b" (HOST_PRIVATE) "+b" ".join(fields)
        if path.endswith("/ifindex"):return b"8" if action=="sysfs_identity" else b"9"
        if path.endswith("/flags"):
            if action=="sysfs_errno":raise OSError(13,"HOST_PRIVATE")
            return b"bad" if action=="sysfs_shape" else b"0x1002"
        raise AssertionError("HOST unknown read")
    def private_record(path):
        if action=="journal_schema" and path.endswith("p2p-lease.json"):raise ValueError("HOST_PRIVATE_SCHEMA")
        return copy.deepcopy(record if path.endswith("p2p-lease.json") else pending)
    def absent(value):
        if value["pid"]==100:
            if action=="gone_errno":raise OSError(13,"HOST_PRIVATE")
            return action!="gone_unknown"
        return action!="process_live"
    def lstat(path):
        if action in ("absent","sysfs_absent"):raise OSError(2,"HOST_PRIVATE")
        return types.SimpleNamespace()
    clock=iter([1,100]) if action=="deadline" else None
    namespace={"time":types.SimpleNamespace(monotonic=(lambda:next(clock,100)) if clock else lambda:1),
        "os":types.SimpleNamespace(listdir=listdir,getpid=lambda:42,lstat=lstat),"re":__import__("re"),
        "RUN":entry.RUN,"TARGET":entry.bounded.TARGET,"AREA":entry.bounded.AREA,
        "MANIFEST_SHA256":entry.bounded.MANIFEST_SHA256,"DEVICE_PENDING":"HOST_PENDING",
        "ReadWriteNetlink":Netlink,"bounded":bounded,"private_folder":lambda unused:None,
        "private_record":private_record,"validate_journal3":lambda unused:None,"process_absent":absent,
        "pending_readonly":lambda:{"present":True,"safe":True,"valid":action!="pending_invalid","lock_safe":True},
        "digest":lambda unused:"0"*64 if action=="manifest" else entry.bounded.MANIFEST_SHA256,
        "hashbytes":lambda value:hashlib.sha256(value).hexdigest()}
    capture=io.StringIO()
    with mock.patch.dict(sys.modules,{"mta_send_wifi":fake}),contextlib.redirect_stdout(capture):exec(entry.BODY,namespace)
    value=ast.literal_eval(capture.getvalue().split("RESULT=",1)[1].strip())
    return value,calls


class BodyTests(unittest.TestCase):
    def test_complete_two_snapshots_exact_socket_closed_no_authorization(self):
        value,calls=fixture();entry.validate_result(value);self.assertTrue(value["check_complete"])
        self.assertEqual(calls.count("interfaces"),2);self.assertEqual(calls.count("close"),1)
        self.assertTrue(value["netlink_socket_closed"]);self.assertFalse(value["authorization_or_lock_held"])
        row=value["observations"][0];self.assertTrue(row["actors"]["clear"]);self.assertTrue(row["owned"]["exact_origin"])
        self.assertEqual(row["journal"]["stage"],"recovery_required");self.assertEqual(row["journal"]["ip_stage"],"confirmed")
    def test_empty_kernel_only_accepted_zombie_and_unknown_never_absence(self):
        value,calls=fixture("kernel_empty");entry.validate_result(value);self.assertTrue(value["check_complete"])
        self.assertEqual(value["observations"][0]["actors"]["counts"]["empty_kernel"],1)
        for action,reason in (("zombie","empty_user_zombie"),("empty_unknown","empty_unknown"),("zombie_task_unknown","empty_user_zombie")):
            with self.subTest(action=action):
                value,calls=fixture(action);entry.validate_result(value);self.assertFalse(value["check_complete"])
                row=value["observations"][0];self.assertEqual(row["actors"]["reason"],reason);self.assertFalse(row["actors"]["clear"])
                self.assertTrue(row["journal"]["complete"]);self.assertTrue(row["owned"]["complete"])
                self.assertTrue(value["netlink_socket_closed"])
        value,calls=fixture("zombie");actor=value["observations"][0]["actors"]
        self.assertTrue(actor["zombie_tasks_recorded"]);self.assertEqual(actor["zombie_task_count"],2)
        value,calls=fixture("zombie_task_unknown");actor=value["observations"][0]["actors"]
        self.assertFalse(actor["zombie_tasks_recorded"]);self.assertIsNone(actor["zombie_task_count"]);self.assertEqual(actor["zombie_task_errno"],13)
    def test_actor_precise_failure_reasons_no_args_or_pid_public(self):
        expected={"many_pids":"proc_count_limit","list_errno":"list_read_error","cmdline_errno":"cmdline_read_errno",
            "byte_limit":"cmdline_byte_limit","truncated":"cmdline_truncated","cmdline_type":"cmdline_type",
            "stat_errno":"stat_read_errno","stat_shape":"stat_shape_invalid","stat_flags":"stat_flags_invalid",
            "gone_unknown":"disappeared_not_proven","gone_errno":"absence_read_errno"}
        for action,reason in expected.items():
            with self.subTest(action=action):
                value,calls=fixture(action);entry.validate_result(value);self.assertFalse(value["check_complete"])
                self.assertEqual(value["observations"][0]["actors"]["reason"],reason)
                self.assertNotIn("HOST_PRIVATE",json.dumps(value));self.assertNotIn("mta12345678",json.dumps(value))
    def test_disappearance_requires_positive_double_check_project_actor_not_clear(self):
        for action in ("gone","stat_gone"):
            value,calls=fixture(action);entry.validate_result(value);self.assertTrue(value["check_complete"])
            self.assertEqual(value["observations"][0]["actors"]["counts"]["disappeared_confirmed"],1)
        value,calls=fixture("actor_present");entry.validate_result(value)
        self.assertTrue(value["check_complete"]);self.assertFalse(value["observations"][0]["actors"]["clear"])
        self.assertEqual(value["observations"][0]["actors"]["reason"],"actor_present")
    def test_empty_kernel_stat_cpu_ticks_not_identity_start_state_flags_changes_not_equal(self):
        value,calls=fixture("kernel_ticks");entry.validate_result(value);self.assertTrue(value["check_complete"])
        for action in ("kernel_start","kernel_state","kernel_flags"):
            value,calls=fixture(action);entry.validate_result(value);self.assertFalse(value["check_complete"]);self.assertFalse(value["snapshots_equal"])
        value,calls=fixture("stat_pid");entry.validate_result(value);self.assertFalse(value["check_complete"])
        self.assertEqual(value["observations"][0]["actors"]["reason"],"stat_identity_invalid")
    def test_owned_absent_collision_type_changed_and_sysfs_observed_separately(self):
        for action,reason in (("absent","absent"),("collision","collision"),("duplicate","collision"),
                             ("type_changed","type_changed"),("sysfs_absent","sysfs_absent")):
            value,calls=fixture(action);entry.validate_result(value);self.assertTrue(value["check_complete"])
            self.assertEqual(value["observations"][0]["owned"]["reason"],reason)
        value,calls=fixture("absent");row=value["observations"][0]["owned"]
        self.assertTrue(row["netlink_recorded"]);self.assertEqual(row["row_count"],0)
        self.assertTrue(row["sysfs_recorded"]);self.assertFalse(row["sysfs_present"]);self.assertFalse(row["exact_origin"])
        value,calls=fixture("sysfs_identity");self.assertFalse(value["observations"][0]["owned"]["sysfs_identity_match"])
    def test_subcheck_errors_preserve_other_observations_not_unknown_as_gone(self):
        for action in ("journal_schema","pending_invalid","bad_interface","sysfs_errno","sysfs_shape"):
            value,calls=fixture(action);entry.validate_result(value);self.assertFalse(value["check_complete"])
            self.assertEqual(len(value["observations"]),2);self.assertTrue(value["observations"][0]["actors"]["complete"])
            self.assertTrue(value["netlink_socket_closed"])
        value,calls=fixture("journal_schema");self.assertEqual(value["observations"][0]["owned"]["reason"],"journal_unavailable")
        self.assertTrue(value["observations"][0]["owned"]["netlink_recorded"])
    def test_manifest_constructor_close_changed_and_deadline_fail_keep_exact_refs(self):
        for action in ("manifest","constructor","close_error","close_noeffect","changed","deadline"):
            value,calls=fixture(action);entry.validate_result(value);self.assertFalse(value["check_complete"])
        value,calls=fixture("constructor");self.assertEqual(calls.count("close"),1)
        self.assertEqual(value["fatal_reason"],"netlink_constructor");self.assertFalse(value["netlink_socket_closed"])
        value,calls=fixture("manifest");self.assertEqual(calls,[]);self.assertEqual(value["fatal_reason"],"reference")
    def test_unknown_keys_bool_counts_types_errno_and_completeness_fail_closed(self):
        good,calls=fixture();bad=[]
        for key,val in (("check_complete",1),("device_writes",True),("fatal_reason","HOST_PRIVATE"),("raw","HOST_PRIVATE")):
            row=copy.deepcopy(good);row[key]=val;bad.append(row)
        for field,val in (("errno",True),("reason","HOST_PRIVATE"),("clear",1),("zombie_task_count",0)):
            row=copy.deepcopy(good);row["observations"][0]["actors"][field]=val;bad.append(row)
        row=copy.deepcopy(good);row["observations"][0]["actors"]["counts"]["examined"]=True;bad.append(row)
        row=copy.deepcopy(good);row["observations"][0]["owned"]["iftype"]=True;bad.append(row)
        row=copy.deepcopy(good);row["observations"][0]["owned"]["match_count"]=0;bad.append(row)
        row=copy.deepcopy(good);row["observations"][0]["journal"]["ip_stage"]="HOST_PRIVATE";bad.append(row)
        for value in bad:
            with self.assertRaises(ValueError):entry.validate_result(value)
    def test_source_uses_no_rf_guard_lock_write_address_stop_or_recovery_call(self):
        tree=ast.parse(entry.BODY,feature_version=(3,5))
        forbidden={"acquire","start","stop","recover","create","remove","delete","address_ack","_save","write","fchmod","flock","LinuxBackend"}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id if isinstance(node.func,ast.Name) else None
                self.assertNotIn(name,forbidden)
        self.assertNotIn("allow_rf=True",entry.BODY);self.assertNotIn("/carrier",entry.BODY)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.capsule,cls.source=entry.build_capsule()
    def test_fixed_current_all_eight_refs_short_payload_ast35_and_old_globals_unchanged(self):
        self.assertEqual(hashlib.sha256(Path(entry.bounded.__file__).read_bytes()).hexdigest(),entry.REFERENCE_SHA256)
        data=previous.payload(self.source);self.assertLessEqual(len(data),entry.bounded.MAX_SOURCE_BYTES)
        self.assertLessEqual(max(map(len,data.splitlines())),2048);self.assertEqual(previous.canonical_4095_model(data),data)
        ast.parse(self.source,feature_version=(3,5));self.assertEqual(previous.assignment(self.source,"RUN"),entry.RUN)
        self.assertEqual(previous.assignment(self.source,"IDENTITY3"),entry.bounded.IDENTITY3)
        originals={name:copy.deepcopy(getattr(entry.bounded,name)) for name in ("SOURCE_PINS","NATIVE_PINS","IDENTITY3","PRIOR_CANDIDATES")}
        self.assertEqual(len(self.capsule.records),8)
        for relative,(pin,size) in self.capsule.records.items():
            raw=(entry.bounded.FROZEN/relative).read_bytes();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(size,pin))
        self.assertEqual(originals,{name:getattr(entry.bounded,name) for name in originals})
    def invoke(self,action,directory):
        created=[]
        class Fake(previous.FakeAdb):
            def run(fake,label,args,timeout=30,input_data=None):
                if label=="v9-current-triage-observation":
                    fake.index+=1;fake.calls.append((label,args,input_data,timeout))
                    if action=="timeout":
                        fake.keep_raw(input_data);(fake.directory/("%02d-%s.host-exit"%(fake.index,label))).write_text("TIMEOUT");raise TimeoutError("HOST_PRIVATE")
                    if action=="truncated":return fake.keep_raw(b"RESULT={\nMTA_REMOTE_EXIT=0\n")
                    if action=="unknown_marker":return fake.keep_raw(wire.wire(fixture()[0])+b"MTA_REMOTE_EXIT=0\n")
                    value,calls=fixture("zombie" if action=="zombie" else "absent" if action=="wifi_false" else "good")
                    return fake.keep_raw(wire.wire(value))
                raw=super(Fake,fake).run(label,args,timeout,input_data)
                if action=="wifi_false" and "baseline" in label:
                    value=copy.deepcopy(fake.first);value["wifi"]["completed"]=False;value["interfaces"]=[];value["station_identity_ok"]=False
                    return fake.keep_raw(wire.wire(value))
                return raw
        def factory(path):
            fake=Fake(path,action);created.append(fake);return fake
        with mock.patch.object(entry,"build_capsule",return_value=(self.capsule,self.source)),mock.patch.object(entry,"Adb",side_effect=factory):
            report,out=entry.run_check(Path(directory)/"HOST_RESULT")
        return report,out,created[0]
    def test_current_baseline_equality_true_wifi_false_not_reported_as_change(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake=self.invoke("wifi_false",directory);self.assertTrue(report["pass"])
            self.assertTrue(report["current_baseline_equal"]);self.assertFalse(report["wifi_completed_preconditions"])
            self.assertFalse(report["before_wifi_completed"]);self.assertFalse(report["after_wifi_completed"])
            self.assertEqual(report["historical_stop_failure_cause"],"NOT_PROVEN")
            self.assertFalse(report["recovery_invoked"]);self.assertFalse(report["network_mutations"])
            self.assertEqual(len(fake.calls),5);self.assertFalse(list(out.glob("*.zip")))
    def test_actor_failure_retained_other_facts_and_all_raw_unmodified(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake=self.invoke("zombie",directory);self.assertFalse(report["pass"])
            self.assertTrue(report["current_baseline_equal"]);self.assertTrue(report["observation"]["observations"][0]["journal"]["complete"])
            self.assertEqual(report["observation"]["observations"][0]["actors"]["reason"],"empty_user_zombie")
            for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
    def test_timeout_marker_metadata_baseline_change_no_retry_mutation_and_final_checks(self):
        for action in ("timeout","truncated","unknown_marker","initial-fixed-v9-eight-readonly","metadata_v9",
                       "after_wifi","after_ipv4","after_process","after_interface","after_boot","after_query"):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake=self.invoke(action,directory);self.assertFalse(report["pass"])
                self.assertFalse(report["rf_trial_invoked"]);self.assertFalse(report["recovery_invoked"]);self.assertFalse(report["retry_invoked"])
                self.assertEqual(sum(row[0]=="after-current-triage-baseline" for row in fake.calls),1)
                self.assertEqual(sum(row[0]=="last-fixed-v9-eight-readonly" for row in fake.calls),1)
                self.assertLessEqual(sum(row[0]=="v9-current-triage-observation" for row in fake.calls),1)
                for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
    def test_changed_ref_and_nonfixed_cli_rejected_before_adb(self):
        with mock.patch.object(entry,"REFERENCE_SHA256","0"*64),mock.patch.object(entry,"Adb",side_effect=AssertionError("HOST no ADB")),self.assertRaises(ValueError):entry.build_capsule()
        for args in ([],["--check-readonly","--run-dir","private"],["--check-readonly","--candidate","f"*16],
                     ["--check-readonly","--recover"],["--check-readonly","--command","private"]):
            with mock.patch.object(sys,"argv",["entry"]+args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):entry.main()


if __name__=="__main__":unittest.main()
