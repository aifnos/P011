"""HOST fake readonly kernel/backend/ADB; never execute real device or socket."""
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
sys.path.insert(0,str(PROJECT/"host"));sys.path.insert(0,str(PROJECT/"runtime"))
import device_p2p_v9restore_readonly as entry
import mta_ip as ip
import mta_ip_lease as lease
from tests import test_device_p2p_v9bounded as previous
from tests import test_device_prior_journal_readonly as wire


def fixture(action="good"):
    calls=[];owned={"name":"mta12345678","ifindex":9,"wdev":2,"phy":0,"iftype":8}
    station={"name":"wlan0","ifindex":3,"wdev":1,"phy":0,"iftype":2}
    spec=ip.AddressSpec(9,"192.168.49.1",24)
    original=ip.AddressRecord(3,ip.ipv4_number("10.20.30.40"),ip.ipv4_number("10.20.30.40"),24,128,0,
        b"wlan0\0",ip.ipv4_number("10.20.30.255"),(ip.UINT_MAX,ip.UINT_MAX,20,20))
    address=ip.AddressRecord(9,spec.address,spec.address,24,128,0,b"mta12345678\0",spec.address|255,(ip.UINT_MAX,ip.UINT_MAX,99,99))
    rules=(ip.RuleRecord(0,255),ip.RuleRecord(32766,254),ip.RuleRecord(32767,253))
    before=ip.IpSnapshot((original,),(),rules)
    routes=lease._expected_routes(spec)
    if action=="subset":routes=(routes[1],)
    if action=="unknown_route":routes=routes+(routes[1]._replace(priority=2),)
    if action=="duplicate_route":routes=routes+(routes[1],)
    if action=="route_flags":routes=(routes[0]._replace(flags=16),)+routes[1:]
    ours=(address,)
    if action=="address_cache":ours=(address._replace(cacheinfo=(ip.UINT_MAX,ip.UINT_MAX,100,99)),)
    if action=="extra_address":ours+=(address._replace(local=spec.address+1,address=spec.address+1),)
    current=ip.IpSnapshot(before.addresses+ours,routes,rules)
    if action=="other_rules":current=ip.IpSnapshot(current.addresses,current.routes,rules+(ip.RuleRecord(123,254),))
    baseline={"boot_id":"HOST_BOOT","processes":[],"station":station,"interfaces":[station],"frequency":2412,
        "route_digest":"1"*64,"station_state_digest":"2"*64,"ipv6_route_digest":"3"*64,"ipv6_address_digest":"4"*64,
        "ipv4":lease.snapshot_data(before)}
    receipt={"stage":"confirmed","owned":{key:owned[key] for key in ("name","ifindex","wdev","phy")},"spec":list(spec),
        "request":{"header":ip.encode_new_address(spec,1,1234)[:16].hex(),"sequence":1,"port_id":1234},
        "address":lease.snapshot_data(ip.IpSnapshot((address,),(),rules))["addresses"][0],"receipt_fsynced":True}
    if action=="receipt_cache":receipt["address"][8][2]=True
    record={"version":3,"kind":"go_ip_only","identity":copy.deepcopy(entry.bounded.IDENTITY3),"stage":"recovery_required",
        "name":owned["name"],"owned":owned,"process":{"pid":123,"starttime":99,"exe":entry.bounded.TARGET+"/native/mta-wpa-supplicant"},
        "ip":receipt,"baseline":baseline,"deadline":100.0}
    pending=dict(entry.bounded.IDENTITY3,journal=entry.RUN+"/p2p-lease.json",boot_id="HOST_BOOT")
    if action=="pending_mismatch":pending["journal"]="HOST_OTHER_RUN"
    ipv6=[{"family":6,"prefix":64,"scope":253,"address":bytes.fromhex("fe80"+"00"*14)}]
    fake=types.ModuleType("mta_send_wifi");fake.STOCK_PINS={"HOST_STOCK":"f"*64}
    fake._origin_match=lambda owner,row:all(owner[key]==row.get(key) for key in ("name","ifindex","wdev","phy"))
    fake._journal_envelope=lambda value:None
    fake._address_dump=lambda unused:copy.deepcopy(ipv6)
    fake._only_link_local=lambda rows:action!="ipv6_address"
    fake._owned_routes_safe=lambda name,allow_ipv4=False:action!="ipv6_routes" and allow_ipv4 is True
    rows=[station,dict(owned,iftype=9)]
    if action=="identity":rows[1]["wdev"]=3
    if action=="bad_type":rows[1]["iftype"]=1
    class Resource:
        def __init__(self,name):self.name=name;self.fd=100;self.closed=False;self.sock=self.socket=self
        def fileno(self):return self.fd
        def close(self):
            calls.append("close:"+self.name)
            if action=="close" and self.name=="ip_transport":raise OSError(5,"HOST_PRIVATE")
            if action=="close_noeffect" and self.name=="nl":return
            self.fd=-1;self.closed=True
    class Backend:
        def __init__(self,binary,caps,directory,allow_rf=False):
            if allow_rf is not False:raise AssertionError("HOST RF forbidden")
            calls.append("backend:readonly");self.boot_id="OTHER" if action=="boot" else "HOST_BOOT"
            self.nl=Resource("nl");self.nl.interfaces=lambda:copy.deepcopy(rows)
            self.ip_transport=Resource("ip_transport");self.diagnostics=Resource("diagnostics");self.guard=Resource("guard")
            self.monitor=None;self.command=None
            if action=="constructor":raise OSError(5,"HOST_PRIVATE")
        def snapshot(self,exclude_owned=None):
            calls.append("snapshot");value=copy.deepcopy(baseline);value["ipv4"]=lease.snapshot_data(current)
            if action in entry.DIFFERENCES:
                key={"boot":"boot_id","original_processes":"processes","station_identity":"station","original_interfaces":"interfaces",
                    "frequency":"frequency","station_state":"station_state_digest","original_ipv6":"ipv6_route_digest"}[action]
                if key=="frequency":value[key]=2437
                else:value[key]="HOST_CHANGED"
            if action=="changed" and calls.count("snapshot")==2:value["station_state_digest"]="9"*64
            return value
    fake.LinuxBackend=Backend
    def process_absent(value):
        if action=="opaque_process":raise OSError(13,"HOST_PRIVATE")
        return action!="process_live"
    def private_record(path):
        calls.append("read:journal" if path.endswith("p2p-lease.json") else "read:pending")
        if action=="journal_schema":raise ValueError("HOST_PRIVATE_INVALID_JOURNAL")
        return copy.deepcopy(record if path.endswith("p2p-lease.json") else pending)
    def bounded(path,bound=1048576):
        if path.endswith("/cmdline"):
            if action=="unknown_actor":raise OSError(13,"HOST_PRIVATE")
            if action=="truncated_cmdline":return b"HOST_OTHER"
            if action in ("kernel_empty","userspace_empty"):return b""
            return b"mta-prior-readonly\0" if action=="actor_live" else b"HOST_OTHER\0"
        if path.endswith("/stat"):return b"100 (HOST_KERNEL) S 0 0 0 0 0 "+(b"2097152" if action=="kernel_empty" else b"0")
        if path.endswith("/flags"):return b"0x1002" if action in ("carrier_down_einval","carrier_down_eacces") else b"0x1003"
        if path.endswith("/carrier"):
            if action in ("carrier_down_einval","carrier_up_einval"):raise OSError(22,"HOST_PRIVATE")
            if action=="carrier_down_eacces":raise OSError(13,"HOST_PRIVATE")
            return b"0" if action=="carrier_zero" else b"1"
        if path.endswith("/ifindex"):return b"9" if action!="sysfs" else b"8"
        return b"HOST_PRIVATE_IPV6_ROUTES"
    namespace={"time":types.SimpleNamespace(monotonic=lambda:50 if action=="deadline" else 1),
        "os":types.SimpleNamespace(listdir=lambda unused:[str(n) for n in range(513)] if action=="many_pids" else ["42","100"],getpid=lambda:42),"re":__import__("re"),
        "RUN":entry.RUN,"TARGET":entry.bounded.TARGET,"MANIFEST_SHA256":entry.bounded.MANIFEST_SHA256,
        "BINARY":entry.bounded.TARGET+"/native/mta-wpa-supplicant","IDENTITY3":entry.bounded.IDENTITY3,"AREA":entry.bounded.AREA,
        "DEVICE_PENDING":"HOST_PENDING","ip":ip,"private_folder":lambda unused:None,"private_record":private_record,
        "validate_journal3":lambda unused:None,"process_absent":process_absent,"identity3":lambda row:row==entry.bounded.IDENTITY3,
        "pending_readonly":lambda:{"safe":True,"valid":True,"lock_safe":True,"present":True},"bounded":bounded,
        "digest":lambda path:("0"*64 if action=="stock" and path=="HOST_STOCK" else "f"*64 if path=="HOST_STOCK" else entry.bounded.MANIFEST_SHA256)}
    if action=="deadline":
        ticks=iter([1,50]);namespace["time"].monotonic=lambda:next(ticks,50)
    buffer=io.StringIO()
    with mock.patch.dict(sys.modules,{"mta_send_wifi":fake}),contextlib.redirect_stdout(buffer):exec(entry.BODY,namespace)
    value=ast.literal_eval(buffer.getvalue().split("RESULT=",1)[1].strip())
    return value,calls


class BodyTests(unittest.TestCase):
    def test_full_expected_receipt_current_observed_old_restore_prerequisites_true_no_authority(self):
        result,calls=fixture();entry.validate_result(result)
        self.assertTrue(result["check_complete"]);self.assertTrue(result["restore_preconditions_observed"])
        self.assertFalse(result["authorization_or_lock_held"]);self.assertFalse(result["network_mutations"])
        self.assertEqual(result["observations"][0]["counts"]["expected_routes_present"],4)
        self.assertEqual(calls.count("snapshot"),2)
        self.assertEqual(set(row for row in calls if row.startswith("close:")),{"close:nl","close:ip_transport","close:diagnostics","close:guard"})
    def test_subset_fact_true_old_without_owned_false_remains_separate_not_authorization(self):
        result,calls=fixture("subset");entry.validate_result(result);self.assertTrue(result["check_complete"])
        facts=result["observations"][0]["booleans"]
        self.assertFalse(facts["without_owned_equals_baseline"]);self.assertTrue(facts["actual_subset_removed_equals_baseline"])
        self.assertTrue(facts["owned_routes_expected_subset"]);self.assertFalse(result["restore_preconditions_observed"])
        self.assertEqual(result["observations"][0]["counts"],{"owned_address_rows":1,"owned_route_rows":1,"expected_routes_present":1})
    def test_unknown_route_flags_extra_address_cache_change_or_rules_never_subset_authorize(self):
        for action in ("unknown_route","route_flags","extra_address","address_cache"):
            with self.subTest(action=action):
                result,calls=fixture(action);entry.validate_result(result);self.assertTrue(result["check_complete"])
                self.assertFalse(result["observations"][0]["booleans"]["actual_subset_removed_equals_baseline"])
                self.assertFalse(result["restore_preconditions_observed"])
        result,calls=fixture("other_rules");self.assertFalse(result["check_complete"])
    def test_duplicate_route_rejected_unknown_distinguished_from_missing(self):
        result,calls=fixture("duplicate_route");entry.validate_result(result)
        # Strict snapshot decoder rejects duplicates before derived facts exist.
        self.assertFalse(result["check_complete"]);self.assertEqual(result["reason"],"schema_or_read_error")
    def test_seven_original_baseline_difference_groups_prevent_observed_old_prerequisites(self):
        for action in entry.DIFFERENCES:
            with self.subTest(action=action):
                result,calls=fixture(action);entry.validate_result(result);self.assertTrue(result["check_complete"])
                self.assertEqual(result["observations"][0]["baseline_differences"],[action])
                self.assertFalse(result["restore_preconditions_observed"])
    def test_sameboot_stock_process_actor_origin_sysfs_and_ipv6_negative_observations_not_gone_guess(self):
        for action in ("stock","process_live","actor_live","identity","bad_type","sysfs","ipv6_address","ipv6_routes","pending_mismatch"):
            with self.subTest(action=action):
                result,calls=fixture(action);entry.validate_result(result);self.assertTrue(result["check_complete"])
                self.assertFalse(result["restore_preconditions_observed"])
        result,calls=fixture("carrier_zero");self.assertTrue(result["restore_preconditions_observed"])
        self.assertFalse(result["observations"][0]["booleans"]["carrier_up"])
    def test_unknown_actor_opaque_pid_bad_journal_or_cache_schema_fail_closed_all_refs_close(self):
        for action in ("unknown_actor","opaque_process","journal_schema","receipt_cache","truncated_cmdline","userspace_empty","many_pids"):
            with self.subTest(action=action):
                result,calls=fixture(action);entry.validate_result(result);self.assertFalse(result["check_complete"])
                self.assertFalse(result["restore_preconditions_observed"]);self.assertTrue(result["netlink_sockets_closed"])
                self.assertEqual(result["reason"],"schema_or_read_error")
    def test_constructor_close_deadline_changed_observations_not_complete(self):
        for action in ("constructor","close","close_noeffect","deadline","changed"):
            with self.subTest(action=action):
                result,calls=fixture(action);entry.validate_result(result);self.assertFalse(result["check_complete"])
                self.assertFalse(result["restore_preconditions_observed"])
        result,calls=fixture("constructor");self.assertFalse(result["netlink_sockets_closed"])
        result,calls=fixture("close");self.assertIn("close:nl",calls);self.assertIn("close:guard",calls)
    def test_known_down_carrier_einval_is_unavailable_not_zero_other_errors_fail(self):
        result,calls=fixture("carrier_down_einval");entry.validate_result(result)
        self.assertTrue(result["check_complete"]);facts=result["observations"][0]["booleans"]
        self.assertTrue(facts["carrier_read_unavailable_down"]);self.assertFalse(facts["carrier_read_valid"]);self.assertFalse(facts["carrier_up"])
        self.assertTrue(result["restore_preconditions_observed"])
        for action in ("carrier_up_einval","carrier_down_eacces"):
            result,calls=fixture(action);self.assertFalse(result["check_complete"])
        result,calls=fixture("kernel_empty");self.assertTrue(result["check_complete"])
    def test_strict_result_unknown_bool_int_count_enum_semantics_and_no_raw_private_output(self):
        good,calls=fixture("subset")
        variants=[]
        for key,val in (("check_complete",1),("network_mutations",True),("reason","HOST_PRIVATE"),("raw",b"HOST_PRIVATE")):
            changed=copy.deepcopy(good);changed[key]=val;variants.append(changed)
        for field in ("owned_address_rows","expected_routes_present"):
            changed=copy.deepcopy(good);changed["observations"][0]["counts"][field]=True;variants.append(changed)
        changed=copy.deepcopy(good);changed["observations"][0]["booleans"]["restore_preconditions_observed"]=True;variants.append(changed)
        changed=copy.deepcopy(good);changed["observations"][0]["baseline_differences"]=["HOST_PRIVATE"];variants.append(changed)
        changed=copy.deepcopy(good);changed["observations"][0]["counts"]["expected_routes_present"]=5;variants.append(changed)
        for value in variants:
            with self.assertRaises(ValueError):entry.validate_result(value)
        text=json.dumps(good)
        for secret in ("192.168","HOST_BOOT","mta12345678","HOST_PRIVATE","wlan0","HOST_PENDING"):self.assertNotIn(secret,text)
    def test_body_calls_no_lock_mutator_controller_or_write_function_allow_rf_false(self):
        tree=ast.parse(entry.BODY,feature_version=(3,5))
        forbidden={"acquire","prepare","clear","start","stop","recover","create","remove","address_ack","prepare_address","_save","write","fchmod","flock"}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,forbidden)
        self.assertIn("allow_rf=False",entry.BODY)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.capsule,cls.source=entry.build_capsule()
    def test_fixed_refs_source_line_byte_ast35_and_no_runtime_marker_override(self):
        self.assertEqual(hashlib.sha256(Path(entry.bounded.__file__).read_bytes()).hexdigest(),entry.REFERENCE_SHA256)
        data=previous.payload(self.source);self.assertLessEqual(len(data),entry.bounded.MAX_SOURCE_BYTES)
        self.assertLessEqual(max(map(len,data.splitlines())),2048);ast.parse(self.source,feature_version=(3,5))
        self.assertEqual(previous.canonical_4095_model(data),data)
        self.assertEqual(previous.assignment(self.source,"RUN"),entry.RUN)
        self.assertEqual(previous.assignment(self.source,"IDENTITY3"),entry.bounded.IDENTITY3)
        self.assertIn("allow_rf=False",self.source)
    def invoke(self,action,directory):
        fakes=[]
        class Fake(previous.FakeAdb):
            def run(fake,label,args,timeout=30,input_data=None):
                if label=="v9-owned-restore-readonly-observation":
                    fake.index+=1;fake.calls.append((label,args,input_data,timeout))
                    if action=="timeout":
                        fake.keep_raw(input_data);(fake.directory/("%02d-%s.host-exit"%(fake.index,label))).write_text("TIMEOUT");raise TimeoutError("HOST_PRIVATE")
                    if action=="truncated":return fake.keep_raw(b"RESULT={\nMTA_REMOTE_EXIT=0\n")
                    value,calls=fixture("subset" if action=="good" else action)
                    return fake.keep_raw(wire.wire(value))
                mapped={"before-restore-readonly-baseline":"first-independent-baseline","after-restore-readonly-baseline":"after-independent-old-reference"}.get(label,label)
                return super(Fake,fake).run(mapped,args,timeout,input_data)
        def factory(path):
            item=Fake(path,action);fakes.append(item);return item
        with mock.patch.object(entry,"build_capsule",return_value=(self.capsule,self.source)),mock.patch.object(entry,"Adb",side_effect=factory):
            result,out=entry.run_check(Path(directory)/"HOST_RESULT")
        return result,out,fakes[0]
    def test_complete_observation_pass_scope_not_old_restore_true_or_mutation_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake=self.invoke("good",directory)
            self.assertTrue(report["pass"]);self.assertFalse(report["restore_preconditions_observed"])
            self.assertFalse(report["rf_trial_invoked"]);self.assertFalse(report["authorization_or_lock_held"])
            self.assertEqual(report["historical_stop_failure_cause"],"NOT_PROVEN")
            self.assertEqual(sum(row[0]=="v9-owned-restore-readonly-observation" for row in fake.calls),1)
            for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
            self.assertFalse(list(out.glob("*.zip")))
    def test_gate_timeout_truncation_unknown_or_after_change_fail_no_rf_recovery_retry(self):
        for action in ("initial-fixed16-readonly","last-fixed-v9-eight-readonly","metadata_v7","timeout","truncated","unknown_actor","after_ipv4"):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake=self.invoke(action,directory);self.assertFalse(report["pass"])
                self.assertFalse(report["rf_trial_invoked"]);self.assertFalse(report["recovery_invoked"]);self.assertFalse(report["retry_invoked"])
                self.assertEqual(sum(row[0]=="after-independent-old-reference" for row in fake.calls),1)
                for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
    def test_only_fixed_check_cli_no_arbitrary_identity_run_or_command(self):
        for args in ([],["--check-readonly","--run-dir","private"],["--check-readonly","--candidate","f"*16],
                     ["--check-readonly","--recover"],["--check-readonly","--command","private"]):
            with mock.patch.object(sys,"argv",["entry"]+args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):entry.main()
        with mock.patch.object(entry,"REFERENCE_SHA256","0"*64),self.assertRaises(ValueError):entry.build_capsule()


if __name__=="__main__":unittest.main()
