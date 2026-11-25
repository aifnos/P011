"""HOST-only V9 functional entry tests: fake device, no RF or formal freeze."""
import ast
import contextlib
import copy
import hashlib
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT / "host"))
import device_p2p_v9mroute as entry
from tests import test_device_p2p_v8routediag as v8
from tests import test_device_p2p_v7l3diag as v7
from tests import test_device_prior_journal_readonly as readonly


class FakeAdb(v8.FakeAdb):
    MAP9 = {"new-fresh-v9-directory":"new-fresh-v8-directory", "new-owned-v9-run-directory":"new-owned-v8-run-directory",
        "push-new-v9-file":"push-new-v8-file", "initial-v9-prior-journals":"initial-v8-prior-journals",
        "last-v9-prior-journals":"last-v8-prior-journals", "owned-v9-journal-readonly":"owned-v8-journal-readonly",
        "finite-owned-p2p-v9-mroute-trial":"finite-owned-p2p-v8-routediag-trial"}
    def __init__(self,directory,action="good"):
        super().__init__(directory,self.MAP9.get(action,action)); self.original_action = action
    def run(self,label,arguments,timeout=30,input_data=None):
        if label in ("initial-fixed-v8-eight-readonly","last-fixed-v8-eight-readonly"):
            self.index += 1; self.calls.append((label,arguments,input_data,timeout))
            ast.parse(input_data.decode(),feature_version=(3,5)); value = v7.good_files(); value["identity_sha256"] = "6" * 64
            if self.original_action == label:value.update(complete=False,gate="file_pin")
            if self.original_action == "old_v8_metadata" and label.startswith("last"):value["identity_sha256"] = "7" * 64
            return self.keep_raw(readonly.wire(value))
        previous = len(self.calls)
        try:return super().run(self.MAP9.get(label,label),arguments,timeout,input_data)
        finally:
            if len(self.calls) > previous:
                old = self.calls[-1]; self.calls[-1] = (label,) + old[1:]


class ParserTests(unittest.TestCase):
    def test_pinned_functional_source_marker_schema_and_accepted_event(self):
        source = (entry.BASE / entry.RUNTIME_DIRECTORY / "mta_send_wifi.py").read_bytes()
        self.assertEqual(len(source),92153); self.assertEqual(hashlib.sha256(source).hexdigest(),entry.SOURCE_PINS["mta_send_wifi.py"])
        tree = ast.parse(source.decode(),feature_version=(3,5)); constants = {}
        for node in tree.body:
            if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant) and isinstance(node.targets[0],ast.Name):
                constants[node.targets[0].id] = node.value.value
        self.assertEqual(constants["DIAGNOSTIC_RUNTIME_MARKER"],entry.RUNTIME_MARKER)
        self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        diagnostic = v8.l3(); diagnostic["observations"]["route_prefix_is_128"] = False
        raw = v8.wire([v8.event(v8.fixtures.ready(),diagnostic),v8.event(v8.fixtures.cleanup(),diagnostic)])
        result = entry.parse_trial(raw); self.assertTrue(result["go_ip_ready_event"]); self.assertTrue(result["cleanup_complete"])
        self.assertEqual(result["ip_creation_l3"],diagnostic)
    def test_fixed_v8_parser_unchanged_raw_and_no_failure_promoted_to_functional_pass(self):
        raw = v8.wire([v8.failed()],1); original = bytes(raw)
        with mock.patch.object(entry.reference,"parse_trial",wraps=entry.reference.parse_trial) as parser:
            result = entry.parse_trial(raw)
        self.assertEqual(parser.call_args.args[0],original); self.assertEqual(raw,original)
        self.assertTrue(result["trial_failed_event"]); self.assertFalse(result["go_ip_ready_event"])
        self.assertTrue(result["failed_trial_cleanup_complete"]); self.assertFalse(result["cleanup_complete"])
        self.assertEqual(result["ip_creation_l3"]["route_details"]["values"]["prefix"],8)
    def test_reused_schema_strict_bool_prefix_unknown_fields_and_terminal_conflict(self):
        for prefix in (True,8.0,-1,129):
            row = v8.failed(); row["ip_creation_l3"]["route_details"]["values"]["prefix"] = prefix
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):entry.parse_trial(v8.wire([row],1))
        row = v8.failed(); row["ip_creation_l3"]["route_details"]["observations"]["flags_up"] = 1
        with self.assertRaises(ValueError):entry.parse_trial(v8.wire([row],1))
        row = v8.failed(); row["ip_creation_l3"]["route_details"]["raw"] = "HOST_PRIVATE"
        with self.assertRaises(ValueError):entry.parse_trial(v8.wire([row],1))
        a = v8.event(v8.fixtures.ready()); b = copy.deepcopy(v8.event(v8.fixtures.cleanup()))
        b["ip_creation_l3"]["observations"]["route_prefix_is_128"] = True
        with self.assertRaises(ValueError):entry.parse_trial(v8.wire([a,b]))
    def test_extra_output_missing_details_duplicate_keys_or_missing_ack_fail_closed(self):
        raw = v8.wire([v8.failed()],1)
        for invalid in (raw + b"HOST_PRIVATE\n",raw + b"MTA_REMOTE_EXIT=1\n",raw.replace(b'"prefix": 8',b'"prefix": 8, "prefix": 8',1)):
            with self.assertRaises((ValueError,json.JSONDecodeError)):entry.parse_trial(invalid)
        row = v8.failed(); row["ip_creation_l3"].pop("route_details")
        with self.assertRaises(ValueError):entry.parse_trial(v8.wire([row],1))


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.frozen = Path(cls.temporary.name) / "HOST_ONLY_EPHEMERAL_V9"
        cls.identity = entry.freeze(cls.frozen)  # Temporary HOST fixture, not formal workspace/device freeze.
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def invoke(self,action,directory):
        fakes = []
        def factory(path):
            fake = FakeAdb(path,action); fakes.append(fake); return fake
        with mock.patch.object(entry,"Adb",side_effect=factory):
            report,out = entry.run_reviewed(self.frozen,self.identity,Path(directory) / "HOST_RESULT")
        return report,out,fakes[0]
    def test_fixed_v8_full_manifest_7pins_and_separate_v7_v8_identity_fingerprints(self):
        before = {name:copy.deepcopy(getattr(entry.reference,name)) for name in ("SOURCE_PINS","NATIVE_PINS","IDENTITY3","PRIOR_CANDIDATES")}
        capsule = entry.build_capsule(self.frozen,self.identity)
        self.assertEqual(before,{name:getattr(entry.reference,name) for name in before})
        manifest = (entry.V8_FROZEN / "SOURCE.sha256").read_bytes()
        self.assertEqual((len(manifest),hashlib.sha256(manifest).hexdigest()),(654,entry.V8_MANIFEST))
        self.assertEqual(set(entry.V8_RECORDS),entry.EXPECTED_FILES)
        for relative,(pin,size) in entry.V8_RECORDS.items():
            raw = (entry.V8_FROZEN / relative).read_bytes(); self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(size,pin))
            self.assertIn(pin,capsule.old_v8_files)
        self.assertNotEqual(capsule.old_v7_files,capsule.old_v8_files)
        self.assertIn(repr(entry.reference.V7_TARGET),capsule.old_v7_files); self.assertIn(repr(entry.V8_TARGET),capsule.old_v8_files)
        self.assertIn("MODE=False",capsule.old_v7_files); self.assertIn("MODE=False",capsule.old_v8_files)
        self.assertEqual(set(entry.PRIOR_CANDIDATES),{"0f2a45489fd3e03b","916a02d44aeeaf0d",entry.reference.V7_ID,entry.V8_ID})
        self.assertEqual(entry.PRIOR_CANDIDATES[entry.V8_ID]["identity"],entry.reference.IDENTITY3)
        self.assertIn(repr(entry.PRIOR_CANDIDATES),capsule.prior); self.assertIn(repr(entry.IDENTITY3),capsule.journal)
        self.assertNotEqual(entry.PRIOR_CANDIDATES[entry.V8_ID]["identity"],entry.IDENTITY3)
    def test_new_eight_files_exact_pins_and_python35_all_generated_programs(self):
        capsule = entry.build_capsule(self.frozen,self.identity)
        self.assertEqual(set(capsule.records),entry.EXPECTED_FILES)
        self.assertEqual(len((self.frozen / "SOURCE.sha256").read_bytes()),654)
        for relative,(pin,size) in capsule.records.items():
            raw = (self.frozen / relative).read_bytes(); self.assertEqual((hashlib.sha256(raw).hexdigest(),len(raw)),(pin,size))
        for source in (capsule.stage,capsule.normalize,capsule.files,capsule.last_files,capsule.old_v7_files,capsule.old_v8_files,
                       capsule.prior,capsule.baseline,capsule.journal,capsule.make_run):
            tree = ast.parse(source,feature_version=(3,5)); self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        self.assertIn("--ttl 20",capsule.command); self.assertNotIn("--recover",capsule.command)
        for source in (capsule.normalize,capsule.files,capsule.old_v7_files,capsule.old_v8_files):self.assertNotIn("from mta_send_wifi",source)
    def test_functional_success_once_after_old16_v7eight_v8eight_and_final_full_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake = self.invoke("good",directory); self.assertTrue(report["pass"])
            labels = [row[0] for row in fake.calls]
            self.assertEqual(labels[:5],["initial-fixed16-readonly","initial-fixed-v7-eight-readonly","initial-fixed-v8-eight-readonly",
                "first-independent-baseline","new-fresh-v9-directory"])
            self.assertEqual(labels.count("push-new-v9-file"),8)
            self.assertEqual(labels[13:],["new-eight-fd-normalize","new-eight-independent-readback","initial-v9-prior-journals","new-owned-v9-run-directory",
                "last-new-eight-readonly","last-fixed16-readonly","last-fixed-v7-eight-readonly","last-fixed-v8-eight-readonly","last-v9-prior-journals",
                "last-independent-baseline","finite-owned-p2p-v9-mroute-trial","after-independent-old-reference","owned-v9-journal-readonly"])
            for key in ("historical_v7_files_verified","historical_v7_metadata_unchanged","historical_v8_files_verified","historical_v8_metadata_unchanged",
                        "full_ipv4_readback_unchanged","full_ipv6_readback_unchanged","journal_ip_receipt_restored"):
                self.assertTrue(report[key])
            self.assertIn("FUNCTIONAL",report["evidence_level"]); self.assertIn("FUNCTIONAL",(out / "README.txt").read_text())
            self.assertFalse(report["old_candidates_permissions_modified"]); self.assertFalse(report["send_available"])
            self.assertFalse(report["dhcp_configuration"]); self.assertEqual(report["phone_interop"],"NOT_TESTED")
            for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
            self.assertFalse(list(out.glob("*.zip")))
    def test_historical_v8_first_last_metadata_or_pin_fail_no_rf_and_independent_after(self):
        for action in ("initial-fixed-v8-eight-readonly","last-fixed-v8-eight-readonly","old_v8_metadata"):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,directory)
                self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                self.assertTrue(any(row[0] == "after-independent-old-reference" for row in fake.calls))
                self.assertFalse(any(row[0] == "finite-owned-p2p-v9-mroute-trial" for row in fake.calls))
    def test_all_inherited_preflight_file_prior_and_final_gates_fail_without_rf_retry(self):
        actions = ("initial-fixed16-readonly","initial-fixed-v7-eight-readonly","last-fixed-v7-eight-readonly","old_v7_metadata",
            "first_baseline","new-fresh-v9-directory","push_failure","new-eight-fd-normalize","new-eight-independent-readback",
            "initial-v9-prior-journals","new-owned-v9-run-directory","last-new-eight-readonly","new_metadata","last-fixed16-readonly",
            "old_metadata","last-v9-prior-journals","last_baseline","last_extra")
        for action in actions:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,directory); self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                self.assertTrue(any(row[0] == "after-independent-old-reference" for row in fake.calls))
                self.assertFalse(report["retry_invoked"]); self.assertFalse(report["recovery_invoked"])
    def test_failed_trial_malformed_timeout_and_receipt_failure_single_rf_no_false_success(self):
        for action in ("trial_failure","trial_timeout","malformed_trial","journal_incomplete"):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,directory); self.assertFalse(report["pass"]); self.assertTrue(report["rf_trial_invoked"])
                self.assertEqual(sum(row[0] == "finite-owned-p2p-v9-mroute-trial" for row in fake.calls),1)
                self.assertEqual([row[0] for row in fake.calls][-2:],["after-independent-old-reference","owned-v9-journal-readonly"])
                if action == "trial_failure":self.assertTrue(report["failed_trial_cleanup_complete"]); self.assertFalse(report["go_ip_ready_event"])
                for secret in ("HOST_PRIVATE","PRIVATE_PUSH","HOST_SECRET",'"PRIVATE"'):self.assertNotIn(secret,(out / "result.json").read_text())
                for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
    def test_ready_cleanup_do_not_mask_full_restore_journal_or_socket_facts(self):
        actions = ("after_stock","after_wifi","after_ipv6","after_ipv4","after_actor","after_process","after_interface","after_pending","after_boot","journal_identity")
        actions += tuple("journal_flag:" + key for key in ("safe","ownership_verified","version3","ipv4_baseline_present","ipv6_baseline_present",
            "pending_clear","baseline_independent_match","owned_process_gone","owned_interface_gone","ip_receipt_restored"))
        for action in actions:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,directory)
                self.assertTrue(report["go_ip_ready_event"]); self.assertTrue(report["cleanup_complete"]); self.assertFalse(report["pass"])
                self.assertEqual(sum(row[0] == "finite-owned-p2p-v9-mroute-trial" for row in fake.calls),1)
    def test_prior_future_identity_manifest_pin_or_reference_changed_block_before_adb(self):
        for change in ("future","identity","pin","manifest"):
            registry = copy.deepcopy(entry.PRIOR_CANDIDATES)
            if change == "future":registry["f" * 16] = registry[entry.V8_ID]
            elif change == "identity":registry[entry.V8_ID]["identity"]["runtime_marker"] = entry.RUNTIME_MARKER
            elif change == "pin":registry[entry.V8_ID]["pins"]["runtime/mta_send_wifi.py"] = "0" * 64
            else:registry[entry.V8_ID]["manifest_sha256"] = "0" * 64
            with mock.patch.object(entry,"PRIOR_CANDIDATES",registry),mock.patch.object(entry,"Adb",side_effect=AssertionError("HOST no ADB")),self.assertRaises(ValueError):
                entry.build_capsule(self.frozen,self.identity)
        for key in entry.REFERENCE_PINS:
            with mock.patch.object(entry,"REFERENCE_PINS",dict(entry.REFERENCE_PINS,**{key:"0" * 64})),self.assertRaises(ValueError):entry.verify_reference()
        broken = dict(entry.V8_RECORDS); broken["runtime/mta_send_wifi.py"] = ("0" * 64,90829)
        with mock.patch.object(entry,"V8_RECORDS",broken),self.assertRaises(ValueError):entry.verify_reference()
    def test_old_candidate_wrong_identity_extra_directory_or_existing_dest_reject(self):
        with self.assertRaises(ValueError):entry.verify_frozen(entry.V8_FROZEN,entry.V8_ID)
        with self.assertRaises(ValueError):entry.verify_frozen(self.frozen,"0" * 16)
        with self.assertRaises(FileExistsError):entry.freeze(self.frozen)
        (self.frozen / "empty_extra").mkdir()
        try:
            with self.assertRaises(ValueError):entry.verify_frozen(self.frozen)
        finally:(self.frozen / "empty_extra").rmdir()
    def test_second_read_payload_or_manifest_changed_reject_without_device_call(self):
        original = entry._data
        for relative in ("runtime/mta_send_wifi.py","SOURCE.sha256"):
            reads = []; changed_path = self.frozen / relative
            def read(path,bound):
                raw = original(path,bound)
                if Path(path) == changed_path:
                    reads.append(True)
                    if len(reads) == 2:return b"X" + raw[1:]
                return raw
            with self.subTest(relative=relative),mock.patch.object(entry,"_data",side_effect=read), \
                    mock.patch.object(entry,"Adb",side_effect=AssertionError("HOST no ADB")),self.assertRaises(ValueError):
                entry.build_capsule(self.frozen,self.identity)
            self.assertEqual(len(reads),2)
    def test_no_old_runner_globals_mutation_or_arbitrary_cli_overrides(self):
        source = inspect.getsource(entry)
        for token in ("reference.run_reviewed(","reader.run_reviewed(","setattr(","os.chmod(","os.chown(","killall","rm -rf"):
            self.assertNotIn(token,source)
        for argv in (["program"],["program","--execute-reviewed"],["program","--execute-reviewed","--ttl","20"],
                     ["program","--execute-reviewed","--command","PRIVATE"],["program","--freeze-only","--expected-candidate","f" * 16]):
            with mock.patch.object(sys,"argv",argv),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):entry.main()


class PinnedFileBodyTests(unittest.TestCase):
    def test_pinned_reader_all_eight_fds_validated_before_fchmod_and_closed(self):
        value,opened,closed,changed = v7.body_fixture(); self.assertTrue(value["complete"])
        self.assertEqual((len(opened),len(closed),len(changed)),(8,8,8))
        value,opened,closed,changed = v7.body_fixture(normalize=False)
        self.assertTrue(value["complete"]); self.assertFalse(changed); self.assertEqual(len(opened),len(closed))
    def test_partial_fd_close_metadata_pin_faults_preserve_failure_without_readonly_writes(self):
        for action in ("readonly_mode","owner","symlink","hardlink","fd_changed","last_pin","partial_open","close_error","extra_file","deadline"):
            with self.subTest(action=action):
                value,opened,closed,changed = v7.body_fixture(action,False)
                self.assertFalse(value["complete"]); self.assertFalse(changed); self.assertEqual(len(opened),len(closed))


if __name__ == "__main__":unittest.main()
