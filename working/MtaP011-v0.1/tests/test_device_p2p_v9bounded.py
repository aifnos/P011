"""Focused HOST-only V9 bounded-entry fixtures; no device/RF/socket/freeze."""
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
sys.path.insert(0, str(PROJECT / "host"))
import device_p2p_v9bounded as entry
from tests import test_device_p2p_v8routediag as v8
from tests import test_device_p2p_v7l3diag as v7
from tests import test_device_prior_journal_readonly as readonly


def payload(program):return (program + "\nprint('MTA_READONLY_OK')\n").encode("utf-8")


def canonical_4095_model(data):
    # Only a HOST model of canonical n_tty storage, NOT live ICANON evidence.
    rows = data.splitlines(keepends=True)
    return b"".join(row[:-1][:4095] + b"\n" if row.endswith(b"\n") else row[:4095] for row in rows)


def assignment(program, name):
    values = [ast.literal_eval(node.value) for node in ast.parse(program, feature_version=(3, 5)).body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name]
    if len(values) != 1:raise ValueError("HOST unique literal")
    return values[0]


_CAPSULES = None
def capsules():
    global _CAPSULES
    if _CAPSULES is None:_CAPSULES = {mode:entry.build_capsule(mode) for mode in (False,True)}
    return _CAPSULES


class FakeAdb(v7.FakeAdb):
    """Unique metadata fingerprints for four separate file groups."""
    def run(self, label, arguments, timeout=30, input_data=None):
        self.index += 1; self.calls.append((label, arguments, input_data, timeout))
        if label == "finite-owned-p2p-v9-bounded-trial":
            if self.action == "trial_timeout":
                self.keep_raw(b"HOST_PRIVATE_TIMEOUT\n"); raise TimeoutError("HOST_PRIVATE_TIMEOUT")
            if self.action == "malformed_trial":return self.keep_raw(b"HOST_PRIVATE\n")
            return self.keep_raw(v8.wire([v8.failed()], 1) if self.action == "trial_failure" else v8.wire())
        ast.parse(input_data.decode("utf-8"), feature_version=(3, 5))
        if any(len(line) > entry.MAX_LINE_BYTES for line in input_data.splitlines()):raise AssertionError("HOST overlong input")
        if label.endswith("fixed16-readonly") or label.endswith("eight-readonly"):
            group = "fixed16" if label.endswith("fixed16-readonly") else label.split("-fixed-", 1)[1].split("-", 1)[0]
            value = v7.old_files() if group == "fixed16" else v7.good_files()
            value["identity_sha256"] = {"fixed16":"1", "v7":"2", "v8":"3", "v9":"4"}[group] * 64
            if self.action == label:
                value.update(complete=False, gate="file_metadata")
                if group == "fixed16":value.update(pins_verified=False, permissions_verified=False)
            if self.action == "metadata_" + group and label.startswith("last-"):value["identity_sha256"] = "9" * 64
        elif label.endswith("prior-journals"):
            if self.action == "prior_timeout":
                self.keep_raw(input_data.replace(b"\n", b"\r\r\n"))
                (self.directory / ("%02d-%s.host-exit" % (self.index, label))).write_text("TIMEOUT")
                raise TimeoutError("HOST_PRIVATE_TIMEOUT")
            if self.action == "prior_echo_only":return self.keep_raw(input_data.replace(b"\n", b"\r\r\n"))
            if self.action == "prior_missing_ok":return self.keep_raw(b"RESULT=True\nMTA_REMOTE_EXIT=0\n")
            if self.action == "prior_duplicate_exit":return self.keep_raw(readonly.wire(True) + b"MTA_REMOTE_EXIT=0\n")
            value = {"clear":True, "global_pending_clear":True, "blocked_count":0, "unsafe_count":0, "inspected_count":7}
            if self.action == label:value.update(clear=False, unsafe_count=1)
        elif label == "new-owned-v9-bounded-run-directory":value = self.action != label
        elif label == "owned-v9-bounded-journal-readonly":
            value = v8.fixtures.journal_summary()
            if self.action in ("journal_incomplete", "trial_failure"):value.update(complete=False, ip_receipt_restored=False, ip_stage="none")
            if self.action.startswith("journal_flag:"):value[self.action.split(":", 1)[1]] = False
            if self.action == "journal_identity":value["identity_mismatch"] = True
        else:
            value = copy.deepcopy(self.first)
            if self.action == "first_baseline" and label.startswith("first-"):value["pending"]["present"] = True
            if self.action == "last_baseline" and label.startswith("last-"):value["ipv4"]["routes"][0][2] = 200
            if self.action == "last_extra" and label.startswith("last-"):value["HOST_PRIVATE"] = True
            if label.startswith("after-"):
                if self.action == "after_stock":value["stock_valid"] = False
                if self.action == "after_wifi":value["wifi"]["completed"] = False
                if self.action == "after_ipv6":value["ipv6_routes_raw"] += b"HOST_CHANGED"
                if self.action == "after_ipv4":value["ipv4"]["addresses"][0][8][2] += 1
                if self.action == "after_rules":value["ipv4"]["rules"][0][1] += 1
                if self.action == "after_actor":value["no_project_trial_actors"] = False
                if self.action == "after_process":value["network_processes"][0]["starttime"] += 1
                if self.action == "after_interface":value["interfaces"][0]["wdev"] += 1
                if self.action == "after_pending":value["pending"]["present"] = True
                if self.action == "after_boot":value["boot_id"] += "-changed"
                if self.action == "after_query":value["query_ok"] = False
        return self.keep_raw(readonly.wire(value))


class ProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.capsules = capsules()
    def test_canonical_model_old_loses_exact405_new_full_and_registry_unchanged(self):
        old = entry.reference.probe_source(entry.TARGET, entry.reference.verify_reference(), entry.reader.old.PRIOR_JOURNALS)
        bounded = entry.bounded_program(old)
        self.assertEqual(len(payload(old)), 32270)
        self.assertEqual(max(len(row) for row in payload(old).splitlines()), 4500)
        self.assertEqual(len(payload(old)) - len(canonical_4095_model(payload(old))), 405)
        self.assertEqual(canonical_4095_model(payload(bounded)), payload(bounded))
        self.assertEqual(assignment(old, "PRIOR_CANDIDATES"), entry.PRIOR_CANDIDATES)
        self.assertEqual(assignment(bounded, "PRIOR_CANDIDATES"), entry.PRIOR_CANDIDATES)
        self.assertEqual(ast.dump(ast.parse(old)), ast.dump(ast.parse(bounded)))
    def test_all_programs_and_completion_payload_under_line_total_limits_python35(self):
        for mode, capsule in self.capsules.items():
            programs = list(capsule.initial_files.values()) + list(capsule.last_files.values())
            programs += [capsule.old_baseline, capsule.prior, capsule.baseline]
            programs += [] if mode else [capsule.journal, capsule.make_run]
            for source in programs:
                with self.subTest(mode=mode, kind=len(source)):
                    self.assertLessEqual(len(payload(source)), entry.MAX_SOURCE_BYTES)
                    self.assertLessEqual(max(map(len, payload(source).splitlines())), entry.MAX_LINE_BYTES)
                    self.assertEqual(canonical_4095_model(payload(source)), payload(source))
                    tree = ast.parse(source, feature_version=(3, 5))
                    self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
            self.assertEqual(assignment(capsule.initial_files["fixed16"], "CANDIDATES"), entry.reader.historical_files.CANDIDATES)
            self.assertEqual(assignment(capsule.prior, "IDENTITY3"), entry.IDENTITY3)
    def test_unreviewed_long_lines_utf8_limits_types_ast_assert_and_total_fail_closed(self):
        for source in ("UNREVIEWED=" + repr("x" * 2048), "x=" + repr("字" * 800), "x='" + "x" * entry.MAX_SOURCE_BYTES + "'",
                       "assert True\n", "PRIOR_CANDIDATES=set()\n", "CANDIDATES={1:'x'}\n", "CANDIDATES={'x':1.0}\n"):
            with self.subTest(kind=source[:24]), self.assertRaises((ValueError, SyntaxError)):entry.bounded_program(source)
        with self.assertRaises(ValueError):entry.bounded_program(b"x=1")
        with self.assertRaises(ValueError):entry._literal({"x":{"y":1}},17)
    def test_multiline_preserves_dict_sequence_order_whole_ast_and_is_idempotent(self):
        data = {"b":(True,None,"中文"),"a":[1,2],"empty":{}}
        source = "# retained\nCANDIDATES=" + repr(data) + "\nx=1\n"
        bounded = entry.bounded_program(source)
        self.assertEqual(ast.dump(ast.parse(source)), ast.dump(ast.parse(bounded)))
        self.assertEqual(list(assignment(bounded,"CANDIDATES")), list(data))
        self.assertEqual(entry.bounded_program(bounded), bounded)
    def test_staged_current_full8_manifest_and_all_prior_pins_no_old_globals_mutation(self):
        originals = {name:copy.deepcopy(getattr(entry.reference,name)) for name in ("SOURCE_PINS","NATIVE_PINS","IDENTITY3","PRIOR_CANDIDATES")}
        with mock.patch.object(entry,"Adb",side_effect=AssertionError("HOST no ADB")):capsule = entry.build_capsule(True)
        self.assertEqual(originals,{name:getattr(entry.reference,name) for name in originals})
        self.assertEqual(len(capsule.records),8); self.assertEqual(capsule.records["SOURCE.sha256"],(entry.MANIFEST_SHA256,654))
        self.assertEqual(set(entry.PRIOR_CANDIDATES),{"0f2a45489fd3e03b","916a02d44aeeaf0d",entry.reference.reference.V7_ID,entry.reference.V8_ID})
        for relative,(pin,size) in capsule.records.items():
            raw = (entry.FROZEN / relative).read_bytes(); self.assertEqual((hashlib.sha256(raw).hexdigest(),len(raw)),(pin,size))
            self.assertIn(pin,capsule.initial_files["v9"])
        for version,target,records in (("v7",entry.reference.reference.V7_TARGET,entry.reference.reference.V7_RECORDS),
                                       ("v8",entry.reference.V8_TARGET,entry.reference.V8_RECORDS)):
            self.assertIn(repr(target),capsule.initial_files[version])
            self.assertEqual(assignment(capsule.initial_files[version],"RECORDS"),records)
        self.assertNotEqual(capsule.initial_files["v7"],capsule.initial_files["v8"])
    def test_changed_pinned_ref_current_record_registry_identity_future_block_before_adb(self):
        for label in entry.REFERENCE_PINS:
            with mock.patch.object(entry,"REFERENCE_PINS",dict(entry.REFERENCE_PINS,**{label:"0"*64})),self.assertRaises(ValueError):entry.verify_reference()
        for field in ("manifest_sha256","identity","pins"):
            data = copy.deepcopy(entry.PRIOR_CANDIDATES)
            if field == "manifest_sha256":data[entry.reference.V8_ID][field] = "0"*64
            elif field == "identity":data[entry.reference.V8_ID][field]["runtime_marker"] = entry.IDENTITY3["runtime_marker"]
            else:data[entry.reference.V8_ID][field]["runtime/mta_send_wifi.py"] = "0"*64
            with mock.patch.object(entry,"PRIOR_CANDIDATES",data),self.assertRaises(ValueError):entry.verify_reference()
        data = copy.deepcopy(entry.PRIOR_CANDIDATES); data["f"*16] = data[entry.reference.V8_ID]
        with mock.patch.object(entry,"PRIOR_CANDIDATES",data),self.assertRaises(ValueError):entry.verify_reference()
        records = dict(entry.RECORDS); records["runtime/mta_send_wifi.py"] = ("0"*64,92153)
        with mock.patch.object(entry,"RECORDS",records),self.assertRaises(ValueError):entry.verify_reference()
    def test_readonly_capsule_has_no_run_command_make_or_journal_and_mode_strict(self):
        capsule = self.capsules[True]
        self.assertIsNone(capsule.run); self.assertIsNone(capsule.make_run); self.assertIsNone(capsule.command); self.assertIsNone(capsule.journal)
        self.assertIn("RUN=None",capsule.last_files["v9"])
        self.assertIn("--ttl 20",self.capsules[False].command); self.assertNotIn("--recover",self.capsules[False].command)
        for invalid in (1,None,"readonly"):
            with self.assertRaises(ValueError):entry.build_capsule(invalid)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.capsules = capsules()
    def invoke(self,action,mode,directory):
        fakes = []
        def factory(path):
            fake = FakeAdb(path,action); fakes.append(fake); return fake
        # Real capsule generation tested separately; reuse only HOST fixtures.
        with mock.patch.object(entry,"build_capsule",return_value=self.capsules[mode]),mock.patch.object(entry,"Adb",side_effect=factory):
            report,out = entry.run_reviewed(mode,Path(directory) / "HOST_RESULT")
        return report,out,fakes[0]
    def test_no_rf_mode_single_prior_all_four_groups_before_after_raw_kept_not_functional(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake = self.invoke("good",True,directory)
            self.assertTrue(report["pass"]); self.assertTrue(report["readonly_preflight_complete"])
            labels = [row[0] for row in fake.calls]
            self.assertEqual(labels[:6],["initial-fixed16-readonly","initial-fixed-v7-eight-readonly","initial-fixed-v8-eight-readonly",
                "initial-fixed-v9-eight-readonly","first-independent-baseline","initial-v9-bounded-prior-journals"])
            self.assertEqual(labels[6:],["last-fixed16-readonly","last-fixed-v7-eight-readonly","last-fixed-v8-eight-readonly",
                "last-fixed-v9-eight-readonly","last-independent-baseline","after-independent-old-reference"])
            self.assertFalse(report["rf_trial_invoked"]); self.assertFalse(report["ip_trial_requested"]); self.assertFalse(report["go_ip_ready_event"])
            self.assertEqual(report["bounded_prior_checks"],1)
            self.assertFalse(any("run-directory" in name or "trial" in name for name in labels))
            self.assertFalse(report["candidate_staging_requested"]); self.assertFalse(report["permissions_modified"])
            self.assertFalse(report["send_available"]); self.assertEqual(report["phone_interop"],"NOT_TESTED")
            self.assertTrue(all(report[key] for key in entry.RESTORE_GATES))
            for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
            self.assertFalse(list(out.glob("*.zip")))
    def test_functional_once_no_stage_or_chmod_two_priors_last_gate_before_actual_trial(self):
        with tempfile.TemporaryDirectory() as directory:
            report,out,fake = self.invoke("good",False,directory)
            self.assertTrue(report["pass"]); self.assertFalse(report["readonly_preflight_complete"]); self.assertTrue(report["rf_trial_invoked"])
            labels = [row[0] for row in fake.calls]
            self.assertEqual(labels.count("finite-owned-p2p-v9-bounded-trial"),1); self.assertEqual(report["bounded_prior_checks"],2)
            self.assertEqual(labels[-4:],["last-independent-baseline","finite-owned-p2p-v9-bounded-trial","after-independent-old-reference","owned-v9-bounded-journal-readonly"])
            self.assertIn("new-owned-v9-bounded-run-directory",labels)
            for forbidden in ("push","normalize","fresh-directory"):self.assertFalse(any(forbidden in label for label in labels))
            self.assertTrue(report["journal_ip_receipt_restored"]); self.assertTrue(report["full_ipv4_readback_unchanged"])
            self.assertFalse(report["candidate_staged"]); self.assertFalse(report["new_candidate_permission_write_requested"])
    def test_every_first_last_group_pin_permission_metadata_failure_prevents_rf_and_keeps_after(self):
        actions = [entry._label(phase,group) for phase in ("initial","last") for group in ("fixed16","v7","v8","v9")]
        actions += ["metadata_"+group for group in ("fixed16","v7","v8","v9")]
        for mode in (True,False):
            for action in actions:
                with self.subTest(mode=mode,action=action),tempfile.TemporaryDirectory() as directory:
                    report,out,fake = self.invoke(action,mode,directory)
                    self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                    self.assertTrue(any(row[0] == "after-independent-old-reference" for row in fake.calls))
                    self.assertFalse(report["retry_invoked"]); self.assertFalse(report["recovery_invoked"])
    def test_original_baseline_prior_make_run_and_late_change_block_no_rf(self):
        actions = ("first_baseline","initial-v9-bounded-prior-journals","last-v9-bounded-prior-journals",
                   "new-owned-v9-bounded-run-directory","last_baseline","last_extra")
        for action in actions:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,False,directory)
                self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                self.assertFalse(any(row[0] == "finite-owned-p2p-v9-bounded-trial" for row in fake.calls))
    def test_readonly_timeout_source_echo_missing_or_duplicate_completion_fail_raw_retained(self):
        for action in ("prior_timeout","prior_echo_only","prior_missing_ok","prior_duplicate_exit"):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,True,directory)
                self.assertFalse(report["pass"]); self.assertFalse(report["readonly_preflight_complete"]); self.assertFalse(report["rf_trial_invoked"])
                status = report["remote_statuses"]["initial-v9-bounded-prior-journals"]
                self.assertFalse(status["result_valid"])
                if action == "prior_timeout":self.assertEqual(status["host"],"timeout"); self.assertEqual(status["remote"],"not_recorded")
                calls = [row for row in fake.calls if row[0].endswith("prior-journals")]
                self.assertEqual(len(calls),1); self.assertEqual(calls[0][3],50)
                for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
    def test_after_baseline_fields_fail_readonly_and_ready_cannot_mask_restore(self):
        actions = ("after_stock","after_wifi","after_ipv6","after_ipv4","after_rules","after_actor","after_process",
                   "after_interface","after_pending","after_boot","after_query")
        for mode in (True,False):
            for action in actions:
                with self.subTest(mode=mode,action=action),tempfile.TemporaryDirectory() as directory:
                    report,out,fake = self.invoke(action,mode,directory); self.assertFalse(report["pass"])
                    self.assertEqual(report["go_ip_ready_event"],not mode); self.assertFalse(report["readonly_preflight_complete"])
    def test_functional_failure_timeout_malformed_and_all_journal_receipts_no_fake_success(self):
        actions = ("trial_failure","trial_timeout","malformed_trial","journal_incomplete","journal_identity")
        actions += tuple("journal_flag:"+key for key in ("safe","ownership_verified","version3","ipv4_baseline_present","ipv6_baseline_present",
            "pending_clear","baseline_independent_match","owned_process_gone","owned_interface_gone","ip_receipt_restored"))
        for action in actions:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                report,out,fake = self.invoke(action,False,directory); self.assertFalse(report["pass"])
                self.assertEqual(sum(row[0] == "finite-owned-p2p-v9-bounded-trial" for row in fake.calls),1)
                self.assertEqual([row[0] for row in fake.calls][-2:],["after-independent-old-reference","owned-v9-bounded-journal-readonly"])
                for path,raw in fake.raw:self.assertEqual(path.read_bytes(),raw)
                for secret in ("HOST_PRIVATE","HOST_PRIVATE_TIMEOUT","HOST_SECRET",'"PRIVATE"'):self.assertNotIn(secret,(out / "result.json").read_text())
    def test_no_old_runner_global_mutation_stage_permissions_or_arbitrary_cli_inputs(self):
        source = inspect.getsource(entry)
        for token in ("reference.run_reviewed(","reference.freeze(","reader.run_reviewed(","setattr(","os.chmod(","fchmod(",
                      '"push"',"killall","rm -rf","--freeze-only"):
            self.assertNotIn(token,source)
        for arguments in ([],["--readonly-preflight","--execute-reviewed"],["--execute-reviewed","--ttl","20"],
            ["--execute-reviewed","--frozen","private"],["--readonly-preflight","--expected-candidate",entry.CANDIDATE],
            ["--execute-reviewed","--output","private"],["--execute-reviewed","--command","private"]):
            with mock.patch.object(sys,"argv",["entry"]+arguments),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):entry.main()
        for arguments,mode in ((["--readonly-preflight"],True),(["--execute-reviewed"],False)):
            with mock.patch.object(sys,"argv",["entry"]+arguments),mock.patch.object(entry,"run_reviewed",return_value=({"pass":False},Path("HOST"))) as runner, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(entry.main(),1); runner.assert_called_once_with(mode)


if __name__ == "__main__":unittest.main()
