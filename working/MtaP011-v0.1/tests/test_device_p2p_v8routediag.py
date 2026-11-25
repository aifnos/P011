"""HOST-only V8 parser/registry/new8+old16+old8 admission and FakeADB tests."""
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
import device_p2p_v8routediag as entry
from tests import test_device_p2p_v7l3diag as v7
from tests import test_device_p2p_v6diag as fixtures
from tests import test_device_prior_journal_readonly as readonly


def details(values=None, flags=None, invalid=None):
    return {"values": {} if values is None else values, "observations": {} if flags is None else flags,
            "invalid_fields": [] if invalid is None else invalid}


def complete_details(values=None, flags=None, invalid=None):
    invalid = [] if invalid is None else invalid
    data = {"prefix":8,"destination_class":"multicast"}; data.update({} if values is None else values)
    facts = {"source_zero":True,"source_prefix_zero":True,"gateway_zero":True,
        **{name:name == "flags_up" for name, unused in entry.ROUTE_FLAG_BITS}, "flags_other_bits_set":False}
    facts.update({} if flags is None else flags)
    for field, fact in (("prefix","prefix"),("destination","destination_class")):
        if field in invalid:data.pop(fact, None)
    for field, fact in (("source","source_zero"),("source_prefix","source_prefix_zero"),("gateway","gateway_zero")):
        if field in invalid:facts.pop(fact, None)
    if "flags" in invalid:facts = {key:flag for key, flag in facts.items() if not key.startswith("flags_")}
    return details(data, facts, invalid)


def l3(previous=None, facts=None):
    return dict(v7.l3() if previous is None else copy.deepcopy(previous), route_details={} if facts is None else facts)


def event(row, diagnostic=None):
    row = copy.deepcopy(row); row["ip_creation_l3"] = l3() if diagnostic is None else diagnostic; return row


def failed(prefix=8):
    row = v7.failed()
    row["ip_creation_l3"]["observations"]["route_prefix_is_128"] = prefix == 128
    row["ip_creation_l3"]["route_details"] = details({"prefix": prefix, "destination_class": "multicast"},
        {"source_zero": True, "source_prefix_zero": True, "gateway_zero": True,
         **{name: name == "flags_up" for name, unused in entry.ROUTE_FLAG_BITS}, "flags_other_bits_set": False})
    return row


def wire(rows=None, status=0):
    return fixtures.wire([event(fixtures.ready()), event(fixtures.cleanup())] if rows is None else rows, status)


class ParserTests(unittest.TestCase):
    def test_real_pinned_v8_schema_constants_and_ready_cleanup(self):
        source = (entry.BASE / entry.RUNTIME_DIRECTORY / "mta_send_wifi.py").read_bytes()
        self.assertEqual(len(source), 90829)
        self.assertEqual(hashlib.sha256(source).hexdigest(), entry.SOURCE_PINS["mta_send_wifi.py"])
        tree = ast.parse(source.decode(), feature_version=(3, 5)); constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "frozenset":
                constants[node.targets[0].id] = frozenset(ast.literal_eval(node.value.args[0]))
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "IP_ROUTE_FLAG_BITS":
                constants[node.targets[0].id] = ast.literal_eval(node.value)
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "IP_ROUTE_BOOLS":
                constants["IP_ROUTE_BOOL_BASE"] = frozenset(ast.literal_eval(node.value.left.args[0]))
        self.assertEqual(entry.ROUTE_CLASSES, constants["IP_ROUTE_CLASSES"])
        self.assertEqual(entry.ROUTE_FIELDS, constants["IP_ROUTE_FIELDS"])
        self.assertEqual(entry.ROUTE_FLAG_BITS, constants["IP_ROUTE_FLAG_BITS"])
        expected = constants["IP_ROUTE_BOOL_BASE"] | frozenset(name for name, unused in constants["IP_ROUTE_FLAG_BITS"])
        self.assertEqual(entry.ROUTE_BOOLS, expected)
        report = entry.parse_trial(wire()); self.assertTrue(report["go_ip_ready_event"])
        self.assertTrue(report["cleanup_complete"]); self.assertEqual(report["ip_creation_l3"], l3())
    def test_route_8_and_128_failures_keep_failure_cleanup_separate(self):
        for prefix in (8, 128):
            report = entry.parse_trial(wire([failed(prefix)], 1))
            self.assertTrue(report["trial_failed_event"]); self.assertTrue(report["failed_trial_cleanup_complete"])
            self.assertFalse(report["cleanup_complete"]); self.assertFalse(report["go_ip_ready_event"])
            self.assertEqual(report["ip_creation_l3"]["route_details"]["values"]["prefix"], prefix)
    def test_exact_type_enum_unknown_raw_fields_and_invalid_conflicts_reject(self):
        bad = [None, [], {"raw": "HOST_PRIVATE"}, dict(details(), extra=True),
            details({"prefix": True}), details({"prefix": 8.0}), details({"prefix": -1}), details({"prefix": 129}),
            details({"destination_class": "HOST_PRIVATE"}), details({"destination_class": True}), details({"unknown": 8}),
            details(flags={"flags_up": 1}), details(flags={"unknown": True}), details(invalid=[True]),
            details(invalid=["unknown"]), details(invalid=["prefix", "prefix"]), details(invalid=["source", "prefix"]),
            details({"prefix": 8}, invalid=["prefix"]), details({"destination_class": "zero"}, invalid=["destination"]),
            details(flags={"source_zero": False}, invalid=["source"]), details(flags={"source_prefix_zero": True}, invalid=["source_prefix"]),
            details(flags={"gateway_zero": False}, invalid=["gateway"]), details(flags={"flags_local": False}, invalid=["flags"]),
            details({"prefix": 8}, invalid=["shape"]), details(invalid=["prefix", "shape"])]
        for facts in bad:
            with self.subTest(facts=facts), self.assertRaises(ValueError):entry.route_details(facts)
        for number in (0, 8, 64, 128):self.assertEqual(entry.route_details(complete_details({"prefix": number}))["values"]["prefix"], number)
        for name in entry.ROUTE_CLASSES:self.assertEqual(entry.route_details(complete_details({"destination_class": name}))["values"]["destination_class"], name)
    def test_invalid_missing_fields_not_clamped_and_same_text_flags_are_not_authorization(self):
        row = failed(); row["ip_creation_l3"]["route_details"] = complete_details({"destination_class": "other"}, invalid=["flags", "prefix"])
        result = entry.parse_trial(wire([row], 1))
        self.assertNotIn("prefix", result["ip_creation_l3"]["route_details"]["values"])
        self.assertTrue(result["trial_failed_event"]); self.assertFalse(result["cleanup_complete"])
        report = entry.parse_trial(wire([failed()], 1))
        self.assertFalse(report["go_ip_ready_event"])
    def test_shaped_rejection_requires_all_six_partitions_and_entire_flags_group(self):
        with self.assertRaises(ValueError):entry.route_details(details())
        full = complete_details(); self.assertEqual(entry.route_details(full), full)
        for key in ("prefix","destination_class"):
            value = copy.deepcopy(full); value["values"].pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):entry.route_details(value)
        for key in full["observations"]:
            value = copy.deepcopy(full); value["observations"].pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):entry.route_details(value)
        for field in ("destination","flags","gateway","prefix","source","source_prefix"):
            value = complete_details(invalid=[field]); self.assertEqual(entry.route_details(value), value)
        unknown_all = complete_details(invalid=["destination","flags","gateway","prefix","source","source_prefix"])
        self.assertEqual(entry.route_details(unknown_all), unknown_all)
        self.assertEqual(unknown_all["values"], {}); self.assertEqual(unknown_all["observations"], {})
    def test_unvisited_address_failure_and_constructor_require_empty_route_details(self):
        original = v7.l3("not_recorded", "not_recorded", {}, {})
        row = event(fixtures.failure(failure_phase="backend_construct", cleanup={"complete": True, "no_radio_mutation": True}), l3(original))
        row.pop("ip_control_socket_closed")
        self.assertEqual(entry.parse_trial(wire([row], 1))["ip_creation_l3"], l3(original))
        for previous in (original, v7.l3(), v7.l3("address_prefix", "address_fields", {"ipv6_address_rows":1,"ipv6_address_rows_examined":1}, {"address_dump_complete":True})):
            with self.assertRaises(ValueError):entry.l3_diagnostic(l3(previous, details({"prefix":8})))
        with self.assertRaises(ValueError):entry.l3_diagnostic(v7.l3())
        with self.assertRaises(ValueError):entry.l3_diagnostic(dict(l3(), extra=True))
    def test_shape_and_prefix_observations_conflict_fail_closed(self):
        previous = v7.l3("route_shape", "route_shape", flags={"address_dump_complete":True,"addresses_accepted":True})
        good = l3(previous, details(invalid=["shape"])); self.assertEqual(entry.l3_diagnostic(good), good)
        for bad in (l3(previous), l3(previous, details()), l3(previous, details({"prefix":8})),
                    l3(v7.failed()["ip_creation_l3"], details({"prefix":8})), l3(v7.failed()["ip_creation_l3"], details(invalid=["shape"]))):
            with self.assertRaises(ValueError):entry.l3_diagnostic(bad)
    def test_terminal_details_changed_missing_or_extra_lines_fail_raw_unchanged(self):
        original = wire([failed()], 1); saved = bytes(original); entry.parse_trial(original); self.assertEqual(original, saved)
        with mock.patch.object(entry.reference, "parse_trial", wraps=entry.reference.parse_trial) as compatibility:
            entry.parse_trial(original)
            self.assertNotIn(b"route_details", compatibility.call_args.args[0]); self.assertIn(b"ip_creation_l3", compatibility.call_args.args[0])
        for raw in (original + b"HOST_PRIVATE\n", original + b"MTA_REMOTE_EXIT=1\n",
                    original.replace(b'"prefix": 8', b'"prefix": 8, "prefix": 8', 1)):
            with self.assertRaises((ValueError, json.JSONDecodeError)):entry.parse_trial(raw)
        missing = event(fixtures.failure()); missing["ip_creation_l3"].pop("route_details")
        with self.assertRaises(ValueError):entry.parse_trial(wire([missing], 1))
        changed = event(fixtures.cleanup()); changed["ip_creation_l3"]["route_details"] = details({"prefix":8})
        with self.assertRaises(ValueError):entry.parse_trial(wire([event(fixtures.ready()), changed]))
    def test_diagnostic_returns_private_input_independent_copy(self):
        diagnostic = failed()["ip_creation_l3"]; result = entry.l3_diagnostic(diagnostic)
        result["route_details"]["values"]["prefix"] = 9
        result["route_details"]["observations"]["source_zero"] = False
        self.assertEqual(diagnostic["route_details"]["values"]["prefix"], 8)
        self.assertTrue(diagnostic["route_details"]["observations"]["source_zero"])


class FakeAdb(v7.FakeAdb):
    MAP = {"new-fresh-v8-directory":"new-fresh-v7-directory", "new-owned-v8-run-directory":"new-owned-v7-run-directory",
        "push-new-v8-file":"push-new-v7-file", "initial-v8-prior-journals":"initial-v7-prior-journals",
        "last-v8-prior-journals":"last-v7-prior-journals", "owned-v8-journal-readonly":"owned-v7-journal-readonly"}
    def __init__(self, directory, action="good"):
        super().__init__(directory, self.MAP.get(action, action)); self.original_action = action
    def run(self, label, arguments, timeout=30, input_data=None):
        if label in ("initial-fixed-v7-eight-readonly", "last-fixed-v7-eight-readonly", "finite-owned-p2p-v8-routediag-trial"):
            self.index += 1; self.calls.append((label, arguments, input_data, timeout))
            if label.endswith("eight-readonly"):
                ast.parse(input_data.decode(), feature_version=(3,5)); value = v7.good_files()
                value["identity_sha256"] = "4" * 64
                if self.original_action == label:value.update(complete=False, gate="file_pin")
                if self.original_action == "old_v7_metadata" and label.startswith("last"):value["identity_sha256"] = "5" * 64
                return self.keep_raw(readonly.wire(value))
            if self.original_action == "trial_timeout":raise TimeoutError("HOST_PRIVATE_TIMEOUT")
            if self.original_action == "trial_failure":return self.keep_raw(wire([failed()], 1))
            if self.original_action == "malformed_trial":return self.keep_raw(v7.wire())
            return self.keep_raw(wire())
        value = super().run(self.MAP.get(label, label), arguments, timeout, input_data)
        old = self.calls[-1]; self.calls[-1] = (label,) + old[1:]; return value


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.frozen = Path(cls.temporary.name) / "HOST_ONLY_EPHEMERAL_V8"
        # HOST temporary fixture only, not a formal workspace/device freeze.
        cls.identity = entry.freeze(cls.frozen)
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def invoke(self, action, directory):
        fakes = []
        def factory(path):
            fake = FakeAdb(path, action); fakes.append(fake); return fake
        with mock.patch.object(entry, "Adb", side_effect=factory):
            report, out = entry.run_reviewed(self.frozen, self.identity, Path(directory) / "HOST_RESULT")
        return report, out, fakes[0]
    def test_full_fixed_v7_manifest_7pins_8sizes_and_no_reference_globals_changed(self):
        before = {name:copy.deepcopy(getattr(entry.reference, name)) for name in ("SOURCE_PINS","NATIVE_PINS","IDENTITY3","PRIOR_CANDIDATES")}
        with mock.patch.object(entry, "Adb", side_effect=AssertionError("HOST no ADB")):capsule = entry.build_capsule(self.frozen, self.identity)
        self.assertEqual(before, {name:getattr(entry.reference, name) for name in before})
        manifest = (entry.V7_FROZEN / "SOURCE.sha256").read_bytes()
        self.assertEqual(len(manifest), 654); self.assertEqual(hashlib.sha256(manifest).hexdigest(), entry.V7_MANIFEST)
        self.assertEqual(set(entry.V7_RECORDS), entry.EXPECTED_FILES)
        for relative, (pin, size) in entry.V7_RECORDS.items():
            raw = (entry.V7_FROZEN / relative).read_bytes(); self.assertEqual(len(raw), size)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
            self.assertIn(repr(relative), capsule.old_v7_files); self.assertIn(pin, capsule.old_v7_files)
        self.assertIn("MODE=False", capsule.old_v7_files); self.assertIn(repr(entry.V7_TARGET), capsule.old_v7_files)
        self.assertEqual(len(entry.PRIOR_CANDIDATES[entry.V7_ID]["pins"]), 7)
        self.assertIn(repr(entry.PRIOR_CANDIDATES), capsule.prior)
        self.assertIn(repr(entry.IDENTITY3), capsule.journal)
        self.assertEqual(set(entry.PRIOR_CANDIDATES), {"0f2a45489fd3e03b","916a02d44aeeaf0d",entry.V7_ID})
    def test_new8_seven_pins_manifest_modes_program_ast_and_no_candidate_import_before_checks(self):
        capsule = entry.build_capsule(self.frozen, self.identity)
        self.assertEqual(set(capsule.records), entry.EXPECTED_FILES)
        self.assertEqual(len((self.frozen / "SOURCE.sha256").read_bytes()), 654)
        for relative, (pin, size) in capsule.records.items():
            raw = (self.frozen / relative).read_bytes(); self.assertEqual((hashlib.sha256(raw).hexdigest(), len(raw)), (pin, size))
        for source in (capsule.stage, capsule.normalize, capsule.files, capsule.last_files, capsule.old_v7_files,
                       capsule.prior, capsule.baseline, capsule.journal, capsule.make_run):
            tree = ast.parse(source, feature_version=(3,5)); self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertIn("--ttl 20", capsule.command); self.assertNotIn("--recover", capsule.command)
        for source in (capsule.normalize, capsule.files, capsule.old_v7_files):self.assertNotIn("from mta_send_wifi", source)
    def test_success_single_rf_only_after_old16_old8_new8_and_full_final_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            report, out, fake = self.invoke("good", directory); self.assertTrue(report["pass"])
            labels = [row[0] for row in fake.calls]
            self.assertEqual(labels[:4], ["initial-fixed16-readonly","initial-fixed-v7-eight-readonly","first-independent-baseline","new-fresh-v8-directory"])
            self.assertEqual(labels.count("push-new-v8-file"), 8)
            ordered = ["new-eight-fd-normalize","new-eight-independent-readback","initial-v8-prior-journals","new-owned-v8-run-directory",
                "last-new-eight-readonly","last-fixed16-readonly","last-fixed-v7-eight-readonly","last-v8-prior-journals",
                "last-independent-baseline","finite-owned-p2p-v8-routediag-trial","after-independent-old-reference","owned-v8-journal-readonly"]
            self.assertEqual(labels[12:], ordered)
            for name in ("historical_v7_files_verified","historical_v7_metadata_unchanged","full_ipv4_readback_unchanged","full_ipv6_readback_unchanged","journal_ip_receipt_restored"):
                self.assertTrue(report[name])
            self.assertFalse(report["old_candidates_permissions_modified"]); self.assertFalse(report["send_available"])
            self.assertFalse(report["dhcp_configuration"]); self.assertFalse(report["phone_interop"] != "NOT_TESTED")
            for path, raw in fake.raw:self.assertEqual(path.read_bytes(), raw)
            self.assertFalse(list(out.glob("*.zip")))
    def test_old_v7_pin_metadata_or_final_change_blocks_before_rf_and_still_final_baseline(self):
        for action in ("initial-fixed-v7-eight-readonly", "last-fixed-v7-eight-readonly", "old_v7_metadata"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                self.assertFalse(any(row[0] == "finite-owned-p2p-v8-routediag-trial" for row in fake.calls))
                self.assertEqual([row[0] for row in fake.calls][-1 if action.startswith("initial") else -2], "after-independent-old-reference")
    def test_inherited_preflight_and_final_gate_faults_block_no_retry(self):
        actions = ("initial-fixed16-readonly","first_baseline","new-fresh-v8-directory","push_failure","new-eight-fd-normalize",
            "new-eight-independent-readback","initial-v8-prior-journals","new-owned-v8-run-directory","last-new-eight-readonly",
            "new_metadata","last-fixed16-readonly","old_metadata","last-v8-prior-journals","last_baseline","last_extra")
        for action in actions:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory); self.assertFalse(report["pass"]); self.assertFalse(report["rf_trial_invoked"])
                self.assertTrue(any(row[0] == "after-independent-old-reference" for row in fake.calls))
                self.assertFalse(report["retry_invoked"]); self.assertFalse(report["recovery_invoked"])
    def test_trial_failure_parse_failure_and_timeout_once_no_fake_ip_success_or_secret_text(self):
        for action in ("trial_failure","trial_timeout","malformed_trial","journal_incomplete"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory); self.assertFalse(report["pass"]); self.assertTrue(report["rf_trial_invoked"])
                self.assertEqual(sum(row[0] == "finite-owned-p2p-v8-routediag-trial" for row in fake.calls), 1)
                self.assertEqual([row[0] for row in fake.calls][-2:], ["after-independent-old-reference","owned-v8-journal-readonly"])
                if action == "trial_failure":
                    self.assertTrue(report["failed_trial_cleanup_complete"]); self.assertFalse(report["go_ip_ready_event"])
                    self.assertEqual(report["ip_creation_l3"]["route_details"]["values"]["prefix"], 8)
                public = (out / "result.json").read_text()
                for text in ("HOST_PRIVATE","PRIVATE_PUSH","HOST_SECRET",'"PRIVATE"'):self.assertNotIn(text, public)
                for path, raw in fake.raw:self.assertEqual(path.read_bytes(), raw)
    def test_main_stage_success_does_not_mask_full_independent_restore_failures(self):
        actions = ("after_stock","after_wifi","after_ipv6","after_ipv4","after_actor","after_process","after_interface","after_pending","after_boot","journal_identity")
        actions += tuple("journal_flag:" + key for key in ("safe","ownership_verified","version3","ipv4_baseline_present","ipv6_baseline_present",
            "pending_clear","baseline_independent_match","owned_process_gone","owned_interface_gone","ip_receipt_restored"))
        for action in actions:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertTrue(report["go_ip_ready_event"]); self.assertTrue(report["cleanup_complete"]); self.assertFalse(report["pass"])
                self.assertEqual(sum(row[0] == "finite-owned-p2p-v8-routediag-trial" for row in fake.calls), 1)
    def test_future_old_identity_pin_manifest_and_changed_reference_rejected_before_adb(self):
        for change in ("future","identity","pin","manifest"):
            registry = copy.deepcopy(entry.PRIOR_CANDIDATES)
            if change == "future":registry["f" * 16] = registry[entry.V7_ID]
            elif change == "identity":registry[entry.V7_ID]["identity"]["runtime_marker"] = entry.RUNTIME_MARKER
            elif change == "pin":registry[entry.V7_ID]["pins"]["runtime/mta_send_wifi.py"] = "0" * 64
            else:registry[entry.V7_ID]["manifest_sha256"] = "0" * 64
            with mock.patch.object(entry, "PRIOR_CANDIDATES", registry), mock.patch.object(entry, "Adb", side_effect=AssertionError("HOST no ADB")), self.assertRaises(ValueError):
                entry.build_capsule(self.frozen, self.identity)
        for key in entry.REFERENCE_PINS:
            with mock.patch.object(entry, "REFERENCE_PINS", dict(entry.REFERENCE_PINS, **{key:"0" * 64})), self.assertRaises(ValueError):entry.verify_reference()
        broken = dict(entry.V7_RECORDS); broken["runtime/mta_send_wifi.py"] = ("0" * 64, 85568)
        with mock.patch.object(entry, "V7_RECORDS", broken), self.assertRaises(ValueError):entry.verify_reference()
    def test_old_frozen_wrong_identity_and_extra_directory_not_accepted(self):
        with self.assertRaises(ValueError):entry.verify_frozen(entry.V7_FROZEN, entry.V7_ID)
        with self.assertRaises(ValueError):entry.verify_frozen(self.frozen, "0" * 16)
        with self.assertRaises(FileExistsError):entry.freeze(self.frozen)
        (self.frozen / "empty_extra").mkdir()
        try:
            with self.assertRaises(ValueError):entry.verify_frozen(self.frozen)
        finally:(self.frozen / "empty_extra").rmdir()
    def test_capsule_second_read_source_or_manifest_change_blocks_before_adb(self):
        original = entry._data
        for relative in ("runtime/mta_send_wifi.py", "SOURCE.sha256"):
            reads = []; changed_path = self.frozen / relative
            def read(path, bound):
                raw = original(path, bound)
                if Path(path) == changed_path:
                    reads.append(True)
                    if len(reads) == 2:return b"X" + raw[1:]
                return raw
            with self.subTest(relative=relative), mock.patch.object(entry, "_data", side_effect=read), \
                    mock.patch.object(entry, "Adb", side_effect=AssertionError("HOST no ADB")), self.assertRaises(ValueError):
                entry.build_capsule(self.frozen, self.identity)
            self.assertEqual(len(reads), 2)
    def test_no_global_mutation_or_old_runner_or_arbitrary_cli(self):
        source = inspect.getsource(entry)
        for token in ("reference.run_reviewed(","setattr(","os.chmod(","os.chown(","killall","rm -rf"):
            self.assertNotIn(token, source)
        for argv in (["program"],["program","--execute-reviewed"],["program","--execute-reviewed","--ttl","20"],
                     ["program","--execute-reviewed","--command","PRIVATE"],["program","--freeze-only","--expected-candidate","f" * 16]):
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):entry.main()


class PinnedFileBodyTests(unittest.TestCase):
    def test_same_pinned_new_and_old8_fd_reader_all_prevalidated_closed_before_writes(self):
        value, opened, closed, changed = v7.body_fixture(); self.assertTrue(value["complete"])
        self.assertEqual((len(opened),len(closed),len(changed)), (8,8,8))
        value, opened, closed, changed = v7.body_fixture(normalize=False)
        self.assertTrue(value["complete"]); self.assertFalse(changed); self.assertEqual(len(opened),len(closed))
    def test_old8_readonly_mode_link_owner_partial_open_and_close_faults_fail_without_write(self):
        for action in ("readonly_mode","owner","symlink","hardlink","fd_changed","last_pin","partial_open","close_error","extra_file","deadline"):
            with self.subTest(action=action):
                value, opened, closed, changed = v7.body_fixture(action, False)
                self.assertFalse(value["complete"]); self.assertFalse(changed); self.assertEqual(len(opened),len(closed))


if __name__ == "__main__":unittest.main()
