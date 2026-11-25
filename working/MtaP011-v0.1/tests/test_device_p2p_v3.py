"""HOST-only V3 candidate/diagnostic/owned lifecycle harness guards.

FakeAdb never touches P011/RF. Synthetic pass means a branch, not hardware.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "host"))
import device_p2p_v3 as v3
import device_p2p_v2 as v2
from test_device_p2p_v2 import baseline, journal


def diagnostics():
    return {"events": [{"stage": name, "code": 0} for name in sorted(v3.INIT_REQUIRED)],
            "diagnostic_invalid": False, "raw_diagnostics_not_logged": True}


def ready():
    return {"event": "private_go_ready", "ttl": 20, "credentials_not_logged": True}


def cleanup():
    return {"event": "private_go_cleanup", "owned_process_removed": True,
            "owned_interface_removed": True, "stock_baseline_equal": True,
            "complete": True, "diagnostics": diagnostics()}


def failure(**changes):
    row = {"event": "private_go_trial_failed", "reason": "os_error",
           "cleanup": {"complete": True, "no_radio_mutation": True, "raw": "HOST_SECRET_NESTED"},
           "complete": False, "diagnostics": diagnostics(), "failure_phase": "interface_create",
           "failure_errno": 16, "netlink_command": "new_interface"}
    row.update(changes)
    return row


def wire(events=None, code=0):
    events = [ready(), cleanup()] if events is None else events
    return ("\n".join(json.dumps(row) for row in events) + "\nMTA_REMOTE_EXIT=" + str(code) + "\n").encode("utf-8")


class FakeAdb(object):
    calls = []
    before = baseline(); after = baseline(); owned = journal()
    prior = {"clear": True, "global_pending_clear": True}
    raw = wire(); timeout = False
    def __init__(self, directory):
        self.directory = directory; self.calls.append(("constructor", None))
    def python(self, label, source, timeout=45):
        self.calls.append((label, source))
        if label in ("initial-stock", "candidate-directory", "verify-pinned-v3-candidate", "new-owned-v3-run-directory"):
            return True
        if label == "prior-journals-v3-readonly":return copy.deepcopy(self.prior)
        if label == "before-independent-v3":return copy.deepcopy(self.before)
        if label == "after-independent-v3":return copy.deepcopy(self.after)
        if label == "owned-journal-v3-readonly":return copy.deepcopy(self.owned)
        raise AssertionError("Unexpected HOST fake probe")
    def run(self, label, arguments, timeout=30):
        self.calls.append((label, arguments))
        if label != "finite-owned-p2p-v3-trial":raise AssertionError("Unexpected fake mutation")
        if self.timeout:raise RuntimeError("HOST_SECRET_TIMEOUT")
        return self.raw


class V3HarnessTests(unittest.TestCase):
    def setUp(self):
        FakeAdb.calls = []; FakeAdb.before = baseline(); FakeAdb.after = baseline(); FakeAdb.owned = journal()
        FakeAdb.prior = {"clear": True, "global_pending_clear": True}; FakeAdb.raw = wire(); FakeAdb.timeout = False
        self.temp = tempfile.TemporaryDirectory(prefix="mta-host-v3-harness-")
        self.root = Path(self.temp.name); self.frozen = self.root / "frozen"
        (self.frozen / "runtime").mkdir(parents=True)
        (self.frozen / "runtime/mta_safety.py").write_text("# HOST fixture only\nAREA='/mnt/data/p011-toolbox'\n", encoding="utf-8")
        (self.frozen / "SOURCE.sha256").write_bytes(b"HOST fake manifest, not a candidate\n")
    def tearDown(self):self.temp.cleanup()
    def execute_fixture(self):
        with mock.patch.object(v3, "Adb", FakeAdb), mock.patch.object(v3, "verify_frozen", return_value="1234567890abcdef"):
            return v3.run_reviewed(self.frozen, "1234567890abcdef", self.root / "result")
    def test_independent_stable_runtime_pin_enums_and_main_v2_unchanged(self):
        raw = (BASE / v3.RUNTIME_DIRECTORY / "mta_send_wifi.py").read_bytes()
        v3._source_checks("mta_send_wifi.py", raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), v3.RUNTIME_SHA256)
        self.assertEqual(hashlib.sha256((BASE / "runtime/mta_send_wifi.py").read_bytes()).hexdigest(), v2.RUNTIME_SHA256)
        self.assertNotEqual(v3.RUNTIME_SHA256, v2.RUNTIME_SHA256)
    def test_actual_host_freeze_exact_five_and_old_v2_cannot_verify_as_v3(self):
        target = self.root / "actual-host-only-frozen"
        identity = v3.freeze(target)
        self.assertEqual(v3.verify_frozen(target, identity), identity)
        self.assertEqual({p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}, v3.EXPECTED_FILES)
        with self.assertRaises(ValueError):v2.verify_frozen(target)
        (target / "unexpected.txt").write_text("HOST extra", encoding="utf-8")
        with self.assertRaises(ValueError):v3.verify_frozen(target)
    def test_old_frozen_v2_rejected_without_adb(self):
        old = v3.ROOT / "logs/MtaP011-P2pV2Freeze-20261001-014415-4c7a06bc/private-candidate"
        with self.assertRaises(ValueError):v3.verify_frozen(old)
        self.assertEqual(FakeAdb.calls, [])
    def test_runtime_changes_rejected_even_if_enum_still_matches(self):
        raw = (BASE / v3.RUNTIME_DIRECTORY / "mta_send_wifi.py").read_bytes()
        with self.assertRaises(ValueError):v3._source_checks("mta_send_wifi.py", raw + b"\n# HOST change\n")
    def test_readonly_sources_35_ast_and_no_lock_acquire(self):
        safety = (BASE / "runtime/mta_safety.py").read_text(encoding="utf-8")
        for body in (v3.PROBE, v3.PRIOR_JOURNALS, v3.JOURNAL):
            source = v3.probe_source("/mnt/data/p011-toolbox/candidates/mta-01-1234567890abcdef", safety, body,
                "RUN='/HOST/fixture'\nBINARY='/HOST/fixture'\nSTAGES=" + repr(tuple(v3.STAGES)))
            ast.parse(source, feature_version=(3, 5))
            for forbidden in ("DeviceGuard(", "JournalLock(", "LinuxBackend(", ".acquire(", "os.O_CREAT"):
                self.assertNotIn(forbidden, body)
    def test_success_uses_native_numeric_allowlist_and_early_zero(self):
        parsed = v3.parse_trial(wire())
        self.assertTrue(parsed["diagnostics_valid"]); self.assertTrue(parsed["early_init_success_reported"])
        self.assertNotIn("failure_phase", parsed)
    def test_failure_fixed_fields_preserved_without_nested_raw(self):
        result = v3.parse_trial(wire([failure()], 1))
        self.assertEqual({k: result[k] for k in ("failure_phase", "failure_errno", "netlink_command", "failure_reason")},
                         {"failure_phase": "interface_create", "failure_errno": 16, "netlink_command": "new_interface", "failure_reason": "os_error"})
        self.assertNotIn("HOST_SECRET", json.dumps(result))
    def test_constructor_failure_unknown_errno_is_zero_not_success(self):
        row = failure(failure_phase="backend_construct", failure_errno=0, netlink_command="not_recorded")
        row["diagnostics"]["events"] = []; FakeAdb.raw = wire([row], 1)
        FakeAdb.owned.update({"present": False, "complete": False})
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertEqual(result["failure_phase"], "backend_construct")
        self.assertEqual(result["failure_errno"], 0); self.assertFalse(result["early_init_success_reported"])
    def test_failure_enum_and_number_limits_reject_free_fields(self):
        changes = ({"failure_phase": "HOST_SECRET"}, {"failure_phase": ["interface_create"]},
                   {"failure_errno": True}, {"failure_errno": -1}, {"failure_errno": 4096},
                   {"failure_errno": "16"}, {"netlink_command": "HOST_SECRET"}, {"netlink_command": []},
                   {"reason": "HOST_SECRET"}, {"raw": "HOST_SECRET"})
        for value in changes:
            with self.subTest(value=value):
                with self.assertRaises((ValueError, TypeError)):v3.parse_trial(wire([failure(**value)], 1))
    def test_old_v2_failure_cannot_silently_use_v3_parser(self):
        row = failure(); row.pop("failure_phase")
        with self.assertRaises(ValueError):v3.parse_trial(wire([row], 1))
    def test_failure_never_passes_even_with_forged_zero_exit_and_baseline(self):
        FakeAdb.raw = wire([ready(), failure()], 0)
        result, _, _ = self.execute_fixture()
        self.assertTrue(result["trial_failed_event"]); self.assertFalse(result["pass"])
    def test_duplicate_terminals_reordered_ready_and_missing_terminal_rejected(self):
        for events in ([ready(), cleanup(), cleanup()], [cleanup(), ready()], [ready()], [failure(), failure()], [ready(), cleanup(), failure()]):
            with self.assertRaises(ValueError):v3.parse_trial(wire(events))
    def test_diagnostics_invalid_or_missing_early_blocks(self):
        for kind in ("invalid", "missing_early", "nonzero"):
            row = cleanup()
            if kind == "invalid":row["diagnostics"]["diagnostic_invalid"] = True
            elif kind == "missing_early":row["diagnostics"]["events"] = [x for x in row["diagnostics"]["events"] if x["stage"] != "early_param"]
            else:row["diagnostics"]["events"].append({"stage": "early_param", "code": 16})
            FakeAdb.raw = wire([ready(), row])
            with tempfile.TemporaryDirectory(dir=str(self.root)) as folder:
                with mock.patch.object(v3, "Adb", FakeAdb), mock.patch.object(v3, "verify_frozen", return_value="1234567890abcdef"):
                    result, _, _ = v3.run_reviewed(self.frozen, "1234567890abcdef", Path(folder) / "out")
            self.assertFalse(result["pass"])
    def test_native_diagnostic_limit_and_extra_fields_rejected(self):
        for diag in ({"stage": "HOST_SECRET", "code": 0}, {"stage": "init_enter", "code": 4096},
                     {"stage": "init_enter", "code": True}, {"stage": "init_enter", "code": 0, "raw": "HOST_SECRET"}):
            row = cleanup(); row["diagnostics"]["events"].append(diag)
            with self.assertRaises(ValueError):v3.parse_trial(wire([ready(), row]))
    def test_duplicate_exit_json_key_non_utf8_and_oversize_rejected(self):
        for blob in (wire() + b"MTA_REMOTE_EXIT=0\n", b'{"event":"private_go_ready","event":"private_go_ready"}\nMTA_REMOTE_EXIT=0\n', b"\xff\nMTA_REMOTE_EXIT=0\n", b" " * 32769):
            with self.assertRaises(ValueError):v3.parse_trial(blob)
    def test_current_project_sta_or_actor_blocks_before_owned_run(self):
        for key in ("no_project_mta_interfaces", "no_project_trial_actors"):
            FakeAdb.before = baseline(); FakeAdb.before[key] = False
            with tempfile.TemporaryDirectory(dir=str(self.root)) as folder:
                with mock.patch.object(v3, "Adb", FakeAdb), mock.patch.object(v3, "verify_frozen", return_value="1234567890abcdef"):
                    result, _, _ = v3.run_reviewed(self.frozen, "1234567890abcdef", Path(folder) / "out")
            self.assertFalse(result["rf_trial_invoked"])
            self.assertNotIn("new-owned-v3-run-directory", [v[0] for v in FakeAdb.calls])
    def test_unreconciled_prior_or_pending_blocks_before_owned_run(self):
        FakeAdb.prior["clear"] = False; FakeAdb.prior["global_pending_clear"] = False
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["rf_trial_invoked"])
        self.assertNotIn("new-owned-v3-run-directory", [v[0] for v in FakeAdb.calls])
    def test_timeout_has_one_dispatch_then_only_readonly_and_no_recover(self):
        FakeAdb.timeout = True; FakeAdb.owned["complete"] = False; FakeAdb.owned["recover_review_ready"] = True
        result, out, archive = self.execute_fixture()
        names = [v[0] for v in FakeAdb.calls]
        self.assertEqual(names.count("finite-owned-p2p-v3-trial"), 1)
        self.assertIn("after-independent-v3", names); self.assertIn("owned-journal-v3-readonly", names)
        self.assertFalse(result["pass"]); self.assertFalse(result["recovery_invoked"]); self.assertFalse(result["retry_invoked"])
        self.assertTrue((out / "private-next-steps.txt").exists())
        with zipfile.ZipFile(archive) as bundle:self.assertNotIn(b"HOST_SECRET", bundle.read("result.json"))
    def test_ipv6_or_baseline_process_identity_change_blocks(self):
        report = v3.parse_trial(wire()); report.update({"rf_trial_invoked": True, "preflight_passed": True, "prior_journals_clear": True})
        for key in ("stock", "network_processes", "interfaces", "boot_id", "route_digest", "ipv6_addresses_raw", "ipv6_routes_raw"):
            after = baseline(); after[key] = b"HOST changed" if key.endswith("raw") else "HOST changed"
            result = dict(report); v3.add_independent_gates(result, baseline(), after, journal())
            self.assertFalse(result["pass"])
    def test_pending_or_journal_readback_still_blocks(self):
        FakeAdb.after["pending"]["present"] = True; FakeAdb.owned["baseline_independent_match"] = False
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["global_pending_clear_independent"])
        self.assertFalse(result["journal_baseline_independent_match"])
    def test_public_zip_failure_only_fixed_diagnostics_no_raw(self):
        FakeAdb.raw = wire([failure()], 1)
        result, _, archive = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertTrue(result["trial_failed_event"])
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(bundle.namelist()), {"result.json", "README.txt"})
            self.assertNotIn(b"HOST_SECRET", bundle.read("result.json")); self.assertNotIn(b"HOST-only IPv6", bundle.read("result.json"))
    def test_success_branch_explicit_go_only_unchanged_ttl_v2_journal_namespace(self):
        result, _, archive = self.execute_fixture()
        self.assertTrue(result["pass"]); self.assertEqual(result["journal_version"], 2)
        self.assertFalse(result["dhcp_or_ip_configuration"]); self.assertEqual(result["phone_interop"], "NOT_TESTED")
        self.assertTrue(result["historical_v1_v2_unchanged"])
        names = [v[0] for v in FakeAdb.calls]
        self.assertLess(names.index("before-independent-v3"), names.index("new-owned-v3-run-directory"))
        command = next(v[1][1] for v in FakeAdb.calls if v[0] == "finite-owned-p2p-v3-trial")
        self.assertIn("--ttl 20", command); self.assertIn("/sessions/mta-p2p-v2-", command)
        self.assertNotIn("--recover", command)
        with zipfile.ZipFile(archive) as bundle:self.assertEqual(set(bundle.namelist()), {"result.json", "README.txt"})


if __name__ == "__main__":unittest.main()
