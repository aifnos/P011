# -*- coding: utf-8 -*-
"""HOST-only V2 harness guards. FakeAdb never invokes ADB or RF."""
import ast
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "host"))
import device_p2p_v2 as v2


def trial_bytes(stages=None):
    stages = sorted(v2.INIT_REQUIRED) if stages is None else stages
    diagnostics = {"events": [{"stage": k, "code": 0} for k in stages],
                   "diagnostic_invalid": False, "raw_diagnostics_not_logged": True}
    events = [{"event": "private_go_ready", "ttl": 20, "credentials_not_logged": True},
              {"event": "private_go_cleanup", "owned_process_removed": True,
               "owned_interface_removed": True, "stock_baseline_equal": True,
               "complete": True, "diagnostics": diagnostics}]
    return ("\n".join(json.dumps(row) for row in events) + "\nMTA_REMOTE_EXIT=0\n").encode("utf-8")


def baseline():
    row = {k: True for k in ("target_ok", "stock_valid", "query_ok", "no_private_wpa_processes",
                             "no_project_trial_actors", "no_p2p_interfaces", "no_project_mta_interfaces", "station_identity_ok")}
    row.update({"wifi": {"completed": True, "same_channel_2ghz": True, "fingerprint": "HOST-stable"},
                "pending": {"present": False, "safe": True, "valid": True, "lock_safe": True},
                "stock": {"HOST_fixture": True}, "route_digest": "HOST-route",
                "ipv6_address_digest": "HOST-v6-address", "ipv6_route_digest": "HOST-v6-route",
                "ipv6_addresses_raw": b"HOST-only IPv6 addresses", "ipv6_routes_raw": b"HOST-only IPv6 routes",
                "network_processes": [{"HOST_fixture": True}], "interfaces": [{"HOST_fixture": True}], "boot_id": "HOST-boot"})
    return row


def journal():
    row = {k: True for k in ("present", "safe", "ownership_verified", "complete", "owned_process_gone",
                             "owned_interface_gone", "version2", "ipv6_baseline_present", "pending_clear", "baseline_independent_match")}
    row.update({"identity_mismatch": False, "recover_review_ready": False, "stage": "reconciled"})
    return row


class FakeAdb(object):
    calls = []
    before = baseline()
    after = baseline()
    owned = journal()
    prior = {"clear": True, "global_pending_clear": True}
    raw = trial_bytes()
    timeout = False
    def __init__(self, directory):
        self.directory = directory
        self.calls.append(("constructor", None))
    def python(self, label, source, timeout=45):
        self.calls.append((label, source))
        if label == "initial-stock":return True
        if label == "candidate-directory":return True
        if label == "verify-pinned-v2-candidate":return True
        if label == "prior-journals-v2-readonly":return copy.deepcopy(self.prior)
        if label == "before-independent-v2":return copy.deepcopy(self.before)
        if label == "new-owned-v2-run-directory":return True
        if label == "after-independent-v2":return copy.deepcopy(self.after)
        if label == "owned-journal-v2-readonly":return copy.deepcopy(self.owned)
        raise AssertionError("Unexpected FakeAdb probe")
    def run(self, label, arguments, timeout=30):
        self.calls.append((label, arguments))
        if label != "finite-owned-p2p-v2-trial":raise AssertionError("Unexpected FakeAdb mutation")
        if self.timeout:raise RuntimeError("HOST_SECRET_TIMEOUT_DETAILS")
        return self.raw


class V2HarnessTests(unittest.TestCase):
    def setUp(self):
        FakeAdb.calls = []; FakeAdb.before = baseline(); FakeAdb.after = baseline()
        FakeAdb.owned = journal(); FakeAdb.prior = {"clear": True, "global_pending_clear": True}
        FakeAdb.raw = trial_bytes(); FakeAdb.timeout = False
        self.temp = tempfile.TemporaryDirectory(prefix="mta-host-v2-harness-")
        self.root = Path(self.temp.name); self.frozen = self.root / "frozen"
        (self.frozen / "runtime").mkdir(parents=True)
        (self.frozen / "runtime/mta_safety.py").write_text("# HOST fixture only\nAREA='/mnt/data/p011-toolbox'\n", encoding="utf-8")
        (self.frozen / "SOURCE.sha256").write_bytes(b"HOST fixture manifest, not a candidate\n")
    def tearDown(self):
        self.temp.cleanup()
    def execute_fixture(self):
        with mock.patch.object(v2, "Adb", FakeAdb), mock.patch.object(v2, "verify_frozen", return_value="1234567890abcdef"):
            return v2.run_reviewed(self.frozen, "1234567890abcdef", self.root / "result")
    def test_parse_numeric_allowlist_and_early_init_zero(self):
        result = v2.parse_trial(trial_bytes())
        self.assertTrue(result["diagnostics_valid"])
        self.assertTrue(result["early_init_success_reported"])
        self.assertEqual({v["stage"] for v in result["diagnostic_events"]}, v2.INIT_REQUIRED)
    def test_parse_rejects_non_allowlisted_diagnostic_shapes(self):
        for row in ({"stage": "HOST_SECRET_STAGE", "code": 0}, {"stage": "init_enter", "code": 4096},
                    {"stage": "init_enter", "code": True}, {"stage": "init_enter", "code": 0, "raw": "HOST_SECRET"}):
            events = [json.loads(line) for line in trial_bytes().decode().splitlines() if line.startswith("{")]
            events[-1]["diagnostics"]["events"].append(row)
            raw = ("\n".join(json.dumps(v) for v in events) + "\nMTA_REMOTE_EXIT=0\n").encode()
            with self.assertRaises(ValueError):v2.parse_trial(raw)
    def test_parse_duplicate_exit_duplicate_key_and_non_utf8_rejected(self):
        for raw in (trial_bytes() + b"MTA_REMOTE_EXIT=0\n", b'{"event":"private_go_ready","event":"private_go_ready"}\nMTA_REMOTE_EXIT=0\n', b"\xff\nMTA_REMOTE_EXIT=0\n"):
            with self.assertRaises(ValueError):v2.parse_trial(raw)
    def test_early_param_missing_never_passes_even_if_ready_cleanup_reported(self):
        FakeAdb.raw = trial_bytes(sorted(v2.INIT_REQUIRED - {"early_param"}))
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["early_init_success_reported"])
    def test_diagnostic_invalid_flag_never_passes(self):
        FakeAdb.raw = trial_bytes().replace(b'"diagnostic_invalid": false', b'"diagnostic_invalid": true')
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["diagnostics_valid"])
    def test_readonly_source_syntax_and_no_lock_acquisition(self):
        safety = (BASE / "runtime/mta_safety.py").read_text(encoding="utf-8")
        for body in (v2.PROBE, v2.PRIOR_JOURNALS, v2.JOURNAL):
            source = v2.probe_source("/mnt/data/p011-toolbox/candidates/mta-01-1234567890abcdef", safety, body,
                                     "RUN='/HOST/fixture'\nBINARY='/HOST/fixture'\nSTAGES=" + repr(tuple(v2.STAGES)))
            ast.parse(source, feature_version=(3, 5))
            for forbidden in ("DeviceGuard(", "JournalLock(", "LinuxBackend(", ".acquire(", "os.O_CREAT"):
                self.assertNotIn(forbidden, body)
    def test_existing_v1_frozen_candidate_is_not_v2(self):
        old = v2.ROOT / "logs/MtaP011-P2pFreeze-20260930-204808-5a08fe44/private-candidate"
        with self.assertRaises(ValueError):v2.verify_frozen(old)
    def test_project_interface_demoted_sta_blocks_before_run_or_rf(self):
        FakeAdb.before["no_project_mta_interfaces"] = False
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["rf_trial_invoked"])
        names = [r[0] for r in FakeAdb.calls]
        self.assertNotIn("new-owned-v2-run-directory", names); self.assertNotIn("finite-owned-p2p-v2-trial", names)
    def test_global_pending_or_prior_journal_blocks_new_run(self):
        FakeAdb.prior = {"clear": False, "global_pending_clear": False}
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["rf_trial_invoked"])
        self.assertNotIn("new-owned-v2-run-directory", [r[0] for r in FakeAdb.calls])
    def test_project_trial_actor_blocks_before_run(self):
        FakeAdb.before["no_project_trial_actors"] = False
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["rf_trial_invoked"])
    def test_timeout_only_reads_owned_journal_and_never_retries_or_recovers(self):
        FakeAdb.timeout = True; FakeAdb.owned["complete"] = False; FakeAdb.owned["recover_review_ready"] = True
        result, out, archive = self.execute_fixture()
        names = [r[0] for r in FakeAdb.calls]
        self.assertEqual(names.count("finite-owned-p2p-v2-trial"), 1)
        self.assertIn("after-independent-v2", names); self.assertIn("owned-journal-v2-readonly", names)
        self.assertFalse(result["pass"]); self.assertFalse(result["recovery_invoked"]); self.assertFalse(result["retry_invoked"])
        self.assertTrue((out / "private-next-steps.txt").is_file())
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(bundle.namelist()), {"result.json", "README.txt"})
            self.assertNotIn(b"HOST_SECRET_TIMEOUT_DETAILS", bundle.read("result.json"))
    def test_independent_ipv6_change_blocks_pass(self):
        FakeAdb.after["ipv6_addresses_raw"] = b"HOST changed"
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["full_ipv6_readback_unchanged"])
    def test_pending_marker_after_blocks_even_when_journal_claims_complete(self):
        FakeAdb.after["pending"]["present"] = True
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["global_pending_clear_independent"])
    def test_journal_saved_baseline_must_match_new_independent_readback(self):
        FakeAdb.owned["baseline_independent_match"] = False
        result, _, _ = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertFalse(result["journal_baseline_independent_match"])
    def test_process_or_interface_identity_change_blocks(self):
        report = v2.parse_trial(trial_bytes())
        report.update({"rf_trial_invoked": True, "preflight_passed": True, "prior_journals_clear": True})
        for field in ("stock", "network_processes", "interfaces", "boot_id"):
            before = baseline(); after = baseline(); after[field] = "HOST changed"
            result = dict(report); v2.add_independent_gates(result, before, after, journal())
            self.assertFalse(result["pass"])
    def test_mock_success_is_explicit_go_only_and_public_zip_bounded(self):
        result, _, archive = self.execute_fixture()
        self.assertTrue(result["pass"])
        self.assertFalse(result["dhcp_or_ip_configuration"]); self.assertEqual(result["phone_interop"], "NOT_TESTED")
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(bundle.namelist()), {"result.json", "README.txt"})
            self.assertNotIn(b"HOST-only IPv6", bundle.read("result.json"))
    def test_failure_reason_and_nested_raw_never_enter_public_result(self):
        events = [{"event": "private_go_trial_failed", "reason": "HOST_SECRET_ERROR_MESSAGE",
                   "cleanup": {"raw": "HOST_SECRET_RAW", "complete": False}, "complete": False,
                   "diagnostics": {"events": [], "diagnostic_invalid": False, "raw_diagnostics_not_logged": True}}]
        FakeAdb.raw = (json.dumps(events[0]) + "\nMTA_REMOTE_EXIT=1\n").encode()
        result, _, archive = self.execute_fixture()
        self.assertFalse(result["pass"]); self.assertTrue(result["trial_failed_event"])
        with zipfile.ZipFile(archive) as bundle:self.assertNotIn(b"HOST_SECRET", bundle.read("result.json"))


if __name__ == "__main__":
    unittest.main()
