"""Linux HOST only: V2 lock ownership, no real interfaces/radios/DBus."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime'))
from mta_send_wifi import DeviceGuard, LeaseError, GoLease, PrivateDiagnostics, _only_link_local
from test_send_wifi_lease import MockBackend


class V2LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.journal = os.path.join(self.temp.name, 'lease.json'); self.backend = MockBackend()
        self.now = [100.0]; self.lease = GoLease(self.backend, self.journal, lambda: self.now[0])
    def tearDown(self): self.temp.cleanup()
    def start(self): self.lease.start(20, lambda path, deadline: None)
    def test_station_type_origin_owned_cleanup_with_original_baseline(self):
        self.start(); self.backend.rows[0]['iftype'] = 2
        report = self.lease.stop(); self.assertTrue(report['complete']); self.assertFalse(self.backend.pending)
    def test_station_type_refuses_changed_original_baseline(self):
        self.start(); self.backend.rows[0]['iftype'] = 2; self.backend.change_baseline = True
        self.assertFalse(self.lease.stop()['complete']); self.assertTrue(self.backend.rows); self.assertTrue(self.backend.pending)
    def test_station_type_refuses_active_or_data_ip_fixture(self):
        self.start(); self.backend.rows[0]['iftype'] = 2; self.backend.station_safe = False
        self.assertFalse(self.lease.stop()['complete']); self.assertTrue(self.backend.rows)
    def test_station_type_refuses_changed_wdev(self):
        self.start(); self.backend.rows[0]['iftype'] = 2; self.backend.rows[0]['wdev'] += 1
        self.assertFalse(self.lease.stop()['complete']); self.assertTrue(self.backend.rows)
    def test_reconciled_rechecks_current_baseline_and_reopens_pending(self):
        self.start(); self.assertTrue(self.lease.stop()['complete'])
        self.backend.change_baseline = True
        self.assertFalse(self.lease.stop()['complete']); self.assertTrue(self.backend.pending)
        self.assertEqual(json.loads(Path(self.journal).read_text())['stage'], 'recovery_required')
    def test_reconciled_does_not_delete_reused_interface_name(self):
        self.start(); owned = copy.deepcopy(self.backend.rows[0]); self.lease.stop()
        owned['wdev'] += 1; self.backend.rows.append(owned)
        before = list(self.backend.calls); self.assertFalse(self.lease.stop()['complete'])
        self.assertEqual(before, self.backend.calls); self.assertTrue(self.backend.rows)
    def test_watchdog_expiry_before_create_never_mutates_rf(self):
        def watchdog(path, end): self.now[0] = end
        with self.assertRaises(LeaseError): self.lease.start(20, watchdog)
        self.assertNotIn('create', self.backend.calls); self.assertFalse(self.backend.pending)
    def test_watchdog_reconciles_before_create_never_mutates_rf(self):
        def watchdog(path, end): self.assertTrue(self.lease.stop()['complete'])
        with self.assertRaises(LeaseError): self.lease.start(20, watchdog)
        self.assertNotIn('create', self.backend.calls)
    def test_watchdog_setup_error_does_not_leave_fake_admission(self):
        def watchdog(path, end): raise LeaseError('watchdog_not_started')
        with self.assertRaises(LeaseError): self.lease.start(20, watchdog)
        self.assertFalse(self.backend.pending); self.assertNotIn('create', self.backend.calls)
    def test_pending_previous_run_blocks_random_new_name(self):
        self.backend.pending = True
        with self.assertRaises(LeaseError): self.start()
        self.assertEqual(self.backend.calls, []); self.assertFalse(os.path.exists(self.journal))
    def test_recovery_requires_full_ipv6_original_baseline(self):
        self.start(); state = json.loads(Path(self.journal).read_text()); del state['baseline']['ipv6_route_digest']
        Path(self.journal).write_text(json.dumps(state))
        with self.assertRaises(LeaseError): GoLease(self.backend, self.journal).recover()
    def test_only_linklocal_ipv6_is_allowed_for_owned_cleanup(self):
        local = {'family': 6, 'prefix': 64, 'scope': 253, 'address': b'\xfe\x80' + b'\0' * 14}
        self.assertTrue(_only_link_local([])); self.assertTrue(_only_link_local([local]))
        for key, value in (('family', 4), ('scope', 0), ('prefix', 128), ('address', b'\x20\x01' + b'\0' * 14)):
            changed = dict(local); changed[key] = value
            self.assertFalse(_only_link_local([changed]))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.lock = os.path.join(self.temp.name, 'device.lock'); self.pending = os.path.join(self.temp.name, 'device.pending')
        self.guard = DeviceGuard(self.lock, self.pending); self.guard.acquire()
    def tearDown(self): self.guard.close(); self.temp.cleanup()
    def test_another_open_description_is_blocked(self):
        second = DeviceGuard(self.lock, self.pending)
        try:
            with self.assertRaises(LeaseError): second.acquire()
        finally: second.close()
    def test_pending_exact_identity_only_recovery(self):
        journal = os.path.join(self.temp.name, 'one.json')
        self.guard.prepare(journal, 'boot')
        with self.assertRaises(LeaseError): self.guard.prepare(journal, 'boot')
        with self.assertRaises(LeaseError): self.guard.prepare(journal + 'other', 'boot', True)
        with self.assertRaises(LeaseError): self.guard.prepare(journal, 'otherboot', True)
        self.guard.prepare(journal, 'boot', True); self.guard.clear(journal, 'boot')
        self.assertFalse(os.path.exists(self.pending))
    def test_pending_mismatch_cannot_be_cleared(self):
        journal = os.path.join(self.temp.name, 'one.json'); self.guard.prepare(journal, 'boot')
        with self.assertRaises(LeaseError): self.guard.clear(journal + 'other', 'boot')
        self.assertTrue(os.path.exists(self.pending))
    def test_symlink_or_partial_pending_refuses(self):
        target = os.path.join(self.temp.name, 'target'); Path(target).write_text('{}')
        os.symlink(target, self.pending)
        with self.assertRaises((LeaseError, OSError)): self.guard.prepare('one', 'boot', True)
        os.unlink(self.pending); Path(self.pending).write_text('{'); os.chmod(self.pending, 0o600)
        with self.assertRaises((LeaseError, ValueError)): self.guard.prepare('one', 'boot', True)
    def test_fork_retains_same_lock_after_parent_closes_reference(self):
        ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_r); os.close(release_w); os.write(ready_w, b'1')
            os.read(release_r, 1); self.guard.close(); os._exit(0)
        os.close(ready_w); os.close(release_r)
        second = DeviceGuard(self.lock, self.pending)
        try:
            self.assertEqual(os.read(ready_r, 1), b'1'); self.guard.close()
            with self.assertRaises(LeaseError): second.acquire()
        finally:
            os.write(release_w, b'1'); os.close(release_w); os.close(ready_r); os.waitpid(pid, 0)
        try: second.acquire()
        finally: second.close()


class DiagnosticTests(unittest.TestCase):
    def test_unterminated_numeric_frame_reports_invalid_without_exporting_tail(self):
        diag = PrivateDiagnostics(); diag.feed(b'MTA_P2P_DIAG stage=4 code=0')
        report = diag.report()
        self.assertTrue(report['diagnostic_invalid']); self.assertEqual(report['events'], [])
        self.assertTrue(report['raw_diagnostics_not_logged'])
        self.assertNotIn('MTA_P2P_DIAG', json.dumps(report))
        self.assertFalse(diag.invalid)  # Incomplete is transient, not a rejected frame.
    def test_partial_report_recovers_after_same_frame_is_completed(self):
        diag = PrivateDiagnostics(); diag.feed(b'MTA_P2P_DIAG stage=16 co')
        self.assertTrue(diag.report()['diagnostic_invalid']); self.assertEqual(diag.events, [])
        diag.feed(b'de=0\n')
        report = diag.report()
        self.assertFalse(report['diagnostic_invalid'])
        self.assertEqual(report['events'], [{'stage': 'p2p_init', 'code': 0}])
        self.assertFalse(diag.invalid); self.assertEqual(diag.buffer, b'')
    def test_complete_prefix_with_private_unterminated_tail_stays_fail_closed(self):
        diag = PrivateDiagnostics()
        diag.feed(b'MTA_P2P_DIAG stage=4 code=0\nprivate-secret-without-newline')
        report = diag.report()
        self.assertTrue(report['diagnostic_invalid'])
        self.assertEqual(report['events'], [{'stage': 'initial_type_gate', 'code': 0}])
        self.assertNotIn('private-secret', json.dumps(report))
        diag.feed(b'\n')
        self.assertTrue(diag.report()['diagnostic_invalid']); self.assertTrue(diag.invalid)
    def test_pipe_eof_with_partial_tail_does_not_become_valid(self):
        readfd, writefd = os.pipe(); diag = PrivateDiagnostics(); diag.attach(readfd)
        try:
            os.write(writefd, b'MTA_P2P_DIAG stage=6 code='); os.close(writefd); writefd = None
            report = diag.report()
            self.assertTrue(report['diagnostic_invalid']); self.assertEqual(report['events'], [])
            self.assertTrue(diag.report()['diagnostic_invalid'])
        finally:
            diag.close()
            if writefd is not None: os.close(writefd)
    def test_incremental_allowlisted_numeric_only(self):
        diag = PrivateDiagnostics(); diag.feed(b'MTA_P2P_DIAG stage=4 co'); diag.feed(b'de=0\nMTA_P2P_DIAG stage=6 code=-16\n')
        self.assertEqual(diag.report()['events'], [{'stage': 'initial_type_gate', 'code': 0}, {'stage': 'interface_up', 'code': -16}])
        self.assertFalse(diag.invalid)
    def test_raw_keys_names_and_unknown_fields_never_exported(self):
        diag = PrivateDiagnostics()
        for blob in (b'PSK=private-secret\n', b'MTA_P2P_DIAG stage=4 code=0 ssid=private-name\n',
                     b'MTA_P2P_DIAG stage=31 code=0\n', b'MTA_P2P_DIAG stage=6 code=-9999\n'):
            diag.feed(blob)
        text = json.dumps(diag.report())
        self.assertNotIn('private-secret', text); self.assertNotIn('private-name', text)
        self.assertTrue(diag.invalid); self.assertEqual(diag.events, [])
    def test_stream_and_event_limits(self):
        diag = PrivateDiagnostics(); diag.feed(b'x' * 4097)
        self.assertTrue(diag.invalid); self.assertEqual(diag.buffer, b'')
        diag = PrivateDiagnostics(); diag.feed(b'MTA_P2P_DIAG stage=4 code=0\n' * 65)
        self.assertTrue(diag.invalid); self.assertEqual(len(diag.events), 64)
    def test_nonblocking_pipe_drains_safely(self):
        readfd, writefd = os.pipe(); diag = PrivateDiagnostics(); diag.attach(readfd)
        try:
            diag.drain(); os.write(writefd, b'MTA_P2P_DIAG stage=16 code=-1\n'); diag.drain()
            self.assertEqual(diag.events, [{'stage': 'p2p_init', 'code': -1}])
        finally: diag.close(); os.close(writefd)


if __name__ == '__main__': unittest.main()
