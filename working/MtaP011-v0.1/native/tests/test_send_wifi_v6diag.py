"""PC HOST-only V6 diagnostics: memory journal/kernel/sysfs, no ADB/RF/sockets."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owned_ip_lease import FakeBackend, FakeLock
import mta_ip_lease as ip

V5 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v5/runtime/mta_send_wifi.py'
V6 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v6diag/runtime/mta_send_wifi.py'
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
v5 = module(V5, 'v5_comparison_only')
v6 = module(V6, 'v6diag_host')


class MemoryFixture(object):
    """All mutation is fake; this fixture does not claim journal durability."""
    def __init__(self):
        self.backend = FakeBackend()
        self.now = [100.0]
        self.saved = None
        self.saves = 0
        self.read_error = None
        self.read_transform = None
        self.save_error = None
        self.lease = v6.GoLease(self.backend, os.path.join(str(ROOT), 'HOST_ONLY_NO_SUCH_JOURNAL'),
                                lambda: self.now[0])
        def save(locked=False):
            if self.save_error: raise self.save_error
            self.saves += 1
            self.saved = copy.deepcopy(self.lease.state)
        self.lease._save = save
        self.patch_lock = mock.patch.object(v6, 'JournalLock', FakeLock)
        def read(path):
            if self.read_error: raise self.read_error
            value = copy.deepcopy(self.saved)
            return self.read_transform(value) if self.read_transform else value
        self.patch_read = mock.patch.object(v6, '_read_private_json', side_effect=read)
    def enter(self):
        self.patch_lock.start(); self.patch_read.start()
        return self
    def close(self):
        self.patch_read.stop(); self.patch_lock.stop()
    def prepare(self):
        owned = {'name': 'mta1234abcd', 'ifindex': 9, 'wdev': 20, 'phy': 0, 'iftype': 8}
        self.backend.rows = [dict(owned, iftype=9)]
        self.backend.ip_transport.name = owned['name']
        self.backend.process = {'pid': 200, 'starttime': 800, 'exe': '/private/mock-wpa'}
        self.lease.state = {'version': 3, 'kind': 'go_ip_only',
            'identity': dict(v6.LEASE_IDENTITY), 'stage': 'go_ready', 'name': owned['name'],
            'baseline': copy.deepcopy(self.backend.baseline), 'deadline': 120.0,
            'owned': owned, 'process': copy.deepcopy(self.backend.process), 'ip': None}
        self.saved = copy.deepcopy(self.lease.state)
    def create(self):
        return self.lease._ip_sublease().create(120.0)
    def diagnostic(self):
        return self.lease.ip_creation_gate_info


class CreationRejectionTests(unittest.TestCase):
    def setUp(self):
        self.f = MemoryFixture().enter(); self.f.prepare()
    def tearDown(self): self.f.close()
    def reject(self, reason, gate=None):
        with self.assertRaises(Exception): self.f.create()
        report = self.f.diagnostic()
        self.assertEqual(report['reason'], reason)
        self.assertEqual(report['gate'], gate or reason)
        self.assertNotIn('newaddr', self.f.backend.calls)
        self.assertNotIn('deladdr', self.f.backend.calls)
        return report
    def test_expiry_short_circuits_before_fresh_journal_read(self):
        self.f.now[0] = 120.0
        self.f.patch_read.stop()
        with mock.patch.object(v6, '_read_private_json', side_effect=AssertionError('not visited')) as read:
            self.reject('expiry')
            read.assert_not_called()
        self.f.patch_read.start()
        self.assertEqual(self.f.saves, 0)
    def test_journal_identity_rejected_without_intent_or_address_write(self):
        self.f.read_transform = lambda row: dict(row, identity=dict(v5.LEASE_IDENTITY))
        self.reject('journal')
        self.assertIsNone(self.f.lease.state['ip']); self.assertEqual(self.f.saves, 0)
    def test_journal_cleanup_epoch_rejected_without_intent_or_address_write(self):
        self.f.read_transform = lambda row: dict(row, stage='cleanup_intent')
        self.reject('journal'); self.assertEqual(self.f.saves, 0)
    def test_journal_read_exception_symbolic_and_reraised(self):
        self.f.read_error = OSError('PRIVATE_IDENTIFIER_NEVER_EXPORT')
        report = self.reject('unexpected_gate_read', 'journal')
        self.assertEqual(report['observations'], {})
        self.assertNotIn('PRIVATE_IDENTIFIER', json.dumps(report))
    def test_process_mismatch_rejected_before_intent(self):
        self.f.backend.process['starttime'] += 1
        self.reject('process'); self.assertEqual(self.f.saves, 0)
    def test_process_query_exception_symbolic_and_reraised(self):
        self.f.backend.ip_process_gate = mock.Mock(side_effect=OSError('PRIVATE_PID_NEVER_EXPORT'))
        self.reject('unexpected_gate_read', 'process')
    def test_unknown_backend_identity_failure_remains_identity_not_carrier(self):
        self.f.backend.gate_ok = False
        report = self.reject('interface_identity')
        self.assertEqual(report['observations'], {})
    def test_backend_carrier_rejection_prevents_first_address_intent(self):
        self.f.backend.ip_creation_gate_info = v6.ip_creation_diagnostic(
            'interface_carrier', 'interface_carrier', {'carrier_read_valid': True, 'carrier_is_up': False})
        self.f.backend.ip_identity_gate = mock.Mock(return_value=False)
        report = self.reject('interface_carrier')
        self.assertEqual(report['observations']['carrier_is_up'], False)
        self.assertIsNone(self.f.lease.state['ip']); self.assertEqual(self.f.saves, 0)
    def test_late_backend_carrier_rejection_never_sends_newaddr(self):
        def changed():
            self.f.backend.ip_creation_gate_info = v6.ip_creation_diagnostic(
                'interface_carrier', 'interface_carrier', {'carrier_read_valid': True, 'carrier_is_up': False})
            self.f.backend.ip_identity_gate = mock.Mock(return_value=False)
        self.f.backend.ip_transport.before_send = changed
        self.reject('interface_carrier'); self.assertGreater(self.f.saves, 0)
    def test_original_network_fingerprint_change_rejected(self):
        self.f.backend.baseline['station_state_digest'] = 'e' * 64
        self.reject('original_baseline'); self.assertEqual(self.f.saves, 0)
    def test_original_snapshot_exception_is_read_failure(self):
        self.f.backend.snapshot = mock.Mock(side_effect=OSError('PRIVATE_SSID_NEVER_EXPORT'))
        self.reject('unexpected_gate_read', 'original_baseline')
    def test_ipv4_before_write_change_is_baseline_not_carrier(self):
        def changed(transport):
            if transport.snapshots >= 2:
                self.f.backend.ip_transport.current = ip.core.IpSnapshot(
                    (), transport.current.routes, transport.current.rules)
        self.f.backend.ip_transport.snapshot_fault = changed
        self.reject('original_baseline')
    def test_late_expiry_after_intent_never_sends_newaddr(self):
        self.f.backend.ip_transport.before_send = lambda: self.f.now.__setitem__(0, 120.0)
        self.reject('expiry'); self.assertGreater(self.f.saves, 0)
    def test_late_process_reuse_never_sends_newaddr(self):
        self.f.backend.ip_transport.before_send = lambda: self.f.backend.process.__setitem__('starttime', 999)
        self.reject('process'); self.assertGreater(self.f.saves, 0)
    def test_save_failure_is_journal_read_write_exception_not_carrier(self):
        self.f.save_error = OSError('PRIVATE_PATH_NEVER_EXPORT')
        self.reject('unexpected_gate_read', 'journal')
    def test_earliest_rejection_is_not_overwritten_by_later_cleanup(self):
        self.f.backend.process['starttime'] += 1
        self.reject('process')
        first = copy.deepcopy(self.f.diagnostic())
        self.f.lease._ip_creation_reject('expiry', 'expiry', {'carrier_is_up': False})
        self.assertEqual(self.f.diagnostic(), first)
    def test_full_start_failure_captures_first_gate_before_cleanup(self):
        self.f.lease.state = None; self.f.saved = None
        self.f.backend.rows = []; self.f.backend.process = None
        self.f.backend.gate_ok = False
        with self.assertRaises(ip.IpLeaseError):
            self.f.lease.start(20, lambda path, end: None)
        report = self.f.lease.failure_info['ip_creation_gate']
        self.assertEqual(report['reason'], 'interface_identity')
        self.assertEqual(self.f.lease.failure_info['failure_phase'], 'ip_create')
        self.assertNotIn('newaddr', self.f.backend.calls)
        self.assertIn('stop_process', self.f.backend.calls)
        self.assertIn('remove', self.f.backend.calls)
        self.assertNotIn('private-mock', json.dumps(report))
        self.f.lease._ip_creation_reject('expiry', 'expiry')
        self.assertEqual(self.f.lease.failure_info['ip_creation_gate'], report)
    def test_clearing_late_intent_does_not_erase_creation_expiry(self):
        self.f.backend.ip_transport.before_send = lambda: self.f.now.__setitem__(0, 120.0)
        self.reject('expiry')
        self.assertEqual(self.f.lease.state['ip']['stage'], 'create_intent')
        self.assertTrue(self.f.lease._ip_sublease().restore(125))
        self.assertIsNone(self.f.lease.state['ip'])
        self.assertEqual(self.f.diagnostic()['reason'], 'expiry')
        self.assertNotIn('newaddr', self.f.backend.calls)
    def test_restore_delegates_original_gate_without_creation_observation(self):
        instance = self.f.lease._ip_sublease()
        with mock.patch.object(ip.OwnedIpLease, '_gate', return_value=True) as original:
            self.assertTrue(instance._gate(150, False))
        original.assert_called_once_with(instance, 150, False)
        self.assertEqual(self.f.diagnostic(), v6.ip_creation_diagnostic())
    def test_creation_gate_clock_is_read_once_in_original_order(self):
        calls = []
        holder = ip.snapshot_data(self.f.backend.ip_transport.current)
        instance = v6.DiagnosticOwnedIpLease(self.f.backend.ip_transport,
            {'baseline': {'ipv4': holder}}, lambda: None,
            lambda creating: calls.append('fresh') or True,
            lambda *args: calls.append('rejected'),
            lambda: calls.append('clock') or 100.0)
        self.assertTrue(instance._gate(120, True))
        self.assertEqual(calls, ['clock', 'fresh'])
    def test_creation_gate_clock_exception_never_visits_fresh(self):
        fresh = mock.Mock(return_value=True)
        instance = v6.DiagnosticOwnedIpLease(None, {}, lambda: None, fresh,
            self.f.lease._ip_creation_reject, mock.Mock(side_effect=OSError('PRIVATE')))
        with self.assertRaises(OSError): instance._gate(120, True)
        fresh.assert_not_called()
        self.assertEqual(self.f.diagnostic()['reason'], 'unexpected_gate_read')
        self.assertEqual(self.f.diagnostic()['gate'], 'expiry')
    def test_successful_host_create_restore_remains_original_transaction(self):
        self.assertTrue(self.f.create())
        self.assertTrue(self.f.lease.state['ip']['receipt_fsynced'])
        self.assertEqual(self.f.diagnostic(), v6.ip_creation_diagnostic())
        self.assertTrue(self.f.lease._ip_sublease().restore(125))
        self.assertEqual(self.f.backend.calls, ['newaddr', 'deladdr'])
        self.assertEqual(self.f.lease.state['ip']['stage'], 'restored')


class InterfaceObservationTests(unittest.TestCase):
    def setUp(self):
        self.owned = {'name': 'mta1234abcd', 'ifindex': 9, 'wdev': 20, 'phy': 0, 'iftype': 8}
        self.row = dict(self.owned, iftype=9)
        self.backend = object.__new__(v6.LinuxBackend)
        self.backend.allow_rf = True; self.backend.guard = mock.Mock(fd=5)
        self.backend.nl = mock.Mock(); self.backend.nl.interfaces.return_value = [self.row]
        self.values = {'flags': '0x1003', 'carrier': '1', 'ifindex': '9'}
    def checked(self, creating=True, stock_ok=True, l3_ok=True, opened_error=None):
        def opened(path, *args):
            key = path.rsplit('/', 1)[1]
            if key == opened_error: raise OSError('PRIVATE_SYSFS_NEVER_EXPORT')
            return io.StringIO(self.values[key])
        with mock.patch('builtins.open', side_effect=opened) as files, \
             mock.patch.object(v6, '_digest', side_effect=lambda path: v6.STOCK_PINS[path] if stock_ok else 'bad'), \
             mock.patch.object(v6, '_address_dump', return_value=[]), \
             mock.patch.object(v6, '_owned_routes_safe', return_value=l3_ok):
            result = self.backend.ip_identity_gate(self.owned, creating)
        return result, files.call_count, getattr(self.backend, 'ip_creation_gate_info', None)
    def test_carrier_zero_rejected_with_only_actual_boolean_observations(self):
        self.values['carrier'] = '0'
        allowed, count, report = self.checked()
        self.assertFalse(allowed); self.assertEqual(count, 3)
        self.assertEqual(report['reason'], 'interface_carrier')
        self.assertEqual(report['observations'], {'go_identity_match': True, 'flags_read_valid': True,
            'flags_up': True, 'carrier_read_valid': True, 'carrier_is_up': False,
            'sysfs_identity_match': True})
    def test_carrier_unknown_value_does_not_report_false_up_fact(self):
        self.values['carrier'] = '2'
        allowed, unused_count, report = self.checked()
        self.assertFalse(allowed); self.assertFalse(report['observations']['carrier_read_valid'])
        self.assertNotIn('carrier_is_up', report['observations'])
    def test_flags_invalid_does_not_report_flags_up_false_fact(self):
        self.values['flags'] = 'not_hex'
        allowed, unused_count, report = self.checked()
        self.assertFalse(allowed); self.assertFalse(report['observations']['flags_read_valid'])
        self.assertNotIn('flags_up', report['observations'])
    def test_sysfs_identity_mismatch_stays_rejected(self):
        self.values['ifindex'] = '10'
        allowed, unused_count, report = self.checked()
        self.assertFalse(allowed); self.assertFalse(report['observations']['sysfs_identity_match'])
        self.assertEqual(report['reason'], 'interface_identity')
    def test_interface_mismatch_never_reads_carrier(self):
        self.backend.nl.interfaces.return_value = [dict(self.row, wdev=21)]
        allowed, count, report = self.checked()
        self.assertFalse(allowed); self.assertEqual(count, 0)
        self.assertEqual(report['reason'], 'interface_identity')
        self.assertEqual(report['observations'], {'go_identity_match': False})
    def test_followup_go_identity_mismatch_rejects_after_sysfs(self):
        self.backend.nl.interfaces.side_effect = [[self.row], [dict(self.row, wdev=21)]]
        allowed, count, report = self.checked()
        self.assertFalse(allowed); self.assertEqual(count, 3)
        self.assertEqual(report['reason'], 'interface_identity')
        self.assertFalse(report['observations']['go_identity_match'])
    def test_stock_digest_mismatch_never_reads_sysfs(self):
        allowed, count, report = self.checked(stock_ok=False)
        self.assertFalse(allowed); self.assertEqual(count, 0)
        self.assertEqual(report['reason'], 'original_baseline')
    def test_carrier_read_exception_does_not_fabricate_missing_booleans(self):
        allowed, count, report = self.checked(opened_error='carrier')
        self.assertFalse(allowed); self.assertEqual(count, 2)
        self.assertEqual(report['reason'], 'unexpected_gate_read')
        self.assertEqual(report['gate'], 'interface_carrier')
        self.assertEqual(report['observations'], {'go_identity_match': True})
    def test_l3_rejection_has_distinct_fixed_reason(self):
        allowed, count, report = self.checked(l3_ok=False)
        self.assertFalse(allowed); self.assertEqual(count, 3)
        self.assertEqual(report['reason'], 'interface_l3')
    def test_restore_still_does_not_read_carrier_or_update_creation_report(self):
        self.backend.ip_creation_gate_info = v6.ip_creation_diagnostic('process', 'process')
        first = copy.deepcopy(self.backend.ip_creation_gate_info)
        allowed, count, report = self.checked(False)
        self.assertTrue(allowed); self.assertEqual(count, 0); self.assertEqual(report, first)
    def test_guard_not_owned_reports_journal_and_does_not_query_interface(self):
        self.backend.guard.fd = None
        allowed, count, report = self.checked()
        self.assertFalse(allowed); self.assertEqual(count, 0)
        self.backend.nl.interfaces.assert_not_called()
        self.assertEqual(report['reason'], 'journal')
    def test_all_supported_sysfs_inputs_keep_exact_v5_acceptance(self):
        cases = [('0x1003', '1', '9'), ('0x1002', '1', '9'), ('0x1003', '0', '9'),
                 ('0x1003', '2', '9'), ('0x1003', '1', '10'), ('bad', '1', '9')]
        for flags, carrier, index in cases:
            with self.subTest(flags=flags, carrier=carrier, index=index):
                self.values = {'flags': flags, 'carrier': carrier, 'ifindex': index}
                actual = self.checked()[0]
                def opened(path, *args): return io.StringIO(self.values[path.rsplit('/', 1)[1]])
                with mock.patch('builtins.open', side_effect=opened), \
                     mock.patch.object(v6, '_digest', side_effect=lambda path: v6.STOCK_PINS[path]), \
                     mock.patch.object(v6, '_address_dump', return_value=[]), \
                     mock.patch.object(v6, '_owned_routes_safe', return_value=True):
                    original = self.backend._ip_identity_gate_original(self.owned, True)
                self.assertEqual(actual, original)


class SourceContractTests(unittest.TestCase):
    def test_diagnostics_reject_unknown_strings_keys_and_non_bool_observations(self):
        result = v6.ip_creation_diagnostic('PRIVATE_IDENTIFIER', 'PRIVATE_PATH',
            {'carrier_is_up': 1, 'flags_up': False, 'PRIVATE_MAC': True})
        self.assertEqual(result, {'reason': 'unexpected_gate_read', 'gate': 'not_recorded',
                                 'observations': {'flags_up': False}})
    def test_v5_and_helpers_unchanged_and_v6_new_marker(self):
        self.assertEqual(hashlib.sha256(V5.read_bytes()).hexdigest(),
            '96f808a9ef7cbaf011bb3254a23c01cbda6d7e09e016ad948c5dba89b671bd87')
        self.assertEqual(hashlib.sha256((ROOT / 'runtime/mta_ip_lease.py').read_bytes()).hexdigest(),
            v5.IP_HELPER_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / 'runtime/mta_ip.py').read_bytes()).hexdigest(),
            v5.IP_CODEC_SHA256)
        self.assertEqual(v6.DIAGNOSTIC_RUNTIME_MARKER, 'p011-go-ip-only-v6diag-1')
        self.assertNotEqual(v5.LEASE_IDENTITY, v6.LEASE_IDENTITY)
    def test_v5_journal_identity_is_not_accepted_by_diagnostic_recovery(self):
        f = MemoryFixture().enter()
        try:
            f.prepare(); state = copy.deepcopy(f.lease.state)
            state['identity'] = dict(v5.LEASE_IDENTITY)
            with self.assertRaises(v6.LeaseError): v6._journal_envelope(state)
        finally: f.close()
    def test_python35_syntax_and_no_assert_side_effects(self):
        tree = ast.parse(V6.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
    def test_original_restore_and_cleanup_source_logic_preserved(self):
        old = ast.parse(V5.read_text(encoding='utf-8'))
        new = ast.parse(V6.read_text(encoding='utf-8'))
        def found(tree, cls, func):
            node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == cls)
            return copy.deepcopy(next(node for node in node.body if isinstance(node, ast.FunctionDef) and node.name == func))
        for cls, original, diagnostic in (
                ('LinuxBackend', 'ip_identity_gate', '_ip_identity_gate_original'),
                ('GoLease', '_ip_gate', '_ip_gate_original'),
                ('GoLease', '_stop_locked', '_stop_locked'),
                ('GoLease', 'recover', 'recover')):
            a = found(old, cls, original); b = found(new, cls, diagnostic)
            b.name = a.name
            self.assertEqual(ast.dump(a), ast.dump(b))


if __name__ == '__main__': unittest.main()
