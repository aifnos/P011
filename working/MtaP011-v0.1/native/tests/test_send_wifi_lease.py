"""Pure host lifecycle QA: no Bluetooth/Wi-Fi/system-bus operations."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime'))
from mta_send_wifi import GoLease, LeaseError, P2P_CLIENT, P2P_GO, _attrs, _attr, _interface, _owned_match
import struct

class MockBackend:
    def __init__(self):
        self.boot_id = 'mock-boot'; self.binary = '/private/mock-wpa'; self.rows = []
        self.baseline = {'boot_id': self.boot_id, 'frequency': 2412,
                         'station': {'name': 'wlan0', 'phy': 0, 'wdev': 1, 'ifindex': 3, 'iftype': 2}}
        self.baseline['interfaces'] = [copy.deepcopy(self.baseline['station'])]
        for field in ('route_digest', 'ipv6_route_digest', 'ipv6_address_digest'):
            self.baseline[field] = '0' * 64
        self.process = None; self.calls = []; self.fail_group = False; self.lose_interface = False
        self.lose_pid = False; self.change_baseline = False; self.allowed = True; self.before_gate = None
        self.pending = False; self.station_safe = True
    def snapshot(self, exclude_owned=None):
        value = copy.deepcopy(self.baseline)
        if self.change_baseline: value['frequency'] = 2437
        value['interfaces'] += [copy.deepcopy(r) for r in self.rows if exclude_owned is None or
                               any(r.get(k) != exclude_owned.get(k) for k in ('name', 'phy', 'wdev', 'ifindex'))]
        return value
    def acquire_device_lock(self): pass
    def begin_lease(self, journal):
        if self.pending: raise LeaseError('mock_pending')
        self.pending = True
    def recover_lease(self, journal): self.pending = True
    def complete_lease(self, journal): self.pending = False
    def capabilities(self):
        return {'phys': [{'index': 0, 'iftypes': ['station', 'p2p_client', 'p2p_go'],
                         'combinations': [{'station_plus_go_same_channel': self.allowed}]}]}
    def interfaces(self): return copy.deepcopy(self.rows)
    def create(self, name, phy):
        self.calls.append('create'); row = {'name': name, 'phy': phy, 'wdev': 20, 'ifindex': 9, 'iftype': P2P_CLIENT}
        self.rows.append(row); return copy.deepcopy(row)
    def spawn_private(self, name, save_process):
        self.calls.append('spawn'); self.process = {'pid': 200, 'starttime': 800, 'exe': self.binary}
        save_process(self.process)
        if self.before_gate: self.before_gate()
    def group_add(self, name, frequency):
        self.calls.append('group_add')
        if self.fail_group: raise LeaseError('mock_group_failed')
        self.rows[0]['iftype'] = P2P_GO
        if self.lose_interface: self.rows[0]['wdev'] += 1
        return {'ssid': 'private-mock', 'passphrase': 'private-mock-secret', 'psk': None,
                'frequency': frequency, 'go_address': '00:00:00:00:00:00'}
    def stop_process(self, record):
        self.calls.append('stop_process')
        if self.lose_pid: return False
        self.process = None; return True
    def process_gone(self, record): return self.process is None
    def station_cleanup_ready(self, owned): return self.station_safe
    def remove(self, owned, allow_station=False):
        self.calls.append('remove')
        if self.rows:
            current = self.rows[0]
            if any(owned.get(k) != current.get(k) for k in ('name', 'phy', 'wdev', 'ifindex')): return False
            if current.get('iftype') not in ((2, P2P_CLIENT, P2P_GO) if allow_station else (P2P_CLIENT, P2P_GO)): return False
        self.rows = []; return True

class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.journal = os.path.join(self.temp.name, 'lease.json'); self.backend = MockBackend()
        self.now = [100.0]; self.watchdog_calls = []
        self.lease = GoLease(self.backend, self.journal, clock=lambda: self.now[0])
    def tearDown(self): self.temp.cleanup()
    def watchdog(self, path, end): self.watchdog_calls.append((path, end))
    def start(self): return self.lease.start(20, self.watchdog)
    def test_lifecycle_secret_free_journal(self):
        self.assertEqual(self.start()['event'], 'private_go_ready'); self.assertTrue(self.watchdog_calls)
        text = Path(self.journal).read_text()
        self.assertNotIn('private-mock-secret', text); self.assertNotIn('private-mock', text)
        self.assertEqual(self.backend.calls[:3], ['create', 'spawn', 'group_add'])
        self.now[0] = 120; self.assertTrue(self.lease.expired())
        self.assertTrue(self.lease.stop()['complete']); self.assertIsNone(self.lease.credentials)
    def test_requires_watchdog_before_write(self):
        with self.assertRaises(LeaseError): self.lease.start()
        self.assertEqual(self.backend.calls, [])
    def test_pid_durable_before_gate(self):
        self.backend.before_gate = lambda: self.assertEqual(json.loads(Path(self.journal).read_text())['process'], self.backend.process)
        self.start(); self.lease.stop()
    def test_failure_cleans_only_self(self):
        self.backend.fail_group = True
        with self.assertRaises(LeaseError): self.start()
        self.assertEqual(self.backend.rows, []); self.assertIsNone(self.backend.process)
        self.assertEqual(json.loads(Path(self.journal).read_text())['stage'], 'reconciled')
    def test_interface_reuse_refuses_delete(self):
        self.start(); self.backend.rows[0]['wdev'] += 1
        report = self.lease.stop(); self.assertFalse(report['complete']); self.assertFalse(report['owned_interface_removed'])
        self.assertEqual(len(self.backend.rows), 1)
    def test_pid_reuse_prevents_interface_deletion(self):
        self.start(); self.backend.lose_pid = True
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('remove', self.backend.calls)
    def test_baseline_change_is_not_restoration(self):
        self.start(); self.backend.change_baseline = True
        self.assertFalse(self.lease.stop()['complete']); self.assertFalse(self.backend.rows)
    def test_missing_concurrency_no_rf(self):
        self.backend.allowed = False
        with self.assertRaises(LeaseError): self.start()
        self.assertFalse(self.backend.calls)
    def test_external_p2p_no_rf(self):
        self.backend.rows.append({'iftype': P2P_CLIENT, 'name': 'external'})
        with self.assertRaises(LeaseError): self.start()
        self.assertFalse(self.backend.calls)
    def test_recovery_exact_identities(self):
        self.start(); recovered = GoLease(self.backend, self.journal, clock=lambda: self.now[0])
        self.assertTrue(recovered.recover()['complete'])
    def test_cleanup_is_idempotent_without_extra_mutation(self):
        self.start(); self.assertTrue(self.lease.stop()['complete'])
        before = list(self.backend.calls)
        self.assertTrue(self.lease.stop()['complete']); self.assertEqual(before, self.backend.calls)
    def test_new_boot_refuses_old_journal(self):
        self.start(); self.backend.boot_id = 'new-boot'
        with self.assertRaises(LeaseError): GoLease(self.backend, self.journal).recover()
    def test_existing_journal_not_overwritten(self):
        Path(self.journal).write_text('{}')
        with self.assertRaises(LeaseError): self.start()
        self.assertEqual(Path(self.journal).read_text(), '{}'); self.assertFalse(self.backend.calls)
    def test_ttl_bounds_and_type(self):
        for value in (0, 21, True, -1, 1.5):
            with self.assertRaises(LeaseError): self.lease.start(value, self.watchdog)
        self.assertFalse(self.backend.calls)
    def test_unknown_create_ownership_is_retained(self):
        def ambiguous(name, phy):
            self.backend.rows.append({'name': name, 'iftype': P2P_CLIENT})
            raise LeaseError('create_reply_ownership_not_proven')
        self.backend.create = ambiguous
        with self.assertRaises(LeaseError): self.start()
        self.assertEqual(json.loads(Path(self.journal).read_text())['stage'], 'recovery_required')
        self.assertNotIn('remove', self.backend.calls)
    def test_decoder_does_not_include_mac(self):
        blob = (_attr(1, struct.pack('I', 0)) + _attr(3, struct.pack('I', 9)) + _attr(4, b'mta12345678\0') +
                _attr(5, struct.pack('I', 8)) + _attr(153, struct.pack('Q', 20)) + _attr(6, b'\xaa' * 6))
        self.assertEqual(set(_interface(blob)), {'name', 'phy', 'ifindex', 'iftype', 'wdev'})
        with self.assertRaises(LeaseError): _attrs(blob[:-1])

if __name__ == '__main__': unittest.main()
