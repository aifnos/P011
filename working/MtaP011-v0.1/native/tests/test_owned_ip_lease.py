"""HOST-only V5 IP/GO transaction fault injection. No ADB/RF/IP sockets."""
import ast
import copy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mta_ip as core
import mta_ip_lease as ip
from test_send_wifi_lease import MockBackend

V4 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v4/runtime/mta_send_wifi.py'
V5 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v5/runtime/mta_send_wifi.py'
spec = importlib.util.spec_from_file_location('owned_ip_v5_host', str(V5))
v5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v5)


def original():
    addr = core.AddressRecord(3, core.ipv4_number('10.20.30.40'), core.ipv4_number('10.20.30.40'),
        24, 128, 0, b'wlan0\0', core.ipv4_number('10.20.30.255'),
        (core.UINT_MAX, core.UINT_MAX, 20, 20))
    route = core.RouteRecord(0, 0, 254, 3, 0, 1, 0, 3,
        core.ipv4_number('10.20.30.1'), 10, core.ipv4_number('10.20.30.40'), ())
    return core.IpSnapshot((addr,), (route,),
        (core.RuleRecord(0, 255), core.RuleRecord(32766, 254), core.RuleRecord(32767, 253)))


class FakeRouteTransport(object):
    def __init__(self, calls):
        self.calls = calls; self.current = original(); self.sequence = 0; self.name = None
        self.create_fault = None; self.delete_fault = None; self.readback_fault = None
        self.before_send = None; self.snapshots = 0; self.snapshot_fault = None
    def stable_snapshot(self, deadline):
        self.snapshots += 1
        if self.snapshot_fault: self.snapshot_fault(self)
        return ip.require_permanent(self.current)
    def prepare_address(self, spec, create):
        self.sequence += 1
        return (core.encode_new_address if create else core.encode_del_address)(spec, self.sequence, 1234)
    def address_ack(self, request, deadline, gate):
        if self.before_send: self.before_send()
        if gate() is not True: raise ip.IpLeaseError('ip_write_not_authorized')
        kind = struct.unpack_from('<H', request, 4)[0]
        index = struct.unpack_from('<I', request, 20)[0]
        address = struct.unpack('>I', request[28:32])[0]
        spec = core.AddressSpec(index, core.ipv4_text(address), 24)
        if kind == core.RTM_NEWADDR:
            self.calls.append('newaddr')
            if self.create_fault == 'eexist': raise ip.IpLeaseError('ip_kernel_rejected', errno.EEXIST)
            row = core.AddressRecord(index, address, address, 24, 128, 0,
                self.name.encode('ascii') + b'\0', address | 255,
                (core.UINT_MAX, core.UINT_MAX, 99, 99))
            self.current = core.IpSnapshot(self.current.addresses + (row,),
                self.current.routes + ip._expected_routes(spec), self.current.rules)
            if self.readback_fault: self.readback_fault(self)
            if self.create_fault == 'lost': raise socket.timeout()
        else:
            self.calls.append('deladdr')
            if self.delete_fault == 'lost': raise socket.timeout()
            self.current = core.IpSnapshot(tuple(r for r in self.current.addresses if r.ifindex != index),
                tuple(r for r in self.current.routes if r not in ip._expected_routes(spec)), self.current.rules)
            if self.delete_fault == 'route_left':
                self.current = core.IpSnapshot(self.current.addresses,
                    self.current.routes + (ip._expected_routes(spec)[0],), self.current.rules)
        return core.AckResult(0, kind)


class FakeBackend(MockBackend):
    def __init__(self):
        MockBackend.__init__(self)
        self.ip_transport = FakeRouteTransport(self.calls); self.ip_deadline = None
        self.baseline['ipv4'] = ip.snapshot_data(self.ip_transport.current)
        self.baseline['station_state_digest'] = 'f' * 64
        self.baseline['processes'] = []
        self.gate_ok = True
    def snapshot(self, exclude_owned=None, exclude_ip=None):
        value = MockBackend.snapshot(self, exclude_owned)
        current = self.ip_transport.stable_snapshot(1000)
        if exclude_ip is not None: current = ip.without_owned(current, exclude_ip, exclude_owned)
        value['ipv4'] = ip.snapshot_data(current)
        return value
    def create(self, name, phy):
        self.ip_transport.name = name
        return MockBackend.create(self, name, phy)
    def ip_identity_gate(self, owned, creating):
        return bool(self.gate_ok and len(self.rows) == 1 and
            all(self.rows[0].get(k) == owned[k] for k in ('name', 'ifindex', 'wdev', 'phy')) and
            self.rows[0]['iftype'] in ((9,) if creating else (2, 8, 9)))
    def ip_process_gate(self, record, creating):
        return self.process == record if creating else self.process is None or self.process == record


class FakeLock(object):
    def __init__(self, path): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


@unittest.skipUnless(os.name == 'posix', 'Linux HOST private journal/uid/fsync fixture')
class LeaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.journal = os.path.join(self.temp.name, 'lease.json'); self.now = [100.0]
        self.backend = FakeBackend(); self.lease = v5.GoLease(self.backend, self.journal, lambda: self.now[0])
        self.lock_patch = mock.patch.object(v5, 'JournalLock', FakeLock); self.lock_patch.start()
    def tearDown(self):
        self.lock_patch.stop(); self.temp.cleanup()
    def start(self): return self.lease.start(20, lambda path, end: None)
    def load(self): return json.loads(Path(self.journal).read_text())
    def test_happy_path_exact_restore_precedes_wpa_and_netdev(self):
        ready = self.start()
        self.assertTrue(ready['ip_ready']); self.assertFalse(ready['send_available'])
        state = self.load(); self.assertEqual(state['version'], 3)
        self.assertEqual(state['identity'], v5.LEASE_IDENTITY)
        self.assertTrue(state['ip']['receipt_fsynced'])
        result = self.lease.stop(); self.assertTrue(result['complete']); self.assertTrue(result['ip_restored'])
        self.assertLess(self.backend.calls.index('deladdr'), self.backend.calls.index('stop_process'))
        self.assertLess(self.backend.calls.index('stop_process'), self.backend.calls.index('remove'))
        self.assertFalse(self.backend.pending); self.assertEqual(self.load()['ip']['stage'], 'restored')
    def test_cancel_epoch_before_newaddr_prevents_address_write(self):
        self.backend.ip_transport.before_send = lambda: self.now.__setitem__(0, 121.0)
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('newaddr', self.backend.calls); self.assertFalse(self.backend.pending)
    def test_eexist_is_not_address_ownership(self):
        self.backend.ip_transport.create_fault = 'eexist'
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertFalse(self.backend.pending)
    def test_create_ack_lost_stops_owned_process_but_never_deletes_netdev(self):
        self.backend.ip_transport.create_fault = 'lost'
        with self.assertRaises(socket.timeout): self.start()
        self.assertIn('stop_process', self.backend.calls)
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending); self.assertEqual(self.load()['stage'], 'recovery_required')
        self.assertEqual(self.load()['ip']['stage'], 'create_intent')
    def test_first_receipt_save_fault_is_not_confirmed(self):
        real = self.lease._save
        def save(locked=False):
            if self.lease.state and (self.lease.state.get('ip') or {}).get('stage') == 'receipt_recorded':
                raise OSError(errno.EIO, 'HOST_FAULT')
            return real(locked)
        self.lease._save = save
        with self.assertRaises(OSError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending)
        # The journal remains persistently unwritable in this fixture; no claim
        # that stop_process happened immediately or that watchdog was executed.
    def test_once_receipt_save_failure_stops_wpa_but_retains_unknown_address(self):
        real = self.lease._save; faulted = [False]
        def save(locked=False):
            if not faulted[0] and self.lease.state and (self.lease.state.get('ip') or {}).get('stage') == 'receipt_recorded':
                faulted[0] = True; raise OSError(errno.EIO, 'HOST_ONCE')
            return real(locked)
        self.lease._save = save
        with self.assertRaises(OSError): self.start()
        self.assertIn('stop_process', self.backend.calls)
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending)
    def test_readback_unknown_address_prevents_netdev_delete(self):
        def unknown(transport):
            old = transport.current; row = old.addresses[-1]._replace(local=core.ipv4_number('192.168.99.7'))
            transport.current = core.IpSnapshot(old.addresses[:-1] + (row,), old.routes, old.rules)
        self.backend.ip_transport.readback_fault = unknown
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
    def test_route_delta_is_not_owned_just_because_same_oif(self):
        def unknown(transport):
            old = transport.current
            transport.current = core.IpSnapshot(old.addresses, old.routes + (old.routes[-1]._replace(table=999),), old.rules)
        self.backend.ip_transport.readback_fault = unknown
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
    def test_unsupported_route_flags_leave_intent_unknown(self):
        def flagged(transport):
            old = transport.current
            transport.current = core.IpSnapshot(old.addresses,
                old.routes[:-1] + (old.routes[-1]._replace(flags=0x10),), old.rules)
        self.backend.ip_transport.readback_fault = flagged
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending)
    def test_private_pid_reuse_before_create_prevents_write(self):
        def reused():
            self.backend.process = dict(self.backend.process, starttime=999); self.backend.lose_pid = True
        self.backend.ip_transport.before_send = reused
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('newaddr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
    def test_private_pid_reuse_before_delete_prevents_write(self):
        self.start(); self.backend.process = dict(self.backend.process, starttime=999); self.backend.lose_pid = True
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('deladdr', self.backend.calls)
        self.assertNotIn('remove', self.backend.calls); self.assertTrue(self.backend.pending)
    def test_original_same_frequency_new_fingerprint_prevents_create(self):
        self.backend.ip_transport.before_send = lambda: self.backend.baseline.__setitem__('station_state_digest', 'e' * 64)
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('newaddr', self.backend.calls)
    def test_original_tracked_process_replacement_prevents_create(self):
        self.backend.ip_transport.before_send = lambda: self.backend.baseline.__setitem__('processes',
            [{'pid': 333, 'starttime': 444, 'exe': '/usr/bin/Z03', 'cmdline_digest': 'c' * 64}])
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('newaddr', self.backend.calls)
    def test_confirmation_original_baseline_change_never_publishes_or_deletes(self):
        def changed(transport): self.backend.change_baseline = True
        self.backend.ip_transport.readback_fault = changed
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertNotIn('deladdr', self.backend.calls); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending)
    def test_confirmed_delete_ack_lost_retains_pending_and_interface(self):
        self.start(); self.backend.ip_transport.delete_fault = 'lost'
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending); self.assertEqual(self.load()['ip']['stage'], 'delete_intent')
    def test_left_automatic_route_prevents_false_restore(self):
        self.start(); self.backend.ip_transport.delete_fault = 'route_left'
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('remove', self.backend.calls)
        self.assertTrue(self.backend.pending)
    def test_foreign_policy_change_blocks_deletion(self):
        self.start(); old = self.backend.ip_transport.current
        self.backend.ip_transport.current = core.IpSnapshot(old.addresses, old.routes,
            old.rules + (core.RuleRecord(100, 100),))
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('deladdr', self.backend.calls)
        self.assertNotIn('remove', self.backend.calls)
    def test_changed_interface_tuple_blocks_deladdr_and_netdev(self):
        self.start(); self.backend.rows[0]['wdev'] += 1
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('deladdr', self.backend.calls)
        self.assertNotIn('remove', self.backend.calls)
    def test_parent_died_after_confirmed_receipt_uses_same_restore_order(self):
        self.start(); recovery = v5.GoLease(self.backend, self.journal, lambda: self.now[0])
        self.assertTrue(recovery.recover()['complete'])
        self.assertLess(self.backend.calls.index('deladdr'), self.backend.calls.index('stop_process'))
        self.assertLess(self.backend.calls.index('stop_process'), self.backend.calls.index('remove'))
    def test_parent_died_after_intent_with_address_keeps_netdev(self):
        self.start(); state = self.load(); state['ip'].pop('address'); state['ip'].pop('receipt_fsynced')
        state['ip']['stage'] = 'create_intent'; Path(self.journal).write_text(json.dumps(state))
        self.backend.calls.clear()
        recovery = v5.GoLease(self.backend, self.journal, lambda: self.now[0])
        self.assertFalse(recovery.recover()['complete'])
        self.assertIn('stop_process', self.backend.calls); self.assertNotIn('deladdr', self.backend.calls)
        self.assertNotIn('remove', self.backend.calls); self.assertTrue(self.backend.pending)
    def test_ttl_expiry_confirmed_address_still_restores(self):
        self.start(); self.now[0] = 121.0
        self.assertTrue(self.lease.expired()); self.assertTrue(self.lease.stop()['complete'])
        self.assertIn('deladdr', self.backend.calls)
    def test_second_stop_has_no_mutation_and_rechecks_complete_baseline(self):
        self.start(); self.assertTrue(self.lease.stop()['complete']); before = list(self.backend.calls)
        self.assertTrue(self.lease.stop()['complete']); self.assertEqual(self.backend.calls, before)
        self.backend.change_baseline = True
        self.assertFalse(self.lease.stop()['complete']); self.assertTrue(self.backend.pending)
    def test_cached_reconciled_unknown_ip_or_cleanup_fields_never_clear_pending(self):
        self.start(); self.assertTrue(self.lease.stop()['complete']); original_state = self.load()
        for location in ('ip', 'cleanup_result'):
            self.backend.pending = True; state = copy.deepcopy(original_state); state[location]['unknown'] = True
            Path(self.journal).write_text(json.dumps(state)); before = list(self.backend.calls)
            with self.assertRaises((v5.LeaseError, ip.IpLeaseError)): self.lease.stop()
            self.assertEqual(before, self.backend.calls); self.assertTrue(self.backend.pending)
    def test_old_v2_journal_is_rejected_before_mutation(self):
        self.start(); state = self.load(); state['version'] = 2
        Path(self.journal).write_text(json.dumps(state)); before = list(self.backend.calls)
        with self.assertRaises(v5.LeaseError): v5.GoLease(self.backend, self.journal).recover()
        self.assertEqual(before, self.backend.calls)
    def test_corrupt_codec_identity_is_rejected_before_mutation(self):
        self.start(); state = self.load(); state['identity']['codec_sha256'] = '0' * 64
        Path(self.journal).write_text(json.dumps(state)); before = list(self.backend.calls)
        with self.assertRaises(v5.LeaseError): v5.GoLease(self.backend, self.journal).recover()
        self.assertEqual(before, self.backend.calls)
    def test_unknown_root_baseline_or_ip_fields_rejected_before_mutation(self):
        self.start(); original_state = self.load(); before = list(self.backend.calls)
        for location in ('root', 'baseline', 'ip'):
            state = copy.deepcopy(original_state)
            (state if location == 'root' else state[location])['unknown'] = True
            Path(self.journal).write_text(json.dumps(state))
            with self.assertRaises((v5.LeaseError, ip.IpLeaseError)):
                v5.GoLease(self.backend, self.journal).recover()
            self.assertEqual(before, self.backend.calls)
    def test_false_or_empty_owned_and_process_are_not_none(self):
        self.start(); original_state = self.load(); before = list(self.backend.calls)
        for field in ('owned', 'process'):
            for value in (False, {}, [], 0):
                state = copy.deepcopy(original_state); state[field] = value
                Path(self.journal).write_text(json.dumps(state))
                with self.assertRaises(v5.LeaseError): v5.GoLease(self.backend, self.journal).recover()
                self.assertEqual(before, self.backend.calls)
    def test_broadcast_changed_immediately_before_deladdr_blocks_write(self):
        self.start()
        def changed():
            old = self.backend.ip_transport.current
            self.backend.ip_transport.current = core.IpSnapshot(old.addresses[:-1] +
                (old.addresses[-1]._replace(broadcast=core.ipv4_number('192.168.49.2')),), old.routes, old.rules)
        self.backend.ip_transport.before_send = changed
        self.assertFalse(self.lease.stop()['complete']); self.assertNotIn('deladdr', self.backend.calls)
        self.assertNotIn('remove', self.backend.calls); self.assertTrue(self.backend.pending)
    def test_initial_dynamic_lifetime_prevents_any_rf(self):
        old = self.backend.ip_transport.current
        self.backend.ip_transport.current = core.IpSnapshot((old.addresses[0]._replace(cacheinfo=(100, 100, 20, 20)),), old.routes, old.rules)
        with self.assertRaises(ip.IpLeaseError): self.start()
        self.assertFalse(self.backend.calls); self.assertFalse(self.backend.pending)
    def test_journal_write_bound_is_enforced_before_rf(self):
        self.backend.baseline['padding'] = 'x' * 65536
        with self.assertRaises(v5.LeaseError): self.start()
        self.assertFalse(self.backend.calls); self.assertFalse(os.path.exists(self.journal))
    def test_public_ready_and_cleanup_do_not_include_address_or_secret(self):
        ready = self.start(); result = self.lease.stop()
        text = json.dumps((ready, result))
        for token in ('192.168.', '10.20.', 'private-mock-secret', 'ssid', 'spec', 'address'):
            self.assertNotIn(token, text)


def packet(command, flags, seq, port, payload):
    return struct.pack('<IHHII', 16 + len(payload), command, flags, seq, port) + payload


class KernelSocket(object):
    def __init__(self): self.queue = []; self.closed = False; self.sent = []; self.sender = (0, 0)
    def set_inheritable(self, value): pass
    def bind(self, value): pass
    def getsockname(self): return (321, 0)
    def settimeout(self, value): pass
    def close(self): self.closed = True
    def sendto(self, request, peer):
        self.sent.append((request, peer)); size, command, flags, seq, port = struct.unpack('<IHHII', request[:16])
        if command == core.RTM_GETRULE:
            rows = []
            for priority, table in ((0, 255), (32766, 254), (32767, 253)):
                payload = struct.pack('<BBBBBBBBI', 2, 0, 0, 0, table, 0, 0, 1, 0)
                if priority: payload += core._attribute(6, struct.pack('<I', priority))
                rows.append(packet(core.RTM_NEWRULE, 2, seq, port, payload))
            self.queue.append(b''.join(rows))
        self.queue.append(packet(3, 2, seq, port, struct.pack('<i', 0)))
        return len(request)
    def recvfrom(self, maximum): return self.queue.pop(0), self.sender


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.family_patch = mock.patch.object(socket, 'AF_NETLINK', 16, create=True); self.family_patch.start()
    def tearDown(self): self.family_patch.stop()
    def test_single_socket_kernel_sender_and_distinct_six_sequences(self):
        sock = KernelSocket(); seen = []
        transport = ip.RouteTransport(lambda *args: seen.append(args) or sock, clock=lambda: 1.0)
        snapshot = transport.stable_snapshot(5.0); transport.close()
        self.assertEqual(seen, [(socket.AF_NETLINK, socket.SOCK_RAW, 0)])
        self.assertTrue(sock.closed); self.assertEqual(len(sock.sent), 6)
        headers = [struct.unpack('<IHHII', request[:16]) for request, peer in sock.sent]
        self.assertEqual(len(set(h[3] for h in headers)), 6)
        self.assertEqual(set(h[4] for h in headers), {321}); self.assertEqual(len(snapshot.rules), 3)
    def test_non_kernel_sender_is_rejected(self):
        sock = KernelSocket(); sock.sender = (99, 0)
        transport = ip.RouteTransport(lambda *args: sock, clock=lambda: 1.0)
        try:
            with self.assertRaises(ip.IpLeaseError): transport.snapshot(5.0)
        finally: transport.close()
    def test_deadline_prevents_any_send(self):
        sock = KernelSocket(); transport = ip.RouteTransport(lambda *args: sock, clock=lambda: 5.0)
        try:
            with self.assertRaises(ip.IpLeaseError): transport.snapshot(5.0)
            self.assertFalse(sock.sent)
        finally: transport.close()
    def test_false_write_gate_prevents_send(self):
        sock = KernelSocket(); transport = ip.RouteTransport(lambda *args: sock, clock=lambda: 1.0)
        try:
            request = transport.prepare_address(core.AddressSpec(9, '192.168.49.1', 24), True)
            with self.assertRaises(ip.IpLeaseError): transport.address_ack(request, 5.0, lambda: False)
            self.assertFalse(sock.sent)
        finally: transport.close()
    def test_two_snapshot_structures_or_cache_timestamp_change_are_rejected(self):
        sock = KernelSocket(); transport = ip.RouteTransport(lambda *args: sock, clock=lambda: 1.0)
        first = original(); second = core.IpSnapshot((first.addresses[0]._replace(cacheinfo=(core.UINT_MAX, core.UINT_MAX, 21, 21)),), first.routes, first.rules)
        try:
            with mock.patch.object(transport, 'snapshot', side_effect=[first, second]):
                with self.assertRaises(ip.IpLeaseError): transport.stable_snapshot(5.0)
        finally: transport.close()
    def test_oversized_recv_is_rejected_without_claiming_msg_ctrunc_check(self):
        sock = KernelSocket(); transport = ip.RouteTransport(lambda *args: sock, clock=lambda: 1.0)
        sock.recvfrom = lambda maximum: (b'x' * maximum, (0, 0))
        try:
            with self.assertRaises(ip.IpLeaseError): transport.snapshot(5.0)
        finally: transport.close()


class JournalDecoderTests(unittest.TestCase):
    def test_bool_version_rejected(self):
        value = ip.snapshot_data(original()); value['version'] = True
        with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
    def test_route_uint_canonical_flags_oif_and_metric_bounds(self):
        for field, replacement in ((0, -1), (0, 1 << 32), (3, 256), (6, 0x20), (7, 0),
                                   (11, [[1, 1], [1, 2]]), (11, [[16, 1]])):
            value = ip.snapshot_data(original()); value['routes'][0][field] = replacement
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
        value = ip.snapshot_data(original()); value['routes'][0][0] = core.ipv4_number('10.1.2.3'); value['routes'][0][1] = 24
        with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
    def test_duplicate_address_identity_with_different_timestamps_rejected(self):
        value = ip.snapshot_data(original()); duplicate = copy.deepcopy(value['addresses'][0]); duplicate[8][2] += 1
        value['addresses'].append(duplicate); value['addresses'].sort(key=repr)
        with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
    def test_missing_or_unknown_keys_rejected(self):
        for key in ('version', 'addresses', 'routes', 'rules'):
            value = ip.snapshot_data(original()); del value[key]
            with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
        value = ip.snapshot_data(original()); value['unknown'] = []
        with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)
    def test_bool_record_fields_are_not_integers(self):
        value = ip.snapshot_data(original()); value['addresses'][0][0] = True
        with self.assertRaises(ip.IpLeaseError): ip.snapshot_from_data(value)


class StaticTests(unittest.TestCase):
    def test_python35_ast_and_no_ip_socket_family(self):
        for path in (V5, ROOT / 'runtime/mta_ip_lease.py'):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        source = (ROOT / 'runtime/mta_ip_lease.py').read_text()
        self.assertNotIn('socket.AF_INET', source); self.assertNotIn('subprocess', source)
    def test_old_v4_sha_is_unchanged(self):
        import hashlib
        self.assertEqual(hashlib.sha256(V4.read_bytes()).hexdigest(),
            'ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334')
    def test_new_helper_and_codec_pins_match_complete_source(self):
        import hashlib
        self.assertEqual(hashlib.sha256((ROOT / 'runtime/mta_ip.py').read_bytes()).hexdigest(), v5.IP_CODEC_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / 'runtime/mta_ip_lease.py').read_bytes()).hexdigest(), v5.IP_HELPER_SHA256)


class CarrierGateTests(unittest.TestCase):
    def setUp(self):
        self.owned = {'name': 'mta1234abcd', 'ifindex': 9, 'wdev': 20, 'phy': 0, 'iftype': 8}
        self.row = dict(self.owned, iftype=9)
        self.backend = object.__new__(v5.LinuxBackend); self.backend.allow_rf = True
        self.backend.guard = mock.Mock(fd=5); self.backend.nl = mock.Mock()
        self.backend.nl.interfaces.return_value = [self.row]
    def check(self, flags, carrier, index='9', creating=True):
        values = {'flags': flags, 'carrier': carrier, 'ifindex': index}
        def opened(path, *args): return io.StringIO(values[path.rsplit('/', 1)[1]])
        with mock.patch('builtins.open', side_effect=opened) as files, \
                mock.patch.object(v5, '_digest', side_effect=lambda path: v5.STOCK_PINS[path]), \
                mock.patch.object(v5, '_address_dump', return_value=[]), \
                mock.patch.object(v5, '_owned_routes_safe', return_value=True):
            result = self.backend.ip_identity_gate(self.owned, creating)
            return result, files.call_count
    def test_creating_requires_up_carrier_one_and_same_sysfs_index(self):
        for flags, carrier, index, allowed in (('0x1003', '1', '9', True), ('0x1002', '1', '9', False),
                ('0x1003', '0', '9', False), ('0x1003', '2', '9', False),
                ('0x1003', '1', '10', False), ('not_hex', '1', '9', False)):
            with self.subTest(flags=flags, carrier=carrier, index=index):
                self.assertEqual(self.check(flags, carrier, index)[0], allowed)
    def test_restore_has_no_up_or_carrier_read_gate(self):
        result, opened = self.check('0x1002', '0', creating=False)
        self.assertTrue(result); self.assertEqual(opened, 0)
    def test_sysfs_name_reuse_cannot_pass_followup_four_tuple_gate(self):
        self.backend.nl.interfaces.side_effect = [[self.row], [dict(self.row, wdev=21)]]
        self.assertFalse(self.check('0x1003', '1')[0])


if __name__ == '__main__': unittest.main()
