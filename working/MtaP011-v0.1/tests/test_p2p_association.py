"""HOST fake UNIX command socket only; no device, real socket/file or RF."""
import ast
import pathlib
import socket
import stat
import sys
import threading
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
import mta_p2p_association as association
from mta_scoped_sockets import OwnedContext, ScopeProof

# Explicit Linux HOST fixture constants. Windows Python lacks these APIs;
# production code keeps the real Linux module and has no platform fallback.
LINUX_SOCKET = types.SimpleNamespace(AF_UNIX=1, SOL_SOCKET=1, SO_TYPE=3,
    SOCK_DGRAM=2, MSG_PEEK=2, MSG_DONTWAIT=64, MSG_TRUNC=32,
    timeout=socket.timeout, socket=socket.socket)


def setUpModule():
    global SOCKET_PATCH
    SOCKET_PATCH = mock.patch.object(association, 'socket', LINUX_SOCKET)
    SOCKET_PATCH.start()


def tearDownModule():
    SOCKET_PATCH.stop()

DEVICE = '02:10:20:30:40:50'
STATION = '02:aa:bb:cc:dd:ee'
OTHER = '02:aa:bb:cc:dd:ec'


def row(station=STATION, device=DEVICE, flags='[AUTH][ASSOC][AUTHORIZED]', extras=''):
    data = (station + '\nflags=' + flags + '\naid=1\ncapability=0x431\n'
            'listen_interval=10\nsupported_rates=82 84 8b\ntimeout_next=NULLFUNC POLL\n')
    if device is not None:
        data += 'p2p_device_name=HOST测试\np2p_device_addr=' + device + '\np2p_config_methods=0x188\n'
    return (data + extras).encode('utf-8')


class Clock:
    def __init__(self): self.value = 10.0
    def __call__(self): self.value += .00001; return self.value
    def sleep(self, seconds): self.value += seconds


class Mutex:
    def __init__(self): self.held = False; self.release_error = False; self.busy = False
    def acquire(self, blocking):
        if self.busy: return False
        self.held = True; return True
    def release(self):
        self.held = False
        if self.release_error: raise OSError('private not exported')


class FakeSocket:
    family = LINUX_SOCKET.AF_UNIX
    def __init__(self):
        self.timeout = 2.0; self.sent = []; self.queue = []; self.replies = []
        self.path = '/tmp/mta-p2p-v3-host/ctrl/cli-12345678'
        self.peer = '/tmp/mta-p2p-v3-host/ctrl/mta12345678'
        self.fd = 42; self.closes = 0; self.ancillary = []; self.flags = 0
        self.restore_error = False; self.send_error = False; self.short_send = False
        self.initial_timeout_error = False
        self.recv_error = None; self.on_send = None
    def fileno(self): return self.fd
    def getsockname(self): return self.path
    def getpeername(self): return self.peer
    def getsockopt(self, level, option): return association.socket.SOCK_DGRAM
    def gettimeout(self): return self.timeout
    def settimeout(self, seconds):
        if self.initial_timeout_error and seconds == 0.0:
            self.timeout = seconds
            raise OSError('partial timeout write')
        if self.restore_error and seconds == 2.0: raise OSError('private restore error')
        self.timeout = seconds
    def send(self, wire):
        self.sent.append(wire)
        if self.on_send: self.on_send(wire)
        if self.send_error: raise OSError('private send error')
        if not self.replies: raise AssertionError('fixture reply missing')
        command, reply = self.replies.pop(0)
        if command != wire: raise AssertionError('fixed command mismatch')
        self.queue.append(reply)
        return len(wire) - 1 if self.short_send else len(wire)
    def recvmsg(self, size, ancillary_size, flags=0):
        if flags:
            if self.queue: return self.queue[0], [], 0, self.peer
            raise BlockingIOError()
        if self.recv_error: raise self.recv_error
        return self.queue.pop(0), self.ancillary, self.flags, self.peer
    def close(self): self.closes += 1; self.fd = -1


class Fixture:
    def __init__(self):
        self.clock = Clock(); self.mutex = Mutex(); self.sock = FakeSocket()
        self.control = types.SimpleNamespace(sock=self.sock, path=self.sock.path)
        self.context = OwnedContext('12345678-1234-1234-1234-123456789abc', 1, 2,
            0, 1, 23, 'mta12345678', 'go', '192.168.49.1', 24, 100.0, 'a' * 64)
        self.cancelled = False; self.proofs = []; self.inodes = [1, 2, 3]
        self.proof_override = None; self.proof_delay = 0
        self.reader = association.AssociationReader(self.control, self.context, self.mutex,
            self.proof, lambda: self.cancelled, clock=self.clock, lstat=self.lstat,
            socket_type=FakeSocket, owner_uid=lambda: 0, sleeper=self.clock.sleep)
    def lstat(self, path):
        index = 0 if path.endswith('/ctrl') else 1 if path == self.sock.path else 2
        mode = stat.S_IFDIR | 0o700 if index == 0 else stat.S_IFSOCK | (0o600 if index == 1 else 0o770)
        return types.SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0, st_nlink=2 if index == 0 else 1,
                                     st_dev=1, st_ino=self.inodes[index])
    def proof(self, control, context, budget):
        self.proofs.append((control, context, budget, self.mutex.held))
        self.clock.value += self.proof_delay
        if self.proof_override is not None: return self.proof_override
        return ScopeProof(self.context, 'confirmed', True, True, True, True, True,
                          False, False, False, None)
    def schedule(self, first=None, second=None, final=None):
        first = [row()] if first is None else first
        second = list(first) if second is None else second
        script = [(b'PING', b'PONG\n')]
        for table in (first, second):
            cmd = b'STA-FIRST'
            for payload in table:
                script.append((cmd, payload))
                mac = payload.split(b'\n', 1)[0].decode('ascii').lower()
                cmd = ('STA-NEXT ' + mac).encode('ascii')
            script.append((cmd, b''))
        if final is not False:
            script.append((('STA ' + STATION).encode('ascii'), row() if final is None else final))
        self.sock.replies.extend(script)


class ParserTests(unittest.TestCase):
    def test_actual_field_name_and_flags(self):
        value = association.parse_station(row())
        self.assertEqual(value.station_mac, bytes.fromhex('02aabbccddee'))
        self.assertEqual(value.device_mac, bytes.fromhex('021020304050'))
        self.assertTrue(association.REQUIRED_FLAGS.issubset(value.flags))
        self.assertNotIn(STATION, repr(value))
    def test_missing_device_mapping_is_not_station_fallback(self):
        self.assertIsNone(association.parse_station(row(device=None)).device_mac)
    def test_duplicate_binding_keys_and_unknown_mapping_rejected(self):
        for extra in ('flags=[AUTH]\n', 'p2p_device_addr=' + DEVICE + '\n', 'p2p_dev_addr=' + DEVICE + '\n'):
            with self.subTest(extra=extra), self.assertRaises(association.AssociationError):
                association.parse_station(row(extras=extra))
    def test_malformed_rows_rejected(self):
        fixtures = (row()[:-1], row().replace(b'aid=1', b'aid=True'),
            row().replace(b'flags=[AUTH]', b'flags=[ALIEN]'), row(flags='[PENDING_POLL'),
            row(flags='[AUTH][AUTH]'), row().replace(b'capability=0x431', b'capability=65536'),
            row().replace(b'listen_interval=10', b'listen_interval=-1'),
            row().replace(b'timeout_next=NULLFUNC POLL', b'timeout_next=?'),
            row().replace(b'p2p_device_name=HOST', b'p2p_device_name=\0HOST'))
        for fixture in fixtures:
            with self.subTest(fixture=fixture[:12]), self.assertRaises(association.AssociationError):
                association.parse_station(fixture)
    def test_limits_fail_and_unknown_command(self):
        for raw in (b'FAIL\n', b'UNKNOWN COMMAND\n', b'x' * 8192,
                    row(extras='alien=1\n'), row(extras='wpsDeviceName=x\n'),
                    row(extras='p2p_group_client: dev=unassessed\n')):
            with self.subTest(raw=raw[:12]), self.assertRaises(association.AssociationError):
                association.parse_station(raw)
        self.assertIsNone(association.parse_station(b''))
    def test_nonbinding_standard_mib_metadata_preserved_not_used(self):
        self.assertEqual(association.parse_station(row(extras='dot11RSNAStatsVersion=1\nrx_bytes=999\n')),
                         association.parse_station(row()))
    def test_mac_unicast_zero_and_shape(self):
        for mac in ('00:00:00:00:00:00', '01:10:20:30:40:50', '02:10:20:30:40:50\n', 'aabbccddeeff'):
            with self.subTest(mac=mac), self.assertRaises(association.AssociationError):
                association.parse_station(row(device=mac))
    def test_event_hint_is_optional_not_observation(self):
        hint = association.parse_event_hint(('<3>AP-STA-CONNECTED ' + STATION + ' p2p_dev_addr=' + DEVICE).encode('ascii'))
        self.assertEqual(hint.kind, 'connected')
        self.assertEqual(hint.device_mac, association.parse_station(row()).device_mac)
        self.assertNotIsInstance(hint, association.AssociationObservation)
        self.assertIsNone(association.parse_event_hint(('AP-STA-CONNECTED ' + STATION).encode('ascii')).device_mac)
        with self.assertRaises(association.AssociationError):
            association.parse_event_hint(('AP-STA-CONNECTED ' + STATION + ' ip_addr=192.168.49.2').encode('ascii'))


class ReaderTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()
    def fail(self, reason, **kwargs):
        with self.assertRaises(association.AssociationError) as caught:
            self.f.reader.read(DEVICE, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(self.f.sock.closes, 0)
        self.assertFalse(self.f.mutex.held)
    def test_current_double_table_and_sta_then_fresh_readback(self):
        self.f.schedule(); first = self.f.reader.read(DEVICE.upper())
        self.assertEqual(first.station_mac, bytes.fromhex('02aabbccddee'))
        self.assertEqual(first.device_mac, bytes.fromhex('021020304050'))
        self.assertEqual(len(self.f.sock.sent), 6)
        self.assertEqual(self.f.sock.timeout, 2.0)
        self.assertTrue(all(p[3] is True and p[0] is self.f.control for p in self.f.proofs))
        self.f.schedule(); fresh = self.f.reader.readback(first)
        self.assertGreater(fresh.observed_at, first.observed_at)
        self.assertEqual(fresh.binding_id, first.binding_id)
        self.assertTrue(self.f.reader.close()); self.assertEqual(self.f.sock.closes, 0)
    def test_counters_may_change_without_mapping_change(self):
        self.f.schedule([row(extras='rx_bytes=1\n')], [row(extras='rx_bytes=2\n')], row(extras='rx_bytes=3\n'))
        self.assertIsInstance(self.f.reader.read(DEVICE), association.AssociationObservation)
        self.assertTrue(any(b'rx_bytes=3' in raw for command, raw in self.f.reader.private_raw()))
    def test_table_changed_rejects(self):
        self.f.schedule([row()], [row(flags='[AUTH][ASSOC]')], False)
        self.fail('table_changed')
    def test_station_and_device_duplicate_rejected(self):
        for rows, reason in (([row(), row()], 'reply_duplicate'), ([row(), row(OTHER)], 'association_ambiguous')):
            self.f = Fixture(); self.f.schedule(rows, final=False); self.fail(reason)
    def test_missing_mapping_and_unauthorized_cannot_admit(self):
        for payload in (row(device=None), row(flags='[AUTH][ASSOC]')):
            self.f = Fixture(); self.f.schedule([payload], final=False); self.fail('association_absent')
    def test_same_mac_without_device_field_never_fallback(self):
        self.f.schedule([row(station=DEVICE, device=None)], final=False)
        self.fail('association_absent')
    def test_final_station_disappears_or_changes(self):
        for final, reason in ((b'FAIL\n', 'reply_unsupported'), (b'', 'association_changed'),
                              (row(device='02:10:20:30:40:52'), 'association_changed')):
            self.f = Fixture(); self.f.schedule(final=final); self.fail(reason)
    def test_typed_current_scope_not_bool_or_copied_context(self):
        proofs = (True, ScopeProof(self.f.context._replace(), 'confirmed', True, True, True, True, True, False, False, False, None),
                  ScopeProof(self.f.context, 'confirmed', 1, True, True, True, True, False, False, False, None))
        for proof in proofs:
            self.f = Fixture(); self.f.proof_override = proof; self.fail('owner_readback_unverified')
            self.assertFalse(self.f.sock.sent)
    def test_scope_budget_exceeded_no_query(self):
        self.f.proof_delay = .3; self.fail('owner_readback_timeout')
        self.assertFalse(self.f.sock.sent)
    def test_control_identity_changed_not_rebound(self):
        self.f.schedule(); self.f.reader.read(DEVICE)
        self.f.inodes[2] += 1; self.f.schedule(); self.fail('control_identity_changed')
        self.assertEqual(len(self.f.sock.sent), 6)
    def test_control_wrong_peer_path_raw_or_closed(self):
        for change in ('peer', 'path', 'raw', 'closed'):
            self.f = Fixture()
            if change == 'peer': self.f.sock.peer = '/tmp/private/wlan0'
            if change == 'path': self.f.control.path += '-changed'
            if change == 'raw': self.f.control.sock = FakeSocket()
            if change == 'closed': self.f.sock.fd = -1
            self.fail('control_identity_failed'); self.assertFalse(self.f.sock.sent)
    def test_queued_reply_or_monitor_event_is_not_skipped(self):
        self.f.sock.queue.append(b'<3>AP-STA-CONNECTED private')
        self.fail('queued_or_event_reply'); self.assertFalse(self.f.sock.sent)
        self.assertTrue(self.f.reader.status()['channel_tainted'])
    def test_event_interleave_shortsend_and_timeout_taint(self):
        scenarios = (('event', 'queued_or_event_reply'), ('short', 'control_io_failed'),
                     ('timeout', 'control_timeout'), ('send', 'control_io_failed'))
        for kind, reason in scenarios:
            self.f = Fixture(); self.f.schedule()
            if kind == 'event': self.f.sock.replies[0] = (b'PING', b'<3>AP-STA-CONNECTED private')
            if kind == 'short': self.f.sock.short_send = True
            if kind == 'timeout': self.f.sock.recv_error = socket.timeout()
            if kind == 'send': self.f.sock.send_error = True
            self.fail(reason); self.assertTrue(self.f.reader.status()['channel_tainted'])
            self.assertEqual(self.f.sock.timeout, 2.0)
            self.fail('channel_tainted')
    def test_truncated_ancillary_flags_and_reply_size_fail_closed(self):
        for kind in ('ancillary', 'flags', 'size'):
            self.f = Fixture(); self.f.schedule()
            if kind == 'ancillary': self.f.sock.ancillary = [(1, 2, b'unknown')]
            if kind == 'flags': self.f.sock.flags = association.socket.MSG_TRUNC
            if kind == 'size': self.f.sock.replies[0] = (b'PING', b'x' * 8192)
            self.fail('reply_truncated'); self.assertTrue(self.f.reader.private_raw())
    def test_timeout_restore_unknown_sticky_even_success_response(self):
        self.f.schedule(); self.f.sock.restore_error = True
        self.fail('timeout_restore_unknown')
        self.assertFalse(self.f.reader.status()['timeout_restore_verified'])
        self.assertFalse(self.f.reader.close()); self.assertEqual(self.f.sock.closes, 0)
    def test_none_original_timeout_is_restored(self):
        self.f.schedule(); self.f.sock.timeout = None
        self.f.reader.read(DEVICE); self.assertIsNone(self.f.sock.timeout)
    def test_mutex_release_error_does_not_return_observation(self):
        self.f.schedule(); self.f.mutex.release_error = True
        self.fail('owner_release_unknown')
        self.assertFalse(self.f.reader.status()['owner_release_verified'])
        self.assertFalse(self.f.reader.status()['observation_ready'])
    def test_unknown_mutex_acquire_retained_and_never_blind_unlock(self):
        def unknown(blocking):
            self.f.mutex.held = True
            raise OSError('unknown acquisition result')
        self.f.mutex.acquire = unknown
        with self.assertRaises(association.AssociationError) as caught: self.f.reader.read(DEVICE)
        self.assertEqual(caught.exception.reason, 'owner_lock_failed')
        self.assertTrue(self.f.mutex.held)
        self.assertIs(self.f.reader._owner_lock, self.f.mutex)
        self.assertFalse(self.f.reader.status()['owner_release_verified'])
        self.assertFalse(self.f.reader.close())
        self.assertFalse(self.f.sock.sent)
    def test_partial_timeout_write_is_restored_before_error_return(self):
        self.f.sock.initial_timeout_error = True
        self.fail('control_io_failed')
        self.assertEqual(self.f.sock.timeout, 2.0)
        self.assertTrue(self.f.reader.status()['timeout_restore_verified'])
        self.assertFalse(self.f.sock.sent)
    def test_cancel_and_lock_deadline_no_command(self):
        self.f.cancelled = True; self.fail('cancelled')
        self.f = Fixture(); self.f.mutex.busy = True; self.fail('expired')
        self.assertFalse(self.f.sock.sent)
    def test_close_during_query_invalidates_result_without_closing_borrow(self):
        self.f.schedule(); self.f.sock.on_send = lambda wire: self.f.reader.close()
        self.fail('reader_closed'); self.assertFalse(self.f.reader.status()['observation_ready'])
    def test_readback_rejects_other_reader_and_actual_mapping_change(self):
        self.f.schedule(); old = self.f.reader.read(DEVICE)
        foreign = Fixture()
        with self.assertRaises(association.AssociationError) as caught: foreign.reader.readback(old)
        self.assertEqual(caught.exception.reason, 'observation_not_owned')
        changed = row(flags='[AUTH][ASSOC][AUTHORIZED][WMM]')
        self.f.schedule([changed], final=changed)
        with self.assertRaises(association.AssociationError) as caught: self.f.reader.readback(old)
        self.assertEqual(caught.exception.reason, 'association_changed')
    def test_huge_bool_nonfinite_budget_and_command_injection_no_io(self):
        for budget in (True, 10 ** 10000, float('inf'), float('nan'), 0, -1, 3):
            with self.subTest(kind=type(budget).__name__), self.assertRaises(association.AssociationError):
                self.f.reader.read(DEVICE, budget)
        with self.assertRaises(association.AssociationError): self.f.reader.read(DEVICE + '\nTERMINATE')
        self.assertFalse(self.f.sock.sent)
    def test_raw_lifetime_budget_is_finite_and_private(self):
        self.f.schedule()
        with mock.patch.object(association, 'MAX_RAW_BYTES', 1): self.fail('raw_budget')
        self.assertNotIn('mac', str(self.f.reader.status()).lower())
        self.assertNotIn('/tmp/', str(self.f.reader.status()))
    def test_clock_reverse_fails_before_unbounded_wait(self):
        values = iter((10., 9.))
        self.f.reader._clock = lambda: next(values)
        self.fail('clock_reversed')
    def test_pure_constructor_does_no_socket_or_file_io(self):
        with mock.patch.object(association.socket, 'socket', side_effect=AssertionError('no creation')), \
             mock.patch.object(association.os, 'lstat', side_effect=AssertionError('no read')):
            fixture = Fixture()
            self.assertFalse(fixture.sock.sent)
            self.assertFalse(fixture.reader.private_raw())
    def test_station_enumeration_budget_and_no_mutation_commands(self):
        rows = [row('02:aa:bb:cc:dd:%02x' % index, '02:10:20:30:40:%02x' % index) for index in range(33)]
        self.f.schedule(rows, final=False); self.fail('station_limit', budget=2)
        self.assertTrue(all(wire == b'PING' or wire == b'STA-FIRST' or wire.startswith(b'STA-NEXT ') for wire in self.f.sock.sent))
    def test_runtime_python35_ast_and_no_io_mutation_calls(self):
        source = (BASE / 'runtime' / 'mta_p2p_association.py').read_text(encoding='utf-8')
        ast.parse(source, feature_version=(3, 5))
        for forbidden in ('socket.socket(', '.connect(', '.bind(', '.unlink(', '.kill(', '.close(', 'import json'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__': unittest.main()
