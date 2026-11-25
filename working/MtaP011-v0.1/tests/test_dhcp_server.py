"""HOST fake-socket admission/race QA; no UDP port, device, RF or real lease."""
import ast
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import mta_dhcp as core
import mta_dhcp_server as adapter

SERVER, CLIENT, MASK = '192.168.77.1', '192.168.77.2', '255.255.255.0'
MAC = b'\x02\x00\x00\x00\x00\x01'
OTHER = b'\x02\x00\x00\x00\x00\x02'
IFNAME, IFINDEX = 'mta_go_host', 91


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeSocket:
    """Explicit Linux-kernel contract fixture, never an actual socket result."""
    family = socket.AF_INET

    def __init__(self, clock):
        self.clock = clock
        self.options = {(socket.SOL_SOCKET, socket.SO_TYPE): socket.SOCK_DGRAM,
                        (socket.SOL_SOCKET, socket.SO_REUSEADDR): 0,
                        (socket.SOL_SOCKET, adapter.SO_REUSEPORT): 0}
        self.calls = []
        self.queue = []
        self.sent = []
        self.closed = False
        self.inheritable = True
        self.address = None
        self.timeout = None
        self.fail_at = None
        self.hook = None
        self.close_fails = False
        self.send_length = None
        self.option_override = {}

    def step(self, name):
        self.calls.append(name)
        if self.hook is not None:
            self.hook(name)
        if self.fail_at == name:
            raise OSError('HOST_PRIVATE_EXCEPTION_VALUE')

    def set_inheritable(self, value):
        self.step('set_inheritable')
        self.inheritable = value

    def get_inheritable(self):
        self.step('get_inheritable')
        return self.inheritable

    def setsockopt(self, level, option, value):
        self.step('setsockopt')
        self.calls.append(('setsockopt', level, option, value))
        self.options[level, option] = value

    def getsockopt(self, level, option, size=None):
        self.step('getsockopt')
        return self.option_override.get((level, option), self.options.get((level, option), 0))

    def settimeout(self, value):
        self.step('settimeout')
        self.timeout = value

    def gettimeout(self):
        self.step('gettimeout')
        return self.timeout

    def bind(self, value):
        self.step('bind')
        self.address = value

    def getsockname(self):
        self.step('getsockname')
        return self.address

    def fileno(self):
        return -1 if self.closed else 123

    def close(self):
        self.calls.append('close')
        if self.close_fails:
            raise OSError('HOST_CLOSE_PENDING')
        self.closed = True

    def recvmsg(self, size, ancillary_size, flags):
        self.step('recvmsg')
        if (size, ancillary_size, flags) != (core.MAX_PACKET + 1, 32, 0):
            raise AssertionError('unexpected_bound')
        if self.closed:
            raise OSError('HOST_ALREADY_CLOSED')
        if not self.queue:
            self.clock.now += self.timeout
            raise socket.timeout()
        return self.queue.pop(0)

    def sendmsg(self, buffers, ancillary, flags, destination):
        self.step('sendmsg')
        if self.closed:
            raise OSError('HOST_ALREADY_CLOSED')
        value = b''.join(buffers)
        self.sent.append((value, ancillary, flags, destination))
        return len(value) if self.send_length is None else self.send_length


def discover(mac=MAC, xid=99):
    return core.encode(1, xid, mac, {53: b'\x01', 61: b'\x01' + mac})


def datagram(packet=None, index=IFINDEX, local=SERVER, destination='255.255.255.255',
             source=('0.0.0.0', 68), flags=0, ancillary=None):
    if ancillary is None:
        ancillary = [(socket.IPPROTO_IP, adapter.IP_PKTINFO,
                      adapter.PKTINFO.pack(index, core.ipv4(local), core.ipv4(destination)))]
    return (discover() if packet is None else packet, ancillary, flags, source)


class DhcpSocketTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.sock = FakeSocket(self.clock)
        self.factory_calls = []
        self.gate = True
        self.cancel = False
        self.index = IFINDEX
        self.admissions = []
        self.admission_callback = None
        self.gate_callback = None
        self.server = None
        # Windows does not export recvmsg/CMSG_SPACE. This explicit HOST-only
        # fixture supplies the ancillary buffer calculation, never production.
        self.cmsg_patch = mock.patch.object(socket, 'CMSG_SPACE', lambda _: 32, create=True)
        self.cmsg_patch.start()
        self.no_socket = mock.patch.object(socket, 'socket', side_effect=AssertionError('NO_ACTUAL_SOCKET'))
        self.no_socket.start()

    def tearDown(self):
        if self.server is not None:
            self.sock.close_fails = False
            self.server.close()
        self.no_socket.stop()
        self.cmsg_patch.stop()

    def factory(self, *args):
        self.factory_calls.append(args)
        return self.sock

    def fresh(self):
        return self.gate_callback() if self.gate_callback else self.gate

    def station(self, mac, ip):
        self.admissions.append((mac, ip))
        return self.admission_callback(mac, ip) if self.admission_callback else mac == MAC

    def make(self, **changes):
        options = dict(ifname=IFNAME, ifindex=IFINDEX, server_ip=SERVER, client_ip=CLIENT,
                       subnet_mask=MASK, deadline=120.0, fresh_gate=self.fresh,
                       admit_station=self.station, cancelled=lambda: self.cancel,
                       clock=self.clock, socket_factory=self.factory,
                       if_nametoindex=lambda _: self.index)
        options.update(changes)
        self.server = adapter.DhcpSocketServer(**options)
        return self.server

    def opened(self, **changes):
        server = self.make(**changes)
        self.assertIs(server.open(), server)
        return server

    def handshake(self, server=None):
        server = server or self.opened()
        client = core.ClientExchange(MAC, SERVER, MASK, deadline=119.0, xid=99)
        self.sock.queue.append(datagram(client.discover(self.clock.now)))
        self.assertEqual(server.serve_once()['event'], 'offer_transmitted')
        request = client.accept_offer(self.sock.sent[-1][0], self.clock.now)
        self.sock.queue.append(datagram(request))
        self.assertEqual(server.serve_once()['event'], 'ack_transmitted')
        return client.accept_ack(self.sock.sent[-1][0], self.clock.now)

    def test_open_exact_device_udp67_no_reuse_and_private_fd(self):
        server = self.opened()
        self.assertEqual(self.factory_calls, [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)])
        self.assertEqual(self.sock.address, ('0.0.0.0', 67))
        self.assertFalse(self.sock.inheritable)
        sets = [call for call in self.sock.calls if isinstance(call, tuple)]
        self.assertEqual(sets, [
            ('setsockopt', socket.SOL_SOCKET, adapter.SO_BINDTODEVICE, IFNAME.encode() + b'\0'),
            ('setsockopt', socket.SOL_SOCKET, socket.SO_BROADCAST, 1),
            ('setsockopt', socket.IPPROTO_IP, adapter.IP_PKTINFO, 1)])
        self.assertTrue(server.close())
        self.assertTrue(server.status()['socket_close_verified'])

    def test_real_dhcp_core_dora_uses_fixed_egress_subnet_broadcast(self):
        result = self.handshake()
        self.assertEqual(result['local_ip'], CLIENT)
        self.assertEqual(len(self.sock.sent), 2)
        for packet, ancillary, flags, destination in self.sock.sent:
            self.assertEqual(destination, ('192.168.77.255', 68))
            self.assertEqual(flags, 0)
            self.assertEqual(ancillary, [(socket.IPPROTO_IP, adapter.IP_PKTINFO,
                adapter.PKTINFO.pack(IFINDEX, core.ipv4(SERVER), core.ZERO))])
            options = core.decode(packet)['options']
            self.assertNotIn(3, options)
            self.assertNotIn(6, options)
        allocation = self.server.allocation()
        self.assertTrue(allocation['ack_transmitted'])
        self.assertFalse(allocation['phone_configured'])
        self.assertEqual(allocation['mac'], MAC)
        self.assertEqual(allocation['usable_until'], 120.0)

    def test_broadcast_calculated_from_actual_non24_prefix(self):
        self.opened(server_ip='10.23.4.1', client_ip='10.23.5.2', subnet_mask='255.255.254.0')
        self.sock.queue.append(datagram(local='10.23.4.1'))
        self.server.serve_once()
        self.assertEqual(self.sock.sent[-1][3], ('10.23.5.255', 68))

    def test_no_client_allocation_before_successful_ack(self):
        server = self.opened()
        self.assertIsNone(server.allocation())
        self.sock.queue.append(datagram())
        server.serve_once()
        self.assertIsNone(server.allocation())
        self.assertFalse(server.status()['allocation_ack_transmitted'])

    def test_allocated_until_follows_integer_ack_seconds_not_longer_deadline(self):
        server = self.opened(deadline=120.9)
        self.clock.now = 100.2
        self.handshake(server)
        seconds = struct.unpack('!I', core.decode(self.sock.sent[-1][0])['options'][51])[0]
        self.assertEqual(seconds, 20)
        self.assertAlmostEqual(server.allocation()['usable_until'], 120.2)

    def test_bad_udp_source_port_or_address_gets_no_reply(self):
        server = self.opened()
        for source in (('0.0.0.0', 67), ('0.0.0.0', 69), ('0.0.0.0', True),
                       ('192.168.77.3', 68), ('not-an-ip', 68), ('0.0.0.0', 68, 1), []):
            with self.subTest(source=source):
                self.sock.queue.append(datagram(source=source))
                self.assertEqual(server.serve_once()['event'], 'ignored')
        self.assertFalse(self.sock.sent)
        self.assertFalse(self.admissions)

    def test_missing_duplicate_unknown_and_wrong_size_pktinfo_get_no_reply(self):
        server = self.opened()
        valid = datagram()[1][0]
        for ancillary in ([], [valid, valid], [valid, (socket.SOL_SOCKET, 1, b'x')],
                          [(socket.IPPROTO_IP, 99, valid[2])], [(socket.IPPROTO_IP, adapter.IP_PKTINFO, b'x')],
                          [(False, adapter.IP_PKTINFO, valid[2])], tuple([valid])):
            with self.subTest(ancillary_shape=type(ancillary).__name__):
                self.sock.queue.append(datagram(ancillary=ancillary))
                self.assertEqual(server.serve_once()['event'], 'ignored')
        self.assertFalse(self.sock.sent)
        self.assertFalse(self.admissions)

    def test_kernel_ingress_index_local_address_and_destination_must_match(self):
        server = self.opened()
        for values in ({'index': 92}, {'local': '192.168.77.3'}, {'destination': '192.168.77.3'}):
            self.sock.queue.append(datagram(**values))
            self.assertEqual(server.serve_once()['event'], 'ignored')
        self.assertFalse(self.sock.sent)
        self.assertFalse(self.admissions)

    def test_datagram_and_cmsg_truncation_oversize_and_malformed_core_drop(self):
        server = self.opened()
        for packet, flags in ((discover(), adapter.MSG_TRUNC), (discover(), adapter.MSG_CTRUNC),
                              (discover(), 1), (b'x' * (core.MAX_PACKET + 1), 0),
                              (b'x' * 239, 0), (b'x' * 300, 0)):
            self.sock.queue.append(datagram(packet=packet, flags=flags))
            self.assertEqual(server.serve_once()['event'], 'ignored')
        self.assertFalse(self.sock.sent)

    def test_no_implicit_first_peer_or_ble_mac_admission(self):
        self.admission_callback = lambda mac, ip: False
        server = self.opened()
        self.sock.queue.append(datagram())
        self.assertEqual(server.serve_once()['reason'], 'station_not_admitted')
        self.assertIsNone(server._core.key)
        self.assertFalse(self.sock.sent)
        self.assertEqual(self.admissions, [(MAC, CLIENT)])

    def test_admission_must_be_exact_true_not_truthy(self):
        self.admission_callback = lambda mac, ip: 1
        server = self.opened()
        self.sock.queue.append(datagram())
        self.assertEqual(server.serve_once()['reason'], 'station_not_admitted')
        self.assertFalse(self.sock.sent)

    def test_actual_station_callback_exception_is_symbolic_failclosed(self):
        def broken(mac, ip):
            raise RuntimeError('HOST_PRIVATE_STATION_VALUE')
        self.admission_callback = broken
        server = self.opened()
        self.sock.queue.append(datagram())
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^station_check_failed$'):
            server.serve_once()
        self.assertTrue(server.close())
        self.assertFalse(self.sock.sent)

    def test_station_revocation_before_reply_prevents_offer_and_closes(self):
        calls = []
        def admitted(mac, ip):
            calls.append(mac)
            return len(calls) == 1
        self.admission_callback = admitted
        server = self.opened()
        self.sock.queue.append(datagram())
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^station_admission_lost$'):
            server.serve_once()
        self.assertFalse(self.sock.sent)
        self.assertTrue(server.close())

    def test_station_revocation_without_new_packet_invalidates_allocation(self):
        self.handshake()
        self.admission_callback = lambda mac, ip: False
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^station_admission_lost$'):
            self.server.allocation()
        self.assertFalse(self.server.status()['allocation_ack_transmitted'])
        self.assertTrue(self.server.close())

    def test_one_client_even_when_platform_wrongly_admits_multiple_stations(self):
        server = self.opened()
        self.admission_callback = lambda mac, ip: True
        self.sock.queue.extend([datagram(), datagram(packet=discover(OTHER, 100))])
        self.assertEqual(server.serve_once()['event'], 'offer_transmitted')
        self.assertEqual(server.serve_once()['event'], 'ignored')
        self.assertEqual(len(self.sock.sent), 1)

    def test_release_removes_private_allocation(self):
        self.handshake()
        release = core.encode(1, 101, MAC, {53: b'\x07', 54: core.ipv4(SERVER), 61: b'\x01' + MAC},
                              ciaddr=core.ipv4(CLIENT))
        self.sock.queue.append(datagram(release, source=(CLIENT, 68)))
        self.assertEqual(self.server.serve_once()['event'], 'ignored')
        self.assertIsNone(self.server.allocation())

    def test_decline_never_reuses_address_and_closes_for_owner_cleanup(self):
        server = self.opened()
        self.sock.queue.append(datagram())
        server.serve_once()
        decline = core.encode(1, 99, MAC, {53: b'\x04', 54: core.ipv4(SERVER),
                              50: core.ipv4(CLIENT), 61: b'\x01' + MAC})
        self.sock.queue.append(datagram(decline))
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^client_declined_address$'):
            server.serve_once()
        self.assertTrue(server.close())
        self.assertEqual(len(self.sock.sent), 1)

    def test_gate_failure_before_open_never_creates_socket(self):
        self.gate = False
        server = self.make()
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^owned_identity_unverified$'):
            server.open()
        self.assertFalse(self.factory_calls)
        self.assertTrue(server.close())

    def test_gate_exception_does_not_leak_private_error(self):
        def broken():
            raise RuntimeError('HOST_PRIVATE_OWNER_IDENTITY')
        self.gate_callback = broken
        server = self.make()
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^owned_identity_check_failed$'):
            server.open()
        self.assertFalse(self.factory_calls)

    def test_ifindex_replacement_before_or_after_open_closes_without_reply(self):
        server = self.opened()
        self.index = 92
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^owned_identity_unverified$'):
            server.serve_once()
        self.assertTrue(self.sock.closed)
        self.assertFalse(self.sock.sent)

    def test_cancel_and_expiry_before_open_are_no_socket(self):
        for reason in ('cancelled', 'lease_expired'):
            with self.subTest(reason=reason):
                self.cancel = False
                self.clock.now = 100
                server = self.make()
                if reason == 'cancelled':
                    self.cancel = True
                else:
                    self.clock.now = 119.1
                with self.assertRaisesRegex(adapter.DhcpSocketError, '^' + reason + '$'):
                    server.open()
                self.assertTrue(server.close())
        self.assertFalse(self.factory_calls)

    def test_cancel_changed_inside_fresh_gate_is_checked_before_mutation(self):
        def gate():
            self.cancel = True
            return True
        self.gate_callback = gate
        server = self.make()
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^cancelled$'):
            server.open()
        self.assertFalse(self.factory_calls)

    def test_deadline_elapsed_inside_fresh_gate_is_checked_before_mutation(self):
        def gate():
            self.clock.now = 120
            return True
        self.gate_callback = gate
        server = self.make()
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^lease_expired$'):
            server.open()
        self.assertFalse(self.factory_calls)

    def test_late_socket_factory_return_after_close_is_owned_and_closed(self):
        close_results = []
        def late_factory(*args):
            self.factory_calls.append(args)
            close_results.append(self.server.close())
            return self.sock
        server = self.make(socket_factory=late_factory)
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^server_closed$'):
            server.open()
        self.assertEqual(close_results, [False])
        self.assertTrue(self.sock.closed)
        self.assertTrue(server.close())
        self.assertNotIn('bind', self.sock.calls)

    def test_factory_error_is_one_attempt_and_no_fallback(self):
        def broken(*args):
            self.factory_calls.append(args)
            raise OSError('HOST_PRIVATE_SOCKET_TEXT')
        server = self.make(socket_factory=broken)
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^socket_open_failed$'):
            server.open()
        self.assertEqual(len(self.factory_calls), 1)
        self.assertTrue(server.close())

    def test_bind_and_option_failures_close_exact_created_socket(self):
        for step in ('set_inheritable', 'setsockopt', 'getsockopt', 'settimeout', 'bind', 'getsockname'):
            with self.subTest(step=step):
                self.sock = FakeSocket(self.clock)
                self.sock.fail_at = step
                server = self.make()
                with self.assertRaisesRegex(adapter.DhcpSocketError, '^socket_open_failed$'):
                    server.open()
                self.assertTrue(self.sock.closed)
                self.assertTrue(server.close())

    def test_unscoped_device_or_reuse_readback_fails_closed(self):
        for key, bad in (((socket.SOL_SOCKET, adapter.SO_BINDTODEVICE), b'wlan0\0'),
                         ((socket.SOL_SOCKET, socket.SO_REUSEADDR), 1),
                         ((socket.SOL_SOCKET, adapter.SO_REUSEPORT), 1),
                         ((socket.IPPROTO_IP, adapter.IP_PKTINFO), 0)):
            with self.subTest(key=key):
                self.sock = FakeSocket(self.clock)
                self.sock.option_override[key] = bad
                server = self.make()
                with self.assertRaises(adapter.DhcpSocketError):
                    server.open()
                self.assertTrue(self.sock.closed)
                self.assertNotIn('bind', self.sock.calls)

    def test_missing_recvmsg_does_not_fall_back_to_recvfrom(self):
        self.sock.recvmsg = None
        server = self.make()
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^required_socket_api_unavailable$'):
            server.open()
        self.assertTrue(self.sock.closed)
        self.assertNotIn('bind', self.sock.calls)

    def test_missing_cmsg_space_fails_before_socket_creation(self):
        with mock.patch.object(socket, 'CMSG_SPACE', None):
            server = self.make()
            with self.assertRaisesRegex(adapter.DhcpSocketError, '^required_socket_api_unavailable$'):
                server.open()
            self.assertFalse(self.factory_calls)

    def test_close_before_open_is_terminal_and_idempotent(self):
        server = self.make()
        self.assertTrue(server.close())
        self.assertTrue(server.close())
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^open_in_invalid_state$'):
            server.open()
        self.assertFalse(self.factory_calls)

    def test_close_failure_retains_exact_handle_until_verified_retry(self):
        server = self.opened()
        self.sock.close_fails = True
        self.assertFalse(server.close())
        self.assertTrue(server.status()['socket_actor_pending'])
        self.assertFalse(server.status()['socket_close_verified'])
        self.sock.close_fails = False
        self.assertTrue(server.close())
        self.assertFalse(server.status()['socket_actor_pending'])

    def test_close_during_recv_prevents_late_packet_response_and_keeps_actor(self):
        server = self.opened()
        self.sock.queue.append(datagram())
        results = []
        def hook(step):
            if step == 'recvmsg':
                results.append(server.close())
        self.sock.hook = hook
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^server_closed$'):
            server.serve_once()
        self.assertEqual(results, [False])
        self.assertFalse(self.sock.sent)
        self.assertTrue(server.close())
        self.assertEqual(server.status()['reason'], 'closed_by_owner')

    def test_concurrent_close_cannot_claim_verified_while_fd_close_actor_is_pending(self):
        server = self.opened()
        entered, finish = threading.Event(), threading.Event()
        original_close = self.sock.close
        results = []
        def delayed_close():
            entered.set()
            if not finish.wait(2):
                raise AssertionError('HOST close release timeout')
            original_close()
        self.sock.close = delayed_close
        thread = threading.Thread(target=lambda: results.append(server.close()))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(server.close())
            self.assertTrue(server.status()['socket_actor_pending'])
            self.assertFalse(server.status()['socket_close_verified'])
        finally:
            finish.set()
            thread.join(2)
            self.sock.close = original_close
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, [True])
        self.assertTrue(server.close())

    def test_actual_host_thread_late_factory_is_closed_not_published(self):
        entered, finish = threading.Event(), threading.Event()
        errors = []
        def delayed_factory(*args):
            self.factory_calls.append(args)
            entered.set()
            if not finish.wait(2):
                raise AssertionError('HOST factory release timeout')
            return self.sock
        server = self.make(socket_factory=delayed_factory)
        def opening():
            try:
                server.open()
            except adapter.DhcpSocketError as error:
                errors.append(str(error))
        thread = threading.Thread(target=opening)
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(server.close())
            self.assertTrue(server.status()['socket_actor_pending'])
        finally:
            finish.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['server_closed'])
        self.assertTrue(self.sock.closed)
        self.assertTrue(server.close())
        self.assertNotIn('bind', self.sock.calls)

    def test_concurrent_poll_reader_is_rejected_not_spawned(self):
        server = self.opened()
        rejected = []
        def hook(step):
            if step == 'recvmsg':
                try:
                    server.serve_once()
                except adapter.DhcpSocketError as error:
                    rejected.append(str(error))
        self.sock.hook = hook
        self.assertEqual(server.serve_once()['event'], 'idle')
        self.assertEqual(rejected, ['concurrent_poll_forbidden'])
        self.assertFalse(self.sock.sent)

    def test_cancel_after_recv_prevents_any_core_mutation_or_reply(self):
        server = self.opened()
        self.sock.queue.append(datagram())
        self.sock.hook = lambda step: setattr(self, 'cancel', True) if step == 'recvmsg' else None
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^cancelled$'):
            server.serve_once()
        self.assertIsNone(server._core.key)
        self.assertFalse(self.sock.sent)

    def test_epoch_gate_lost_after_admission_prevents_any_reply(self):
        def admitted(mac, ip):
            self.gate = False
            return True
        self.admission_callback = admitted
        server = self.opened()
        self.sock.queue.append(datagram())
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^owned_identity_unverified$'):
            server.serve_once()
        self.assertFalse(self.sock.sent)

    def test_short_send_and_send_failure_never_export_allocation(self):
        for fail_at, send_length in (('sendmsg', None), (None, 1)):
            with self.subTest(fail_at=fail_at):
                self.sock = FakeSocket(self.clock)
                server = self.opened()
                self.sock.fail_at = fail_at
                self.sock.send_length = send_length
                self.sock.queue.append(datagram())
                with self.assertRaises(adapter.DhcpSocketError):
                    server.serve_once()
                self.assertFalse(server.status()['allocation_ack_transmitted'])
                self.assertTrue(server.close())

    def test_cancel_during_send_never_reports_ack_or_ready_after_kernel_send(self):
        server = self.opened()
        client = core.ClientExchange(MAC, SERVER, MASK, 119, xid=99)
        self.sock.queue.append(datagram(client.discover(100)))
        server.serve_once()
        request = client.accept_offer(self.sock.sent[-1][0], 100)
        self.sock.queue.append(datagram(request))
        self.sock.hook = lambda step: setattr(self, 'cancel', True) if step == 'sendmsg' else None
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^cancelled$'):
            server.serve_once()
        self.assertFalse(server.status()['allocation_ack_transmitted'])
        self.assertTrue(server.close())

    def test_run_is_bounded_by_lease_expiry_and_closes_no_permanent_thread(self):
        server = self.make(deadline=101.5)
        server.run()
        self.assertTrue(server.close())
        self.assertEqual(server.status()['reason'], 'lease_expired')
        self.assertLessEqual(self.clock.now, 101.7)

    def test_rate_and_total_packet_limits_are_bounded(self):
        server = self.opened()
        self.sock.queue.extend(datagram() for _ in range(adapter.MAX_PACKETS + 1))
        events = [server.serve_once() for _ in range(adapter.MAX_PACKETS)]
        self.assertEqual(sum(row['event'] == 'offer_transmitted' for row in events), adapter.MAX_PACKETS_PER_SECOND)
        self.assertTrue(any(row['reason'] == 'rate_limited' for row in events))
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^session_packet_limit$'):
            server.serve_once()
        self.assertTrue(server.close())

    def test_passive_status_has_only_fixed_public_fields(self):
        server = self.opened()
        self.handshake(server)
        calls = len(self.admissions)
        status = server.status()
        self.assertEqual(len(self.admissions), calls)
        self.assertEqual(set(status), {'stage', 'reason', 'packets_received', 'replies_transmitted',
            'packets_ignored', 'client_limit', 'socket_close_verified', 'socket_actor_pending',
            'allocation_ack_transmitted', 'phone_configured', 'default_route_supplied', 'dns_supplied'})
        self.assertNotIn(SERVER, repr(status))
        self.assertNotIn(CLIENT, repr(status))
        self.assertNotIn(IFNAME, repr(status))
        self.assertFalse(status['phone_configured'])

    def test_backwards_clock_invalid_callbacks_and_protected_iface_reject(self):
        server = self.opened()
        self.clock.now = 99
        with self.assertRaisesRegex(adapter.DhcpSocketError, '^clock_moved_backwards$'):
            server.serve_once()
        self.clock.now = 100
        for values in ({'ifname': 'wlan0'}, {'ifname': 'lo'}, {'ifname': 'bad/name'},
                       {'ifindex': True}, {'ifindex': 0}, {'fresh_gate': None},
                       {'deadline': float('inf')}, {'deadline': 401}):
            with self.subTest(values=values):
                with self.assertRaises(adapter.DhcpSocketError):
                    self.make(**values)

    def test_runtime_source_parses_python35_and_does_not_import_json_or_subprocess(self):
        source = Path(adapter.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertNotIn('json', imports)
        self.assertNotIn('subprocess', imports)


if __name__ == '__main__':
    unittest.main()
