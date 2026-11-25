"""Synthetic HOST-only dynamic DORA tests; no device, socket or IP changes."""
import ast
import pathlib
import random
import socket
import struct
import sys
import unittest
from unittest import mock

PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'runtime'))
import mta_dhcp as wire
import mta_dhcp_client_core as core

MAC = b'\x02\x11\x22\x33\x44\x55'
OTHER_MAC = b'\x02\x11\x22\x33\x44\x56'
XID = 0x12345678
SERVER = '10.70.4.9'
CLIENT = '10.70.4.31'
MASK = '255.255.255.0'


def u32(n):
    return struct.pack('!I', n)


def response(kind=wire.OFFER, server=SERVER, client=CLIENT, mask=MASK,
             lease=60, mac=MAC, xid=XID, op=2, ciaddr=wire.ZERO,
             siaddr=wire.ZERO, extras=None, omit=(), client_id=False):
    options = {53: bytes((kind,)), 54: wire.ipv4(server)}
    if kind in (wire.OFFER, wire.ACK):
        options.update({1: wire.ipv4(mask), 51: u32(lease)})
    if client_id:
        options[61] = b'\x01' + MAC
    if extras:
        options.update(extras)
    for key in omit:
        options.pop(key, None)
    return wire.encode(op, xid, mac, options, ciaddr=ciaddr, siaddr=siaddr,
                       yiaddr=wire.ipv4(client) if kind != wire.NAK else wire.ZERO)


def exchange(**kwargs):
    args = {'xid': XID, 'deadline': 100.0}
    args.update(kwargs)
    return core.DynamicClientExchange(MAC, **args)


def requesting(**kwargs):
    value = exchange(**kwargs)
    value.start(1)
    value.accept_offer(response(), 2)
    return value


def bound(**kwargs):
    value = requesting(**kwargs)
    value.accept_ack(response(wire.ACK), 3)
    return value


class DynamicDoraTests(unittest.TestCase):
    def check_error(self, reason, callback):
        with self.assertRaises(core.DhcpClientError) as caught:
            callback()
        self.assertEqual(str(caught.exception), reason)

    def test_dynamic_dora_no_dot_one_or_router_assumption(self):
        value = exchange()
        discover = wire.decode(value.start(1))
        self.assertEqual(discover['type'], wire.DISCOVER)
        self.assertNotIn(54, discover['options'])
        request = wire.decode(value.accept_offer(response(client_id=True), 2))
        self.assertEqual(request['options'][54], wire.ipv4(SERVER))
        self.assertEqual(request['options'][50], wire.ipv4(CLIENT))
        config = value.accept_ack(response(wire.ACK, client_id=True), 3)
        self.assertEqual((config.local_ip, config.server_ip, config.subnet_mask,
                          config.prefix), (CLIENT, SERVER, MASK, 24))
        self.assertFalse(value.status(3)['endpoint_verified'])

    def test_parameter_list_and_identity_are_same_for_discover_request(self):
        value = exchange()
        discover = wire.decode(value.start(1))
        request = wire.decode(value.accept_offer(response(), 2))
        for field in ('xid', 'chaddr', 'ciaddr', 'yiaddr', 'siaddr'):
            self.assertEqual(discover[field], request[field])
        self.assertEqual(discover['options'][55], request['options'][55])
        self.assertEqual(discover['options'][61], request['options'][61])
        self.assertEqual(request['flags'], 0x8000)

    def test_configuration_is_immutable_and_not_public_pin(self):
        value = bound()
        config = value.configuration(4)
        with self.assertRaises(AttributeError):
            config.local_ip = '10.1.1.1'
        self.assertIsNone(getattr(value, 'offer', None))
        self.assertIsNone(getattr(value, 'server', None))
        self.assertEqual(value.configuration(4), config)

    def test_configuration_current_check_clears_after_cancel(self):
        value = bound()
        historical = value.configuration(4)
        value.cancel()
        self.assertIsNone(value.configuration(4))
        self.assertEqual(historical.local_ip, CLIENT)  # Snapshot, not authority.
        self.assertFalse(value.status(4)['configuration_available'])
        self.assertEqual(value.status(4)['usable_lease_remaining'], 0)

    def test_original_request_start_is_lease_origin_not_ack(self):
        value = requesting()
        value.tick(3)
        config = value.accept_ack(response(wire.ACK, lease=10), 8)
        self.assertEqual(config.usable_until, 12)
        self.assertEqual(value.status(8)['usable_lease_remaining'], 4)

    def test_ack_actual_lease_can_differ_from_offer(self):
        value = requesting()
        config = value.accept_ack(response(wire.ACK, lease=12), 3)
        self.assertEqual(config.server_lease_seconds, 12)
        self.assertEqual(config.usable_until, 14)

    def test_deadline_bounds_infinite_lease(self):
        value = requesting(deadline=20)
        config = value.accept_ack(response(wire.ACK, lease=0xffffffff), 3)
        self.assertEqual(config.usable_until, 20)
        self.assertEqual(config.server_lease_seconds, 0xffffffff)

    def test_delayed_ack_cannot_start_already_expired_lease(self):
        value = requesting()
        self.check_error('allocation_expired', lambda: value.accept_ack(
            response(wire.ACK, lease=2), 4))
        self.assertEqual(value.status(4)['stage'], 'expired')
        self.assertIsNone(value.configuration(4))

    def test_expiry_clears_current_configuration_without_rounding_early(self):
        value = bound()
        self.assertIsNotNone(value.configuration(61.9))
        self.assertEqual(value.status(61.9)['usable_lease_remaining'], 0)
        self.assertTrue(value.status(61.9)['configuration_available'])
        self.assertIsNone(value.configuration(62))
        self.assertEqual(value.status(62)['stage'], 'expired')

    def test_valid_nak_clears_and_late_ack_does_not_resurrect(self):
        value = requesting()
        self.check_error('server_nak', lambda: value.accept_ack(response(wire.NAK), 3))
        self.assertIsNone(value.configuration(3))
        self.check_error('stage_mismatch', lambda: value.accept_ack(response(wire.ACK), 4))
        value.cancel()
        self.assertEqual(value.status(4)['stage'], 'rejected')

    def test_nak_wrong_server_does_not_poison_request(self):
        value = requesting()
        self.check_error('ack_drift', lambda: value.accept_ack(
            response(wire.NAK, server='10.70.4.8'), 3))
        self.assertIsNotNone(value.accept_ack(response(wire.ACK), 4))

    def test_nak_nonzero_yiaddr_rejected(self):
        value = requesting()
        packet = wire.encode(2, XID, MAC, {53: b'\x06', 54: wire.ipv4(SERVER)},
                             yiaddr=wire.ipv4(CLIENT))
        self.check_error('nak_invalid', lambda: value.accept_ack(packet, 3))
        self.assertEqual(value.status(3)['stage'], 'requesting')

    def test_identity_xid_mac_op_ciaddr(self):
        variants = ({'xid': XID + 1}, {'mac': OTHER_MAC}, {'op': 1},
                    {'ciaddr': wire.ipv4(CLIENT)})
        for variant in variants:
            with self.subTest(variant=tuple(variant)):
                value = exchange()
                value.start(1)
                self.check_error('identity_mismatch', lambda: value.accept_offer(
                    response(**variant), 2))
                self.assertEqual(value.status(2)['stage'], 'selecting')

    def test_wrong_client_id_rejected_offer_ack_and_nak(self):
        for kind in (wire.OFFER, wire.ACK, wire.NAK):
            with self.subTest(kind=kind):
                value = exchange() if kind == wire.OFFER else requesting()
                if kind == wire.OFFER:
                    value.start(1)
                accept = value.accept_offer if kind == wire.OFFER else value.accept_ack
                self.check_error('identity_mismatch', lambda: accept(response(
                    kind, extras={61: b'\x01' + OTHER_MAC}), 3))

    def test_absent_client_id_is_accepted_not_authentication(self):
        self.assertIsNotNone(bound().configuration(3))
        self.assertFalse(bound().status(3)['endpoint_verified'])

    def test_malformed_client_id_wire_length_rejected_all_response_kinds(self):
        for kind in (wire.OFFER, wire.ACK, wire.NAK):
            value = exchange() if kind == wire.OFFER else requesting()
            if kind == wire.OFFER:
                value.start(1)
            packet = response(kind)[:240] + bytes((53, 1, kind, 61, 1, 1, 255))
            accept = value.accept_offer if kind == wire.OFFER else value.accept_ack
            self.check_error('invalid_packet', lambda: accept(packet, 3))

    def test_siaddr_is_not_the_server_identifier_or_endpoint(self):
        value = exchange()
        value.start(1)
        value.accept_offer(response(siaddr=wire.ipv4('203.0.113.11')), 2)
        config = value.accept_ack(response(wire.ACK, siaddr=wire.ipv4('203.0.113.12')), 3)
        self.assertEqual(config.server_ip, SERVER)
        self.assertNotIn('endpoint', config._fields)

    def test_router_dns_are_not_installed_or_promoted(self):
        value = requesting()
        config = value.accept_ack(response(wire.ACK, extras={
            3: wire.ipv4('10.70.4.8'), 6: wire.ipv4('10.70.4.7')}), 3)
        self.assertEqual(config.server_ip, SERVER)
        self.assertFalse(value.status(3)['default_route_installed'])
        self.assertFalse(value.status(3)['dns_installed'])

    def test_missing_server_subnet_or_lease(self):
        for kind, reason in ((54, 'server_identifier_invalid'),
                             (1, 'subnet_invalid'), (51, 'lease_invalid')):
            value = exchange()
            value.start(1)
            self.check_error(reason, lambda: value.accept_offer(response(omit=(kind,)), 2))
        value = requesting()
        self.check_error('server_identifier_invalid', lambda: value.accept_ack(
            response(wire.NAK, omit=(54,)), 3))

    def test_invalid_mask_prefix_and_noncontiguous(self):
        for mask in ('255.0.255.0', '255.255.255.254', '254.0.0.0', '0.0.0.0'):
            value = exchange()
            value.start(1)
            self.check_error('subnet_invalid', lambda: value.accept_offer(response(mask=mask), 2))

    def test_private_host_same_subnet_and_distinct_addresses_required(self):
        variants = ({'server': '203.0.113.9'}, {'client': '10.70.5.31'},
                    {'client': '10.70.4.0'}, {'client': '10.70.4.255'},
                    {'server': '10.70.4.0'}, {'server': '10.70.4.255'},
                    {'client': SERVER})
        for variant in variants:
            value = exchange()
            value.start(1)
            self.check_error('allocation_invalid', lambda: value.accept_offer(response(**variant), 2))

    def test_ack_cannot_drift_server_address_or_mask(self):
        for variant in ({'server': '10.70.4.8'}, {'client': '10.70.4.32'},
                        {'mask': '255.255.0.0'}):
            value = requesting()
            self.check_error('ack_drift', lambda: value.accept_ack(response(wire.ACK, **variant), 3))
            self.assertEqual(value.status(3)['stage'], 'requesting')

    def test_zero_lease_rejected_offer_and_ack(self):
        value = exchange()
        value.start(1)
        self.check_error('lease_invalid', lambda: value.accept_offer(response(lease=0), 2))
        value = requesting()
        self.check_error('lease_invalid', lambda: value.accept_ack(response(wire.ACK, lease=0), 3))

    def test_lease_timers_valid_optional(self):
        for extras in ({58: u32(10)}, {59: u32(50)}, {58: u32(10), 59: u32(50)}, {}):
            value = requesting()
            self.assertIsNotNone(value.accept_ack(response(wire.ACK, extras=extras), 3))

    def test_lease_timers_invalid_offer_and_ack(self):
        for extras in ({58: u32(0)}, {59: u32(60)}, {58: u32(61)},
                       {58: u32(40), 59: u32(20)}, {58: u32(20), 59: u32(20)}):
            for kind in (wire.OFFER, wire.ACK):
                value = exchange() if kind == wire.OFFER else requesting()
                if kind == wire.OFFER:
                    value.start(1)
                accept = value.accept_offer if kind == wire.OFFER else value.accept_ack
                self.check_error('lease_timers_invalid', lambda: accept(response(kind, extras=extras), 3))

    def test_discover_retries_exact_bytes_and_no_early_retry(self):
        value = exchange()
        initial = value.start(1)
        self.assertIsNone(value.tick(1.9))
        self.assertEqual(value.tick(2), initial)
        self.assertEqual(value.tick(3), initial)
        self.assertIsNone(value.tick(4))
        self.assertEqual(value.status(4)['reason'], 'discover_attempt_limit')
        self.assertEqual(value.status(4)['discover_attempts'], 3)

    def test_request_retries_exact_bytes_and_no_xid_change(self):
        value = exchange()
        value.start(1)
        request = value.accept_offer(response(), 2)
        self.assertIsNone(value.tick(2.9))
        self.assertEqual(value.tick(3), request)
        self.assertEqual(value.tick(4), request)
        self.assertIsNone(value.tick(5))
        self.assertEqual(value.status(5)['reason'], 'request_attempt_limit')
        self.assertEqual(value.status(5)['request_attempts'], 3)

    def test_tick_no_burst_catchup(self):
        value = exchange()
        packet = value.start(1)
        self.assertEqual(value.tick(50), packet)
        self.assertIsNone(value.tick(50))
        self.assertEqual(value.status(50)['discover_attempts'], 2)

    def test_single_attempt_budgets_wait_one_interval_then_terminal(self):
        value = exchange(max_discovers=1, max_requests=1)
        value.start(1)
        self.assertIsNone(value.tick(1.5))
        value.accept_offer(response(), 1.6)
        self.assertIsNone(value.tick(2.6))
        self.assertEqual(value.status(2.6)['stage'], 'timed_out')

    def test_deadline_stops_new_exchange_or_active_exchange(self):
        value = exchange(deadline=1)
        self.check_error('stage_mismatch', lambda: value.start(1))
        self.assertEqual(value.status(1)['reason'], 'transaction_timeout')
        value = requesting(deadline=4)
        self.check_error('stage_mismatch', lambda: value.accept_ack(response(wire.ACK), 4))
        self.assertIsNone(value.configuration(4))

    def test_cancel_idempotent_and_never_returns_late_packets(self):
        for factory in (exchange, requesting, bound):
            value = factory()
            value.cancel()
            value.cancel()
            self.assertIsNone(value.tick(4))
            self.assertIsNone(value.configuration(4))
            self.check_error('stage_mismatch', lambda: value.start(4))
            self.check_error('stage_mismatch', lambda: value.accept_offer(response(), 4))
            self.check_error('stage_mismatch', lambda: value.accept_ack(response(wire.ACK), 4))
            self.assertEqual(value.status(4)['stage'], 'cancelled')

    def test_duplicate_offer_and_ack_not_repin_or_extend(self):
        value = requesting()
        self.check_error('stage_mismatch', lambda: value.accept_offer(
            response(server='10.70.4.8'), 3))
        config = value.accept_ack(response(wire.ACK), 3)
        self.check_error('stage_mismatch', lambda: value.accept_ack(response(wire.ACK, lease=90), 4))
        self.assertEqual(value.configuration(4), config)

    def test_cross_stage_message_types_rejected(self):
        value = exchange()
        value.start(1)
        self.check_error('unexpected_message_type', lambda: value.accept_offer(response(wire.ACK), 2))
        value.accept_offer(response(), 2)
        self.check_error('unexpected_message_type', lambda: value.accept_ack(response(), 3))

    def test_packet_budget_saturates_and_cannot_resurrect(self):
        value = exchange(max_packets=2)
        value.start(1)
        for _ in range(2):
            self.check_error('invalid_packet', lambda: value.accept_offer(b'bad', 2))
        self.check_error('packet_budget', lambda: value.accept_offer(response(), 2))
        for _ in range(5):
            self.check_error('stage_mismatch', lambda: value.accept_offer(response(), 2))
        self.assertEqual(value.status(2)['packets_received'], 3)
        self.assertIsNone(value.configuration(2))

    def test_invalid_constructor_mac_xid_deadline_interval_budget(self):
        for mac in (b'', b'\0' * 6, b'\x01' + MAC[1:], bytearray(MAC), 'private'):
            self.check_error('invalid_mac', lambda: core.DynamicClientExchange(mac, 10, xid=XID))
        for xid in (True, 0, -1, 2 ** 32, 1.0, float('nan'), float('inf'), 10 ** 1000):
            self.check_error('invalid_xid', lambda: exchange(xid=xid))
        for item in (True, -1, float('nan'), float('inf'), 2 ** 53 + 1, 10 ** 1000, 'private'):
            self.check_error('invalid_deadline', lambda: exchange(deadline=item))
        for item in (True, 0, 0.09, 5.1, float('nan'), float('inf'), 10 ** 1000):
            self.check_error('invalid_retry_interval', lambda: exchange(retry_interval=item))
        for key, high in (('max_discovers', 8), ('max_requests', 8), ('max_packets', 64)):
            for item in (True, 0, high + 1, 1.0, float('nan'), float('inf'), 10 ** 1000):
                self.check_error('invalid_budget', lambda: exchange(**{key: item}))

    def test_default_xid_once_and_zero_random_maps_one(self):
        with mock.patch.object(core.os, 'urandom', return_value=b'\0' * 4) as random_bytes:
            value = core.DynamicClientExchange(MAC, 100)
            packet = value.start(1)
            self.assertEqual(wire.decode(packet)['xid'], 1)
            self.assertEqual(value.tick(2), packet)
            random_bytes.assert_called_once_with(4)

    def test_entropy_failure_is_fixed_and_has_no_unsafe_fallback(self):
        with mock.patch.object(core.os, 'urandom', side_effect=OSError('private-text')):
            self.check_error('entropy_unavailable', lambda: core.DynamicClientExchange(MAC, 100))
        for invalid in (b'', bytearray(b'1234'), 'private-text'):
            with mock.patch.object(core.os, 'urandom', return_value=invalid):
                self.check_error('entropy_unavailable', lambda: core.DynamicClientExchange(MAC, 100))

    def test_invalid_time_clears_bound_config_and_rejects_overflow(self):
        for item in (True, -1, float('nan'), float('inf'), 2 ** 53 + 1, 10 ** 1000, 'private'):
            value = bound()
            self.check_error('invalid_time', lambda: value.configuration(item))
            self.assertIsNone(value.configuration(4))
            self.assertEqual(value.status(4)['reason'], 'invalid_time')

    def test_clock_backward_fails_closed(self):
        value = bound()
        value.status(5)
        self.check_error('clock_moved_backwards', lambda: value.configuration(4))
        self.assertIsNone(value.configuration(5))
        self.assertEqual(value.status(5)['stage'], 'failed')

    def test_status_exact_fixed_schema_and_no_addresses_identifiers(self):
        value = bound()
        status = value.status(4)
        self.assertEqual(set(status), {'stage', 'reason', 'discover_attempts', 'request_attempts',
            'packets_received', 'usable_lease_remaining', 'configuration_available',
            'interface_configured', 'endpoint_verified', 'default_route_installed', 'dns_installed'})
        for secret in (SERVER, CLIENT, MASK, str(XID), MAC.hex()):
            self.assertNotIn(secret, repr(status))
        status['stage'] = 'fake'
        self.assertEqual(value.status(4)['stage'], 'bound')

    def test_wire_duplicate_truncated_relay_critical_length_and_overload(self):
        header = response()[:240]
        cases = (header + b'\x35\x01\x02\x35\x01\x02\xff',
                 header + b'\x35\x01\x02\x36\x04\x01',
                 header + b'\x35\x01\x02\x36\x03\x01\x02\x03\xff',
                 header + b'\x35\x01\x02\x34\x01\x01\xff',
                 response()[:3] + b'\x01' + response()[4:],
                 response()[:24] + wire.ipv4('10.70.4.1') + response()[28:],
                 b'', response()[:239], response() + b'\x01', b'x' * 1473)
        for packet in cases:
            value = exchange()
            value.start(1)
            self.check_error('invalid_packet', lambda: value.accept_offer(packet, 2))

    def test_bounded_malformed_samples_only_fixed_errors(self):
        rng = random.Random(20261001)
        for _ in range(128):
            packet = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 1500)))
            value = exchange()
            value.start(1)
            try:
                value.accept_offer(packet, 2)
            except core.DhcpClientError as error:
                self.assertIn(str(error), core.ERROR_CODES)
            else:
                self.fail('synthetic garbage unexpectedly accepted')

    def test_no_socket_creation_in_any_exchange_operation(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')):
            value = exchange()
            value.start(1)
            value.tick(2)
            value.accept_offer(response(), 2)
            value.tick(3)
            value.accept_ack(response(wire.ACK), 3)
            value.configuration(4)
            value.status(4)
            value.cancel()
            value.tick(5)
            value.configuration(5)

    def test_safe_exception_class_never_accepts_arbitrary_text(self):
        for value in ('peer-private-secret', [], {}, True, None):
            self.assertEqual(str(core.DhcpClientError(value)), 'invalid_packet')

    def test_python35_syntax_and_no_mutation_imports(self):
        source = (PROJECT / 'runtime' / 'mta_dhcp_client_core.py').read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {'math', 'os', 'struct', 'collections', 'mta_dhcp'})
        self.assertNotIn('print(', source)
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
