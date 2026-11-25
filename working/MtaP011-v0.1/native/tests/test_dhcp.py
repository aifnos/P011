"""Pure HOST DHCP protocol QA: no socket, address, route, DNS, or RF operations."""
import random
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime'))
import mta_dhcp as d

MAC = b'\x02\x00\x00\x00\x00\x01'
OTHER = b'\x02\x00\x00\x00\x00\x02'
SERVER, CLIENT, MASK = '192.168.49.1', '192.168.49.2', '255.255.255.0'


def response(kind=d.OFFER, xid=99, mac=MAC, client=CLIENT, server=SERVER, mask=MASK, lease=100, client_id=b'\x01' + MAC):
    options = {53: bytes((kind,)), 54: d.ipv4(server)}
    if kind in (d.OFFER, d.ACK):
        options.update({1: d.ipv4(mask), 51: struct.pack('!I', lease)})
    if client_id is not None:
        options[61] = client_id
    return d.encode(2, xid, mac, options, yiaddr=d.ipv4(client) if kind != d.NAK else d.ZERO)


class CodecTests(unittest.TestCase):
    def packet(self):
        return d.encode(1, 99, MAC, {53: b'\x01', 61: b'\x01' + MAC})

    def test_wire_roundtrip(self):
        packet = self.packet(); decoded = d.decode(packet)
        self.assertEqual(len(packet), 300); self.assertEqual(d.HEADER.size, 236)
        self.assertEqual(decoded['type'], d.DISCOVER); self.assertEqual(decoded['xid'], 99)
        self.assertEqual(decoded['chaddr'], MAC)

    def test_size_cookie_envelope_bounds(self):
        packet = self.packet()
        for candidate in (b'', packet[:239], packet + b'\0' * 1472, packet[:236] + b'abcd' + packet[240:]):
            with self.assertRaises(d.DhcpError): d.decode(candidate)
        for offset, value in ((0, 3), (1, 2), (2, 16), (3, 1)):
            candidate = bytearray(packet); candidate[offset] = value
            with self.assertRaises(d.DhcpError): d.decode(bytes(candidate))
        candidate = bytearray(packet); candidate[24] = 1
        with self.assertRaises(d.DhcpError): d.decode(bytes(candidate))

    def test_invalid_flags_and_xid(self):
        packet = bytearray(self.packet()); packet[10:12] = b'\0\x01'
        with self.assertRaises(d.DhcpError): d.decode(bytes(packet))
        packet = bytearray(self.packet()); packet[4:8] = d.ZERO
        with self.assertRaises(d.DhcpError): d.decode(bytes(packet))

    def test_mac_rejected_when_multicast_or_zero(self):
        for mac in (b'\0' * 6, b'\xff' * 6, b'\x01' + b'\0' * 5, b'12345'):
            with self.assertRaises(d.DhcpError): d.encode(1, 1, mac, {53: b'\x01'})

    def test_duplicate_and_truncated_options(self):
        head = self.packet()[:240]
        for options in (b'\x35\x01\x01\x35\x01\x01\xff', b'\x35', b'\x35\x04\x01', b'\x35\x01\x01'):
            with self.assertRaises(d.DhcpError): d.decode(head + options)

    def test_nonpadding_after_end(self):
        with self.assertRaises(d.DhcpError): d.decode(self.packet()[:240] + b'\x35\x01\x01\xff\x01')

    def test_option_limits_and_critical_lengths(self):
        head = self.packet()[:240]
        for kind, length in d.CRITICAL_LENGTHS.items():
            options = {53: b'\x01', kind: b'\0' * (length + 1)}
            with self.assertRaises(d.DhcpError): d.encode(1, 1, MAC, options)
        with self.assertRaises(d.DhcpError): d.decode(head + b'\x35\x01\x01' + b''.join(bytes((n, 1, 1)) for n in range(1, 131) if n != 53) + b'\xff')

    def test_overload_and_invalid_client_id(self):
        for extra in ({52: b'\x01'}, {61: b'x'}, {61: b'x' * 65}, {55: b'x' * 65}, {57: b'\0\x01'}):
            options = {53: b'\x01'}; options.update(extra)
            with self.assertRaises(d.DhcpError): d.encode(1, 1, MAC, options)

    def test_rapid_commit_is_ignored_not_granted(self):
        packet = d.encode(1, 99, MAC, {53: b'\x01', 80: b''})
        server = d.SingleClientServer(SERVER, CLIENT, MASK, 120)
        self.assertEqual(d.decode(server.handle(packet, 100))['type'], d.OFFER)

    def test_private_subnet_only(self):
        for server, client, mask in (('127.0.0.1', '127.0.0.2', MASK), ('8.8.8.1', '8.8.8.2', MASK),
                (SERVER, '192.168.50.2', MASK), (SERVER, '192.168.49.255', MASK),
                (SERVER, SERVER, MASK), (SERVER, CLIENT, '255.0.255.0'), (SERVER, CLIENT, '255.255.255.255')):
            with self.assertRaises(d.DhcpError): d.SingleClientServer(server, client, mask, 120)
        for bad in ('010.0.0.1', '256.0.0.1', '1.1.1', '1.1.1.1\n', '1.1.1.1x'):
            with self.assertRaises(d.DhcpError): d.ipv4(bad)
        with self.assertRaises(d.DhcpError): d.prefix(b'x')

    def test_adversarial_packet_fuzz_only_symbolic_errors(self):
        rng = random.Random(300)
        base = self.packet()
        for i in range(20000):
            if i % 2:
                candidate = bytearray(base)
                for _ in range(rng.randrange(1, 10)):
                    candidate[rng.randrange(len(candidate))] = rng.randrange(256)
                candidate = bytes(candidate)
            else:
                candidate = bytes(bytearray(rng.randrange(256) for _ in range(rng.randrange(0, 1600))))
            try: d.decode(candidate)
            except d.DhcpError as error:
                self.assertRegex(str(error), r'^[a-z_]+$')


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.server = d.SingleClientServer(SERVER, CLIENT, MASK, deadline=120, expected_mac=MAC)
        self.client = d.ClientExchange(MAC, SERVER, MASK, deadline=118, xid=99)

    def handshake(self):
        discover = self.client.discover(100)
        offer = self.server.handle(discover, 101)
        request = self.client.accept_offer(offer, 102)
        ack = self.server.handle(request, 103)
        return self.client.accept_ack(ack, 104)

    def test_dora_remaining_not_fictional_lease(self):
        result = self.handshake()
        self.assertEqual(result['local_ip'], CLIENT); self.assertEqual(result['server_ip'], SERVER)
        self.assertEqual(result['usable_until'], 118)
        self.assertEqual(result['server_lease_seconds'], 17)
        self.assertFalse(self.client.status(104)['interface_configured'])
        self.assertEqual(self.server.status(104)['lease_remaining'], 16)

    def test_no_socket_or_shell_side_effects(self):
        with patch('socket.socket', side_effect=AssertionError('no socket allowed')):
            self.handshake()

    def test_server_does_not_send_default_router_or_dns(self):
        reply = d.decode(self.server.handle(self.client.discover(100), 101))
        self.assertNotIn(3, reply['options']); self.assertNotIn(6, reply['options'])
        self.assertEqual(reply['options'][61], b'\x01' + MAC)

    def test_server_one_client_limit(self):
        self.server.handle(self.client.discover(100), 101)
        other = d.ClientExchange(OTHER, SERVER, MASK, 118, xid=100)
        self.assertIsNone(self.server.handle(other.discover(102), 103))
        same_mac_other_id = d.encode(1, 100, MAC, {53: b'\x01', 61: b'\x01' + OTHER})
        self.assertIsNone(self.server.handle(same_mac_other_id, 103))

    def test_server_requires_prior_offer_matching_xid_address_server(self):
        self.server.handle(self.client.discover(100), 101)
        for xid, wanted, owner in ((100, CLIENT, SERVER), (99, '192.168.49.3', SERVER), (99, CLIENT, '192.168.49.5')):
            request = d.encode(1, xid, MAC, {53: b'\x03', 61: b'\x01' + MAC, 50: d.ipv4(wanted), 54: d.ipv4(owner)})
            self.assertIsNone(self.server.handle(request, 102))
        empty = d.SingleClientServer(SERVER, CLIENT, MASK, 120)
        self.assertIsNone(empty.handle(self.client.accept_offer(response(), 102), 103))

    def test_server_deadline_has_no_zero_or_infinite_lease_reply(self):
        discover = self.client.discover(100)
        self.assertIsNone(self.server.handle(discover, 119.1))
        self.assertIsNone(self.server.handle(discover, 120))
        self.assertEqual(d.decode(self.server.handle(discover, 118))['options'][51], struct.pack('!I', 2))

    def test_release_frees_only_matching_client(self):
        self.handshake()
        options = {53: b'\x07', 54: d.ipv4(SERVER), 61: b'\x01' + OTHER}
        self.assertIsNone(self.server.handle(d.encode(1, 800, MAC, options, ciaddr=d.ipv4(CLIENT)), 105))
        self.assertTrue(self.server.bound)
        options[61] = b'\x01' + MAC
        self.server.handle(d.encode(1, 800, MAC, options, ciaddr=d.ipv4(CLIENT)), 106)
        self.assertFalse(self.server.bound); self.assertIsNone(self.server.key)

    def test_decline_prevents_reuse_until_new_actual_lease(self):
        self.server.handle(self.client.discover(100), 101)
        self.server.handle(d.encode(1, 99, MAC, {53: b'\x04', 54: d.ipv4(SERVER), 50: d.ipv4(CLIENT), 61: b'\x01' + MAC}), 102)
        self.assertTrue(self.server.declined)
        self.assertIsNone(self.server.handle(self.client.discover(103), 104))

    def test_client_xid_mac_server_id_clientid_checks(self):
        self.client.discover(100)
        for packet in (response(xid=100), response(mac=OTHER), response(server='192.168.49.3'), response(client_id=b'\x01' + OTHER)):
            with self.assertRaises(d.DhcpError): self.client.accept_offer(packet, 101)
        self.assertEqual(self.client.state, 'selecting')

    def test_client_subnet_and_network_broadcast_checks(self):
        self.client.discover(100)
        for packet in (response(client='192.168.50.2'), response(client='192.168.49.0'), response(client='192.168.49.255'),
                       response(client=SERVER), response(mask='255.255.0.0'), response(lease=0)):
            with self.assertRaises(d.DhcpError): self.client.accept_offer(packet, 101)

    def test_client_ack_cannot_change_offer(self):
        self.client.discover(100); self.client.accept_offer(response(), 101)
        with self.assertRaises(d.DhcpError): self.client.accept_ack(response(kind=d.ACK, client='192.168.49.3'), 102)
        self.assertEqual(self.client.state, 'requesting')

    def test_expected_nak_rejects_no_configuration(self):
        self.client.discover(100); self.client.accept_offer(response(), 101)
        with self.assertRaisesRegex(d.DhcpError, 'expected_server_rejected_request'):
            self.client.accept_ack(response(kind=d.NAK), 102)
        self.assertEqual(self.client.state, 'rejected'); self.assertIsNone(self.client.configuration)

    def test_unknown_nak_does_not_reject_exchange(self):
        self.client.discover(100); self.client.accept_offer(response(), 101)
        with self.assertRaises(d.DhcpError): self.client.accept_ack(response(kind=d.NAK, server='192.168.49.5'), 102)
        self.assertEqual(self.client.state, 'requesting')

    def test_client_accepts_missing_echo_but_not_wrong_client_id(self):
        self.client.discover(100)
        self.client.accept_offer(response(client_id=None), 101)
        result = self.client.accept_ack(response(kind=d.ACK, client_id=None), 102)
        self.assertEqual(result['local_ip'], CLIENT)

    def test_server_long_lease_capped_by_owned_deadline(self):
        self.client.discover(100); self.client.accept_offer(response(lease=0xffffffff), 101)
        self.assertEqual(self.client.accept_ack(response(kind=d.ACK, lease=0xffffffff), 102)['usable_until'], 118)

    def test_deadline_and_time_validation(self):
        for value in (float('nan'), float('inf'), -1, True, 10 ** 400):
            with self.assertRaises(d.DhcpError): self.client.discover(value)
        with self.assertRaises(d.DhcpError): self.client.discover(118)
        self.assertEqual(self.client.state, 'expired')

    def test_invalid_state_rejects_unsolicited_ack(self):
        with self.assertRaises(d.DhcpError): self.client.accept_ack(response(kind=d.ACK), 100)
        with self.assertRaises(d.DhcpError): self.client.accept_offer(response(), 100)
        with self.assertRaises(d.DhcpError): self.client.request(100)

    def test_expired_ack_has_no_usable_configuration(self):
        self.handshake()
        self.assertEqual(self.client.status(118)['stage'], 'expired')
        self.assertIsNone(self.client.configuration)


if __name__ == '__main__':
    unittest.main()
