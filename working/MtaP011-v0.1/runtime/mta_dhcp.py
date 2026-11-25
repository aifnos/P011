# -*- coding: utf-8 -*-
"""Bounded DHCP wire/state core; never creates sockets or changes interfaces.

This is NOT a verified P011 DHCP backend. The caller must independently own a
P2P interface and IP lease. All packet/client/address values are private; this
module has no logging, shell commands, routes, DNS, timers, or radio operations.
RFC 2131/2132, Ethernet BOOTP only, no relay/option-overload support.
Compatible with the stripped device Python 3.5 standard library.
"""
import math
import os
import re
import socket
import struct

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
COOKIE = b'\x63\x82\x53\x63'
HEADER = struct.Struct('!BBBBIHH4s4s4s4s16s64s128s')
ZERO = b'\0' * 4
MAX_PACKET = 1472
MAX_OPTIONS = 128
CRITICAL_LENGTHS = {1: 4, 50: 4, 51: 4, 53: 1, 54: 4, 57: 2, 58: 4, 59: 4}


class DhcpError(ValueError):
    """Symbolic error only: never insert packet, MAC, client-id or IP values."""


def _integer(value, low, high, reason):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DhcpError(reason)
    return value


def _clock(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not 0 <= value <= 2 ** 53 or not math.isfinite(value)):
        raise DhcpError('invalid_monotonic_time')
    return float(value)


def ipv4(value):
    if not isinstance(value, str) or not re.match(r'^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\Z', value):
        raise DhcpError('invalid_ipv4')
    parts = [int(p) for p in value.split('.')]
    if any(p > 255 for p in parts):
        raise DhcpError('invalid_ipv4')
    return bytes(bytearray(parts))


def address(value):
    if not isinstance(value, bytes) or len(value) != 4:
        raise DhcpError('invalid_ipv4_bytes')
    return socket.inet_ntoa(value)


def _number(value):
    return struct.unpack('!I', value)[0]


def _private(value):
    number = _number(value)
    return (number >> 24 == 10 or number >> 20 == 0xac1 or number >> 16 == 0xc0a8)


def prefix(mask):
    packed = ipv4(mask) if isinstance(mask, str) else mask
    if not isinstance(packed, bytes) or len(packed) != 4:
        raise DhcpError('invalid_subnet_mask')
    number = _number(packed)
    inverse = number ^ 0xffffffff
    if inverse & (inverse + 1):
        raise DhcpError('noncontiguous_subnet_mask')
    bits = bin(number).count('1')
    if not 8 <= bits <= 30:
        raise DhcpError('subnet_prefix_out_of_scope')
    return bits


def _subnet(ip, server, mask):
    candidate, owner, netmask = _number(ip), _number(server), _number(mask)
    network = owner & netmask
    if (not _private(ip) or not _private(server) or candidate & netmask != network or
            candidate in (network, network | (netmask ^ 0xffffffff)) or
            owner in (network, network | (netmask ^ 0xffffffff))):
        raise DhcpError('address_outside_expected_private_subnet')


def _mac(value):
    if not isinstance(value, bytes) or len(value) != 6 or value == b'\0' * 6 or value[0] & 1:
        raise DhcpError('invalid_ethernet_client_address')
    return value


def _validate_options(options):
    if not isinstance(options, dict) or len(options) > MAX_OPTIONS:
        raise DhcpError('invalid_options_container')
    for kind, value in options.items():
        _integer(kind, 1, 254, 'invalid_option_code')
        if not isinstance(value, bytes) or not 0 <= len(value) <= 255 or not value and kind != 80:
            raise DhcpError('invalid_option_value')
        if kind == 80 and value:
            raise DhcpError('invalid_rapid_commit_option')
        if kind in CRITICAL_LENGTHS and len(value) != CRITICAL_LENGTHS[kind]:
            raise DhcpError('invalid_critical_option_length')
        if kind == 52:
            raise DhcpError('option_overload_not_supported')
        if kind == 61 and not 2 <= len(value) <= 64:
            raise DhcpError('invalid_client_identifier_length')
        if kind == 55 and len(value) > 64:
            raise DhcpError('parameter_request_list_limit')
        if kind == 57 and struct.unpack('!H', value)[0] < 576:
            raise DhcpError('client_maximum_message_too_small')
    if options.get(53) not in tuple(bytes(bytearray((n,))) for n in range(1, 9)):
        raise DhcpError('dhcp_message_type_missing_or_invalid')


def decode(packet):
    """Return private, bounded BOOTP fields. Reject duplicates, relay and truncation."""
    if not isinstance(packet, bytes) or not 240 <= len(packet) <= MAX_PACKET:
        raise DhcpError('dhcp_packet_size_invalid')
    op, htype, hlen, hops, xid, secs, flags, ci, yi, si, gi, chaddr, _, _ = HEADER.unpack_from(packet)
    if op not in (1, 2) or htype != 1 or hlen != 6 or hops != 0 or gi != ZERO:
        raise DhcpError('unsupported_bootp_envelope')
    if xid == 0 or flags & ~0x8000:
        raise DhcpError('invalid_bootp_transaction')
    _mac(chaddr[:6])
    if packet[236:240] != COOKIE:
        raise DhcpError('dhcp_cookie_invalid')
    options = {}; at = 240; ended = False; count = 0
    while at < len(packet):
        kind = packet[at]; at += 1
        if kind == 0:
            continue
        if kind == 255:
            ended = True
            if any(packet[at:]):
                raise DhcpError('nonpadding_after_end')
            break
        count += 1
        if count > MAX_OPTIONS or at >= len(packet):
            raise DhcpError('dhcp_option_limit_or_truncated')
        length = packet[at]; at += 1
        if at + length > len(packet) or kind in options:
            raise DhcpError('dhcp_option_duplicate_or_truncated')
        options[kind] = packet[at:at + length]; at += length
    if not ended:
        raise DhcpError('dhcp_option_end_missing')
    _validate_options(options)
    return {'op': op, 'xid': xid, 'secs': secs, 'flags': flags, 'ciaddr': ci,
            'yiaddr': yi, 'siaddr': si, 'chaddr': chaddr[:6], 'options': options,
            'type': options[53][0]}


def encode(op, xid, mac, options, ciaddr=ZERO, yiaddr=ZERO, siaddr=ZERO, broadcast=True):
    _integer(op, 1, 2, 'invalid_bootp_operation')
    _integer(xid, 1, 0xffffffff, 'invalid_transaction_id'); _mac(mac)
    _validate_options(options)
    for value in (ciaddr, yiaddr, siaddr):
        if not isinstance(value, bytes) or len(value) != 4:
            raise DhcpError('invalid_bootp_address_length')
    if not isinstance(broadcast, bool):
        raise DhcpError('invalid_broadcast_flag')
    body = HEADER.pack(op, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0,
                       ciaddr, yiaddr, siaddr, ZERO, mac + b'\0' * 10, b'\0' * 64, b'\0' * 128)
    body += COOKIE
    for kind in sorted(options):
        value = options[kind]
        body += bytes(bytearray((kind, len(value)))) + value
    body += b'\xff'
    if len(body) > MAX_PACKET:
        raise DhcpError('encoded_packet_limit')
    return body + b'\0' * max(0, 300 - len(body))


def _client_key(message):
    return message['chaddr'], message['options'].get(61)


class SingleClientServer:
    """Pure one-address state machine. Deadline comes from the actual owned lease.

    Replies contain subnet/server/remaining lease, never default-router or DNS.
    The transport must validate ingress interface, UDP source port 68 and an
    independently admitted WPA station. A DHCP identity is not authentication.
    """
    def __init__(self, server_ip, client_ip, subnet_mask, deadline, expected_mac=None):
        self.server = ipv4(server_ip); self.client = ipv4(client_ip); self.mask = ipv4(subnet_mask)
        prefix(self.mask); _subnet(self.client, self.server, self.mask)
        if self.server == self.client:
            raise DhcpError('server_and_client_address_equal')
        self.deadline = _clock(deadline)
        self.expected_mac = _mac(expected_mac) if expected_mac is not None else None
        self.key = None; self.offered_xid = None; self.bound = False; self.declined = False

    def remaining(self, now):
        return max(0, int(self.deadline - _clock(now)))

    def _reply(self, message, kind, now):
        remaining = self.remaining(now)
        if not remaining:
            return None
        options = {53: bytes(bytearray((kind,))), 54: self.server}
        if kind in (OFFER, ACK):
            options.update({1: self.mask, 51: struct.pack('!I', remaining)})
        if 61 in message['options']:
            options[61] = message['options'][61]
        return encode(2, message['xid'], message['chaddr'], options,
                      yiaddr=self.client if kind in (OFFER, ACK) else ZERO,
                      siaddr=self.server, broadcast=True)

    def handle(self, packet, now):
        """Return a broadcast reply packet or None. No peers/packets are logged."""
        message = decode(packet); options = message['options']; kind = message['type']
        if (message['op'] != 1 or not self.remaining(now) or self.declined or
                message['yiaddr'] != ZERO or message['siaddr'] != ZERO or
                self.expected_mac is not None and message['chaddr'] != self.expected_mac):
            return None
        key = _client_key(message)
        if self.key is not None and key != self.key:
            return None
        if kind == DISCOVER:
            if message['ciaddr'] != ZERO or 54 in options:
                return None
            self.key = key; self.offered_xid = message['xid']
            return self._reply(message, OFFER, now)
        if self.key is None:
            return None
        if kind == REQUEST:
            selecting = (message['ciaddr'] == ZERO and options.get(54) == self.server and
                         options.get(50) == self.client and message['xid'] == self.offered_xid)
            renewing = (self.bound and message['ciaddr'] == self.client and 50 not in options and
                        (54 not in options or options[54] == self.server))
            rebooting = (self.bound and message['ciaddr'] == ZERO and 54 not in options and options.get(50) == self.client)
            if selecting or renewing or rebooting:
                self.bound = True
                return self._reply(message, ACK, now)
            # Ignore another server's selection or unknown addresses. A broad NAK
            # could disrupt a peer's other interfaces, so no speculative NAK.
            return None
        if kind == RELEASE and self.bound and message['ciaddr'] == self.client and options.get(54) == self.server:
            self.key = None; self.offered_xid = None; self.bound = False
        elif (kind == DECLINE and message['xid'] == self.offered_xid and
              options.get(54) == self.server and options.get(50) == self.client):
            # Address conflict: never reuse or fabricate successful allocation.
            self.declined = True; self.bound = False
        return None

    def status(self, now):
        return {'stage': 'declined' if self.declined else 'bound' if self.bound else 'offered' if self.key else 'idle',
                'lease_remaining': self.remaining(now), 'client_limit': 1,
                'default_route_supplied': False, 'dns_supplied': False}


class ClientExchange:
    """Pure fresh DORA exchange, strict expected private server/subnet.

    Receiving ACK returns private configuration; it does NOT install an IP,
    route, DNS or infer phone authentication. The adapter must read back an
    independently owned IP lease before advertising a usable data path.
    """
    def __init__(self, mac, expected_server, expected_mask, deadline, xid=None):
        self.mac = _mac(mac); self.server = ipv4(expected_server); self.mask = ipv4(expected_mask)
        self.prefix = prefix(self.mask); _subnet(self.server, self.server, self.mask)
        self.deadline = _clock(deadline)
        self.xid = _integer(xid if xid is not None else _number(os.urandom(4)) or 1,
                            1, 0xffffffff, 'invalid_transaction_id')
        self.client_id = b'\x01' + mac; self.offer = None; self.state = 'new'; self.configuration = None

    def _alive(self, now):
        if _clock(now) >= self.deadline:
            self.state = 'expired'; self.configuration = None
            raise DhcpError('dhcp_exchange_deadline_expired')

    def discover(self, now):
        self._alive(now)
        if self.state not in ('new', 'selecting'):
            raise DhcpError('discover_in_invalid_state')
        self.state = 'selecting'
        return encode(1, self.xid, self.mac, {53: b'\x01', 61: self.client_id,
                      55: b'\x01\x33\x36', 57: struct.pack('!H', MAX_PACKET)})

    def _response(self, packet):
        message = decode(packet); options = message['options']
        if (message['op'] != 2 or message['xid'] != self.xid or message['chaddr'] != self.mac or
                message['ciaddr'] != ZERO or options.get(54) != self.server or
                61 in options and options[61] != self.client_id or
                message['siaddr'] not in (ZERO, self.server)):
            raise DhcpError('dhcp_response_identity_mismatch')
        return message

    def _allocation(self, message):
        options = message['options']; assigned = message['yiaddr']
        if options.get(1) != self.mask or assigned == self.server:
            raise DhcpError('dhcp_response_subnet_mismatch')
        _subnet(assigned, self.server, self.mask)
        lease = _number(options.get(51, ZERO))
        if lease == 0:
            raise DhcpError('dhcp_lease_missing_or_zero')
        return assigned, lease

    def accept_offer(self, packet, now):
        self._alive(now)
        if self.state != 'selecting':
            raise DhcpError('offer_in_invalid_state')
        message = self._response(packet)
        if message['type'] != OFFER:
            raise DhcpError('expected_offer')
        self.offer, _ = self._allocation(message); self.state = 'requesting'
        return self.request(now)

    def request(self, now):
        self._alive(now)
        if self.state != 'requesting' or self.offer is None:
            raise DhcpError('request_in_invalid_state')
        return encode(1, self.xid, self.mac, {53: b'\x03', 61: self.client_id,
                      50: self.offer, 54: self.server, 55: b'\x01\x33\x36'})

    def accept_ack(self, packet, now):
        self._alive(now)
        if self.state != 'requesting':
            raise DhcpError('ack_in_invalid_state')
        message = self._response(packet)
        if message['type'] == NAK:
            if message['yiaddr'] != ZERO:
                raise DhcpError('invalid_nak_address')
            self.state = 'rejected'; self.configuration = None
            raise DhcpError('expected_server_rejected_request')
        if message['type'] != ACK:
            raise DhcpError('expected_ack')
        assigned, seconds = self._allocation(message)
        if assigned != self.offer:
            raise DhcpError('ack_address_differs_from_offer')
        self.state = 'bound'
        self.configuration = {'local_ip': address(assigned), 'server_ip': address(self.server),
                              'prefix': self.prefix, 'usable_until': min(self.deadline, _clock(now) + seconds),
                              'server_lease_seconds': seconds}
        return dict(self.configuration)

    def status(self, now):
        now = _clock(now)
        remaining = max(0, int(self.configuration['usable_until'] - now)) if self.configuration else 0
        if now >= self.deadline or self.configuration and not remaining:
            self.state = 'expired'; self.configuration = None
        return {'stage': self.state, 'usable_lease_remaining': remaining,
                'interface_configured': False, 'default_route_installed': False, 'dns_installed': False}
