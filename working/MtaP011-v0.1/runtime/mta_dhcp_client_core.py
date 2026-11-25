# -*- coding: utf-8 -*-
"""Pure, bounded fresh DORA core. No sockets, address writes or peer proof.

Private packets/configurations must never be added to public logs. A returned
configuration is a historical immutable snapshot, not continuing permission;
the adapter must call configuration(now) and independently prove ingress, the
owned link/IP lease and the intended GO endpoint. This is not a complete DHCP
client: no renewal, rebind, release, relay, ARP conflict check or cached lease.
Compatible syntax: Python 3.5. Existing mta_dhcp wire profile remains unchanged.
"""
import math
import os
import struct
from collections import namedtuple

import mta_dhcp as wire


ERROR_CODES = frozenset((
    'invalid_mac', 'invalid_deadline', 'invalid_xid', 'invalid_retry_interval',
    'invalid_budget', 'invalid_time', 'clock_moved_backwards', 'stage_mismatch',
    'invalid_packet', 'identity_mismatch', 'server_identifier_invalid',
    'subnet_invalid', 'allocation_invalid', 'lease_invalid',
    'lease_timers_invalid', 'ack_drift', 'unexpected_message_type',
    'nak_invalid', 'server_nak', 'packet_budget', 'entropy_unavailable', 'transaction_timeout',
    'discover_attempt_limit', 'request_attempt_limit', 'allocation_expired'))
TERMINAL = frozenset(('rejected', 'cancelled', 'timed_out', 'expired', 'failed'))
PARAMETERS = b'\x01\x33\x36\x3a\x3b'
_Configuration = namedtuple('_Configuration', (
    'local_ip', 'server_ip', 'subnet_mask', 'prefix', 'usable_until',
    'server_lease_seconds'))


class DhcpClientError(ValueError):
    """Always a fixed symbolic code, never a packet or third-party error text."""
    def __init__(self, code):
        ValueError.__init__(self, code if type(code) is str and code in ERROR_CODES else 'invalid_packet')


def _integer(value, low, high, reason):
    if type(value) is not int or not low <= value <= high:
        raise DhcpClientError(reason)
    return value


def _finite(value, low, high, reason):
    # Bound before float conversion so enormous integers cannot overflow.
    if (type(value) not in (int, float) or not low <= value <= high or
            not math.isfinite(value)):
        raise DhcpClientError(reason)
    return float(value)


def _u32(value):
    return struct.unpack('!I', value)[0]


class DynamicClientExchange:
    """Select the first valid Offer; keep its server/address/mask for ACK.

    Each budget includes the initial transmission. tick() is a bounded fixed
    interval scheduling primitive, not RFC 2131's full randomized exponential
    retry policy. The caller must transmit each returned packet promptly, or
    discard this exchange. No method opens another transaction automatically.
    """
    def __init__(self, mac_bytes, deadline, xid=None, retry_interval=1.0,
                 max_discovers=3, max_requests=3, max_packets=64):
        if (type(mac_bytes) is not bytes or len(mac_bytes) != 6 or
                mac_bytes == b'\0' * 6 or mac_bytes[0] & 1):
            raise DhcpClientError('invalid_mac')
        self._mac = mac_bytes
        self._client_id = b'\x01' + mac_bytes
        self._deadline = _finite(deadline, 0, 2 ** 53, 'invalid_deadline')
        self._interval = _finite(retry_interval, 0.1, 5, 'invalid_retry_interval')
        self._max_discovers = _integer(max_discovers, 1, 8, 'invalid_budget')
        self._max_requests = _integer(max_requests, 1, 8, 'invalid_budget')
        self._max_packets = _integer(max_packets, 1, 64, 'invalid_budget')
        if xid is None:
            try:
                entropy = os.urandom(4)
            except OSError:
                raise DhcpClientError('entropy_unavailable') from None
            if type(entropy) is not bytes or len(entropy) != 4:
                raise DhcpClientError('entropy_unavailable')
            xid = _u32(entropy) or 1
        self._xid = _integer(xid, 1, 0xffffffff, 'invalid_xid')
        self._state = 'new'
        self._reason = 'not_recorded'
        self._last_now = None
        self._next_retry = None
        self._request_started = None
        self._offer = None
        self._configuration = None
        self._discovers = 0
        self._requests = 0
        self._packets = 0

    def _finish(self, stage, reason):
        if self._state not in TERMINAL:
            self._state = stage
            self._reason = reason
            self._configuration = None
            self._next_retry = None

    def _time(self, now):
        try:
            now = _finite(now, 0, 2 ** 53, 'invalid_time')
        except DhcpClientError:
            self._finish('failed', 'invalid_time')
            raise
        if self._last_now is not None and now < self._last_now:
            self._finish('failed', 'clock_moved_backwards')
            raise DhcpClientError('clock_moved_backwards')
        self._last_now = now
        if (self._state == 'bound' and self._configuration is not None and
                now >= self._configuration.usable_until):
            self._finish('expired', 'allocation_expired')
        elif self._state not in TERMINAL and now >= self._deadline:
            self._finish('timed_out', 'transaction_timeout')
        return now

    def _require(self, stage):
        if self._state != stage:
            raise DhcpClientError('stage_mismatch')

    def _consume(self, packet):
        self._packets = min(self._max_packets + 1, self._packets + 1)
        if self._packets > self._max_packets:
            self._finish('failed', 'packet_budget')
            raise DhcpClientError('packet_budget')
        try:
            message = wire.decode(packet)
        except wire.DhcpError:
            raise DhcpClientError('invalid_packet') from None
        options = message['options']
        if (message['op'] != 2 or message['xid'] != self._xid or
                message['chaddr'] != self._mac or message['ciaddr'] != wire.ZERO or
                61 in options and options[61] != self._client_id):
            raise DhcpClientError('identity_mismatch')
        return message

    def _server(self, message):
        server = message['options'].get(54)
        if type(server) is not bytes or len(server) != 4:
            raise DhcpClientError('server_identifier_invalid')
        return server

    def _allocation(self, message):
        options = message['options']
        server = self._server(message)
        mask = options.get(1)
        try:
            bits = wire.prefix(mask)
        except wire.DhcpError:
            raise DhcpClientError('subnet_invalid') from None
        assigned = message['yiaddr']
        try:
            wire._subnet(assigned, server, mask)
        except wire.DhcpError:
            raise DhcpClientError('allocation_invalid') from None
        if assigned == server:
            raise DhcpClientError('allocation_invalid')
        lease_bytes = options.get(51)
        if type(lease_bytes) is not bytes or len(lease_bytes) != 4:
            raise DhcpClientError('lease_invalid')
        seconds = _u32(lease_bytes)
        if seconds == 0:
            raise DhcpClientError('lease_invalid')
        timers = [None, None]
        for i, kind in enumerate((58, 59)):
            if kind in options:
                timers[i] = _u32(options[kind])
                if not 0 < timers[i] < seconds:
                    raise DhcpClientError('lease_timers_invalid')
        if timers[0] is not None and timers[1] is not None and timers[0] >= timers[1]:
            raise DhcpClientError('lease_timers_invalid')
        return (server, assigned, mask, bits), seconds

    def _discover(self):
        return wire.encode(1, self._xid, self._mac, {
            53: b'\x01', 61: self._client_id, 55: PARAMETERS,
            57: struct.pack('!H', wire.MAX_PACKET)})

    def _request(self):
        return wire.encode(1, self._xid, self._mac, {
            53: b'\x03', 61: self._client_id, 55: PARAMETERS,
            50: self._offer[1], 54: self._offer[0],
            57: struct.pack('!H', wire.MAX_PACKET)})

    def start(self, now):
        """Return private DISCOVER bytes; construction alone transmits nothing."""
        now = self._time(now)
        self._require('new')
        packet = self._discover()
        self._state = 'selecting'
        self._discovers = 1
        self._next_retry = now + self._interval
        return packet

    def accept_offer(self, packet, now):
        """Validate and pin a dynamic Offer; return private REQUEST bytes."""
        now = self._time(now)
        self._require('selecting')
        message = self._consume(packet)
        if message['type'] != wire.OFFER:
            raise DhcpClientError('unexpected_message_type')
        offer, _ = self._allocation(message)
        self._offer = offer  # Bytes/ints only, no caller-owned mutable pin.
        request = self._request()
        self._state = 'requesting'
        self._requests = 1
        self._request_started = now
        self._next_retry = now + self._interval
        return request

    def accept_ack(self, packet, now):
        """Return immutable allocation data only, never installed/verified proof."""
        now = self._time(now)
        self._require('requesting')
        message = self._consume(packet)
        server = self._server(message)
        if server != self._offer[0]:
            raise DhcpClientError('ack_drift')
        if message['type'] == wire.NAK:
            if message['yiaddr'] != wire.ZERO:
                raise DhcpClientError('nak_invalid')
            self._finish('rejected', 'server_nak')
            raise DhcpClientError('server_nak')
        if message['type'] != wire.ACK:
            raise DhcpClientError('unexpected_message_type')
        allocation, seconds = self._allocation(message)
        if allocation != self._offer:
            raise DhcpClientError('ack_drift')
        # RFC 2131 4.4.1: count the ACK lease from the ORIGINAL REQUEST, not
        # ACK arrival or a retransmission. No renewal occurs in this core.
        until = self._request_started + min(seconds, self._deadline - self._request_started)
        if now >= until:
            self._finish('expired', 'allocation_expired')
            raise DhcpClientError('allocation_expired')
        self._configuration = _Configuration(
            wire.address(allocation[1]), wire.address(allocation[0]),
            wire.address(allocation[2]), allocation[3], until, seconds)
        self._state = 'bound'
        self._next_retry = None
        return self._configuration

    def tick(self, now):
        """One due retry or None; no burst catch-up and no automatic new xid."""
        now = self._time(now)
        if self._state not in ('selecting', 'requesting') or now < self._next_retry:
            return None
        if self._state == 'selecting':
            if self._discovers >= self._max_discovers:
                self._finish('timed_out', 'discover_attempt_limit')
                return None
            packet = self._discover()
            self._discovers += 1
        else:
            if self._requests >= self._max_requests:
                self._finish('timed_out', 'request_attempt_limit')
                return None
            packet = self._request()
            self._requests += 1
        self._next_retry = now + self._interval
        return packet

    def cancel(self):
        """Invalidate active allocation locally; sends no RELEASE or other packet."""
        self._finish('cancelled', 'cancelled')

    def configuration(self, now):
        """Private current data or None; caller must not retain it as a proof."""
        self._time(now)
        return self._configuration if self._state == 'bound' else None

    def status(self, now):
        """Fixed nonsecret schema, independent of the private allocation values."""
        now = self._time(now)
        remaining = (max(0, int(self._configuration.usable_until - now))
                     if self._state == 'bound' else 0)
        return {'stage': self._state, 'reason': self._reason,
                'discover_attempts': self._discovers, 'request_attempts': self._requests,
                'packets_received': self._packets, 'usable_lease_remaining': remaining,
                'configuration_available': self._state == 'bound',
                'interface_configured': False, 'endpoint_verified': False,
                'default_route_installed': False, 'dns_installed': False}
