# -*- coding: utf-8 -*-
"""Private, bounded Linux UDP adapter for the actual owned GO/IP lease.

No interface/address/route/DNS changes, subprocesses, journal or capability
publication. The session owns this object BEFORE open(), closes it BEFORE IP
restore, and supplies fast, read-only exact-owner/station callbacks. Dependency
injection is for trusted platform code/HOST tests, never QML/HTTP input.
Python 3.5 compatible; no stdlib json dependency.
"""
import math
import re
import socket
import struct
import sys
import threading
import time

import mta_dhcp as core

# Linux UAPI only, not a recvfrom/unscoped portability fallback.
IP_PKTINFO = 8
SO_BINDTODEVICE = 25
SO_REUSEPORT = 15
MSG_TRUNC = 0x20
MSG_CTRUNC = 0x08
PKTINFO = struct.Struct('=I4s4s')
POLL_SECONDS = 0.2
MAX_PACKETS = 512
MAX_PACKETS_PER_SECOND = 20
MAX_SESSION_SECONDS = 300


class DhcpSocketError(RuntimeError):
    """Fixed symbolic errors only; never include OS text or private values."""


def _time(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or not 0 <= value <= 2 ** 53):
        raise DhcpSocketError('invalid_monotonic_time')
    return float(value)


class DhcpSocketServer:
    """One synchronous reader, no permanent threads, one admitted DHCP client.

    fresh_gate() must return exactly True only while the supplied boot/phy/WDEV/
    ifindex/name/IP/epoch/deadline identity remains owned and read-back verified.
    admit_station(mac_bytes, client_ip) must return exactly True only for the
    currently independently admitted WPA station. It MUST NOT compare an
    unproven BLE MAC or just accept the first packet. Both callbacks are bounded,
    read-only, and coordinated with the session's mutation/restore lock.

    Socket factory/clock/if_nametoindex are trusted HOST dependency seams; real
    defaults require Linux recvmsg/sendmsg. A failure never opens another socket
    or falls back to the stock Wi-Fi/default route.
    """
    def __init__(self, ifname, ifindex, server_ip, client_ip, subnet_mask,
                 deadline, fresh_gate, admit_station, cancelled,
                 clock=None, socket_factory=None, if_nametoindex=None):
        if (not isinstance(ifname, str) or not re.match(r'^[A-Za-z0-9_.-]{1,15}\Z', ifname)
                or ifname in ('lo', 'wlan0')):
            raise DhcpSocketError('invalid_owned_interface_name')
        if isinstance(ifindex, bool) or not isinstance(ifindex, int) or not 1 <= ifindex <= 0x7fffffff:
            raise DhcpSocketError('invalid_owned_interface_index')
        if not all(callable(fn) for fn in (fresh_gate, admit_station, cancelled)):
            raise DhcpSocketError('required_lease_callbacks_missing')
        self._clock = clock or time.monotonic
        if not callable(self._clock):
            raise DhcpSocketError('invalid_clock_callback')
        self._deadline = _time(deadline)
        now = _time(self._clock())
        if not 1 <= self._deadline - now <= MAX_SESSION_SECONDS:
            raise DhcpSocketError('owned_deadline_out_of_scope')
        try:
            self._core = core.SingleClientServer(server_ip, client_ip, subnet_mask, self._deadline)
        except core.DhcpError:
            raise DhcpSocketError('invalid_owned_subnet')
        self._ifname = ifname.encode('ascii')
        self._ifname_text = ifname
        self._ifindex = ifindex
        self._server_ip = server_ip
        self._client_ip = client_ip
        owner = struct.unpack('!I', self._core.server)[0]
        mask = struct.unpack('!I', self._core.mask)[0]
        self._broadcast = struct.pack('!I', (owner & mask) | (mask ^ 0xffffffff))
        self._broadcast_ip = core.address(self._broadcast)
        self._fresh_gate = fresh_gate
        self._admit_station = admit_station
        self._cancelled = cancelled
        self._factory = socket_factory or socket.socket
        self._real_factory = socket_factory is None
        self._index_reader = if_nametoindex or getattr(socket, 'if_nametoindex', None)
        if not callable(self._factory) or not callable(self._index_reader):
            raise DhcpSocketError('required_socket_api_unavailable')
        self._lock = threading.RLock()
        self._socket = None
        self._pending_close = []
        self._closing_fds = 0
        self._opening = False
        self._active = False
        self._closing = False
        self._generation = 0
        self._stage = 'new'
        self._reason = 'not_opened'
        self._last_time = now
        self._window_start = now
        self._window_packets = 0
        self._packets = 0
        self._replies = 0
        self._ignored = 0
        self._allocation = None

    def _now(self):
        with self._lock:
            try:
                now = _time(self._clock())
            except Exception:
                self._abort('clock_failed')
            if now < self._last_time:
                self._abort('clock_moved_backwards')
            self._last_time = now
            return now

    def _abort(self, reason):
        with self._lock:
            self._reason = reason
            self._allocation = None
        self.close()
        raise DhcpSocketError(reason)

    def _check(self):
        with self._lock:
            if self._closing:
                raise DhcpSocketError('server_closed')
        now = self._now()
        try:
            cancelled = self._cancelled()
        except Exception:
            self._abort('cancel_check_failed')
        if not isinstance(cancelled, bool):
            self._abort('cancel_check_invalid')
        if cancelled:
            self._abort('cancelled')
        if self._deadline - now < 1:
            self._abort('lease_expired')
        try:
            admitted = self._fresh_gate()
            index = self._index_reader(self._ifname_text)
        except Exception:
            self._abort('owned_identity_check_failed')
        if admitted is not True or type(index) is not int or index != self._ifindex:
            self._abort('owned_identity_unverified')
        now = self._now()
        try:
            cancelled = self._cancelled()
        except Exception:
            self._abort('cancel_check_failed')
        if not isinstance(cancelled, bool):
            self._abort('cancel_check_invalid')
        if cancelled:
            self._abort('cancelled')
        if self._deadline - now < 1:
            self._abort('lease_expired')
        with self._lock:
            if self._closing:
                raise DhcpSocketError('server_closed')
        return now

    def _station(self, mac):
        try:
            return self._admit_station(mac, self._client_ip) is True
        except Exception:
            self._abort('station_check_failed')

    def _close_one(self, sock, reserved=False):
        if not reserved:
            with self._lock:
                self._closing_fds += 1
        try:
            try:
                sock.close()
            except Exception:
                pass
            try:
                verified = sock.fileno() == -1
            except Exception:
                verified = False
            if not verified:
                with self._lock:
                    if all(existing is not sock for existing in self._pending_close):
                        self._pending_close.append(sock)
            return verified
        finally:
            with self._lock:
                self._closing_fds -= 1

    def _closed_state(self):
        with self._lock:
            complete = (self._closing and not self._opening and not self._active and
                        self._socket is None and not self._pending_close and not self._closing_fds)
            if complete:
                self._stage = 'closed'
            elif self._closing:
                self._stage = 'closing'
            return complete

    def close(self):
        """Return True only after owned fds AND any opening/reader actor are gone.

        A pending late factory/recvmsg or failed close retains ownership. The
        session must not restore/reuse the interface until this returns True.
        """
        with self._lock:
            self._closing = True
            self._generation += 1
            if self._reason in ('not_opened', 'ready_for_admitted_station'):
                self._reason = 'closed_by_owner'
            self._allocation = None
            sock = self._socket
            self._socket = None
            pending = self._pending_close
            self._pending_close = []
            handles = ([sock] if sock is not None else [])
            for item in pending:
                if all(existing is not item for existing in handles):
                    handles.append(item)
            self._closing_fds += len(handles)
        for item in handles:
            self._close_one(item, reserved=True)
        return self._closed_state()

    def _options_verified(self, sock):
        device = sock.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)
        if not isinstance(device, bytes) or device.rstrip(b'\0') != self._ifname:
            raise DhcpSocketError('device_binding_readback_failed')
        if (sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM or
                sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0 or
                sock.getsockopt(socket.SOL_SOCKET, SO_REUSEPORT) != 0 or
                sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) != 1 or
                sock.getsockopt(socket.IPPROTO_IP, IP_PKTINFO) != 1):
            raise DhcpSocketError('socket_options_readback_failed')

    def open(self):
        """Open only AF_INET UDP67 on the exact device; never change networking."""
        with self._lock:
            if self._stage != 'new' or self._closing:
                raise DhcpSocketError('open_in_invalid_state')
            self._opening = True
            self._stage = 'opening'
            generation = self._generation
        candidate = None
        try:
            self._check()
            if self._real_factory and not sys.platform.startswith('linux'):
                raise DhcpSocketError('linux_socket_api_required')
            if not callable(getattr(socket, 'CMSG_SPACE', None)):
                raise DhcpSocketError('required_socket_api_unavailable')
            candidate = self._factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._check()
            if (candidate.family != socket.AF_INET or
                    not all(callable(getattr(candidate, name, None)) for name in
                            ('recvmsg', 'sendmsg', 'gettimeout', 'set_inheritable', 'get_inheritable'))):
                raise DhcpSocketError('required_socket_api_unavailable')
            candidate.set_inheritable(False)
            if candidate.get_inheritable() is not False:
                raise DhcpSocketError('socket_inheritance_readback_failed')
            candidate.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self._ifname + b'\0')
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            candidate.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
            candidate.settimeout(POLL_SECONDS)
            if candidate.gettimeout() != POLL_SECONDS:
                raise DhcpSocketError('socket_timeout_readback_failed')
            self._options_verified(candidate)
            self._check()
            candidate.bind(('0.0.0.0', 67))
            if candidate.getsockname() != ('0.0.0.0', 67):
                raise DhcpSocketError('udp_binding_readback_failed')
            self._options_verified(candidate)
            self._check()
            with self._lock:
                if self._closing or self._generation != generation:
                    raise DhcpSocketError('late_socket_after_close')
                self._socket = candidate
                candidate = None
                self._stage = 'listening'
                self._reason = 'ready_for_admitted_station'
            return self
        except DhcpSocketError as error:
            with self._lock:
                if self._reason == 'not_opened':
                    self._reason = str(error)
            self.close()
            raise
        except Exception:
            self._abort('socket_open_failed')
        finally:
            if candidate is not None:
                self._close_one(candidate)
            with self._lock:
                self._opening = False
            self._closed_state()

    def _ignore(self, reason):
        self._ignored += 1
        return {'event': 'ignored', 'reason': reason}

    def _envelope(self, packet, ancillary, flags, source):
        if (not isinstance(packet, bytes) or not 240 <= len(packet) <= core.MAX_PACKET or
                type(flags) is not int or flags != 0):
            return 'packet_truncated_or_invalid'
        if (not isinstance(source, tuple) or len(source) != 2 or
                type(source[1]) is not int or source[1] != 68):
            return 'source_port_invalid'
        try:
            origin = core.ipv4(source[0])
        except core.DhcpError:
            return 'source_address_invalid'
        if origin not in (core.ZERO, self._core.client):
            return 'source_address_not_allocated'
        if not isinstance(ancillary, list) or len(ancillary) != 1:
            return 'pktinfo_missing_duplicate_or_unknown'
        row = ancillary[0]
        if (not isinstance(row, tuple) or len(row) != 3 or
                type(row[0]) is not int or type(row[1]) is not int or
                row[0] != socket.IPPROTO_IP or row[1] != IP_PKTINFO or
                not isinstance(row[2], bytes) or len(row[2]) != PKTINFO.size):
            return 'pktinfo_missing_duplicate_or_unknown'
        index, local, destination = PKTINFO.unpack(row[2])
        if (index != self._ifindex or local != self._core.server or
                destination not in (self._core.server, self._broadcast, b'\xff' * 4)):
            return 'pktinfo_identity_mismatch'
        return None

    def serve_once(self):
        """Bounded recvmsg step; invalid/unadmitted datagrams get NO reply."""
        self._check()
        with self._lock:
            if self._active:
                raise DhcpSocketError('concurrent_poll_forbidden')
            if self._socket is None or self._stage != 'listening':
                raise DhcpSocketError('poll_in_invalid_state')
            self._active = True
            sock = self._socket
            generation = self._generation
        try:
            if self._core.key is not None and not self._station(self._core.key[0]):
                self._abort('station_admission_lost')
            sock.settimeout(min(POLL_SECONDS, self._deadline - self._check()))
            if sock.gettimeout() != POLL_SECONDS:
                self._abort('socket_timeout_readback_failed')
            try:
                packet, ancillary, flags, source = sock.recvmsg(core.MAX_PACKET + 1,
                                                               socket.CMSG_SPACE(PKTINFO.size), 0)
            except socket.timeout:
                self._check()
                return {'event': 'idle', 'reason': 'no_packet'}
            now = self._check()
            self._packets += 1
            if self._packets > MAX_PACKETS:
                self._abort('session_packet_limit')
            if now - self._window_start >= 1:
                self._window_start = now
                self._window_packets = 0
            self._window_packets += 1
            if self._window_packets > MAX_PACKETS_PER_SECOND:
                return self._ignore('rate_limited')
            reason = self._envelope(packet, ancillary, flags, source)
            if reason is not None:
                return self._ignore(reason)
            try:
                message = core.decode(packet)
            except core.DhcpError:
                return self._ignore('dhcp_packet_invalid')
            if not self._station(message['chaddr']):
                return self._ignore('station_not_admitted')
            self._check()
            try:
                reply_time = self._now()
                reply = self._core.handle(packet, reply_time)
            except core.DhcpError:
                return self._ignore('dhcp_packet_invalid')
            if self._core.declined:
                self._abort('client_declined_address')
            if not self._core.bound:
                self._allocation = None
            if reply is None:
                return self._ignore('no_reply_for_state')
            if not self._station(message['chaddr']):
                self._abort('station_admission_lost')
            self._check()
            pktinfo = PKTINFO.pack(self._ifindex, self._core.server, core.ZERO)
            with self._lock:
                if self._closing or generation != self._generation or self._socket is not sock:
                    raise DhcpSocketError('late_reply_after_close')
                sent = sock.sendmsg([reply], [(socket.IPPROTO_IP, IP_PKTINFO, pktinfo)],
                                    0, (self._broadcast_ip, 68))
            if type(sent) is not int or sent != len(reply):
                self._abort('udp_reply_not_fully_sent')
            self._check()
            self._replies += 1
            kind = core.decode(reply)['type']
            if kind == core.ACK:
                with self._lock:
                    if self._closing or generation != self._generation:
                        raise DhcpSocketError('late_reply_after_close')
                    seconds = struct.unpack('!I', core.decode(reply)['options'][51])[0]
                    self._allocation = {'client_ip': self._client_ip, 'mac': message['chaddr'],
                                        'usable_until': min(self._deadline, reply_time + seconds),
                                        'ack_transmitted': True,
                                        'phone_configured': False}
            return {'event': 'ack_transmitted' if kind == core.ACK else 'offer_transmitted',
                    'reason': 'kernel_send_completed_not_phone_configuration'}
        except DhcpSocketError:
            raise
        except Exception:
            with self._lock:
                if self._closing:
                    raise DhcpSocketError('server_closed')
            self._abort('socket_io_failed')
        finally:
            with self._lock:
                self._active = False
            self._closed_state()

    def allocation(self):
        """PRIVATE allocation fact, not peer app authentication/configuration.

        Re-check ownership and real station admission on every query. The
        returned IP/MAC must never enter UI/public logs; DHCP cannot prove
        the phone has installed this address or completed a file transfer.
        """
        now = self._check()
        if self._allocation is None or not self._core.bound:
            return None
        if now >= self._allocation['usable_until']:
            self._allocation = None
            return None
        if not self._station(self._allocation['mac']):
            self._abort('station_admission_lost')
        self._check()
        with self._lock:
            return dict(self._allocation) if self._allocation is not None and not self._closing else None

    def run(self):
        """Caller-owned worker loop; deadline/cancel close, other errors propagate."""
        try:
            self.open()
            while True:
                self.serve_once()
        except DhcpSocketError as error:
            if str(error) not in ('cancelled', 'lease_expired', 'server_closed'):
                raise
        finally:
            self.close()

    def status(self):
        """Fixed-field passive status; no address/MAC/ifname/callback invocation."""
        with self._lock:
            return {'stage': self._stage, 'reason': self._reason,
                    'packets_received': self._packets, 'replies_transmitted': self._replies,
                    'packets_ignored': self._ignored, 'client_limit': 1,
                    'socket_close_verified': self._stage == 'closed',
                    'socket_actor_pending': (self._opening or self._active or bool(self._pending_close)
                                             or bool(self._closing_fds)),
                    'allocation_ack_transmitted': self._allocation is not None,
                    'phone_configured': False, 'default_route_supplied': False, 'dns_supplied': False}
