"""Bounded GO DHCP on the actual native-issued binding and owned UDP ticket.

SOURCE only: no P011/phone/physical-close evidence is implied by this file.
The fixed deployment loads this definition before mta_go_native; its import is
deferred until the actual constructor is called. Constructor is pure. It never
creates a socket, controller, address, route, DNS, lock or durable permission.
Bootstrap must retain its original constructor ticket BEFORE calling it, then
record the returned original server before open. All operations use the actual
native definition methods, not caller callbacks, socket factories or booleans.

The actual owner holds its original mutex throughout synchronous operations.
Setup/listening has one original cap and grants no DHCP packet activity. Only
after final Native readback may start_service consume the first issued service
scope and construct the lease core. Neither phase renews the original session.
ANY:67 admits broadcast DORA only on the exact device with complete pktinfo;
sendmsg supplies the original server address and ifindex. No recvfrom/sendto
or default-interface fallback exists. Socket remains strongly retained after
close; only Native's original once-close and typed EBADF prove its release.
"""
import math
import socket
import struct
import threading

import mta_dhcp as wire
import mta_ip as ip

IP_PKTINFO = 8
SO_BINDTODEVICE = 25
SO_REUSEPORT = 15
PKTINFO = struct.Struct('=I4s4s')
POLL_SECONDS = 0.2
MAX_PACKETS = 32
MAX_PACKETS_PER_SECOND = 8


class GoDhcpError(ValueError):
    """Symbolic error only; no address, MAC, packet or OS exception text."""


def _fail(reason):
    raise GoDhcpError(reason) from None


def _native_module():
    import mta_go_native
    return mta_go_native


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(float(value)) or not 0 <= value < 1e12:
        _fail('dhcp_clock_invalid')
    return float(value)


class GoDhcpServer(object):
    """One actual native socket, one admitted client, one original worker."""
    def __init__(self, binding):
        native = _native_module()
        if type(binding) is not native.GoDhcpBinding:
            _fail('dhcp_binding_invalid')
        # Pure retention only: owner.dhcp is not assigned until ctor returned.
        self.binding = self._binding_original = binding
        self._binding_class = native.GoDhcpBinding
        self._originals = (binding.native, binding.owner, binding.store,
            binding.deployment, binding.worker, binding.mutex, binding.clock,
            binding.until, binding.origin, binding.server_ip, binding.client_ip,
            binding.subnet_mask)
        self.socket = self._socket_original = None
        self._open_called = self._open_returned = self._opening = False
        self._close_called = self._closed = self._active = False
        self._setup_until = self._setup_until_original = binding.setup_until
        self._service_called = False
        self._active_until = self._active_until_original = None
        self._core = None
        self._last = self._window_start = None
        self._packets = self._replies = self._ignored = self._window_packets = 0
        self._allocation = None
        self._stage, self._reason = 'new', 'not_opened'
        self._failure = None
        self._raw_returns = []  # Bounded PRIVATE originals; never status/UI.

    def _context(self):
        native = _native_module()
        binding = self.binding
        if (type(self) is not GoDhcpServer or binding is not self._binding_original or
                type(binding) is not self._binding_class or native.GoDhcpBinding is not self._binding_class or
                threading.current_thread() is not binding.worker or
                getattr(binding.mutex, '_is_owned', lambda: False)() is not True or
                any(actual is not original for actual, original in zip(
                    (binding.native, binding.owner, binding.store, binding.deployment,
                     binding.worker, binding.mutex, binding.clock, binding.until, binding.origin),
                    self._originals[:9])) or
                (binding.server_ip, binding.client_ip, binding.subnet_mask) != self._originals[9:] or
                self.socket is not self._socket_original):
            _fail('dhcp_original_owner_changed')
        if (self._setup_until is not self._setup_until_original or
                binding.setup_until is not self._setup_until_original):
            _fail('dhcp_setup_scope_changed')
        return binding

    def _now(self):
        binding = self._context()
        now = _time(binding.clock())
        if self._last is not None and now < self._last:
            _fail('dhcp_clock_regressed')
        self._last = now
        return now

    def _cancelled(self):
        binding = self._context()
        result = self._binding_class.cancelled(binding, self)
        if type(result) is not bool:
            _fail('dhcp_cancel_invalid')
        return result

    def _stopped(self):
        now = self._now()
        if self._active_until is not self._active_until_original:
            _fail('dhcp_scope_changed')
        # Stop-only, no renewed check/grant after the original slice expires.
        if self._active_until is not None and now >= self._active_until:
            return True
        return self._cancelled()

    def _check(self):
        binding = self._context()
        now = _time(self._binding_class.check(binding, self))
        if self._last is not None and now < self._last:
            _fail('dhcp_clock_regressed')
        self._last = now
        end = self._active_until if self._service_called else self._setup_until
        if (end is None or self._active_until is not self._active_until_original or
                binding.native._scope != end or not now < end <= binding.until):
            _fail('dhcp_scope_changed')
        return now

    def _normal_stop(self, error):
        """Recognize only actual scope expiry/cancel, never an active grant.

        A native pre/postcheck can cross the original service end between the
        last timeout readback and the next call. That ends a silent service; it
        does not erase a different canonical/owner/IO failure at the same time.
        """
        native = _native_module()
        if type(error) is not native.sources.GoSourceError or str(error) not in ('deadline', 'stop_requested'):
            return False
        self._context()
        if (self._active_until is None or self._active_until is not self._active_until_original or
                self.binding.native._scope != self._active_until):
            return False
        if str(error) == 'deadline':
            return self._now() >= self._active_until
        return self._cancelled()

    def _socket_current(self):
        binding = self._context()
        if self.socket is None or self._binding_class.socket_current(binding, self, self.socket) is not True:
            _fail('dhcp_socket_changed')
        return self.socket

    def _options(self):
        sock = self._socket_current()
        device = sock.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)
        expected = self.binding.origin.name.encode('ascii') + b'\0'
        if type(device) is not bytes or device != expected:
            _fail('dhcp_device_readback')
        checks = ((socket.SOL_SOCKET, socket.SO_TYPE, socket.SOCK_DGRAM),
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 0),
            (socket.SOL_SOCKET, SO_REUSEPORT, 0),
            (socket.SOL_SOCKET, socket.SO_BROADCAST, 1),
            (socket.IPPROTO_IP, IP_PKTINFO, 1))
        if any(sock.getsockopt(level, option) != expected for level, option, expected in checks):
            _fail('dhcp_options_readback')
        if sock.get_inheritable() is not False:
            _fail('dhcp_inheritance_readback')

    def _timeout(self):
        now = self._check()
        end = self._active_until if self._service_called else self._setup_until
        timeout = min(POLL_SECONDS, end - now)
        sock = self._socket_current()
        sock.settimeout(timeout)
        actual = sock.gettimeout()
        if type(actual) not in (int, float) or not 0 < actual <= timeout + 1e-9 or actual > POLL_SECONDS:
            _fail('dhcp_timeout_readback')
        self._check()
        return sock

    def open(self):
        self._context()
        if self._open_called or self._close_called or self._stage != 'new':
            _fail('dhcp_open_already_attempted')
        self._open_called, self._opening, self._stage = True, True, 'opening'
        try:
            binding = self.binding
            end = self._setup_until
            now = self._check()
            if not 0 < end - now <= 20.0 or binding.subnet_mask != 0xffffff00:
                _fail('dhcp_setup_scope_invalid')
            self._broadcast = struct.pack('!I', (binding.server_ip & binding.subnet_mask) |
                (binding.subnet_mask ^ 0xffffffff))
            self._broadcast_text = wire.address(self._broadcast)
            self._window_start = now
            candidate = self._binding_class.open_socket(binding, self)
            # Retain before socket APIs/postcheck. Native retained before factory.
            self.socket = self._socket_original = candidate
            self._check(); sock = self._socket_current()
            if (sock.family != socket.AF_INET or sock.type != socket.SOCK_DGRAM or
                    not all(callable(getattr(sock, name, None)) for name in
                        ('recvmsg', 'sendmsg', 'gettimeout', 'set_inheritable', 'get_inheritable')) or
                    not callable(getattr(socket, 'CMSG_SPACE', None))):
                _fail('dhcp_socket_api_unavailable')
            for level, option, value in ((socket.SOL_SOCKET, SO_BINDTODEVICE,
                    binding.origin.name.encode('ascii') + b'\0'),
                    (socket.SOL_SOCKET, socket.SO_BROADCAST, 1),
                    (socket.IPPROTO_IP, IP_PKTINFO, 1)):
                self._check(); sock.setsockopt(level, option, value); self._check()
            self._check(); sock.set_inheritable(False); self._check()
            self._timeout(); self._options(); self._check()
            # Broadcast DORA cannot be received by binding a unicast local IP.
            # ANY is still scoped by the original device and complete pktinfo.
            sock.bind(('0.0.0.0', 67)); self._check()
            if sock.getsockname() != ('0.0.0.0', 67):
                _fail('dhcp_endpoint_readback')
            self._options(); self._check()
            self._open_returned, self._stage, self._reason = True, 'listening', 'native_socket_listening'
            return self
        except BaseException as error:
            self._failure = error
            self._stage, self._reason, self._allocation = 'failed', 'dhcp_open_failed', None
            raise
        finally:
            self._opening = False

    def start_service(self):
        """Once consume Native's post-listening cap; no TTL or socket creation."""
        binding = self._context()
        if (self._service_called or not self._open_returned or self._close_called or
                self._opening or self._active or self._failure is not None or
                self._stage != 'listening' or self._core is not None):
            _fail('dhcp_service_already_attempted')
        # Once BEFORE fetching/constructing: even a late or failed handoff does
        # not permit a new service cap or a second protocol core.
        self._service_called = True
        try:
            end = self._binding_class.active_until(binding, self)
            if type(end) is not float:
                _fail('dhcp_service_scope_invalid')
            self._active_until = self._active_until_original = end
            now = self._check()
            if not 0 < end - now <= 20.0:
                _fail('dhcp_service_scope_invalid')
            self._socket_current(); self._options(); self._check()
            self._core = wire.SingleClientServer(ip.ipv4_text(binding.server_ip),
                ip.ipv4_text(binding.client_ip), ip.ipv4_text(binding.subnet_mask), end)
            self._window_start = now
            self._check()
            self._stage, self._reason = 'serving', 'native_service_scope_issued'
            return self
        except BaseException as error:
            self._failure = error
            self._stage, self._reason, self._allocation = 'failed', 'dhcp_service_start_failed', None
            raise

    def _ignore(self, reason):
        self._ignored += 1
        return {'event': 'ignored', 'reason': reason}

    def _envelope(self, returned):
        if type(returned) is not tuple or len(returned) != 4:
            return 'dhcp_recv_shape'
        packet, ancillary, flags, source = returned
        if type(packet) is not bytes or not 240 <= len(packet) <= wire.MAX_PACKET or type(flags) is not int or flags != 0:
            return 'dhcp_packet_truncated'
        if type(source) is not tuple or len(source) != 2 or type(source[1]) is not int or source[1] != 68:
            return 'dhcp_source_port'
        try:
            origin = wire.ipv4(source[0])
        except wire.DhcpError:
            return 'dhcp_source_address'
        if origin not in (wire.ZERO, self._core.client):
            return 'dhcp_source_not_allocated'
        if type(ancillary) is not list or len(ancillary) != 1:
            return 'dhcp_pktinfo_missing'
        row = ancillary[0]
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not int or type(row[1]) is not int or
                row[:2] != (socket.IPPROTO_IP, IP_PKTINFO) or type(row[2]) is not bytes or len(row[2]) != PKTINFO.size):
            return 'dhcp_pktinfo_invalid'
        index, local, destination = PKTINFO.unpack(row[2])
        if (index != self.binding.origin.ifindex or local != self._core.server or
                destination not in (self._core.server, self._broadcast, b'\xff' * 4)):
            return 'dhcp_pktinfo_not_owned'
        return None

    def _station(self, mac):
        self._check()
        result = self._binding_class.admit_station(self.binding, self, mac, self.binding.client_ip)
        if type(result) is not bool:
            _fail('dhcp_station_result_invalid')
        self._check()
        return result

    def serve_once(self):
        self._context()
        if (self._close_called or not self._open_returned or not self._service_called or
                self._core is None or self._stage != 'serving' or self._active or self._failure is not None):
            _fail('dhcp_poll_invalid')
        if self._stopped():
            return {'event': 'finished', 'reason': 'original_service_stopped'}
        self._active = True
        try:
            if self._packets >= MAX_PACKETS:
                _fail('dhcp_packet_limit')
            sock = self._timeout()
            try:
                returned = sock.recvmsg(wire.MAX_PACKET + 1, socket.CMSG_SPACE(PKTINFO.size), 0)
            except socket.timeout:
                # Clipped timeout may arrive exactly at original service end.
                # This observation is stop-only, not another active grant.
                if self._stopped():
                    return {'event': 'finished', 'reason': 'original_service_stopped'}
                self._check()
                return {'event': 'idle', 'reason': 'no_packet'}
            self._raw_returns.append(returned)
            self._packets += 1
            if self._stopped():
                return {'event': 'finished', 'reason': 'late_packet_not_authorized'}
            now = self._check(); self._socket_current()
            if now - self._window_start >= 1.0:
                self._window_start, self._window_packets = now, 0
            self._window_packets += 1
            if self._window_packets > MAX_PACKETS_PER_SECOND:
                return self._ignore('dhcp_rate_limited')
            reason = self._envelope(returned)
            if reason is not None:
                return self._ignore(reason)
            packet = returned[0]
            try:
                message = wire.decode(packet)
            except wire.DhcpError:
                return self._ignore('dhcp_packet_invalid')
            if not self._station(message['chaddr']):
                return self._ignore('dhcp_station_not_admitted')
            reply_time = self._check()
            reply = self._core.handle(packet, reply_time)
            if self._core.declined:
                self._allocation = None; _fail('dhcp_client_declined')
            if not self._core.bound:
                self._allocation = None
            if reply is None:
                return self._ignore('dhcp_no_reply')
            if not self._station(message['chaddr']):
                self._allocation = None; _fail('dhcp_station_admission_lost')
            sock = self._timeout(); self._options(); self._check()
            pktinfo = PKTINFO.pack(self.binding.origin.ifindex, self._core.server, wire.ZERO)
            sent = sock.sendmsg([reply], [(socket.IPPROTO_IP, IP_PKTINFO, pktinfo)], 0, (self._broadcast_text, 68))
            self._raw_returns.append(('send_return', sent))
            if type(sent) is not int or sent != len(reply):
                _fail('dhcp_short_reply')
            if self._stopped():
                self._allocation = None
                return {'event': 'finished', 'reason': 'late_send_not_allocation'}
            self._check(); self._socket_current(); self._replies += 1
            response = wire.decode(reply)
            if response['type'] == wire.ACK:
                seconds = struct.unpack('!I', response['options'][51])[0]
                self._allocation = {'client_ip': self.binding.client_ip, 'mac': message['chaddr'],
                    'usable_until': min(self._active_until, reply_time + seconds),
                    'ack_transmitted': True, 'phone_configured': False}
            return {'event': 'ack_transmitted' if response['type'] == wire.ACK else 'offer_transmitted',
                'reason': 'kernel_send_only_not_phone_configuration'}
        except BaseException as error:
            if self._normal_stop(error):
                self._allocation = None
                return {'event': 'finished', 'reason': 'original_service_stopped'}
            self._failure = error
            self._stage, self._reason, self._allocation = 'failed', 'dhcp_io_failed', None
            raise
        finally:
            self._active = False

    def allocation(self):
        """Private transmitted ACK fact only; not IP install/app authentication."""
        self._context()
        if (self._close_called or not self._open_returned or not self._service_called or
                self._core is None or self._failure is not None or self._stopped()):
            self._allocation = None; return None
        now = self._check()
        if self._allocation is None or not self._core.bound or now >= self._allocation['usable_until']:
            self._allocation = None; return None
        if not self._station(self._allocation['mac']):
            self._allocation = None; return None
        self._check()
        return dict(self._allocation)

    def close(self):
        """Only native cleanup closes original UDP; expiry is not an active gate."""
        self._context()
        if self._close_called:
            return self._closed
        self._close_called = True
        self._allocation = None
        if self._opening or self._active:
            self._stage, self._reason = 'close_pending', 'dhcp_worker_pending'
            return False
        # None is not caller-signed absence: Native must establish that its
        # factory was never called, or its exact retained raw was actually
        # once-closed with typed EBADF after a late unreturned handoff.
        result = self._binding_class.close_socket(self.binding, self, self.socket)
        if type(result) is not bool:
            _fail('dhcp_close_result_invalid')
        self._closed = result
        self._stage = 'closed' if self._closed else 'close_pending'
        self._reason = 'native_close_verified' if self._closed else 'native_close_pending'
        return self._closed

    def status(self):
        """Passive counts/scope only; private socket and allocation stay retained."""
        return {'stage': self._stage, 'reason': self._reason,
            'packets_received': self._packets, 'replies_transmitted': self._replies,
            'packets_ignored': self._ignored, 'client_limit': 1,
            'socket_close_verified': self._closed,
            'socket_actor_pending': self._opening or self._active or self._open_called and not self._closed,
            'allocation_ack_transmitted': self._allocation is not None,
            'phone_configured': False, 'default_route_supplied': False, 'dns_supplied': False,
            'dhcp_ready': False, 'send_ready': False}
