# -*- coding: utf-8 -*-
"""Private Linux TCP factories; no network mutation or production capability.

The caller owns this capsule before calling either factory and must retain it
until close() is verified. Proof callbacks and the shared lease lock are trusted
backend inputs, never QML/HTTP arguments. Python 3.5; no stdlib json dependency.
"""
import errno
import math
import re
import select
import socket
import ssl
import struct
import sys
import threading
import time
from collections import namedtuple

SO_BINDTODEVICE = 25                 # Linux UAPI, not a portability fallback.
SO_REUSEPORT = 15
POLL_SECONDS = 0.1
PROOF_SECONDS = 0.2
MAX_SESSION_SECONDS = 300
MAX_CONNECT_SECONDS = 3
MAX_ATTEMPTS = 16
MAX_RESOURCES = 3

OwnedContext = namedtuple('OwnedContext', 'boot_id task_epoch native_epoch phy '
    'wdev ifindex ifname mode local_ip prefix deadline receipt_id')
PeerEndpoint = namedtuple('PeerEndpoint', 'host port proof_id')
ScopeProof = namedtuple('ScopeProof', 'context receipt_stage receipt_fsynced '
    'persistent_readback_verified owner_verified address_verified '
    'route_baseline_verified client_association_verified dhcp_verified '
    'peer_verified endpoint')
TransportClosedProof = namedtuple('TransportClosedProof',
    'context raw_socket all_sockets_closed all_actors_exited')

_ERROR_CODES = frozenset(('invalid_monotonic_value', 'invalid_private_ipv4',
    'owned_context_required', 'invalid_owned_context', 'invalid_owned_host_address',
    'verified_client_endpoint_required', 'endpoint_is_local_address', 'endpoint_not_on_owned_subnet',
    'go_listener_has_no_admitted_endpoint', 'required_owner_callbacks_missing',
    'required_socket_api_unavailable', 'invalid_raw_socket_type', 'owned_deadline_out_of_scope',
    'clock_failed', 'clock_moved_backwards', 'capsule_closed', 'actor_limit', 'resource_limit',
    'cancel_check_failed', 'cancel_check_invalid', 'cancelled', 'lease_or_connect_expired',
    'owner_lock_failed', 'owner_lock_timeout', 'scope_readback_failed',
    'scope_readback_budget_exceeded', 'owned_scope_unverified', 'client_peer_unverified',
    'go_listener_not_peer_authority', 'raw_ipv4_tcp_required', 'socket_scope_readback_failed',
    'socket_already_connected', 'source_binding_readback_failed', 'linux_socket_api_required',
    'socket_identity_already_owned', 'listener_endpoint_out_of_scope', 'connector_endpoint_out_of_scope',
    'connect_timeout_out_of_scope', 'nonblocking_readback_failed', 'connect_failed',
    'connect_poll_readback_failed', 'peer_binding_readback_failed', 'source_port_changed_during_connect',
    'socket_timeout_readback_failed', 'socket_operation_failed', 'unclassified_scope_failure'))


class ScopedSocketError(RuntimeError):
    """Symbolic reasons only; do not propagate private OS/backend text."""
    def __init__(self, reason):
        if not isinstance(reason, str) or reason not in _ERROR_CODES:
            reason = 'unclassified_scope_failure'
        RuntimeError.__init__(self, reason)


def _number(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or not 0 <= value <= 2 ** 53):
        raise ScopedSocketError('invalid_monotonic_value')
    return float(value)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _ip(value):
    if not isinstance(value, str) or not re.match(r'^\d{1,3}(\.\d{1,3}){3}\Z', value):
        raise ScopedSocketError('invalid_private_ipv4')
    parts = value.split('.')
    if any(str(int(part)) != part or not 0 <= int(part) <= 255 for part in parts):
        raise ScopedSocketError('invalid_private_ipv4')
    octets = tuple(int(part) for part in parts)
    if not (octets[0] == 10 or (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)):
        raise ScopedSocketError('invalid_private_ipv4')
    return octets


def _hash(value):
    return isinstance(value, str) and re.match(r'^[0-9a-f]{64}\Z', value) is not None


class ScopedDataSockets:
    """Bounded raw TCP creation and explicit transport ownership handoff.

    proof_callback(context, purpose, budget) must perform bounded, read-only
    actual owner/address/route/journal readbacks under ownership_lock (the same
    reentrant lock as lease mutation/restore). It returns an exact ScopeProof,
    not a generic truthy gate. A blocked callback remains a pending actor; no
    thread is abandoned and close() cannot report completion meanwhile.

    GO listener proof does NOT require a phone station: the eventual sender
    remains deny-all until its coordinator independently proves the peer. CLIENT
    connector proof requires real association/DHCP/endpoint proof on every call;
    a GO-only IP receipt validator is not a CLIENT validator.

    Injected socket/type/select/index/clock inputs are private HOST test seams.
    Defaults require real Linux socket APIs. No fallback, REUSE, DNS or route
    modifications. Handed-off raw sockets may be detached by TLS; fileno() is
    never used to decide that their transport resources have closed.
    """
    def __init__(self, context, proof_callback, cancelled, ownership_lock,
                 endpoint=None, clock=None, socket_factory=None,
                 if_nametoindex=None, select_ready=None, raw_socket_type=None):
        if type(context) is not OwnedContext:
            raise ScopedSocketError('owned_context_required')
        if (not isinstance(context.boot_id, str) or not re.match(
                r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z', context.boot_id) or
                not _integer(context.task_epoch, 1, 2 ** 53) or
                not _integer(context.native_epoch, 1, 2 ** 53) or
                not _integer(context.phy, 0, 0x7fffffff) or
                not _integer(context.wdev, 1, 2 ** 64 - 1) or
                not _integer(context.ifindex, 1, 0x7fffffff) or
                not isinstance(context.ifname, str) or not re.match(
                    r'^[A-Za-z0-9_.-]{1,15}\Z', context.ifname) or
                context.ifname in ('lo', 'wlan0') or context.mode not in ('go', 'client') or
                not _integer(context.prefix, 1, 30) or not _hash(context.receipt_id)):
            raise ScopedSocketError('invalid_owned_context')
        local = _ip(context.local_ip)
        address = (local[0] << 24) | (local[1] << 16) | (local[2] << 8) | local[3]
        mask = (0xffffffff << (32 - context.prefix)) & 0xffffffff
        if address in (address & mask, (address & mask) | (mask ^ 0xffffffff)):
            raise ScopedSocketError('invalid_owned_host_address')
        if context.mode == 'client':
            if (type(endpoint) is not PeerEndpoint or not _integer(endpoint.port, 1, 65535)
                    or not _hash(endpoint.proof_id)):
                raise ScopedSocketError('verified_client_endpoint_required')
            _ip(endpoint.host)
            if endpoint.host == context.local_ip:
                raise ScopedSocketError('endpoint_is_local_address')
            peer = _ip(endpoint.host)
            peer_address = (peer[0] << 24) | (peer[1] << 16) | (peer[2] << 8) | peer[3]
            if ((peer_address & mask) != (address & mask) or
                    peer_address in (address & mask, (address & mask) | (mask ^ 0xffffffff))):
                raise ScopedSocketError('endpoint_not_on_owned_subnet')
        elif endpoint is not None:
            raise ScopedSocketError('go_listener_has_no_admitted_endpoint')
        if (not callable(proof_callback) or not callable(cancelled) or
                not callable(getattr(ownership_lock, 'acquire', None)) or
                not callable(getattr(ownership_lock, 'release', None))):
            raise ScopedSocketError('required_owner_callbacks_missing')
        self._context = context
        self._endpoint = endpoint
        self._proof_callback = proof_callback
        self._cancelled = cancelled
        self._owner_lock = ownership_lock
        self._clock = clock or time.monotonic
        self._factory = socket_factory or socket.socket
        self._raw_type = raw_socket_type or socket.socket
        self._select = select_ready or select.select
        self._index = if_nametoindex or getattr(socket, 'if_nametoindex', None)
        if not all(callable(fn) for fn in (self._clock, self._factory, self._select, self._index)):
            raise ScopedSocketError('required_socket_api_unavailable')
        if not isinstance(self._raw_type, type):
            raise ScopedSocketError('invalid_raw_socket_type')
        self._real_factory = socket_factory is None and raw_socket_type is None
        try:
            now = _number(self._clock())
        except ScopedSocketError:
            raise
        except Exception:
            raise ScopedSocketError('clock_failed')
        if not 1 <= _number(context.deadline) - now <= MAX_SESSION_SECONDS:
            raise ScopedSocketError('owned_deadline_out_of_scope')
        self._last_time = now
        self._lock = threading.RLock()
        self._actors = {}
        self._next_actor = 0
        self._attempts = 0
        self._generation = 0
        self._closing = False
        self._handed = []
        self._pending_close = []
        self._closers = {}
        self._verifying = []
        self._reason = 'not_opened'

    @property
    def context(self):
        return self._context

    @property
    def endpoint(self):
        return self._endpoint

    def _now(self):
        try:
            now = _number(self._clock())
        except Exception:
            raise ScopedSocketError('clock_failed')
        with self._lock:
            if now < self._last_time:
                raise ScopedSocketError('clock_moved_backwards')
            self._last_time = now
        return now

    def _begin(self, purpose, allow_closed=False):
        with self._lock:
            if self._closing and not allow_closed:
                raise ScopedSocketError('capsule_closed')
            if len(self._actors) >= MAX_RESOURCES:
                raise ScopedSocketError('actor_limit')
            if purpose in ('listener', 'connector'):
                if self._attempts >= MAX_ATTEMPTS or len(self._handed) + len(self._actors) >= MAX_RESOURCES:
                    raise ScopedSocketError('resource_limit')
                self._attempts += 1
            self._next_actor += 1
            actor = self._next_actor
            self._actors[actor] = {'generation': self._generation, 'socket': None,
                                   'purpose': purpose}
            return actor

    def _basic(self, actor, deadline):
        with self._lock:
            row = self._actors.get(actor)
            if row is None or self._closing or row['generation'] != self._generation:
                raise ScopedSocketError('capsule_closed')
        now = self._now()
        try:
            cancel = self._cancelled()
        except Exception:
            raise ScopedSocketError('cancel_check_failed')
        if type(cancel) is not bool:
            raise ScopedSocketError('cancel_check_invalid')
        if cancel:
            raise ScopedSocketError('cancelled')
        if now >= deadline:
            raise ScopedSocketError('lease_or_connect_expired')
        with self._lock:
            if self._closing or self._actors[actor]['generation'] != self._generation:
                raise ScopedSocketError('capsule_closed')
        return now

    def _acquire_owner(self, budget):
        try:
            acquired = self._owner_lock.acquire(timeout=budget)
        except Exception:
            raise ScopedSocketError('owner_lock_failed')
        if acquired is not True:
            raise ScopedSocketError('owner_lock_timeout')

    def _proof(self, actor, deadline, owner_held=False):
        start = self._basic(actor, deadline)
        budget = min(PROOF_SECONDS, deadline - start)
        acquired = False
        try:
            if not owner_held:
                self._acquire_owner(budget)
                acquired = True
            self._basic(actor, deadline)
            with self._lock:
                purpose = self._actors[actor]['purpose']
            try:
                proof = self._proof_callback(self.context, purpose, budget)
                index = self._index(self.context.ifname)
            except Exception:
                raise ScopedSocketError('scope_readback_failed')
            if self._now() - start > budget:
                raise ScopedSocketError('scope_readback_budget_exceeded')
            if (type(proof) is not ScopeProof or proof.context is not self.context or
                    proof.receipt_stage != 'confirmed' or
                    any(flag is not True for flag in (proof.receipt_fsynced,
                        proof.persistent_readback_verified, proof.owner_verified,
                        proof.address_verified, proof.route_baseline_verified)) or
                    type(index) is not int or index != self.context.ifindex):
                raise ScopedSocketError('owned_scope_unverified')
            peer_flags = (proof.client_association_verified, proof.dhcp_verified, proof.peer_verified)
            if self.context.mode == 'client':
                if proof.endpoint is not self.endpoint or any(flag is not True for flag in peer_flags):
                    raise ScopedSocketError('client_peer_unverified')
            elif proof.endpoint is not None or any(flag is not False for flag in peer_flags):
                raise ScopedSocketError('go_listener_not_peer_authority')
            return self._basic(actor, deadline)
        finally:
            if acquired:
                self._owner_lock.release()

    def _handed_contains(self, raw):
        return any(sock is raw for sock in self._handed)

    def _dispose(self, raw):
        with self._lock:
            if self._handed_contains(raw) or id(raw) in self._closers:
                return False
            self._closers[id(raw)] = raw
        verified = False
        try:
            try:
                raw.close()
                fd = raw.fileno()
                verified = type(fd) is int and fd == -1
            except Exception:
                pass
            return verified
        finally:
            with self._lock:
                self._closers.pop(id(raw), None)
                self._pending_close = [sock for sock in self._pending_close if sock is not raw]
                if not verified:
                    self._pending_close.append(raw)

    def _socket_options(self, raw):
        if (not isinstance(raw, self._raw_type) or isinstance(raw, ssl.SSLSocket) or
                raw.family != socket.AF_INET):
            raise ScopedSocketError('raw_ipv4_tcp_required')
        device = raw.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)
        linger = raw.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)
        if (not isinstance(device, bytes) or device.rstrip(b'\0') != self.context.ifname.encode('ascii') or
                raw.get_inheritable() is not False or not isinstance(linger, bytes) or
                len(linger) != 8 or struct.unpack('=ii', linger)[0] != 0):
            raise ScopedSocketError('socket_scope_readback_failed')
        for option, expected in ((socket.SO_TYPE, socket.SOCK_STREAM), (socket.SO_ACCEPTCONN, 0),
                                 (socket.SO_REUSEADDR, 0), (SO_REUSEPORT, 0)):
            actual = raw.getsockopt(socket.SOL_SOCKET, option)
            if type(actual) is not int or actual != expected:
                raise ScopedSocketError('socket_scope_readback_failed')

    def _unconnected(self, raw):
        try:
            raw.getpeername()
        except OSError as error:
            if error.errno == errno.ENOTCONN:
                return
        raise ScopedSocketError('socket_already_connected')

    def _source(self, raw, requested_port=None):
        source = raw.getsockname()
        if (not isinstance(source, tuple) or len(source) != 2 or
                source[0] != self.context.local_ip or not _integer(source[1], 1, 65535) or
                (requested_port not in (None, 0) and source[1] != requested_port)):
            raise ScopedSocketError('source_binding_readback_failed')
        return source

    def _created(self, actor, deadline):
        self._proof(actor, deadline)
        if self._real_factory and not sys.platform.startswith('linux'):
            raise ScopedSocketError('linux_socket_api_required')
        raw = self._factory(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # Registration precedes any proof/options after a potentially late create.
        with self._lock:
            self._actors[actor]['socket'] = raw
            if (self._handed_contains(raw) or any(sock is raw for sock in self._pending_close) or
                    id(raw) in self._closers or any(key != actor and row['socket'] is raw
                                                 for key, row in self._actors.items())):
                raise ScopedSocketError('socket_identity_already_owned')
        self._proof(actor, deadline)
        if not isinstance(raw, self._raw_type) or isinstance(raw, ssl.SSLSocket) or raw.family != socket.AF_INET:
            raise ScopedSocketError('raw_ipv4_tcp_required')
        raw.set_inheritable(False)
        raw.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.context.ifname.encode('ascii') + b'\0')
        self._socket_options(raw)
        self._unconnected(raw)
        self._proof(actor, deadline)
        return raw

    def _handoff(self, actor, raw, deadline):
        budget = min(PROOF_SECONDS, deadline - self._basic(actor, deadline))
        self._acquire_owner(budget)
        try:
            self._proof(actor, deadline, owner_held=True)
            with self._lock:
                if self._closing or self._actors[actor]['generation'] != self._generation:
                    raise ScopedSocketError('capsule_closed')
                self._handed.append(raw)
                self._actors[actor]['socket'] = None
                self._reason = 'transport_handoff_pending'
                return raw
        finally:
            self._owner_lock.release()

    def _operation(self, purpose, host, port, timeout=None):
        actor = self._begin(purpose)
        raw = None
        try:
            if purpose == 'listener':
                if self.context.mode != 'go' or host != self.context.local_ip or not _integer(port, 0, 65535):
                    raise ScopedSocketError('listener_endpoint_out_of_scope')
                deadline = self.context.deadline
            else:
                if (self.context.mode != 'client' or host != self.endpoint.host or
                        not _integer(port, 1, 65535) or port != self.endpoint.port):
                    raise ScopedSocketError('connector_endpoint_out_of_scope')
                duration = _number(timeout)
                if not 0 < duration <= MAX_CONNECT_SECONDS:
                    raise ScopedSocketError('connect_timeout_out_of_scope')
                deadline = min(self.context.deadline, self._now() + duration)
            raw = self._created(actor, deadline)
            raw.bind((self.context.local_ip, port if purpose == 'listener' else 0))
            source = self._source(raw, port if purpose == 'listener' else None)
            self._socket_options(raw)
            self._unconnected(raw)
            self._proof(actor, deadline)
            if purpose == 'connector':
                raw.setblocking(False)
                if raw.gettimeout() != 0.0:
                    raise ScopedSocketError('nonblocking_readback_failed')
                result = raw.connect_ex((host, port))
                self._proof(actor, deadline)
                pending = (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EAGAIN, errno.EINTR)
                if type(result) is not int or result not in (0,) + pending:
                    raise ScopedSocketError('connect_failed')
                if result != 0:
                    while True:
                        now = self._proof(actor, deadline)
                        ready = self._select([], [raw], [raw], min(POLL_SECONDS, deadline - now))
                        self._proof(actor, deadline)
                        if (not isinstance(ready, tuple) or len(ready) != 3 or ready[0] or
                                any(item is not raw for row in ready[1:] for item in row)):
                            raise ScopedSocketError('connect_poll_readback_failed')
                        if ready[1] or ready[2]:
                            error = raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                            if type(error) is not int or error != 0:
                                raise ScopedSocketError('connect_failed')
                            break
                peer = raw.getpeername()
                if (not isinstance(peer, tuple) or len(peer) != 2 or peer[0] != host or
                        type(peer[1]) is not int or peer[1] != port):
                    raise ScopedSocketError('peer_binding_readback_failed')
                if self._source(raw) != source:
                    raise ScopedSocketError('source_port_changed_during_connect')
                self._socket_options(raw)
                remaining = deadline - self._proof(actor, deadline)
                raw.settimeout(remaining)
                if raw.gettimeout() != remaining:
                    raise ScopedSocketError('socket_timeout_readback_failed')
            else:
                self._unconnected(raw)
            result = self._handoff(actor, raw, deadline)
            raw = None
            return result
        except ScopedSocketError as error:
            with self._lock:
                self._reason = str(error)
            self.close()
            raise
        except Exception:
            with self._lock:
                self._reason = 'socket_operation_failed'
            self.close()
            raise ScopedSocketError('socket_operation_failed')
        finally:
            with self._lock:
                candidate = self._actors[actor]['socket']
            if candidate is not None:
                self._dispose(candidate)
            with self._lock:
                self._actors.pop(actor, None)

    def listener_factory(self, host, port):
        """Bound, unconnected, NOT listening raw TCP; caller remains deny-all."""
        return self._operation('listener', host, port)

    def socket_factory(self, host, port, timeout):
        """Connected raw TCP on independently proven CLIENT endpoint only."""
        return self._operation('connector', host, port, timeout)

    def check(self):
        """Coordinator's ongoing bounded proof; no handed-off socket is closed."""
        actor = self._begin('active')
        try:
            self._proof(actor, self.context.deadline)
            return True
        except ScopedSocketError as error:
            with self._lock:
                self._reason = str(error)
            self.close()
            raise
        finally:
            with self._lock:
                self._actors.pop(actor, None)

    def confirm_transport_closed(self, raw, closed_proof_callback):
        """Resolve exact handoff only with trusted all-resources/actors proof.

        Callback(context, raw, budget) returns TransportClosedProof. Not fileno,
        TLS detach, FD reuse, close() requested or a boolean. Invalid/slow/failed
        proof returns False and keeps this exact resource outstanding.
        """
        if not callable(closed_proof_callback):
            return False
        with self._lock:
            if (not self._handed_contains(raw) or any(sock is raw for sock in self._verifying) or
                    any(row['socket'] is raw for row in self._actors.values())):
                return False
            try:
                actor = self._begin('close_proof', allow_closed=True)
            except ScopedSocketError:
                return False
            self._verifying.append(raw)
        verified = False
        try:
            start = self._now()
            proof = closed_proof_callback(self.context, raw, PROOF_SECONDS)
            verified = (self._now() - start <= PROOF_SECONDS and type(proof) is TransportClosedProof and
                proof.context is self.context and proof.raw_socket is raw and
                proof.all_sockets_closed is True and proof.all_actors_exited is True)
        except Exception:
            pass
        finally:
            with self._lock:
                self._verifying = [sock for sock in self._verifying if sock is not raw]
                self._actors.pop(actor, None)
                if verified:
                    self._handed = [sock for sock in self._handed if sock is not raw]
                else:
                    self._reason = 'transport_close_unverified'
        return verified

    def close(self):
        """Close ONLY pre-handoff sockets; True requires no outstanding owner."""
        with self._lock:
            if not self._closing:
                self._closing = True
                self._generation += 1
            if self._reason == 'not_opened':
                self._reason = 'closed_by_owner'
            candidates = list(self._pending_close)
            for row in self._actors.values():
                raw = row['socket']
                if raw is not None and all(sock is not raw for sock in candidates):
                    candidates.append(raw)
        for raw in candidates:
            self._dispose(raw)
        return self.status()['close_verified']

    def status(self):
        """Passive fixed counts/booleans; no interface/IP/receipt identifiers."""
        with self._lock:
            pending = bool(self._actors or self._handed or self._pending_close or self._closers)
            complete = self._closing and not pending
            stage = 'closed' if complete else ('closing' if self._closing else
                ('active' if self._handed or self._actors else 'new'))
            return {'stage': stage, 'reason': self._reason, 'actors_pending': bool(self._actors or self._closers),
                'handoffs_pending': len(self._handed), 'pre_handoff_close_pending': len(self._pending_close),
                'close_verified': complete, 'peer_authorized': False}
