"""Private CLIENT neighbour observation after the actual native L3 handoff.

No entry point, probe, scan, TCP connect, route/DNS write or endpoint capsule.
DHCP source/option54 is only a candidate. A result is a bounded kernel mapping
to the currently associated GO interface BSSID, not application authentication.
The existing Provider must consume this reader's original close inventory
before IP/network restoration. This module does not enable send or receive.

Linux 4.14 neighbour UAPI: NDA_IFINDEX is the dump filter; ndm_ifindex alone is
not a filter. Intentionally filtered replies carry NLM_F_DUMP_FILTERED.
See linux/v4.14/include/uapi/linux/neighbour.h and net/core/neighbour.c.
Python 3.5; all private packet/status/IP/MAC data stays in retained originals.
"""
import contextlib
import errno
import struct
import threading
from collections import namedtuple

import mta_ip as ip
import mta_p2p_client_init as core
import mta_p2p_client_ctrl as ctrl
import mta_client_dora as dora
import mta_client_dynamic_ip as dynamic

RTM_NEWNEIGH, RTM_GETNEIGH = 28, 30
NDA_DST, NDA_LLADDR, NDA_CACHEINFO, NDA_PROBES, NDA_IFINDEX = 1, 2, 3, 4, 8
NTF_ROUTER = 0x80
NUD_INCOMPLETE, NUD_REACHABLE, NUD_STALE, NUD_DELAY = 1, 2, 4, 8
NUD_PROBE, NUD_FAILED, NUD_NOARP, NUD_PERMANENT = 16, 32, 64, 128
_STATES = frozenset((0, 1, 2, 4, 8, 16, 32, 64, 128))
_RESOLVED = frozenset((NUD_REACHABLE, NUD_STALE, NUD_DELAY, NUD_PROBE))
_HAS_ADDRESS = _RESOLVED | frozenset((NUD_NOARP, NUD_PERMANENT))
_ND = struct.Struct('<BBHiHBB')
_CACHE = struct.Struct('<IIII')
_U32, _S32 = struct.Struct('<I'), struct.Struct('<i')
READ_SECONDS = 5.0
MAX_RECORDS, MAX_BYTES, MAX_DATAGRAMS = 256, 512 * 1024, 32


class PeerReadError(RuntimeError):
    """Fixed source codes/numeric errno only, never OS messages or identifiers."""
    def __init__(self, code, errno=0):
        self.code, self.errno = code, errno
        RuntimeError.__init__(self, code)


def _fail(code, errno=0): raise PeerReadError(code, errno) from None


class NeighborRecord(namedtuple('_NeighborRecord',
        'ifindex destination link_layer state flags kind cacheinfo probes')):
    """Immutable decoded facts, never an ownership or endpoint authority."""
    __slots__ = ()
    def __new__(cls, ifindex, destination, link_layer, state, flags, kind, cacheinfo, probes):
        ip._uint(ifindex, 0x7fffffff, 1); ip._uint(destination)
        if type(state) is not int or state not in _STATES or type(flags) is not int or \
                flags not in (0, NTF_ROUTER) or type(kind) is not int or kind != 1:
            _fail('unsupported_neighbor')
        if (type(cacheinfo) is not tuple or len(cacheinfo) != 4 or
                any(type(v) is not int or not 0 <= v <= ip.UINT_MAX for v in cacheinfo)):
            _fail('invalid_cacheinfo')
        ip._uint(probes)
        if link_layer is not None and (type(link_layer) is not bytes or len(link_layer) != 6 or
                not any(link_layer) or link_layer[0] & 1): _fail('invalid_link_layer')
        if (state in _HAS_ADDRESS) != (link_layer is not None): _fail('neighbor_state_mismatch')
        return tuple.__new__(cls, (ifindex, destination, link_layer, state, flags, kind, cacheinfo, probes))
    def key(self): return tuple(self)
    def mapping_key(self): return self.ifindex, self.destination, self.link_layer


def encode_neighbor_dump(ifindex, sequence, port_id):
    """Read-only AF_INET/one-interface dump; never a destination/subnet scan."""
    ip._uint(ifindex, 0x7fffffff, 1)
    payload = _ND.pack(ip.AF_INET, 0, 0, ifindex, 0, 0, 0)
    payload += ip._attribute(NDA_IFINDEX, _U32.pack(ifindex))
    return ip._message(RTM_GETNEIGH, ip.NLM_F_REQUEST | ip.NLM_F_DUMP,
        sequence, port_id, payload)


def decode_neighbor(payload, ifindex):
    if type(payload) is not bytes or len(payload) < _ND.size: _fail('truncated_neighbor')
    family, pad1, pad2, actual_index, state, flags, kind = _ND.unpack_from(payload)
    if family != ip.AF_INET or pad1 or pad2 or actual_index != ifindex: _fail('neighbor_interface')
    attrs = ip._attributes(payload[_ND.size:], (NDA_DST, NDA_LLADDR, NDA_CACHEINFO, NDA_PROBES))
    if any(key not in attrs for key in (NDA_DST, NDA_CACHEINFO, NDA_PROBES)):
        _fail('missing_neighbor_attribute')
    if len(attrs[NDA_DST]) != 4 or len(attrs[NDA_CACHEINFO]) != _CACHE.size or len(attrs[NDA_PROBES]) != 4:
        _fail('invalid_neighbor_attribute')
    return NeighborRecord(ifindex, int.from_bytes(attrs[NDA_DST], 'big'), attrs.get(NDA_LLADDR),
        state, flags, kind, _CACHE.unpack(attrs[NDA_CACHEINFO]), _U32.unpack(attrs[NDA_PROBES])[0])


class NeighborCollector(object):
    """Correlated, finite, poison-on-error multipart neighbour dump."""
    def __init__(self, ifindex, sequence, port_id):
        self.request = encode_neighbor_dump(ifindex, sequence, port_id)
        self.ifindex, self.sequence, self.port_id = ifindex, sequence, port_id
        self.complete = self.failed = False
        self._records, self._seen, self._bytes, self._datagrams = [], set(), 0, 0
    def _error(self, flags, payload):
        if flags & ~ip.NLM_F_CAPPED or len(payload) < 20: _fail('invalid_neighbor_ack')
        error = _S32.unpack_from(payload)[0]
        if not -4095 <= error < 0 or payload[4:20] != self.request[:16]: _fail('invalid_neighbor_ack')
        if flags & ip.NLM_F_CAPPED:
            if len(payload) != 20: _fail('invalid_neighbor_ack')
        elif len(payload) != 4 + len(self.request) or payload[4:] != self.request:
            _fail('invalid_neighbor_ack')
        _fail('neighbor_kernel_error', -error)
    def feed(self, datagram):
        if self.failed or self.complete:
            self.failed = True; _fail('neighbor_dump_consumed')
        try:
            messages = ip._messages(datagram)
            if self._bytes + len(datagram) > MAX_BYTES or self._datagrams >= MAX_DATAGRAMS:
                _fail('neighbor_dump_limit')
            pending, seen, finished = [], set(self._seen), False
            for kind, flags, sequence, port_id, payload in messages:
                if finished: _fail('neighbor_message_after_done')
                if sequence != self.sequence or port_id != self.port_id: _fail('neighbor_dump_identity')
                if flags & ip.NLM_F_DUMP_INTR: _fail('neighbor_dump_interrupted')
                if kind == ip.NLMSG_ERROR: self._error(flags, payload)
                if kind == ip.NLMSG_DONE:
                    if flags not in (0, ip.NLM_F_MULTI, ip.NLM_F_MULTI | ip.NLM_F_DUMP_FILTERED) or len(payload) != 4:
                        _fail('invalid_neighbor_done')
                    error = _S32.unpack(payload)[0]
                    if not -4095 <= error <= 0: _fail('invalid_neighbor_errno')
                    if error: _fail('neighbor_kernel_error', -error)
                    finished = True; continue
                if kind != RTM_NEWNEIGH or flags != ip.NLM_F_MULTI | ip.NLM_F_DUMP_FILTERED:
                    _fail('unexpected_neighbor_message')
                record = decode_neighbor(payload, self.ifindex)
                identity = record.ifindex, record.destination
                if identity in seen: _fail('duplicate_neighbor')
                seen.add(identity); pending.append(record)
                if len(self._records) + len(pending) > MAX_RECORDS: _fail('neighbor_record_limit')
            self._records.extend(pending); self._seen = seen
            self._bytes += len(datagram); self._datagrams += 1; self.complete = finished
        except BaseException:
            self.failed = True
            raise
    def records(self):
        if self.failed or not self.complete: _fail('incomplete_neighbor_dump')
        return tuple(self._records)


class ClientPeerReader(object):
    """One actual L3 owner, one bounded observation, original resource inventory.

    None means absent/unresolved neighbour, not a guessed endpoint. Even a
    returned record is only an observation; no detached proof, socket factory,
    user callback or boolean can grant authority through this module.
    An active ARP producer is deliberately absent. A later implementation must
    restrict it to this original candidate/owned interface/BSSID and preserve
    original deadline, raw ingress and once-close before it can be consumed.
    """
    def __init__(self, ip_owner, _transport=None):
        if type(ip_owner) is not dynamic.ClientDynamicIp: _fail('native_ip_owner_required')
        self.ip_owner, self.provider, self.lease, self.store = ip_owner, ip_owner.provider, ip_owner.lease, ip_owner.store
        self.handoff, self.operation, self.owned = ip_owner.handoff, ip_owner.dora._operation, ip_owner.owned
        if (type(self.provider) is not dora.linux.LinuxClientInitProvider or
                type(self.handoff) is not dora.L3Handoff or self.handoff._issuer is not ip_owner.dora or
                self.handoff._operation is not self.operation or self.provider._connection is not self.operation or
                self.provider._client_ip_owner_v28 is not ip_owner or self.provider._owned is not self.owned or
                type(ip_owner.record) is not dynamic.DynamicIpRecord or ip_owner.record.phase != 'applied' or
                not ip_owner.applied or ip_owner.unknown or ip_owner.mutation_unknown or ip_owner.cleanup_called):
            _fail('applied_ip_owner_required')
        if getattr(self.provider, '_client_peer_owner_v29', None) is not None: _fail('already_registered')
        self.request, self.binding, self.credentials, self.group = self.operation.request, self.operation.binding, self.operation.credentials, self.operation.group
        self._info_wire, self._binding_wire = self.request._info_wire, self.binding._wire
        self._peer_port = self.operation.peer_port
        if type(self._peer_port) is not int or not 1 <= self._peer_port <= 65535: _fail('invalid_original_port')
        self._ack, self._configuration = self.handoff._ack, self.handoff._configuration
        self._packet, self._source = self._ack['packet'], self._ack['source']
        self._ancillary = tuple(self._ack['ancillary'])
        self._candidate = ip.ipv4_number(self._configuration.server_ip)
        self._deadline = self.handoff._until
        self._ip_record_key = ip_owner.record.key()
        self._record_key = self.lease.record.key()
        self.transport = dynamic.ClientRouteTransport(self.lease._now, _io=self.provider._io) if _transport is None else _transport
        if (type(self.transport) is not dynamic.ClientRouteTransport or self.transport.io is not self.provider._io or
                getattr(self.transport.clock, '__self__', None) is not self.lease or
                getattr(self.transport.clock, '__func__', None) is not core.ClientInitLease._now or
                self.transport.ticket is not None or self.transport.closed or self.transport.unknown or self.transport.rows):
            _fail('native_route_transport_required')
        self._transport_io, self._transport_clock, self._transport_creator = self.transport.io, self.transport.clock, self.transport.creator
        self._mutex, self._worker = self.store._mutex, threading.current_thread()
        self._locks, self._store_epoch = self.lease.locks, self.store._epoch
        self._journal_epoch, self._marker, self._store_binding = self.store._journal_epoch, self.store._marker, self.store._binding
        self._device = self._locks._device
        self.rows, self.associations, self.failures, self.lock_rows = [], [], [], []
        self.link_rows = []
        self._last = self._result = self._read_until = self._close_until = None
        self._fixed_scope = self._descriptor_cleanup_until = None
        self._open_ticket, self._open_started, self._open_returned = None, False, False
        self._open_original = None
        self._close_transport_called = self._close_transport_returned = False
        self.started = self._active = self.unknown = self.close_called = False
        self.reason = 'not_started'
        self.provider._client_peer_owner_v29 = self  # Before any native factory/IO.
    def _time(self, until=None):
        now = dynamic._number(self.lease._now())
        if self._last is not None and now < self._last: _fail('clock_regressed')
        self._last = now
        if until is not None and now >= dynamic._number(until): _fail('peer_read_deadline')
        return now
    def _io_until_for_provider(self, provider, deadline):
        """Pure deadline tightening from this registered native read original.

        No IO, new grant, callback, caller scope object or renewed timestamp.
        Existing Provider/Store authority checks remain separately mandatory.
        Inactive/descriptor-close-only phases never tighten restoration.
        """
        dynamic._number(deadline)
        if (provider is not self.provider or provider._client_peer_owner_v29 is not self):
            _fail('peer_owner_changed')
        if not self._active: return float(deadline)
        scope = self._fixed_scope
        if (threading.current_thread() is not self._worker or self.store._mutex is not self._mutex or
                provider._store is not self.store or provider._lease is not self.lease or
                provider._client_ip_owner_v28 is not self.ip_owner or provider._connection is not self.operation or
                self.ip_owner.handoff is not self.handoff or self.handoff._operation is not self.operation or
                self.handoff._mutex is not self._mutex or self.handoff._locks is not self._locks or
                self.lease.locks is not self._locks or self.store._current_locks is not self._locks or
                self.store._epoch is not self._store_epoch or self.store._journal_epoch is not self._journal_epoch or
                self.store._marker is not self._marker or self.store._binding is not self._store_binding or
                self._locks._device is not self._device or provider._owned is not self.owned or
                type(scope) is not tuple or len(scope) != 3 or self._read_until != scope[1] or
                self._descriptor_cleanup_until != scope[2] or
                scope[1] != min(self._deadline, scope[0] + READ_SECONDS) or
                scope[2] != scope[1] + dynamic.IO_SECONDS or not scope[0] < scope[1] <= self._deadline or
                not scope[1] < scope[2] <= scope[0] + READ_SECONDS + dynamic.IO_SECONDS):
            _fail('peer_read_scope_changed')
        return min(float(deadline), self._read_until)
    @contextlib.contextmanager
    def _scope(self, until):
        row = {'mutex': self._mutex, 'returned': None, 'acquired': False,
            'release_called': False, 'release_result': False, 'release_returned': False,
            'observation_unknown': False, 'unknown': True}
        self.lock_rows.append(row)  # Before the original timed acquisition.
        try:
            now = self._time(until)
            row['returned'] = self._mutex.acquire(timeout=min(dora.LOCK_SECONDS, until - now))
            row['acquired'] = row['returned'] is True
            self._time(until)
            if type(row['returned']) is not bool: _fail('owner_lock_unknown')
            if not row['acquired']:
                row['unknown'] = False; _fail('owner_lock_pending')
            yield
        finally:
            if row['acquired']:
                row['release_called'] = True
                try:
                    value = self._mutex.release(); row['release_result'] = value
                    row['release_returned'] = value is None
                    if not row['release_returned']: _fail('owner_release_unknown')
                    row['unknown'] = False  # Actual release is known even if its observation is late.
                    self._time(until)
                except BaseException:
                    row['observation_unknown'] = True; self.unknown = True
                    raise
    def _gate(self, until):
        """Same locked transaction's quick continuity, NOT a fresh IO proof.

        Full Store/controller/link reads bracket read(). Native STATUS/kernel
        and IP/neighbour dumps remain real reads. Re-running the full Proc
        tree for every message consumed the fixed inventory before STATUS.
        No resource limits or original network grant are increased here.
        """
        self._time(until)
        self._io_until_for_provider(self.provider, until)
        if (self.store._mutex is not self._mutex or self.handoff._mutex is not self._mutex or
                self.provider._client_peer_owner_v29 is not self or self.provider._client_ip_owner_v28 is not self.ip_owner or
                self.ip_owner.handoff is not self.handoff or self.provider._connection is not self.operation or
                self.provider._owned is not self.owned or self.operation.owned is not self.owned or
                self.transport.io is not self._transport_io or self.provider._io is not self._transport_io or
                self.transport.clock is not self._transport_clock or
                self.transport.creator is not self._transport_creator or
                self.operation.request is not self.request or self.operation.binding is not self.binding or
                self.operation.credentials is not self.credentials or self.operation.group is not self.group or
                self.request._info_wire is not self._info_wire or self.binding._wire != self._binding_wire or
                type(self.operation.peer_port) is not int or self.operation.peer_port != self._peer_port):
            _fail('peer_owner_changed')
        info = dora.frame.ConnectRequest.private_info(self.request)
        if info.port != self._peer_port: _fail('original_port_changed')
        current, canonical = self.lease.record, self.store._canonical
        if (type(current) is not core.Journal or current.key() != self._record_key or
                type(canonical) is not dora.linux.stores.files.CanonicalRecord or
                type(canonical.journal) is not core.Journal or canonical.journal.key() != self._record_key or
                not self.store.session_issued_v28(current, self.store._session_profile, current.deadline) or
                self.ip_owner.unknown or self.ip_owner.mutation_unknown or self.ip_owner.cleanup_called or
                not self.ip_owner.applied or type(self.ip_owner.record) is not dynamic.DynamicIpRecord or
                self.ip_owner.record.key() != self._ip_record_key or
                not dora.PrivateClientDora.l3_handoff_current(self.ip_owner.dora,
                    self.handoff, self.ip_owner, current, True)):
            _fail('l3_continuity_changed')
        value = current.client_ip
        if type(value) is not dynamic.DynamicIpRecord or value.phase != 'applied' or value.key() != self._ip_record_key:
            _fail('applied_ip_changed')
        ack = self._ack
        if (self.handoff._ack is not ack or not any(row is ack for row in self.ip_owner.dora._acks) or
                not ack['accepted'] or ack['unknown'] or ack['packet'] is not self._packet or
                ack['source'] is not self._source or tuple(ack['ancillary']) != self._ancillary or
                ack['flags'] != 0 or ack['configuration'] is not self._configuration or
                self.handoff._configuration is not self._configuration or type(self._source) is not tuple or
                len(self._source) != 2 or type(self._source[1]) is not int or self._source[1] != 67 or
                ip.ipv4_number(self._source[0]) != self._candidate): _fail('original_ack_changed')
        decoded = dora.wire.decode(self._packet)
        if ip.ipv4_number(dora.wire.address(decoded['options'][54])) != self._candidate: _fail('original_ack_changed')
        mask = ip._mask(value.prefix); last = value.local_ip | (ip.UINT_MAX ^ mask)
        if (not ip._private(self._candidate) or self._candidate == value.local_ip or
                self._candidate & mask != value.local_ip & mask or self._candidate in (value.local_ip & mask, last)):
            _fail('candidate_out_of_scope')
        self._time(until)
        return current
    def _full_link_gate(self, until):
        """Actual fresh Store/current/controller/link read at phase boundary."""
        self._gate(until)
        row = {'current': None, 'unknown': True}
        self.link_rows.append(row)
        row['current'] = dynamic.ClientDynamicIp._link_gate(self.ip_owner, until, True)
        if row['current'].key() != self._record_key: _fail('journal_changed')
        self._gate(until); row['unknown'] = False
        return row['current']
    def _association(self, until):
        current = self._gate(until)
        row = {'operation': self.operation, 'status_wire': None, 'status': None, 'kernel': None, 'unknown': True}
        self.associations.append(row)  # Original before native control/kernel IO.
        dora.connection._Connection._drain(self.operation)
        raw = dora.connection._Connection._exchange(self.operation, ctrl.status_command().private_bytes())
        row['status_wire'] = raw; self._gate(until)
        report = ctrl.parse_status(raw, self.credentials); row['status'] = report
        fields, saved = report.private_fields(), current.association
        if (not report.public_summary()['ctrl_completed'] or fields.get('id') != self.operation.network_id or
                fields.get('address') != saved.local_mac or fields.get('bssid') != saved.bssid or
                fields.get('freq') != saved.frequency or fields.get('ip_address', current.client_ip.local_ip) != current.client_ip.local_ip):
            _fail('l3_status_mismatch')
        # This actual reader does not run the old no-L3 snapshot/receipt path.
        observation = dora.linux.LinuxClientInitProvider._connection_kernel(self.provider, self.operation, self.operation.deadline)
        row['kernel'] = observation; self._gate(until)
        dora.connection._Connection._kernel_fields(self.operation, observation, fields, self.group.private_fields())
        kernel = observation.private_fields()
        if (kernel['local_mac'], kernel['stations'][0][0], kernel['channel'][1]) != (saved.local_mac, saved.bssid, saved.frequency):
            _fail('l3_kernel_mismatch')
        dora.connection._Connection._drain(self.operation)
        self._gate(until); row['unknown'] = False
        return saved.bssid
    def _ip_readback(self, until):
        current = self._gate(until)
        snapshot = self.transport.stable_snapshot(until)
        if dynamic.snapshot_key(snapshot) != dynamic.snapshot_key(current.client_ip.observed): _fail('l3_readback_changed')
        self._gate(until)
    def _neighbors(self, until):
        self._gate(until)
        collector = NeighborCollector(self.owned.ifindex, self.transport._next(), self.transport.port_id)
        row = {'collector': collector, 'transport_row': None, 'records': None, 'match': None, 'unknown': True}
        self.rows.append(row)
        row['transport_row'] = self.transport._send(collector.request, until)
        while not collector.complete:
            self._gate(until)
            collector.feed(self.transport._recv(row['transport_row'], until))
            self._gate(until)
        records = collector.records(); row['records'] = records
        matches = tuple(record for record in records if record.destination == self._candidate)
        if len(matches) > 1: _fail('duplicate_candidate')
        row['match'] = matches[0] if matches else None; row['unknown'] = False
        return row['match']
    def read(self):
        if self.started or self.close_called: _fail('already_started')
        self.started = True
        error, found = None, None
        try:
            started = self._time()
            until = min(self._deadline, started + READ_SECONDS)
            self._fixed_scope = (started, until, until + dynamic.IO_SECONDS)
            self._read_until, self._descriptor_cleanup_until = self._fixed_scope[1:]
            # Both absolute ends are fixed BEFORE acquire/factory/any native IO.
            # Only the first is network-active; the second permits descriptor close.
            self._active = True
            with self._scope(until):
                self._full_link_gate(until)
                bssid = self._association(until)
                self._gate(until); self._open_started = True
                dynamic.ClientRouteTransport.open(self.transport, until)
                self._open_ticket, self._open_returned = self.transport.ticket, True
                self._open_original = (self._open_ticket['creator'], self._open_ticket['raw'],
                    self._open_ticket['fd'], self._open_ticket['metadata'])
                self._gate(until)
                self._ip_readback(until)
                first, second = self._neighbors(until), self._neighbors(until)
                fresh_bssid = self._association(until)
                self._ip_readback(until)
                self._full_link_gate(until)
                if fresh_bssid != bssid: _fail('association_changed')
                if first is None or second is None:
                    self.reason = 'neighbor_absent'
                elif first.state not in _RESOLVED or second.state not in _RESOLVED:
                    self.reason = 'neighbor_unresolved'
                elif first.mapping_key() != second.mapping_key() or second.link_layer != bssid:
                    _fail('neighbor_peer_mismatch')
                else:
                    found = second; self.reason = 'neighbor_mapping_observed'
                self._gate(until)
        except BaseException as failure:
            error = failure; self.failures.append(failure); self.unknown = True
            self.reason = failure.code if type(failure) is PeerReadError else 'peer_io_unknown'
        finally:
            self._active = False
            if self._descriptor_cleanup_until is not None:
                # No clock-derived renewal here, even when the grant expired.
                self.close(self._descriptor_cleanup_until)
            else: self.unknown = True
        if error is not None: raise error
        if not all(closed for attempted, closed in self.closed_facts()): _fail('peer_close_unknown')
        if self.unknown: _fail('peer_observation_unknown')
        self._result = found
        return found
    def close(self, recovery_until):
        if self.close_called: return all(closed for attempted, closed in self.closed_facts())
        if self._active: return False  # No close while an actual producer is still running.
        self.close_called = True  # Logical request; transport alone owns raw.close.
        try:
            now = self._time(); recovery_until = dynamic._number(recovery_until)
            if not 0 < recovery_until - now <= 60: _fail('invalid_close_scope')
            if self._descriptor_cleanup_until is None:
                # Pure constructor/no-read cleanup consumes only the actual
                # existing Lease restore cap, never an arbitrary new period.
                if self.started or self.store._recovery_deadline != recovery_until:
                    _fail('invalid_close_scope')
                self._descriptor_cleanup_until = recovery_until
            self._close_until = min(recovery_until, self._descriptor_cleanup_until)
            if self._close_until <= now or self.provider._client_peer_owner_v29 is not self:
                _fail('invalid_close_scope')
            if (type(self.transport) is not dynamic.ClientRouteTransport or
                    self.transport.io is not self._transport_io or self.provider._io is not self._transport_io or
                    self.transport.clock is not self._transport_clock or self.transport.creator is not self._transport_creator):
                _fail('peer_transport_changed')
            self._close_transport_called = True
            result = dynamic.ClientRouteTransport.close(self.transport, self._close_until)
            self._close_transport_returned = type(result) is bool
            self._time(self._close_until)
        except BaseException as failure:
            self.failures.append(failure); self.unknown = True
        return all(closed for attempted, closed in self.closed_facts())
    def _transport_closed_facts(self):
        """Physical originals only; observation failure is not FD uncertainty.

        A successful native open and this actual native close call are required.
        Generic receive/parse/late-observation flags remain untouched. A partial
        or late factory is still pending, even if a returned raw later closed.
        """
        row = self.transport.ticket
        if row is None:
            return () if not self._open_started else ((False, False),)
        error = row['ebadf']
        known = (self._open_returned and row is self._open_ticket and
            type(self._open_original) is tuple and len(self._open_original) == 4 and
            self.transport.io is self._transport_io and self.provider._io is self._transport_io and
            self.transport.clock is self._transport_clock and self.transport.creator is self._transport_creator and
            row['creator'] is self._transport_creator and row['creator'] is self._open_original[0] and
            row['raw'] is self._open_original[1] and row['fd'] == self._open_original[2] and
            row['metadata'] == self._open_original[3] and row['factory_returned'] and not row['factory_active'] and
            row['raw'] is not None and type(row['fd']) is int and row['metadata'] is not None and
            self._close_transport_called and self._close_transport_returned and
            row['close_called'] and row['close_returned'] and row['close_result'] is None and
            row['close_error'] is None and row['fileno_closed'] and isinstance(error, OSError) and
            type(error.errno) is int and error.errno == errno.EBADF)
        return ((bool(row['close_called']), bool(known)),)
    def closed_facts(self):
        locks_known = all(row['mutex'] is self._mutex and type(row['returned']) is bool and
            ((row['returned'] is False and row['acquired'] is False and not row['release_called']) or
             (row['returned'] is True and row['acquired'] is True and row['release_called'] and
              row['release_returned'] and row['release_result'] is None)) for row in self.lock_rows)
        known = (self.provider._client_peer_owner_v29 is self and self.store._mutex is self._mutex and
            self.close_called and not self._active and locks_known)
        return ((self.close_called, bool(known)),) + tuple((a, bool(c and known)) for a, c in self._transport_closed_facts())
    def status(self):
        return {'started': self.started, 'neighbor_mapping_observed': self._result is not None,
            'observation_unknown': self.unknown,
            'closed': all(closed for attempted, closed in self.closed_facts()),
            'resource_pending': not all(closed for attempted, closed in self.closed_facts()),
            'reason': self.reason, 'neighbor_dumps': len(self.rows), 'association_reads': len(self.associations),
            'arp_probe_implemented': False, 'endpoint_verified': False, 'send_available': False,
            'receive_available': False, 'phone_tested': False, 'production_available': False}
