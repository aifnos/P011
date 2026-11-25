"""Private CLIENT ACK-address sublease. No main, shell, default route or DNS.

Construction is pure and registration precedes the first IO. A default owner
has no durable producer and start therefore refuses without opening a socket.
Only the actual DORA L3Handoff plus actual Journal/current/lock generations can
authorize an address intent. HOST transport models are not P011/phone evidence.
Python 3.5; neither stdlib json nor a GO static-subnet chooser is required.
"""
import errno
import math
import os
import socket
import stat
import struct
from collections import namedtuple
import mta_ip as ip
import mta_p2p_client_init as core

IO_SECONDS = 5.0
MAX_REQUESTS, MAX_DATAGRAMS, MAX_WIRE_BYTES = 64, 128, 8 * 1024 * 1024
_PHASES = ('intent', 'applied', 'delete_intent', 'restored')


class DynamicIpError(RuntimeError):
    def __init__(self, code):
        self.code = code
        RuntimeError.__init__(self, code)


def _fail(code): raise DynamicIpError(code) from None


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(float(value)) or not 0 <= value < 1e12:
        _fail('invalid_deadline')
    return float(value)


def snapshot_key(value):
    """Full private facts, including all cacheinfo; no object identity shortcut."""
    if type(value) is not ip.IpSnapshot: _fail('invalid_snapshot')
    core._ipv4(value)
    return (tuple(sorted((tuple(r) for r in value.addresses), key=repr)),
        tuple(sorted((tuple(r) for r in value.routes), key=repr)), tuple(sorted(value.rules)))


class DynamicAddressSpec(namedtuple('_DynamicAddressSpec', 'ifindex address prefixlen')):
    __slots__ = ()
    def __new__(cls, ifindex, address, prefixlen):
        ip._uint(ifindex, 0x7fffffff, 1)
        local = ip.ipv4_number(address)
        if type(prefixlen) is not int or not 8 <= prefixlen <= 30: _fail('unsupported_prefix')
        mask = ip._mask(prefixlen); network, broadcast = local & mask, local | (ip.UINT_MAX ^ mask)
        if not ip._private(network) or not ip._private(broadcast) or local in (network, broadcast):
            _fail('invalid_address')
        return super(DynamicAddressSpec, cls).__new__(cls, ifindex, local, prefixlen)
    def __repr__(self): return '<private CLIENT dynamic address spec>'


def encode_address(spec, sequence, port_id, create):
    if type(spec) is not DynamicAddressSpec or type(create) is not bool: _fail('invalid_address')
    wire = struct.pack('>I', spec.address)
    broadcast = spec.address | (ip.UINT_MAX ^ ip._mask(spec.prefixlen))
    payload = (struct.pack('<BBBBI', ip.AF_INET, spec.prefixlen, ip.IFA_F_PERMANENT, 0, spec.ifindex) +
        ip._attribute(ip.IFA_ADDRESS, wire) + ip._attribute(ip.IFA_LOCAL, wire) +
        ip._attribute(ip.IFA_BROADCAST, struct.pack('>I', broadcast)))
    command = ip.RTM_NEWADDR if create else ip.RTM_DELADDR
    flags = ip.NLM_F_REQUEST | ip.NLM_F_ACK
    if create: flags |= ip.NLM_F_CREATE | ip.NLM_F_EXCL
    return ip._message(command, flags, sequence, port_id, payload)


def expected_routes(spec):
    if type(spec) is not DynamicAddressSpec: _fail('invalid_address')
    network = spec.address & ip._mask(spec.prefixlen)
    broadcast = spec.address | (ip.UINT_MAX ^ ip._mask(spec.prefixlen))
    def row(destination, prefix, table, scope, kind):
        return ip.RouteRecord(destination, prefix, table, 2, scope, kind, 0,
            spec.ifindex, None, None, spec.address, ())
    return (row(network, spec.prefixlen, 254, 253, 1), row(spec.address, 32, 255, 254, 2),
        row(network, 32, 255, 253, 3), row(broadcast, 32, 255, 253, 3))


def _without_delta(observed, baseline, owned, spec):
    snapshot_key(observed); snapshot_key(baseline)
    addresses = tuple(r for r in observed.addresses if r.ifindex == owned.ifindex)
    routes = tuple(r for r in observed.routes if r.oif == owned.ifindex)
    if len(addresses) != 1: _fail('address_readback')
    row = addresses[0]
    broadcast = spec.address | (ip.UINT_MAX ^ ip._mask(spec.prefixlen))
    if tuple(row[:-1]) != (spec.ifindex, spec.address, spec.address, spec.prefixlen,
            ip.IFA_F_PERMANENT, 0, owned.name.encode('ascii') + b'\0', broadcast):
        _fail('address_readback')
    if row.cacheinfo is None or row.cacheinfo[:2] != (ip.UINT_MAX, ip.UINT_MAX): _fail('address_lifetime')
    expected = expected_routes(spec)
    if len(routes) != len(expected) or set(routes) != set(expected): _fail('automatic_route_delta')
    result = ip.IpSnapshot(tuple(r for r in observed.addresses if r is not row),
        tuple(r for r in observed.routes if r not in routes), observed.rules)
    if snapshot_key(result) != snapshot_key(baseline): _fail('baseline_changed')
    return result


class DynamicIpRecord(object):
    """Durable schema facts ONLY. This is neither a DORA grant nor a close proof."""
    __slots__ = ('phase', 'owned', 'local_ip', 'prefix', 'allocation_until', 'baseline', 'observed')
    def __init__(self, phase, owned, local_ip, prefix, allocation_until, baseline, observed=None):
        if type(phase) is not str or phase not in _PHASES or type(owned) is not core.Origin or owned.iftype != 8:
            _fail('invalid_record')
        spec = DynamicAddressSpec(owned.ifindex, local_ip, prefix)
        until = _number(allocation_until); snapshot_key(baseline)
        if any(r.ifindex == owned.ifindex for r in baseline.addresses) or any(r.oif == owned.ifindex for r in baseline.routes):
            _fail('baseline_owned_l3')
        if phase == 'intent':
            if observed is not None: _fail('invalid_record')
        elif phase == 'restored':
            if snapshot_key(observed) != snapshot_key(baseline): _fail('baseline_changed')
        else: _without_delta(observed, baseline, owned, spec)
        for name, value in (('phase', phase), ('owned', owned), ('local_ip', spec.address),
                ('prefix', prefix), ('allocation_until', until), ('baseline', baseline), ('observed', observed)):
            object.__setattr__(self, name, value)
    def __setattr__(self, name, value): raise AttributeError('private immutable IP facts')
    def __repr__(self): return '<private CLIENT IP record {}>'.format(self.phase)
    def facts_key(self):
        return (self.owned.key(), self.local_ip, self.prefix, self.allocation_until, snapshot_key(self.baseline))
    def key(self): return (self.phase, self.facts_key(), None if self.observed is None else snapshot_key(self.observed))
    def replace(self, phase, observed):
        return DynamicIpRecord(phase, self.owned, ip.ipv4_text(self.local_ip), self.prefix,
            self.allocation_until, self.baseline, observed)


def same_record(left, right):
    return type(left) is DynamicIpRecord and type(right) is DynamicIpRecord and left.key() == right.key()


def _snapshot_data(value):
    snapshot_key(value)
    return {'addresses': [[r.ifindex, r.local, r.address, r.prefixlen, r.flags, r.scope,
        None if r.label is None else r.label.hex(), r.broadcast, None if r.cacheinfo is None else list(r.cacheinfo)]
        for r in sorted(value.addresses, key=lambda row: repr(tuple(row)))],
        'routes': [list(r[:-1]) + [[list(v) for v in r.metrics]] for r in sorted(value.routes, key=lambda row: repr(tuple(row)))],
        'rules': [list(r) for r in sorted(value.rules)]}


def _snapshot_from_data(value):
    if type(value) is not dict or set(value) != {'addresses', 'routes', 'rules'} or any(
            type(value[k]) is not list or len(value[k]) > ip.MAX_DUMP_RECORDS for k in value): _fail('invalid_snapshot')
    try:
        addresses = []
        for row in value['addresses']:
            if type(row) is not list or len(row) != 9: _fail('invalid_snapshot')
            label = None if row[6] is None else bytes.fromhex(row[6])
            cache = None if row[8] is None else tuple(row[8])
            addresses.append(ip.AddressRecord(*(row[:6] + [label, row[7], cache])))
        routes = []
        for row in value['routes']:
            if type(row) is not list or len(row) != 12 or type(row[-1]) is not list: _fail('invalid_snapshot')
            routes.append(ip.RouteRecord(*(row[:-1] + [tuple(tuple(v) for v in row[-1])])))
        result = ip.IpSnapshot(tuple(addresses), tuple(routes), tuple(ip.RuleRecord(*r) for r in value['rules']))
        if _snapshot_data(result) != value: _fail('invalid_snapshot')
        return result
    except (ValueError, TypeError, IndexError, AttributeError): _fail('invalid_snapshot')


def record_data(record):
    if type(record) is not DynamicIpRecord: _fail('invalid_record')
    return {'phase': record.phase, 'owned': list(record.owned.key()), 'local_ip': record.local_ip,
        'prefix': record.prefix, 'allocation_until': record.allocation_until,
        'baseline': _snapshot_data(record.baseline),
        'observed': None if record.observed is None else _snapshot_data(record.observed)}


def record_from_data(value):
    if type(value) is not dict or set(value) != set(DynamicIpRecord.__slots__) or \
            type(value['owned']) is not list or len(value['owned']) != 5 or type(value['local_ip']) is not int or \
            type(value['allocation_until']) is not float: _fail('invalid_record')
    result = DynamicIpRecord(value['phase'], core.Origin(*value['owned']), ip.ipv4_text(value['local_ip']),
        value['prefix'], value['allocation_until'], _snapshot_from_data(value['baseline']),
        None if value['observed'] is None else _snapshot_from_data(value['observed']))
    if record_data(result) != value: _fail('invalid_record')
    return result


def _metadata(value):
    result = tuple(getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_rdev'))
    if any(type(v) is not int or v < 0 for v in result) or not stat.S_ISSOCK(result[2]): _fail('socket_identity')
    return result


class ClientRouteTransport(object):
    """Pure constructor, exact retained raw socket, one close/immediate EBADF.

    IO limits bound this candidate's wire history, not the entire process heap.
    Snapshot and ACK messages use the already-reviewed mta_ip byte primitives.
    """
    def __init__(self, clock, _socket_factory=None, _io=None, _sequence=None):
        self.clock, self.io = clock, os if _io is None else _io
        self.creator = socket.socket if _socket_factory is None else _socket_factory
        self.sequence = _sequence
        self.ticket, self.rows, self.wire_bytes, self.datagrams = None, [], 0, 0
        self.last, self.closed, self.unknown = None, False, False
    def _now(self, deadline=None):
        value = _number(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if deadline is not None and value >= _number(deadline): _fail('deadline')
        return value
    def open(self, deadline):
        self._now(deadline)
        if self.ticket is not None or self.closed: _fail('already_started')
        row = {'creator': self.creator, 'raw': None, 'fd': None, 'metadata': None,
            'factory_started': True, 'factory_returned': False, 'factory_active': True,
            'unknown': True, 'close_requested': False, 'close_called': False, 'close_returned': False,
            'close_result': None, 'close_error': None, 'ebadf': None, 'fileno_closed': False}
        self.ticket = row
        try:
            raw = row['creator'](socket.AF_NETLINK, socket.SOCK_RAW, 0)
            row['raw'], row['factory_returned'] = raw, True
            descriptor = raw.fileno(); row['fd'] = descriptor
            if type(descriptor) is not int or not 0 <= descriptor <= 0x7fffffff: _fail('socket_identity')
            row['metadata'] = _metadata(self.io.fstat(descriptor)); self._now(deadline)
            raw.set_inheritable(False); self._now(deadline)
            raw.bind((0, 0)); self._now(deadline)
            address = raw.getsockname()
            if type(address) is not tuple or len(address) != 2 or type(address[0]) is not int or \
                    not 0 < address[0] <= ip.UINT_MAX or type(address[1]) is not int or address[1] != 0:
                _fail('socket_identity')
            self.port_id = address[0]
            if self.sequence is None: self.sequence = int.from_bytes(os.urandom(4), 'little') & 0x7fffffff
            ip._uint(self.sequence, ip.UINT_MAX - 1)
            self._now(deadline); row['unknown'] = False
        except BaseException:
            self.unknown = row['unknown'] = True
            raise
        finally: row['factory_active'] = False
    def _next(self):
        if self.closed or self.ticket is None or self.ticket['unknown'] or self.sequence >= ip.UINT_MAX:
            _fail('transport_unavailable')
        self.sequence += 1
        return self.sequence
    def prepare_address(self, spec, create): return encode_address(spec, self._next(), self.port_id, create)
    def _budget(self, deadline):
        now = self._now(deadline)
        if self.closed or self.ticket is None or self.ticket['unknown'] or self.unknown: _fail('transport_unavailable')
        row = self.ticket; descriptor = row['raw'].fileno()
        if type(descriptor) is not int or descriptor != row['fd'] or _metadata(self.io.fstat(descriptor)) != row['metadata']:
            self.unknown = row['unknown'] = True; _fail('socket_identity')
        row['raw'].settimeout(min(IO_SECONDS, deadline - now)); self._now(deadline)
    def _send(self, request, deadline):
        if type(request) is not bytes or len(self.rows) >= MAX_REQUESTS: _fail('wire_budget')
        self._budget(deadline)
        row = {'request': request, 'send_started': True, 'send_returned': False, 'written': None,
            'datagrams': [], 'unknown': True}
        self.rows.append(row)
        try:
            row['written'] = self.ticket['raw'].sendto(request, (0, 0)); row['send_returned'] = True
            self._now(deadline)
            if type(row['written']) is not int or row['written'] != len(request): _fail('partial_send')
            row['unknown'] = False
            return row
        except BaseException:
            self.unknown = True
            raise
    def _recv(self, row, deadline):
        if self.datagrams >= MAX_DATAGRAMS or self.wire_bytes + ip.MAX_DATAGRAM_BYTES + 1 > MAX_WIRE_BYTES:
            _fail('wire_budget')
        self._budget(deadline)
        original = {'returned': False, 'value': None, 'unknown': True}; row['datagrams'].append(original)
        try:
            original['value'] = self.ticket['raw'].recvfrom(ip.MAX_DATAGRAM_BYTES + 1); original['returned'] = True
            value = original['value']; self._now(deadline)
            if type(value) is not tuple or len(value) != 2: _fail('kernel_sender')
            blob, sender = value
            if type(sender) is not tuple or len(sender) != 2 or any(type(v) is not int for v in sender) or \
                    sender != (0, 0) or type(blob) is not bytes or not 0 < len(blob) <= ip.MAX_DATAGRAM_BYTES:
                _fail('kernel_sender')
            self.datagrams += 1; self.wire_bytes += len(blob)
            original['unknown'] = False
            return blob
        except BaseException:
            self.unknown = row['unknown'] = True
            raise
    def snapshot(self, deadline):
        collectors = []
        for kind in ('addresses', 'routes', 'rules'):
            collector = ip.DumpCollector(kind, self._next(), self.port_id)
            row = self._send(collector.request, deadline); row['collector'] = collector
            while not collector.complete: collector.feed(self._recv(row, deadline))
            collectors.append(collector)
        value = ip.snapshot_from_dumps(*collectors); snapshot_key(value); self._now(deadline)
        return value
    def stable_snapshot(self, deadline):
        first, second = self.snapshot(deadline), self.snapshot(deadline)
        if snapshot_key(first) != snapshot_key(second): _fail('snapshot_changed')
        return second
    def address_ack(self, request, deadline, gate):
        if not callable(gate): _fail('write_not_authorized')
        # gate performs actual native owner/current/link IO; its boolean alone
        # is not an external admission mechanism or a public callable interface.
        if gate() is not True: _fail('write_not_authorized')
        row = self._send(request, deadline)
        result = ip.decode_ack(self._recv(row, deadline), request); row['ack'] = result
        self._now(deadline)
        if not result.success: _fail('kernel_rejected')
        return result
    def close(self, deadline):
        row = self.ticket
        if row is None: self.closed = True; return not self.unknown
        if row['close_requested']: return self.closed_facts()[0][1]
        row['close_requested'] = True  # No retry after an unknown pre-close gate.
        if row['factory_active'] or row['raw'] is None or not row['factory_returned']:
            self.unknown = row['unknown'] = True; return False
        try:
            self._now(deadline); raw, descriptor = row['raw'], row['fd']
            first = raw.fileno()
            if type(first) is not int or type(descriptor) is not int or first != descriptor or \
                    row['metadata'] is None or _metadata(self.io.fstat(descriptor)) != row['metadata']:
                _fail('socket_identity')
            final = raw.fileno()
            if type(final) is not int or final != descriptor: _fail('socket_identity')
            self._now(deadline)
            row['close_called'] = True  # Exactly once, before raw.close may raise.
            try: row['close_result'] = raw.close(); row['close_returned'] = True
            except BaseException as error: row['close_error'] = error; row['unknown'] = True
            try: self.io.fstat(descriptor)
            except OSError as error: row['ebadf'] = error
            except BaseException as error: row['after_close_error'] = error; row['unknown'] = True
            value = raw.fileno(); row['fileno_closed'] = type(value) is int and value == -1
            self._now(deadline); self.closed = True
        except BaseException as error:
            row['close_failure'] = error; self.unknown = row['unknown'] = True
            return False
        closed = self.closed_facts()[0][1]
        if not closed: self.unknown = row['unknown'] = True
        return closed
    def closed_facts(self):
        row = self.ticket
        if row is None: return ()  # Exact no-factory/no-raw resource inventory.
        error = row['ebadf']
        complete = (row['creator'] is self.creator and row['factory_returned'] and not row['factory_active'] and
            not row['unknown'] and not self.unknown and row['close_called'] and row['close_returned'] and
            row['close_result'] is None and row['close_error'] is None and row['fileno_closed'] and
            isinstance(error, OSError) and type(error.errno) is int and error.errno == errno.EBADF)
        return ((bool(row['close_called']), bool(complete)),)


class ClientDynamicIp(object):
    """Native registered IP owner. durable_commit is trusted product code only.

    Producer(record) must really commit Journal.client_ip under the existing
    Store and update lease.record. None/bool/dict are not durable receipts.
    It must return the actual canonical native Journal (codec may recreate it).
    A missing producer causes a no-IO refusal, not an installation capability.
    """
    def __init__(self, dora, allocation, durable_commit=None, _transport=None):
        import mta_client_dora as dhcp
        if type(dora) is not dhcp.PrivateClientDora or type(allocation) is not dhcp.LiveAllocation or \
                allocation._issuer is not dora: _fail('invalid_allocation')
        self.dora, self.allocation = dora, allocation
        self.lease, self.provider, self.store = dora.lease, dora.provider, dora.store
        if getattr(self.provider, '_client_ip_owner_v28', None) is not None: _fail('already_registered')
        self.commit = durable_commit
        self.transport = ClientRouteTransport(self.lease._now, _io=self.provider._io) if _transport is None else _transport
        if type(self.transport) is not ClientRouteTransport: _fail('invalid_transport')
        self.handoff, self.record, self.original, self.commits = None, None, None, []
        self.started = self.applied = self.restored = self.unknown = self.mutation_unknown = False
        self.mutation_started = False
        self._cleanup_until, self._active, self.cleanup_called = None, False, False
        self.provider._client_ip_owner_v28 = self  # Original before factory/any IO.
    def _slice(self, until):
        now = _number(self.lease._now()); until = _number(until)
        if now >= until: _fail('deadline')
        return min(until, now + IO_SECONDS)
    def _current(self, creating):
        import mta_client_dora as dhcp
        if self.provider._client_ip_owner_v28 is not self or self.handoff is None or \
                type(self.handoff) is not dhcp.L3Handoff: _fail('owner_changed')
        token = self.handoff
        if self.store._mutex is not token._mutex or self.store._epoch is not token._store_epoch or \
                self.store._journal_epoch is not token._journal_epoch or self.lease.locks is not token._locks or \
                self.store._current_locks is not token._locks or self.store._marker is not token._marker or \
                self.store._binding is not token._binding: _fail('owner_changed')
        current = self.store.current(self.lease.locks)
        if type(current) is not core.Journal or self.lease.record.key() != current.key(): _fail('journal_changed')
        self.store._canonical_valid(self.store._canonical, current)
        if not dhcp.PrivateClientDora.l3_handoff_current(self.dora, token, self, current, creating):
            _fail('handoff_changed')
        value = current.client_ip
        if self.record is not None and (type(value) is not DynamicIpRecord or not same_record(value, self.record)):
            _fail('journal_changed')
        return current
    def _persist(self, value, creating):
        if not callable(self.commit): _fail('durable_journal_unavailable')
        before = self._current(creating)
        row = {'producer': self.commit, 'before': before, 'proposed': value, 'returned': None, 'unknown': True}
        self.commits.append(row)  # Before the actual durable producer.
        result = row['producer'](value); row['returned'] = result
        if type(result) is not core.Journal or type(result.client_ip) is not DynamicIpRecord or \
                not same_record(result.client_ip, value) or self.lease.record.key() != result.key() or \
                self.store._canonical.journal.key() != result.key(): _fail('durability_unknown')
        self.store._canonical_valid(self.store._canonical, result)
        if not self.dora.l3_handoff_current(self.handoff, self, result, creating): _fail('handoff_changed')
        self.record = result.client_ip; row['unknown'] = False
        return self.record
    def _link_gate(self, until, creating):
        self._slice(until); current = self._current(creating)
        end = self._slice(until)
        self.provider._begin(end, mutating=False, allow_pending=not creating)
        if not self.provider._origin_exact(self.original.owned, end): _fail('origin_changed')
        if creating:
            actor = self.provider.live_actor(self.handoff._controller, end)
            if type(actor) is not core.Actor or actor.key() != self.handoff._controller.actor.key() or not actor.live():
                _fail('controller_changed')
        self._slice(until)
        return current
    def _free_subnet(self, baseline, spec):
        network = spec.address & ip._mask(spec.prefixlen)
        last = spec.address | (ip.UINT_MAX ^ ip._mask(spec.prefixlen))
        occupied = []
        for row in baseline.addresses:
            for value in (row.local, row.address):
                first = value & ip._mask(row.prefixlen); occupied.append((first, first | (ip.UINT_MAX ^ ip._mask(row.prefixlen))))
        for row in baseline.routes:
            if row.prefixlen: occupied.append((row.network, row.network | (ip.UINT_MAX ^ ip._mask(row.prefixlen))))
            for value in (row.gateway, row.prefsrc):
                if value is not None: occupied.append((value, value))
        if any(network <= b and a <= last for a, b in occupied): _fail('subnet_overlap')
    def start(self):
        if self.started: _fail('already_started')
        if not callable(self.commit) or 'client_ip' not in core.Journal.__slots__: _fail('durable_journal_unavailable')
        import mta_client_dora as dhcp
        self.started = self._active = True
        try:
            # Fresh native DORA validation issues the only original handoff.
            self.handoff = dhcp.PrivateClientDora.issue_l3_handoff(self.dora, self.allocation)
            dhcp.PrivateClientDora.bind_l3_owner(self.dora, self.handoff, self)
            until = self.handoff._until
            with self.store._mutex:
                initial = self._current(True)
                if initial.client_ip is not None: _fail('current_ip_exists')
                config = self.handoff._configuration
                spec = DynamicAddressSpec(initial.owned.ifindex, config.local_ip, config.prefix)
                self.original = DynamicIpRecord('intent', initial.owned, config.local_ip, config.prefix,
                    until, initial.baseline.ipv4)
                self._free_subnet(self.original.baseline, spec)
                self._link_gate(until, True)
                self.transport.open(self._slice(until))
                before = self.transport.stable_snapshot(self._slice(until))
                if snapshot_key(before) != snapshot_key(self.original.baseline): _fail('baseline_changed')
                self._persist(self.original, True)  # Actual durable intent BEFORE mutation.
                request = self.transport.prepare_address(spec, True)
                def create_gate():
                    self._link_gate(until, True)
                    now = self.transport.stable_snapshot(self._slice(until))
                    if snapshot_key(now) != snapshot_key(self.original.baseline): _fail('baseline_changed')
                    return True
                self.mutation_started = True
                self.transport.address_ack(request, self._slice(until), create_gate)
                after = self.transport.stable_snapshot(self._slice(until))
                applied = self.original.replace('applied', after)
                self._link_gate(until, True); self._persist(applied, True)
                self.applied = True
                return self.record
        except BaseException:
            self.unknown = True
            self.mutation_unknown = self.mutation_started and not self.applied
            raise
        finally: self._active = False
    def cleanup(self, recovery_until):
        now, recovery_until = _number(self.lease._now()), _number(recovery_until)
        if not 0 < recovery_until - now <= 60: _fail('invalid_cleanup_deadline')
        if self._cleanup_until is None: self._cleanup_until = recovery_until
        elif self._cleanup_until != recovery_until: _fail('cleanup_renewal')
        if self._active: _fail('concurrent_operation')
        self.cleanup_called = True
        self._active = True
        try:
            with self.store._mutex:
                if not self.started:
                    self.restored = True
                    self.transport.close(self._slice(recovery_until))
                    self._active = False  # All synchronous producers have returned.
                    return all(closed for attempted, closed in self.closed_facts())
                if self.unknown or self.mutation_unknown or any(r['unknown'] for r in self.commits):
                    # Known raw handles may close, but an unknown mutation is
                    # never promoted from an intent/readback to address ownership.
                    self.transport.close(self._slice(recovery_until))
                    return False
                self._link_gate(recovery_until, False)
                current = self.transport.stable_snapshot(self._slice(recovery_until))
                if self.record is None or self.record.phase == 'intent':
                    if self.mutation_started or snapshot_key(current) != snapshot_key(self.original.baseline):
                        _fail('ownership_unknown')
                    self._persist(self.original.replace('restored', current), False)
                elif self.record.phase in ('applied', 'delete_intent'):
                    spec = DynamicAddressSpec(self.record.owned.ifindex, ip.ipv4_text(self.record.local_ip), self.record.prefix)
                    if snapshot_key(current) == snapshot_key(self.original.baseline):
                        if self.record.phase != 'delete_intent': _fail('owned_address_disappeared')
                    else:
                        _without_delta(current, self.original.baseline, self.original.owned, spec)
                        if self.record.phase == 'applied': self._persist(self.record.replace('delete_intent', current), False)
                        request = self.transport.prepare_address(spec, False)
                        def delete_gate():
                            self._link_gate(recovery_until, False)
                            fresh = self.transport.stable_snapshot(self._slice(recovery_until))
                            _without_delta(fresh, self.original.baseline, self.original.owned, spec)
                            return True
                        self.transport.address_ack(request, self._slice(recovery_until), delete_gate)
                        current = self.transport.stable_snapshot(self._slice(recovery_until))
                        if snapshot_key(current) != snapshot_key(self.original.baseline): _fail('restore_readback')
                    self._persist(self.record.replace('restored', current), False)
                elif self.record.phase == 'restored':
                    if snapshot_key(current) != snapshot_key(self.original.baseline): _fail('restore_readback')
                else: _fail('invalid_record')
                self.restored = True
                self.transport.close(self._slice(recovery_until))
                self._slice(recovery_until)
                self._active = False  # Passive original history only from this point.
                return all(closed for attempted, closed in self.closed_facts())
        except BaseException:
            self.unknown = True
            return False
        finally: self._active = False
    def closed_facts(self):
        registered = self.provider._client_ip_owner_v28 is self and self.provider._store is self.store and self.provider._lease is self.lease
        known = registered and self.restored and not self.unknown and not self.mutation_unknown and \
            not self._active and all(not r['unknown'] for r in self.commits)
        return ((self.cleanup_called, bool(known)),) + tuple((a, bool(c and known)) for a, c in self.transport.closed_facts())
    def status(self):
        return {'registered': self.provider._client_ip_owner_v28 is self, 'started': self.started,
            'applied': self.applied, 'restored': self.restored, 'closed': self.transport.closed,
            'resource_pending': not all(c for a, c in self.closed_facts()), 'mutation_unknown': self.mutation_unknown,
            'transport_ticket_count': int(self.transport.ticket is not None),
            'requests': len(self.transport.rows), 'datagrams': self.transport.datagrams,
            'send_available': False, 'receive_available': False, 'phone_tested': False}
