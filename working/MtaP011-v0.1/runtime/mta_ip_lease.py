"""Private IP-only sublease; caller owns the ONE GO journal/guard/watchdog.

Only AF_NETLINK/NETLINK_ROUTE is used. No IP sockets, DHCP or route writes.
Python 3.5. A HOST fake kernel is not P011 installation evidence.
"""
import errno
import os
import socket
import struct
import time
import mta_ip as core

VERSION_MARKER = 'p011-go-ip-only-v5-1'
RECOVERY_SECONDS = 5.0
CANDIDATES = ('192.168.49.0/24', '192.168.74.0/24', '172.30.219.0/24')


class IpLeaseError(RuntimeError):
    def __init__(self, code, number=0):
        self.code = code
        self.errno = number if type(number) is int and 0 <= number <= 4095 else 0
        RuntimeError.__init__(self, code)


def _error(code, number=0):
    raise IpLeaseError(code, number)


def require_permanent(snapshot):
    core.require_default_rules(snapshot)
    for row in snapshot.addresses:
        if row.flags != core.IFA_F_PERMANENT or row.cacheinfo is None or \
                row.cacheinfo[:2] != (core.UINT_MAX, core.UINT_MAX):
            _error('ip_lifetime_not_supported')
    return snapshot


def snapshot_data(snapshot):
    """Full private records. Timestamps are retained, not silently discarded."""
    require_permanent(snapshot)
    addresses = [list(row[:-3]) + [row.label.hex() if row.label is not None else None,
                 row.broadcast, list(row.cacheinfo)] for row in snapshot.addresses]
    routes = [list(row[:-1]) + [[list(v) for v in row.metrics]] for row in snapshot.routes]
    return {'version': 1, 'addresses': sorted(addresses, key=repr),
            'routes': sorted(routes, key=repr), 'rules': [list(v) for v in sorted(snapshot.rules)]}


def snapshot_from_data(value):
    """Strict private journal decoder; never accepts a digest-only baseline."""
    if type(value) is not dict or set(value) != {'version', 'addresses', 'routes', 'rules'} or \
            type(value['version']) is not int or value['version'] != 1:
        _error('invalid_ip_baseline')
    if any(type(value[k]) is not list or len(value[k]) > core.MAX_DUMP_RECORDS
           for k in ('addresses', 'routes', 'rules')):
        _error('invalid_ip_baseline')
    try:
        addresses = []
        for row in value['addresses']:
            if type(row) is not list or len(row) != 9 or any(type(v) is not int for v in row[:6]):
                _error('invalid_ip_baseline')
            label = None if row[6] is None else bytes.fromhex(row[6])
            if label is not None and (not 2 <= len(label) <= 16 or label[-1:] != b'\0' or b'\0' in label[:-1]):
                _error('invalid_ip_baseline')
            if type(row[8]) is not list or len(row[8]) != 4 or any(type(v) is not int or not 0 <= v <= core.UINT_MAX for v in row[8]):
                _error('invalid_ip_baseline')
            if not 0 < row[0] <= 0x7fffffff or any(not 0 <= v <= core.UINT_MAX for v in row[1:3]) or \
                    not 0 <= row[3] <= 32 or row[5] not in (0, 253, 254) or \
                    (row[7] is not None and (type(row[7]) is not int or not 0 <= row[7] <= core.UINT_MAX)):
                _error('invalid_ip_baseline')
            addresses.append(core.AddressRecord(*(row[:6] + [label, row[7], tuple(row[8])])))
        routes = []
        for row in value['routes']:
            if type(row) is not list or len(row) != 12 or any(type(v) is not int for v in row[:7]):
                _error('invalid_ip_baseline')
            if any(v is not None and (type(v) is not int or not 0 <= v <= core.UINT_MAX) for v in row[7:11]):
                _error('invalid_ip_baseline')
            if type(row[11]) is not list or any(type(v) is not list or len(v) != 2 or
                    any(type(n) is not int or not 0 <= n <= core.UINT_MAX for n in v) for v in row[11]):
                _error('invalid_ip_baseline')
            if not 0 <= row[0] <= core.UINT_MAX or not 0 <= row[1] <= 32 or \
                    row[0] & ((core.UINT_MAX << (32 - row[1])) & core.UINT_MAX if row[1] else 0) != row[0] or \
                    not 0 < row[2] <= core.UINT_MAX or not 0 <= row[3] <= 255 or \
                    row[4] not in (0, 253, 254) or row[5] not in (1, 2, 3) or \
                    not 0 <= row[6] <= 0x19 or row[6] & ~0x19 or \
                    (row[7] is not None and not 0 < row[7] <= 0x7fffffff) or \
                    any(not 1 <= pair[0] <= 15 for pair in row[11]) or \
                    len(set(pair[0] for pair in row[11])) != len(row[11]) or row[11] != sorted(row[11]):
                _error('invalid_ip_baseline')
            routes.append(core.RouteRecord(*(row[:11] + [tuple(tuple(v) for v in row[11])])))
        rules = []
        for row in value['rules']:
            if type(row) is not list or len(row) != 2 or any(type(n) is not int or not 0 <= n <= core.UINT_MAX for n in row):
                _error('invalid_ip_baseline')
            rules.append(core.RuleRecord(*row))
        result = require_permanent(core.IpSnapshot(tuple(addresses), tuple(routes), tuple(rules)))
        if snapshot_data(result) != value or len(set((r.ifindex, r.local, r.address, r.prefixlen)
                for r in result.addresses)) != len(result.addresses) or len(set(result.routes)) != len(result.routes):
            _error('invalid_ip_baseline')
        return result
    except (ValueError, TypeError, IndexError, AttributeError):
        _error('invalid_ip_baseline')


class RouteTransport(object):
    """One unicast kernel socket; three dump sequences share its bound port."""
    def __init__(self, socket_factory=None, clock=time.monotonic):
        self.clock = clock; self.socket = None; self.closed = False
        self.sequence = int.from_bytes(os.urandom(4), 'little') & 0x7fffffff
        factory = socket_factory or socket.socket
        try:
            self.socket = factory(socket.AF_NETLINK, socket.SOCK_RAW, 0)
            self.socket.set_inheritable(False); self.socket.bind((0, 0))
            address = self.socket.getsockname()
            if type(address) is not tuple or len(address) != 2 or type(address[0]) is not int or \
                    not 0 < address[0] <= core.UINT_MAX or address[1] != 0:
                _error('route_socket_identity')
            self.port_id = address[0]
        except BaseException:
            self.close(); raise

    def close(self):
        self.closed = True
        if self.socket is not None:
            self.socket.close(); self.socket = None

    def _next(self):
        if self.closed or self.sequence >= core.UINT_MAX:
            _error('route_transport_closed')
        self.sequence += 1
        return self.sequence

    def _budget(self, deadline):
        if self.closed or type(deadline) not in (int, float) or self.clock() >= deadline:
            _error('ip_deadline_expired')
        self.socket.settimeout(max(.001, deadline - self.clock()))

    def _send(self, request, deadline):
        self._budget(deadline)
        if self.socket.sendto(request, (0, 0)) != len(request):
            _error('route_partial_send')

    def _recv(self, deadline):
        self._budget(deadline)
        blob, sender = self.socket.recvfrom(core.MAX_DATAGRAM_BYTES + 1)
        if sender != (0, 0) or type(blob) is not bytes or not blob or len(blob) > core.MAX_DATAGRAM_BYTES:
            _error('route_kernel_sender')
        return blob

    def snapshot(self, deadline):
        collectors = []
        for kind in ('addresses', 'routes', 'rules'):
            collector = core.DumpCollector(kind, self._next(), self.port_id)
            self._send(collector.request, deadline)
            while not collector.complete:
                collector.feed(self._recv(deadline))
            collectors.append(collector)
        return require_permanent(core.snapshot_from_dumps(*collectors))

    def stable_snapshot(self, deadline):
        first = self.snapshot(deadline); second = self.snapshot(deadline)
        if snapshot_data(first) != snapshot_data(second):
            _error('ip_snapshot_changed')
        return second

    def prepare_address(self, spec, create):
        encode = core.encode_new_address if create else core.encode_del_address
        return encode(spec, self._next(), self.port_id)

    def address_ack(self, request, deadline, gate):
        if not callable(gate) or gate() is not True:
            _error('ip_write_not_authorized')
        self._send(request, deadline)
        ack = core.decode_ack(self._recv(deadline), request)
        if not ack.success:
            _error('ip_kernel_rejected', ack.errno)
        return ack


def _origin(owned):
    if type(owned) is not dict or any(k not in owned for k in ('name', 'ifindex', 'wdev', 'phy')):
        _error('ip_interface_identity')
    result = {k: owned[k] for k in ('name', 'ifindex', 'wdev', 'phy')}
    if type(result['name']) is not str or not result['name'].startswith('mta') or len(result['name']) != 11 or \
            any(c not in '0123456789abcdef' for c in result['name'][3:]) or \
            any(type(result[k]) is not int or result[k] < 0 for k in ('ifindex', 'wdev', 'phy')) or \
            not 0 < result['ifindex'] <= 0x7fffffff or result['phy'] > core.UINT_MAX or result['wdev'] > 0xffffffffffffffff:
        _error('ip_interface_identity')
    return result


def _spec(record):
    value = record.get('spec')
    if type(value) is not list or len(value) != 3 or any(type(v) is not int for v in value):
        _error('ip_receipt_invalid')
    return core.AddressSpec(value[0], core.ipv4_text(value[1]), value[2])


def _expected_routes(spec):
    def row(network, prefix, table, scope, kind):
        return core.RouteRecord(network, prefix, table, 2, scope, kind, 0,
                                spec.ifindex, None, None, spec.address, ())
    network = spec.address & 0xffffff00
    return (row(network, 24, 254, 253, 1), row(spec.address, 32, 255, 254, 2),
            row(network, 32, 255, 253, 3), row(network | 255, 32, 255, 253, 3))


def _new_address(snapshot, spec, owned):
    rows = [r for r in snapshot.addresses if r.ifindex == spec.ifindex]
    if len(rows) != 1:
        _error('ip_address_readback')
    row = rows[0]
    if (row.local, row.address, row.prefixlen, row.flags, row.scope, row.label, row.broadcast) != \
            (spec.address, spec.address, 24, core.IFA_F_PERMANENT, 0,
             owned['name'].encode('ascii') + b'\0', spec.address | 255):
        _error('ip_address_readback')
    return row


def _validate_receipt(record, owned):
    if type(record) is not dict or set(record) != {'stage', 'owned', 'spec', 'request', 'address', 'receipt_fsynced'} or \
            record['stage'] not in ('confirmed', 'delete_intent', 'restored') or record['receipt_fsynced'] is not True or \
            record['owned'] != _origin(owned):
        _error('ip_receipt_invalid')
    spec = _spec(record)
    if spec.ifindex != owned['ifindex']:
        _error('ip_receipt_invalid')
    request = record['request']
    if type(request) is not dict or set(request) != {'header', 'sequence', 'port_id'} or \
            any(type(request[k]) is not int or not 0 < request[k] <= core.UINT_MAX for k in ('sequence', 'port_id')) or \
            type(request['header']) is not str or len(request['header']) != 32 or \
            request['header'] != core.encode_new_address(spec, request['sequence'], request['port_id'])[:16].hex():
        _error('ip_receipt_invalid')
    before = {'version': 1, 'addresses': [record['address']], 'routes': [],
              'rules': [[0, 255], [32766, 254], [32767, 253]]}
    address = snapshot_from_data(before).addresses[0]
    _new_address(core.IpSnapshot((address,), (), ()), spec, owned)
    return spec, address


def _validate_intent(record, owned):
    extra = {'address', 'receipt_fsynced'} if record.get('stage') == 'receipt_recorded' else set()
    if set(record) != {'stage', 'owned', 'spec', 'request'} | extra or \
            record.get('stage') not in ('create_intent', 'receipt_recorded') or record['owned'] != _origin(owned):
        _error('ip_receipt_invalid')
    spec = _spec(record); request = record['request']
    if spec.ifindex != owned['ifindex'] or type(request) is not dict or \
            set(request) != {'header', 'sequence', 'port_id'} or \
            any(type(request[k]) is not int or not 0 < request[k] <= core.UINT_MAX for k in ('sequence', 'port_id')) or \
            request['header'] != core.encode_new_address(spec, request['sequence'], request['port_id'])[:16].hex() or \
            (extra and record['receipt_fsynced'] is not False):
        _error('ip_receipt_invalid')
    if extra:
        probe = dict(record, stage='confirmed', receipt_fsynced=True)
        _validate_receipt(probe, owned)  # Shape only, never grants authority.


def validate_ip_record(record, owned):
    if record is None: return
    if type(record) is not dict: _error('ip_receipt_invalid')
    if record.get('stage') in ('create_intent', 'receipt_recorded'):
        _validate_intent(record, owned)
    else:
        _validate_receipt(record, owned)


def without_owned(snapshot, record, owned):
    """Exclude ONLY the exact receipt and expected kernel route set."""
    if record is None or record.get('stage') == 'restored':
        return snapshot
    spec, address = _validate_receipt(record, owned)
    routes = _expected_routes(spec)
    if address not in snapshot.addresses or any(r not in snapshot.routes for r in routes):
        _error('ip_owned_delta_changed')
    return core.IpSnapshot(tuple(r for r in snapshot.addresses if r != address),
                           tuple(r for r in snapshot.routes if r not in routes), snapshot.rules)


class OwnedIpLease(object):
    """No separate lock/worker. Every method is called under the GO journal lock.

    intent -> request ACK -> receipt_recorded(fsync) -> confirmed(fsync)
    A failed first receipt write never becomes ownership by inference.
    """
    def __init__(self, transport, state, save, fresh_gate, clock=time.monotonic):
        self.transport = transport; self.state = state; self.save = save
        self.fresh_gate = fresh_gate; self.clock = clock

    def _gate(self, deadline, creating):
        if self.clock() >= deadline or self.fresh_gate(creating) is not True:
            _error('ip_epoch_or_identity_changed')
        return True

    def create(self, deadline, candidates=CANDIDATES):
        if self.state.get('ip') is not None:
            _error('ip_lease_already_started')
        owned = _origin(self.state['owned'])
        baseline = snapshot_from_data(self.state['baseline']['ipv4'])
        self._gate(deadline, True)
        before = self.transport.stable_snapshot(deadline)
        if snapshot_data(before) != snapshot_data(baseline) or any(r.ifindex == owned['ifindex'] for r in before.addresses):
            _error('ip_precreate_baseline_changed')
        chosen = core.select_subnet(before, candidates)
        spec = core.AddressSpec(owned['ifindex'], core.ipv4_text(chosen.network + 1), 24)
        request = self.transport.prepare_address(spec, True)
        unused_size, unused_type, unused_flags, sequence, port = struct.unpack('<IHHII', request[:16])
        record = {'stage': 'create_intent', 'owned': owned, 'spec': list(spec),
                  'request': {'sequence': sequence, 'port_id': port, 'header': request[:16].hex()}}
        self.state['ip'] = record; self.save()
        self._gate(deadline, True)
        if snapshot_data(self.transport.stable_snapshot(deadline)) != snapshot_data(before):
            _error('ip_prewrite_baseline_changed')
        def create_gate():
            self._gate(deadline, True)
            if snapshot_data(self.transport.stable_snapshot(deadline)) != snapshot_data(before):
                _error('ip_prewrite_baseline_changed')
            return True
        self.transport.address_ack(request, deadline, create_gate)
        after = self.transport.stable_snapshot(deadline)
        address = _new_address(after, spec, owned)
        probe = {'stage': 'confirmed', 'owned': owned, 'spec': list(spec), 'request': record['request'],
                 'address': snapshot_data(core.IpSnapshot((address,), (), baseline.rules))['addresses'][0],
                 'receipt_fsynced': True}
        if snapshot_data(without_owned(after, probe, owned)) != snapshot_data(before):
            _error('ip_unexpected_route_delta')
        self._gate(deadline, True)
        # First persisted payload is not yet authoritative. Only a successful
        # return permits a second commit carrying receipt_fsynced=True.
        record.update({'stage': 'receipt_recorded', 'address': probe['address'], 'receipt_fsynced': False})
        self.save()
        record['stage'] = 'confirmed'; record['receipt_fsynced'] = True; self.save()
        self._gate(deadline, True)
        return True

    def restore(self, deadline):
        record = self.state.get('ip')
        if record is None:
            return True
        validate_ip_record(record, self.state['owned'])
        owned = _origin(self.state['owned'])
        baseline = snapshot_from_data(self.state['baseline']['ipv4'])
        self._gate(deadline, False)
        current = self.transport.stable_snapshot(deadline)
        if record.get('stage') in ('create_intent', 'receipt_recorded'):
            _validate_intent(record, owned)
            # Intent is not ownership. Unknown address or route cannot be
            # removed indirectly by deleting an otherwise owned netdev.
            if snapshot_data(current) != snapshot_data(baseline):
                _error('ip_ownership_uncertain')
            self.state['ip'] = None; self.save(); return True
        spec, address = _validate_receipt(record, owned)
        if snapshot_data(current) == snapshot_data(baseline):
            record['stage'] = 'restored'; self.save(); return True
        if record['stage'] == 'restored' or snapshot_data(without_owned(current, record, owned)) != snapshot_data(baseline):
            _error('ip_restore_baseline_changed')
        self._gate(deadline, False)
        record['stage'] = 'delete_intent'; self.save()
        request = self.transport.prepare_address(spec, False)
        def delete_gate():
            self._gate(deadline, False)
            fresh = self.transport.stable_snapshot(deadline)
            if snapshot_data(without_owned(fresh, record, owned)) != snapshot_data(baseline):
                _error('ip_restore_baseline_changed')
            return True
        self.transport.address_ack(request, deadline, delete_gate)
        after = self.transport.stable_snapshot(deadline)
        if snapshot_data(after) != snapshot_data(baseline):
            _error('ip_restore_readback_changed')
        record['stage'] = 'restored'; self.save(); return True
