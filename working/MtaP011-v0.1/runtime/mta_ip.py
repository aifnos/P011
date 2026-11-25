"""P011 IPv4 rtnetlink bytes core; no sockets, subprocesses or network writes.

All records and subnet choices are private data, not public status objects.
The caller must supply authenticated kernel datagrams and fresh ownership
evidence. A decoded ACK proves neither address readback nor lease ownership.
Wire integers use the P011 little-endian ABI; IPv4 values use network order.
Compatible with Python 3.5 without json, ipaddress, fcntl or resource.
"""

import struct
from collections import namedtuple


AF_INET = 2
RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR = 20, 21, 22
RTM_NEWROUTE, RTM_GETROUTE = 24, 26
RTM_NEWRULE, RTM_GETRULE = 32, 34
NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN = 2, 3, 4
NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK = 1, 2, 4
NLM_F_DUMP_INTR, NLM_F_DUMP_FILTERED = 16, 32
NLM_F_DUMP = 0x300
NLM_F_EXCL, NLM_F_CREATE, NLM_F_CAPPED = 0x200, 0x400, 0x100
NLM_F_ACK_TLVS = 0x200
IFA_ADDRESS, IFA_LOCAL, IFA_LABEL = 1, 2, 3
IFA_BROADCAST, IFA_CACHEINFO, IFA_FLAGS = 4, 6, 8
IFA_F_PERMANENT = 0x80
RTA_DST, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY = 1, 4, 5, 6
RTA_PREFSRC, RTA_METRICS, RTA_TABLE = 7, 8, 15
FRA_PRIORITY, FRA_SUPPRESS_IFGROUP = 6, 13
FRA_SUPPRESS_PREFIXLEN, FRA_TABLE = 14, 15
UINT_MAX = 0xffffffff
MAX_DATAGRAM_BYTES = 65536
MAX_DUMP_BYTES = 2 * 1024 * 1024
MAX_DUMP_DATAGRAMS = 256
MAX_DUMP_RECORDS = 4096
MAX_ATTRIBUTES = 64
MAX_CANDIDATES = 32
_NL = struct.Struct('<IHHII')
_ATTR = struct.Struct('<HH')
_ADDR = struct.Struct('<BBBBI')
_ROUTE = struct.Struct('<BBBBBBBBI')
_RULE = struct.Struct('<BBBBBBBBI')
_U32 = struct.Struct('<I')
_S32 = struct.Struct('<i')


class IpCoreError(ValueError):
    """Only fixed codes and numeric errno; never include packet or IP data."""
    def __init__(self, code, errno=0):
        self.code = code
        self.errno = errno
        ValueError.__init__(self, code)


def _fail(code, errno=0):
    raise IpCoreError(code, errno)


def _uint(value, maximum=UINT_MAX, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('invalid_integer')
    return value


def ipv4_number(text):
    """Accept canonical dotted decimal only; no octal, whitespace or aliases."""
    if type(text) is not str:
        _fail('invalid_ipv4')
    parts = text.split('.')
    if len(parts) != 4:
        _fail('invalid_ipv4')
    value = 0
    for part in parts:
        if not part or len(part) > 3 or any(c not in '0123456789' for c in part):
            _fail('invalid_ipv4')
        if len(part) != 1 and part[0] == '0':
            _fail('invalid_ipv4')
        item = int(part)
        if item > 255:
            _fail('invalid_ipv4')
        value = (value << 8) | item
    return value


def ipv4_text(number):
    """Private formatting helper; callers must not put its output in UI/logs."""
    _uint(number)
    return '.'.join(str((number >> shift) & 255) for shift in (24, 16, 8, 0))


def _mask(prefixlen):
    _uint(prefixlen, 32)
    return (UINT_MAX << (32 - prefixlen)) & UINT_MAX if prefixlen else 0


def _private(number):
    return ((number & 0xff000000) == 0x0a000000 or
            (number & 0xfff00000) == 0xac100000 or
            (number & 0xffff0000) == 0xc0a80000)


def _align(length):
    return (length + 3) & ~3


def _attribute(kind, payload):
    size = 4 + len(payload)
    return _ATTR.pack(size, kind) + payload + b'\0' * (_align(size) - size)


def _message(kind, flags, sequence, port_id, payload):
    _uint(sequence, minimum=1)
    _uint(port_id, minimum=1)
    size = 16 + len(payload)
    return _NL.pack(size, kind, flags, sequence, port_id) + payload


def _bytes(data):
    if type(data) is not bytes or not data or len(data) > MAX_DATAGRAM_BYTES:
        _fail('invalid_datagram')
    return data


def _messages(data):
    _bytes(data)
    result, offset = [], 0
    while offset < len(data):
        if len(data) - offset < 16:
            _fail('truncated_header')
        length, kind, flags, sequence, port_id = _NL.unpack_from(data, offset)
        end, aligned = offset + length, offset + _align(length)
        if length < 16 or end > len(data) or aligned > len(data):
            _fail('invalid_message_length')
        if any(data[end:aligned]):
            _fail('invalid_padding')
        result.append((kind, flags, sequence, port_id, data[offset + 16:end]))
        if len(result) > MAX_DUMP_RECORDS + 1:
            _fail('message_limit')
        offset = aligned
    return tuple(result)


def _attributes(data, allowed, nested=()):
    """Reject duplicates, unknown attrs, unsupported flags and malformed pads."""
    attrs, offset = {}, 0
    while offset < len(data):
        if len(data) - offset < 4:
            _fail('truncated_attribute')
        length, raw_kind = _ATTR.unpack_from(data, offset)
        kind, flags = raw_kind & 0x3fff, raw_kind & 0xc000
        end, aligned = offset + length, offset + _align(length)
        if length < 4 or end > len(data) or aligned > len(data):
            _fail('invalid_attribute_length')
        if any(data[end:aligned]):
            _fail('invalid_padding')
        if kind not in allowed:
            _fail('unknown_attribute')
        if flags and not (flags == 0x8000 and kind in nested):
            _fail('unsupported_attribute_flags')
        if kind in attrs:
            _fail('duplicate_attribute')
        attrs[kind] = data[offset + 4:end]
        if len(attrs) > MAX_ATTRIBUTES:
            _fail('attribute_limit')
        offset = aligned
    return attrs


def _number(data):
    if len(data) != 4:
        _fail('invalid_attribute_size')
    return _U32.unpack(data)[0]


def _ip(data):
    if len(data) != 4:
        _fail('invalid_attribute_size')
    return struct.unpack('>I', data)[0]


def _optional(attrs, kind, decoder):
    return decoder(attrs[kind]) if kind in attrs else None


class AddressRecord(namedtuple('_AddressRecord',
                              'ifindex local address prefixlen flags scope '
                              'label broadcast cacheinfo')):
    __slots__ = ()
    def __repr__(self):
        return '<AddressRecord private>'


class RouteRecord(namedtuple('_RouteRecord',
                            'network prefixlen table protocol scope kind flags '
                            'oif gateway priority prefsrc metrics')):
    __slots__ = ()
    def __repr__(self):
        return '<RouteRecord private>'


class RuleRecord(namedtuple('_RuleRecord', 'priority table')):
    __slots__ = ()


def _parse_address(payload):
    if len(payload) < 8:
        _fail('truncated_address')
    family, prefix, flags8, scope, index = _ADDR.unpack_from(payload)
    if family != AF_INET or prefix > 32 or not 0 < index <= 0x7fffffff:
        _fail('invalid_address_header')
    if scope not in (0, 253, 254):
        _fail('unsupported_address_scope')
    attrs = _attributes(payload[8:], (1, 2, 3, 4, 6, 8))
    if IFA_ADDRESS not in attrs:
        _fail('missing_address')
    address = _ip(attrs[IFA_ADDRESS])
    local = _ip(attrs[IFA_LOCAL]) if IFA_LOCAL in attrs else address
    flags = _number(attrs[IFA_FLAGS]) if IFA_FLAGS in attrs else flags8
    if flags & ~0xfff:
        _fail('unknown_address_flags')
    # IFA_FLAGS supersedes the u8 header according to Linux UAPI.
    label = attrs.get(IFA_LABEL)
    if label is not None:
        if not 2 <= len(label) <= 16 or label[-1:] != b'\0' or b'\0' in label[:-1]:
            _fail('invalid_address_label')
    cache = attrs.get(IFA_CACHEINFO)
    if cache is not None:
        if len(cache) != 16:
            _fail('invalid_attribute_size')
        cache = struct.unpack('<IIII', cache)
        if cache[0] > cache[1]:
            _fail('invalid_address_lifetime')
    return AddressRecord(index, local, address, prefix, flags, scope, label,
                         _optional(attrs, IFA_BROADCAST, _ip), cache)


def _parse_route(payload):
    if len(payload) < 12:
        _fail('truncated_route')
    family, prefix, source_prefix, tos, table8, protocol, scope, kind, flags = \
        _ROUTE.unpack_from(payload)
    if family != AF_INET or prefix > 32:
        _fail('invalid_route_header')
    if source_prefix or tos or flags & ~0x19 or kind not in (1, 2, 3) or scope not in (0, 253, 254):
        _fail('unsupported_route')
    attrs = _attributes(payload[12:], (1, 4, 5, 6, 7, 8, 15), (RTA_METRICS,))
    if prefix and RTA_DST not in attrs:
        _fail('missing_route_destination')
    network = _ip(attrs[RTA_DST]) if RTA_DST in attrs else 0
    if network & _mask(prefix) != network:
        _fail('noncanonical_route')
    table = _number(attrs[RTA_TABLE]) if RTA_TABLE in attrs else table8
    if not table or (RTA_TABLE in attrs and table8 != (table if table < 256 else 252)):
        _fail('invalid_route_table')
    oif = _optional(attrs, RTA_OIF, _number)
    if oif is not None and not 0 < oif <= 0x7fffffff:
        _fail('invalid_route_interface')
    metrics = ()
    if RTA_METRICS in attrs:
        nested = _attributes(attrs[RTA_METRICS], tuple(range(1, 16)))
        metrics = tuple(sorted((key, _number(value)) for key, value in nested.items()))
    return RouteRecord(network, prefix, table, protocol, scope, kind, flags,
                       oif, _optional(attrs, RTA_GATEWAY, _ip),
                       _optional(attrs, RTA_PRIORITY, _number),
                       _optional(attrs, RTA_PREFSRC, _ip), metrics)


def _parse_rule(payload):
    if len(payload) < 12:
        _fail('truncated_rule')
    family, dst_len, src_len, tos, table8, res1, res2, action, flags = \
        _RULE.unpack_from(payload)
    if family != AF_INET or dst_len or src_len or tos or res1 or res2 or action != 1 or flags:
        _fail('unsupported_policy')
    attrs = _attributes(payload[12:], (6, 13, 14, 15))
    # Kernel default rules contain suppress_prefixlen=-1; it is disabled.
    for attr in (FRA_SUPPRESS_PREFIXLEN, FRA_SUPPRESS_IFGROUP):
        if attr in attrs and _number(attrs[attr]) != UINT_MAX:
            _fail('unsupported_policy')
    table = _number(attrs[FRA_TABLE]) if FRA_TABLE in attrs else table8
    if not table or (FRA_TABLE in attrs and table8 != (table if table < 256 else 0)):
        _fail('invalid_rule_table')
    priority = _number(attrs[FRA_PRIORITY]) if FRA_PRIORITY in attrs else 0
    return RuleRecord(priority, table)


_DUMPS = {'addresses': (RTM_GETADDR, RTM_NEWADDR, _ADDR.pack(AF_INET, 0, 0, 0, 0),
                        _parse_address),
          'routes': (RTM_GETROUTE, RTM_NEWROUTE,
                     _ROUTE.pack(AF_INET, 0, 0, 0, 0, 0, 0, 0, 0), _parse_route),
          'rules': (RTM_GETRULE, RTM_NEWRULE,
                    _RULE.pack(AF_INET, 0, 0, 0, 0, 0, 0, 0, 0), _parse_rule)}


def encode_dump(kind, sequence, port_id):
    """An unfiltered AF_INET dump; routes deliberately request table UNSPEC."""
    if type(kind) is not str or kind not in _DUMPS:
        _fail('invalid_dump_kind')
    command, unused_type, payload, unused_parser = _DUMPS[kind]
    return _message(command, NLM_F_REQUEST | NLM_F_DUMP, sequence, port_id, payload)


class AckResult(namedtuple('_AckResult', 'errno command')):
    __slots__ = ()
    @property
    def success(self):
        return self.errno == 0


def _request_header(request):
    messages = _messages(request)
    if len(messages) != 1:
        _fail('invalid_request')
    kind, flags, sequence, port_id, payload = messages[0]
    expected = {RTM_NEWADDR: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                RTM_DELADDR: NLM_F_REQUEST | NLM_F_ACK,
                RTM_GETADDR: NLM_F_REQUEST | NLM_F_DUMP,
                RTM_GETROUTE: NLM_F_REQUEST | NLM_F_DUMP,
                RTM_GETRULE: NLM_F_REQUEST | NLM_F_DUMP}
    if kind not in expected or flags != expected[kind] or not sequence or not port_id:
        _fail('invalid_request')
    return kind, sequence, port_id


def _ack_message(message, request):
    command, sequence, port_id = _request_header(request)
    kind, flags, reply_sequence, reply_port, payload = message
    if kind != NLMSG_ERROR or reply_sequence != sequence or reply_port != port_id:
        _fail('ack_identity_mismatch')
    if flags & ~NLM_F_CAPPED:
        # EXT_ACK was not requested; no free-form error text is accepted/logged.
        _fail('unsupported_ack_flags')
    if len(payload) < 20:
        _fail('truncated_ack')
    error = _S32.unpack_from(payload)[0]
    if error > 0 or error < -4095:
        _fail('invalid_kernel_errno')
    if payload[4:20] != request[:16]:
        _fail('ack_request_mismatch')
    if error == 0 or flags & NLM_F_CAPPED:
        if len(payload) != 20:
            _fail('invalid_ack_length')
    elif len(payload) != 4 + len(request) or payload[4:] != request:
        _fail('ack_request_mismatch')
    return AckResult(-error, command)


def decode_ack(datagram, request):
    """Return success/numeric errno only after exact request correlation."""
    messages = _messages(datagram)
    if len(messages) != 1:
        _fail('ack_message_count')
    return _ack_message(messages[0], request)


class DumpCollector(object):
    """Bounded, poison-on-error multipart collector; partial data is unusable."""
    def __init__(self, kind, sequence, port_id):
        self.request = encode_dump(kind, sequence, port_id)
        self.kind, self.sequence, self.port_id = kind, sequence, port_id
        self._records, self._seen = [], set()
        self._bytes, self._datagrams = 0, 0
        self.complete, self.failed = False, False

    def feed(self, datagram):
        if self.failed:
            _fail('dump_failed')
        if self.complete:
            self.failed = True
            _fail('dump_already_complete')
        try:
            self._feed(datagram)
        except IpCoreError:
            self.failed = True
            raise

    def _feed(self, datagram):
        messages = _messages(datagram)
        if self._bytes + len(datagram) > MAX_DUMP_BYTES or self._datagrams + 1 > MAX_DUMP_DATAGRAMS:
            _fail('dump_limit')
        expected_type, parser = _DUMPS[self.kind][1], _DUMPS[self.kind][3]
        pending, seen, finished = [], set(self._seen), False
        for kind, flags, sequence, port_id, payload in messages:
            if finished:
                _fail('message_after_done')
            if sequence != self.sequence or port_id != self.port_id:
                _fail('dump_identity_mismatch')
            if flags & (NLM_F_DUMP_INTR | NLM_F_DUMP_FILTERED):
                _fail('inconsistent_dump')
            if kind == NLMSG_ERROR:
                ack = _ack_message((kind, flags, sequence, port_id, payload), self.request)
                if not ack.errno:
                    _fail('unexpected_dump_ack')
                _fail('kernel_error', ack.errno)
            if kind == NLMSG_OVERRUN:
                _fail('dump_overrun')
            if kind == NLMSG_DONE:
                if flags not in (0, NLM_F_MULTI) or len(payload) != 4:
                    _fail('invalid_dump_done')
                error = _S32.unpack(payload)[0]
                if error > 0 or error < -4095:
                    _fail('invalid_kernel_errno')
                if error:
                    _fail('kernel_error', -error)
                finished = True
                continue
            if kind != expected_type or flags != NLM_F_MULTI:
                _fail('unexpected_dump_message')
            record = parser(payload)
            identity = (record.ifindex, record.local, record.address, record.prefixlen) \
                if type(record) is AddressRecord else record
            if identity in seen:
                _fail('duplicate_record')
            seen.add(identity)
            pending.append(record)
            if len(self._records) + len(pending) > MAX_DUMP_RECORDS:
                _fail('record_limit')
        # Commit a datagram only after every message has passed validation.
        self._records.extend(pending)
        self._seen = seen
        self._bytes += len(datagram)
        self._datagrams += 1
        self.complete = finished

    def records(self):
        if self.failed or not self.complete:
            _fail('incomplete_dump')
        return tuple(self._records)


class IpSnapshot(namedtuple('_IpSnapshot', 'addresses routes rules')):
    """Private immutable records from three complete dumps, not an atomic view."""
    __slots__ = ()
    def __new__(cls, addresses, routes, rules):
        if (type(addresses) is not tuple or type(routes) is not tuple or type(rules) is not tuple or
                any(type(row) is not AddressRecord for row in addresses) or
                any(type(row) is not RouteRecord for row in routes) or
                any(type(row) is not RuleRecord for row in rules)):
            _fail('invalid_snapshot')
        return super(IpSnapshot, cls).__new__(cls, addresses, routes, rules)

    def __repr__(self):
        return '<IpSnapshot addresses={} routes={} rules={}>'.format(
            len(self.addresses), len(self.routes), len(self.rules))

    def structural_key(self):
        """Private stable comparison; exclude changing cache lifetimes/timestamps.

        Complete cacheinfo remains in addresses. The future adapter must check
        lease/lifetime semantics separately; this key is not a consistency gate.
        """
        addresses = tuple(sorted((tuple(row[:-1]) for row in self.addresses), key=repr))
        routes = tuple(sorted(self.routes, key=lambda row: repr(tuple(row))))
        return addresses, routes, tuple(sorted(self.rules))


def snapshot_from_dumps(addresses, routes, rules):
    dumps = (addresses, routes, rules)
    if any(type(item) is not DumpCollector for item in dumps):
        _fail('invalid_snapshot')
    if tuple(item.kind for item in dumps) != ('addresses', 'routes', 'rules'):
        _fail('invalid_snapshot')
    # Sequential completed requests may reuse a sequence. Per-message sequence
    # and type checks happen in each collector; the future adapter should still
    # allocate monotonic sequences and reject stale datagrams on its own socket.
    if len(set(item.port_id for item in dumps)) != 1:
        _fail('snapshot_dump_identity')
    return IpSnapshot(*(item.records() for item in dumps))


def require_default_rules(snapshot):
    if type(snapshot) is not IpSnapshot:
        _fail('invalid_snapshot')
    if sorted(snapshot.rules) != [RuleRecord(0, 255), RuleRecord(32766, 254), RuleRecord(32767, 253)]:
        _fail('nondefault_policy')


class SubnetChoice(namedtuple('_SubnetChoice', 'network prefixlen')):
    __slots__ = ()
    def __repr__(self):
        return '<SubnetChoice private>'


def select_subnet(snapshot, candidates):
    """Choose an explicit bounded RFC1918 /24; never infer a gateway/local IP.

    All address prefixes (local AND point-to-point peer), concrete routes in
    every table, and gateway/prefsrc endpoints participate. /0 routes remain
    in the snapshot but do not conflict with every possible candidate.
    """
    require_default_rules(snapshot)
    if type(candidates) not in (tuple, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        _fail('invalid_candidates')
    networks, seen = [], set()
    for candidate in candidates:
        if type(candidate) is not str or candidate.count('/') != 1:
            _fail('invalid_candidate')
        text, prefix = candidate.split('/')
        network = ipv4_number(text)
        if prefix != '24' or network & 255 or not _private(network) or network in seen:
            _fail('invalid_candidate')
        seen.add(network)
        networks.append(network)
    occupied = []
    for row in snapshot.addresses:
        mask = _mask(row.prefixlen)
        for address in (row.local, row.address):
            start = address & mask
            occupied.append((start, start | (UINT_MAX ^ mask)))
    for row in snapshot.routes:
        if row.prefixlen:
            occupied.append((row.network, row.network | (UINT_MAX ^ _mask(row.prefixlen))))
        for address in (row.gateway, row.prefsrc):
            if address is not None:
                occupied.append((address, address))
    for network in networks:
        if not any(network <= end and start <= network + 255 for start, end in occupied):
            return SubnetChoice(network, 24)
    _fail('no_available_subnet')


class AddressSpec(namedtuple('_AddressSpec', 'ifindex address prefixlen')):
    """Explicit private host address; this object is NOT ownership evidence."""
    __slots__ = ()
    def __new__(cls, ifindex, address, prefixlen):
        _uint(ifindex, 0x7fffffff, 1)
        number = ipv4_number(address)
        if type(prefixlen) is not int or prefixlen != 24 or not _private(number) or number & 255 in (0, 255):
            _fail('invalid_address_spec')
        return super(AddressSpec, cls).__new__(cls, ifindex, number, prefixlen)

    def __repr__(self):
        return '<AddressSpec private>'


def _address_payload(spec):
    if type(spec) is not AddressSpec:
        _fail('invalid_address_spec')
    _uint(spec.ifindex, 0x7fffffff, 1)
    _uint(spec.address)
    if type(spec.prefixlen) is not int or spec.prefixlen != 24 or not _private(spec.address) or spec.address & 255 in (0, 255):
        _fail('invalid_address_spec')
    wire = struct.pack('>I', spec.address)
    broadcast = struct.pack('>I', spec.address | 255)
    return (_ADDR.pack(AF_INET, spec.prefixlen, IFA_F_PERMANENT, 0, spec.ifindex) +
            _attribute(IFA_ADDRESS, wire) + _attribute(IFA_LOCAL, wire) +
            _attribute(IFA_BROADCAST, broadcast))


def encode_new_address(spec, sequence, port_id):
    """Bytes only. Future caller persists intent then fresh-validates ownership."""
    return _message(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                    sequence, port_id, _address_payload(spec))


def encode_del_address(spec, sequence, port_id):
    """Exact index/local/address/prefix; never flushes or encodes route deletion."""
    return _message(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK,
                    sequence, port_id, _address_payload(spec))
