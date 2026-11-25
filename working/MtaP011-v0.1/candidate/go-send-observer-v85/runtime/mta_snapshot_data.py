"""Fixed private Snapshot DATA/key codec, Python 3.5, SOURCE only.

The imported core is the caller's already loaded fixed domain. RO33 and GO28
have text-identical Origin, Actor and Snapshot/key definitions. No cross-domain
Snapshot, Actor, IpSnapshot, lease, proof or grant is reconstructed on decode.
All eleven Snapshot fields are retained, including complete IPv4 records,
IPv6 rows and Actor task states. The stable key is exactly Snapshot.key(None):
Actor.key omits task states, but no IP cache field or IPv6 row is removed.

Canonical ASCII is PRIVATE DATA, not an observation, source authentication,
atomic baseline, restoration receipt or admission. A digest compares supplied
DATA only. Actual single-worker sampling, inventories, provenance, deadlines
and restore/admission producers remain the caller's separate obligations.

Only fixed classes and explicit field layouts are read. There is no generic
object/dict/slots/repr serializer, no constructor of a native record, and no
syscall, process, clock, thread, callback or filesystem operation here. Private
DATA representations never include raw fields by default. This module does
not alter p011_json or the Bridge's independent 8192-byte frame limit.

Both full+key envelope and key envelope must fit p011_json.loads' actual
131072-character, depth-24 and 8192-node limits. Excess rejects the COMPLETE
package; there is no truncation, record sampling, implicit chunking or grant.
"""
import hashlib

import p011_json as json
import mta_ip as ip
import mta_p2p_client_init as core


DATA_SCHEMA = 'p011-snapshot-data-v85'
KEY_SCHEMA = 'p011-snapshot-key-v85'
MAX_ASCII_BYTES = 131072
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 8192
MAX_ROWS = 4096
MAX_TAG_DEPTH = 12
_HEX = frozenset('0123456789abcdef')
_NAME = frozenset('abcdefghijklmnopqrstuvwxyz0123456789_.-')
_TASK_STATES = frozenset(('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I'))
_DATA_ISSUER = object()
_SNAPSHOT, _ACTOR, _ORIGIN = core.Snapshot, core.Actor, core.Origin
_IP_SNAPSHOT, _ADDRESS, _ROUTE, _RULE = (
    ip.IpSnapshot, ip.AddressRecord, ip.RouteRecord, ip.RuleRecord)
_SNAPSHOT_KEY, _ACTOR_KEY, _ORIGIN_KEY = (
    _SNAPSHOT.key, _ACTOR.key, _ORIGIN.key)
_STOCK_PINS = core.STOCK_PINS


class SnapshotDataError(ValueError):
    """Constant reason only; never include input, path, PID, IP or raw DATA."""
    pass


def _fail(reason):
    raise SnapshotDataError(reason) from None


class SnapshotData(object):
    """Immutable parsed primitive DATA, never a core Snapshot or permission."""
    __slots__ = ('fields', 'stable_key', 'data_sha', 'key_sha', '_raw', '_key_raw')

    def __init__(self, fields, key, raw, key_raw, _issuer=None):
        if _issuer is not _DATA_ISSUER:
            _fail('data_constructor')
        for name, value in (('fields', fields), ('stable_key', key),
                ('data_sha', hashlib.sha256(raw).hexdigest()),
                ('key_sha', hashlib.sha256(key_raw).hexdigest()),
                ('_raw', raw), ('_key_raw', key_raw)):
            object.__setattr__(self, name, value)

    def __setattr__(self, *unused):
        raise AttributeError('immutable private Snapshot DATA')

    def __delattr__(self, *unused):
        raise AttributeError('immutable private Snapshot DATA')

    def __repr__(self):
        return '<private Snapshot DATA; not sampling, restore or admission>'

    __str__ = __repr__

    def private_ascii(self):
        return self._raw

    def private_key_ascii(self):
        return self._key_raw


def _fixed_types():
    if (any(current is not original for current, original in zip(
            (core.Snapshot, core.Actor, core.Origin, core.ip,
             ip.IpSnapshot, ip.AddressRecord, ip.RouteRecord, ip.RuleRecord),
            (_SNAPSHOT, _ACTOR, _ORIGIN, ip, _IP_SNAPSHOT, _ADDRESS, _ROUTE, _RULE))) or
            core.Snapshot.key is not _SNAPSHOT_KEY or core.Actor.key is not _ACTOR_KEY or
            core.Origin.key is not _ORIGIN_KEY):
        _fail('fixed_domain_changed')


def _tuple(value, width=None, minimum=0, maximum=MAX_ROWS):
    if (type(value) is not tuple or not minimum <= len(value) <= maximum or
            width is not None and len(value) != width):
        _fail('tuple_shape')
    return value


def _uint(value, maximum=0xffffffff, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('integer_shape')
    return value


def _text(value, minimum=1, maximum=256):
    if (type(value) is not str or not minimum <= len(value) <= maximum or
            any(0xd800 <= ord(c) <= 0xdfff for c in value)):
        _fail('text_shape')
    return value


def _sha(value):
    _text(value, 64, 64)
    if any(c not in _HEX for c in value): _fail('hash_shape')


def _origin_fields(value):
    if type(value) is not _ORIGIN: _fail('origin_type')
    return (value.phy, value.wdev, value.ifindex, value.name, value.iftype)


def _actor_fields(value):
    if type(value) is not _ACTOR: _fail('actor_type')
    return (value.pid, value.start, value.exe, value.argv_sha, value.tasks)


def _address_fields(value):
    if type(value) is not _ADDRESS: _fail('address_type')
    return (value.ifindex, value.local, value.address, value.prefixlen,
            value.flags, value.scope, value.label, value.broadcast, value.cacheinfo)


def _route_fields(value):
    if type(value) is not _ROUTE: _fail('route_type')
    return (value.network, value.prefixlen, value.table, value.protocol,
            value.scope, value.kind, value.flags, value.oif, value.gateway,
            value.priority, value.prefsrc, value.metrics)


def _rule_fields(value):
    if type(value) is not _RULE: _fail('rule_type')
    return (value.priority, value.table)


def _origin(row):
    _tuple(row, 5)
    _uint(row[0]); _uint(row[1], (1 << 64) - 1, 1)
    _uint(row[2], 0x7fffffff, 1); _text(row[3], 1, 15); _uint(row[4], 12, 1)
    if any(c not in _NAME for c in row[3]): _fail('origin_shape')


def _actor(row):
    _tuple(row, 5)
    _uint(row[0], 0x7fffffff, 1); _uint(row[1], (1 << 64) - 1, 1)
    _text(row[2]); _sha(row[3]); _tuple(row[4], minimum=1, maximum=128)
    if (not row[2].startswith('/') or any(p in ('', '.', '..') for p in row[2][1:].split('/')) or
            any(ord(c) < 32 for c in row[2])):
        _fail('actor_path_shape')
    for task in row[4]:
        _tuple(task, 3); _uint(task[0], 0x7fffffff, 1)
        _uint(task[1], (1 << 64) - 1, 1)
        if type(task[2]) is not str or task[2] not in _TASK_STATES:
            _fail('task_shape')
    if (len(set(t[0] for t in row[4])) != len(row[4]) or
            not any(t[:2] == row[:2] for t in row[4]) or
            any(t[2] in ('Z', 'X') for t in row[4])):
        _fail('actor_task_shape')


def _address(row):
    _tuple(row, 9)
    _uint(row[0], 0x7fffffff, 1); _uint(row[1]); _uint(row[2])
    _uint(row[3], 32); _uint(row[4]); _uint(row[5])
    if row[4] != 0x80 or row[5] not in (0, 253, 254): _fail('address_shape')
    label = row[6]
    if label is not None and (type(label) is not bytes or not 2 <= len(label) <= 16 or
            label[-1:] != b'\x00' or b'\x00' in label[:-1]):
        _fail('address_label_shape')
    if row[7] is not None: _uint(row[7])
    _tuple(row[8], 4)
    for value in row[8]: _uint(value)
    if row[8][:2] != (0xffffffff, 0xffffffff): _fail('address_cache_shape')


def _route(row):
    _tuple(row, 12)
    for value in row[:7]: _uint(value)
    _uint(row[1], 32); _uint(row[2], minimum=1); _uint(row[3], 255)
    if (row[4] not in (0, 253, 254) or row[5] not in (1, 2, 3) or row[6] & ~0x19 or
            row[0] & ((0xffffffff << (32 - row[1])) & 0xffffffff if row[1] else 0) != row[0]):
        _fail('route_shape')
    for value in row[7:11]:
        if value is not None: _uint(value)
    if row[7] is not None: _uint(row[7], 0x7fffffff, 1)
    _tuple(row[11], maximum=15)
    for metric in row[11]:
        _tuple(metric, 2); _uint(metric[0], 15, 1); _uint(metric[1])
    if len(set(m[0] for m in row[11])) != len(row[11]): _fail('route_metrics_shape')


def _rule(row):
    _tuple(row, 2); _uint(row[0]); _uint(row[1], minimum=1)


def _ipv6(rows, width, unique):
    _tuple(rows)
    for row in rows:
        _tuple(row, width)
        for text in row:
            _text(text)
            if '\x00' in text or '\r' in text or '\n' in text: _fail('ipv6_row_shape')
    if unique and len(set(rows)) != len(rows): _fail('ipv6_duplicate')


def _full(fields):
    # Explicit Snapshot layout, not dynamic slots/attributes or an object hook.
    _tuple(fields, 11)
    boot, hashes, actors, station, state_sha, frequency, interfaces, ipv4, v6a, v6r, completed = fields
    _text(boot, 36, 36)
    if (any(boot[i] != '-' for i in (8, 13, 18, 23)) or
            len(boot.replace('-', '')) != 32 or any(c not in _HEX for c in boot.replace('-', ''))):
        _fail('boot_shape')
    _tuple(hashes, minimum=1, maximum=16)
    for row in hashes:
        _tuple(row, 2); _text(row[0]); _sha(row[1])
        if not row[0].startswith('/'): _fail('stock_path_shape')
    if hashes != tuple(sorted(_STOCK_PINS)) or completed is not True: _fail('stock_shape')
    _tuple(actors, minimum=1, maximum=32)
    for row in actors: _actor(row)
    if (len(set(a[0] for a in actors)) != len(actors) or
            not {'/usr/bin/Z03', '/usr/bin/control_engine'} <= set(a[2] for a in actors) or
            not any(a[2].rsplit('/', 1)[-1] == 'weston' for a in actors)):
        _fail('stock_actors_shape')
    _origin(station); _sha(state_sha); _uint(frequency, 2484, 2412)
    _tuple(interfaces, minimum=1, maximum=32)
    for row in interfaces: _origin(row)
    if (station[3] != 'wlan0' or station[4] != 2 or
            len(set(r[2] for r in interfaces)) != len(interfaces) or
            len(set(r[3] for r in interfaces)) != len(interfaces) or
            sum(r == station for r in interfaces) != 1):
        _fail('interfaces_shape')
    _tuple(ipv4, 3)
    for rows, validator in zip(ipv4, (_address, _route, _rule)):
        _tuple(rows)
        for row in rows: validator(row)
        if len(set(rows)) != len(rows): _fail('ipv4_duplicate')
    if tuple(sorted(ipv4[2])) != ((0, 255), (32766, 254), (32767, 253)):
        _fail('default_rules_shape')
    _ipv6(v6a, 6, True); _ipv6(v6r, 10, False)
    return fields


def _fields(snapshot):
    _fixed_types()
    if type(snapshot) is not _SNAPSHOT: _fail('snapshot_type')
    _tuple(snapshot.stock_actors, minimum=1, maximum=32)
    _tuple(snapshot.interfaces, minimum=1, maximum=32)
    if type(snapshot.ipv4) is not _IP_SNAPSHOT: _fail('ipv4_type')
    v4 = snapshot.ipv4
    for rows in (v4.addresses, v4.routes, v4.rules): _tuple(rows)
    return _full((snapshot.boot, snapshot.stock_hashes,
        tuple(_actor_fields(a) for a in snapshot.stock_actors), _origin_fields(snapshot.station),
        snapshot.station_state_sha, snapshot.station_frequency,
        tuple(_origin_fields(o) for o in snapshot.interfaces),
        (tuple(_address_fields(r) for r in v4.addresses),
         tuple(_route_fields(r) for r in v4.routes), tuple(_rule_fields(r) for r in v4.rules)),
        snapshot.ipv6_addresses, snapshot.ipv6_routes, snapshot.station_completed))


def _bytes_literal(value):
    # Reproduce the fixed primitive bytes component of core's tuple-row sort.
    # No repr()/str() is invoked on a user object, record or arbitrary container.
    quote = '"' if b"'" in value and b'"' not in value else "'"
    parts = ['b', quote]
    for item in value:
        if item == 92: parts.append('\\\\')
        elif item == ord(quote): parts.append('\\' + quote)
        elif item == 9: parts.append('\\t')
        elif item == 10: parts.append('\\n')
        elif item == 13: parts.append('\\r')
        elif 32 <= item <= 126: parts.append(chr(item))
        else: parts.append('\\x%02x' % item)
    return ''.join(parts) + quote


def _row_sort_text(value):
    # Called only for already validated address/route primitive field tuples.
    if value is None: return 'None'
    if type(value) is int: return str(value)
    if type(value) is bytes: return _bytes_literal(value)
    if type(value) is tuple:
        content = ', '.join(_row_sort_text(item) for item in value)
        return '(' + content + (',' if len(value) == 1 else '') + ')'
    _fail('row_sort_shape')


def _stable_key(fields):
    # Primitive equivalent of the original Snapshot.key(None), including its
    # exact address/route tuple-representation order. No owned subtraction.
    boot, hashes, actors, station, state_sha, frequency, interfaces, v4, v6a, v6r, completed = fields
    actors = tuple(sorted((a[0], a[1], a[2], a[3], tuple((t[0], t[1]) for t in a[4])) for a in actors))
    return (boot, hashes, actors, station, state_sha, frequency, tuple(sorted(interfaces)),
            tuple(sorted(v4[0], key=_row_sort_text)), tuple(sorted(v4[1], key=_row_sort_text)),
            tuple(sorted(v4[2])), tuple(sorted(v6a)), tuple(sorted(v6r)))


def _original_key(snapshot, fields):
    # The original fixed method remains the encoding standard. Its complete
    # IP records are normalized only to explicit primitive tuples for DATA.
    _fixed_types()
    value = _SNAPSHOT_KEY(snapshot)
    _tuple(value, 12)
    for rows in value[7:10]: _tuple(rows)
    normalized = value[:7] + (tuple(_address_fields(r) for r in value[7]),
        tuple(_route_fields(r) for r in value[8]), tuple(_rule_fields(r) for r in value[9])) + value[10:]
    if normalized != _stable_key(fields): _fail('original_key_changed')
    return normalized


def _pack(value, depth=0, _nodes=None):
    # Internal only, after fixed field validation: no dict/list/object encoder.
    # Reject each tagged subtree before constructing more than one JSON quota;
    # _canonical additionally checks the combined full+key envelope's quota.
    if depth > MAX_TAG_DEPTH: _fail('tag_depth')
    if _nodes is None: _nodes = [0]
    _nodes[0] += 3 if type(value) in (tuple, bytes) else 1
    if _nodes[0] > MAX_JSON_NODES: _fail('json_structure_limit')
    if value is None or type(value) in (bool, int, str): return value
    if type(value) is bytes: return ['bytes', value.hex()]
    if type(value) is tuple:
        return ['tuple', [_pack(item, depth + 1, _nodes) for item in value]]
    _fail('tag_shape')


def _unpack(value, depth=0):
    if depth > MAX_TAG_DEPTH: _fail('tag_depth')
    if value is None or type(value) is bool: return value
    if type(value) is int: return _uint(value, (1 << 64) - 1)
    if type(value) is str: return _text(value, 0, 256)
    if type(value) is not list or len(value) != 2 or type(value[0]) is not str:
        _fail('tag_shape')
    if value[0] == 'tuple':
        if type(value[1]) is not list or len(value[1]) > MAX_ROWS: _fail('tuple_shape')
        return tuple(_unpack(item, depth + 1) for item in value[1])
    if value[0] == 'bytes':
        text = value[1]
        if (type(text) is not str or len(text) > 32 or len(text) % 2 or
                any(c not in _HEX for c in text)):
            _fail('bytes_shape')
        return bytes.fromhex(text)
    _fail('tag_shape')


def _json_budget(tree):
    # Same value-node/depth convention as p011_json.loads, before encoding.
    pending, count = [(tree, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH: _fail('json_structure_limit')
        if type(value) is list:
            pending.extend((item, depth + 1) for item in value)
        elif value is not None and type(value) not in (bool, int, str):
            _fail('json_shape')


def _canonical(tree):
    _json_budget(tree)
    raw = (json.dumps(tree, ensure_ascii=True) + '\n').encode('ascii')
    if not 1 <= len(raw) <= MAX_ASCII_BYTES: _fail('ascii_limit')
    return raw


def encode_snapshot(snapshot):
    """Complete same-domain Snapshot -> canonical private full+key bytes."""
    fields = _fields(snapshot)
    key = _original_key(snapshot, fields)
    return _canonical([DATA_SCHEMA, _pack(fields), _pack(key)])


def key_ascii(snapshot):
    """Original complete stable-key DATA, not a sampling or authority proof."""
    fields = _fields(snapshot)
    return _canonical([KEY_SCHEMA, _pack(_original_key(snapshot, fields))])


def key_digest(snapshot):
    """SHA256 of canonical stable-key DATA; never a freshness/restore grant."""
    return hashlib.sha256(key_ascii(snapshot)).hexdigest()


def decode_snapshot(raw):
    """Validate private DATA only; never call a native record constructor."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_ASCII_BYTES: _fail('ascii_limit')
    try:
        text = raw.decode('ascii')
        tree = json.loads(text)
    except (ValueError, UnicodeError):
        _fail('json_invalid')
    if type(tree) is not list or len(tree) != 3 or tree[0] != DATA_SCHEMA:
        _fail('data_schema')
    fields, supplied_key = _unpack(tree[1]), _unpack(tree[2])
    _full(fields)
    key = _stable_key(fields)
    if supplied_key != key: _fail('stable_key_mismatch')
    if _canonical([DATA_SCHEMA, _pack(fields), _pack(key)]) != raw: _fail('noncanonical_data')
    key_raw = _canonical([KEY_SCHEMA, _pack(key)])
    return SnapshotData(fields, key, raw, key_raw, _DATA_ISSUER)
