"""Private canonical CLIENT session v6 codec, not a disk Store or authority.

No I/O, hooks, unfixed imports, migration, flock, atomic replace or fsync.
The later fixed dynamic-IP definition is imported only for non-null IP facts.
The bytes and decoded record remain private; do not put either into a public
report. Reconstructed core objects prove schema only, not current OS ownership.
"""
import p011_json as json
import mta_p2p_client_init as core
import mta_ip as ip


MAX_BYTES, MAX_NODES, MAX_DEPTH = 131072, 8192, 24
MAX_ROWS, MAX_ACTORS, MAX_TASKS = 4096, 32, 128
_HEX = frozenset('0123456789abcdef')
_CODES = frozenset(('invalid_input', 'byte_budget', 'structure_budget',
    'invalid_json', 'unsupported_envelope', 'invalid_schema',
    'invalid_record', 'noncanonical'))
_ORIGIN = ('phy', 'wdev', 'ifindex', 'name', 'iftype')
_ACTOR = ('pid', 'start', 'exe', 'argv_sha', 'tasks')
_TICKET = ('token', 'role', 'boot', 'exe', 'argv_sha')
_ITICKET = ('boot', 'phy', 'name', 'sequence', 'port_id')
_IDENTITY = ('candidate_sha', 'wpa_sha', 'ctrl_sha')
_ADDRESS = ('ifindex', 'local', 'address', 'prefixlen', 'flags', 'scope',
    'label_hex', 'broadcast', 'cacheinfo')
_ROUTE = ('network', 'prefixlen', 'table', 'protocol', 'scope', 'kind',
    'flags', 'oif', 'gateway', 'priority', 'prefsrc', 'metrics')
_RULE = ('priority', 'table')
_SNAPSHOT = ('boot', 'stock_hashes', 'stock_actors', 'station', 'station_state_sha',
    'station_frequency', 'interfaces', 'ipv4', 'ipv6_addresses',
    'ipv6_routes', 'station_completed')
_JOURNAL = ('identity', 'stage', 'baseline', 'deadline', 'session_profile', 'issued_at', 'owned', 'interface_ticket',
    'controller_ticket', 'controller', 'watchdog_ticket', 'watchdog', 'ready', 'association', 'client_ip')
_ASSOCIATION = ('phase', 'binding', 'executor', 'local_mac_hex', 'bssid_hex', 'frequency', 'observed_digest')
_CLIENT_IP = ('phase', 'owned', 'local_ip', 'prefix', 'allocation_until', 'baseline', 'observed')
_ENVELOPE = ('version', 'kind', 'marker', 'journal')


class JournalCodecError(ValueError):
    """Only fixed codes. Never stringify caller data or a core exception."""
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'invalid_record'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise JournalCodecError(code) from None


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys): _fail('invalid_schema')
    return value


def _uint(value, maximum=0xffffffff, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum: _fail('invalid_record')
    return value


def _text(value, maximum=256):
    if type(value) is not str or not 1 <= len(value) <= maximum or any(0xd800 <= ord(c) <= 0xdfff for c in value):
        _fail('invalid_record')
    return value


def _hash(value):
    _text(value, 64)
    if len(value) != 64 or any(c not in _HEX for c in value): _fail('invalid_record')
    return value


def _sequence(value, maximum, minimum=0, width=None):
    if type(value) is not list or not minimum <= len(value) <= maximum or (width is not None and len(value) != width):
        _fail('invalid_record')
    return value


def _tuple_source(value, maximum, minimum=0):
    if type(value) is not tuple or not minimum <= len(value) <= maximum: _fail('invalid_record')
    return value


def _bool(value):
    if type(value) is not bool: _fail('invalid_record')
    return value


def _optional(value, parse):
    return None if value is None else parse(value)


def _guard(value):
    # Same global node/depth envelope as bundled loads, also enforced on encode.
    count = [0]; encoded_bytes = [0]
    def charge(amount):
        encoded_bytes[0] += amount
        if encoded_bytes[0] > MAX_BYTES: _fail('byte_budget')
    def visit(item, depth):
        count[0] += 1
        if count[0] > MAX_NODES or depth > MAX_DEPTH: _fail('structure_budget')
        if item is None: charge(4); return
        if type(item) is bool: charge(4 if item else 5); return
        if type(item) is int: _uint(item, (1 << 64) - 1); charge(len(str(item))); return
        if type(item) is float:
            if not 0 <= item < 1e12: _fail('invalid_record')
            charge(len(repr(item)))
            return
        if type(item) is str: _text(item); charge(len(json.dumps(item, ensure_ascii=True))); return
        if type(item) is list:
            if len(item) > MAX_ROWS: _fail('structure_budget')
            charge(2 + 2 * max(0, len(item) - 1))
            for child in item: visit(child, depth + 1)
            return
        if type(item) is dict:
            if len(item) > 16 or any(type(key) is not str or not 1 <= len(key) <= 64 for key in item):
                _fail('invalid_schema')
            charge(2 + 2 * max(0, len(item) - 1))
            for key in item: charge(len(json.dumps(key, ensure_ascii=True)) + 2)
            for child in item.values(): visit(child, depth + 1)
            return
        _fail('invalid_record')
    visit(value, 0)


def _map_source(value, cls, keys):
    if type(value) is not cls: _fail('invalid_record')
    return dict((key, getattr(value, key)) for key in keys)


def _origin_tree(value):
    return _map_source(value, core.Origin, _ORIGIN)


def _actor_tree(value):
    row = _map_source(value, core.Actor, _ACTOR)
    row['tasks'] = [list(_tuple_source(task, 3, 3)) for task in _tuple_source(value.tasks, MAX_TASKS, 1)]
    return row


def _ticket_tree(value):
    return _map_source(value, core.Ticket, _TICKET)


def _iticket_tree(value):
    return _map_source(value, core.InterfaceTicket, _ITICKET)


def _identity_tree(value):
    if type(value) is not core.Identity: _fail('invalid_record')
    return {'candidate_sha': value.candidate_sha, 'wpa_sha': core.WPA_SHA, 'ctrl_sha': core.CTRL_SHA}


def _label_tree(value):
    if value is None: return None
    if type(value) is not bytes or not 2 <= len(value) <= 16: _fail('invalid_record')
    return ''.join('%02x' % item for item in value)


def _ipv4_tree(value):
    if type(value) is not ip.IpSnapshot: _fail('invalid_record')
    addresses, routes, rules = [], [], []
    for row in _tuple_source(value.addresses, MAX_ROWS):
        if type(row) is not ip.AddressRecord: _fail('invalid_record')
        record = dict((key, getattr(row, key)) for key in _ADDRESS if key != 'label_hex')
        record['label_hex'] = _label_tree(row.label)
        record['cacheinfo'] = list(_tuple_source(row.cacheinfo, 4, 4)); addresses.append(record)
    for row in _tuple_source(value.routes, MAX_ROWS):
        record = _map_source(row, ip.RouteRecord, _ROUTE)
        record['metrics'] = [list(_tuple_source(pair, 2, 2)) for pair in _tuple_source(row.metrics, 15)]
        routes.append(record)
    for row in _tuple_source(value.rules, MAX_ROWS): rules.append(_map_source(row, ip.RuleRecord, _RULE))
    return {'addresses': addresses, 'routes': routes, 'rules': rules}


def _snapshot_tree(value):
    if type(value) is not core.Snapshot: _fail('invalid_record')
    row = dict((key, getattr(value, key)) for key in ('boot', 'station_state_sha', 'station_frequency', 'station_completed'))
    row['stock_hashes'] = [dict(zip(('path', 'sha256'), _tuple_source(pair, 2, 2)))
        for pair in _tuple_source(value.stock_hashes, 16, 1)]
    row['stock_actors'] = [_actor_tree(actor) for actor in _tuple_source(value.stock_actors, MAX_ACTORS, 1)]
    row['station'] = _origin_tree(value.station)
    row['interfaces'] = [_origin_tree(origin) for origin in _tuple_source(value.interfaces, 32, 1)]
    row['ipv4'] = _ipv4_tree(value.ipv4)
    for key, width in (('ipv6_addresses', 6), ('ipv6_routes', 10)):
        row[key] = [list(_tuple_source(pair, width, width)) for pair in _tuple_source(getattr(value, key), MAX_ROWS)]
    return row


def _mac_tree(value):
    if value is None: return None
    if type(value) is not bytes or len(value) != 6: _fail('invalid_record')
    return ''.join('%02x' % item for item in value)


def _association_tree(value):
    if type(value) is not core.ClientAssociationRecord: _fail('invalid_record')
    return {'phase': value.phase, 'binding': value.binding, 'executor': _actor_tree(value.executor),
        'local_mac_hex': _mac_tree(value.local_mac), 'bssid_hex': _mac_tree(value.bssid),
        'frequency': value.frequency, 'observed_digest': value.observed_digest}


def _client_ip_tree(value):
    import mta_client_dynamic_ip as dynamic
    row = _map_source(value, dynamic.DynamicIpRecord, _CLIENT_IP)
    row['owned'] = _origin_tree(value.owned)
    row['baseline'] = _ipv4_tree(value.baseline)
    row['observed'] = _optional(value.observed, _ipv4_tree)
    return row


def _document(value):
    if type(value) is not core.Journal: _fail('invalid_record')
    row = {'identity': _identity_tree(value.identity), 'stage': value.stage,
        'baseline': _snapshot_tree(value.baseline), 'deadline': value.deadline,
        'session_profile': value.session_profile, 'issued_at': value.issued_at, 'ready': value.ready}
    for key, encoder in (('owned', _origin_tree), ('interface_ticket', _iticket_tree),
            ('controller_ticket', _ticket_tree), ('controller', _actor_tree),
            ('watchdog_ticket', _ticket_tree), ('watchdog', _actor_tree)):
        row[key] = _optional(getattr(value, key), encoder)
    row['association'] = _optional(value.association, _association_tree)
    row['client_ip'] = _optional(value.client_ip, _client_ip_tree)
    return {'version': core.VERSION, 'kind': core.KIND, 'marker': core.MARKER, 'journal': row}


def _origin(value):
    row = _object(value, _ORIGIN)
    return core.Origin(_uint(row['phy']), _uint(row['wdev'], (1 << 64) - 1, 1),
        _uint(row['ifindex'], 0x7fffffff, 1), _text(row['name'], 15), _uint(row['iftype'], 12, 1))


def _actor(value):
    row = _object(value, _ACTOR); tasks = []
    for task in _sequence(row['tasks'], MAX_TASKS, 1):
        _sequence(task, 3, width=3)
        tasks.append((_uint(task[0], 0x7fffffff, 1), _uint(task[1], (1 << 64) - 1, 1), _text(task[2], 1)))
    return core.Actor(_uint(row['pid'], 0x7fffffff, 1), _uint(row['start'], (1 << 64) - 1, 1),
        _text(row['exe']), _hash(row['argv_sha']), tuple(tasks))


def _ticket(value):
    row = _object(value, _TICKET)
    return core.Ticket(_text(row['token'], 32), _text(row['role'], 10),
        _text(row['boot'], 36), _text(row['exe']), _hash(row['argv_sha']))


def _iticket(value):
    row = _object(value, _ITICKET)
    return core.InterfaceTicket(_text(row['boot'], 36), _uint(row['phy']), _text(row['name'], 15),
        _uint(row['sequence'], minimum=1), _uint(row['port_id'], minimum=1))


def _identity(value):
    row = _object(value, _IDENTITY)
    if row['wpa_sha'] != core.WPA_SHA or row['ctrl_sha'] != core.CTRL_SHA: _fail('unsupported_envelope')
    return core.Identity(_hash(row['candidate_sha']))


def _label(value):
    if value is None: return None
    if type(value) is not str or not 4 <= len(value) <= 32 or len(value) % 2 or any(c not in _HEX for c in value):
        _fail('invalid_record')
    return bytes(int(value[pos:pos + 2], 16) for pos in range(0, len(value), 2))


def _ipv4(value):
    row = _object(value, ('addresses', 'routes', 'rules')); addresses, routes, rules = [], [], []
    for value in _sequence(row['addresses'], MAX_ROWS):
        record = _object(value, _ADDRESS)
        cache = tuple(_uint(v) for v in _sequence(record['cacheinfo'], 4, width=4))
        addresses.append(ip.AddressRecord(_uint(record['ifindex'], 0x7fffffff, 1), _uint(record['local']),
            _uint(record['address']), _uint(record['prefixlen'], 32), _uint(record['flags']),
            _uint(record['scope'], 255), _label(record['label_hex']), _optional(record['broadcast'], _uint), cache))
    for value in _sequence(row['routes'], MAX_ROWS):
        record = _object(value, _ROUTE); metrics = []
        for pair in _sequence(record['metrics'], 15):
            _sequence(pair, 2, width=2); metrics.append((_uint(pair[0], 15, 1), _uint(pair[1])))
        routes.append(ip.RouteRecord(_uint(record['network']), _uint(record['prefixlen'], 32),
            _uint(record['table'], minimum=1), _uint(record['protocol'], 255), _uint(record['scope'], 255),
            _uint(record['kind'], 255), _uint(record['flags']), _optional(record['oif'], lambda v: _uint(v, 0x7fffffff, 1)),
            _optional(record['gateway'], _uint), _optional(record['priority'], _uint),
            _optional(record['prefsrc'], _uint), tuple(metrics)))
    for value in _sequence(row['rules'], MAX_ROWS):
        record = _object(value, _RULE)
        rules.append(ip.RuleRecord(_uint(record['priority']), _uint(record['table'], minimum=1)))
    return ip.IpSnapshot(tuple(addresses), tuple(routes), tuple(rules))


def _snapshot(value):
    row = _object(value, _SNAPSHOT); stock = []
    for value in _sequence(row['stock_hashes'], 16, 1):
        pair = _object(value, ('path', 'sha256')); stock.append((_text(pair['path']), _hash(pair['sha256'])))
    v6 = {}
    for key, width in (('ipv6_addresses', 6), ('ipv6_routes', 10)):
        v6[key] = tuple(tuple(_text(v) for v in _sequence(pair, width, width=width))
            for pair in _sequence(row[key], MAX_ROWS))
    return core.Snapshot(_text(row['boot'], 36), tuple(stock),
        tuple(_actor(v) for v in _sequence(row['stock_actors'], MAX_ACTORS, 1)), _origin(row['station']),
        _hash(row['station_state_sha']), _uint(row['station_frequency'], 2484, 2412),
        tuple(_origin(v) for v in _sequence(row['interfaces'], 32, 1)), _ipv4(row['ipv4']),
        v6['ipv6_addresses'], v6['ipv6_routes'], _bool(row['station_completed']))


def _mac(value):
    if type(value) is not str or len(value) != 12 or any(c not in _HEX for c in value):
        _fail('invalid_record')
    return bytes(int(value[pos:pos + 2], 16) for pos in range(0, 12, 2))


def _association(value):
    row = _object(value, _ASSOCIATION)
    _object(row['binding'], core._ASSOCIATION_BINDING)
    return core.ClientAssociationRecord(_text(row['phase'], 11), row['binding'], _actor(row['executor']),
        _optional(row['local_mac_hex'], _mac), _optional(row['bssid_hex'], _mac),
        _optional(row['frequency'], lambda v: _uint(v, 2484, 2412)),
        _optional(row['observed_digest'], _hash))


def _client_ip(value):
    import mta_client_dynamic_ip as dynamic
    row = _object(value, _CLIENT_IP)
    if type(row['allocation_until']) is not float or not 0 <= row['allocation_until'] < 1e12:
        _fail('invalid_record')
    return dynamic.DynamicIpRecord(_text(row['phase'], 16), _origin(row['owned']),
        ip.ipv4_text(_uint(row['local_ip'], minimum=1)), _uint(row['prefix'], 30, 8),
        row['allocation_until'], _ipv4(row['baseline']), _optional(row['observed'], _ipv4))


def _decode_document(value):
    envelope = _object(value, _ENVELOPE)
    if type(envelope['version']) is not int or envelope['version'] != 6 or \
            type(envelope['kind']) is not str or envelope['kind'] != 'p2p_client_association' or \
            type(envelope['marker']) is not str or envelope['marker'] != 'p011-client-session-v28-1':
        _fail('unsupported_envelope')
    row = _object(envelope['journal'], _JOURNAL)
    if type(row['deadline']) is not float or not 0 <= row['deadline'] < 1e12: _fail('invalid_record')
    if type(row['issued_at']) is not float or not 0 <= row['issued_at'] < 1e12: _fail('invalid_record')
    # Only fixed names reconstruct schema. No legacy inference or caller TTL.
    profile = core.session_profile_named(_text(row['session_profile'], 16))
    return core.Journal(_identity(row['identity']), _text(row['stage'], 32), _snapshot(row['baseline']), row['deadline'],
        owned=_optional(row['owned'], _origin), interface_ticket=_optional(row['interface_ticket'], _iticket),
        controller_ticket=_optional(row['controller_ticket'], _ticket), controller=_optional(row['controller'], _actor),
        watchdog_ticket=_optional(row['watchdog_ticket'], _ticket), watchdog=_optional(row['watchdog'], _actor), ready=_bool(row['ready']),
        association=_optional(row['association'], _association),
        session_profile=profile.name, issued_at=row['issued_at'], client_ip=_optional(row['client_ip'], _client_ip))


def _canonical(document):
    return json.dumps(document, ensure_ascii=True, sort_keys=True).encode('ascii')


def encode_journal(record):
    """Return private canonical bounded bytes; revalidate all core fields."""
    try:
        document = _document(record); _guard(document)
        rebuilt = _decode_document(document)
        if _document(rebuilt) != document: _fail('noncanonical')
        data = _canonical(document)
        if len(data) > MAX_BYTES: _fail('byte_budget')
        return data
    except JournalCodecError: raise
    except Exception: _fail('invalid_record')


def decode_journal(data):
    """Schema reconstruction only; no pending/owner/OS/durability approval."""
    if type(data) is not bytes or not data: _fail('invalid_input')
    if len(data) > MAX_BYTES: _fail('byte_budget')
    try: document = json.loads(data.decode('utf-8', 'strict'))
    except Exception: _fail('invalid_json')
    try:
        _guard(document); result = _decode_document(document)
        if _canonical(_document(result)) != data: _fail('noncanonical')
        return result
    except JournalCodecError: raise
    except Exception: _fail('invalid_record')
