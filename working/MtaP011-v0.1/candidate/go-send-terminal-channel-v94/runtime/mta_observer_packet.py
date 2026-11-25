"""Private bounded observer packet DATA codec, Python 3.5, SOURCE only.

This channel is independent of the GO Bridge's 8192-byte frames. A fixed
18-byte prefix gives exact header/payload lengths; canonical ASCII header and
the original complete Snapshot ASCII payload follow without base64 or any
truncation. Header <= 64 KiB, payload <= 128 KiB, complete packet <= 256 KiB.
The two helper stdout/stderr originals are retained as hex DATA in the header.

Decoded values are immutable primitive DATA and SnapshotData, not a native
Snapshot, Actor, source authentication, sampling/closure/restore receipt or
admission. No clock, FD, syscall, subprocess, callback or native constructor
is invoked here. A future Parent must separately bind the original launch,
pipe/EOF, wait/reap, source pins and lifetime; packet validity or exit zero
alone is never that evidence. All packet/header/payload data remain private.
"""
import hashlib
import math
import re
import struct

import p011_json as json
import mta_snapshot_data as snapshots

SCHEMA = 'p011-go-observer-packet-v87'
MAGIC = b'P011OBS87\x00'
PREFIX_BYTES = len(MAGIC) + 8
MAX_HEADER = 65536
MAX_PAYLOAD = 131072
MAX_PACKET = 262144
MAX_CHUNKS = 4096
SOURCE_MANIFEST_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
SOURCE_COUNT = 38
HELPERS = (
    ('/var/volatile/tmp/p011-mta-state-v69/native/mta-bluez-helper',
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('/var/volatile/tmp/p011-mta-state-v69/native/mta-network-helper',
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
_BIND_KEYS = frozenset(('nonce', 'task_id', 'native_epoch', 'operation_epoch',
                       'until', 'cleanup_until'))
_HEADER_KEYS = frozenset(('schema', 'binding', 'source_manifest_sha256',
    'source_count', 'helpers', 'lock_metadata', 'payload_bytes',
    'payload_sha256', 'stable_key_sha256', 'rf_requested',
    'restoration_verified', 'production_admitted'))
_RESULT_KEYS = frozenset(('schema', 'binding', 'snapshot_raw', 'stable_key_sha256',
    'helper_raw', 'lock_metadata', 'source_manifest_sha256', 'source_count',
    'active_until', 'cleanup_until', 'rf_requested', 'restoration_verified',
    'production_admitted'))
_DATA_ISSUER = object()
_JSON_MODULE, _JSON_DUMPS, _JSON_LOADS = json, json.dumps, json.loads
_SNAPSHOT_MODULE, _SNAPSHOT_DECODE = snapshots, snapshots.decode_snapshot


class ObserverPacketError(ValueError):
    """Constant reason only; no raw packet, identifier, path or helper text."""
    pass


def _fail(reason):
    raise ObserverPacketError(reason) from None


def _fixed():
    if (json is not _JSON_MODULE or json.dumps is not _JSON_DUMPS or
            json.loads is not _JSON_LOADS or snapshots is not _SNAPSHOT_MODULE or
            snapshots.decode_snapshot is not _SNAPSHOT_DECODE):
        _fail('packet_definition_changed')


def _finite(value):
    return type(value) is float and math.isfinite(value) and 0 < value < 1e12


def _sha(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        _fail('packet_hash')
    return value


def _binding(value):
    if type(value) is not dict or set(value) != _BIND_KEYS:
        _fail('packet_binding')
    if any(type(value[name]) is not str or re.fullmatch('[0-9a-f]{32}', value[name]) is None
           for name in ('nonce', 'task_id')):
        _fail('packet_binding')
    if (any(type(value[name]) is not int or not 1 <= value[name] < (1 << 53)
            for name in ('native_epoch', 'operation_epoch')) or
            value['native_epoch'] != value['operation_epoch'] or
            not _finite(value['until']) or not _finite(value['cleanup_until']) or
            not value['until'] <= value['cleanup_until'] <= value['until'] + 5.0):
        _fail('packet_binding')
    return tuple((key, value[key]) for key in sorted(_BIND_KEYS))


def _lock(value):
    if (type(value) not in (tuple, list) or len(value) != 9 or
            any(type(item) is not int or not 0 <= item < (1 << 64) for item in value) or
            tuple(value[2:7]) != (0o100600, 0, 0, 1, 0)):
        _fail('packet_lock_data')
    return tuple(value)


def _raw_hex(value, maximum):
    if (type(value) is not str or len(value) > maximum * 2 or len(value) % 2 or
            re.fullmatch('[0-9a-f]*', value) is None):
        _fail('packet_helper_data')
    return bytes.fromhex(value)


def _helpers(value):
    if type(value) is not list or len(value) != 2:
        _fail('packet_helper_data')
    result = []
    for expected, row in zip(HELPERS, value):
        if (type(row) is not dict or set(row) != {'path', 'binary_sha256', 'stdout_hex', 'stderr_hex'} or
                type(row['path']) is not str or type(row['binary_sha256']) is not str or
                (row['path'], row['binary_sha256']) != expected):
            _fail('packet_helper_data')
        out = _raw_hex(row['stdout_hex'], 8192)
        err = _raw_hex(row['stderr_hex'], 4096)
        if not out or err:
            # Successful frozen Body retains full stdout and requires empty stderr.
            _fail('packet_helper_data')
        result.append((row['path'], out, err))
    return tuple(result)


def _canonical(value):
    _fixed()
    try:
        raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    except (UnicodeError, ValueError, TypeError):
        _fail('packet_header')
    if not 1 <= len(raw) <= MAX_HEADER:
        _fail('packet_header_limit')
    return raw


def _header(value, payload):
    if type(value) is not dict or set(value) != _HEADER_KEYS:
        _fail('packet_header')
    if (type(value['schema']) is not str or value['schema'] != SCHEMA or
            type(value['source_manifest_sha256']) is not str or
            value['source_manifest_sha256'] != SOURCE_MANIFEST_SHA or
            type(value['source_count']) is not int or value['source_count'] != SOURCE_COUNT or
            any(value[name] is not False for name in
                ('rf_requested', 'restoration_verified', 'production_admitted')) or
            type(value['payload_bytes']) is not int or value['payload_bytes'] != len(payload)):
        _fail('packet_header')
    binding = _binding(value['binding'])
    helpers = _helpers(value['helpers'])
    lock = _lock(value['lock_metadata'])
    if hashlib.sha256(payload).hexdigest() != _sha(value['payload_sha256']):
        _fail('packet_payload_changed')
    _fixed()
    decoded = _SNAPSHOT_DECODE(payload)
    if decoded.key_sha != _sha(value['stable_key_sha256']):
        _fail('packet_stable_key_changed')
    return binding, helpers, lock, decoded


class ObserverPacketData(object):
    """Private immutable DATA; no native owner, receipt, proof or permission."""
    __slots__ = ('binding', 'source_manifest_sha256', 'source_count', 'helper_raw',
        'lock_metadata', 'snapshot', 'packet_sha256', '_header_raw', '_payload_raw')

    def __init__(self, binding, helpers, lock, snapshot, packet, header, payload, _issuer=None):
        if _issuer is not _DATA_ISSUER:
            _fail('packet_data_constructor')
        for name, value in (('binding', binding), ('source_manifest_sha256', SOURCE_MANIFEST_SHA),
                ('source_count', SOURCE_COUNT), ('helper_raw', helpers), ('lock_metadata', lock),
                ('snapshot', snapshot), ('packet_sha256', hashlib.sha256(packet).hexdigest()),
                ('_header_raw', header), ('_payload_raw', payload)):
            object.__setattr__(self, name, value)

    def __setattr__(self, *unused):
        raise AttributeError('immutable private observer DATA')

    def __delattr__(self, *unused):
        raise AttributeError('immutable private observer DATA')

    def __repr__(self):
        return '<private observer DATA; no sampling, closure, restore or admission>'

    __str__ = __repr__

    def private_header_ascii(self):
        return self._header_raw

    def private_snapshot_ascii(self):
        return self._payload_raw


def encode_result(value):
    """Frozen Body private result -> complete packet; this is DATA validation."""
    _fixed()
    if (type(value) is not dict or set(value) != _RESULT_KEYS or
            type(value['schema']) is not str or value['schema'] != 'p011-go-preflight-data-v85' or
            type(value['binding']) is not tuple or len(value['binding']) != 6):
        _fail('packet_result')
    for row in value['binding']:
        if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str:
            _fail('packet_binding')
    binding = dict(value['binding'])
    if _binding(binding) != value['binding'] or (
            type(value['active_until']) is not float or type(value['cleanup_until']) is not float or
            value['active_until'] != binding['until'] or
            value['cleanup_until'] != binding['cleanup_until']):
        _fail('packet_binding')
    payload = value['snapshot_raw']
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD:
        _fail('packet_payload_limit')
    if type(value['helper_raw']) is not tuple or len(value['helper_raw']) != 2:
        _fail('packet_helper_data')
    helpers = []
    for expected, row in zip(HELPERS, value['helper_raw']):
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or row[0] != expected[0] or
                type(row[1]) is not bytes or type(row[2]) is not bytes or
                not 1 <= len(row[1]) <= 8192 or len(row[2]) > 4096):
            _fail('packet_helper_data')
        helpers.append(dict(path=row[0], binary_sha256=expected[1],
                            stdout_hex=row[1].hex(), stderr_hex=row[2].hex()))
    header = dict(schema=SCHEMA, binding=binding,
        source_manifest_sha256=value['source_manifest_sha256'], source_count=value['source_count'],
        helpers=helpers, lock_metadata=list(_lock(value['lock_metadata'])), payload_bytes=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(), stable_key_sha256=value['stable_key_sha256'],
        rf_requested=value['rf_requested'], restoration_verified=value['restoration_verified'],
        production_admitted=value['production_admitted'])
    _header(header, payload)
    header_raw = _canonical(header)
    result = MAGIC + struct.pack('!II', len(header_raw), len(payload)) + header_raw + payload
    if len(result) > MAX_PACKET:
        _fail('packet_total_limit')
    return result


def decode_packet(raw):
    """Strict complete private packet -> DATA only, independent of launch/EOF."""
    _fixed()
    if type(raw) is not bytes or not PREFIX_BYTES < len(raw) <= MAX_PACKET or raw[:len(MAGIC)] != MAGIC:
        _fail('packet_prefix')
    hsize, psize = struct.unpack('!II', raw[len(MAGIC):PREFIX_BYTES])
    if (not 1 <= hsize <= MAX_HEADER or not 1 <= psize <= MAX_PAYLOAD or
            PREFIX_BYTES + hsize + psize != len(raw)):
        _fail('packet_lengths')
    header_raw, payload = raw[PREFIX_BYTES:PREFIX_BYTES + hsize], raw[PREFIX_BYTES + hsize:]
    try:
        header = json.loads(header_raw.decode('ascii'))
    except (ValueError, UnicodeError):
        _fail('packet_header')
    binding, helpers, lock, snapshot = _header(header, payload)
    if _canonical(header) != header_raw:
        _fail('packet_header_noncanonical')
    return ObserverPacketData(binding, helpers, lock, snapshot, raw, header_raw, payload, _DATA_ISSUER)


class ObserverPacketReader(object):
    """Bounded primitive stream collector. finish() is not proof of pipe EOF."""
    def __init__(self):
        self.parts, self.size, self.expected = [], 0, None
        self.ended, self.failure, self.value = False, None, None

    def feed(self, raw):
        if self.ended or self.failure is not None:
            _fail('packet_reader_ended')
        try:
            if (type(raw) is not bytes or not 1 <= len(raw) <= 65536 or
                    len(self.parts) >= MAX_CHUNKS or self.size + len(raw) > MAX_PACKET):
                _fail('packet_reader_budget')
            self.parts.append(raw)
            self.size += len(raw)
            if self.expected is None and self.size >= PREFIX_BYTES:
                head = b''.join(self.parts)[:PREFIX_BYTES]
                if head[:len(MAGIC)] != MAGIC:
                    _fail('packet_prefix')
                hsize, psize = struct.unpack('!II', head[len(MAGIC):])
                if not 1 <= hsize <= MAX_HEADER or not 1 <= psize <= MAX_PAYLOAD:
                    _fail('packet_lengths')
                self.expected = PREFIX_BYTES + hsize + psize
            if self.expected is not None and self.size > self.expected:
                _fail('packet_trailing_data')
        except BaseException as error:
            self.failure = error
            raise
        return None

    def finish(self):
        if self.ended or self.failure is not None:
            _fail('packet_reader_ended')
        self.ended = True
        try:
            if self.expected is None or self.size != self.expected:
                _fail('packet_incomplete')
            self.value = decode_packet(b''.join(self.parts))
        except BaseException as error:
            self.failure = error
            raise
        return self.value



# Terminal94 is an APPENDED independent channel. Every preceding byte/constant
# and all Observer87 preflight algorithms remain the frozen original prefix.
# These pure codecs validate supplied primitive DATA, never observation,
# process/FD closure, EOF, restoration, admission, freshness or permission.
TERMINAL_REQUEST_SCHEMA = 'p011-go-terminal-request-v94'
TERMINAL_DATA_SCHEMA = 'p011-go-terminal-data-v94'
TERMINAL_PACKET_SCHEMA = 'p011-go-terminal-packet-v94'
TERMINAL_MAGIC = b'P011TERM94\x00'
TERMINAL_PREFIX_BYTES = len(TERMINAL_MAGIC) + 12
TERMINAL_MAX_REQUEST = 16384
TERMINAL_MAX_FINISH = 4096
TERMINAL_MAX_HEADER = 65536
TERMINAL_MAX_PAYLOAD = 131072
TERMINAL_MAX_PACKET = 393216
_TERMINAL_ISSUER = object()
_TERMINAL_LIMIT_KEYS = frozenset(('task_until', 'service_until',
    'go_cleanup_until', 'service_cleanup_until'))
_TERMINAL_LAUNCH_KEYS = frozenset(('run', 'manifest', 'task', 'nonce',
    'native_epoch', 'operation_epoch', 'until', 'candidate_sha', 'child_pid'))
_TERMINAL_FINISH_KEYS = frozenset(('schema', 'provenance', 'binding', 'journal',
    'cleanup_until', 'finished_at', 'device_lock_metadata', 'f_actor',
    'f_actor_data', 'children', 'children_outcomes', 'inventory_counts',
    'business_failed_at_capture', 'native_full_inventory_export',
    'independent_restore_verified', 'production_admitted'))
_TERMINAL_JOURNAL_KEYS = frozenset(('schema', 'run_token', 'candidate_sha',
    'task_id', 'boot_id', 'issued_at', 'until', 'phase', 'generation',
    'baseline', 'interface_intent', 'owned', 'watchdog', 'controller',
    'group_add', 'group_observed', 'cleanup_until', 'restored', 'ip', 'dhcp'))
_TERMINAL_FALSE_KEYS = ('rf_requested', 'native_restore_verified',
    'restoration_verified', 'independent_restore_verified', 'production_admitted')
_TERMINAL_RESULT_KEYS = frozenset(('schema', 'binding', 'launch_binding',
    'cleanup_limits', 'finish_raw', 'finish_sha256', 'journal_raw',
    'journal_sha256', 'journal_metadata', 'device_lock_metadata',
    'journal_lock_metadata', 'snapshot_raw', 'stable_key_sha256',
    'snapshot_round_count', 'absence_facts', 'source_manifest_sha256',
    'source_count', 'active_until', 'cleanup_until') + _TERMINAL_FALSE_KEYS)
_TERMINAL_HEADER_KEYS = (_TERMINAL_RESULT_KEYS -
    {'finish_raw', 'journal_raw', 'snapshot_raw'}) | {
        'finish_ascii', 'snapshot_bytes', 'snapshot_sha256', 'journal_bytes'}
_TERMINAL_SNAPSHOT_FUNCTIONS = (
    snapshots._full, snapshots._stable_key, snapshots._pack,
    snapshots._canonical, snapshots.decode_snapshot)
_TERMINAL_ORIGIN_KEYS = ('phy', 'wdev', 'ifindex', 'name', 'iftype')
_TERMINAL_ACTOR_KEYS = ('pid', 'start', 'exe', 'argv_sha', 'tasks')
_TERMINAL_SNAPSHOT_KEYS = ('boot', 'stock_hashes', 'stock_actors', 'station',
    'station_state_sha', 'station_frequency', 'interfaces', 'ipv4',
    'ipv6_addresses', 'ipv6_routes', 'station_completed')
_TERMINAL_ADDRESS_KEYS = ('ifindex', 'local', 'address', 'prefixlen', 'flags',
    'scope', 'label_hex', 'broadcast', 'cacheinfo')
_TERMINAL_ROUTE_KEYS = ('network', 'prefixlen', 'table', 'protocol', 'scope',
    'kind', 'flags', 'oif', 'gateway', 'priority', 'prefsrc', 'metrics')
_TERMINAL_STATES = frozenset(('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I', 'P'))


def _terminal_fixed():
    _fixed()
    if any(a is not b for a, b in zip(
            (snapshots._full, snapshots._stable_key, snapshots._pack,
             snapshots._canonical, snapshots.decode_snapshot),
            _TERMINAL_SNAPSHOT_FUNCTIONS)):
        _fail('terminal_definition_changed')


def _terminal_object(value, keys):
    if (type(value) is not dict or any(type(key) is not str for key in value) or
            set(value) != set(keys)):
        _fail('terminal_object')
    return value


def _terminal_sequence(value, width=None, minimum=0, maximum=4096):
    if (type(value) not in (list, tuple) or not minimum <= len(value) <= maximum or
            width is not None and len(value) != width):
        _fail('terminal_sequence')
    return value


def _terminal_int(value, minimum=0, maximum=(1 << 64) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail('terminal_integer')
    return value


def _terminal_number(value, positive=False):
    if (type(value) is not float or not math.isfinite(value) or
            not 0 <= value < 1e12 or positive and value <= 0):
        _fail('terminal_number')
    return value


def _terminal_hex(value, width):
    if type(value) is not str or re.fullmatch('[0-9a-f]{%d}' % width, value) is None:
        _fail('terminal_hex')
    return value


def _terminal_time_text(value):
    if type(value) is not str or not 1 <= len(value) <= 32:
        _fail('terminal_time_text')
    try: number = float(value)
    except ValueError: _fail('terminal_time_text')
    _terminal_number(number, True)
    if repr(number) != value: _fail('terminal_time_text')
    return number


def _terminal_primitive(value, depth=0, nodes=None):
    # Exact builtins only, BEFORE JSON encoding/freezing. No user method,
    # object hook, repr, iterable, mapping protocol or native record is used.
    if nodes is None: nodes = [0]
    nodes[0] += 1
    if depth > 24 or nodes[0] > 8192: _fail('terminal_structure_limit')
    if value is None or type(value) is bool: return
    if type(value) is int:
        _terminal_int(value); return
    if type(value) is float:
        _terminal_number(value); return
    if type(value) is str:
        if len(value) > 16384 or any(0xd800 <= ord(c) <= 0xdfff for c in value):
            _fail('terminal_text')
        return
    if type(value) in (list, tuple):
        if len(value) > 4096: _fail('terminal_structure_limit')
        for item in value: _terminal_primitive(item, depth + 1, nodes)
        return
    if type(value) is dict:
        if len(value) > 32 or any(type(k) is not str or not 1 <= len(k) <= 64 for k in value):
            _fail('terminal_object')
        for item in value.values(): _terminal_primitive(item, depth + 1, nodes)
        return
    _fail('terminal_primitive')


def _terminal_canonical(value, maximum, newline=True):
    _terminal_fixed()
    _terminal_primitive(value)
    try:
        raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) +
               ('\n' if newline else '')).encode('ascii')
    except (ValueError, TypeError, UnicodeError):
        _fail('terminal_json')
    if not 1 <= len(raw) <= maximum: _fail('terminal_ascii_limit')
    return raw


def _terminal_json(raw, maximum, newline=True):
    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        _fail('terminal_ascii_limit')
    _terminal_fixed()
    try: value = json.loads(raw.decode('ascii'))
    except (ValueError, UnicodeError): _fail('terminal_json')
    if _terminal_canonical(value, maximum, newline) != raw:
        _fail('terminal_noncanonical')
    return value


def _terminal_pairs(value, keys):
    _terminal_primitive(value)
    if type(value) is not tuple or len(value) != len(keys):
        _fail('terminal_pairs')
    for row in value:
        if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str:
            _fail('terminal_pairs')
    result = dict(value)
    if (set(result) != set(keys) or
            tuple((key, result[key]) for key in sorted(keys)) != value):
        _fail('terminal_pairs')
    return result


def _terminal_launch(value):
    _terminal_object(value, _TERMINAL_LAUNCH_KEYS)
    for key in ('run', 'task', 'nonce'): _terminal_hex(value[key], 32)
    for key in ('manifest', 'candidate_sha'): _terminal_hex(value[key], 64)
    for key in ('native_epoch', 'operation_epoch'): _terminal_int(value[key], 1, (1 << 53) - 1)
    if value['native_epoch'] != value['operation_epoch']: _fail('terminal_epoch')
    _terminal_time_text(value['until'])
    _terminal_int(value['child_pid'], 1, 0x7fffffff)
    return tuple((key, value[key]) for key in sorted(_TERMINAL_LAUNCH_KEYS))


def _terminal_limits(value, binding, launch):
    _terminal_object(value, _TERMINAL_LIMIT_KEYS)
    for item in value.values(): _terminal_number(item, True)
    task, service = value['task_until'], value['service_until']
    go, service_cleanup = value['go_cleanup_until'], value['service_cleanup_until']
    if (task != _terminal_time_text(launch['until']) or task > service or
            go > task + 60.0 or service_cleanup != service + 60.0 or
            binding['until'] > min(go, service_cleanup) or
            binding['cleanup_until'] > min(go, service_cleanup)):
        _fail('terminal_cleanup_limits')
    if (binding['nonce'] == launch['nonce'] or binding['task_id'] != launch['task'] or
            binding['native_epoch'] != launch['native_epoch'] or
            binding['operation_epoch'] != launch['operation_epoch']):
        _fail('terminal_ownership')
    return tuple((key, value[key]) for key in sorted(_TERMINAL_LIMIT_KEYS))


def _terminal_metadata(value, size):
    _terminal_sequence(value, 9)
    for item in value: _terminal_int(item)
    if tuple(value[2:7]) != (0o100600, 0, 0, 1, size):
        _fail('terminal_metadata')
    return tuple(value)


def _terminal_actor(value, fixed_python=False):
    _terminal_object(value, _TERMINAL_ACTOR_KEYS)
    pid = _terminal_int(value['pid'], 1, 0x7fffffff)
    start = _terminal_int(value['start'], 1)
    exe = value['exe']
    if (type(exe) is not str or not 1 <= len(exe) <= 256 or not exe.startswith('/') or
            any(p in ('', '.', '..') for p in exe[1:].split('/')) or
            any(ord(c) < 32 or 0xd800 <= ord(c) <= 0xdfff for c in exe) or
            fixed_python and exe != '/usr/bin/python3.5'):
        _fail('terminal_actor_exe')
    _sha(value['argv_sha'])
    tasks = _terminal_sequence(value['tasks'], minimum=1, maximum=128)
    current, prior, leader = [], 0, False
    for task in tasks:
        _terminal_sequence(task, 3)
        tid = _terminal_int(task[0], 1, 0x7fffffff)
        begun = _terminal_int(task[1], 1)
        if type(task[2]) is not str or task[2] not in _TERMINAL_STATES or tid <= prior:
            _fail('terminal_actor_tasks')
        leader = leader or (tid == pid and begun == start)
        prior = tid
        current.append(tuple(task))
    if not leader: _fail('terminal_actor_leader')
    return (pid, start, exe, value['argv_sha'], tuple(current))


def _terminal_finish(raw, launch):
    if (type(raw) is not bytes or not 1 <= len(raw) <= TERMINAL_MAX_FINISH or
            not raw.startswith(b'GOFINISH84=')):
        _fail('terminal_finish_ascii')
    value = _terminal_json(raw[len(b'GOFINISH84='):], TERMINAL_MAX_FINISH)
    _terminal_object(value, _TERMINAL_FINISH_KEYS)
    if value['schema'] != 'p011-go-finish-data-v93' or value['provenance'] != 'returned_restore':
        _fail('terminal_finish_schema')
    keys = _TERMINAL_LAUNCH_KEYS - {'candidate_sha', 'child_pid'}
    binding = _terminal_object(value['binding'], keys)
    if any(type(binding[k]) is not type(launch[k]) or binding[k] != launch[k] for k in keys):
        _fail('terminal_finish_binding')
    actor = _terminal_actor(value['f_actor_data'], True)
    triple = _terminal_sequence(value['f_actor'], 3)
    _terminal_int(triple[0], 1, 0x7fffffff); _terminal_int(triple[1], 1); _sha(triple[2])
    if tuple(triple) != (actor[0], actor[1], actor[3]) or actor[0] != launch['child_pid']:
        _fail('terminal_finish_actor')
    _terminal_number(value['cleanup_until'], True); _terminal_number(value['finished_at'])
    if value['finished_at'] >= value['cleanup_until']: _fail('terminal_finish_period')
    _terminal_metadata(value['device_lock_metadata'], 0)
    journal = _terminal_object(value['journal'], ('schema', 'phase', 'generation',
        'sha256', 'bytes', 'metadata', 'facts_key'))
    if journal['schema'] != 'p011-go-typed-live-v72' or journal['phase'] != 'reconciled':
        _fail('terminal_finish_journal')
    _terminal_int(journal['generation'], 1, 25); _sha(journal['sha256'])
    _terminal_int(journal['bytes'], 1, TERMINAL_MAX_PAYLOAD)
    _terminal_metadata(journal['metadata'], journal['bytes'])
    facts = _terminal_sequence(journal['facts_key'], 7)
    if (facts[0] != journal['schema'] or facts[1] != launch['run'] or
            facts[2] != launch['candidate_sha'] or facts[3] != launch['task']):
        _fail('terminal_finish_facts')
    if type(facts[4]) is not str or re.fullmatch(
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', facts[4]) is None:
        _fail('terminal_boot')
    _terminal_number(facts[5]); _terminal_number(facts[6], True)
    if facts[6] != _terminal_time_text(launch['until']) or not 0 < facts[6] - facts[5] <= 300.0:
        _fail('terminal_finish_facts')
    children = _terminal_sequence(value['children'], maximum=2)
    outcomes = _terminal_sequence(value['children_outcomes'], len(children))
    roles = []
    for child, outcome in zip(children, outcomes):
        _terminal_sequence(child, 3)
        if type(child[0]) is not str or child[0] not in ('controller', 'watchdog') or child[0] in roles:
            _fail('terminal_child_role')
        roles.append(child[0])
        if (child[1] is None) is not (child[2] is None): _fail('terminal_child_actor')
        if child[1] is not None:
            _terminal_int(child[1], 1, 0x7fffffff); _terminal_int(child[2], 1)
        _terminal_object(outcome, ('role', 'fork_requested', 'fork_negative',
            'waited', 'exit_verified', 'actor_present'))
        if outcome['role'] != child[0] or any(type(outcome[k]) is not bool
                for k in ('fork_requested', 'fork_negative', 'waited', 'exit_verified', 'actor_present')):
            _fail('terminal_child_outcome')
        requested, negative = outcome['fork_requested'], outcome['fork_negative']
        if (outcome['actor_present'] is not (child[1] is not None) or
                negative and not requested or
                (not requested or negative) and (child[1] is not None or outcome['waited'] or outcome['exit_verified']) or
                requested and not negative and (child[1] is None or
                    outcome['waited'] is not True or outcome['exit_verified'] is not True)):
            _fail('terminal_child_outcome')
    counts = _terminal_sequence(value['inventory_counts'], 2)
    _terminal_int(counts[0], 8, 256); _terminal_int(counts[1], 0, 8192)
    if type(value['business_failed_at_capture']) is not bool or any(value[k] is not False
            for k in ('native_full_inventory_export', 'independent_restore_verified', 'production_admitted')):
        _fail('terminal_finish_claim')
    return value, actor


def _terminal_request_fields(binding, launch, finish_raw, limits):
    for value in (binding, launch, limits): _terminal_primitive(value)
    _binding(binding); _terminal_launch(launch)
    limit_rows = _terminal_limits(limits, binding, launch)
    finish, actor = _terminal_finish(finish_raw, launch)
    # The F's first restore cap and the Parent's later first GO cleanup cap
    # are distinct original DATA. Neither is reconstructed from the other.
    if binding['cleanup_until'] > min(limits['go_cleanup_until'],
            limits['service_cleanup_until'], finish['cleanup_until']):
        _fail('terminal_cleanup_limits')
    return (_binding(binding), _terminal_launch(launch), limit_rows, finish, actor)


def _terminal_freeze(value):
    # Only already validated exact primitive DATA is frozen, never a record.
    if type(value) is dict:
        return tuple((key, _terminal_freeze(value[key])) for key in sorted(value))
    if type(value) in (list, tuple): return tuple(_terminal_freeze(item) for item in value)
    return value


class TerminalRequestData(object):
    """Immutable private request DATA, not a deadline grant or authorization."""
    __slots__ = ('binding', 'launch_binding', 'cleanup_limits', 'finish_data',
        'finish_sha256', 'request_sha256', '_finish_raw', '_request_raw')

    def __init__(self, fields, finish_raw, request_raw, _issuer=None):
        if _issuer is not _TERMINAL_ISSUER: _fail('terminal_data_constructor')
        binding, launch, limits, finish, unused_actor = fields
        for key, value in (('binding', binding), ('launch_binding', launch),
                ('cleanup_limits', limits), ('finish_data', _terminal_freeze(finish)),
                ('finish_sha256', hashlib.sha256(finish_raw).hexdigest()),
                ('request_sha256', hashlib.sha256(request_raw).hexdigest()),
                ('_finish_raw', finish_raw), ('_request_raw', request_raw)):
            object.__setattr__(self, key, value)

    def __setattr__(self, *unused): raise AttributeError('immutable terminal request DATA')
    def __delattr__(self, *unused): raise AttributeError('immutable terminal request DATA')
    def __repr__(self): return '<private terminal request DATA; no authority>'
    __str__ = __repr__

    def private_finish_ascii(self): return self._finish_raw
    def private_request_ascii(self): return self._request_raw


def encode_terminal_request(binding, launch_binding, finish_raw, cleanup_limits):
    """Canonical request DATA only; no issuance or clock interpretation."""
    _terminal_fixed()
    _terminal_request_fields(binding, launch_binding, finish_raw, cleanup_limits)
    return _terminal_canonical(dict(schema=TERMINAL_REQUEST_SCHEMA, binding=binding,
        launch_binding=launch_binding, finish_ascii=finish_raw.decode('ascii'),
        cleanup_limits=cleanup_limits), TERMINAL_MAX_REQUEST)


def decode_terminal_request(raw):
    value = _terminal_json(raw, TERMINAL_MAX_REQUEST)
    _terminal_object(value, ('schema', 'binding', 'launch_binding', 'finish_ascii', 'cleanup_limits'))
    if value['schema'] != TERMINAL_REQUEST_SCHEMA or type(value['finish_ascii']) is not str:
        _fail('terminal_request_schema')
    try: finish = value['finish_ascii'].encode('ascii')
    except UnicodeError: _fail('terminal_finish_ascii')
    fields = _terminal_request_fields(value['binding'], value['launch_binding'], finish, value['cleanup_limits'])
    return TerminalRequestData(fields, finish, raw, _TERMINAL_ISSUER)


def _terminal_origin(value):
    _terminal_object(value, _TERMINAL_ORIGIN_KEYS)
    return tuple(value[key] for key in _TERMINAL_ORIGIN_KEYS)


def _terminal_snapshot_tree(value):
    # Convert the Journal's EXPLICIT eleven-field primitive layout to the
    # existing pure Snapshot DATA validator. Never call Core/IP constructors.
    _terminal_object(value, _TERMINAL_SNAPSHOT_KEYS)
    hashes = []
    for row in _terminal_sequence(value['stock_hashes'], minimum=1, maximum=16):
        _terminal_object(row, ('path', 'sha256'))
        hashes.append((row['path'], row['sha256']))
    actors = tuple(_terminal_actor(row) for row in
        _terminal_sequence(value['stock_actors'], minimum=1, maximum=32))
    origins = tuple(_terminal_origin(row) for row in
        _terminal_sequence(value['interfaces'], minimum=1, maximum=32))
    v4 = _terminal_object(value['ipv4'], ('addresses', 'routes', 'rules'))
    addresses, routes, rules = [], [], []
    for row in _terminal_sequence(v4['addresses']):
        _terminal_object(row, _TERMINAL_ADDRESS_KEYS)
        label = row['label_hex']
        if label is not None:
            if (type(label) is not str or not 4 <= len(label) <= 32 or len(label) % 2 or
                    re.fullmatch('[0-9a-f]+', label) is None): _fail('terminal_label')
            label = bytes.fromhex(label)
        addresses.append(tuple(row[k] for k in _TERMINAL_ADDRESS_KEYS[:6]) +
            (label, row['broadcast'], tuple(_terminal_sequence(row['cacheinfo'], 4))))
    for row in _terminal_sequence(v4['routes']):
        _terminal_object(row, _TERMINAL_ROUTE_KEYS)
        metrics = tuple(tuple(_terminal_sequence(pair, 2)) for pair in
                        _terminal_sequence(row['metrics'], maximum=15))
        routes.append(tuple(row[k] for k in _TERMINAL_ROUTE_KEYS[:-1]) + (metrics,))
    for row in _terminal_sequence(v4['rules']):
        _terminal_object(row, ('priority', 'table')); rules.append((row['priority'], row['table']))
    v6a = tuple(tuple(_terminal_sequence(row, 6)) for row in _terminal_sequence(value['ipv6_addresses']))
    v6r = tuple(tuple(_terminal_sequence(row, 10)) for row in _terminal_sequence(value['ipv6_routes']))
    fields = (value['boot'], tuple(hashes), actors, _terminal_origin(value['station']),
        value['station_state_sha'], value['station_frequency'], origins,
        (tuple(addresses), tuple(routes), tuple(rules)), v6a, v6r, value['station_completed'])
    _terminal_fixed()
    _TERMINAL_SNAPSHOT_FUNCTIONS[0](fields)
    return fields, _TERMINAL_SNAPSHOT_FUNCTIONS[1](fields)


def _terminal_journal(raw, launch, finish, snapshot):
    value = _terminal_json(raw, TERMINAL_MAX_PAYLOAD, False)
    _terminal_object(value, _TERMINAL_JOURNAL_KEYS)
    summary = finish['journal']
    if (len(raw) != summary['bytes'] or hashlib.sha256(raw).hexdigest() != summary['sha256'] or
            value['phase'] != 'reconciled' or type(value['generation']) is not int or
            value['generation'] != summary['generation'] or
            type(value['cleanup_until']) is not float or value['cleanup_until'] != finish['cleanup_until']):
        _fail('terminal_journal_facts')
    facts = [value[k] for k in ('schema', 'run_token', 'candidate_sha', 'task_id', 'boot_id', 'issued_at', 'until')]
    if facts != summary['facts_key'] or any(type(a) is not type(b) for a, b in zip(facts, summary['facts_key'])):
        _fail('terminal_journal_facts')
    before, before_key = _terminal_snapshot_tree(value['baseline'])
    after, after_key = _terminal_snapshot_tree(value['restored'])
    if (before[0] != facts[4] or after[0] != facts[4] or
            before_key != after_key or before_key != snapshot.stable_key):
        _fail('terminal_journal_snapshot')
    # Retain the complete outer twenty fields. This is not GO record decode,
    # not a reconstructed durable canonical or kernel/restoration authority.
    if value['ip'] is not None:
        item = _terminal_object(value['ip'], ('phase', 'origin', 'spec', 'request', 'address'))
        if item['phase'] != 'restored': _fail('terminal_journal_ip')
    if value['dhcp'] is not None:
        item = _terminal_object(value['dhcp'], ('phase', 'origin', 'server_ip', 'client_ip', 'prefix', 'until'))
        if (item['phase'] != 'closed' or type(item['until']) is not float or item['until'] != facts[6]):
            _fail('terminal_journal_dhcp')
    children = dict((row[0], (row, outcome)) for row, outcome in
                    zip(finish['children'], finish['children_outcomes']))
    expected = [('f', _terminal_actor(finish['f_actor_data'], True))]
    for role in ('controller', 'watchdog'):
        child = value[role]
        if child is not None:
            _terminal_object(child, ('phase', 'spec_sha', 'argv_sha', 'until', 'actor'))
            if type(child['phase']) is not str or child['phase'] not in ('intent', 'preexec', 'live'):
                _fail('terminal_journal_child')
            _sha(child['spec_sha']); _sha(child['argv_sha']); _terminal_number(child['until'], True)
            if child['until'] != facts[6] or (child['phase'] == 'intent') is not (child['actor'] is None):
                _fail('terminal_journal_child')
        pair = children.get(role)
        if pair is None:
            if child is not None: _fail('terminal_child_outcome_missing')
            continue
        row, outcome = pair
        if not outcome['fork_requested'] or outcome['fork_negative']:
            if child is not None and child['actor'] is not None: _fail('terminal_child_negative_conflict')
            continue
        if child is None or child['actor'] is None: _fail('terminal_child_actor_unavailable')
        actor = _terminal_actor(child['actor'])
        if (actor[:2] != tuple(row[1:]) or child['phase'] == 'live' and actor[3] != child['argv_sha']):
            _fail('terminal_child_actor_mismatch')
        expected.append((role, actor))
    if len(set(actor[0] for role, actor in expected)) != len(expected):
        _fail('terminal_actor_duplicate')
    return value, tuple(expected)


def _terminal_response(value, snapshot_raw, journal_raw):
    _terminal_primitive(value)
    _terminal_object(value, _TERMINAL_HEADER_KEYS)
    if value['schema'] != TERMINAL_PACKET_SCHEMA or any(value[k] is not False for k in _TERMINAL_FALSE_KEYS):
        _fail('terminal_response_schema')
    binding = _binding(value['binding'])
    launch = _terminal_launch(value['launch_binding'])
    limits = _terminal_limits(value['cleanup_limits'], value['binding'], value['launch_binding'])
    if type(value['finish_ascii']) is not str: _fail('terminal_finish_ascii')
    try: finish_raw = value['finish_ascii'].encode('ascii')
    except UnicodeError: _fail('terminal_finish_ascii')
    unused_binding, unused_launch, unused_limits, finish, unused_actor = _terminal_request_fields(
        value['binding'], value['launch_binding'], finish_raw, value['cleanup_limits'])
    if hashlib.sha256(finish_raw).hexdigest() != _sha(value['finish_sha256']):
        _fail('terminal_finish_changed')
    if (value['source_manifest_sha256'] != SOURCE_MANIFEST_SHA or
            type(value['source_count']) is not int or value['source_count'] != SOURCE_COUNT or
            type(value['snapshot_round_count']) is not int or value['snapshot_round_count'] != 2 or
            type(value['active_until']) is not float or value['active_until'] != value['binding']['until'] or
            type(value['cleanup_until']) is not float or value['cleanup_until'] != value['binding']['cleanup_until']):
        _fail('terminal_response_binding')
    for raw, length_key, sha_key in ((snapshot_raw, 'snapshot_bytes', 'snapshot_sha256'),
                                    (journal_raw, 'journal_bytes', 'journal_sha256')):
        if (type(raw) is not bytes or not 1 <= len(raw) <= TERMINAL_MAX_PAYLOAD or
                type(value[length_key]) is not int or value[length_key] != len(raw) or
                _sha(value[sha_key]) != hashlib.sha256(raw).hexdigest()):
            _fail('terminal_payload_changed')
    _terminal_fixed()
    snapshot = _SNAPSHOT_DECODE(snapshot_raw)
    if snapshot.key_sha != _sha(value['stable_key_sha256']): _fail('terminal_snapshot_key')
    metadata = _terminal_metadata(value['journal_metadata'], len(journal_raw))
    if metadata != tuple(finish['journal']['metadata']): _fail('terminal_journal_metadata')
    device_lock = _terminal_metadata(value['device_lock_metadata'], 0)
    if device_lock != tuple(finish['device_lock_metadata']): _fail('terminal_device_lock')
    journal_lock = _terminal_metadata(value['journal_lock_metadata'], 0)
    journal, expected = _terminal_journal(journal_raw, value['launch_binding'], finish, snapshot)
    absence = _terminal_sequence(value['absence_facts'], len(expected))
    rows = []
    for row, pair in zip(absence, expected):
        _terminal_sequence(row, 6)
        role, actor = pair
        if (type(row[0]) is not str or row[0] != role or
                type(row[1]) is not int or type(row[2]) is not int or tuple(row[1:3]) != actor[:2] or
                type(row[3]) is not int or row[3] != 2):
            _fail('terminal_absence_actor')
        _terminal_int(row[4], 0, 280); _terminal_int(row[5], 0, 280)
        if row[4] != row[5]: _fail('terminal_absence_files')
        rows.append(tuple(row))
    return (binding, launch, limits, finish_raw, finish, journal, snapshot,
            metadata, device_lock, journal_lock, tuple(rows))


class TerminalPacketData(object):
    """Immutable terminal DATA. All restoration/admission permission stays False."""
    __slots__ = ('binding', 'launch_binding', 'cleanup_limits', 'finish_data',
        'journal_data', 'snapshot', 'absence_facts', 'journal_metadata',
        'device_lock_metadata', 'journal_lock_metadata', 'source_manifest_sha256',
        'source_count', 'active_until', 'cleanup_until', 'snapshot_round_count',
        'finish_sha256', 'journal_sha256', 'stable_key_sha256', 'packet_sha256',
        'rf_requested', 'native_restore_verified', 'restoration_verified',
        'independent_restore_verified', 'production_admitted',
        '_header_raw', '_snapshot_raw', '_journal_raw', '_finish_raw')

    def __init__(self, fields, header, packet, header_raw, snapshot_raw, journal_raw, _issuer=None):
        if _issuer is not _TERMINAL_ISSUER: _fail('terminal_data_constructor')
        binding, launch, limits, finish_raw, finish, journal, snapshot, meta, device, lock, absence = fields
        values = dict(binding=binding, launch_binding=launch, cleanup_limits=limits,
            finish_data=_terminal_freeze(finish), journal_data=_terminal_freeze(journal),
            snapshot=snapshot, absence_facts=absence, journal_metadata=meta,
            device_lock_metadata=device, journal_lock_metadata=lock,
            source_manifest_sha256=SOURCE_MANIFEST_SHA, source_count=SOURCE_COUNT,
            active_until=header['active_until'], cleanup_until=header['cleanup_until'],
            snapshot_round_count=2, finish_sha256=header['finish_sha256'],
            journal_sha256=header['journal_sha256'], stable_key_sha256=header['stable_key_sha256'],
            packet_sha256=hashlib.sha256(packet).hexdigest(), _header_raw=header_raw,
            _snapshot_raw=snapshot_raw, _journal_raw=journal_raw, _finish_raw=finish_raw)
        for key in _TERMINAL_FALSE_KEYS: values[key] = False
        for key, value in values.items(): object.__setattr__(self, key, value)

    def __setattr__(self, *unused): raise AttributeError('immutable terminal packet DATA')
    def __delattr__(self, *unused): raise AttributeError('immutable terminal packet DATA')
    def __repr__(self): return '<private terminal packet DATA; no sampling, EOF, restore or admission>'
    __str__ = __repr__

    def private_header_ascii(self): return self._header_raw
    def private_snapshot_ascii(self): return self._snapshot_raw
    def private_journal_ascii(self): return self._journal_raw
    def private_finish_ascii(self): return self._finish_raw


def encode_terminal_result(value):
    """Body94 complete private result -> independent bounded terminal packet."""
    _terminal_fixed()
    _terminal_object(value, _TERMINAL_RESULT_KEYS)
    if type(value['schema']) is not str or value['schema'] != TERMINAL_DATA_SCHEMA:
        _fail('terminal_result_schema')
    binding = _terminal_pairs(value['binding'], _BIND_KEYS)
    launch = _terminal_pairs(value['launch_binding'], _TERMINAL_LAUNCH_KEYS)
    limits = _terminal_pairs(value['cleanup_limits'], _TERMINAL_LIMIT_KEYS)
    snapshot_raw, journal_raw, finish_raw = value['snapshot_raw'], value['journal_raw'], value['finish_raw']
    if (type(snapshot_raw) is not bytes or not 1 <= len(snapshot_raw) <= TERMINAL_MAX_PAYLOAD or
            type(journal_raw) is not bytes or not 1 <= len(journal_raw) <= TERMINAL_MAX_PAYLOAD or
            type(finish_raw) is not bytes or not 1 <= len(finish_raw) <= TERMINAL_MAX_FINISH):
        _fail('terminal_payload_limit')
    try: finish_ascii = finish_raw.decode('ascii')
    except UnicodeError: _fail('terminal_finish_ascii')
    header = dict((key, value[key]) for key in _TERMINAL_RESULT_KEYS -
                  {'schema', 'binding', 'launch_binding', 'cleanup_limits', 'finish_raw', 'journal_raw', 'snapshot_raw'})
    header.update(schema=TERMINAL_PACKET_SCHEMA, binding=binding, launch_binding=launch,
        cleanup_limits=limits, finish_ascii=finish_ascii, snapshot_bytes=len(snapshot_raw),
        snapshot_sha256=hashlib.sha256(snapshot_raw).hexdigest(), journal_bytes=len(journal_raw))
    _terminal_response(header, snapshot_raw, journal_raw)
    header_raw = _terminal_canonical(header, TERMINAL_MAX_HEADER)
    result = TERMINAL_MAGIC + struct.pack('!III', len(header_raw), len(snapshot_raw), len(journal_raw)) + header_raw + snapshot_raw + journal_raw
    if len(result) > TERMINAL_MAX_PACKET: _fail('terminal_total_limit')
    return result


def decode_terminal_packet(raw):
    _terminal_fixed()
    if (type(raw) is not bytes or not TERMINAL_PREFIX_BYTES < len(raw) <= TERMINAL_MAX_PACKET or
            raw[:len(TERMINAL_MAGIC)] != TERMINAL_MAGIC):
        _fail('terminal_prefix')
    hsize, ssize, jsize = struct.unpack('!III', raw[len(TERMINAL_MAGIC):TERMINAL_PREFIX_BYTES])
    if (not 1 <= hsize <= TERMINAL_MAX_HEADER or not 1 <= ssize <= TERMINAL_MAX_PAYLOAD or
            not 1 <= jsize <= TERMINAL_MAX_PAYLOAD or
            TERMINAL_PREFIX_BYTES + hsize + ssize + jsize != len(raw)):
        _fail('terminal_lengths')
    hend, send = TERMINAL_PREFIX_BYTES + hsize, TERMINAL_PREFIX_BYTES + hsize + ssize
    header_raw, snapshot_raw, journal_raw = raw[TERMINAL_PREFIX_BYTES:hend], raw[hend:send], raw[send:]
    header = _terminal_json(header_raw, TERMINAL_MAX_HEADER)
    fields = _terminal_response(header, snapshot_raw, journal_raw)
    return TerminalPacketData(fields, header, raw, header_raw, snapshot_raw, journal_raw, _TERMINAL_ISSUER)


class TerminalPacketReader(object):
    """Bounded primitive reader; finish validates bytes, NEVER actual pipe EOF."""
    def __init__(self):
        self.parts, self.size, self.expected = [], 0, None
        self.ended, self.failure, self.value = False, None, None

    def feed(self, raw):
        if self.ended or self.failure is not None: _fail('terminal_reader_ended')
        try:
            if (type(raw) is not bytes or not 1 <= len(raw) <= 65536 or
                    len(self.parts) >= MAX_CHUNKS or self.size + len(raw) > TERMINAL_MAX_PACKET):
                _fail('terminal_reader_budget')
            self.parts.append(raw); self.size += len(raw)
            if self.expected is None and self.size >= TERMINAL_PREFIX_BYTES:
                prefix = b''.join(self.parts)[:TERMINAL_PREFIX_BYTES]
                if prefix[:len(TERMINAL_MAGIC)] != TERMINAL_MAGIC: _fail('terminal_prefix')
                hsize, ssize, jsize = struct.unpack('!III', prefix[len(TERMINAL_MAGIC):])
                if (not 1 <= hsize <= TERMINAL_MAX_HEADER or
                        not 1 <= ssize <= TERMINAL_MAX_PAYLOAD or not 1 <= jsize <= TERMINAL_MAX_PAYLOAD):
                    _fail('terminal_lengths')
                self.expected = TERMINAL_PREFIX_BYTES + hsize + ssize + jsize
                if self.expected > TERMINAL_MAX_PACKET: _fail('terminal_total_limit')
            if self.expected is not None and self.size > self.expected: _fail('terminal_trailing_data')
        except BaseException as error:
            self.failure = error
            raise
        return None

    def finish(self):
        if self.ended or self.failure is not None: _fail('terminal_reader_ended')
        self.ended = True
        try:
            if self.expected is None or self.size != self.expected: _fail('terminal_incomplete')
            self.value = decode_terminal_packet(b''.join(self.parts))
        except BaseException as error:
            self.failure = error
            raise
        return self.value
