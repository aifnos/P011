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
