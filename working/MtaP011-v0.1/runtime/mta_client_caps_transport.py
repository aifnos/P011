"""One-shot, read-only Linux v4.14 nl80211 split capability transport.

No socket at import/construction, RF command, thread, retry or mutation proof.
DecodedCaps is a declaration, not permission to create/associate an interface.
Raw responses and unassessed attributes are private evidence, not public logs.
Linux UAPI numbers are interface definitions; implementation is independent.
"""

import math
import socket
import struct
import sys
import threading
import time
from collections import namedtuple

import mta_client_caps as caps


AF_NETLINK, NETLINK_GENERIC, GENL_CTRL = 16, 16, 16
CTRL_GETFAMILY, CTRL_NEWFAMILY, CTRL_VERSION = 3, 1, 2
GET_WIPHY, NEW_WIPHY, GET_PROTOCOL_FEATURES = 1, 3, 95
PROTOCOL_FEATURES, SPLIT_WIPHY_DUMP = 173, 174
NL_VERSION, SPLIT_FEATURE = 1, 1
NL_ERROR, NL_DONE, NL_OVERRUN = 2, 3, 4
REQUEST, MULTI, DUMP_INTR, DUMP = 1, 2, 16, 0x300
MSG_TRUNC, MSG_CTRUNC = 32, 8
MAX_DATAGRAM, MAX_RAW_BYTES, MAX_DATAGRAMS = 65536, 1048576, 128
MAX_MESSAGES, MAX_TOP_ATTRIBUTES = 256, 4096
_NL, _GENL, _ATTR = struct.Struct('<IHHII'), struct.Struct('<BBH'), struct.Struct('<HH')
_U32, _U16, _I32 = struct.Struct('<I'), struct.Struct('<H'), struct.Struct('<i')
_PROJECT = frozenset((1, 32, 50, 120, 121))
# Explicit send_wiphy policy, not a numeric range. Known unassessed fields
# remain exact raw. Their acceptance does NOT evaluate bands/roles/regulation.
_U8_TOP = frozenset((43, 61, 62, 86, 89, 123, 133, 206))
_U16_TOP = frozenset((56, 124))
_U32_TOP = frozenset((1, 46, 63, 64, 105, 106, 111, 113, 114, 141,
                      143, 144, 167, 202, 222, 223, 224, 239, 256))
_FLAG_TOP = frozenset((102, 104, 108, 115, 130, 131, 139, 140, 192, 193, 216))
_NESTED_TOP = frozenset((22, 32, 50, 99, 100, 118, 120, 121, 182,
                         197, 198, 227, 230))
_BINARY_TOP = frozenset((57, 148, 169, 170, 176, 217))
_KNOWN_TOP = _U8_TOP | _U16_TOP | _U32_TOP | _FLAG_TOP | _NESTED_TOP | _BINARY_TOP | {2}
_REPEATED_TOP = frozenset((1, 2, 46, 22, 230))
RawDatagram = namedtuple('RawDatagram', 'sequence data ancillary flags peer')
UnassessedAttribute = namedtuple('UnassessedAttribute', 'fragment kind flags encoded')


class CapsTransportError(ValueError):
    def __init__(self, code, errno_value=0):
        self.code = code
        self.errno = (errno_value if type(errno_value) is int and
                      0 <= errno_value <= 4095 else 0)
        ValueError.__init__(self, code)


def _fail(code):
    raise CapsTransportError(code)


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _attr(kind, value):
    data = _ATTR.pack(4 + len(value), kind) + value
    return data + b'\0' * ((-len(data)) & 3)


def _attrs(data):
    at, rows = 0, []
    while at < len(data):
        if len(data) - at < 4:
            _fail('truncated_attribute')
        size, raw_kind = _ATTR.unpack_from(data, at)
        step = (size + 3) & ~3
        if size < 4 or step > len(data) - at:
            _fail('truncated_attribute')
        if any(data[at + size:at + step]):
            _fail('nonzero_attribute_padding')
        rows.append((raw_kind & 0x3fff, raw_kind & 0xc000,
                     data[at + 4:at + size], data[at:at + step]))
        if len(rows) > MAX_TOP_ATTRIBUTES:
            _fail('attribute_budget')
        at += step
    return tuple(rows)


def _nested(flags, data):
    if flags not in (0, 0x8000):
        _fail('attribute_flags')
    # Non-projected contents are structurally framed but NOT semantically
    # assessed. In v4.14 unflagged nested encoding is legitimate.
    for _, child_flags, _, _ in _attrs(data):
        if child_flags not in (0, 0x8000):
            _fail('attribute_flags')


def _scalar(flags, data, size):
    if flags != 0 or len(data) != size:
        _fail('scalar_format')


def _family(data):
    fields = {}
    for kind, flags, value, _ in _attrs(data):
        if kind not in range(1, 8) or kind in fields:
            _fail('family_attribute')
        fields[kind] = value
        if kind == 1:
            _scalar(flags, value, 2)
        elif kind == 2:
            if flags or value != b'nl80211\0':
                _fail('family_name')
        elif kind in (3, 4, 5):
            _scalar(flags, value, 4)
        else:
            _nested(flags, value)
            seen_ids, seen_values = set(), set()
            for index, child_flags, child, _ in _attrs(value):
                if not 1 <= index <= 256 or index in seen_ids:
                    _fail('family_nested_index')
                seen_ids.add(index)
                _nested(child_flags, child)
                parts = {}
                for subkind, subflags, subvalue, _ in _attrs(child):
                    if subkind not in (1, 2) or subkind in parts:
                        _fail('family_nested_attribute')
                    parts[subkind] = subvalue
                    if kind == 7 and subkind == 1:
                        if subflags or not 2 <= len(subvalue) <= 16 or \
                                subvalue[-1:] != b'\0' or b'\0' in subvalue[:-1]:
                            _fail('family_group_name')
                    else:
                        _scalar(subflags, subvalue, 4)
                if set(parts) != {1, 2}:
                    _fail('family_nested_attribute')
                if kind == 6 and (_U32.unpack(parts[1])[0] == 0 or
                                 _U32.unpack(parts[2])[0] & ~0x1f):
                    _fail('family_operation')
                if kind == 7 and _U32.unpack(parts[2])[0] == 0:
                    _fail('family_group_id')
                key = parts[1] if kind == 6 else parts[2]
                if key in seen_values:
                    _fail('family_nested_duplicate')
                seen_values.add(key)
    if not {1, 2, 3, 4, 5}.issubset(fields):
        _fail('family_missing_attribute')
    family = _U16.unpack(fields[1])[0]
    if not 19 <= family <= 1023 or _U32.unpack(fields[3])[0] != NL_VERSION or \
            _U32.unpack(fields[4])[0] != 0 or not 174 <= _U32.unpack(fields[5])[0] <= 4095:
        _fail('family_abi')
    return family


class ClientCapsReader(object):
    """One operation owns one socket. Constructor is pure.

    socket_factory/clock are trusted internal dependency injection, never UI
    inputs or byte-to-kernel proof. Linux production uses the actual socket.
    The outer owner must account for its calling thread; this starts none.
    A failed/unknown factory or failed close stays pending, with exact refs.
    """
    def __init__(self, phy, timeout=5.0, socket_factory=None, clock=None):
        if not _int(phy, 0, 0xffffffff):
            _fail('invalid_phy')
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 10 or \
                not math.isfinite(float(timeout)):
            _fail('invalid_timeout')
        if socket_factory is not None and not callable(socket_factory):
            _fail('invalid_factory')
        if clock is not None and not callable(clock):
            _fail('invalid_clock')
        self._phy, self._timeout = phy, float(timeout)
        self._factory, self._clock = socket_factory, clock or time.monotonic
        self._lock = threading.RLock()
        self._claimed = self._finished = self._created = False
        self._closed = self._unknown_factory = self._success = False
        self._socket = None  # strong exact reference retained even after close
        self._creator = None
        self._raw, self._wiphy_raw, self._extra = [], [], []
        self._requests, self._total, self._messages, self._top_count = [], 0, 0, 0
        self._last_error, self._port, self._family = 'not_started', None, None
        self._last_clock = None

    @property
    def raw_datagrams(self):
        return tuple(self._raw)

    @property
    def raw_wiphy_messages(self):
        return tuple(self._wiphy_raw)

    @property
    def unprojected_attributes(self):
        return tuple(self._extra)

    @property
    def raw_requests(self):
        return tuple(self._requests)

    def status(self):
        with self._lock:
            return {'attempted': self._claimed, 'finished': self._finished,
                    'read_success': self._success, 'socket_closed': self._closed,
                    'resource_pending': self._unknown_factory or
                        (self._created and not self._closed),
                    'has_unassessed_fields': bool(self._extra),
                    'datagram_count': len(self._raw), 'message_count': self._messages,
                    'unassessed_count': len(self._extra), 'reason': self._last_error}

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not -1e12 <= value <= 1e12 or \
                not math.isfinite(float(value)):
            _fail('invalid_clock_value')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock:
            _fail('clock_regressed')
        self._last_clock = value
        return value

    def _budget(self, raw, deadline):
        remaining = deadline - self._now()
        if remaining <= 0:
            _fail('deadline')
        raw.settimeout(remaining)
        # CPython 3.5 stores ROUND_CEILING integer nanoseconds, then
        # gettimeout() reconstructs seconds as sec + ns * 1e-9. Match that
        # exact API value, not the unquantized monotonic float difference.
        nanoseconds = math.ceil(remaining * 1000000000)
        seconds, fraction = divmod(nanoseconds, 1000000000)
        expected = seconds + fraction * 1e-9
        observed = raw.gettimeout()
        if type(observed) is not float or not math.isfinite(observed) or \
                observed <= 0 or observed != expected:
            _fail('timeout_readback')

    def _request(self, raw, family, command, version, attrs, seq, dump, deadline):
        request = (_NL.pack(20 + len(attrs), family, REQUEST | (DUMP if dump else 0),
                            seq, self._port) + _GENL.pack(command, version, 0) + attrs)
        self._requests.append(request)
        self._budget(raw, deadline)
        sent = raw.sendto(request, (0, 0))
        if type(sent) is not int or sent != len(request):
            _fail('short_send')
        rows, done = [], False
        while not done:
            self._budget(raw, deadline)
            packet, ancillary, flags, peer = raw.recvmsg(MAX_DATAGRAM + 1, 256, 0)
            if type(packet) is not bytes:
                _fail('invalid_receive')
            controls = tuple(ancillary) if type(ancillary) in (tuple, list) else ()
            self._raw.append(RawDatagram(seq, packet, controls, flags, peer))
            self._total += len(packet)
            if len(self._raw) > MAX_DATAGRAMS or self._total > MAX_RAW_BYTES or \
                    not 16 <= len(packet) <= MAX_DATAGRAM:
                _fail('receive_budget')
            if type(flags) is not int or flags & (MSG_TRUNC | MSG_CTRUNC):
                _fail('receive_truncated')
            if flags != 0 or type(ancillary) not in (tuple, list) or ancillary:
                _fail('receive_control')
            if self._now() >= deadline:
                _fail('deadline')
            if type(peer) is not tuple or len(peer) != 2 or \
                    not all(type(v) is int for v in peer) or peer != (0, 0):
                _fail('not_kernel_peer')
            at = 0
            while at < len(packet):
                if done:
                    _fail('message_after_terminal')
                if len(packet) - at < 16:
                    _fail('truncated_message')
                size, kind, bits, q, port = _NL.unpack_from(packet, at)
                step = (size + 3) & ~3
                if size < 16 or step > len(packet) - at or any(packet[at + size:at + step]):
                    _fail('truncated_message')
                self._messages += 1
                if self._messages > MAX_MESSAGES:
                    _fail('message_budget')
                if q != seq or port != self._port:
                    _fail('message_identity')
                if bits & DUMP_INTR:
                    _fail('dump_interrupted')
                if bits != (MULTI if dump else 0):
                    _fail('message_flags')
                body = packet[at + 16:at + size]
                encoded = packet[at:at + step]
                at += step
                if kind == NL_ERROR:
                    _fail('netlink_error')  # including success ACK, never DONE
                if kind == NL_OVERRUN:
                    _fail('netlink_overrun')
                if kind == NL_DONE:
                    if not dump or len(body) != 4 or _I32.unpack(body)[0] != 0 or not rows:
                        _fail('invalid_done')
                    done = True
                    continue
                if kind != family or len(body) < 4:
                    _fail('wrong_family')
                expected = NEW_WIPHY if dump else (CTRL_NEWFAMILY if family == GENL_CTRL else command)
                cmd, actual_version, reserved = _GENL.unpack_from(body)
                if cmd != expected or actual_version != version or reserved != 0:
                    _fail('generic_header')
                rows.append(body[4:])
                if dump:
                    self._wiphy_raw.append(encoded)
                    if len(self._wiphy_raw) > caps.MAX_FRAGMENTS:
                        _fail('fragment_budget')
                else:
                    done = True
        return tuple(rows)

    def _projection(self, fragments):
        result, seen, identity = [], set(), None
        for index, fragment in enumerate(fragments):
            fields, projected = {}, []
            for kind, flags, value, encoded in _attrs(fragment):
                self._top_count += 1
                if self._top_count > MAX_TOP_ATTRIBUTES:
                    _fail('attribute_budget')
                if kind not in _KNOWN_TOP:
                    _fail('unreviewed_top_attribute')
                if kind in fields or (kind in seen and kind not in _REPEATED_TOP):
                    _fail('duplicate_top_attribute')
                fields[kind] = value
                seen.add(kind)
                if kind in _NESTED_TOP:
                    _nested(flags, value)
                elif kind == 2:
                    if flags or not 2 <= len(value) <= 64 or value[-1:] != b'\0' or b'\0' in value[:-1]:
                        _fail('wiphy_name_format')
                elif kind in _FLAG_TOP:
                    _scalar(flags, value, 0)
                elif kind in _BINARY_TOP:
                    if flags or (kind == 57 and len(value) % 4) or \
                            (kind == 148 and len(value) != 26) or \
                            (kind == 176 and len(value) != 12) or len(value) > 4096:
                        _fail('binary_format')
                else:
                    _scalar(flags, value, 1 if kind in _U8_TOP else 2 if kind in _U16_TOP else 4)
                if kind in _PROJECT:
                    projected.append(encoded)
                else:
                    self._extra.append(UnassessedAttribute(index, kind, flags, encoded))
            if not {1, 2, 46}.issubset(fields) or _U32.unpack(fields[1])[0] != self._phy:
                _fail('wiphy_identity')
            current = (fields[1], fields[2], fields[46])
            if identity is not None and identity != current:
                _fail('wiphy_generation_changed')
            identity = current
            result.append(b''.join(projected))
        try:
            decoded = caps.decode_wiphy_projection(tuple(result))
        except caps.CapsDecodeError:
            _fail('caps_schema')
        if len(decoded.phys) != 1 or not all((decoded.phys[0].iftypes_present,
                decoded.phys[0].software_iftypes_present, decoded.phys[0].combinations_present,
                decoded.phys[0].commands_present)):
            _fail('missing_caps_fields')
        return decoded

    def read(self):
        with self._lock:
            if self._claimed:
                _fail('already_attempted')
            self._claimed = True
        raw, error, decoded = None, None, None
        try:
            if sys.byteorder != 'little' or (self._factory is None and sys.platform != 'linux'):
                _fail('unsupported_platform')
            deadline = self._now() + self._timeout
            self._unknown_factory = True
            factory = self._factory or socket.socket
            self._creator = factory
            raw = factory(AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
            self._socket, self._created = raw, True
            self._unknown_factory = False
            required = ('set_inheritable', 'get_inheritable', 'bind', 'getsockname',
                        'settimeout', 'gettimeout', 'sendto', 'recvmsg', 'close', 'fileno')
            if raw is None or not all(callable(getattr(raw, name, None)) for name in required):
                _fail('socket_contract')
            raw.set_inheritable(False)
            if raw.get_inheritable() is not False:
                _fail('inheritable_readback')
            raw.bind((0, 0))
            endpoint = raw.getsockname()
            if type(endpoint) is not tuple or len(endpoint) != 2 or \
                    not _int(endpoint[0], 1, 0xffffffff) or type(endpoint[1]) is not int or endpoint[1] != 0:
                _fail('bound_port')
            self._port = endpoint[0]
            family_rows = self._request(raw, GENL_CTRL, CTRL_GETFAMILY, CTRL_VERSION,
                                        _attr(2, b'nl80211\0'), 1, False, deadline)
            self._family = _family(family_rows[0])
            features = self._request(raw, self._family, GET_PROTOCOL_FEATURES, NL_VERSION,
                                     b'', 2, False, deadline)
            fields = _attrs(features[0])
            if len(fields) != 1 or fields[0][0] != PROTOCOL_FEATURES:
                _fail('protocol_features_format')
            _scalar(fields[0][1], fields[0][2], 4)
            if _U32.unpack(fields[0][2])[0] != SPLIT_FEATURE:
                _fail('split_not_supported')
            fragments = self._request(raw, self._family, GET_WIPHY, NL_VERSION,
                _attr(1, _U32.pack(self._phy)) + _attr(SPLIT_WIPHY_DUMP, b''), 3, True, deadline)
            decoded = self._projection(fragments)
            if self._now() >= deadline:
                _fail('deadline')
        except CapsTransportError as caught:
            error = caught
        except OSError as caught:
            error = CapsTransportError('os_error', getattr(caught, 'errno', 0))
        except Exception:
            error = CapsTransportError('unexpected_read_error')
        except BaseException:
            error = CapsTransportError('interrupted')
        finally:
            if raw is not None:
                try:
                    raw.close()  # exactly once, never retry an ambiguous close
                    descriptor = raw.fileno()
                    self._closed = type(descriptor) is int and descriptor == -1
                except BaseException:
                    self._closed = False
                if not self._closed:
                    error = CapsTransportError('socket_close_unverified')
            with self._lock:
                self._finished = True
                self._success = error is None and decoded is not None and self._closed
                self._last_error = error.code if error is not None else 'read_closed'
        if error is not None:
            raise error from None
        return decoded
