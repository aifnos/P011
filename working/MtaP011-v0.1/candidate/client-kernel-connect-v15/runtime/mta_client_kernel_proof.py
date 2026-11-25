"""Bounded read-only nl80211 CLIENT observations; not RF/L3 admission.

Independent implementation of Linux v4.14 UAPI. Reuses the audited capability
transport's framing, family and CPython 3.5 timeout rules, never its WIPHY read.
Constructors are pure. Only read() performs the fixed read-only requests.
"""
import errno
import math
import os
import re
import socket
import stat
import struct
import sys
import threading
import time

import mta_client_caps_transport as wire
import mta_client_proc as proc
import mta_p2p_client_init as core

GET_INTERFACE, NEW_INTERFACE, GET_STATION, NEW_STATION = 5, 7, 17, 19
_NL, _GENL = struct.Struct('<IHHII'), struct.Struct('<BBH')
_U32, _U64, _FLAGS = struct.Struct('<I'), struct.Struct('<Q'), struct.Struct('<II')
_CODES = frozenset(('invalid_input', 'already_attempted', 'unsupported_platform',
    'deadline', 'clock_regressed', 'socket_unknown', 'socket_identity',
    'socket_close_unknown', 'read_failed', 'receive_unknown', 'receive_budget',
    'kernel_peer', 'message_identity', 'message_format', 'kernel_error',
    'attribute_format', 'attribute_duplicate', 'interface_identity',
    'interface_changed', 'channel_changed', 'station_identity', 'station_changed',
    'process_unknown', 'boot_changed', 'ifindex_changed', 'resource_unknown',
    'wrong_observation', 'interrupted', 'cancelled'))


class KernelReadError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'read_failed'
        ValueError.__init__(self, self.code)


def _fail(code): raise KernelReadError(code) from None
def _int(value, low, high): return type(value) is int and low <= value <= high


def _metadata(value):
    fields = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
    if any(type(v) is not int or v < 0 for v in fields): _fail('resource_unknown')
    return fields


def _fields(data, station_info=False):
    result = {}
    try: rows = wire._attrs(data)
    except wire.CapsTransportError: _fail('attribute_format')
    for kind, flags, value, encoded in rows:
        if station_info and kind == 33:
            if flags or value != b'': _fail('attribute_format')
            continue
        if kind in result: _fail('attribute_duplicate')
        if flags not in (0, 0x8000): _fail('attribute_format')
        result[kind] = (flags, value, encoded)
    return result


def _scalar(fields, kind, layout, required=False):
    if kind not in fields:
        if required: _fail('attribute_format')
        return None
    flags, raw, unused = fields[kind]
    if flags or len(raw) != layout.size: _fail('attribute_format')
    return layout.unpack(raw)[0]


def _interface(data, origin):
    fields = _fields(data)
    phy = _scalar(fields, 1, _U32, True)
    index = _scalar(fields, 3, _U32, True)
    wdev = _scalar(fields, 153, _U64, True)
    if 4 not in fields: _fail('interface_identity')
    flags, raw, unused = fields[4]
    if flags or not 2 <= len(raw) <= 16 or raw[-1:] != b'\0' or b'\0' in raw[:-1]:
        _fail('interface_identity')
    try: name = raw[:-1].decode('ascii')
    except UnicodeError: _fail('interface_identity')
    if (phy, wdev, index, name) != origin.key()[:4]: _fail('interface_identity')
    role, frequency = _scalar(fields, 5, _U32), _scalar(fields, 38, _U32)
    if role is not None and not 1 <= role <= 12: _fail('attribute_format')
    if frequency is not None and not 1 <= frequency <= 100000: _fail('attribute_format')
    # Unknown metadata remains raw; it is not a concurrency/regulatory proof.
    extra = tuple(v[2] for k, v in fields.items() if k not in (1, 3, 4, 5, 38, 153))
    return (role, frequency), extra


def _station(data, origin):
    fields = _fields(data)
    if _scalar(fields, 3, _U32, True) != origin.ifindex: _fail('station_identity')
    if 6 not in fields: _fail('station_identity')
    flags, mac, unused = fields[6]
    if flags or len(mac) != 6 or not any(mac) or mac[0] & 1: _fail('station_identity')
    generation = _scalar(fields, 46, _U32)
    mask = values = None
    if 21 in fields:
        nested_flags, raw, unused = fields[21]
        if nested_flags not in (0, 0x8000): _fail('attribute_format')
        nested = _fields(raw, station_info=True)
        if 17 in nested:
            flags, raw_flags, unused = nested[17]
            if flags or len(raw_flags) != 8: _fail('attribute_format')
            mask, values = _FLAGS.unpack(raw_flags)
            if mask & ~0xfe or values & ~mask: _fail('attribute_format')
    # No flag absent from the driver mask may become FALSE or TRUE.
    states = tuple('UNKNOWN' if mask is None or not mask & (1 << bit) else
                   ('TRUE' if values & (1 << bit) else 'FALSE') for bit in (7, 1, 5))
    return (mac, generation, mask, values, states), tuple(v[2] for v in fields.values())


class KernelObservation(object):
    __slots__ = ('_reader', '_origin', '_executor', '_boot', '_channel', '_stations', '_reason')
    def __init__(self, reader, executor, channel, stations, reason):
        for name, value in (('_reader', reader), ('_origin', reader._origin),
                ('_executor', executor), ('_boot', reader._boot), ('_channel', channel),
                ('_stations', stations), ('_reason', reason)):
            object.__setattr__(self, name, value)
    def __setattr__(self, name, value): raise AttributeError('private immutable observation')
    def __repr__(self): return '<private CLIENT kernel observation>'
    def public_summary(self):
        states = self._stations[0][4] if len(self._stations) == 1 else ('UNKNOWN',) * 3
        role = 'UNKNOWN' if self._channel[0] is None else ('CLIENT' if self._channel[0] == 8 else 'MISMATCH')
        return {'role': role, 'frequency_observed': self._channel[1] is not None,
            'associated': states[0], 'authorized': states[1], 'authenticated': states[2],
            'station_count': len(self._stations), 'reason': self._reason,
            'endpoint_verified': False, 'ip_verified': False, 'production_available': False}
    def private_fields(self):
        return {'origin': self._origin, 'executor': self._executor, 'boot': self._boot,
                'channel': self._channel, 'stations': self._stations}


class _Io(object):
    def new_socket(self): return socket.socket(16, socket.SOCK_RAW, 16)
    def open_ifindex(self, name):
        return os.open('/sys/class/net/' + name + '/ifindex',
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)


class ClientKernelReader(wire.ClientCapsReader):
    """One issued observation, exact owner/epoch; no lease authority.

    Provider must register this exact reader before calling read(), under its
    existing F/Store lock and context gates. authenticate() checks issuer only;
    fresh association requires a new read, not reuse of an old observation.
    """
    def __init__(self, origin, boot, owner, operation_epoch, timeout=5.0,
                 _io=None, _proc_factory=None, _clock=None, _checkpoint=None, _deadline=None):
        if type(origin) is not core.Origin or origin.iftype != 8 or owner is None or not _int(operation_epoch, 1, 2**53):
            _fail('invalid_input')
        if type(boot) is not str or re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) is None:
            _fail('invalid_input')
        if _checkpoint is not None and not callable(_checkpoint): _fail('invalid_input')
        if _deadline is not None and (type(_deadline) not in (int, float) or
                not 0 < _deadline <= 1e12 or not math.isfinite(float(_deadline))): _fail('invalid_input')
        super(ClientKernelReader, self).__init__(origin.phy, timeout=timeout, clock=_clock)
        self._origin, self._boot, self._owner, self._epoch = origin, boot, owner, operation_epoch
        self._io, self._proc_factory = _io or _Io(), _proc_factory or proc.ProcReader
        self._tickets, self._readers, self._unassessed = [], [], []
        self._received_unknown = False
        self._observation = None
        self._cancel_callback, self._external_deadline = _checkpoint, _deadline
        self._cancelled, self._receipt_unknown = False, False
        self._close_receipts = []  # Exact producers, issued only in actual EBADF branches.
        self._read_deadline = None
    @property
    def original_resources(self): return tuple(self._tickets)
    @property
    def proc_readers(self): return tuple(self._readers)
    @property
    def unassessed_attributes(self): return tuple(self._unassessed)
    @property
    def closed_receipts(self): return tuple(self._close_receipts)
    def _checkpoint(self):
        # None preserves standalone read-only use. Provider must pass original
        # synchronous F bool callback, not _Connection._checkpoint (returns None).
        if self._cancelled: _fail('cancelled')
        if self._cancel_callback is None: return
        try: value = self._cancel_callback()
        except BaseException: value = None
        if type(value) is not bool or value:
            self._cancelled = True; _fail('cancelled')
    def _check(self, deadline):
        self._checkpoint()
        if self._now() >= deadline: _fail('deadline')
    def _budget(self, raw, deadline):
        self._check(deadline)
        super(ClientKernelReader, self)._budget(raw, deadline)
    def _issue_closed(self, io, fd, producer):
        # Internal issuance ONLY from the existing fresh EBADF branches below.
        # An integer or copied bool is never an original producer grant.
        try:
            issued = (type(producer) is dict and any(producer is row for row in self._tickets) and
                io is self._io and producer['fd'] == fd and producer['closed'] is True and producer['unknown'] is False)
            issued = issued or (type(producer) is proc.ProcReader and any(row['reader'] is producer for row in self._readers) and
                any(source is io and original == fd for source, original in producer._fd_refs))
            if not issued or not _int(fd, 0, 0x7fffffff) or len(self._close_receipts) >= 1024:
                self._receipt_unknown = True; return
            self._close_receipts.append((io, fd, producer))
        except BaseException: self._receipt_unknown = True
    def _ticket(self, kind):
        row = {'kind': kind, 'value': None, 'fd': None, 'meta': None,
               'unknown': True, 'attempted': False, 'closed': False}
        self._tickets.append(row)
        return row
    def _claim(self, row, value, fd):
        row['value'], row['fd'] = value, fd
        if not _int(fd, 0, 0x7fffffff) or any(r is not row and r['fd'] == fd and not r['closed'] for r in self._tickets):
            _fail('resource_unknown')
        meta = self._io.fstat(fd)
        row['meta'] = _metadata(meta)
        expected = stat.S_ISSOCK if row['kind'] == 'socket' else stat.S_ISREG
        if not expected(meta.st_mode): _fail('resource_unknown')
        row['unknown'] = False
    def _close(self, row):
        if row['attempted']: return row['closed']
        row['attempted'] = True
        if row['unknown']: return False
        try:
            before = self._io.fstat(row['fd'])
            if _metadata(before) != row['meta']:
                return False
            if row['kind'] == 'socket':
                row['value'].close()
                if type(row['value'].fileno()) is not int or row['value'].fileno() != -1: return False
            else: self._io.close(row['fd'])
            try: self._io.fstat(row['fd'])
            except OSError as error:
                row['closed'] = type(error.errno) is int and error.errno == errno.EBADF
                if row['closed']: self._issue_closed(self._io, row['fd'], row)
        except BaseException: pass
        return row['closed']
    def _ifindex(self, deadline):
        self._check(deadline); row = self._ticket('ifindex')
        fd = self._io.open_ifindex(self._origin.name)
        self._claim(row, None, fd)
        raw = self._io.read(fd, 17)
        if type(raw) is not bytes or not 2 <= len(raw) <= 16 or raw[-1:] != b'\n' or \
                not raw[:-1].isdigit() or raw[:1] == b'0' or self._io.read(fd, 1) != b'':
            _fail('ifindex_changed')
        if int(raw[:-1]) != self._origin.ifindex: _fail('ifindex_changed')
        self._check(deadline)
    def _self(self, deadline):
        self._check(deadline); left = deadline - self._now()
        if left < .1: _fail('deadline')
        row = {'reader': None, 'unknown': True, 'closed': False}
        self._readers.append(row)
        reader = self._proc_factory(timeout=min(3.0, left), _clock=self._clock)
        row['reader'], row['unknown'] = reader, False
        if type(reader) is not proc.ProcReader: _fail('process_unknown')
        observation = reader.read_self()
        row['value'] = observation # Retain the actual return before checkpoint/validation.
        refs = getattr(reader, '_fd_refs', None)
        if type(refs) is not list: _fail('process_unknown')
        closed = True
        for fs, fd in refs:
            try: fs.fstat(fd); closed = False
            except OSError as error:
                absent = type(error.errno) is int and error.errno == errno.EBADF
                if absent: self._issue_closed(fs, fd, reader)
                closed = closed and absent
        row['closed'] = closed and reader._pending is False and reader._active is False and \
            reader._files == reader._closed and reader._open_attempt is None
        if type(observation) is not proc.ProcObservation or not row['closed'] or observation.kind != 'live_actor' or observation.passes != 2 or \
                observation.resource_pending or not observation.same_boot or observation.boot != self._boot or \
                type(observation.actor) is not core.Actor or not observation.actor.live(): _fail('process_unknown')
        self._check(deadline)
        return observation.actor
    def _query(self, raw, family, command, attrs, sequence, dump, deadline):
        # No caller-supplied command or raw control passthrough.
        if (family == wire.GENL_CTRL and command != wire.CTRL_GETFAMILY) or \
                (family != wire.GENL_CTRL and command not in (GET_INTERFACE, GET_STATION)):
            _fail('invalid_input')
        version = 2 if family == wire.GENL_CTRL else 1
        request = _NL.pack(20 + len(attrs), family, 1 | (0x300 if dump else 0), sequence, self._port) + _GENL.pack(command, version, 0) + attrs
        self._requests.append(request); self._budget(raw, deadline)
        self._check(deadline)
        if raw.sendto(request, (0, 0)) != len(request): _fail('read_failed')
        rows, done = [], False
        while not done:
            self._budget(raw, deadline)
            value = raw.recvmsg(65537, 256, 0)
            if type(value) is not tuple or len(value) != 4: _fail('receive_unknown')
            packet, ancillary, flags, peer = value
            self._raw.append(wire.RawDatagram(sequence, packet, ancillary, flags, peer))
            if ancillary: self._received_unknown = True; _fail('receive_unknown')
            if type(packet) is not bytes or type(flags) is not int or flags or type(ancillary) not in (tuple, list) or \
                    type(peer) is not tuple or len(peer) != 2 or any(type(v) is not int for v in peer) or peer != (0, 0):
                _fail('kernel_peer')
            self._total += len(packet)
            if not 16 <= len(packet) <= 65536 or self._total > 1048576 or len(self._raw) > 64: _fail('receive_budget')
            self._check(deadline); at = 0
            while at < len(packet):
                if done or len(packet) - at < 16: _fail('message_format')
                size, kind, bits, seq, port = _NL.unpack_from(packet, at); step = (size + 3) & ~3
                if size < 16 or step > len(packet) - at or any(packet[at+size:at+step]): _fail('message_format')
                if seq != sequence or port != self._port: _fail('message_identity')
                body = packet[at+16:at+size]; at += step
                self._messages += 1
                if self._messages > 128: _fail('receive_budget')
                if kind == 2:
                    if bits != 0 or len(body) < 20 or body[4:] != request: _fail('message_format')
                    number = struct.unpack_from('<i', body)[0]
                    if dump and command == GET_STATION and number in (-95, -61):
                        if at != len(packet): _fail('message_format')
                        return None
                    _fail('kernel_error')
                if bits != (2 if dump else 0): _fail('message_format')
                if kind == 3:
                    if not dump or body not in (b'', b'\0'*4): _fail('message_format')
                    done = True; continue
                expected = 1 if family == wire.GENL_CTRL else (NEW_INTERFACE if command == GET_INTERFACE else NEW_STATION)
                if kind != family or len(body) < 4 or _GENL.unpack_from(body) != (expected, version, 0): _fail('message_format')
                rows.append(body[4:])
                if len(rows) > 16: _fail('receive_budget')
                if not dump: done = True
        return tuple(rows)
    def read(self):
        with self._lock:
            if self._claimed: _fail('already_attempted')
            self._claimed = True
            error = None; observation = None
            try:
                if self._io.__class__ is _Io and (sys.platform != 'linux' or sys.byteorder != 'little'):
                    _fail('unsupported_platform')
                deadline = self._now() + self._timeout
                if self._external_deadline is not None: deadline = min(deadline, self._external_deadline)
                self._read_deadline = deadline # Single absolute end; never renew after checkpoint/phase.
                first_actor = self._self(deadline); self._ifindex(deadline)
                row = self._ticket('socket'); raw = self._io.new_socket()
                row['value'] = self._socket = raw
                self._claim(row, raw, raw.fileno())
                self._created = True
                raw.set_inheritable(False)
                if raw.get_inheritable() is not False: _fail('socket_identity')
                raw.bind((0, 0)); endpoint = raw.getsockname()
                if type(endpoint) is not tuple or len(endpoint) != 2 or not _int(endpoint[0], 1, 0xffffffff) or type(endpoint[1]) is not int or endpoint[1] != 0:
                    _fail('socket_identity')
                self._port = endpoint[0]
                family = self._query(raw, 16, 3, wire._attr(2, b'nl80211\0'), 1, False, deadline)
                if len(family) != 1: _fail('message_format')
                self._family = wire._family(family[0])
                selectors = wire._attr(3, _U32.pack(self._origin.ifindex)) + wire._attr(153, _U64.pack(self._origin.wdev))
                channels, stations = [], []
                for sequence in (2, 4, 6):
                    rows = self._query(raw, self._family, GET_INTERFACE, selectors, sequence, False, deadline)
                    if len(rows) != 1: _fail('interface_identity')
                    channel, extra = _interface(rows[0], self._origin); channels.append(channel); self._unassessed.extend(extra)
                    if sequence != 6:
                        rows = self._query(raw, self._family, GET_STATION, selectors, sequence+1, True, deadline)
                        decoded = None if rows is None else tuple(_station(v, self._origin) for v in rows)
                        if decoded is not None:
                            values = tuple(v for v, extra in decoded)
                            if len(set(v[0] for v in values)) != len(values): _fail('station_identity')
                            self._unassessed.extend(e for v, extra in decoded for e in extra)
                        else: values = None
                        stations.append(values)
                if any(c != channels[0] for c in channels[1:]): _fail('channel_changed')
                if stations[0] != stations[1]: _fail('station_changed')
                self._ifindex(deadline); second_actor = self._self(deadline)
                self._check(deadline)
                if second_actor.key() != first_actor.key(): _fail('process_unknown')
                reason = 'station_unsupported' if stations[0] is None else ('no_station' if not stations[0] else 'observed')
                observation = KernelObservation(self, second_actor, channels[0], stations[0] or (), reason)
            except KernelReadError as caught: error = caught
            except wire.CapsTransportError: error = KernelReadError('read_failed')
            except Exception: error = KernelReadError('read_failed')
            except BaseException: error = KernelReadError('interrupted')
            finally:
                for row in reversed(self._tickets): self._close(row)
                self._closed = all(r['closed'] for r in self._tickets) and all(r['closed'] and not r['unknown'] for r in self._readers) and not self._received_unknown and not self._receipt_unknown
                self._finished = True; self._success = error is None and self._closed and observation is not None
                self._last_error = error.code if error is not None else ('read_closed' if self._closed else 'resource_unknown')
                if self._success: self._observation = observation
            if error is not None: raise error from None
            if not self._closed: _fail('resource_unknown')
            return observation
    def status(self):
        with self._lock:
            return {'attempted': self._claimed, 'finished': self._finished,
                'read_success': self._success,
                'socket_closed': any(r['kind'] == 'socket' and r['closed'] for r in self._tickets),
                'resources_closed': self._closed,
                'resource_pending': not self._closed if self._claimed else False,
                'datagram_count': len(self._raw), 'request_count': len(self._requests),
                'proc_reader_count': len(self._readers), 'original_resource_count': len(self._tickets),
                'has_unassessed_fields': bool(self._unassessed), 'reason': self._last_error,
                'cancel_requested': self._cancelled, 'receipt_unknown': self._receipt_unknown,
                'close_receipt_count': len(self._close_receipts),
                'production_available': False}
    def authenticate(self, owner, operation_epoch, observation):
        with self._lock:
            if owner is not self._owner or not _int(operation_epoch, 1, 2**53) or operation_epoch != self._epoch or type(observation) is not KernelObservation or \
                    observation is not self._observation or observation._reader is not self or not self._success or not self._closed:
                _fail('wrong_observation')
            return None
