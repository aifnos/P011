"""Native same-owner GO bootstrap mechanics, Linux 4.14/ARM, SOURCE only.

This module does not import a CLIENT lease/provider/Ready/caps grant. Neutral
Snapshot/Actor/Origin and the actual route dump decoder are facts only. Every
mutation needs this original GO Store's durable intent, original creator and
same worker/period. Constructor/status do no IO. There is no arbitrary command,
scan, guessed peer/channel, default route, IP/DHCP/send or public raw logging.

The fixed WPA 2.12 source uses p2p_no_group_iface=1: GROUP_ADD applies
SET_INTERFACE to the original private type 8 netdev, then starts type 9 AP.
Fresh kernel/event/STATUS must prove that SAME tuple; extra interfaces are
pending, never adopted by name. See the pinned archive's p2p_supplicant.c
6200/8115/8182, ap.c 1044/1068 and driver_nl80211.c 7216/8215. These are source
mechanics, not a claim that P011 firmware/driver or a phone has passed them.

Private event/STATUS/packets can contain SSID/PSK and remain strong in-memory
originals only. No repr/status/export reveals them. HOST _io seams are explicit
OS models, not permission or evidence of a device executable.

r4 retains incomplete CREATE ECHO as side-effect evidence only, separates
original raw close from a first pathname unlink, and passively waits for the
original controller endpoint under the unchanged stage deadline.

r5 stop-only cleanup authenticates the once original owner period and existing
bound cleanup accounting. An unknown GO publication never authorizes group
commands, netdev deletion, pending removal or a restoration-success claim.
"""
import errno
import hashlib
import math
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
import threading

import mta_ip as ip
import mta_p2p_client_init as core
import mta_go_deployment as sources

_NL, _GH, _NA, _CRED = struct.Struct('<IHHII'), struct.Struct('<BBH'), struct.Struct('<HH'), struct.Struct('<iii')
_MAX_PACKET, _MAX_RAW, _MAX_FDS, _MAX_ROWS = 262144, 16777216, 8192, 4096
_READ, _CLOEXEC, _NOFOLLOW = 0, 0x80000, 0x8000
_TRACKED = ('Z03', 'control_engine', 'weston', 'connmand', 'wpa_supplicant', 'bluetoothd')
_BOOT = '/proc/sys/kernel/random/boot_id'
_PRIVATE = frozenset((b'ATTACH', b'STATUS'))


def _fail(code): raise sources.GoSourceError(code) from None
def _int(v, lo=0, hi=0xffffffff): return type(v) is int and lo <= v <= hi
def _meta(v):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
    row = tuple(getattr(v, n, None) for n in names)
    if any(not sources._uint(x) for x in row): _fail('native_metadata_unknown')
    return row
def _attr(kind, raw):
    if not _int(kind, 1, 16383) or type(raw) is not bytes or len(raw) > 65531: _fail('native_attr_invalid')
    n = 4 + len(raw)
    return _NA.pack(n, kind) + raw + b'\0' * ((-n) & 3)
def _attrs(raw):
    if type(raw) is not bytes or len(raw) > _MAX_PACKET: _fail('native_attr_invalid')
    at, rows = 0, []
    while at < len(raw):
        if len(raw) - at < 4: _fail('native_attr_invalid')
        n, kind = _NA.unpack_from(raw, at); end = at + ((n + 3) & ~3)
        if n < 4 or end > len(raw) or any(raw[at + n:end]) or kind & 0x4000: _fail('native_attr_invalid')
        rows.append((kind & 0x3fff, kind & 0xc000, raw[at + 4:at + n])); at = end
        if len(rows) > _MAX_ROWS: _fail('native_attr_limit')
    return tuple(rows)
def _fields(raw):
    result = {}
    for kind, flags, value in _attrs(raw):
        if kind in result: _fail('native_attr_duplicate')
        result[kind] = (flags, value)
    return result
def _u(row, width=4):
    if type(row) is not tuple or len(row) != 2 or row[0] or len(row[1]) != width: _fail('native_scalar_invalid')
    return struct.unpack('<Q' if width == 8 else '<I' if width == 4 else '<H', row[1])[0]
def _flag(row):
    if row != (0, b''): _fail('native_flag_invalid')
    return True
def _nested(row):
    if row[0] not in (0, 0x8000): _fail('native_nested_invalid')
    return _attrs(row[1])
def _text(row, limit=256):
    flags, raw = row
    if flags or not 2 <= len(raw) <= limit or raw[-1:] != b'\0' or b'\0' in raw[:-1]: _fail('native_text_invalid')
    try: value = raw[:-1].decode('ascii')
    except UnicodeError: _fail('native_text_invalid')
    if any(ord(x) < 32 or ord(x) > 126 for x in value): _fail('native_text_invalid')
    return value
def _origin(raw):
    f = _fields(raw)
    if not {1, 3, 4, 5, 153} <= set(f): _fail('native_interface_invalid')
    value = core.Origin(_u(f[1]), _u(f[153], 8), _u(f[3]), _text(f[4], 16), _u(f[5]))
    frequency = _u(f[38]) if 38 in f else None
    mac = f[6][1] if 6 in f and not f[6][0] else None
    if mac is not None and (len(mac) != 6 or not any(mac) or mac[0] & 1): _fail('native_interface_invalid')
    return value, frequency, mac
def _status(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192 or b'\0' in raw: _fail('native_status_invalid')
    result = {}
    for line in raw.splitlines():
        if b'=' not in line: _fail('native_status_invalid')
        name, value = line.split(b'=', 1)
        if re.fullmatch(b'[a-zA-Z0-9_]{1,64}', name) is None or name in result: _fail('native_status_invalid')
        result[name] = value
    return result


class _LinuxIo(object):
    def validate(self): sources._LinuxIo().validate()
    def open(self, path, flags): return os.open(path, flags)
    def read(self, fd, n): return os.read(fd, n)
    def close(self, fd): return os.close(fd)
    def fstat(self, fd): return os.fstat(fd)
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def listdir(self, path): return os.listdir(path)
    def realpath(self, path): return os.path.realpath(path)
    def unlink(self, path): return os.unlink(path)
    def socket(self, protocol): return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
    def unix(self): return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    def kill_term(self, pid): return os.kill(pid, signal.SIGTERM)
    def pause(self, seconds): return select.select((), (), (), seconds)


class _Resource(object):
    """Exact original native return retained before validation/first syscall."""
    def __init__(self, native, kind, cleanup_until):
        self.native, self.kind, self.cleanup_until = native, kind, cleanup_until
        self._cleanup_until_original = cleanup_until
        self.value = self.fd = self.metadata = self.port = None
        self.returned = self.unknown = self.attempted = self.closed = False
        self.path = self.path_meta = self.peer = self.peer_meta = self.actor = None
        self.bound = self.unlink_called = False
        self.endpoint_closed = True
        self.failure = self.close_failure = self.endpoint_failure = None
    def __repr__(self): return '<private original GO native resource>'


class _Observation(object):
    def __init__(self, native):
        for name,value in (('native',native),('owner',native.owner),('until',native.until)):
            object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable original GO observation')
    def __repr__(self): return '<private GO native observation; not readiness>'


class GoBaselineObservation(_Observation):
    def __init__(self, native, snapshot): _Observation.__init__(self, native); object.__setattr__(self,'snapshot',snapshot)
class GoChannelObservation(_Observation):
    def __init__(self, native, frequency, caps_raw, channel_raw, beacon_interval, go_beacon_interval):
        _Observation.__init__(self, native)
        for name,value in (('frequency',frequency),('caps_raw',caps_raw),('channel_raw',channel_raw),
                ('beacon_interval',beacon_interval),('go_beacon_interval',go_beacon_interval),
                ('caps_sha256',hashlib.sha256(b''.join(caps_raw)).hexdigest()),
                ('channel_sha256',hashlib.sha256(channel_raw).hexdigest())):
            object.__setattr__(self,name,value)
class GoGroupSource(_Observation):
    def __init__(self, native, channel):
        _Observation.__init__(self, native)
        for name,value in (('channel',channel),('frequency',channel.frequency),
                ('channel_sha256',channel.channel_sha256),('caps_sha256',channel.caps_sha256)):
            object.__setattr__(self,name,value)
class GoGroupObservation(_Observation):
    def __init__(self, native, event_raw, status_raw, frequency, observed_origin):
        _Observation.__init__(self, native)
        for name,value in (('event_raw',event_raw),('status_raw',status_raw),('frequency',frequency),('observed_origin',observed_origin)):
            object.__setattr__(self,name,value)
class GoNativeRestoreObservation(_Observation):
    def __init__(self, native, snapshot): _Observation.__init__(self, native); object.__setattr__(self,'snapshot',snapshot)


class NativeGoResources(object):
    """Real socket/file/kernel/control producers under the exact original GO F.

    Default Linux IO; seams may model OS only. Pure ctor retains Store/entry/
    fixed source originals. Each method receives a narrowing absolute period,
    never remaining TTL. Resource observations and physical closure uncertainty
    are separate; parsing/timeout does not erase an actual close+typed EBADF.
    """
    def __init__(self, owner, _io=None):
        self.owner, self.store, self.deployment = owner, owner.store, owner.deployment
        self.until, self.worker, self.mutex, self.clock = self.store.until, self.store.worker, self.store.mutex, self.store.clock
        self.entry, self.io = owner.entry, _io if _io is not None else _LinuxIo()
        self._originals = (owner, self.store, self.deployment, self.until, self.worker, self.mutex, self.clock, self.entry, self.io)
        self.rows, self.raw, self.observations, self.proc_observations = [], [], [], []
        self._rows_original, self._history = self.rows, ()
        self._raw_bytes, self._packets, self._sequence, self._endpoint_sequence = 0, 0, 0, 0
        self._scope, self._scope_cleanup, self.last, self.failure = None, False, None, None
        self.baseline = self.channel = self.group_source = self.group = self.restored = None
        self.interface_ticket = self.create_row = self.create_request = self.owned = None
        self._create_echo_original = None  # An ECHO alone is NOT confirmed ownership.
        self.command_row = self.event_row = self._ctrl_actor = None
        self._create_called = self._delete_called = self._group_submit_called = self._group_remove_called = False
        self._termination = {}; self._config_raw = self._config_meta = self._config_anchors = None
        self._stop_only_calls,self._stop_only_observations,self._stop_only_failures=set(),[],[]
        self._ancillary_unknown = False; self._server_unlink_called = self._server_absent = False
        self._server_original = None
        self._go_beacon_interval = None
    def __repr__(self): return '<private original native GO resources; no IP/send readiness>'
    def _owner(self):
        self.deployment.loader.authenticate(self.deployment)
        module = self.deployment.modules['mta_go_bootstrap']
        if type(self.owner) is not module.GoBootstrap or self.owner.native is not self or \
                self.store._native_original is not self or self.store.owner is not self.owner or \
                self.deployment.loader.runtime is not self.owner or threading.current_thread() is not self.worker or threading.active_count()!=1 or \
                self.rows is not self._rows_original or tuple(self.rows) != self._history or \
                (self.owner, self.store, self.deployment, self.until, self.worker, self.mutex, self.clock, self.entry, self.io) != self._originals or \
                self.entry is not self.owner.entry or self.entry.clock is not self.clock or self.entry.until != self.until:
            _fail('native_owner_changed')
        self.entry._context(); self.store._owner()
    def _now(self, end=None):
        self._owner(); value = sources._time(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if end is not None and value >= end: _fail('deadline')
        return value
    def _begin(self, end, cleanup=False):
        self._owner(); end = sources._time(end)
        limit = self.store.restore_until if cleanup else self.until
        if limit is None or end > limit or cleanup and not self.store.restore_attempted: _fail('native_scope_invalid')
        self._scope, self._scope_cleanup = end, cleanup
        self._now(end)
        # This is the existing process accounting cap, not CLIENT authority.
        self.entry.accounting._io_deadline = end
        return end
    def _check(self):
        value=self._now(self._scope)
        if not self._scope_cleanup:
            module=self.deployment.modules['mta_go_bootstrap']
            if module.GoBootstrap._cancelled(self.owner,self._scope): _fail('stop_requested')
        return value
    def _record(self, kind, lifecycle=False):
        self._check()
        if len(self.rows) >= _MAX_FDS: _fail('native_fd_limit')
        # Independent one descriptor-close cap fixed BEFORE its native factory;
        # does not permit more network activity or renew the session/restore.
        cap = min(self.store.restore_until, self._scope + 5) if self._scope_cleanup else self.until+60 if lifecycle else self._scope+5
        row = _Resource(self, kind, cap); self.rows.append(row); self._history += (row,)
        return row
    def _retain(self, value):
        self.raw.append(value)
        size = sum(len(x) for x in value if type(x) is bytes) if type(value) is tuple else len(value) if type(value) is bytes else 0
        self._raw_bytes += size
        if self._raw_bytes > _MAX_RAW: _fail('native_raw_limit')
    def _adopt(self, row, value, fd):
        row.value, row.fd, row.returned = value, fd, True
        if not _int(fd, 0, 0x7fffffff) or any(r is not row and r.returned and not r.closed and r.fd == fd for r in self.rows):
            row.unknown = True; _fail('native_fd_unknown')
        row.metadata = _meta(self.io.fstat(fd)); row.unknown = False
    def _fd_current(self, row, close=False):
        if type(row) is not _Resource or row.native is not self or not any(r is row for r in self._history) or \
                not row.returned or row.unknown or row.closed or not close and row.attempted or \
                _meta(self.io.fstat(row.fd)) != row.metadata or row.kind != 'file' and row.value.fileno() != row.fd:
            _fail('native_fd_changed')
    def _unlink_endpoint(self, row, cap):
        """First unlink only for an actually closed original bound pathname.

        An expired precheck has not called unlink and may be considered again
        under the SAME fixed cap. An attempted uncertain unlink is never retried.
        This method does not fstat/close a historical numeric descriptor.
        """
        self._owner()
        if row.native is not self or not any(row is r for r in self._history) or \
                not row.returned or not row.attempted or not row.closed or row.unknown:
            _fail('native_endpoint_close_pending')
        cap=sources._time(cap)
        if row.cleanup_until!=row._cleanup_until_original or cap>row._cleanup_until_original:
            _fail('native_endpoint_cleanup_cap_changed')
        if self.owner.restore_attempted:
            module=self.deployment.modules['mta_go_bootstrap']
            original=module.GoBootstrap._cleanup_period_current(self.owner,self)
            if cap>original: _fail('native_endpoint_cleanup_cap_changed')
        if self.store.restore_until is not None and (self.store.restore_until!=self.store._restore_until_original or
                cap>self.store.restore_until): _fail('native_endpoint_cleanup_cap_changed')
        if self._scope_cleanup and (self._scope is None or cap>self._scope): _fail('native_endpoint_cleanup_cap_changed')
        self._now(cap)
        if not row.bound or row.endpoint_closed: return
        if row.unlink_called: _fail('native_endpoint_close_pending')
        try:
            self._now(cap)
            if row.path is None or row.path_meta is None or self._path_metadata(row.path) != row.path_meta:
                _fail('native_endpoint_changed')
            self._now(cap)
            row.unlink_called = True  # Before actual unlink; uncertain return is not retried.
            if self.io.unlink(row.path) is not None: _fail('native_endpoint_close_pending')
            try: self.io.stat(row.path)
            except OSError as error:
                row.endpoint_closed = type(error.errno) is int and error.errno == errno.ENOENT
            if not row.endpoint_closed: _fail('native_endpoint_close_pending')
            self._now(cap)  # Retain actual absence even if this postcheck is late.
        except BaseException as error:
            row.endpoint_failure = error
            raise
    def _close(self, row, _absolute_deadline=None):
        cap=min(row.cleanup_until,self.store.restore_until) if self.store.restore_attempted and self.store.restore_until is not None else row.cleanup_until
        if self._scope_cleanup and self._scope is not None: cap=min(cap,self._scope)
        if _absolute_deadline is not None: cap=min(cap,sources._time(_absolute_deadline))
        if row.closed:
            if row.bound and not row.endpoint_closed: self._unlink_endpoint(row, cap)
            return
        if row.attempted or not row.returned or row.unknown: _fail('native_close_pending')
        original_error = None
        try:
            self._now(cap); self._fd_current(row, True)
            row.attempted = True
            result = self.io.close(row.fd) if row.kind == 'file' else row.value.close()
            try: self.io.fstat(row.fd)
            except OSError as error:
                row.closed = result is None and type(error.errno) is int and error.errno == errno.EBADF
            if not row.closed: row.unknown = True; _fail('native_close_pending')
            # Keep actual closure before a late postcheck; never repeat close.
            self._now(cap)
        except BaseException as error:
            original_error = error
            row.close_failure = error
            raise
        finally:
            if row.closed and row.bound and not row.endpoint_closed and not row.unlink_called:
                try:
                    self._unlink_endpoint(row, cap)
                except BaseException:
                    if original_error is None: raise
    def _socket(self, protocol):
        row = self._record('netlink')
        try: value = self.io.socket(protocol)
        except OSError:
            row.attempted = row.closed = True
            raise
        row.value, row.returned = value, True  # Before fileno or any socket IO.
        self._adopt(row, value, value.fileno())
        if not stat.S_ISSOCK(row.metadata[2]): _fail('native_socket_invalid')
        value.set_inheritable(False)
        if value.get_inheritable() is not False: _fail('native_socket_invalid')
        value.bind((0, 0)); endpoint = value.getsockname()
        if type(endpoint) is not tuple or len(endpoint) != 2 or not _int(endpoint[0], 1) or endpoint[1] != 0: _fail('native_socket_invalid')
        row.port = endpoint[0]; self._check()
        return row
    def _timeout(self, row, poll=False):
        self._fd_current(row); remaining = 0.0 if poll else self._scope - self._check()
        row.value.settimeout(remaining)
        actual = row.value.gettimeout()
        if type(actual) not in (int, float) or (actual != 0 if poll else not 0 < actual <= remaining + 1e-9): _fail('native_timeout_invalid')
    def _send(self, row, request):
        self._timeout(row); self._retain(('request', request))
        returned = row.value.sendto(request, (0, 0))
        self._retain(('send_return', returned)); self._check()
        if type(returned) is not int or returned != len(request): _fail('native_short_write')
    def _recv(self, row):
        self._timeout(row)
        returned = row.value.recvmsg(_MAX_PACKET + 1, 256, 0)
        self._retain(('kernel_return', returned))  # Original retained before unpack/postcheck.
        if type(returned) is not tuple or len(returned) != 4: _fail('native_kernel_invalid')
        raw, ancillary, flags, peer = returned
        self._retain(('kernel_raw', raw)); self._packets += 1
        if self._packets > 1024 or type(raw) is not bytes or not 16 <= len(raw) <= _MAX_PACKET or ancillary or flags or peer != (0, 0):
            _fail('native_kernel_invalid')
        self._check(); return raw
    def _next(self):
        if self._sequence >= 0xffffffff: _fail('native_sequence_limit')
        self._sequence += 1; return self._sequence
    def _request(self, row, family, command, attrs=b'', flags=0, sequence=None):
        if sequence is None: sequence=self._next()
        elif row is not self.create_row or command!=7 or self.interface_ticket is None or \
                sequence!=self.interface_ticket.sequence or row.port!=self.interface_ticket.port_id:
            _fail('native_request_not_original')
        version = 2 if family == 16 else 1
        request = _NL.pack(20 + len(attrs), family, 1 | flags, sequence, row.port) + _GH.pack(command, version, 0) + attrs
        self._send(row, request); records, ack, done = [], False, False
        for unused in range(64):
            raw = self._recv(row); at = 0
            while at < len(raw):
                if done or len(raw) - at < 16: _fail('native_kernel_invalid')
                n, kind, bits, seq, port = _NL.unpack_from(raw, at); end = at + ((n + 3) & ~3)
                if n < 16 or end > len(raw) or any(raw[at+n:end]) or seq != sequence or port != row.port or bits & (16 | 32):
                    _fail('native_kernel_invalid')
                body = raw[at+16:at+n]; at = end
                if kind == 2:
                    if ack or not flags & 4 or bits not in (0, 0x100) or len(body) < 20 or body[4:20] != request[:16]:
                        _fail('native_ack_invalid')
                    code = struct.unpack_from('<i', body)[0]
                    if not -4095 <= code <= 0 or (len(body) != 20 if code == 0 or bits & 0x100 else body[4:] != request):
                        _fail('native_ack_invalid')
                    if code: _fail('native_kernel_error')
                    ack = True
                elif kind == 3:
                    if not flags & 0x300 or bits not in (0, 2) or body not in (b'', b'\0'*4): _fail('native_done_invalid')
                    done = True
                else:
                    if kind != family or bits != (2 if flags & 0x300 else 0) or len(body) < 4 or body[1:4] != bytes((version,0,0)):
                        _fail('native_kernel_invalid')
                    records.append((body[0], body[4:]))
                    if row is self.create_row and command == 7 and flags & 8:
                        self._retain_create_echo(row, request, sequence, body[0], body[4:])
                    if len(records) > 256: _fail('native_kernel_limit')
            if flags & 0x300:
                if done: return tuple(records), request
            elif flags & 8:
                if len(records) > 1: _fail('native_create_ambiguous')
                if ack and len(records) == 1: return tuple(records), request
            elif flags & 4:
                if records: _fail('native_ack_invalid')
                if ack: return (), request
            elif len(records) == 1: return tuple(records), request
        _fail('native_kernel_limit')
    def _retain_create_echo(self, row, request, sequence, command, raw):
        """Keep actual correlated ECHO before waiting for ACK, without a grant."""
        ticket = self.interface_ticket
        if row is not self.create_row or type(ticket) is not core.InterfaceTicket or \
                not self._create_called or sequence != ticket.sequence or row.port != ticket.port_id or \
                command != 7 or self._create_echo_original is not None:
            _fail('native_create_echo_invalid')
        origin, frequency, mac = _origin(raw)
        # Retain parsed actual origin even when the following constraints fail.
        # No caller can use this observation as owned or ACK-confirmed source.
        self._create_echo_original = (request, ticket, origin, raw)
        self._retain(('create_echo_observed', raw))
        if origin.iftype != 8 or origin.phy != ticket.phy or origin.name != ticket.name or self.baseline is None or \
                any(r.wdev == origin.wdev or r.ifindex == origin.ifindex or r.name == origin.name
                    for r in self.baseline.snapshot.interfaces):
            _fail('native_create_origin_changed')
        return None
    def _family(self, row):
        records, request = self._request(row, 16, 3, _attr(2, b'nl80211\0'))
        if len(records) != 1 or records[0][0] != 1: _fail('native_family_invalid')
        f = _fields(records[0][1])
        if not {1, 2, 3, 4, 5} <= set(f) or _text(f[2]) != 'nl80211' or _u(f[3]) != 1 or _u(f[4]) != 0 or _u(f[5]) < 174:
            _fail('native_family_invalid')
        value = _u(f[1], 2)
        if not 19 <= value <= 1023: _fail('native_family_invalid')
        return value
    def _interfaces(self):
        row = self._socket(16)
        try:
            family = self._family(row); records, request = self._request(row, family, 5, flags=0x300)
            if not 1 <= len(records) <= 32 or any(cmd != 7 for cmd, data in records): _fail('native_interface_invalid')
            result = tuple(_origin(data) for cmd, data in records)
            if any(len(set(getattr(x[0], field) for x in result)) != len(result) for field in ('wdev','ifindex','name')):
                _fail('native_interface_ambiguous')
            return result
        finally: self._close(row)
    def _path_metadata(self, path): return sources._meta(self.io.stat(path))
    def _anchors(self, path):
        if type(path) is not str or not path.startswith('/') or any(p in ('','..','.') for p in path[1:].split('/')):
            _fail('native_path_invalid')
        resolved = self.io.realpath(path)
        if type(resolved) is not str or not resolved.startswith('/') or any(p in ('','..','.') for p in resolved[1:].split('/')):
            _fail('native_path_invalid')
        result = []
        for i in range(len(resolved.split('/')) - 1):
            name = '/' if i == 0 else '/' + '/'.join(resolved.split('/')[1:i+1])
            self._check(); m = self._path_metadata(name)
            temporary = name in ('/var/volatile','/var/volatile/tmp')
            if not stat.S_ISDIR(m[2]) or m[3:5] != (0,0) or not temporary and m[2] & 0o002 or \
                    name.startswith(sources.ROOT) and stat.S_IMODE(m[2]) != 0o700:
                _fail('native_path_unowned')
            result.append((name, m[:6]))
        # Symlink resolution itself must remain unchanged, not just final inode.
        if self.io.realpath(path) != resolved: _fail('native_path_changed')
        return resolved, tuple(result)
    def _file(self, path, maximum=1048576, image=False):
        self._check(); parts, total = [], 0
        if not image: anchors = None if path.startswith('/proc/') else self._anchors(path)
        else: anchors = None  # Exact fresh Proc actor's exe magiclink only.
        row = self._record('file')  # Immediately before factory, not before passive path refusal.
        try:
            try: returned = self.io.open(path, _CLOEXEC | (0 if image else _NOFOLLOW))
            except OSError:
                row.attempted = row.closed = True
                raise
            self._adopt(row, returned, returned)
            before = sources._meta(self.io.fstat(row.fd))
            if not stat.S_ISREG(before[2]) or before[3:5] != (0,0): _fail('native_file_unowned')
            if not path.startswith('/proc/') and (before[2] & 0o022 or before[5] != 1): _fail('native_file_unowned')
            while True:
                self._check(); n = min(65536, maximum + 1 - total); chunk = self.io.read(row.fd,n)
                if type(chunk) is not bytes or len(chunk) > n: _fail('native_file_invalid')
                parts.append(chunk); total += len(chunk)
                if total > maximum: _fail('native_file_limit')
                if not chunk: break
            raw = b''.join(parts); self._retain(('file', path, raw if maximum <= 1048576 else hashlib.sha256(raw).digest()))
            if sources._meta(self.io.fstat(row.fd)) != before or not image and self._path_metadata(path) != before or \
                    anchors is not None and self._anchors(path) != anchors: _fail('native_file_changed')
            self._check(); return raw, before
        finally: self._close(row)
    def _proc(self, pid, expected=None):
        self._check(); value = self.entry.reader.read_actor(pid, expected, _absolute_deadline=self._scope)
        self.proc_observations.append(value); self._check()
        proc = self.deployment.modules['mta_client_proc']
        if type(value) is not proc.ProcObservation or value.kind != 'live_actor' or type(value.actor) is not core.Actor or \
                value.same_boot is not True or type(value.passes) is not int or value.passes != 2 or value.resource_pending is not False or \
                value.boot != self.entry.boot or not any(r.observation is value and self.entry.reader.owns_generation(r)
                    for r in self.entry.reader._history) or not self.entry.reader.history_closed(): _fail('native_actor_unknown')
        return value
    def _actors(self):
        self._check(); names = self.io.listdir('/proc')
        if type(names) not in (list,tuple) or len(names) > _MAX_ROWS or any(type(n) is not str for n in names): _fail('native_proc_limit')
        launcher, excluded = self.owner.launcher, {}
        if launcher is not None:
            for ticket in launcher._tickets:
                if ticket.pid is not None and not ticket.waited:
                    actor = ticket.postexec or ticket.preexec
                    if actor is None or ticket.unknown: _fail('native_private_actor_unknown')
                    fresh = self._proc(ticket.pid, actor)
                    if fresh.actor.key() != actor.key() or not fresh.actor.live(): _fail('native_private_actor_changed')
                    excluded[ticket.pid] = actor
        result, found = [], {}
        for name in sorted(names):
            if re.fullmatch('[1-9][0-9]{0,9}',name) is None: continue
            number = int(name)
            if not _int(number,1,0x7fffffff): _fail('native_proc_limit')
            if number in excluded: continue
            try: comm = self._file('/proc/'+name+'/comm',128)[0].strip().decode('ascii')
            except UnicodeError: _fail('native_actor_unknown')
            if comm not in _TRACKED: continue
            actor = self._proc(number).actor
            if actor.exe.rsplit('/',1)[-1] != comm or not actor.live(): _fail('native_actor_unknown')
            if comm in ('Z03','control_engine') and actor.exe != '/usr/bin/'+comm: _fail('native_actor_unknown')
            result.append(actor); found[comm] = found.get(comm,0)+1
        if any(found.get(n) != 1 for n in ('Z03','control_engine','weston','wpa_supplicant')) or len(result)>32:
            _fail('native_actor_unknown')
        return tuple(result)
    def _pins(self, actors):
        manifest = self.deployment.manifest.baseline_manifest
        if len(manifest) != 4 or tuple(sorted(r for r in manifest if r[0] != '/usr/sbin/wpa_cli')) != tuple(sorted(core.STOCK_PINS)) or \
                sum(r[0] == '/usr/sbin/wpa_cli' for r in manifest) != 1: _fail('native_baseline_manifest_invalid')
        result, metadata = [], {}
        for path, expected in manifest:
            raw, m = self._file(path,67108864)
            if hashlib.sha256(raw).hexdigest() != expected: _fail('native_stock_pin_changed')
            metadata[path] = m
            if path != '/usr/sbin/wpa_cli': result.append((path,expected))
        for actor in actors:
            if actor.exe not in ('/usr/bin/Z03','/usr/bin/control_engine'): continue
            raw, m = self._file('/proc/'+str(actor.pid)+'/exe',67108864,True)
            if m != metadata[actor.exe] or hashlib.sha256(raw).hexdigest() != dict(manifest)[actor.exe] or \
                    self._proc(actor.pid,actor).actor.key() != actor.key(): _fail('native_stock_image_changed')
        return tuple(result)
    def _unix_owner(self, path, actor):
        fresh = self._proc(actor.pid,actor)
        if fresh.actor.key() != actor.key() or not fresh.actor.live(): _fail('native_ctrl_actor_changed')
        raw = self._file('/proc/net/unix')[0]
        try: lines = raw.decode('ascii').splitlines()
        except UnicodeError: _fail('native_unix_table_invalid')
        rows = []
        for line in lines[1:]:
            fields = line.split()
            if len(fields) not in (7,8): _fail('native_unix_table_invalid')
            if len(fields)==8 and fields[7]==path:
                if fields[4]!='0002' or fields[5]!='01' or not fields[6].isdigit(): _fail('native_ctrl_unowned')
                rows.append(int(fields[6]))
        if len(rows)!=1: _fail('native_ctrl_unowned')
        names = self.io.listdir('/proc/'+str(actor.pid)+'/fd')
        if type(names) not in (list,tuple) or len(names)>4096: _fail('native_proc_limit')
        matched = []
        for name in names:
            if type(name) is not str or re.fullmatch('[0-9]{1,10}',name) is None: _fail('native_proc_limit')
            if self.io.readlink('/proc/'+str(actor.pid)+'/fd/'+name)=='socket:[%d]' % rows[0]: matched.append(name)
            self._check()
        if len(matched)!=1 or self._proc(actor.pid,actor).actor.key()!=actor.key(): _fail('native_ctrl_unowned')
        return rows[0]
    def _stock_endpoint(self, actor):
        raw = self._file('/proc/net/unix')[0]
        try: lines = raw.decode('ascii').splitlines()
        except UnicodeError: _fail('native_unix_table_invalid')
        candidates = []
        for line in lines[1:]:
            f = line.split()
            if len(f)==8 and f[7].startswith('/') and f[7].rsplit('/',1)[-1]=='wlan0' and f[4]=='0002': candidates.append(f[7])
        if len(candidates)!=1: _fail('native_stock_ctrl_ambiguous')
        self._unix_owner(candidates[0],actor)
        return candidates[0]
    def _unix(self, peer, actor, lifecycle=False):
        self._check(); self._anchors(peer); before = self._path_metadata(peer)
        if not stat.S_ISSOCK(before[2]) or before[3:5]!=(0,0) or before[5]!=1: _fail('native_ctrl_unowned')
        self._unix_owner(peer,actor)
        row = self._record('unix',lifecycle)
        try: raw = self.io.unix()
        except OSError:
            row.attempted=row.closed=True
            raise
        row.value,row.returned=raw,True; self._adopt(row,raw,raw.fileno())
        raw.set_inheritable(False); raw.setsockopt(1,16,1)
        if raw.get_inheritable() is not False or raw.getsockopt(1,16)!=1: _fail('native_ctrl_unknown')
        self._endpoint_sequence += 1
        local = self.deployment.manifest.run+'/go-read-%04d' % self._endpoint_sequence
        self._anchors(local)
        try: self.io.stat(local)
        except OSError as error:
            if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
        else: _fail('native_endpoint_present')
        row.path=local; row.endpoint_closed=False
        try: raw.bind(local)
        except OSError:
            # Native bind negative: this creator did not create the pathname.
            # Do not delete a preexisting/foreign endpoint to make it pass.
            row.endpoint_closed=True
            raise
        row.bound=True
        row.path_meta=self._path_metadata(local)
        if not stat.S_ISSOCK(row.path_meta[2]) or row.path_meta[3:5]!=(0,0) or row.path_meta[5]!=1: _fail('native_endpoint_unowned')
        raw.connect(peer); row.peer,row.peer_meta,row.actor=peer,before,actor
        self._unix_gate(row)
        return row
    def _unix_gate(self,row):
        self._check(); self._fd_current(row)
        if row.actor is None or row.peer is None or self._path_metadata(row.peer)!=row.peer_meta or \
                self._path_metadata(row.path)!=row.path_meta or row.value.getpeername()!=row.peer or row.value.getsockname()!=row.path or \
                row.value.get_inheritable() is not False or row.value.getsockopt(1,16)!=1: _fail('native_ctrl_changed')
    def _ctrl_recv(self,row,poll=False):
        self._unix_gate(row); self._timeout(row,poll)
        try: returned=row.value.recvmsg(8193,socket.CMSG_SPACE(_CRED.size)+socket.CMSG_SPACE(64),0x40000000)
        except OSError as error:
            if poll and type(error.errno) is int and error.errno in (errno.EAGAIN,errno.EWOULDBLOCK): return None
            raise
        self._retain(('private_ctrl_return',returned))
        if type(returned) is not tuple or len(returned)!=4: _fail('native_ctrl_invalid')
        packet,ancillary,flags,address=returned
        credentials=[]
        if type(ancillary) not in (list,tuple): _fail('native_ctrl_invalid')
        for item in ancillary:
            if type(item) is not tuple or len(item)!=3 or item[:2]!=(1,2) or type(item[2]) is not bytes or len(item[2])!=_CRED.size:
                # SCM_RIGHTS is never requested/accepted; MSG_CMSG_CLOEXEC makes
                # any unexpected received descriptor noninheritable, but such
                # an unknown resource is pending, not dropped as successful.
                self._unexpected_ancillary(ancillary,row.cleanup_until)
                _fail('native_ctrl_ancillary_unknown')
            credentials.append(_CRED.unpack(item[2]))
        if type(flags) is int and flags&8: self._ancillary_unknown=True
        if credentials!=[(row.actor.pid,0,0)] or type(packet) is not bytes or not 1<=len(packet)<=8192 or \
                flags not in (0,0x40000000) or address not in (row.peer,row.peer.encode('ascii')): _fail('native_ctrl_unowned')
        self._retain(('private_ctrl_raw',packet)); self._unix_gate(row)
        return packet
    def _unexpected_ancillary(self,ancillary,cap):
        """Actual received rights are resources; known raw FD stays known."""
        for item in ancillary:
            if type(item) is not tuple or len(item)!=3: self._ancillary_unknown=True;continue
            if item[:2]!=(1,1): continue
            raw=item[2]
            if type(raw) is not bytes or not raw or len(raw)%4 or len(raw)>64:
                self._ancillary_unknown=True;continue
            for fd in struct.unpack('<%di' % (len(raw)//4),raw):
                if len(self.rows)>=_MAX_FDS: self._ancillary_unknown=True;continue
                received=_Resource(self,'file',cap);self.rows.append(received);self._history+=(received,)
                received.value=received.fd=fd;received.returned=True
                try:
                    self._adopt(received,fd,fd);self._close(received)
                except BaseException as error: received.close_failure=error
    def _exchange(self,row,wire):
        if type(wire) is not bytes: _fail('native_control_command_invalid')
        if row is self.event_row:
            if wire!=b'ATTACH' or self._scope_cleanup: _fail('native_control_command_invalid')
        elif row is self.command_row:
            if wire!=b'STATUS':
                record=self.store.current.record
                add=b'P2P_GROUP_ADD freq=%d' % self.group_source.frequency if self.group_source is not None else None
                remove=b'P2P_GROUP_REMOVE '+self.owned.name.encode('ascii') if self.owned is not None else None
                if wire==add:
                    facts=None if record.group_add is None else dict(record.group_add)
                    if self._scope_cleanup or not self._group_submit_called or record.phase!='group_add_intent' or facts is None or \
                            facts['command_sha256']!=hashlib.sha256(wire).hexdigest(): _fail('native_control_command_invalid')
                elif wire==remove:
                    if not self._scope_cleanup or not self._group_remove_called or record.phase!='restore_intent':
                        _fail('native_control_command_invalid')
                else: _fail('native_control_command_invalid')
        elif wire!=b'STATUS': _fail('native_stock_command_forbidden')
        self._unix_gate(row); self._timeout(row); self._retain(('private_ctrl_request',wire))
        n=row.value.send(wire); self._retain(('private_ctrl_send_return',n)); self._check()
        if type(n) is not int or n!=len(wire): _fail('native_short_write')
        return self._ctrl_recv(row)
    def _stock_status(self,actors):
        actor=next(a for a in actors if a.exe.rsplit('/',1)[-1]=='wpa_supplicant')
        row=self._unix(self._stock_endpoint(actor),actor)
        try:
            raw=self._exchange(row,b'STATUS'); f=_status(raw)
            if f.get(b'wpa_state')!=b'COMPLETED' or re.fullmatch(b'[0-9]{4}',f.get(b'freq',b'')) is None:
                _fail('native_station_unavailable')
            frequency=int(f[b'freq'])
            if frequency not in range(2412,2473,5): _fail('native_station_channel_unavailable')
            return raw,f,frequency
        finally: self._close(row)
    def _ipv4(self):
        row=self._socket(0); dumps=[]
        try:
            for kind in ('addresses','routes','rules'):
                collector=ip.DumpCollector(kind,self._next(),row.port); self._send(row,collector.request)
                while not collector.complete: collector.feed(self._recv(row))
                dumps.append(collector)
            return ip.snapshot_from_dumps(*dumps)
        finally: self._close(row)
    def _ipv6(self,path,widths):
        raw=self._file(path)[0]
        try: rows=tuple(tuple(line.split()) for line in raw.decode('ascii').splitlines())
        except UnicodeError: _fail('native_ipv6_invalid')
        if len(rows)>_MAX_ROWS or path!='/proc/net/ipv6_route' and len(set(rows))!=len(rows): _fail('native_ipv6_invalid')
        for row in rows:
            if len(row)!=len(widths)+1 or any(re.fullmatch('[0-9a-f]{%d}' % width,row[i]) is None for i,width in enumerate(widths)) or \
                    re.fullmatch('[A-Za-z0-9_.-]{1,15}',row[-1]) is None: _fail('native_ipv6_invalid')
        return rows
    def _snapshot_once(self):
        self.io.validate(); boot=self._file(_BOOT,128)[0]
        try: boot=boot.strip().decode('ascii')
        except UnicodeError: _fail('native_boot_invalid')
        if boot!=self.entry.boot: _fail('native_boot_changed')
        actors=self._actors(); pins=self._pins(actors); interfaces=self._interfaces()
        station=tuple(r for r,f,m in interfaces if r.name=='wlan0' and r.iftype==2)
        if len(station)!=1: _fail('native_station_unavailable')
        status,fields,frequency=self._stock_status(actors)
        if next(f for r,f,m in interfaces if r is station[0])!=frequency: _fail('native_station_channel_changed')
        return core.Snapshot(boot,pins,actors,station[0],hashlib.sha256(status).hexdigest(),frequency,
            tuple(r for r,f,m in interfaces),self._ipv4(),
            self._ipv6('/proc/net/if_inet6',(32,2,2,2,2)),
            self._ipv6('/proc/net/ipv6_route',(32,2,32,2,32,8,8,8,8)),True)
    def _stable_snapshot(self):
        first=self._snapshot_once(); second=self._snapshot_once()
        self.observations.extend((first,second))
        if first.key()!=second.key(): _fail('native_baseline_unstable')
        self._check(); return second
    def _outside_key(self,snapshot,current):
        if self.baseline is None or self.owned is None or current.key()[:4]!=self.owned.key()[:4] or current.iftype not in (8,9):
            _fail('native_origin_changed')
        matching=tuple(r for r in snapshot.interfaces if r.wdev==current.wdev or r.ifindex==current.ifindex or r.name==current.name)
        if len(matching)!=1 or matching[0].key()!=current.key(): _fail('native_origin_changed')
        if any(a.ifindex==current.ifindex for a in snapshot.ipv4.addresses) or any(r.oif==current.ifindex for r in snapshot.ipv4.routes):
            _fail('native_unexpected_l3')
        # Reuse the neutral mechanical IPv6 shape validation, not key(owned8).
        core._owned_ipv6(snapshot.ipv6_addresses,snapshot.ipv6_routes,current)
        return (snapshot.boot,snapshot.stock_hashes,tuple(sorted(a.key() for a in snapshot.stock_actors)),
            snapshot.station.key(),snapshot.station_state_sha,snapshot.station_frequency,
            tuple(sorted(r.key() for r in snapshot.interfaces if r.key()[:4]!=current.key()[:4])),
            tuple(sorted(snapshot.ipv4.addresses,key=lambda r:repr(tuple(r)))),
            tuple(sorted(snapshot.ipv4.routes,key=lambda r:repr(tuple(r)))),tuple(sorted(snapshot.ipv4.rules)),
            tuple(sorted(r for r in snapshot.ipv6_addresses if r[-1]!=current.name)),
            tuple(sorted(r for r in snapshot.ipv6_routes if r[-1]!=current.name)))
    def observe_baseline(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.baseline is not None or self._create_called: _fail('native_baseline_already_issued')
            value=GoBaselineObservation(self,self._stable_snapshot()); self.baseline=value
            self.observations.append(value); return value
    def baseline_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoBaselineObservation or original is not self.baseline: _fail('native_baseline_not_original')
        if self._stable_snapshot().key()!=original.snapshot.key(): _fail('native_baseline_changed')
        return original
    def _config(self):
        path=self.deployment.manifest.cfg; raw,metadata=self._file(path,4096)
        if stat.S_IMODE(metadata[2])!=0o400 or metadata[5]!=1: _fail('native_config_unowned')
        expected=(b'ctrl_interface='+self.deployment.manifest.ctrl.encode('ascii')+b'\n'+
            b'p2p_no_group_iface=1\nap_scan=2\ndevice_name=P011\ndevice_type=1-0050F204-1\n'+
            b'driver_param=mta_p2p_initial=1 control_port=0\n')
        if raw==expected: bi=100  # Pinned src/ap/ap_config.c fallback via ap.c; not measured BI.
        elif raw.startswith(expected) and re.fullmatch(b'beacon_int=[1-9][0-9]{0,4}\n',raw[len(expected):]):
            bi=int(raw[len(expected)+11:-1])
            if not 15<=bi<=65535: _fail('native_config_invalid')
        else: _fail('native_config_invalid')
        anchors=self._anchors(path)
        if self._config_raw is not None and (raw!=self._config_raw or metadata!=self._config_meta or anchors!=self._config_anchors):
            _fail('native_config_changed')
        self._config_raw,self._config_meta,self._config_anchors,self._go_beacon_interval=raw,metadata,anchors,bi
        ctrl=self.deployment.manifest.ctrl; self._anchors(ctrl+'/unused')
        m=self._path_metadata(ctrl)
        if not stat.S_ISDIR(m[2]) or m[3:5]!=(0,0) or stat.S_IMODE(m[2])!=0o700: _fail('native_ctrl_directory_unowned')
        return bi
    def validate_config(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline); self._config(); return None
    def _durable(self,phase,cleanup=False):
        self._owner()
        canonical=self.store.current
        if canonical is None or not self.store._canonical_history or self.store._canonical_history[-1] is not canonical or \
                canonical.issuer is not self.store.issuer or canonical.record.phase!=phase or self.store.publication_unknown or \
                not cleanup and (self.store.restore_attempted or self.store.failure is not None): _fail('native_durable_intent_missing')
        self.store._set_scope(self._scope,cleanup); self.store._fresh(); self._check()
        # Full stage boundary checks the actual SAME F task set through the
        # original bound ProcReader. IO midway uses only original/clock/pipe
        # gates, not recursive full-baseline/Proc per packet or file chunk.
        observed=self._proc(self.entry.actor.pid,self.entry.actor)
        if observed.actor.key()!=self.entry.actor.key() or not observed.actor.live() or len(observed.actor.tasks)!=1:
            _fail('native_f_identity_changed')
        if self.store.current is not canonical: _fail('native_canonical_changed')
        return canonical
    def _scan_bss(self,row,family,station,frequency,bssid):
        if re.fullmatch(b'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',bssid) is None: _fail('native_station_bssid_unavailable')
        mac=bytes(int(v,16) for v in bssid.split(b':'))
        records,request=self._request(row,family,32,_attr(3,struct.pack('<I',station.ifindex)),0x300)
        candidates=[]
        for cmd,raw in records:
            if cmd!=34: _fail('native_bss_invalid')  # NEW_SCAN_RESULTS, not TRIGGER_SCAN.
            f=_fields(raw)
            if 3 not in f or _u(f[3])!=station.ifindex or 47 not in f: _fail('native_bss_invalid')
            b=_fields(f[47][1])
            if f[47][0] not in (0,0x8000): _fail('native_bss_invalid')
            if b.get(1)!=(0,mac): continue
            if not {2,4,9}<=set(b) or _u(b[2])!=frequency or _u(b[9])!=1: continue
            bi=_u(b[4],2)
            if not 15<=bi<=65535: _fail('native_bss_invalid')
            candidates.append((bi,raw))
        if len(candidates)!=1: _fail('native_station_beacon_unavailable')
        return candidates[0]
    def _caps(self,row,family,phy):
        features,request=self._request(row,family,95)
        if len(features)!=1 or features[0][0]!=95: _fail('native_caps_invalid')
        f=_fields(features[0][1])
        if 173 not in f: _fail('native_caps_invalid')
        bits=_u(f[173])
        attrs=_attr(1,struct.pack('<I',phy))+(_attr(174,b'') if bits&1 else b'')
        rows,request=self._request(row,family,1,attrs,0x300)
        scalars,frequencies,generations={}, {},set()
        fragments=[]
        for command,raw in rows:
            if command!=3: _fail('native_caps_invalid')
            f=_fields(raw)
            if 1 not in f or _u(f[1])!=phy: _fail('native_caps_phy_changed')
            fragments.append(raw)
            if 46 in f: generations.add(_u(f[46]))
            for key in (32,50,120,121):
                if key in f:
                    if key in scalars and scalars[key]!=f[key]: _fail('native_caps_inconsistent')
                    scalars[key]=f[key]
            if 22 in f:
                for band,bflags,braw in _nested(f[22]):
                    bf=_fields(braw)
                    if bflags not in (0,0x8000): _fail('native_caps_invalid')
                    if 1 not in bf: continue
                    for index,flags,fraw in _nested(bf[1]):
                        if flags not in (0,0x8000): _fail('native_caps_invalid')
                        ff=_fields(fraw)
                        if 1 not in ff: _fail('native_caps_invalid')
                        freq=_u(ff[1])
                        if freq in frequencies and frequencies[freq]!=ff: _fail('native_caps_inconsistent')
                        frequencies[freq]=ff
        if not fragments or len(generations)>1 or not {32,50,120}<=set(scalars): _fail('native_caps_incomplete')
        types=[]
        for kind,flags,raw in _nested(scalars[32]):
            if not 1<=kind<=12: _fail('native_caps_iftype_unknown')
            _flag((flags,raw)); types.append(kind)
        if len(set(types))!=len(types) or not {2,8,9}<=set(types): _fail('native_caps_go_unsupported')
        software=[]
        # Linux emits software-iftypes only if nonempty. Complete split dump
        # omission is an empty set, not a fabricated supported-iftype grant.
        if 121 in scalars:
            for kind,flags,raw in _nested(scalars[121]):
                if not 1<=kind<=12: _fail('native_caps_iftype_unknown')
                _flag((flags,raw)); software.append(kind)
        if len(set(software))!=len(software): _fail('native_caps_invalid')
        commands=[]
        for index,flags,raw in _nested(scalars[50]): commands.append(_u((flags,raw)))
        if len(set(commands))!=len(commands) or not {6,7,8,15,16}<=set(commands): _fail('native_caps_command_unsupported')
        combinations=[]
        for index,flags,raw in _nested(scalars[120]):
            if flags not in (0,0x8000): _fail('native_caps_invalid')
            f=_fields(raw)
            if not {1,2,4}<=set(f) or set(f)-set(range(1,8)): _fail('native_caps_constraint_unknown')
            maximum,channels=_u(f[2]),_u(f[4])
            if not 1<=maximum<=32 or not 1<=channels<=32: _fail('native_caps_invalid')
            limits=[];seen=set()
            for li,lf,lr in _nested(f[1]):
                if lf not in (0,0x8000): _fail('native_caps_invalid')
                fields=_fields(lr)
                if set(fields)!={1,2}: _fail('native_caps_constraint_unknown')
                n=_u(fields[1]);ts=[]
                for kind,kf,kv in _nested(fields[2]):
                    if not 1<=kind<=12 or kind in seen: _fail('native_caps_invalid')
                    _flag((kf,kv));ts.append(kind);seen.add(kind)
                if not 1<=n<=32 or not ts: _fail('native_caps_invalid')
                limits.append((n,tuple(ts)))
            if not limits or len(limits)>16: _fail('native_caps_invalid')
            match=_flag(f[3]) if 3 in f else False
            gcd=_u(f[7]) if 7 in f else None
            if gcd is not None and not 1<=gcd<=65535: _fail('native_caps_invalid')
            # No radar operation is requested. Omission of optional UAPI radar
            # masks is normal v4.14; nonzero masks remain facts, not permission.
            for k in (5,6):
                if k in f: _u(f[k])
            combinations.append((maximum,channels,tuple(limits),match,gcd))
        if not combinations or len(combinations)>16: _fail('native_caps_go_unsupported')
        return tuple(fragments),frequencies,tuple(software),tuple(combinations)
    def _combo(self,interfaces,phy,role,software,combinations,station_bi,go_bi):
        rows=[r for r,f,m in interfaces if r.phy==phy and r.iftype not in software]
        if self.owned is not None:
            rows=[r for r in rows if r.key()[:4]!=self.owned.key()[:4]]
        counts={}
        for row in rows: counts[row.iftype]=counts.get(row.iftype,0)+1
        if role not in software: counts[role]=counts.get(role,0)+1
        # More than the one already-associated stock STA on the measured phy
        # needs a genuine measured channel source, not a guessed one-channel
        # assertion. This first slice therefore refuses that unknown topology.
        if any(r.iftype!=2 or r.name!='wlan0' for r in rows): _fail('native_caps_topology_unassessed')
        for maximum,channels,limits,match,gcd in combinations:
            covered=set(t for n,ts in limits for t in ts)
            if sum(counts.values())>maximum or channels<1 or set(counts)-covered: continue
            if any(sum(counts.get(t,0) for t in ts)>n for n,ts in limits): continue
            if match and station_bi!=go_bi: continue
            if gcd is not None:
                a,b=station_bi,go_bi
                while b: a,b=b,a%b
                if a<gcd: continue
            return
        _fail('native_caps_go_combo_unavailable')
    def _channel_read(self):
        bi=self._config()
        interfaces=self._interfaces();station=tuple((r,f,m) for r,f,m in interfaces if r.name=='wlan0' and r.iftype==2)
        if len(station)!=1: _fail('native_station_unavailable')
        r,frequency,mac=station[0]
        actors=self._actors();status,fields,reported=self._stock_status(actors)
        if frequency!=reported or self.baseline is None or frequency!=self.baseline.snapshot.station_frequency or \
                r.key()!=self.baseline.snapshot.station.key(): _fail('native_station_channel_changed')
        row=self._socket(16)
        try:
            family=self._family(row);station_bi,bss_raw=self._scan_bss(row,family,r,frequency,fields.get(b'bssid',b''))
            raw,freqs,software,combinations=self._caps(row,family,r.phy)
            f=freqs.get(frequency)
            if f is None or any(k in f for k in (2,3,5,14,16)) or set(f)-set(range(1,18)):
                _fail('native_channel_ir_unavailable')
            # 2.4GHz only; measured station/BSS frequency, never the requested
            # GROUP_ADD frequency as evidence of the operating channel.
            if frequency not in range(2412,2473,5): _fail('native_channel_unavailable')
            self._combo(interfaces,r.phy,8,software,combinations,station_bi,bi)
            self._combo(interfaces,r.phy,9,software,combinations,station_bi,bi)
            # Assessed facts exclude BSS age/TSF; full actual BSS is retained
            # separately in the original private kernel datagram inventory.
            channel_raw=struct.pack('<IHH',frequency,station_bi,bi)+fields[b'bssid']+b''.join(_attr(k,v) for k,(flags,v) in sorted(f.items()))
            return GoChannelObservation(self,frequency,raw,channel_raw,station_bi,bi)
        finally: self._close(row)
    def observe_channel(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.channel is not None or self.baseline is None: _fail('native_channel_already_issued')
            self._durable('watchdog_live');self.baseline_current(self.baseline,_absolute_deadline)
            first=self._channel_read();second=self._channel_read();self.observations.extend((first,second))
            if (first.frequency,first.channel_sha256,first.caps_sha256)!=(second.frequency,second.channel_sha256,second.caps_sha256):
                _fail('native_channel_unstable')
            self.channel=second;return second
    def channel_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoChannelObservation or original is not self.channel: _fail('native_channel_not_original')
        current=self._channel_read();self.observations.append(current)
        if (current.frequency,current.channel_sha256,current.caps_sha256)!=(original.frequency,original.channel_sha256,original.caps_sha256):
            _fail('native_channel_changed')
        return original
    def reserve_interface(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.interface_ticket is not None or self.create_row is not None: _fail('native_interface_already_issued')
            self._durable('watchdog_live')
            row=self._socket(16);self.create_row=row
            try:
                family=self._family(row);sequence=self._next()
                ticket=core.InterfaceTicket(self.entry.boot,self.baseline.snapshot.station.phy,self.deployment.manifest.ifname,sequence,row.port)
                self.interface_ticket=ticket;self._create_family=family;self._create_until=self._scope;self._create_sequence=sequence
                return ticket
            except BaseException:
                self._close(row);raise
    def interface_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not core.InterfaceTicket or original is not self.interface_ticket or self._create_called or \
                self.create_row is None or original.port_id!=self.create_row.port or original.sequence!=self._create_sequence:
            _fail('native_interface_not_original')
        self._fd_current(self.create_row)
        if original.boot!=self.entry.boot or original.phy!=self.baseline.snapshot.station.phy or original.name!=self.deployment.manifest.ifname:
            _fail('native_interface_not_original')
        if self._stable_snapshot().key()!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return original
    def create_interface(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self._create_called or self.interface_ticket is None or self.create_row is None: _fail('native_create_unavailable')
            canonical=self._durable('interface_intent');ticket=self.interface_ticket
            if canonical.record.interface_intent.key()!=ticket.key() or self._scope>self._create_until: _fail('native_create_intent_changed')
            self._fd_current(self.create_row)
            attrs=_attr(1,struct.pack('<I',ticket.phy))+_attr(4,ticket.name.encode('ascii')+b'\0')+_attr(5,struct.pack('<I',8))
            self._create_called=True
            try:
                records,request=self._request(self.create_row,self._create_family,7,attrs,4|8,ticket.sequence)
                self.create_request=request
                if len(records)!=1 or records[0][0]!=7: _fail('native_create_echo_missing')
                echo=self._create_echo_original
                if echo is None or echo[0] != request or echo[1] is not ticket or echo[3] != records[0][1]:
                    _fail('native_create_echo_missing')
                owned=echo[2];self.owned=owned  # Publish ONLY after actual complete ACK+ECHO.
                if owned.iftype!=8 or owned.phy!=ticket.phy or owned.name!=ticket.name or \
                        any(r.wdev==owned.wdev or r.ifindex==owned.ifindex or r.name==owned.name for r in self.baseline.snapshot.interfaces):
                    _fail('native_create_origin_changed')
                self.origin_current(owned,_absolute_deadline)
                return owned
            finally: self._close(self.create_row)
    def origin_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not core.Origin or original is not self.owned or original.iftype!=8 or not self._create_called or self.create_request is None:
            _fail('native_origin_not_original')
        current=self._stable_snapshot()
        if self._outside_key(current,original)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return original
    def observe_group_source(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.group_source is not None or self.owned is None: _fail('native_group_source_unavailable')
            self._durable('controller_live');self.origin_current(self.owned,_absolute_deadline)
            channel=self._channel_read();self.observations.append(channel)
            value=GoGroupSource(self,channel);self.group_source=value;self.observations.append(value)
            return value
    def group_source_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoGroupSource or original is not self.group_source or original.channel not in self.observations:
            _fail('native_group_source_not_original')
        current=self._channel_read();self.observations.append(current)
        if (current.frequency,current.channel_sha256,current.caps_sha256)!=(original.frequency,original.channel_sha256,original.caps_sha256):
            _fail('native_group_source_changed')
        return original
    def _controller(self):
        launcher=self.owner.launcher;ticket=self.owner.controller
        launch=self.deployment.modules['mta_go_process_owner']
        if type(launcher) is not launch.GoDirectChildOwner or launcher is not self.store._launcher_original or \
                type(ticket) is not launch.ChildTicket or ticket is not self.owner.controller or ticket.spec is not self.deployment.controller_spec:
            _fail('native_controller_not_original')
        launch.GoDirectChildOwner._exact(launcher,ticket)
        if ticket.unknown or not ticket.released or ticket.postexec is None or ticket.waited: _fail('native_controller_unavailable')
        observed=self._proc(ticket.pid,ticket.postexec)
        if observed.actor.key()!=ticket.postexec.key() or not observed.actor.live(): _fail('native_controller_changed')
        facts=self.store.current.record.controller
        if facts is None or facts.phase!='live' or facts.actor.key()!=ticket.postexec.key(): _fail('native_controller_not_durable')
        return ticket.postexec
    def open_control(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.command_row is not None or self.event_row is not None: _fail('native_control_already_open')
            self._durable('controller_live');self._config();actor=self._controller()
            peer=self.deployment.manifest.ctrl+'/'+self.owned.name
            anchors=self._anchors(peer);metadata=inode=None
            for unused in range(2048):
                self._check()
                if self._anchors(peer)!=anchors: _fail('native_ctrl_directory_changed')
                try: metadata=self._path_metadata(peer)
                except OSError as error:
                    if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
                    self._retain(('controller_endpoint_absent', error))
                    self.io.pause(min(.01,self._scope-self._check()))
                    self._check();continue
                if not stat.S_ISSOCK(metadata[2]) or metadata[3:5]!=(0,0) or metadata[5]!=1: _fail('native_ctrl_unowned')
                if self._controller() is not actor: _fail('native_controller_changed')
                inode=self._unix_owner(peer,actor)
                if self._path_metadata(peer)!=metadata or self._anchors(peer)!=anchors: _fail('native_ctrl_changed')
                self._check();break
            if inode is None: _fail('native_controller_endpoint_unavailable')
            self._server_original=(peer,metadata,actor,inode)  # Before either channel factory.
            # Two real native datagram channels, original controller path/
            # socket inode/Proc PID source and credential-authenticated replies.
            self.command_row=self._unix(peer,actor,True)
            self.event_row=self._unix(peer,actor,True)
            self._ctrl_actor=actor
            if self.command_row.peer_meta!=self.event_row.peer_meta: _fail('native_control_changed')
            if self._exchange(self.event_row,b'ATTACH')!=b'OK\n': _fail('native_attach_failed')
            return None
    def _group_status(self):
        self._controller();raw=self._exchange(self.command_row,b'STATUS');f=_status(raw)
        if f.get(b'wpa_state')!=b'COMPLETED' or f.get(b'mode')!=b'AP' or \
                re.fullmatch(b'[0-9]{4}',f.get(b'freq',b'')) is None: _fail('native_go_status_unavailable')
        frequency=int(f[b'freq'])
        interfaces=self._interfaces();rows=tuple((r,k,m) for r,k,m in interfaces if r.key()[:4]==self.owned.key()[:4])
        if len(rows)!=1 or rows[0][0].iftype!=9 or rows[0][1]!=frequency or frequency!=self.group_source.frequency:
            _fail('native_go_origin_changed')
        origin,kfreq,mac=rows[0]
        if mac is None or f.get(b'bssid',b'').lower()!=b':'.join(('%02x' % x).encode('ascii') for x in mac):
            _fail('native_go_bssid_changed')
        current=self._stable_snapshot()
        if self._outside_key(current,origin)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return raw,frequency,origin
    def submit_group_add(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self._group_submit_called or self.group_source is None or self.command_row is None or self.event_row is None:
                _fail('native_group_submit_unavailable')
            canonical=self._durable('group_add_intent');facts=None if canonical.record.group_add is None else dict(canonical.record.group_add)
            self.group_source_current(self.group_source,_absolute_deadline);self.origin_current(self.owned,_absolute_deadline)
            self._controller();wire=('P2P_GROUP_ADD freq=%d' % self.group_source.frequency).encode('ascii')
            if facts is None or facts['frequency']!=self.group_source.frequency or facts['command_sha256']!=hashlib.sha256(wire).hexdigest() or \
                    facts['channel_sha256']!=self.group_source.channel_sha256 or facts['caps_sha256']!=self.group_source.caps_sha256:
                _fail('native_group_intent_changed')
            self._group_submit_called=True  # Before actual native send, no retry.
            if self._exchange(self.command_row,wire)!=b'OK\n': _fail('native_group_submit_failed')
            return None
    def wait_group(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if not self._group_submit_called or self.group is not None: _fail('native_group_event_unavailable')
            self._durable('group_add_intent');event=None
            for unused in range(64):
                raw=self._ctrl_recv(self.event_row)
                eventraw=re.sub(b'^<[0-4]>',b'',raw)
                if eventraw.startswith((b'P2P-GROUP-REMOVED ',b'P2P-GROUP-FORMATION-FAILURE',b'CTRL-EVENT-TERMINATING')):
                    _fail('native_group_event_failed')
                if not eventraw.startswith(b'P2P-GROUP-STARTED '): continue
                # WPA2.12 p2p_supplicant.c event layout, private bytes only. Do
                # not split quoted SSID or persist credential strings to disk.
                match=re.match(b'^P2P-GROUP-STARTED (mta[0-9a-f]{8}) GO ssid="(?:\\\\.|[^"\\\\])*" freq=([0-9]{4})(?: |$)',eventraw)
                if match is None or match.group(1)!=self.owned.name.encode('ascii') or int(match.group(2))!=self.group_source.frequency:
                    _fail('native_group_event_mismatch')
                event=raw;break
            if event is None: _fail('native_group_event_limit')
            first,freq,origin=self._group_status();second,sfreq,sorigin=self._group_status()
            if (freq,origin.key())!=(sfreq,sorigin.key()): _fail('native_group_unstable')
            value=GoGroupObservation(self,event,second,sfreq,sorigin);self.group=value;self.observations.append(value)
            self._check();return value
    def group_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoGroupObservation or original is not self.group or original not in self.observations or \
                not self._group_submit_called or original.observed_origin.key()[:4]!=self.owned.key()[:4] or original.observed_origin.iftype!=9:
            _fail('native_group_not_original')
        raw,freq,origin=self._group_status()
        if freq!=original.frequency or origin.key()!=original.observed_origin.key(): _fail('native_group_changed')
        return original
    def prepare_cleanup(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('restore_intent',True)
            if self._group_submit_called and not self._group_remove_called and self.command_row is not None:
                self._group_remove_called=True
                try:
                    self._controller()
                    wire=b'P2P_GROUP_REMOVE '+self.owned.name.encode('ascii')
                    reply=self._exchange(self.command_row,wire)
                    if reply not in (b'OK\n',b'FAIL\n'): _fail('native_group_remove_unknown')
                except BaseException as error:
                    # Observation failure is retained. Same original process
                    # TERM/absence + exact original netdev deletion/readback are
                    # still needed; FAIL/timeout is not unmutated restoration.
                    self.failure=error
            errors=[]
            for row in (self.command_row,self.event_row,self.create_row):
                if row is not None and not row.closed:
                    try: self._close(row,_absolute_deadline)
                    except BaseException as error: errors.append(error)
            if errors: raise errors[0]
            return None
    def stop_child(self,ticket,_absolute_deadline):
        """Actual original direct-child TERM/wait/Proc absence, never killall/KILL."""
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('restore_intent',True)
            launch=self.deployment.modules['mta_go_process_owner'];launcher=self.owner.launcher
            if type(launcher) is not launch.GoDirectChildOwner: _fail('native_child_source_changed')
            launch.GoDirectChildOwner._exact(launcher,ticket)
            if ticket.fork_negative or not ticket.fork_requested:
                launcher.close_inventory(ticket,_absolute_deadline=_absolute_deadline)
                return None
            if ticket.unknown or ticket.preexec is None or ticket.pid is None: _fail('native_child_stop_pending')
            if not ticket.waited:
                if ticket not in self._termination:
                    observed=None
                    try: observed=self._proc(ticket.pid,ticket.postexec or ticket.preexec)
                    except BaseException as error: self.failure=error
                    if observed is not None and observed.actor.live():
                        expected=ticket.postexec or ticket.preexec
                        if (observed.actor.pid,observed.actor.start)!=(expected.pid,expected.start): _fail('native_child_stop_changed')
                        row={'ticket':ticket,'actor':observed.actor,'requested':True,'returned':None,'unknown':True}
                        self._termination[ticket]=row
                        returned=self.io.kill_term(ticket.pid);row['returned']=returned;row['unknown']=returned is not None
                        self._check()
                        if row['unknown']: _fail('native_child_term_unknown')
                if launcher.wait_reap(ticket,timeout=min(2.0,self._scope-self._check()),_absolute_deadline=self._scope) is not True:
                    _fail('native_child_wait_pending')
            if launcher.fresh_exit(ticket,_absolute_deadline=self._scope) is not True: _fail('native_child_absence_pending')
            launcher.close_inventory(ticket,_absolute_deadline=self._scope)
            if any(not row.closed or row.unknown for row in ticket.fds): _fail('native_child_fd_pending')
            return None
    def stop_child_only(self,ticket):
        """Original registered direct child only, WITHOUT uncertain RF authority.

        No scalar deadline input, GO canonical, GROUP_REMOVE, netlink operation,
        marker clear or logical restore. Unknown/unverified original children
        are not signalled by PID. Each independently known local FD may still
        be closed by the original launcher once under the SAME cleanup period.
        """
        with self.mutex:
            self._owner();module=self.deployment.modules['mta_go_bootstrap']
            end=module.GoBootstrap._cleanup_period_current(self.owner,self)
            self._scope,self._scope_cleanup=end,True;self._now(end)
            self.entry.accounting._io_deadline=end
            launch=self.deployment.modules['mta_go_process_owner'];launcher=self.owner.launcher
            if type(launcher) is not launch.GoDirectChildOwner or launcher is not self.store._launcher_original:
                _fail('native_child_source_changed')
            launch.GoDirectChildOwner._exact(launcher,ticket)
            if ticket in self._stop_only_calls: _fail('native_child_stop_only_already_attempted')
            self._stop_only_calls.add(ticket);errors=[];original_error=None
            try:
                if ticket is not self.owner.controller and ticket is not self.owner.watchdog: _fail('native_child_source_changed')
                if ticket.fork_negative or not ticket.fork_requested: return None
                if ticket.unknown or ticket.preexec is None or not ticket.fork_returned or \
                        type(ticket.preexec) is not core.Actor or type(ticket.parent) is not core.Actor or \
                        ticket.parent.key()!=self.entry.actor.key() or ticket.boot!=self.entry.boot or \
                        not _int(ticket.pid,1,0x7fffffff) or ticket.pid!=ticket.preexec.pid or \
                        not ticket.preexec.live() or len(ticket.preexec.tasks)!=1 or \
                        (ticket.preexec.exe,ticket.preexec.argv_sha)!=(ticket.parent.exe,ticket.parent.argv_sha):
                    _fail('native_child_stop_only_unverified')
                proc=self.deployment.modules['mta_client_proc']
                if not any(type(g.observation) is proc.ProcObservation and g.observation.actor is ticket.preexec and
                        g.observation.boot==ticket.boot and g.observation.kind=='live_actor' and
                        g.observation.same_boot is True and g.observation.passes==2 and
                        g.observation.resource_pending is False and self.entry.reader.owns_generation(g)
                        for g in self.entry.reader._history): _fail('native_child_stop_only_unverified')
                if not ticket.waited:
                    # Current two-pass original Proc producer, no expected old
                    # preexec key which could turn a valid exec transition into
                    # a fabricated match or erase a failed observation.
                    observed=self._proc(ticket.pid)
                    self._stop_only_observations.append((ticket,observed))
                    actor=observed.actor
                    allowed=((ticket.preexec.exe,ticket.preexec.argv_sha),(ticket.spec.exe,ticket.spec.argv_sha))
                    if (actor.pid,actor.start)!=(ticket.preexec.pid,ticket.preexec.start) or \
                            (actor.exe,actor.argv_sha) not in allowed or len(actor.tasks)!=1 or \
                            ticket.postexec is not None and actor.key()!=ticket.postexec.key():
                        _fail('native_child_stop_only_changed')
                    if actor.live() and ticket not in self._termination:
                        self._check()
                        row={'ticket':ticket,'actor':actor,'requested':True,'returned':None,'unknown':True}
                        self._termination[ticket]=row  # BEFORE same original once TERM.
                        try:
                            result=self.io.kill_term(ticket.pid);row['returned']=result;row['unknown']=result is not None
                            self._check()
                            if row['unknown']: _fail('native_child_term_unknown')
                        except BaseException as error:
                            row['error']=error;errors.append(error)
                    try:
                        if launcher.wait_reap(ticket,timeout=min(2.0,end-self._check()),_absolute_deadline=end) is not True:
                            _fail('native_child_wait_pending')
                    except BaseException as error: errors.append(error)
                if ticket.waited:
                    try:
                        if launcher.fresh_exit(ticket,_absolute_deadline=end) is not True: _fail('native_child_absence_pending')
                    except BaseException as error: errors.append(error)
                if errors: raise errors[0]
            except BaseException as error:
                original_error=error
                self._stop_only_failures.append((ticket,error));raise
            finally:
                # Original FD creator/metadata/once-close path only. Do not skip
                # this local attempt because current Proc or publication failed.
                try:
                    if launcher.close_inventory(ticket,_absolute_deadline=end) is not True:
                        _fail('native_child_fd_pending')
                except BaseException as error:
                    self._stop_only_failures.append((ticket,error))
                    if original_error is None: raise
            return None
    def _close_server_endpoint(self):
        if self._server_absent: return
        controller=self.owner.controller
        if controller is None or not controller.fork_requested or controller.fork_negative:
            if self._server_original is not None: _fail('native_ctrl_server_pending')
            self._server_absent=True;return
        if not controller.waited or controller.exit_verified is not True: _fail('native_ctrl_server_pending')
        peer=self.deployment.manifest.ctrl+'/'+self.owned.name
        original=self._server_original
        if original is not None and (original[0]!=peer or original[2] is not controller.postexec): _fail('native_ctrl_server_changed')
        try: before=self._path_metadata(peer)
        except OSError as error:
            if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
            self._server_absent=True;return
        # A controller which never yielded an authenticated server inode can
        # prove absence after reap, but cannot adopt/unlink a pathname by name.
        if original is None or before!=original[1] or self._server_unlink_called: _fail('native_ctrl_server_changed')
        self._server_unlink_called=True
        if self.io.unlink(peer) is not None: _fail('native_ctrl_server_pending')
        try: self.io.stat(peer)
        except OSError as error: self._server_absent=type(error.errno) is int and error.errno==errno.ENOENT
        if not self._server_absent: _fail('native_ctrl_server_pending')
        self._check()
    def delete_interface(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('restore_intent',True)
            if self._delete_called: _fail('native_delete_already_attempted')
            controller=self.owner.controller
            if controller is not None and controller.fork_requested and not controller.fork_negative and \
                    (not controller.waited or controller.exit_verified is not True):
                _fail('native_controller_still_live')
            self._close_server_endpoint()
            if not self._create_called:
                # Durable interface-intent without submission still uses real
                # baseline/readback and inventory, not old rfFalse bypass.
                if self._stable_snapshot().key()!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
                return None
            if self.owned is None or self.create_request is None: _fail('native_create_pending')
            current=self._stable_snapshot()
            match=tuple(r for r in current.interfaces if r.key()[:4]==self.owned.key()[:4])
            if len(match)!=1 or match[0].iftype not in (8,9) or self._outside_key(current,match[0])!=self.baseline.snapshot.key():
                _fail('native_delete_origin_pending')
            row=self._socket(16)
            try:
                family=self._family(row);self._delete_called=True
                self._request(row,family,8,_attr(153,struct.pack('<Q',self.owned.wdev)),4)
            finally: self._close(row)
            first=self._stable_snapshot()
            if first.key()!=self.baseline.snapshot.key(): _fail('native_delete_readback_pending')
            return None
    def observe_restore(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('restore_intent',True)
            if self.restored is not None: _fail('native_restore_already_issued')
            snapshot=self._stable_snapshot()
            if self.baseline is None or snapshot.key()!=self.baseline.snapshot.key(): _fail('native_baseline_not_restored')
            if any(not a or not c for a,c in self.closed_facts()): _fail('native_resource_pending')
            value=GoNativeRestoreObservation(self,snapshot);self.restored=value;self.observations.append(value);return value
    def restore_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline,True)
        if type(original) is not GoNativeRestoreObservation or original is not self.restored or original not in self.observations:
            _fail('native_restore_not_original')
        if self._stable_snapshot().key()!=original.snapshot.key() or any(not a or not c for a,c in self.closed_facts()):
            _fail('native_restore_pending')
        return original
    def close_known_inventory(self,_absolute_deadline):
        with self.mutex:
            self._owner();end=sources._time(_absolute_deadline)
            if self.store.restore_until is not None and end>self.store.restore_until: _fail('native_cleanup_scope_invalid')
            failures=[]
            for row in self._history:
                needs_raw=row.returned and not row.closed and not row.attempted and not row.unknown
                needs_endpoint=row.returned and row.closed and row.bound and not row.endpoint_closed and not row.unlink_called and not row.unknown
                if needs_raw or needs_endpoint:
                    try: self._close(row,end)
                    except BaseException as error: failures.append(error)
            if failures: raise failures[0]
            return self.closed_facts()
    def closed_facts(self):
        if self.rows is not self._rows_original or tuple(self.rows)!=self._history: return ((True,False),)
        facts=tuple((r.attempted,r.closed and not r.unknown and r.endpoint_closed) for r in self._history)
        if self._ancillary_unknown: facts+=((True,False),)
        if self.owner.controller is not None: facts+=((self._server_unlink_called or self._server_absent,self._server_absent),)
        return facts
    def status(self):
        return {'interface_echo_observed':self._create_echo_original is not None,
            'interface_echo_ack':self.owned is not None and self.create_request is not None,
            'group_observed':self.group is not None,'native_closed':all(a and c for a,c in self.closed_facts()),
            'go_ready':False,'ip_ready':False,'dhcp_ready':False,'send_ready':False,
            'device_tested':False,'phone_tested':False}
