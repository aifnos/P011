"""Concrete, private ARM CLIENT RF-init adapter; not a transfer capability.

Constructors are pure. Explicit methods perform bounded Linux calls only for
the current B/Owner/bridge. No GO, association, SCAN, DHCP, address or data API.
An externally reviewed fixed manifest is required; this is not its verifier.
Unknown originals stay strongly referenced and are never blindly reclosed.
"""
import errno
import hashlib
import math
import os
import re
import signal
import socket
import stat
import struct
import sys
import threading
import time

import mta_client_baseline as baseline
import mta_client_caps_transport as caps_transport
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_proc as proc
import mta_client_process_owner as processes
import mta_client_pending as pending
import mta_client_launch_registration as launches
import mta_client_store as stores
import mta_client_two_phase_lease as phases
import mta_client_wpa_status as original_status
import mta_p2p_client_init as core

ARM_READ, ARM_DIR = 0x80000 | 0x8000, 0x80000 | 0x8000 | 0x4000
MAX_ROWS, MAX_OBSERVERS, MAX_PROC_CALLS = 64, 32, 512
MAX_FD_RECEIPTS = 32768
_NL, _GENL = struct.Struct('<IHHII'), struct.Struct('<BBH')
_CRED = struct.Struct('=iII')
_OWNERS = []  # Registered before the first action, never discarded on failure.
_KEYS = frozenset(('version', 'run_token', 'candidate_sha', 'ifname', 'baseline_manifest',
    'status_manifest', 'wpa_exe', 'wpa_sha', 'python_exe', 'python_sha',
    'executor_path', 'executor_sha'))
_REASONS = frozenset(('not_started', 'unavailable', 'invalid_manifest', 'wrong_owner',
    'deadline', 'clock_unknown', 'platform', 'resource_unknown', 'close_unknown',
    'unsafe_directory', 'file_changed', 'config_exists', 'config_unknown', 'actor_unknown',
    'baseline_changed', 'kernel_reply', 'kernel_error', 'interface_unknown',
    'ambiguous_create', 'origin_changed', 'ctrl_unknown', 'ctrl_invalid', 'prior_blocked',
    'restore_unknown', 'child_stop_unknown', 'mutation_sealed', 'interrupted', 'io_error'))


class LinuxProviderError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _REASONS else 'io_error'
        RuntimeError.__init__(self, self.code)


def _fail(code):
    raise LinuxProviderError(code) from None


def _int(value, low=0, high=0xffffffff):
    return type(value) is int and low <= value <= high


def _hex(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _path(value):
    return type(value) is str and 1 < len(value) <= 256 and value.startswith('/') and \
        all(p not in ('', '.', '..') for p in value[1:].split('/')) and \
        all(32 <= ord(c) < 127 for c in value)


class ProviderManifest(object):
    """Private immutable normalization, not producer authentication or pin proof."""
    __slots__ = tuple(_KEYS) + ('run_dir', 'ctrl_dir', 'cfg', 'identity', 'manifest_sha256')

    def __init__(self, value, _manifest_sha256=None):
        if type(value) is not dict or set(value) != _KEYS or type(value['version']) is not int or \
                value['version'] != 1 or not _hex(value['run_token'], 32) or \
                not _hex(value['candidate_sha'], 64) or not _hex(_manifest_sha256, 64) or \
                type(value['ifname']) is not str or re.fullmatch('mta[0-9a-f]{8}', value['ifname']) is None:
            _fail('invalid_manifest')
        for name in ('wpa_exe', 'python_exe', 'executor_path'):
            if not _path(value[name]): _fail('invalid_manifest')
        for name in ('wpa_sha', 'python_sha', 'executor_sha'):
            if not _hex(value[name], 64): _fail('invalid_manifest')
        if type(value['status_manifest']) is not dict or value['wpa_sha'] != core.WPA_SHA or \
                value['wpa_exe'] == value['status_manifest'].get('daemon_exe'):
            _fail('invalid_manifest')
        pins = value['baseline_manifest']
        if type(pins) not in (tuple, list) or len(pins) != 4 or any(type(r) not in (tuple, list) or
                len(r) != 2 or not _path(r[0]) or not _hex(r[1], 64) for r in pins): _fail('invalid_manifest')
        pins = tuple(tuple(r) for r in pins)
        if len(set(r[0] for r in pins)) != 4 or \
                tuple(sorted(r for r in pins if r[0] != baseline.CLI)) != tuple(sorted(core.STOCK_PINS)):
            _fail('invalid_manifest')
        status = original_status._manifest(value['status_manifest'])
        run = '/tmp/' + coordination.BASE + '/' + coordination.RUN_PREFIX + value['run_token']
        for name in _KEYS:
            item = pins if name == 'baseline_manifest' else tuple(sorted(status.items())) if name == 'status_manifest' else value[name]
            object.__setattr__(self, name, item)
        for name, item in (('run_dir', run), ('ctrl_dir', run + '/ctrl'), ('cfg', run + '/client.conf'),
                           ('identity', core.Identity(value['candidate_sha'])), ('manifest_sha256', _manifest_sha256)):
            object.__setattr__(self, name, item)

    def __setattr__(self, name, value): raise AttributeError('private immutable manifest')
    def __repr__(self): return '<private CLIENT provider manifest>'


class _ArmIo(original_status._LinuxIo):
    def __init__(self): self._at = files._LinuxIo()
    def validate(self):
        super(_ArmIo, self).validate()
        if getattr(os, 'O_DIRECTORY', None) != 0x4000 or getattr(os, 'O_DIRECT', None) != 0x10000:
            _fail('platform')

    def flag(self, name): return getattr(os, name)
    def open_at(self, parent, name, flags, mode=0):
        # Existing reviewed FILES binding supplies libc openat on target Python.
        return self._at.open_at(parent, name, flags, mode)
    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def write(self, fd, raw): return os.write(fd, raw)
    def fsync(self, fd): return os.fsync(fd)
    def seek(self, fd): return os.lseek(fd, 0, 0)
    def new_genl(self): return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    def new_ctrl(self): return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    def kill(self, pid): return os.kill(pid, signal.SIGTERM)
    def pid(self): return os.getpid()


class _Row(object):
    def __init__(self, kind):
        self.kind, self.value, self.fd, self.meta = kind, None, None, None
        self.close_meta = None  # Only narrowly authenticated own ctrl rmdir.
        self.returned = self.attempted = self.closed = False
        self.unknown = True

    def __repr__(self): return '<private CLIENT resource>'


class _Ledger(object):
    def __init__(self, io): self.io, self.rows, self.pending = io, [], False
    def new(self, kind):
        if len(self.rows) >= MAX_ROWS: _fail('resource_unknown')
        row = _Row(kind); self.rows.append(row); return row
    def adopt(self, row, value):
        row.value, row.returned = value, True
        row.fd = value if row.kind != 'socket' else value.fileno()
        if not _int(row.fd, 3, 0x7fffffff) or any(r is not row and not r.closed and r.fd == row.fd for r in self.rows):
            self.pending = True; _fail('resource_unknown')
        row.meta = baseline._metadata(self.io.fstat(row.fd))
        row.unknown = False; return row
    def open(self, path, flags):
        row = self.new('file')
        try: value = self.io.open(path, flags)
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def open_at(self, parent, name, flags, mode=0):
        row = self.new('file')
        try: value = self.io.open_at(parent.fd, name, flags, mode)
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def sock(self, creator):
        row = self.new('socket')
        try: value = creator()
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        row.value, row.returned = value, True  # Before fileno or other validation.
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def ebadf(self, row):
        if row.unknown or not row.closed: return False
        if row.fd is None: return row.returned is False
        try: self.io.fstat(row.fd)
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: pass
        return False
    def close(self, row):
        if row.attempted or row.closed: return self.ebadf(row)
        if row.unknown or row.meta is None: self.pending = True; return False
        row.attempted = True
        try:
            now = baseline._metadata(self.io.fstat(row.fd))
            if now[:6] != (row.meta[:6] if row.close_meta is None else row.close_meta): _fail('close_unknown')
            result = row.value.close() if row.kind == 'socket' else self.io.close(row.fd)
            if result is not None or row.kind == 'socket' and row.value.fileno() != -1: _fail('close_unknown')
            try: self.io.fstat(row.fd)
            except OSError as e:
                row.closed = type(e.errno) is int and e.errno == errno.EBADF
            if not row.closed: _fail('close_unknown')
        except BaseException: row.unknown = self.pending = True
        return row.closed and not row.unknown
    def close_all(self):
        good = True
        for row in self.rows:
            try: good = self.close(row) and good
            except BaseException: self.pending = True; good = False
        return good and not self.pending
    def component_closed(self, row, attempted):
        # A pinned component is the single close owner, never close it again.
        row.attempted = attempted is True
        try:
            row.closed = row.attempted and row.value.fileno() == -1
            if row.closed:
                try: self.io.fstat(row.fd); row.closed = False
                except OSError as e: row.closed = type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: row.closed = False
        if not row.closed: row.unknown = self.pending = True
        return row.closed and not row.unknown


def _attr(kind, data):
    raw = struct.pack('<HH', len(data) + 4, kind) + data
    return raw + b'\0' * (-len(raw) % 4)


def _origin(body):
    fields = {}
    for kind, flags, value, raw in caps_transport._attrs(body):
        if kind in fields: _fail('kernel_reply')
        fields[kind] = (flags, value)
    if not {1, 3, 4, 5, 153}.issubset(fields): _fail('kernel_reply')
    values = []
    for kind, width in ((1, 4), (153, 8), (3, 4), (5, 4)):
        flags, raw = fields[kind]
        if flags or len(raw) != width: _fail('kernel_reply')
        values.append(struct.unpack('<Q' if width == 8 else '<I', raw)[0])
    flags, name = fields[4]
    if flags or not 2 <= len(name) <= 16 or name[-1:] != b'\0' or b'\0' in name[:-1]: _fail('kernel_reply')
    try: text = name[:-1].decode('ascii')
    except UnicodeError: _fail('kernel_reply')
    return core.Origin(values[0], values[1], values[2], text, values[3])


def _caps_core(decoded):
    """Lossless conversion of the real immutable transport result only."""
    c = caps_transport.caps
    if type(decoded) is not c.DecodedCaps or len(decoded.phys) != 1: _fail('interface_unknown')
    phys = []
    for phy in decoded.phys:
        if type(phy) is not c.Phy or not all((phy.iftypes_present, phy.software_iftypes_present,
                phy.combinations_present, phy.commands_present)) or not {7, 8} <= set(phy.commands): _fail('interface_unknown')
        combinations = []
        for combo in phy.combinations:
            if type(combo) is not c.Combination or not combo.radar_widths_present or not combo.radar_regions_present or \
                    not combo.bi_min_gcd_present or combo.bi_min_gcd != 1: _fail('interface_unknown')
            combinations.append({'max_interfaces': combo.maximum, 'num_channels': combo.channels,
                'limits': tuple({'max': row.maximum, 'types': row.types} for row in combo.limits),
                'radar_widths': combo.radar_widths, 'radar_regions': combo.radar_regions,
                'beacon_match': combo.beacon_match})
        phys.append({'index': phy.index, 'iftypes': phy.iftypes, 'software_iftypes': phy.software_iftypes,
            'combinations': tuple(combinations), 'unknown_constraints': ()})
    return {'complete': True, 'phys': tuple(phys)}


class _Kernel(object):
    """One owned unicast socket. CREATE must receive ECHO and matching ACK."""
    def __init__(self, provider):
        self.p, self.row, self.family, self.port, self.seq = provider, None, None, None, 0
        self.requests, self.packets = [], []  # Private bounded diagnostic bytes.
    def open(self, deadline):
        if self.row is not None: return
        self.row = self.p._ledger.sock(self.p._io.new_genl)
        raw = self.row.value; raw.set_inheritable(False)
        if raw.get_inheritable() is not False: _fail('resource_unknown')
        raw.bind((0, 0)); endpoint = raw.getsockname()
        if type(endpoint) is not tuple or len(endpoint) != 2 or not _int(endpoint[0], 1) or endpoint[1] != 0:
            _fail('kernel_reply')
        self.port = endpoint[0]
        rows = self.request(16, 3, _attr(2, b'nl80211\0'), 0, deadline)
        if len(rows) != 1: _fail('kernel_reply')
        self.family = caps_transport._family(rows[0][1])
    def reserve(self):
        if self.seq >= 0xffffffff: _fail('kernel_reply')
        self.seq += 1; return self.seq
    def request(self, family, cmd, attrs, flags, deadline, sequence=None):
        self.p._now(deadline)
        sequence = self.reserve() if sequence is None else sequence
        if sequence != self.seq or not _int(self.port, 1): _fail('kernel_reply')
        version = 2 if family == 16 else 1
        dumping = flags & 0x300 == 0x300
        request = _NL.pack(20 + len(attrs), family, 1 | flags, sequence, self.port) + _GENL.pack(cmd, version, 0) + attrs
        if len(self.requests) >= 64: _fail('kernel_reply')
        self.requests.append(request)
        if self.row.value.sendto(request, (0, 0)) != len(request): _fail('kernel_reply')
        result, ack, done, total = [], False, False, 0
        for unused in range(64):
            remaining = self.p._now(deadline)
            self.row.value.settimeout(remaining)
            timeout = self.row.value.gettimeout()
            if type(timeout) not in (int, float) or not 0 < timeout <= remaining + 0.000000001: _fail('kernel_reply')
            packet, ancillary, bits, sender = self.row.value.recvmsg(262144)
            self.p._now(deadline)
            if type(packet) is not bytes or not packet or ancillary or bits or type(sender) is not tuple or sender != (0, 0):
                _fail('kernel_reply')
            self.packets.append(packet); total += len(packet)
            if total > 1048576: _fail('kernel_reply')
            at = 0
            while at < len(packet):
                if len(packet) - at < 16: _fail('kernel_reply')
                n, kind, nflags, seq, port = _NL.unpack_from(packet, at); end = at + ((n + 3) & ~3)
                if n < 16 or end > len(packet) or seq != sequence or port != self.port or nflags & 16:
                    _fail('kernel_reply')
                body = packet[at + 16:at + n]; at = end
                if kind == 2:
                    if ack or len(body) < 20 or body[4:20] != request[:16]: _fail('kernel_reply')
                    code = struct.unpack_from('<i', body)[0]
                    if code > 0 or code < -4095: _fail('kernel_reply')
                    if code: _fail('kernel_error')
                    if not flags & 4: _fail('kernel_reply')
                    ack = True
                elif kind == 3:
                    if done or not dumping or body not in (b'', b'\0' * 4): _fail('kernel_reply')
                    done = True
                else:
                    if kind != family or len(body) < 4 or body[1:4] != bytes((version, 0, 0)): _fail('kernel_reply')
                    result.append((body[0], body[4:]))
            if dumping:
                if done: return result
            elif flags & 8:
                if ack and len(result) == 1: return result
                if len(result) > 1: _fail('ambiguous_create')
            elif flags & 4:
                if ack and not result: return result
                if result: _fail('kernel_reply')
            elif len(result) == 1: return result
        _fail('kernel_reply')
    def interfaces(self, deadline):
        self.open(deadline)
        rows = self.request(self.family, 5, b'', 0x300, deadline)
        if not rows or len(rows) > 32 or any(cmd != 7 for cmd, body in rows): _fail('kernel_reply')
        result = tuple(_origin(body) for cmd, body in rows)
        for getter in (lambda r: r.name, lambda r: r.wdev, lambda r: r.ifindex):
            if len(set(getter(r) for r in result)) != len(result): _fail('kernel_reply')
        return result


class _ObservationIo(_ArmIo):
    """Only same-owner issued controller may be excluded from stock enumeration."""
    def __init__(self, provider): self.p = provider
    def listdir(self, path):
        names = self.p._io.listdir(path)
        if path != '/proc': return names
        excluded = self.p._private_pids()
        return [name for name in names if name not in excluded]
    def __getattribute__(self, name):
        if name in ('p', 'listdir', '__class__', '__dict__', '__getattribute__', 'validate'):
            return object.__getattribute__(self, name)
        return getattr(object.__getattribute__(self, 'p')._io, name)
    def validate(self): return self.p._io.validate()


class _AuthenticatedCollector(baseline.BaselineCollector):
    def __init__(self, provider, timeout):
        self.p, self.status_readers = provider, []
        super(_AuthenticatedCollector, self).__init__(provider.manifest.baseline_manifest,
            timeout=timeout, _io=_ObservationIo(provider), _clock=provider._clock,
            _reader=provider._proc_factory(timeout=timeout, _clock=provider._clock))
    def _open(self, path, flags=None):
        return super(_AuthenticatedCollector, self)._open(path, ARM_READ if flags is None else flags)
    def _status(self, unused_executable):
        remaining = self._deadline - self._now()
        if remaining < 0.1: _fail('deadline')
        row = {'reader': None, 'unknown': True, 'value': None}; self.status_readers.append(row)
        source = original_status.LinuxStatusSource(dict(self.p.manifest.status_manifest),
            _io=_ObservationIo(self.p), _clock=self.p._clock)
        row['source'] = source
        reader = self.p._status_factory(dict(self.p.manifest.status_manifest), source,
            timeout=min(3, remaining), _io=_ObservationIo(self.p), _clock=self.p._clock)
        row['reader'] = reader
        result = reader.read_status(self._deadline); row['value'] = result
        state = reader.status()
        if type(result) is not dict or reader._result is not result or result.get('source_authenticated') is not True or \
                result.get('completed') is not True or not _int(result.get('frequency'), 2412, 2484) or \
                state.get('read_success') is not True or state.get('resource_pending') is not False or \
                state.get('socket_closed') is not True: _fail('baseline_changed')
        row['unknown'] = False
        return result['digest'], result['frequency']


class LinuxClientInitProvider(phases.TwoPhaseClientInitProvider):
    """Explicit trusted adapter; default manifest=None cannot perform actions."""
    def __init__(self, manifest=None, _io=None, _proc_factory=None, _collector_factory=None,
                 _status_factory=None, _caps_factory=None, _clock=None):
        if manifest is not None and type(manifest) is not ProviderManifest: _fail('invalid_manifest')
        self.manifest = manifest
        self._io, self._clock = _io or _ArmIo(), _clock or time.monotonic
        self._proc_factory = _proc_factory or proc.ProcReader
        self._collector_factory = _collector_factory or _AuthenticatedCollector
        self._status_factory = _status_factory or original_status.AuthenticatedStatusReader
        self._caps_factory = _caps_factory or caps_transport.ClientCapsReader
        self.cancelled = threading.Event()
        self._ledger, self._kernel = _Ledger(self._io), _Kernel(self)
        self._store = self._owner = self._bridge = self._lease = None
        self._self = self._boot = self._baseline_record = self._owned = self._intent = None
        self._proc_calls, self._collectors, self._caps_readers = [], [], []
        self._tickets, self._prior, self._restores = {}, [], []
        self._run_anchor = self._ctrl_anchor = self._config = None
        self._anchor_chain, self._anchor_requested = [], False
        self._ctrl_deinit_observation = None
        self._fd_receipts = []
        self._ctrl = None
        self._ctrl_setup = self._ctrl_failed = self._ctrl_receive_unknown = False
        self._ctrl_incoming, self._ctrl_rights = [], []
        self._last = self._deadline = None
        self._started = self._sealed = self._close_requested = self._unknown = False
        self._create_requested = self._delete_requested = False
        self._reason = 'not_started'
    def __repr__(self): return '<private Linux CLIENT provider>'
    def _now(self, deadline=None):
        value = self._clock()
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)) or \
                self._last is not None and value < self._last: _fail('clock_unknown')
        self._last = float(value)
        if deadline is None: return float(value)
        if type(deadline) not in (int, float) or not math.isfinite(float(deadline)) or not 0 < deadline - value <= 20:
            _fail('deadline')
        return float(deadline - value)
    def _begin(self, deadline, mutating=False, allow_pending=False):
        if self.manifest is None or self._store is None: _fail('unavailable')
        if mutating and self._sealed: _fail('mutation_sealed')
        if not allow_pending and (self._unknown or self._ledger.pending or self._ctrl_receive_unknown or any(r['unknown'] for r in
                self._proc_calls + self._collectors + self._caps_readers)): _fail('resource_unknown')
        self._now(deadline); self._deadline = deadline
        if not self._started:
            if len(_OWNERS) >= 1 and not any(p is self for p in _OWNERS): _fail('resource_unknown')
            _OWNERS.append(self); self._started = True
            self._io.validate()
        if mutating and self._store.lock_valid(self._store._current_locks) is not True: _fail('wrong_owner')
    def attach(self, store, owner, bridge, lease=None):
        if self._store is not None or type(store) is not stores.DurableClientInitStore or \
                type(owner) is not processes.DirectChildOwner or type(bridge) is not LinuxDirectChildLaunchBridge or \
                bridge.store is not store or bridge.owner is not owner or bridge.provider is not self or \
                store._identity.key() != self.manifest.identity.key() or lease is not None and \
                (type(lease) is not LinuxClientInitLease or lease.provider is not self or lease.store is not store or lease.bridge is not bridge):
            _fail('wrong_owner')
        self._store, self._owner, self._bridge, self._lease = store, owner, bridge, lease
    def specs(self):
        if self.manifest is None: _fail('unavailable')
        m = self.manifest
        return (processes.LaunchSpec('watchdog', m.python_exe,
            (m.python_exe, '-B', m.executor_path, '--watchdog', '--run-token', m.run_token,
             '--manifest-sha256', m.manifest_sha256, '--ttl', '20'), (), m.python_sha),
            processes.LaunchSpec('controller', m.wpa_exe,
            (m.wpa_exe, '-Dnl80211', '-i' + m.ifname, '-c' + m.cfg, '-C' + m.ctrl_dir),
            (('MTA_PRIVATE_P2P', '1'),), m.wpa_sha))
    def _observe(self, pid=None, expected=None, absence=False):
        if len(self._proc_calls) >= MAX_PROC_CALLS: _fail('actor_unknown')
        row = {'reader': None, 'value': None, 'unknown': True}; self._proc_calls.append(row)
        reader = self._proc_factory(timeout=min(3, self._now(self._deadline)), _clock=self._clock)
        row['reader'] = reader
        value = reader.read_absence(expected, self._boot) if absence else reader.read_self() if pid is None else reader.read_actor(pid, expected)
        row['value'] = value
        # Resource state is separate from an opaque/non-live actor result.
        if type(value) is proc.ProcObservation and value.resource_pending is False and \
                value.closed_count == value.file_count and self._remember_proc(reader, value):
            row['unknown'] = False
        if type(value) is not proc.ProcObservation or value.resource_pending is not False or value.same_boot is not True or \
                value.passes != 2 or value.closed_count != value.file_count: _fail('actor_unknown')
        if not absence and (value.kind != 'live_actor' or type(value.actor) is not core.Actor or not value.actor.live()):
            _fail('actor_unknown')
        if self._boot is not None and value.boot != self._boot: _fail('actor_unknown')
        row['unknown'] = False; return value
    def executor(self, deadline):
        self._begin(deadline)
        value = self._observe()
        if len(value.actor.tasks) != 1 or value.actor.pid != self._io.pid(): _fail('actor_unknown')
        if self._self is None: self._self, self._boot = value.actor, value.boot
        if value.actor.key() != self._self.key(): _fail('wrong_owner')
        return core.ExecutorProof('owner', value.actor, False)
    def _private_pids(self):
        if self._owner is None: return ()
        result = []
        for child in self._owner._tickets:
            if child.spec.role != 'controller' or child.postexec is None: continue
            self._owner._exact(child)
            if child.waited:
                if child.exit_verified is not True: _fail('actor_unknown')
                continue
            if child.unknown or child.spec.exe != self.manifest.wpa_exe or child.spec.sha != self.manifest.wpa_sha:
                _fail('actor_unknown')
            observed = self._observe(child.pid, child.postexec)
            if observed.actor.key() != child.postexec.key(): _fail('actor_unknown')
            result.append(str(child.pid))
        return tuple(result)
    def snapshot(self, deadline):
        self._begin(deadline)
        if len(self._collectors) >= MAX_OBSERVERS: _fail('resource_unknown')
        row = {'reader': None, 'value': None, 'unknown': True}; self._collectors.append(row)
        reader = self._collector_factory(self, min(5, self._now(deadline))); row['reader'] = reader
        value = reader.collect(deadline); row['value'] = value
        state = reader.status()
        if type(value) is not core.Snapshot or state.get('read_success') is not True or \
                state.get('resource_pending') is not False or state.get('closed_count') != state.get('resource_count'):
            _fail('baseline_changed')
        if any(r is not row and r['value'] is value for r in self._collectors): _fail('baseline_changed')
        if self._boot is not None and value.boot != self._boot: _fail('baseline_changed')
        if self._baseline_record is None: self._baseline_record = value
        if not self._remember_collector(reader): _fail('close_unknown')
        row['unknown'] = False; return value
    def caps(self, deadline):
        self._begin(deadline)
        if self._baseline_record is None or len(self._caps_readers) >= 8: _fail('interface_unknown')
        row = {'reader': None, 'value': None, 'unknown': True, 'socket': None}; self._caps_readers.append(row)
        def creator(family, kind, protocol):
            if (family, kind, protocol) != (16, 3, 16) or row['socket'] is not None: _fail('interface_unknown')
            claimed = self._ledger.sock(self._io.new_genl); row['socket'] = claimed
            return claimed.value
        reader = self._caps_factory(self._baseline_record.station.phy, timeout=min(5, self._now(deadline)),
            clock=self._clock, socket_factory=creator)
        row['reader'] = reader
        try: value = reader.read(); row['value'] = value
        finally:
            if row['socket'] is not None:
                self._ledger.component_closed(row['socket'], reader._finished and reader._created)
                if row['socket'].closed: self._remember(self._io, row['socket'].fd, row['socket'])
        state = reader.status()
        if type(value) is not caps_transport.caps.DecodedCaps or state.get('read_success') is not True or state.get('socket_closed') is not True or \
                state.get('resource_pending') is not False: _fail('interface_unknown')
        row['unknown'] = False
        result = _caps_core(value)
        core.client_combo(result, self._baseline_record)
        return result
    def original_actors(self, baseline_value, deadline):
        self._begin(deadline)
        if type(baseline_value) is not core.Snapshot: _fail('baseline_changed')
        for actor in baseline_value.stock_actors:
            if self._observe(actor.pid, actor).actor.key() != actor.key(): _fail('actor_unknown')
        return True
    def register(self, role, identity, boot, deadline):
        self._begin(deadline, True)
        if type(identity) is not core.Identity or identity.key() != self.manifest.identity.key() or \
                boot != self._boot or role not in ('watchdog', 'controller') or role in self._tickets: _fail('wrong_owner')
        if role == 'controller': self._prepare_config(deadline)
        spec = next(s for s in self.specs() if s.role == role)
        ticket = core.Ticket(self.manifest.run_token, role, boot, spec.exe, spec.argv_sha)
        self._tickets[role] = ticket; return ticket
    def _anchors(self, deadline):
        if self._anchor_requested:
            if self._ctrl_anchor is None: _fail('unsafe_directory')
            return self._verify_anchors(deadline)
        self._anchor_requested = True
        root = self._ledger.open('/', ARM_DIR)
        if not stat.S_ISDIR(root.meta[2]) or root.meta[3:5] != (0, 0) or root.meta[2] & 0o022:
            _fail('unsafe_directory')
        self._anchor_chain.append((None, '/', root))
        current = root
        for name, private in (('tmp', False), (coordination.BASE, True),
                              (coordination.RUN_PREFIX + self.manifest.run_token, True), ('ctrl', True)):
            self._now(deadline)
            before = baseline._metadata(self._io.stat_at(current.fd, name))
            child = self._ledger.open_at(current, name, ARM_DIR)
            mode = stat.S_IMODE(child.meta[2])
            self._anchor_chain.append((current, name, child))
            if before != child.meta or not stat.S_ISDIR(child.meta[2]) or child.meta[3:5] != (0, 0) or \
                    private and mode != 0o700 or not private and mode & 0o022 and not mode & stat.S_ISVTX:
                _fail('unsafe_directory')
            if name == coordination.RUN_PREFIX + self.manifest.run_token: self._run_anchor = child
            current = child
        self._ctrl_anchor = current
        self._verify_anchors(deadline)
    def _verify_anchors(self, deadline):
        if len(self._anchor_chain) != 5 or self._ctrl_anchor is None: _fail('unsafe_directory')
        for parent, name, row in self._anchor_chain:
            self._now(deadline)
            actual = baseline._metadata(self._io.fstat(row.fd))
            path = self._io.stat('/') if parent is None else self._io.stat_at(parent.fd, name)
            if row.unknown or row.closed or actual[:6] != row.meta[:6] or \
                    baseline._metadata(path)[:6] != row.meta[:6]: _fail('unsafe_directory')
    def _prepare_config(self, deadline):
        if self._config is not None or self._owned is None: _fail('config_unknown')
        self._anchors(deadline)
        payload = b'ctrl_interface=' + self.manifest.ctrl_dir.encode('ascii') + b'\n' + core.CLIENT_CONFIG
        try: row = self._ledger.open_at(self._run_anchor, 'client.conf', ARM_READ | 1 | 0x40 | 0x80, 0o600)
        except OSError as e:
            if e.errno == errno.EEXIST: _fail('config_exists')
            raise
        self._config = row
        if not stat.S_ISREG(row.meta[2]) or row.meta[3] != 0 or row.meta[5] != 1 or stat.S_IMODE(row.meta[2]) != 0o600:
            _fail('config_unknown')
        if self._io.write(row.fd, payload) != len(payload) or self._io.fsync(row.fd) is not None: _fail('config_unknown')
        # Exact readback uses a separate original read FD, never reuses write-only.
        readback = self._ledger.open_at(self._run_anchor, 'client.conf', ARM_READ)
        if self._io.read(readback.fd, len(payload) + 1) != payload or self._io.read(readback.fd, 1) != b'': _fail('config_unknown')
        if baseline._metadata(self._io.fstat(readback.fd))[:7] != baseline._metadata(self._io.fstat(row.fd))[:7]:
            _fail('config_unknown')
        row.meta = baseline._metadata(self._io.fstat(row.fd)); readback.meta = baseline._metadata(self._io.fstat(readback.fd))
        read_ok = self._ledger.close(readback); write_ok = self._ledger.close(row)
        if not read_ok or not write_ok: _fail('close_unknown')
        if self._io.fsync(self._run_anchor.fd) is not None: _fail('config_unknown')
        self._verify_anchors(deadline)
    def register_interface(self, identity, baseline_value, deadline):
        self._begin(deadline, True)
        if self._intent is not None or identity.key() != self.manifest.identity.key() or baseline_value.boot != self._boot:
            _fail('wrong_owner')
        rows = self._kernel.interfaces(deadline)
        if any(r.name == self.manifest.ifname for r in rows) or \
                tuple(sorted(r.key() for r in rows)) != tuple(sorted(r.key() for r in baseline_value.interfaces)):
            _fail('baseline_changed')
        seq = self._kernel.reserve()
        self._intent = core.InterfaceTicket(self._boot, baseline_value.station.phy, self.manifest.ifname, seq, self._kernel.port)
        return self._intent
    def create_client(self, ticket, deadline):
        self._begin(deadline, True)
        if ticket is not self._intent or self._create_requested: _fail('wrong_owner')
        self._create_requested = True
        attrs = _attr(1, struct.pack('<I', ticket.phy)) + _attr(5, struct.pack('<I', 8)) + _attr(4, ticket.name.encode('ascii') + b'\0')
        rows = self._kernel.request(self._kernel.family, 7, attrs, 4 | 8 | 0x600, deadline, ticket.sequence)
        if len(rows) != 1 or rows[0][0] != 7: _fail('ambiguous_create')
        owned = _origin(rows[0][1]); self._owned = owned  # Save before postchecks.
        if (owned.name, owned.phy, owned.iftype) != (ticket.name, ticket.phy, 8) or any(
                owned.name == r.name or owned.ifindex == r.ifindex or owned.wdev == r.wdev for r in self._baseline_record.interfaces):
            _fail('ambiguous_create')
        if not self._origin_exact(owned, deadline): _fail('origin_changed')
        return owned
    def _origin_exact(self, owned, deadline):
        if type(owned) is not core.Origin or owned is not self._owned or owned.iftype != 8: _fail('wrong_owner')
        rows = tuple(r for r in self._kernel.interfaces(deadline) if
            r.name == owned.name or r.ifindex == owned.ifindex or r.wdev == owned.wdev)
        return len(rows) == 1 and rows[0].key() == owned.key()
    def origin_up(self, owned, deadline):
        self._begin(deadline)
        if not self._origin_exact(owned, deadline): return False
        row = self._ledger.open('/sys/class/net/' + owned.name + '/flags', ARM_READ)
        try:
            raw = self._io.read(row.fd, 32)
            if type(raw) is not bytes or re.fullmatch(br'0x[0-9a-f]+\n', raw) is None: _fail('origin_changed')
            return bool(int(raw, 16) & 1)
        finally:
            if not self._ledger.close(row): _fail('close_unknown')
    def live_actor(self, handle, deadline):
        self._begin(deadline); self._handle(handle)
        return self._observe(handle.actor.pid, handle.actor).actor
    def _handle(self, handle):
        if type(handle) is not core.Handle or handle.ticket is not self._tickets.get(handle.ticket.role) or \
                not any(c is handle.resource for c in self._owner._tickets) or handle.resource.postexec is None or \
                handle.resource.postexec.key() != handle.actor.key(): _fail('wrong_owner')
        self._owner._exact(handle.resource); return handle.resource
    def status(self, handle=None, owned=None, deadline=None):
        if handle is None:
            return {'provider_implemented': True, 'attempted': self._started, 'mutation_sealed': self._sealed,
                'resource_pending': self._unknown or self._ledger.pending or any(r['unknown'] for r in
                    self._proc_calls + self._collectors + self._caps_readers), 'reason': self._reason,
                'orphan_recovery': False, 'send_available': False, 'receive_available': False}
        self._begin(deadline); child = self._handle(handle)
        if child.spec.role != 'controller' or not self._origin_exact(owned, deadline): _fail('ctrl_unknown')
        self.live_actor(handle, deadline)
        return self._control(handle, owned, deadline)
    def _control(self, handle, owned, deadline):
        if self._ctrl_failed: _fail('ctrl_unknown')
        self._verify_anchors(deadline)
        if not self._ctrl_setup:
            self._ctrl_setup = True
            try:
                self._ctrl = self._ledger.sock(self._io.new_ctrl)
                raw = self._ctrl.value; raw.set_inheritable(False)
                if raw.get_inheritable() is not False: _fail('ctrl_unknown')
                raw.setsockopt(1, 16, 1)
                if raw.getsockopt(1, 16) != 1: _fail('ctrl_unknown')
                local = b'\0p011-client-' + self.manifest.run_token.encode('ascii')
                raw.bind(local)
                if raw.getsockname() != local: _fail('ctrl_unknown')
                endpoint = self.manifest.ctrl_dir + '/' + owned.name
                before = baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name))
                # Fixed 2.12 ctrl_iface_unix.c chmods interface sockets 0770.
                # This exception is ONLY root:root under the exact 0700 chain.
                if not stat.S_ISSOCK(before[2]) or before[3:5] != (0, 0) or \
                        stat.S_IMODE(before[2]) != 0o770 or before[5] != 1: _fail('ctrl_unknown')
                raw.connect(endpoint)
                if raw.getpeername() != endpoint: _fail('ctrl_unknown')
                self._ctrl_endpoint = (endpoint, before, local)
            except BaseException:
                self._ctrl_failed = True; raise
        raw = self._ctrl.value
        endpoint, before, local = self._ctrl_endpoint
        try:
            if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name)) != before or \
                    raw.getpeername() != endpoint or raw.getsockname() != local: _fail('ctrl_unknown')
            remaining = min(2, self._now(deadline)); raw.settimeout(remaining)
            actual = raw.gettimeout()
            if type(actual) not in (int, float) or not 0 < actual <= remaining + 1e-9: _fail('ctrl_unknown')
            if raw.send(b'STATUS') != 6: _fail('ctrl_unknown')
            self._ctrl_receive_unknown = True
            value = raw.recvmsg(2049, self._io.cmsg_space(_CRED.size) + self._io.cmsg_space(16 * 4), 0x40000000)
            self._ctrl_incoming.append(value)  # Before unpack/flags/FD interpretation.
            if type(value) is not tuple or len(value) != 4: _fail('ctrl_unknown')
            packet, ancillary, flags, address = value
            credential = self._ctrl_controls(ancillary)
            self._now(deadline)
            if type(flags) is not int or flags & (8 | 32) or flags not in (0, 0x40000000):
                self._ctrl_receive_unknown = True; _fail('ctrl_unknown')
            if type(packet) is not bytes or not 1 <= len(packet) <= 2048 or \
                    credential != (handle.actor.pid, 0, 0) or address not in (endpoint, endpoint.encode('ascii')):
                _fail('ctrl_unknown')
            self._verify_anchors(deadline)
            if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name)) != before or \
                    raw.getpeername() != endpoint or raw.getsockname() != local: _fail('ctrl_unknown')
            self.live_actor(handle, deadline); core.parse_init_status(packet)
            return packet
        except BaseException:
            self._ctrl_failed = True; raise
        finally:
            # Rights are rejected, but known installed originals still close.
            for row in self._ctrl_rights:
                self._ledger.close(row)
    def _ctrl_controls(self, controls):
        if type(controls) not in (tuple, list) or len(controls) > 16: _fail('ctrl_unknown')
        credentials, invalid, rights = [], False, False
        for item in controls:
            if type(item) is not tuple or len(item) != 3 or type(item[0]) is not int or \
                    type(item[1]) is not int or type(item[2]) is not bytes:
                invalid = True; continue
            level, kind, data = item
            if (level, kind) == (1, 1):
                rights = True
                if not data or len(data) % 4 or len(data) > 64: invalid = True
                for at in range(0, min(len(data), 64) - len(data) % 4, 4):
                    row = self._ledger.new('file'); self._ctrl_rights.append(row)
                    try: self._ledger.adopt(row, struct.unpack_from('=i', data, at)[0])
                    except BaseException: invalid = True
            elif (level, kind) == (1, 2) and len(data) == _CRED.size:
                credentials.append(_CRED.unpack(data))
            else: invalid = True
        if invalid:
            self._ledger.pending = True; _fail('ctrl_unknown')
        self._ctrl_receive_unknown = False
        if rights or len(credentials) != 1: _fail('ctrl_unknown')
        return credentials[0]
    def request_child_stop(self, child, deadline):
        self._begin(deadline)
        self._owner._exact(child)
        if child not in tuple(op.child for op in self._bridge._operations) or child.unknown or child.postexec is None:
            core._fail('provider_unavailable')
        if child.waited:
            if child.exit_verified is not True: _fail('child_stop_unknown')
            return None
        try: self._observe(child.pid, child.postexec)
        except (proc.ProcReadError, LinuxProviderError):
            # A naturally exited direct child may be a zombie/non-live Actor.
            # Only actual owner wait/reap + fresh entire-task absence permits it.
            if self._owner.wait_reap(child, min(.1, self._now(deadline))) is not True or \
                    self._owner.fresh_exit(child) is not True: _fail('child_stop_unknown')
            return None
        # An unreaped direct child cannot have its PID reassigned. No global kill.
        if self._io.kill(child.pid) is not None: _fail('child_stop_unknown')
        if self._owner.wait_reap(child, min(2, self._now(deadline))) is not True: _fail('child_stop_unknown')
        if self._owner.fresh_exit(child) is not True: _fail('child_stop_unknown')
        return None
    def delete_client(self, owned, deadline):
        self._begin(deadline, True)
        if self._delete_requested or not self.cleanup_origin_ready(owned, deadline):
            _fail('origin_changed')
        self._delete_requested = True
        self._kernel.request(self._kernel.family, 8, _attr(153, struct.pack('<Q', owned.wdev)), 4, deadline)
        return self.origin_absent(owned, deadline)
    def cleanup_origin_ready(self, owned, deadline):
        self._begin(deadline)
        if not self._origin_exact(owned, deadline) or not self._bridge.verify_closed(): return False
        for child in self._owner._tickets:
            if child.fork_requested and not child.fork_negative:
                if child.waited is not True or child.exit_verified is not True or child.postexec is None:
                    return False
                actual = self._observe(child.pid, child.postexec, True)
                if actual.kind != 'absence' or actual.pid_path_absent is not True or actual.remaining_tasks != ():
                    return False
        current = self.snapshot(deadline)
        if current.key(owned) != self._baseline_record.key(): return False
        return self._observe_ctrl_deinit(deadline)
    def _observe_ctrl_deinit(self, deadline):
        # Called ONLY after every exact child actual wait+absence, closed bridge
        # and unchanged full original network. Fixed 2.12 unlinks endpoint then
        # rmdirs ctrl; open original directory FDs may validly have nlink=0.
        if self._ctrl_anchor is None: return True
        self._now(deadline)
        ctrl, run = self._ctrl_anchor, self._run_anchor
        cm, rm = baseline._metadata(self._io.fstat(ctrl.fd)), baseline._metadata(self._io.fstat(run.fd))
        if cm[:5] != ctrl.meta[:5] or rm[:5] != run.meta[:5]: return False
        try: current = baseline._metadata(self._io.stat_at(run.fd, 'ctrl'))
        except OSError as e:
            if type(e.errno) is not int or e.errno != errno.ENOENT: return False
            current = None
        if current is not None:
            return current[:6] == cm[:6] == ctrl.meta[:6] and rm[:6] == run.meta[:6]
        controllers = [c for c in self._owner._tickets if c.spec.role == 'controller' and
            c.spec.exe == self.manifest.wpa_exe and c.spec.sha == self.manifest.wpa_sha]
        if len(controllers) != 1 or controllers[0].postexec is None or controllers[0].waited is not True or \
                controllers[0].exit_verified is not True: return False
        if ctrl.meta[5] != 2 or cm[5] != 0 or run.meta[5] < 3 or rm[5] != run.meta[5] - 1:
            return False
        try: self._io.stat_at(ctrl.fd, self.manifest.ifname)
        except OSError as e:
            if type(e.errno) is not int or e.errno != errno.ENOENT: return False
        else: return False
        if self._ctrl_deinit_observation is not None and self._ctrl_deinit_observation != (cm[:6], rm[:6]): return False
        self._ctrl_deinit_observation = (cm[:6], rm[:6])
        ctrl.close_meta, run.close_meta = cm[:6], rm[:6]
        return True
    def origin_absent(self, owned, deadline):
        self._begin(deadline)
        if owned is not self._owned: _fail('wrong_owner')
        return not any(r.name == owned.name or r.ifindex == owned.ifindex or r.wdev == owned.wdev
            for r in self._kernel.interfaces(deadline))
    def _remember(self, io, fd, owner):
        # Capture actual immediate EBADF before a later registered open can
        # legitimately reuse this number. This is NOT a current close request.
        if not _int(fd, 0, 0x7fffffff) or not self._fd_absent(io, fd): return False
        if not any(i is io and n == fd and o is owner for i, n, o in self._fd_receipts):
            if len(self._fd_receipts) >= MAX_FD_RECEIPTS: _fail('close_unknown')
            self._fd_receipts.append((io, fd, owner))
        return True
    def _remember_proc(self, reader, value):
        return len(reader._fd_refs) == value.file_count and all(self._remember(fs, fd, reader)
            for fs, fd in reader._fd_refs)
    def _remember_collector(self, reader):
        value = reader._reader
        if len(value._fd_refs) < value._files or value._pending or value._closed != value._files: return False
        good = all(self._remember(fs, fd, value) for fs, fd in value._fd_refs)
        for row in reader._tickets:
            if row['fd'] is not None:
                good = row['attempted'] and row['closed'] and not row['unknown'] and \
                    self._remember(reader._io, row['fd'], row) and good
        for row in reader.status_readers:
            r, source = row.get('reader'), row.get('source')
            if row['unknown'] or r is None or source is None: return False
            if r._socket_fd is not None:
                good = r._socket_attempted and r._socket_closed and self._remember(r._io, r._socket_fd, r) and good
            for item in r._rights:
                good = item['attempted'] and item['closed'] and not item['unknown'] and \
                    self._remember(r._io, item['fd'], item) and good
            for group in source._files:
                for item in group._tickets:
                    if item['fd'] is not None:
                        good = item['attempted'] and item['closed'] and not item['unknown'] and \
                            self._remember(group._io, item['fd'], item) and good
            for call in source._actor_calls:
                observer = call['reader']
                if call['unknown'] or observer is None or observer._pending or observer._files != observer._closed: return False
                good = all(self._remember(fs, fd, observer) for fs, fd in observer._fd_refs) and good
        return good
    def _known_live_fd(self, fd, actual):
        """Only exact *current* registered B/Owner/Provider originals can reuse.

        A matching inode without a live issued owner never suffices. Unknown,
        closed and stale journal tickets are not admitted and are never closed.
        """
        claims = []
        for row in self._ledger.rows:
            if row.fd == fd and not row.closed and not row.unknown and row.meta is not None:
                claims.append((self._io, row.meta[:6] if row.close_meta is None else row.close_meta))
        store = self._store
        if type(store) is stores.DurableClientInitStore:
            c, jf = store._coordination, store._files
            if type(c) is coordination.ClientCoordination:
                for ticket, parent, name, identity, private, temporary in c._anchors:
                    if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown:
                        claims.append((ticket.io, identity))
                locks = store._current_locks
                if locks is not None:
                    for ticket in (locks._device, locks._journal):
                        if ticket.fd == fd and any(t is ticket for t in c._inventory) and not ticket.closed and \
                                not ticket.opening_unknown and ticket.flock_state == 'held' and ticket.identity is not None:
                            claims.append((ticket.io, ticket.identity))
            if type(jf) is files.ClientJournalFiles:
                for ticket, parent, name, identity, private, temporary in jf._anchors:
                    if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown:
                        claims.append((ticket.io, identity))
            marker = store._marker
            if type(marker) is pending.ClientPendingMarker and marker._ticket is not None:
                ticket = marker._ticket
                if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown and marker._durable and marker._metadata is not None:
                    claims.append((ticket.io, marker._metadata[:5]))
        if type(self._owner) is processes.DirectChildOwner:
            for child in self._owner._tickets:
                for ticket in child.fds:
                    if ticket.fd == fd and ticket.returned and not ticket.closed and not ticket.unknown and ticket.metadata is not None:
                        claims.append((self._owner._os, ticket.metadata[:6]))
        # Multiple claimed live originals at one FD would be inconsistent.
        if len(claims) != 1: return False
        io, expected = claims[0]
        try:
            current = baseline._metadata(io.fstat(fd))
            return current == actual and current[:len(expected)] == expected
        except BaseException: return False
    def _closed_fd(self, io, fd, owner):
        if not any(i is io and n == fd and o is owner for i, n, o in self._fd_receipts): return False
        try: actual = baseline._metadata(io.fstat(fd))
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: return False
        return self._known_live_fd(fd, actual)
    def _capture_issued_closed(self, io, fd, original):
        # Called ONLY by the exact new bridge for old pinned close producers.
        # Those original rows are closed solely after close-once + EBADF in
        # the frozen producer. No user bool/number is accepted as that source.
        bridge = self._bridge
        if type(bridge) is not LinuxDirectChildLaunchBridge or bridge.provider is not self or self._owner is not bridge.owner:
            return False
        issued = type(original) is processes._FD and io is bridge.owner._os and any(
            any(r is original for r in c.fds) and c.owner is bridge.owner for c in bridge.owner._tickets) and \
            original.returned and original.closed and original.attempted and not original.unknown and original.metadata is not None
        issued = issued or type(original) is launches._Fd and original.io is io and any(
            r is original for r in bridge.registry._inventory) and original.closed and original.attempted and \
            not original.opening_unknown and original.metadata is not None
        reader = bridge.owner._reader
        issued = issued or original is reader and type(reader) is proc.ProcReader and not reader._pending and \
            reader._open_attempt is None and reader._files == reader._closed and any(i is io and n == fd for i, n in reader._fd_refs)
        if not issued or not _int(fd, 0, 0x7fffffff): return False
        if any(i is io and n == fd and o is original for i, n, o in self._fd_receipts):
            return self._closed_fd(io, fd, original)
        if self._remember(io, fd, original): return True
        try: actual = baseline._metadata(io.fstat(fd))
        except BaseException: return False
        if not self._known_live_fd(fd, actual) or len(self._fd_receipts) >= MAX_FD_RECEIPTS: return False
        self._fd_receipts.append((io, fd, original)); return True
    def _closed_objects(self):
        result, proc_attempted, proc_closed = [], [], []
        for row in self._proc_calls:
            reader = row['reader']; value = row['value']
            proc_attempted.append(reader is not None and type(value) is proc.ProcObservation and
                value.file_count > 0 and value.file_count == len(reader._fd_refs) and value.closed_count == value.file_count)
            proc_closed.append(not row['unknown'] and reader is not None and type(value) is proc.ProcObservation and
                not value.resource_pending and all(self._closed_fd(fs, fd, reader) for fs, fd in reader._fd_refs))
        # The logical handle here is the exact retained ProcReader inventory.
        # Every actual FD inside it is read back; count is not physical FD count.
        if proc_closed: result.append((all(proc_attempted), all(proc_closed)))
        for row in self._collectors:
            reader = row['reader']; state = reader.status() if reader is not None else {}
            ok = not row['unknown'] and state.get('resource_pending') is False and \
                state.get('closed_count') == state.get('resource_count')
            if ok:
                ok = all(r['closed'] and not r['unknown'] and
                    (r['fd'] is None or self._closed_fd(reader._io, r['fd'], r)) for r in reader._tickets)
                ok = ok and all(self._authenticated_closed(s) for s in reader.status_readers)
                observer = reader._reader
                ok = ok and not observer._pending and observer._files == observer._closed and \
                    all(self._closed_fd(fs, fd, observer) for fs, fd in observer._fd_refs)
            attempted = reader is not None and reader._ended and all(r['fd'] is None or r['attempted']
                for r in reader._tickets) and all(s.get('reader') is not None and s['reader']._socket_attempted
                    for s in reader.status_readers)
            result.append((attempted, ok))
        for row in self._caps_readers:
            reader = row['reader']; state = reader.status() if reader is not None else {}
            raw = row.get('socket')
            attempted = raw is not None and raw.attempted
            closed = raw is not None and raw.closed and not raw.unknown and raw.value.fileno() == -1 and \
                self._closed_fd(self._io, raw.fd, raw)
            result.append((attempted, not row['unknown'] and state.get('resource_pending') is False and
                state.get('socket_closed') is True and closed))
        return result
    def _authenticated_closed(self, row):
        reader, source = row.get('reader'), row.get('source')
        if row['unknown'] or reader is None or source is None or source._pending or \
                reader.status()['resource_pending'] is not False or reader.status()['socket_closed'] is not True:
            return False
        if reader._socket is not None and (reader._socket.fileno() != -1 or
                not self._closed_fd(reader._io, reader._socket_fd, reader)): return False
        for group in source._files:
            if group._pending or any(not r['closed'] or r['unknown'] or r['fd'] is not None and
                    not self._closed_fd(group._io, r['fd'], r) for r in group._tickets): return False
        for call in source._actor_calls:
            if call['unknown'] or call['reader'] is None or any(not self._closed_fd(fs, fd, call['reader'])
                    for fs, fd in call['reader']._fd_refs): return False
        return all(r['closed'] and not r['unknown'] and self._closed_fd(reader._io, r['fd'], r)
                   for r in reader._rights)
    @staticmethod
    def _fd_absent(io, fd):
        try: io.fstat(fd)
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: pass
        return False
    def _proof(self):
        # CloseProof counts retained owner handles, NOT fabricated physical FDs.
        # Every concrete FD inside each composite owner is checked separately.
        facts = self._closed_objects()
        returned = [r for r in self._ledger.rows if r.returned]
        if returned or self._ledger.pending:
            facts.append((bool(returned) and all(r.attempted for r in returned),
                not self._ledger.pending and not self._ctrl_receive_unknown and all(r.closed and not r.unknown and
                    self._closed_fd(self._io, r.fd, r) for r in returned)))
        if self._bridge is not None:
            facts.extend((op.inventory_close_requested and self._bridge._registry_close_requested,
                self._bridge.verify_closed()) for op in self._bridge._operations)
        if len(facts) > 128: _fail('close_unknown')
        return core.CloseProof(len(facts), tuple(a for a, c in facts), tuple(c for a, c in facts))
    def close_resources(self, handles, deadline):
        self._begin(deadline, allow_pending=True)
        if type(handles) is not tuple or any(type(h) is not core.Handle for h in handles): _fail('wrong_owner')
        if self._close_requested: _fail('close_unknown')
        self._close_requested = self._sealed = True
        self._ledger.close_all()
        for row in self._ledger.rows:
            if row.returned and row.closed and not row.unknown: self._remember(self._io, row.fd, row)
        return self._proof()
    def closed_resources(self, handles, deadline):
        self._begin(deadline); return self._proof()
    def private_inventory_counts(self):
        """Counts of original descriptor receipts, NOT public descriptor values.

        FD numbers can be reused; counts are issuance records, not distinct
        simultaneous kernel FD slots. This passive method signs no closure.
        """
        return {'observer_fd_receipts': len(self._fd_receipts),
            'provider_fd_receipts': sum(r.returned and r.fd is not None for r in self._ledger.rows),
            'child_fd_receipts': sum(f.returned and f.fd is not None for c in
                (() if self._owner is None else self._owner._tickets) for f in c.fds),
            'registration_fd_receipts': sum(f.fd is not None for f in
                (() if self._bridge is None else self._bridge.registry._inventory))}
    def read_prior(self, store, locks, value, deadline):
        self._begin(deadline)
        if store is not self._store or locks is not store._current_locks or store._marker is not None or \
                store._coordination.read_pending(locks).get('entry_absent_observed') is not True: _fail('prior_blocked')
        # Prior history is not taken over. Unknown or any prior run blocks.
        names = self._io.listdir('/tmp/' + coordination.BASE)
        if type(names) is not list or sorted(names) != [coordination.RUN_PREFIX + self.manifest.run_token]: _fail('prior_blocked')
        current = self.snapshot(deadline)
        if current.key() != value.key(): _fail('baseline_changed')
        self._prior.append((store, locks, value, current)); return current
    def authenticate_prior(self, store, locks, value, actual, deadline):
        self._begin(deadline)
        if not any(s is store and l is locks and v is value and a is actual for s, l, v, a in self._prior):
            _fail('prior_blocked')
        return None
    def read_restore(self, store, locks, record, deadline):
        self._begin(deadline)
        if store is not self._store or locks is not store._current_locks or type(record) is not core.Journal or \
                record.identity.key() != self.manifest.identity.key() or record.ready or \
                record.stage not in ('cleanup_verified', 'reconciled') or not self._sealed or \
                self._owned is not None and self._delete_requested is not True:
            _fail('restore_unknown')
        current = self.snapshot(deadline); proof = self._proof()
        if self._owned is not None and any(r.name == self._owned.name or r.ifindex == self._owned.ifindex or
                r.wdev == self._owned.wdev for r in current.interfaces): _fail('restore_unknown')
        if current.key() != record.baseline.key() or not proof.complete(): _fail('restore_unknown')
        value = (current, proof); self._restores.append((store, locks, record, value)); return value
    def authenticate_restore(self, store, locks, record, value, deadline):
        self._begin(deadline)
        if not any(s is store and l is locks and r is record and v is value for s, l, r, v in self._restores):
            _fail('restore_unknown')
        if not self._proof().complete(): _fail('restore_unknown')
        return None
    def request_stop(self): self.cancelled.set()
    def poll_requests(self):
        if self._owner is None: return False
        found = False
        for child in self._owner._tickets:
            if child.spec.role == 'watchdog' and not child.waited:
                if self._owner.read_requests(child): self.cancelled.set(); found = True
        return found


class LinuxDirectChildLaunchBridge(phases.DirectChildLaunchBridge):
    """Only verification understands *authenticated* current FD reuse.

    All launch, C persistence, gate, once-close and wait actions stay inherited.
    Issued original close producers require exact registry/class and their
    actual close+EBADF branch. Current generation always fresh typed-owner IO.
    """
    def __init__(self, store, owner, specs, provider):
        super(LinuxDirectChildLaunchBridge, self).__init__(store, owner, specs)
        if type(provider) is not LinuxClientInitProvider: core._fail('invalid_provider')
        self.provider, self._generation_unknown = provider, False
    def _capture_closed(self):
        good = True
        for child in self.owner._tickets:
            for row in child.fds:
                if row.closed and row.fd is not None:
                    good = self.provider._capture_issued_closed(self.owner._os, row.fd, row) and good
        for row in self.registry._inventory:
            if row.closed and row.fd is not None:
                good = self.provider._capture_issued_closed(row.io, row.fd, row) and good
        reader = self.owner._reader
        if type(reader) is proc.ProcReader:
            for io, fd in reader._fd_refs:
                good = self.provider._capture_issued_closed(io, fd, reader) and good
        if not good: self._generation_unknown = True
        return good
    def _after(self):
        try: self._capture_closed()
        except BaseException: self._generation_unknown = True
    def prepare(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).prepare(op)
        finally: self._after()
    def launch(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).launch(op)
        finally: self._after()
    def release(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).release(op)
        finally: self._after()
    def resolve(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).resolve(op)
        finally: self._after()
    def _close_child_inventory(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self)._close_child_inventory(op)
        finally: self._after()
    def _close_pregate(self, op, deadline):
        try: return super(LinuxDirectChildLaunchBridge, self)._close_pregate(op, deadline)
        finally: self._after()
    def verify_closed(self):
        with self._mutex:
            if self._generation_unknown: return False
            children = [o.child for o in self._operations if o.child is not None]
            if (self._pending or self.owner._active or self.registry._pending or
                    len(children) != len(self._operations) or len(children) != len(self.owner._tickets) or
                    any(not any(t is child for child in children) for t in self.owner._tickets) or
                    not self._registry_close_requested): return False
            for op in self._operations:
                child = op.child
                if op.prepare_unknown or op.stop_unknown or child.unknown or not op.inventory_closed: return False
                if child.fork_requested and not child.fork_negative:
                    if child.waited is not True or child.exit_verified is not True: return False
                    try:
                        if self.owner.fresh_exit(child) is not True: return False
                    except BaseException: return False
                for row in child.fds:
                    if row.unknown or row.closed is not True: return False
                    if row.fd is None:
                        if row.attempted: return False
                    elif not row.attempted or not self.provider._closed_fd(self.owner._os, row.fd, row): return False
            self._after()
            if self._generation_unknown: return False
            for row in self.registry._inventory:
                if row.opening_unknown or row.closed is not True: return False
                if row.fd is None:
                    if row.attempted: return False
                elif not row.attempted or not self.provider._closed_fd(row.io, row.fd, row): return False
            reader = self.owner._reader
            if type(reader) is proc.ProcReader:
                if reader._pending or any(not self.provider._closed_fd(io, fd, reader) for io, fd in reader._fd_refs): return False
            return True
    def status(self):
        value = super(LinuxDirectChildLaunchBridge, self).status()
        value['resource_pending'] = value['resource_pending'] or self._generation_unknown
        value['generation_unassessed'] = self._generation_unknown
        return value


class LinuxClientInitLease(phases.TwoPhaseClientInitLease):
    """Only teardown origin gate differs: safe owned DOWN is not reported UP."""
    def __init__(self, provider, store, identity, clock, bridge=None):
        core.ClientInitLease.__init__(self, provider, store, identity, clock)
        if type(provider) is not LinuxClientInitProvider or type(store) is not stores.DurableClientInitStore or (bridge is not None and
                (type(bridge) is not LinuxDirectChildLaunchBridge or bridge.store is not store or bridge.provider is not provider)):
            core._fail('invalid_store')
        self.bridge, self.launches, self.returned_handles = bridge, [], []
        self._start_attempted = self._restore_held = False
        self._provider_close_requested = self._provider_close_unknown = False
        self._provider_close = None
    def _restore_slice(self, deadline, seconds=20):
        now = self._now()
        if not 0 < deadline - now <= 60: core._fail('expired')
        return min(deadline, now + seconds)

    def restore(self, timeout=60, inherited=None):
        core._finite(timeout, 'invalid_budget')
        if not 0 < timeout <= 60: core._fail('invalid_budget')
        deadline = self._now() + timeout
        if self.sealed: return self._sealed_status(self._restore_slice(deadline))
        if self.bridge is None: self.reason = 'provider_unavailable'; return self.status()
        with self.store._mutex:
            # The original current/_save/commit paths keep all CAS predicates.
            # Their default short budget is now also beneath this total. This
            # private field is not a caller-provided RF or restoration proof.
            previous_budget = self.store._recovery_deadline
            if previous_budget is not None: core._fail('current_blocked')
            self.store._recovery_deadline = deadline
            try:
                self._known_locks_before_acquire(self._restore_slice(deadline))
                proof = self._executor(self._restore_slice(deadline), inherited=self.locks if inherited is None else inherited)
                if proof.role != 'owner': core._fail('executor_role_forbidden')
                for op in self.launches:
                    for actual in (op.child.preexec, op.child.postexec) if op.child is not None else ():
                        if actual is not None and (proof.actor.pid, proof.actor.start) == (actual.pid, actual.start):
                            core._fail('self_actor_recovery')
                if not self._restore_held:
                    self.locks = self.store.acquire(self.identity, self._restore_slice(deadline), self.locks if inherited is None else inherited)
                    self._restore_held = True
                self.record = self.store.current(self.locks)
                if type(self.record) is not core.Journal or not self._pending_admission(self.record): core._fail('current_blocked')
                if self.record.stage != 'cleanup_intent': self._save(self.record.replace(stage='cleanup_intent', ready=False))
                self._baseline(self._restore_slice(deadline, 5), self.record.owned)
                if self.bridge.cleanup(self.provider, self._restore_slice(deadline, 8)) is not True: core._fail('resource_close_unknown')
                self._baseline(self._restore_slice(deadline, 5), self.record.owned)
                owned = self.record.owned
                if owned is not None:
                    # Durable readback is a value object, not the CREATE owner.
                    issued = self.provider._owned
                    if type(issued) is not core.Origin or type(owned) is not core.Origin or issued.key() != owned.key():
                        core._fail('origin_changed')
                    owned = issued
                if owned is not None:
                    if self.provider.cleanup_origin_ready(owned, self._restore_slice(deadline, 5)) is not True or self.provider.delete_client(owned, self._restore_slice(deadline, 5)) is not True:
                        core._fail('origin_changed')
                    if self.provider.origin_absent(owned, self._restore_slice(deadline)) is not True: core._fail('origin_changed')
                self._baseline(self._restore_slice(deadline, 5))
                if not self._provider_close_requested:
                    self._provider_close_requested = True
                    try: self._provider_close = self.provider.close_resources(tuple(self.handles.values()), self._restore_slice(deadline))
                    except BaseException: self._provider_close_unknown = True; raise
                    if type(self._provider_close) is not core.CloseProof or not self._provider_close.complete():
                        self._provider_close_unknown = True
                if self._provider_close_unknown or type(self._provider_close) is not core.CloseProof or \
                        self._provider_close.expected < len(self.launches) or not self.bridge.verify_closed():
                    core._fail('resource_close_unknown')
                if self.store._restore_reader is None: core._fail('store_unavailable')
                self._baseline(self._restore_slice(deadline, 5))
                self._save(self.record.replace(stage='cleanup_verified', ready=False))
                self._finish_receipt(self.record, True, deadline)
                if self.cleanup_complete: self.reason = 'not_recorded'
            except BaseException as error:
                self.pending = True; self.cleanup_complete = False
                self.reason = error.code if type(error) is core.ClientInitError else 'unexpected_provider_error'
                if not isinstance(error, Exception): raise
            finally:
                self.store._recovery_deadline = previous_budget
        return self.status()
    def status(self):
        value = super(LinuxClientInitLease, self).status()
        value.update({'evidence': 'LINUX_CLIENT_PROVIDER_UNVERIFIED', 'provider_implemented': True,
            'rf_init_possible': self.provider.manifest is not None and not self.provider._sealed,
            'production_provider': False, 'target_verified': False})
        return value


def assemble(manifest):
    """Pure assembly, not deployment, source verification or an RF admission."""
    provider = LinuxClientInitProvider(manifest)
    store = stores.DurableClientInitStore(manifest.run_token, manifest.identity,
        _clock=provider._clock, _restore_reader=provider, _prior_reader=provider)
    owner = processes.DirectChildOwner(_clock=provider._clock)
    bridge = LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
    lease = LinuxClientInitLease(provider, store, manifest.identity, provider._clock, bridge)
    provider.attach(store, owner, bridge, lease)
    return provider, store, owner, bridge, lease
