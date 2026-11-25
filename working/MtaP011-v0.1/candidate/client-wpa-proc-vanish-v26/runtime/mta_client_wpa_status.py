"""Authenticated, one-command original WPA STATUS snapshot; not RF admission.

Pure constructors. A fixed private manifest is mandatory. The concrete Linux
source reuses the existing file ledger and ProcReader, not wpa_cli/subprocess.
Only status() is public-safe. Other records contain private identities/SSID.
"""
import errno
import hashlib
import math
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
import zlib

import mta_client_baseline as baseline
import mta_client_proc as proc
import mta_p2p_client_ctrl as ctrl
import mta_p2p_client_init as core

SOL_SOCKET, SO_PASSCRED, SCM_RIGHTS, SCM_CREDENTIALS = 1, 16, 1, 2
AF_UNIX, SOCK_DGRAM = 1, 2  # Linux UAPI; no Windows optional constants required.
MSG_TRUNC, MSG_CTRUNC, MSG_CMSG_CLOEXEC = 32, 8, 0x40000000
MAX_STATUS, MAX_RIGHTS, MAX_CONFIG = 16384, 253, 1048576
MAX_SOURCE_FILES = 512
MAX_ACTOR_CALLS = 8
_ARM_READ_FLAGS = 0x8000 | 0x80000  # P011 ARM Linux O_NOFOLLOW | O_CLOEXEC
_CRED, _FD = struct.Struct('=iII'), struct.Struct('=i')
_MANIFEST = frozenset(('daemon_exe', 'daemon_sha256', 'endpoint', 'real_uid',
                      'real_gid', 'namespace_kind', 'config_sha256'))
_SOURCE = frozenset(('boot', 'self_actor', 'daemon_actor', 'uid', 'gid', 'image',
                    'endpoint', 'anchors', 'sockfs_inode', 'namespaces',
                    'namespace_profile', 'files_closed', 'resolved_endpoint', 'endpoint_chain'))
_NS = frozenset(('cgroup', 'ipc', 'mnt', 'net', 'pid', 'pid_for_children', 'user', 'uts'))
_REASONS = frozenset(('not_started', 'unavailable', 'invalid_manifest', 'invalid_budget',
    'invalid_clock', 'deadline', 'already_attempted', 'unsupported_platform',
    'source_unknown', 'source_invalid', 'source_changed', 'source_authentication',
    'namespace_invalid', 'image_invalid', 'endpoint_invalid', 'file_budget',
    'actor_unknown', 'socket_unknown', 'socket_identity', 'socket_option',
    'timeout_readback', 'short_send', 'receive_unknown', 'receive_invalid',
    'receive_truncated', 'receive_control', 'credential_mismatch', 'wrong_endpoint',
    'invalid_status', 'rights_rejected', 'rights_unknown', 'close_unknown',
    'read_closed', 'io_error', 'interrupted'))


class WpaStatusError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _REASONS else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise WpaStatusError(code) from None


def _int(value, low=0, high=0x7fffffff):
    return type(value) is int and low <= value <= high


def _number(value, low, high):
    return type(value) in (int, float) and low <= value <= high and math.isfinite(float(value))


def _path(value, limit=256):
    return type(value) is str and 1 < len(value) <= limit and value.startswith('/') and \
        all(p not in ('', '.', '..') for p in value[1:].split('/')) and \
        all(32 <= ord(c) < 127 for c in value)


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _manifest(value):
    if type(value) is not dict or set(value) != _MANIFEST or not _path(value['daemon_exe']) or \
            not _path(value['endpoint'], 107) or not value['endpoint'].endswith('/wlan0') or \
            not _hash(value['daemon_sha256']) or not _int(value['real_uid'], 0, 0xffffffff) or \
            not _int(value['real_gid'], 0, 0xffffffff):
        _fail('invalid_manifest')
    kind = value['namespace_kind']
    if kind not in ('full4_present', 'namespaces_disabled_cgroup_mnt') or \
            (kind == 'full4_present' and value['config_sha256'] is not None) or \
            (kind == 'namespaces_disabled_cgroup_mnt' and not _hash(value['config_sha256'])):
        _fail('invalid_manifest')
    return dict(value)


def _meta(value):
    return baseline._metadata(value)


def _observation(value, single=False):
    if type(value) is not proc.ProcObservation or value.kind != 'live_actor' or \
            type(value.actor) is not core.Actor or not value.actor.live() or value.same_boot is not True or \
            type(value.passes) is not int or value.passes != 2 or value.resource_pending is not False or \
            not _int(value.file_count, 1) or value.closed_count != value.file_count or \
            type(value.closed_count) is not int or value.task_count != len(value.actor.tasks) or \
            type(value.task_count) is not int or single and value.task_count != 1:
        _fail('actor_unknown')
    return value.actor


def _source_key(value, manifest):
    if type(value) is not dict or set(value) != _SOURCE:
        _fail('source_invalid')
    core._boot(value['boot'])
    actors = (value['self_actor'], value['daemon_actor'])
    if any(type(a) is not core.Actor or not a.live() for a in actors) or len(actors[0].tasks) != 1 or \
            actors[1].exe != manifest['daemon_exe'] or value['uid'] != manifest['real_uid'] or \
            value['gid'] != manifest['real_gid'] or not _int(value['uid'], 0, 0xffffffff) or \
            not _int(value['gid'], 0, 0xffffffff):
        _fail('source_invalid')
    image, endpoint = value['image'], value['endpoint']
    if type(image) is not tuple or len(image) != 9 or any(not _int(v, 0, (1 << 64) - 1) for v in image) or \
            not stat.S_ISREG(image[2]) or image[3] != 0 or image[5] != 1 or image[2] & 0o022 or \
            not image[2] & 0o111 or not 1 <= image[6] <= baseline.MAX_FILE or \
            type(endpoint) is not tuple or len(endpoint) != 6 or any(not _int(v, 0, (1 << 64) - 1) for v in endpoint) or \
            not stat.S_ISSOCK(endpoint[2]) or endpoint[3] != 0 or endpoint[5] != 1 or endpoint[2] & 0o002:
        _fail('source_invalid')
    resolved, chain = value['resolved_endpoint'], value['endpoint_chain']
    if not _path(resolved) or type(chain) is not tuple or not 2 <= len(chain) <= 64:
        _fail('source_invalid')
    for row in chain:
        if type(row) is not tuple or len(row) != 3 or not (row[0] == '/' or _path(row[0])) or \
                type(row[1]) is not tuple or len(row[1]) != 6 or \
                any(not _int(v, 0, (1 << 64) - 1) for v in row[1]) or row[1][3] != 0:
            _fail('source_invalid')
        if stat.S_ISLNK(row[1][2]):
            if row[1][5] != 1 or type(row[2]) is not str or not 1 <= len(row[2]) <= 256 or \
                    any(ord(c) < 32 or ord(c) >= 127 for c in row[2]): _fail('source_invalid')
        elif row[2] is not None or (stat.S_ISDIR(row[1][2]) and row[1][2] & 0o022):
            _fail('source_invalid')
        elif not (stat.S_ISDIR(row[1][2]) or stat.S_ISSOCK(row[1][2])): _fail('source_invalid')
    parents = ['/', *('/' + '/'.join(resolved[1:].split('/')[:i])
                    for i in range(1, len(resolved[1:].split('/'))))]
    anchors = value['anchors']
    if type(anchors) is not tuple or len(anchors) != len(parents): _fail('source_invalid')
    for row, name in zip(anchors, parents):
        if type(row) is not tuple or len(row) != 2 or row[0] != name or type(row[1]) is not tuple or \
                len(row[1]) != 6 or any(not _int(v, 0, (1 << 64) - 1) for v in row[1]) or \
                not stat.S_ISDIR(row[1][2]) or row[1][3] != 0 or row[1][2] & 0o022:
            _fail('source_invalid')
    proofs = value['files_closed']
    if not _int(value['sockfs_inode'], 1, (1 << 64) - 1) or type(proofs) is not tuple or \
            not 1 <= len(proofs) <= 4 or any(type(p) is not core.CloseProof or p.expected == 0 or
                not p.complete() for p in proofs) or sum(p.expected for p in proofs) > MAX_SOURCE_FILES:
        _fail('source_invalid')
    rows, profile = value['namespaces'], value['namespace_profile']
    if type(profile) is not dict or set(profile) != {'kind', 'names', 'config_sha256', 'config_namespaces'} or \
            profile['kind'] != manifest['namespace_kind'] or type(rows) is not tuple or not 1 <= len(rows) <= 8:
        _fail('namespace_invalid')
    names = []
    for row in rows:
        if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str or row[0] not in _NS or \
                type(row[1]) is not tuple or len(row[1]) != 2 or row[1][0] != row[1][1]:
            _fail('namespace_invalid')
        stem = 'pid' if row[0] == 'pid_for_children' else row[0]
        if type(row[1][0]) is not str or re.fullmatch(stem + r':\[[1-9][0-9]{0,19}\]', row[1][0]) is None:
            _fail('namespace_invalid')
        names.append(row[0])
    if tuple(names) != tuple(sorted(set(names))) or profile['names'] != tuple(names):
        _fail('namespace_invalid')
    if profile['kind'] == 'full4_present':
        if not {'mnt', 'net', 'pid', 'user'}.issubset(names) or profile['config_sha256'] is not None or \
                profile['config_namespaces'] != 'NOT_EVALUATED': _fail('namespace_invalid')
    elif tuple(names) != ('cgroup', 'mnt') or profile['config_sha256'] != manifest['config_sha256'] or \
            profile['config_namespaces'] != 'disabled': _fail('namespace_invalid')
    return (value['boot'], actors[0].key(), actors[1].key(), value['uid'], value['gid'],
            image, endpoint, anchors, resolved, chain, value['sockfs_inode'], rows,
            tuple(sorted(profile.items())))


class _LinuxIo(baseline._LinuxIo):
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or \
                os.uname()[4] != 'armv7l' or getattr(os, 'O_NOFOLLOW', None) != 0x8000 or \
                getattr(os, 'O_CLOEXEC', None) != 0x80000:
            _fail('unsupported_platform')

    def readlink(self, path): return os.readlink(path)
    def new_socket(self): return socket.socket(AF_UNIX, SOCK_DGRAM, 0)
    def token(self): return os.urandom(16)
    def cmsg_space(self, count): return socket.CMSG_SPACE(count)


class _ReadFiles(object):
    """Reuse pinned baseline file ledger; never invoke its collect/Popen path."""
    _now = baseline.BaselineCollector._now
    _adopt_fd = baseline.BaselineCollector._adopt_fd
    _read_file = baseline.BaselineCollector._read_file
    _binary_parents = baseline.BaselineCollector._binary_parents
    _close_row = baseline.BaselineCollector._close_row

    def __init__(self, io, clock, deadline, manifest):
        self._io, self._clock, self._deadline = io, clock, deadline
        self._manifest = ((manifest['daemon_exe'], manifest['daemon_sha256']),)
        self._last_clock, self._pending = None, False
        self._tickets, self._raw = [], []
        self._tickets_original, self._io_original = self._tickets, self._io
        self._open_creator_original = self._io.open
        self._absent_discovery = self._absent_discovery_original = []

    def _open(self, path, flags=None):
        # The original v25 ledger flow, with the actual open receipt retained.
        # No returned FD and a real errno differ from an attempted FD close.
        flags = _ARM_READ_FLAGS if flags is None else flags
        row = self._ticket('fd')
        row.update(owner=self, path=path, flags=flags,
            open_creator=self._open_creator_original, open_started=False,
            open_returned=False, open_error=None, open_result=None)
        try:
            row['open_started'] = True
            descriptor = row['open_creator'](path, flags)
        except OSError as error:
            row['open_error'] = error
            row['unknown'], row['closed'] = False, True
            raise
        except BaseException as error:
            row['open_error'] = error
            self._pending = True
            raise
        row['open_result'], row['open_returned'] = descriptor, True
        self._adopt_fd(row, descriptor)
        return row

    def _known_absent_comm(self, row, error):
        if (type(self) is not _ReadFiles or self._tickets is not self._tickets_original or
                type(self._tickets) is not list or self._io is not self._io_original or
                type(row) is not dict or sum(r is row for r in self._tickets) != 1 or
                row.get('owner') is not self or row.get('kind') != 'fd' or
                row.get('flags') != _ARM_READ_FLAGS or type(row.get('flags')) is not int or
                row.get('open_creator') is not self._open_creator_original or
                getattr(self._open_creator_original, '__self__', None) is not self._io or
                getattr(self._open_creator_original, '__func__', None) is not
                    getattr(type(self._io), 'open', None) or
                row.get('open_started') is not True or row.get('open_returned') is not False or
                row.get('open_result') is not None or row.get('open_error') is not error or
                not isinstance(error, OSError) or type(error.errno) is not int or
                error.errno not in (errno.ENOENT, errno.ESRCH) or
                row.get('fd') is not None or row.get('value') is not None or
                row.get('unknown') is not False or
                row.get('closed') is not True or row.get('attempted') is not False):
            return False
        path = row.get('path')
        match = re.fullmatch('/proc/([1-9][0-9]{0,9})/comm', path) if type(path) is str else None
        return match is not None and 0 < int(match.group(1)) <= 0x7fffffff

    def _record_absent_comm(self, before, path, error):
        # Only an unselected numeric comm open failure can be omitted from
        # discovery. Required actors/images/endpoints never use this seam.
        if (type(before) is not int or before < 0 or len(self._tickets) != before + 1 or
                self._pending or self._absent_discovery is not self._absent_discovery_original or
                type(self._absent_discovery) is not list):
            return False
        row = self._tickets[-1]
        if row.get('path') != path or not self._known_absent_comm(row, error):
            return False
        if any(pair[0] is row for pair in self._absent_discovery):
            _fail('source_invalid')
        self._absent_discovery.append((row, error))  # both exact originals
        return True

    def _real_fd_tickets(self):
        # CloseProof covers real owned FDs only. Known unopened discovery
        # rows stay in the full original close audit, never fake attempted=True.
        if (type(self) is not _ReadFiles or self._tickets is not self._tickets_original or
                type(self._tickets) is not list or len(self._tickets) > MAX_SOURCE_FILES or
                self._io is not self._io_original or self._pending or
                self._absent_discovery is not self._absent_discovery_original or
                type(self._absent_discovery) is not list):
            _fail('source_invalid')
        excluded = []
        for pair in self._absent_discovery:
            if (type(pair) is not tuple or len(pair) != 2 or
                    any(pair[0] is row for row in excluded) or
                    not self._known_absent_comm(pair[0], pair[1])):
                _fail('source_invalid')
            excluded.append(pair[0])
        actual, seen = [], []
        for row in self._tickets:
            if type(row) is not dict or any(row is other for other in seen):
                _fail('source_invalid')
            seen.append(row)
            if any(row is absent for absent in excluded):
                continue
            if (row.get('owner') is not self or row.get('kind') != 'fd' or
                    row.get('open_creator') is not self._open_creator_original or
                    row.get('open_started') is not True or row.get('open_returned') is not True or
                    row.get('open_error') is not None or not _int(row.get('fd')) or
                    row.get('open_result') != row['fd'] or type(row.get('open_result')) is not int or
                    row.get('unknown') is not False or row.get('closed') is not True or
                    row.get('attempted') is not True):
                _fail('source_invalid')
            actual.append(row)
        if len(actual) + len(excluded) != len(self._tickets):
            _fail('source_invalid')
        return tuple(actual)

    def _ticket(self, kind):
        if len(self._tickets) >= MAX_SOURCE_FILES: _fail('file_budget')
        return baseline.BaselineCollector._ticket(self, kind)

    def close(self):
        for row in self._tickets: self._close_row(row)
        return not self._pending and all(r['closed'] and not r['unknown'] for r in self._tickets)


class LinuxStatusSource(object):
    """Concrete fixed manifest source, two reads in one exact consumer epoch.

    Registry authentication only binds our own fresh actual observations. It
    does not elevate FakeIO, a caller manifest or root compromise to trust.
    """
    def __init__(self, manifest, _io=None, _proc_reader=None, _clock=None):
        self._manifest = _manifest(manifest)
        self._io, self._reader = _io if _io is not None else _LinuxIo(), _proc_reader
        self._clock = _clock or time.monotonic
        self._consumer, self._issued, self._files, self._raw = None, [], [], []
        self._actor_calls = []  # exact reader/call owners, including unknown returns
        self._pending = False

    def __repr__(self): return '<private Linux WPA source>'

    def _actor(self, files, pid=None, expected=None):
        remaining = files._deadline - files._now()
        if remaining < 0.1: _fail('deadline')
        if len(self._actor_calls) >= MAX_ACTOR_CALLS or \
                sum(row['files'] is files for row in self._actor_calls) >= 4:
            _fail('actor_unknown')
        row = {'files': files, 'method': 'read_self' if pid is None else 'read_actor',
               'pid': pid, 'expected': expected, 'reader': None, 'started': False,
               'returned': False, 'value': None, 'error': None, 'unknown': True}
        self._actor_calls.append(row)  # before construction or any read_* call
        try:
            reader = self._reader if self._reader is not None else proc.ProcReader(timeout=min(remaining, 3))
            row['reader'] = reader  # retain original FD/_open_attempt owner before IO
            row['started'] = True
            value = (reader.read_self(_absolute_deadline=files._deadline) if pid is None else
                reader.read_actor(pid, expected, _absolute_deadline=files._deadline))
            row['value'], row['returned'] = value, True  # before postchecks/evidence allocation
        except BaseException as caught:
            row['error'] = caught
            self._pending = True; raise
        self._raw.append(value)
        if getattr(value, 'resource_pending', None) is not False: self._pending = True
        files._now(); _observation(value, pid is None)
        row['unknown'] = False
        return value

    def _namespaces(self, files, pid):
        paths = ('/proc/' + str(pid) + '/ns', '/proc/self/ns')
        names = []
        for path in paths:
            files._now(); row = self._io.listdir(path)
            if type(row) not in (tuple, list) or not 1 <= len(row) <= 8 or \
                    any(type(v) is not str or v not in _NS for v in row) or len(set(row)) != len(row):
                _fail('namespace_invalid')
            names.append(tuple(sorted(row)))
        if names[0] != names[1]: _fail('namespace_invalid')
        rows = []
        for name in names[0]:
            files._now(); pair = tuple(self._io.readlink(path + '/' + name) for path in paths)
            rows.append((name, pair))
        for path, expected in zip(paths, names):
            files._now()
            if tuple(sorted(self._io.listdir(path))) != expected: _fail('namespace_invalid')
        profile = {'kind': self._manifest['namespace_kind'], 'names': names[0],
                   'config_sha256': None, 'config_namespaces': 'NOT_EVALUATED'}
        if profile['kind'] == 'namespaces_disabled_cgroup_mnt':
            raw = files._read_file('/proc/config.gz', MAX_CONFIG)[0]
            try:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                config = decoder.decompress(raw, MAX_CONFIG + 1)
            except zlib.error: _fail('namespace_invalid')
            if len(config) > MAX_CONFIG or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                _fail('namespace_invalid')
            if hashlib.sha256(config).hexdigest() != self._manifest['config_sha256']: _fail('namespace_invalid')
            lines = config.splitlines()
            if lines.count(b'# CONFIG_NAMESPACES is not set') != 1 or \
                    any(v.startswith(b'CONFIG_NAMESPACES=') for v in lines): _fail('namespace_invalid')
            profile.update(config_sha256=hashlib.sha256(config).hexdigest(), config_namespaces='disabled')
        return tuple(rows), profile

    def _endpoint(self, files, pid):
        original = self._manifest['endpoint']; path, chain = self._resolve_endpoint(files, original)
        pieces = path[1:].split('/')
        parents = ['/', *('/' + '/'.join(pieces[:i]) for i in range(1, len(pieces)))]
        anchors = tuple((p, _meta(self._io.stat(p))[:6]) for p in parents)
        endpoint = _meta(self._io.stat(path))[:6]
        raw = files._read_file('/proc/net/unix', MAX_CONFIG)[0]
        lines = raw.splitlines()
        if not raw.endswith(b'\n') or not lines or lines[0].split() != \
                [b'Num', b'RefCount', b'Protocol', b'Flags', b'Type', b'St', b'Inode', b'Path'] or len(lines) > 4097:
            _fail('endpoint_invalid')
        found = []
        for line in lines[1:]:
            parts = line.split(None, 7)
            if len(parts) not in (7, 8) or re.fullmatch(br'[0-9a-fA-F]{8,16}:', parts[0]) is None or \
                    any(re.fullmatch(br'[0-9a-fA-F]{8}', parts[i]) is None for i in (1, 2, 3)) or \
                    re.fullmatch(br'[0-9a-fA-F]{4}', parts[4]) is None or \
                    re.fullmatch(br'[0-9a-fA-F]{2}', parts[5]) is None or \
                    re.fullmatch(br'[1-9][0-9]{0,19}', parts[6]) is None:
                _fail('endpoint_invalid')
            if len(parts) == 8 and parts[7] == original.encode('ascii'):
                if parts[4] != b'0002': _fail('endpoint_invalid')
                found.append(int(parts[6]))
        if len(found) != 1: _fail('endpoint_invalid')
        files._now(); root = '/proc/' + str(pid) + '/fd'; names = self._io.listdir(root)
        if type(names) not in (tuple, list) or len(names) > 512 or len(set(names)) != len(names) or \
                any(type(v) is not str or re.fullmatch('(0|[1-9][0-9]{0,9})', v) is None for v in names):
            _fail('endpoint_invalid')
        matched = []
        for name in names:
            files._now(); link = self._io.readlink(root + '/' + name)
            if link == 'socket:[' + str(found[0]) + ']': matched.append(name)
        if not matched or tuple(sorted(self._io.listdir(root))) != tuple(sorted(names)):
            _fail('endpoint_invalid')
        if _meta(self._io.stat(path))[:6] != endpoint or \
                tuple((p, _meta(self._io.stat(p))[:6]) for p in parents) != anchors:
            _fail('endpoint_invalid')
        for name, metadata, target in chain:
            files._now()
            if _meta(self._io.stat(name))[:6] != metadata or \
                    target is not None and self._io.readlink(name) != target: _fail('endpoint_invalid')
        return endpoint, anchors, found[0], path, chain

    def _resolve_endpoint(self, files, original):
        pending, current, chain, links = original[1:].split('/'), [], [], set()
        while pending:
            files._now()
            if len(chain) >= 64: _fail('endpoint_invalid')
            root = _meta(self._io.stat('/'))[:6]
            if not stat.S_ISDIR(root[2]) or root[3] != 0 or root[2] & 0o022: _fail('endpoint_invalid')
            if not chain: chain.append(('/', root, None))
            component = pending.pop(0)
            if component in ('', '.'): continue
            if component == '..':
                if not current: _fail('endpoint_invalid')
                current.pop(); continue
            current.append(component); name = '/' + '/'.join(current)
            metadata = _meta(self._io.stat(name))[:6]
            if metadata[3] != 0: _fail('endpoint_invalid')
            if stat.S_ISLNK(metadata[2]):
                target = self._io.readlink(name)
                if name in links or len(links) >= 8 or metadata[5] != 1 or type(target) is not str or \
                        not 1 <= len(target) <= 256 or any(ord(c) < 32 or ord(c) >= 127 for c in target):
                    _fail('endpoint_invalid')
                links.add(name); chain.append((name, metadata, target))
                # Resolve intermediate symlinks before '..', using physical
                # parent components. Never lexical-realpath an unobserved link.
                pending = ([] if target.startswith('/') else current[:-1]) + target.split('/') + pending
                current = []
                if not pending or len(pending) > 32: _fail('endpoint_invalid')
            else:
                if (pending and (not stat.S_ISDIR(metadata[2]) or metadata[2] & 0o022)) or \
                        not pending and not stat.S_ISSOCK(metadata[2]): _fail('endpoint_invalid')
                chain.append((name, metadata, None))
        resolved = '/' + '/'.join(current)
        if not _path(resolved): _fail('endpoint_invalid')
        return resolved, tuple(chain)

    def read_source(self, consumer, deadline):
        if self._pending or len(self._issued) >= 2 or self._consumer not in (None, consumer):
            _fail('source_unknown')
        self._consumer = consumer
        files = _ReadFiles(self._io, self._clock, deadline, self._manifest)
        self._files.append(files)  # before any syscall or ProcReader invocation
        result, error = None, None
        try:
            self._io.validate(); self_before = self._actor(files)
            # No process-name selection: manifest producer pins exact daemon PID
            # through the actual unique endpoint inode / daemon FD table.
            names = self._io.listdir('/proc')
            if type(names) not in (tuple, list) or len(names) > 4096 or any(type(v) is not str for v in names):
                _fail('actor_unknown')
            actors = []
            for name in names:
                files._now()
                if re.fullmatch('[1-9][0-9]{0,9}', name) is None: continue
                if int(name) > 0x7fffffff: _fail('actor_unknown')
                path = '/proc/' + name + '/comm'
                before_tickets = len(files._tickets)
                try:
                    comm = files._read_file(path, 128)[0]
                except OSError as comm_error:
                    if files._record_absent_comm(before_tickets, path, comm_error):
                        continue
                    raise
                if comm == b'wpa_supplicant\n': actors.append(self._actor(files, int(name)))
            if len(actors) != 1: _fail('actor_unknown')
            daemon = actors[0].actor
            if daemon.exe != self._manifest['daemon_exe']: _fail('image_invalid')
            path = '/proc/' + str(daemon.pid)
            command = files._read_file(path + '/cmdline', 32768)[0]
            if not command or not command.endswith(b'\0') or hashlib.sha256(command).hexdigest() != daemon.argv_sha:
                _fail('actor_unknown')
            status_raw = files._read_file(path + '/status', 32768)[0]; ids = {}
            for line in status_raw.splitlines():
                key, sep, data = line.partition(b':')
                if key not in (b'Uid', b'Gid'): continue
                if key in ids or not sep: _fail('actor_unknown')
                fields = data.split()
                if len(fields) != 4 or any(re.fullmatch(br'(0|[1-9][0-9]{0,9})', v) is None for v in fields):
                    _fail('actor_unknown')
                ids[key] = tuple(int(v) for v in fields)
            if ids != {b'Uid': (self._manifest['real_uid'],) * 4, b'Gid': (self._manifest['real_gid'],) * 4}:
                _fail('actor_unknown')
            image, unused, image_meta = files._read_file(daemon.exe, baseline.MAX_FILE, binary=True)
            if hashlib.sha256(image).hexdigest() != self._manifest['daemon_sha256']: _fail('image_invalid')
            row = files._open(path + '/exe', baseline._EXEC_READ_FLAGS); raw = b''
            try:
                if _meta(self._io.fstat(row['fd'])) != image_meta: _fail('image_invalid')
                while True:
                    files._now(); chunk = self._io.read(row['fd'], min(65536, baseline.MAX_FILE + 1 - len(raw)))
                    if type(chunk) is not bytes or len(chunk) > min(65536, baseline.MAX_FILE + 1 - len(raw)):
                        _fail('image_invalid')
                    raw += chunk
                    if len(raw) > baseline.MAX_FILE: _fail('image_invalid')
                    if not chunk: break
                if hashlib.sha256(raw).hexdigest() != self._manifest['daemon_sha256'] or \
                        _meta(self._io.fstat(row['fd'])) != image_meta: _fail('image_invalid')
            finally: files._close_row(row)
            namespaces, profile = self._namespaces(files, daemon.pid)
            endpoint, anchors, inode, resolved, chain = self._endpoint(files, daemon.pid)
            after = self._actor(files, daemon.pid, daemon); self_after = self._actor(files)
            if self_before.boot != after.boot or self_before.boot != self_after.boot or \
                    self_before.actor.key() != self_after.actor.key() or daemon.key() != after.actor.key():
                _fail('source_changed')
            result = {'boot': after.boot, 'self_actor': self_after.actor, 'daemon_actor': after.actor,
                'uid': ids[b'Uid'][0], 'gid': ids[b'Gid'][0], 'image': image_meta,
                'endpoint': endpoint, 'anchors': anchors, 'sockfs_inode': inode,
                'namespaces': namespaces, 'namespace_profile': profile, 'files_closed': None,
                'resolved_endpoint': resolved, 'endpoint_chain': chain}
        except BaseException as caught: error = caught
        finally:
            if not files.close() or self._pending:
                self._pending = True; error = WpaStatusError('close_unknown')
        if error is not None: raise error
        # Core CloseProof retains its <=128 original-resource contract. Chunk
        # this larger /proc inventory rather than signing an aggregate bool.
        owned = files._real_fd_tickets()
        result['files_closed'] = tuple(core.CloseProof(len(rows),
            tuple(r['attempted'] for r in rows), tuple(r['closed'] for r in rows))
            for rows in (owned[i:i + 128] for i in range(0, len(owned), 128)))
        # Actual unopened comm receipts remain private in the original ledger.
        key = _source_key(result, self._manifest)
        self._issued.append((consumer, result, key, files))
        return result

    def authenticate_source(self, consumer, observation, deadline):
        if self._pending or not any(c is consumer and o is observation and not f._pending and
                all(r['closed'] and not r['unknown'] for r in f._tickets) and
                sum(p.expected for p in o['files_closed']) == len(f._real_fd_tickets()) and
                key == _source_key(o, self._manifest) for c, o, key, f in self._issued):
            _fail('source_authentication')
        now = self._clock()
        if not _number(now, 0, 1e12) or now >= deadline: _fail('deadline')
        return None


class AuthenticatedStatusReader(object):
    """One fixed STATUS, synchronous owner; caller lifetime belongs to outer F.

    Manifest/source/FakeIO are private construction inputs, never HTTP fields.
    No background thread, retries, endpoint fallback, ATTACH or service actions.
    """
    def __init__(self, manifest=None, source=None, timeout=3.0, _io=None, _proc_reader=None, _clock=None):
        if not _number(timeout, 0.1, 3): _fail('invalid_budget')
        if _clock is not None and not callable(_clock): _fail('invalid_clock')
        self._manifest = None if manifest is None else _manifest(manifest)
        self._io, self._clock = _io if _io is not None else _LinuxIo(), _clock or time.monotonic
        self._source = source if source is not None else (LinuxStatusSource(self._manifest,
            self._io, _proc_reader, self._clock) if self._manifest is not None else None)
        if source is not None and not all(callable(getattr(source, v, None)) for v in ('read_source', 'authenticate_source')):
            _fail('invalid_manifest')
        self._timeout, self._mutex, self._last = float(timeout), threading.RLock(), None
        self._attempted = self._success = self._ended = self._pending = False
        self._reason, self._socket, self._socket_fd = 'not_started', None, None
        self._socket_unknown = self._socket_attempted = self._socket_closed = False
        self._receive_unknown = self._source_unknown = False
        self._rights, self._raw, self._sources = [], [], []
        self._incoming, self._result, self._failure = None, None, None

    def __repr__(self): return '<private authenticated WPA STATUS reader>'

    def _now(self):
        value = self._clock()
        if not _number(value, 0, 1e12) or self._last is not None and value < self._last: _fail('invalid_clock')
        self._last = float(value)
        if hasattr(self, '_deadline') and value >= self._deadline: _fail('deadline')
        return float(value)

    def _source_read(self):
        self._now(); self._source_unknown = True
        value = self._source.read_source(self, self._deadline)
        self._sources.append(value)  # before schema, authentication or postcheck
        key = _source_key(value, self._manifest)
        if self._source.authenticate_source(self, value, self._deadline) is not None:
            _fail('source_authentication')
        if _source_key(value, self._manifest) != key: _fail('source_changed')
        self._source_unknown = False; self._now()
        return value, key

    def _budget(self):
        remaining = self._deadline - self._now()
        self._socket.settimeout(remaining)
        seconds, ns = divmod(math.ceil(remaining * 1e9), 1000000000)
        expected = seconds + ns * 1e-9
        actual = self._socket.gettimeout()
        if type(actual) is not float or not math.isfinite(actual) or actual != expected or actual <= 0:
            _fail('timeout_readback')

    def _open_socket(self):
        self._socket_unknown = True
        value = self._io.new_socket(); self._socket = value
        if not all(callable(getattr(value, v, None)) for v in ('fileno', 'close', 'bind', 'getsockname',
                'connect', 'getpeername', 'set_inheritable', 'get_inheritable', 'setsockopt', 'getsockopt',
                'settimeout', 'gettimeout', 'send', 'recvmsg')): _fail('socket_unknown')
        self._socket_fd = value.fileno()
        if not _int(self._socket_fd): _fail('socket_unknown')
        metadata = _meta(self._io.fstat(self._socket_fd))
        if not stat.S_ISSOCK(metadata[2]): _fail('socket_identity')
        self._socket_metadata = metadata[:6]
        self._socket_unknown = False
        if not isinstance(value.family, int) or type(value.family) is bool or value.family != AF_UNIX or \
                not isinstance(value.type, int) or type(value.type) is bool or value.type != SOCK_DGRAM or \
                type(value.proto) is not int or value.proto != 0:
            _fail('socket_identity')
        value.set_inheritable(False)
        if value.get_inheritable() is not False: _fail('socket_option')
        value.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        if type(value.getsockopt(SOL_SOCKET, SO_PASSCRED)) is not int or value.getsockopt(SOL_SOCKET, SO_PASSCRED) != 1:
            _fail('socket_option')
        token = self._io.token()
        if type(token) is not bytes or len(token) != 16: _fail('socket_identity')
        local = b'\0p011-mta-status-' + token.hex().encode('ascii')
        self._local = local; value.bind(local)
        if value.getsockname() != local: _fail('socket_identity')
        self._budget(); value.connect(self._manifest['endpoint'])
        if value.getpeername() != self._manifest['endpoint']: _fail('wrong_endpoint')

    def _controls(self, controls):
        if type(controls) not in (tuple, list) or len(controls) > 16:
            self._pending = True; _fail('receive_control')
        credentials, invalid, has_rights, seen = [], False, False, set()
        for item in controls:
            if type(item) is not tuple or len(item) != 3 or type(item[0]) is not int or \
                    type(item[1]) is not int or type(item[2]) is not bytes:
                self._pending = True; invalid = True; continue
            level, kind, data = item
            if level == SOL_SOCKET and kind == SCM_RIGHTS:
                has_rights = True
                if len(data) > MAX_RIGHTS * 4:
                    self._pending = True; invalid = True; continue
                if not data or len(data) % 4: self._pending = True; invalid = True
                for at in range(0, len(data) - len(data) % 4, 4):
                    fd = _FD.unpack_from(data, at)[0]
                    row = {'fd': fd, 'attempted': False, 'closed': False, 'unknown': True, 'metadata': None}
                    self._rights.append(row)
                    if len(self._rights) > MAX_RIGHTS or not _int(fd) or fd in seen or fd == self._socket_fd:
                        self._pending = True; invalid = True; continue
                    seen.add(fd)
                    try: row['metadata'] = _meta(self._io.fstat(fd))[:6]; row['unknown'] = False
                    except BaseException: self._pending = True; invalid = True
            elif level == SOL_SOCKET and kind == SCM_CREDENTIALS and len(data) == _CRED.size:
                credentials.append(_CRED.unpack(data))
            else:
                # Do not assume an unrecognized control installs no resource.
                self._pending = True; invalid = True
        if not self._pending: self._receive_unknown = False
        if invalid: _fail('receive_control')
        if has_rights: _fail('rights_rejected')
        if len(credentials) != 1: _fail('receive_control')
        return credentials[0]

    def _close(self):
        for row in self._rights:
            if row['attempted'] or row['closed']: continue
            if row['unknown']: self._pending = True; continue
            row['attempted'] = True
            try:
                if _meta(self._io.fstat(row['fd']))[:6] != row['metadata']: _fail('close_unknown')
                returned = self._io.close(row['fd'])
                try: self._io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException: self._pending = True
            if not row['closed']: self._pending = True
        if self._socket is not None and not self._socket_attempted and not self._socket_unknown:
            self._socket_attempted = True
            try:
                if self._socket.fileno() != self._socket_fd or \
                        _meta(self._io.fstat(self._socket_fd))[:6] != self._socket_metadata: _fail('close_unknown')
                returned = self._socket.close()
                if type(self._socket.fileno()) is not int or self._socket.fileno() != -1: _fail('close_unknown')
                try: self._io.fstat(self._socket_fd)
                except OSError as error:
                    self._socket_closed = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException: self._pending = True
        if self._socket is not None and not self._socket_closed: self._pending = True

    def read_status(self, deadline):
        with self._mutex:
            if self._attempted: _fail('already_attempted')
            if not _number(deadline, 0, 1e12): _fail('invalid_budget')
            self._attempted = True; error, result = None, None
            try:
                if self._manifest is None or self._source is None: _fail('unavailable')
                self._deadline = min(float(deadline), self._now() + self._timeout)
                self._now(); self._io.validate()
                before, key = self._source_read(); self._open_socket(); self._budget()
                sent = self._socket.send(b'STATUS')
                if type(sent) is not int or sent != 6: _fail('short_send')
                self._budget(); self._receive_unknown = True
                value = self._socket.recvmsg(MAX_STATUS + 1, self._io.cmsg_space(12) + self._io.cmsg_space(MAX_RIGHTS * 4), MSG_CMSG_CLOEXEC)
                self._incoming = value  # retain before unpack/schema/ancillary parsing
                if type(value) is not tuple or len(value) != 4: self._pending = True; _fail('receive_invalid')
                packet, controls, flags, peer = value
                self._raw.append(value)
                credential = self._controls(controls)
                self._receive_unknown = False
                if type(flags) is not int or flags & (MSG_TRUNC | MSG_CTRUNC):
                    self._pending = True; _fail('receive_truncated')
                if flags not in (0, MSG_CMSG_CLOEXEC): _fail('receive_invalid')
                if credential != (before['daemon_actor'].pid, before['uid'], before['gid']):
                    _fail('credential_mismatch')
                if peer != self._manifest['endpoint'] or self._socket.getpeername() != peer or self._socket.getsockname() != self._local:
                    _fail('wrong_endpoint')
                fields = parse_status(packet)
                after, after_key = self._source_read()
                if after is before or key != after_key: _fail('source_changed')
                self._now(); result = {'raw': packet, 'fields': fields,
                    'digest': hashlib.sha256(packet).hexdigest(), 'frequency': fields.get(b'freq'),
                    'completed': fields[b'wpa_state'] == b'COMPLETED', 'source_authenticated': True}
            except BaseException as caught:
                self._failure = caught  # private original, never public error text
                error = caught; self._reason = caught.code if type(caught) is WpaStatusError or \
                    type(caught) is baseline.BaselineError and caught.code in _REASONS else \
                    ('interrupted' if not isinstance(caught, Exception) else 'io_error')
            finally:
                self._close(); self._ended = True
                if self._pending or self._source_unknown or self._socket_unknown or self._receive_unknown:
                    self._pending = True
                    if error is None: error = WpaStatusError('close_unknown'); self._reason = 'close_unknown'
            if error is not None: raise WpaStatusError(self._reason) from None
            self._result, self._success, self._reason = result, True, 'read_closed'
            return result

    def status(self):
        with self._mutex:
            return {'attempted': self._attempted, 'finished': self._ended, 'read_success': self._success,
                'source_authenticated': self._success, 'socket_closed': self._socket_closed,
                'resource_pending': self._pending, 'source_count': len(self._sources),
                'datagram_count': len(self._raw), 'rights_count': len(self._rights),
                'rights_closed': sum(r['closed'] for r in self._rights), 'reason': self._reason,
                'restoration_verified': False, 'mutation_admission': False,
                'send_available': False, 'receive_available': False}


def parse_status(raw):
    """Original STATUS shape; no credentials/key policy or client association."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_STATUS or not raw.endswith(b'\n') or \
            b'\0' in raw or b'\r' in raw: _fail('invalid_status')
    fields = {}
    for line in raw[:-1].split(b'\n'):
        key, sep, value = line.partition(b'=')
        if not sep or key not in ctrl._STATUS_FIELDS or key in fields or not value or \
                len(line) > 512 or any(c < 32 or c > 126 for c in value): _fail('invalid_status')
        fields[key] = value
        if len(fields) > 32: _fail('invalid_status')
    if fields.get(b'wpa_state') not in ctrl.STATES: _fail('invalid_status')
    if b'freq' in fields:
        raw_freq = fields[b'freq']
        if re.fullmatch(br'[1-9][0-9]{3}', raw_freq) is None: _fail('invalid_status')
        fields[b'freq'] = int(raw_freq)
        if fields[b'freq'] not in tuple(range(2412, 2473, 5)) + (2484,): _fail('invalid_status')
    if fields[b'wpa_state'] == b'COMPLETED' and b'freq' not in fields: _fail('invalid_status')
    return fields
