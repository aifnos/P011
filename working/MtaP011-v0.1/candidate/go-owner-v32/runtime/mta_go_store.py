"""GO reservation filesystem producer, SOURCE first slice only (Python 3.5).

This is not a CLIENT Journal, RF grant, GO-ready proof or send provider. It
performs real native fixed-path flock/CAS/fsync/readback when called explicitly.
The corresponding v32 owner never creates an interface/process/control socket.
Therefore this revision can reconcile only its original UNMUTATED reservation.
No public entry point, arbitrary path, shell, firmware write or directory maker.
Construction is pure. Default native methods have not been executed on P011.
"""
import ctypes
import errno
import hashlib
import math
import os
import re
import stat
import sys
import threading
import time
import p011_json as json

BASE = 'p011-mta-go-session'
RUN_PREFIX = 'go-'
DEVICE_LOCK = 'p011-mta-p2p-device.lock'
GLOBAL_PENDING = 'p011-mta-p2p-device.pending'
JOURNAL_LOCK, JOURNAL = 'go-journal.lock', 'go-journal.json'
SCHEMA = 'p011-go-unmutated-reservation-v32'
MAX_FDS, MAX_RECORD = 64, 8192
MAX_ACTIVE_SECONDS, PREPARE_SECONDS, CLEANUP_SECONDS = 300.0, 10.0, 60.0
_PHASES = ('reserved', 'group_add_prepared', 'restore_intent', 'reconciled')
_KEYS = frozenset(('schema', 'run_token', 'candidate_sha', 'task_id', 'boot_id',
    'issued_at', 'until', 'phase', 'generation', 'group_add', 'rf_requested'))


class GoStoreError(RuntimeError):
    def __init__(self, code):
        self.code = code
        RuntimeError.__init__(self, code)


def _fail(code): raise GoStoreError(code) from None


def _uint(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def _number(value):
    if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
        _fail('invalid_time')
    return float(value)


def _hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None


def _boot(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None


def _meta(value):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size',
             'st_mtime_ns', 'st_ctime_ns')
    result = tuple(getattr(value, name, None) for name in names)
    if any(not _uint(item) for item in result): _fail('metadata_unknown')
    return result


def _file(value):
    row = _meta(value)
    if not stat.S_ISREG(row[2]) or row[3:5] != (0, 0) or row[5] != 1 or stat.S_IMODE(row[2]) != 0o600 or row[6] > MAX_RECORD:
        _fail('unsafe_file')
    return row


class GoRecord(object):
    """Persisted secret-free facts, NOT continuing permission or an RF grant."""
    __slots__ = tuple(_KEYS)
    def __init__(self, values):
        if type(values) is not dict or set(values) != _KEYS or values['schema'] != SCHEMA or \
                not _hex(values['run_token'], 32) or not _hex(values['candidate_sha'], 64) or \
                type(values['task_id']) is not str or re.fullmatch('[A-Za-z0-9_-]{1,96}', values['task_id']) is None or \
                not _boot(values['boot_id']) or values['phase'] not in _PHASES or \
                not _uint(values['generation'], 0, 3) or values['rf_requested'] is not False:
            _fail('invalid_record')
        issued, until = _number(values['issued_at']), _number(values['until'])
        if not 0 < until - issued <= MAX_ACTIVE_SECONDS: _fail('invalid_record')
        group = values['group_add']
        if group is not None:
            if type(group) is not dict or set(group) != {'frequency', 'command_sha256'} or \
                    type(group['frequency']) is not int or group['frequency'] not in range(2412, 2473, 5) or \
                    not _hex(group['command_sha256'], 64) or group['command_sha256'] != \
                    hashlib.sha256(('P2P_GROUP_ADD freq=%d' % group['frequency']).encode('ascii')).hexdigest():
                _fail('invalid_record')
            group = tuple(sorted(group.items()))
        expected_generation = {'reserved': 0, 'group_add_prepared': 1,
            'restore_intent': 1 if group is None else 2,
            'reconciled': 2 if group is None else 3}[values['phase']]
        if values['generation'] != expected_generation or \
                values['phase'] == 'reserved' and group is not None or \
                values['phase'] == 'group_add_prepared' and group is None:
            _fail('invalid_record')
        for name in _KEYS:
            value = group if name == 'group_add' else issued if name == 'issued_at' else until if name == 'until' else values[name]
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable GO facts')
    def __repr__(self): return '<private unmutated GO reservation facts; not RF permission>'
    def data(self):
        result = {name: getattr(self, name) for name in _KEYS}
        result['group_add'] = None if self.group_add is None else dict(self.group_add)
        return result
    def facts_key(self):
        return (self.schema, self.run_token, self.candidate_sha, self.task_id,
                self.boot_id, self.issued_at, self.until, self.rf_requested)
    def key(self): return self.facts_key() + (self.phase, self.generation, self.group_add)


def encode(record):
    if type(record) is not GoRecord: _fail('invalid_record')
    raw = json.dumps(record.data(), ensure_ascii=True, sort_keys=True).encode('ascii')
    if len(raw) > MAX_RECORD: _fail('invalid_record')
    return raw


def decode(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RECORD: _fail('invalid_record')
    try: record = GoRecord(json.loads(raw.decode('ascii')))
    except (ValueError, TypeError, UnicodeError, KeyError): _fail('invalid_record')
    if encode(record) != raw: _fail('noncanonical_record')
    return record


class GoCanonical(object):
    __slots__ = ('issuer', 'record', 'raw', 'metadata')
    def __init__(self, issuer, record, raw, metadata):
        for key, value in (('issuer', issuer), ('record', record), ('raw', raw), ('metadata', metadata)):
            object.__setattr__(self, key, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable original GO readback')
    def __repr__(self): return '<private original GO journal readback>'


class _Fd(object):
    def __init__(self, role):
        self.role, self.fd, self.metadata = role, None, None
        self.returned = self.attempted = self.closed = False
        self.unknown = True
    def __repr__(self): return '<private GO original FD ticket>'


class _LinuxIo(object):
    """Fixed native file operations only. No constructor syscall or RF API."""
    def __init__(self): self.library = None
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or os.uname()[4] != 'armv7l' or \
                getattr(os, 'O_NOFOLLOW', None) != 0x8000 or getattr(os, 'O_CLOEXEC', None) != 0x80000 or \
                getattr(os, 'O_DIRECTORY', None) != 0x4000:
            _fail('unsupported_platform')
        if os.stat not in getattr(os, 'supports_dir_fd', ()) or os.stat not in getattr(os, 'supports_follow_symlinks', ()):
            _fail('unsupported_fixed_stat')
    def pid(self): return os.getpid()
    def flags(self, *names):
        result = 0
        for name in names:
            value = getattr(os, name, None)
            if not _uint(value, 0, 0x7fffffff): _fail('unsupported_flags')
            result |= value
        return result
    def _libc(self):
        if self.library is None:
            value = ctypes.CDLL(None, use_errno=True)
            value.openat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint)
            value.openat.restype = ctypes.c_int
            # Mechanical reuse of existing FILES' actual renameat ABI, not its
            # CLIENT schema/canonical issuer. P011 need not expose os.rename fd.
            value.renameat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
            value.renameat.restype = ctypes.c_int
            value.unlinkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
            value.unlinkat.restype = ctypes.c_int
            value.flock.argtypes = (ctypes.c_int, ctypes.c_int); value.flock.restype = ctypes.c_int
            self.library = value
        return self.library
    def open_root(self, flags): return os.open('/', flags)
    def open_path(self, path, flags): return os.open(path, flags)
    def open_at(self, parent, name, flags, mode=0):
        if os.open in getattr(os, 'supports_dir_fd', ()):
            return os.open(name, flags, mode, dir_fd=parent)
        result = self._libc().openat(parent, name.encode('ascii'), flags, mode)
        if result < 0: raise OSError(ctypes.get_errno(), 'GO fixed open failure')
        return result
    def stat_root(self): return os.stat('/', follow_symlinks=False)
    def stat_path(self, path): return os.stat(path, follow_symlinks=False)
    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, raw): return os.write(fd, raw)
    def fsync(self, fd): return os.fsync(fd)
    def close(self, fd): return os.close(fd)
    def rename_at(self, parent, source, destination):
        if destination != JOURNAL or re.fullmatch('go-journal\\.[0-9]{2}\\.tmp', source) is None: _fail('fixed_name_required')
        ctypes.set_errno(0)
        result = self._libc().renameat(parent, source.encode('ascii'), parent, destination.encode('ascii'))
        if result != 0: raise OSError(ctypes.get_errno(), 'GO fixed rename failure')
    def unlink_at(self, parent, name):
        if name != GLOBAL_PENDING: _fail('fixed_name_required')
        ctypes.set_errno(0)
        result = self._libc().unlinkat(parent, name.encode('ascii'), 0)
        if result != 0: raise OSError(ctypes.get_errno(), 'GO fixed unlink failure')
    def flock(self, fd):
        ctypes.set_errno(0); result = self._libc().flock(fd, 2 | 4)
        return result, ctypes.get_errno()
    def pause(self, seconds): return time.sleep(seconds)


class GoReservationStore(object):
    """One reservation/one preparation/one restore, original fixed paths only.

    Current revision has no mutation API and refuses any rf_requested record.
    _io/_clock are trusted internal HOST seams, not public grant callbacks.
    Files/directories must already exist; only lock/marker/journal files are
    created. Unknown publication is retained and never rebased or auto-retried.
    """
    def __init__(self, run_token, candidate_sha, task_id, until, _io=None, _clock=None):
        if not _hex(run_token, 32) or not _hex(candidate_sha, 64) or type(task_id) is not str or \
                re.fullmatch('[A-Za-z0-9_-]{1,96}', task_id) is None:
            _fail('invalid_config')
        self.run_token, self.candidate_sha, self.task_id, self.until = run_token, candidate_sha, task_id, _number(until)
        self.io, self.clock = _io if _io is not None else _LinuxIo(), _clock or time.monotonic
        self.mutex, self.worker, self.issuer = threading.RLock(), threading.current_thread(), object()
        self.owner, self.pid, self.last, self.scope_until = None, None, None, None
        self.rows, self.anchors = [], []
        self.device = self.journal_lock = self.tmp = self.run = None
        self.current = self.marker_raw = self.marker_metadata = self.boot_id = None
        self.attempted = self.prepare_attempted = self.restore_attempted = False
        self.publication_unknown = self.observation_failed = False
        self.marker_cleared = self.logical_restored = False
        self.failure, self.restore_failure = None, None
        self.restore_until, self._temporary = None, 0
    def __repr__(self): return '<private native unmutated GO reservation store>'

    def bind(self, owner):
        import mta_go_owner as module
        if type(owner) is not module.GoOwner or owner.store is not self or self.owner is not None or self.attempted:
            _fail('wrong_owner')
        self.owner = owner

    def _now(self, check=True):
        value = _number(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if check and self.scope_until is not None and value >= self.scope_until: _fail('deadline')
        return value

    def _owner(self):
        import mta_go_owner as module
        if type(self.owner) is not module.GoOwner or self.owner.store is not self or threading.current_thread() is not self.worker or \
                self.pid is not None and self.io.pid() != self.pid:
            _fail('wrong_owner')

    def _open(self, role, parent=None, name=None, path=None, flags=None, mode=0):
        self._now()
        if len(self.rows) >= MAX_FDS: _fail('fd_budget')
        row = _Fd(role); self.rows.append(row)  # BEFORE original creation call.
        try:
            fd = self.io.open_path(path, flags) if path is not None else self.io.open_root(flags) if parent is None else self.io.open_at(parent, name, flags, mode)
            row.fd, row.returned = fd, True
            if not _uint(fd, 0, 0x7fffffff) or any(other is not row and other.fd == fd and not other.closed for other in self.rows):
                _fail('fd_unknown')
            row.metadata = _meta(self.io.fstat(fd)); row.unknown = False
            self._now()
            return row
        except OSError as error:
            if not row.returned and type(error.errno) is int and 1 <= error.errno <= 4095:
                row.unknown, row.closed = False, True  # Known negative native open.
            raise

    def _close(self, row):
        if row.attempted or row.closed: return
        if row.unknown or row.metadata is None: return
        # Physical close facts are independent of a late/failed observation.
        # No renewed activity cap, no numeric-FD retry or borrowed-FD close.
        try:
            if _meta(self.io.fstat(row.fd))[:6] != row.metadata[:6]: row.unknown = True; return
        except BaseException: row.unknown = True; return
        row.attempted = True
        result = error = None
        try: result = self.io.close(row.fd)
        except BaseException as value: error = value
        try: self.io.fstat(row.fd)
        except OSError as value:
            row.closed = error is None and result is None and type(value.errno) is int and value.errno == errno.EBADF
        except BaseException: pass

    def _directory(self, value, expected=None):
        row = _meta(value)
        if not stat.S_ISDIR(row[2]) or row[3:5] != (0, 0) or \
                expected is None and row[2] & 0o022 or expected is not None and stat.S_IMODE(row[2]) != expected:
            _fail('unsafe_directory')
        return row[:5]

    def _alias(self):
        paths = (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp'))
        before = []
        for path, target in paths:
            self._now(); row = _meta(self.io.stat_path(path))
            if row[2] != stat.S_IFLNK | 0o777 or row[3:6] != (0, 0, 1) or row[6] != len(target) or self.io.readlink(path) != target:
                _fail('fixed_alias_changed')
            before.append(row)
        for (path, target), previous in zip(paths, before):
            self._now()
            if _meta(self.io.stat_path(path)) != previous or self.io.readlink(path) != target: _fail('fixed_alias_changed')

    def _directories(self):
        flags = self.io.flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
        for name, mode in ((None, None), ('var', 0o755), ('volatile', 0o1777), ('tmp', 0o1777),
                           (BASE, 0o700), (RUN_PREFIX + self.run_token, 0o700)):
            parent = None if not self.anchors else self.anchors[-1][0]
            before = self._directory(self.io.stat_root() if parent is None else self.io.stat_at(parent.fd, name), mode)
            row = self._open('directory', parent=None if parent is None else parent.fd, name=name, flags=flags)
            if self._directory(self.io.fstat(row.fd), mode) != before: _fail('directory_changed')
            self.anchors.append((row, parent, name, before, mode))
        self.tmp, self.run = self.anchors[3][0], self.anchors[-1][0]
        self._alias(); self._anchors()

    def _anchors(self):
        for row, parent, name, metadata, mode in self.anchors:
            self._now()
            if row.closed or row.unknown or self._directory(self.io.fstat(row.fd), mode) != metadata or \
                    self._directory(self.io.stat_root() if parent is None else self.io.stat_at(parent.fd, name), mode) != metadata:
                _fail('directory_changed')
        self._alias()

    def _absent(self, parent, name):
        self._now()
        try: self.io.stat_at(parent.fd, name)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT: return
            raise
        _fail('entry_already_exists')

    def _lock(self, parent, name):
        before = None
        try: before = _file(self.io.stat_at(parent.fd, name))
        except OSError as error:
            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
        flags = self.io.flags('O_RDWR', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC')
        if before is None: flags |= self.io.flags('O_CREAT', 'O_EXCL')
        row = self._open('lock', parent=parent.fd, name=name, flags=flags, mode=0o600 if before is None else 0)
        current = _file(self.io.fstat(row.fd))
        if before is not None and before[:6] != current[:6] or _file(self.io.stat_at(parent.fd, name))[:6] != current[:6]:
            _fail('lock_changed')
        row.parent, row.name = parent, name
        self._lock_current(row)
        return row

    def _lock_current(self, row):
        self._now()
        if row is None or row.closed or row.attempted or row.unknown or \
                _file(self.io.fstat(row.fd))[:6] != row.metadata[:6] or \
                _file(self.io.stat_at(row.parent.fd, row.name))[:6] != row.metadata[:6]:
            _fail('lock_changed')
        while True:
            self._now(); result = self.io.flock(row.fd); self._now()
            if type(result) is not tuple or len(result) != 2 or any(type(v) is not int for v in result): _fail('flock_unknown')
            if result == (0, 0): return
            if result[0] != -1 or result[1] not in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK): _fail('flock_unknown')
            self.io.pause(0.01)

    def _read(self, parent, name):
        before = _file(self.io.stat_at(parent.fd, name))
        row = self._open('read', parent=parent.fd, name=name, flags=self.io.flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
        try:
            if _file(self.io.fstat(row.fd)) != before: _fail('file_changed')
            raw = b''
            while True:
                self._now(); requested = min(4096, before[6] + 1 - len(raw))
                part = self.io.read(row.fd, requested)
                if type(part) is not bytes or len(part) > requested: _fail('invalid_read')
                raw += part
                if len(raw) > before[6]: _fail('file_changed')
                if not part: break
            if len(raw) != before[6] or _file(self.io.fstat(row.fd)) != before or _file(self.io.stat_at(parent.fd, name)) != before:
                _fail('file_changed')
            self._now()
            return raw, before
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _boot_read(self):
        row = self._open('boot', path='/proc/sys/kernel/random/boot_id', flags=self.io.flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC'))
        try:
            if not stat.S_ISREG(row.metadata[2]) or row.metadata[3:6] != (0, 0, 1) or row.metadata[2] & 0o022:
                _fail('boot_unknown')
            raw = self.io.read(row.fd, 65); self._now()
            if type(raw) is not bytes or len(raw) != 37 or raw[-1:] != b'\n' or not _boot(raw[:-1].decode('ascii')):
                _fail('boot_unknown')
            if _meta(self.io.fstat(row.fd))[:6] != row.metadata[:6]: _fail('boot_changed')
            return raw[:-1].decode('ascii')
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _sync(self, fd):
        self._now()
        if self.io.fsync(fd) is not None: _fail('fsync_unknown')
        self._now()  # EINVAL/EBADF/late never count as durable publication.

    def _new_file(self, parent, name, raw):
        row = self._open('write', parent=parent.fd, name=name,
            flags=self.io.flags('O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC'), mode=0o600)
        try:
            created = _file(self.io.fstat(row.fd))
            if created[6] != 0: _fail('file_changed')
            at = 0
            while at < len(raw):
                self._now(); chunk = raw[at:at + 4096]; count = self.io.write(row.fd, chunk)
                if not _uint(count, 1, len(chunk)): _fail('short_write_unknown')
                at += count
            self._sync(row.fd)
            written = _file(self.io.fstat(row.fd))
            if written[:6] != created[:6] or written[6] != len(raw) or _file(self.io.stat_at(parent.fd, name)) != written:
                _fail('file_changed')
            return written
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _fresh(self):
        self._owner(); self._anchors(); self._lock_current(self.device); self._lock_current(self.journal_lock)
        if self.marker_raw is not None:
            raw, metadata = self._read(self.tmp, GLOBAL_PENDING)
            if raw != self.marker_raw or metadata != self.marker_metadata: _fail('marker_changed')
        if self.current is not None:
            raw, metadata = self._read(self.run, JOURNAL)
            if raw != self.current.raw or metadata != self.current.metadata or decode(raw).key() != self.current.record.key():
                _fail('stale_current')

    def _save(self, record):
        if type(record) is not GoRecord: _fail('invalid_record')
        previous = self.current
        if previous is not None:
            old = previous.record
            transitions = {'reserved': ('group_add_prepared', 'restore_intent'),
                'group_add_prepared': ('restore_intent',), 'restore_intent': ('reconciled',), 'reconciled': ()}
            if previous.issuer is not self.issuer or record.facts_key() != old.facts_key() or \
                    record.phase not in transitions[old.phase] or record.generation != old.generation + 1 or \
                    old.group_add is not None and record.group_add != old.group_add:
                _fail('invalid_transition')
        elif record.phase != 'reserved' or record.generation != 0: _fail('invalid_transition')
        self._fresh()
        if previous is None: self._absent(self.run, JOURNAL)
        self._temporary += 1
        if self._temporary > 4: _fail('publication_limit')
        name, raw = 'go-journal.%02d.tmp' % self._temporary, encode(record)
        self.publication_unknown = True
        written = self._new_file(self.run, name, raw)
        self._fresh()
        if _file(self.io.stat_at(self.run.fd, name)) != written: _fail('file_changed')
        if self.io.rename_at(self.run.fd, name, JOURNAL) is not None: _fail('rename_unknown')
        self._sync(self.run.fd)
        observed, metadata = self._read(self.run, JOURNAL)
        if observed != raw or metadata[:7] != written[:7] or decode(observed).key() != record.key(): _fail('publication_changed')
        self.current = GoCanonical(self.issuer, decode(observed), observed, metadata)
        self.publication_unknown = False
        return self.current

    def reserve(self):
        with self.mutex:
            self._owner()
            if self.attempted: _fail('already_attempted')
            self.attempted = True
            issued = self._now(False)
            if not 0 < self.until - issued <= MAX_ACTIVE_SECONDS: _fail('original_until_invalid')
            self.scope_until = min(self.until, issued + PREPARE_SECONDS)
            try:
                self.io.validate(); self.pid = self.io.pid()
                if not _uint(self.pid, 1, 0x7fffffff): _fail('wrong_owner')
                self._directories(); self._absent(self.tmp, GLOBAL_PENDING)
                self.device = self._lock(self.tmp, DEVICE_LOCK)
                self._absent(self.tmp, GLOBAL_PENDING)
                self.journal_lock = self._lock(self.run, JOURNAL_LOCK)
                self._absent(self.tmp, GLOBAL_PENDING); self._absent(self.run, JOURNAL)
                self.boot_id = self._boot_read()
                marker = {'schema': SCHEMA, 'run_token': self.run_token, 'candidate_sha': self.candidate_sha,
                    'task_id': self.task_id, 'boot_id': self.boot_id, 'issued_at': issued, 'until': self.until}
                raw = json.dumps(marker, ensure_ascii=True, sort_keys=True).encode('ascii')
                self.publication_unknown = True
                written = self._new_file(self.tmp, GLOBAL_PENDING, raw)
                self._sync(self.tmp.fd)
                current, metadata = self._read(self.tmp, GLOBAL_PENDING)
                if current != raw or metadata[:7] != written[:7]: _fail('marker_changed')
                self.marker_raw, self.marker_metadata = current, metadata
                self.publication_unknown = False
                record = GoRecord(dict(marker, phase='reserved', generation=0, group_add=None, rf_requested=False))
                result = self._save(record); self._now()
                return result
            except BaseException as error:
                self.failure, self.observation_failed = error, True
                raise

    def prepare_group_add(self, frequency):
        with self.mutex:
            self._owner()
            if self.prepare_attempted or self.restore_attempted or self.current is None or self.current.record.phase != 'reserved' or \
                    self.failure is not None or self.publication_unknown or type(frequency) is not int or frequency not in range(2412, 2473, 5):
                _fail('preparation_unavailable')
            self.prepare_attempted = True
            self.scope_until = min(self.until, self._now(False) + PREPARE_SECONDS)
            try:
                fields = self.current.record.data()
                fields.update(phase='group_add_prepared', generation=1, group_add={
                    'frequency': frequency, 'command_sha256': hashlib.sha256(('P2P_GROUP_ADD freq=%d' % frequency).encode('ascii')).hexdigest()})
                return self._save(GoRecord(fields))
            except BaseException as error:
                self.failure, self.observation_failed = error, True
                raise

    def restore_unmutated(self, original_cleanup_until):
        """Exactly once. No signals/interface delete or unknown publication repair."""
        with self.mutex:
            self._owner()
            if self.restore_attempted: _fail('restore_already_attempted')
            self.restore_attempted = True
            try:
                now, end = self._now(False), _number(original_cleanup_until)
                if not 0 < end - now <= CLEANUP_SECONDS: _fail('cleanup_until_invalid')
                self.restore_until, self.scope_until = end, end
                if self.current is None or self.failure is not None or self.publication_unknown:
                    _fail('publication_pending')
                self._fresh()
                if self._boot_read() != self.boot_id: _fail('boot_changed')
                fields = self.current.record.data()
                fields.update(phase='restore_intent', generation=fields['generation'] + 1)
                self._save(GoRecord(fields))
                fields = self.current.record.data()
                fields.update(phase='reconciled', generation=fields['generation'] + 1)
                self._save(GoRecord(fields)); self._fresh()
                if self.io.unlink_at(self.tmp.fd, GLOBAL_PENDING) is not None: _fail('unlink_unknown')
                self._sync(self.tmp.fd); self._absent(self.tmp, GLOBAL_PENDING)
                self.marker_cleared = True; self.logical_restored = True
            except BaseException as error:
                self.restore_failure = error
            finally:
                # Device OFD closes last. A logical failed observation never
                # erases a known physical close+typed EBADF inventory fact.
                for row in reversed(self.rows):
                    if row is not self.device: self._close(row)
                if self.device is not None: self._close(self.device)
            return self.closed_facts()

    def closed_facts(self):
        """Actual local inventory tuples, not core.CloseProof or network restore."""
        return tuple((row.attempted or row.closed, row.closed and not row.unknown) for row in self.rows)

    def status(self):
        return {'phase': None if self.current is None else self.current.record.phase,
            'original_until': self.until, 'restore_called': self.restore_attempted,
            'reservation_marker_cleared': self.marker_cleared,
            'journal_and_marker_reconciled': self.logical_restored,
            'unmutated_reservation_reconciled': self.logical_restored and all(a and c for a, c in self.closed_facts()),
            'fd_inventory_count': len(self.rows),
            'fd_pending_count': sum(not row.closed or row.unknown for row in self.rows),
            'publication_unknown': self.publication_unknown,
            'native_rf_bootstrap_implemented': False, 'go_ready': False,
            'ip_ready': False, 'dhcp_ready': False, 'send_available': False,
            'receive_available': False, 'stock_restore_verified': False,
            'device_tested': False, 'phone_tested': False}
