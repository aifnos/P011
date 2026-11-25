"""Synchronous fixed CLIENT lock resources, NOT a Store or executor proof.

Import/constructor have no I/O. Old/global pending is observed only and any
entry blocks. No marker writing, unlock, fork, inherited registration or RF.
Trusted callers must exclusively own every recorded descriptor lifecycle.
"""
import ctypes
import errno
import math
import os
import stat
import sys
import threading
import time

import mta_p2p_client_init as core
import mta_client_tmp_alias as tmp_alias


BASE = 'p011-mta-client-rfinit'
RUN_PREFIX = 'client-'
DEVICE_LOCK = 'p011-mta-p2p-device.lock'
GLOBAL_PENDING = 'p011-mta-p2p-device.pending'
JOURNAL_LOCK = 'journal.lock'
LOCK_FLAGS = 2 | 4  # LOCK_EX | LOCK_NB; NEVER LOCK_UN.
MAX_RESOURCES = 6
FIXED_ALIAS_RESOURCES = 8  # Two extra physical prefix tickets; ordinary MAX6 unchanged.
_HEX = frozenset('0123456789abcdef')
_RLOCK_TYPE = type(threading.RLock())
_CODES = frozenset(('invalid_config', 'unsupported_platform', 'unsupported_io',
    'invalid_clock', 'clock_regressed', 'deadline', 'already_attempted',
    'invalid_lockset', 'not_acquired', 'resource_pending', 'unsafe_directory',
    'directory_changed', 'unsafe_lock', 'lock_changed', 'global_pending_blocked',
    'lock_create_race', 'flock_failed', 'flock_unknown', 'close_unverified',
    'invalid_descriptor', 'resource_budget', 'io_error', 'operation_interrupted',
    'invalid_handoff', 'handoff_attempted', 'journal_released', 'handoff_unknown'))


class CoordinationError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise CoordinationError(code) from None


def _int(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def _errno(error, number):
    return type(error.errno) is int and error.errno == number


class _DomainLock(object):
    """Outer serialization first; recapture after an initial bind changes it."""
    def __init__(self, owner, inner):
        self.owner, self.inner, self.outer = owner, inner, None

    def __enter__(self):
        while True:
            outer = self.owner._serialization_lock
            outer.acquire()
            try:
                self.inner.acquire()
            except BaseException:
                outer.release()
                raise
            if outer is self.owner._serialization_lock:
                self.outer = outer
                return self
            self.inner.release()
            outer.release()

    def __exit__(self, *unused):
        try:
            self.inner.release()
        finally:
            self.outer.release()


class _Private(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable coordination observation')

    def __repr__(self):
        return '<CLIENT private coordination observation>'

    __str__ = __repr__


class LockSet(_Private):
    """Exact instance ticket, not ownership/same-OFD/mutation authority."""
    __slots__ = ('_issuer', '_device', '_journal')

    def __init__(self, issuer, device, journal):
        for key, value in (('_issuer', issuer), ('_device', device), ('_journal', journal)):
            object.__setattr__(self, key, value)


class ClosedObservation(_Private):
    """Readback only; not core.CloseProof or a cleared-pending receipt."""
    __slots__ = ('_issuer', 'observed', 'unreturned_open_count', 'resource_pending')

    def __init__(self, issuer, observed, unknown, pending):
        for key, value in (('_issuer', issuer), ('observed', observed),
                           ('unreturned_open_count', unknown), ('resource_pending', pending)):
            object.__setattr__(self, key, value)

    def complete(self):
        return bool(self.observed and not self.unreturned_open_count and not self.resource_pending and all(self.observed))


class ReleasedJournal(_Private):
    """Issuer-registered local handoff, not an Executor or inherited proof."""
    __slots__ = ('_issuer', '_context')

    def __init__(self, issuer, context):
        object.__setattr__(self, '_issuer', issuer)
        object.__setattr__(self, '_context', context)


class ReacquiredJournal(_Private):
    __slots__ = ('_issuer', '_context', 'locks')

    def __init__(self, issuer, context, locks):
        for key, value in (('_issuer', issuer), ('_context', context), ('locks', locks)):
            object.__setattr__(self, key, value)


class _JournalHandoff(object):
    """Strong references survive every partial release/open/publish window."""
    def __init__(self, owner, locks, binding, epoch):
        self.owner, self.initial, self.binding, self.epoch = owner, locks, binding, epoch
        self.device, self.journal = locks._device, locks._journal
        self.original_identity = locks._journal.identity
        self.old_epoch, self.new_epoch = None, object()
        self.stage, self.unknown = 'preparing', False
        self.released, self.reacquired, self.new_ticket, self.new_locks = None, None, None, None
        self.release_verified, self.reacquire_attempted = False, False

    def __repr__(self):
        return '<CLIENT private journal handoff>'


class _Fd(object):
    __slots__ = ('io', 'fd', 'role', 'opening_unknown', 'attempted', 'closed',
                 'flock_state', 'parent', 'name', 'identity')

    def __init__(self, io, role):
        self.io, self.fd, self.role = io, None, role
        self.opening_unknown, self.attempted, self.closed = True, False, False
        self.flock_state, self.parent, self.name, self.identity = 'not_attempted', None, None, None

    def __repr__(self):
        return '<CLIENT private exact lock resource>'


class _LinuxIo(object):
    def __init__(self):
        self.library = None

    def validate(self):
        if sys.platform != 'linux' or os.geteuid() != 0: _fail('unsupported_platform')
        if os.stat not in getattr(os, 'supports_dir_fd', ()) or \
                os.stat not in getattr(os, 'supports_follow_symlinks', ()):
            _fail('unsupported_io')

    def flag(self, name):
        value = getattr(os, name, None)
        if not _int(value, 0, 0x7fffffff): _fail('unsupported_io')
        return value

    def _libc(self):
        if self.library is None:
            library = ctypes.CDLL(None, use_errno=True)
            library.flock.argtypes = (ctypes.c_int, ctypes.c_int)
            library.flock.restype = ctypes.c_int
            library.openat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint)
            library.openat.restype = ctypes.c_int
            self.library = library
        return self.library

    def open_root(self, flags): return os.open('/', flags)

    def open_at(self, parent, name, flags, mode=0):
        if os.open in getattr(os, 'supports_dir_fd', ()):
            return os.open(name, flags, mode, dir_fd=parent)
        result = self._libc().openat(parent, name.encode('ascii'), flags, mode)
        if result < 0: raise OSError(ctypes.get_errno(), 'CLIENT fixed open failure')
        return result

    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def stat_root(self): return os.stat('/', follow_symlinks=False)
    def readlink_at(self, parent, name):
        if name != 'tmp': _fail('unsupported_io')
        if os.readlink in getattr(os, 'supports_dir_fd', ()):
            return os.readlink(name, dir_fd=parent)
        library = self._libc()
        library.readlinkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
        library.readlinkat.restype = ctypes.c_ssize_t
        buffer = ctypes.create_string_buffer(256)
        ctypes.set_errno(0)
        size = library.readlinkat(parent, b'tmp', buffer, 256)
        if size < 0: raise OSError(ctypes.get_errno(), 'CLIENT fixed readlink failure')
        if not 0 < size < 256: _fail('unsafe_directory')
        return buffer.raw[:size].decode('ascii')
    def fstat(self, fd): return os.fstat(fd)
    def close(self, fd): return os.close(fd)

    def flock(self, fd, flags):
        library = self._libc()
        ctypes.set_errno(0)
        result = library.flock(fd, flags)
        return result, ctypes.get_errno()

    def pause(self, seconds): time.sleep(seconds)


def _metadata(value):
    row = tuple(getattr(value, key, None) for key in
                ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(not _int(v) for v in row): _fail('unsafe_lock')
    return row


def _directory(value, private=False, temporary=False):
    row = _metadata(value)
    if not stat.S_ISDIR(row[2]) or row[3] != 0 or row[5] < 1: _fail('unsafe_directory')
    mode = stat.S_IMODE(row[2])
    if private:
        if mode != 0o700: _fail('unsafe_directory')
    elif mode & 0o022 and not (temporary and mode & stat.S_ISVTX):
        _fail('unsafe_directory')
    return row[:5]  # Time/size/nlink changes from normal entry creation are not identity.


def _lock_identity(value):
    row = _metadata(value)
    if not stat.S_ISREG(row[2]) or row[3] != 0 or row[5] != 1 or \
            stat.S_IMODE(row[2]) != 0o600 or row[6] != 0:
        _fail('unsafe_lock')
    return row


class ClientCoordination(object):
    """One synchronous acquisition lifetime in a fixed, already-existing run.

    RLock covers individual methods ONLY, not a cross-call journal/RLock lease.
    This is not ClientInitStore, ExecutorProof, inherited OFD or RF admission.
    _io/_clock are trusted HOST/internal seams; never UI configuration.
    """
    def __init__(self, run_token, identity, timeout=3.0, _io=None, _clock=None,
                 _serialization_lock=None):
        if type(run_token) is not str or len(run_token) != 32 or any(c not in _HEX for c in run_token) or \
                type(identity) is not core.Identity or type(timeout) not in (int, float) or \
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or \
                (_clock is not None and not callable(_clock)) or \
                (_serialization_lock is not None and type(_serialization_lock) is not _RLOCK_TYPE):
            _fail('invalid_config')
        self._run, self._identity, self._timeout = RUN_PREFIX + run_token, identity, float(timeout)
        self._io, self._clock = _io if _io is not None else _LinuxIo(), _clock or time.monotonic
        self._mutex, self._issuer = threading.RLock(), object()
        self._serialization_lock = _serialization_lock if _serialization_lock is not None else self._mutex
        self._serial_explicit = _serialization_lock is not None
        self._owned_marker_binding, self._owned_marker_epoch = None, None
        self._inventory, self._anchors = [], []
        self._tmp_alias = None
        self._locksets, self._handoff = [], None
        self._locks, self._attempted, self._ended = None, False, False
        self._resource_pending, self._lock_unknown = False, False
        self._stage, self._reason = 'new', 'not_recorded'
        self._last_clock, self._deadline = None, None

    def _operation(self):
        return _DomainLock(self, self._mutex)

    def _begin(self):
        self._last_clock, self._deadline = None, None
        self._deadline = self._check() + self._timeout

    def _handoff_budget(self, deadline):
        if type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or \
                not math.isfinite(float(deadline)):
            _fail('invalid_config')
        self._begin()
        now = self._check()
        if not 0 < deadline - now <= 20: _fail('deadline')
        self._deadline = min(self._deadline, float(deadline))

    def _check(self):
        try: value = self._clock()
        except Exception: _fail('invalid_clock')
        if type(value) not in (int, float) or not -1e12 <= value <= 1e12 or not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock: _fail('clock_regressed')
        self._last_clock = value
        if self._deadline is not None and value >= self._deadline: _fail('deadline')
        return value

    def _flags(self, *names):
        result = 0
        for name in names:
            flag = self._io.flag(name)
            if not _int(flag, 0, 0x7fffffff): _fail('unsupported_io')
            result |= flag
        return result

    def _open(self, parent, name, flags, mode=0, role='anchor'):
        self._check()
        limit = FIXED_ALIAS_RESOURCES if self._tmp_alias is not None else MAX_RESOURCES
        if len(self._inventory) >= limit: _fail('resource_budget')
        ticket = _Fd(self._io, role)
        self._inventory.append(ticket)  # Before any actual creation/open.
        try:
            ticket.fd = self._io.open_root(flags) if parent is None else self._io.open_at(parent, name, flags, mode)
            if not _int(ticket.fd, 0, 0x7fffffff):
                self._resource_pending = True
                _fail('invalid_descriptor')
            if any(t is not ticket and not t.closed and t.fd == ticket.fd for t in self._inventory):
                self._resource_pending = True
                _fail('invalid_descriptor')  # Retain unknown return; never close a borrowed numeric FD.
            ticket.opening_unknown = False
            return ticket
        except OSError as error:
            # Direct POSIX open's explicit error returns no FD. A non-returned
            # Python result/MemoryError is not this contract and stays unknown.
            if ticket.fd is None and _int(error.errno, 1, 4095):
                ticket.opening_unknown, ticket.closed = False, True
            else: self._resource_pending = True
            raise
        except BaseException:
            self._resource_pending = True
            raise

    def _close_one(self, ticket):
        if ticket.closed or ticket.attempted: return
        if ticket.opening_unknown or not _int(ticket.fd, 0, 0x7fffffff):
            self._resource_pending = True
            return
        ticket.attempted = True
        returned = False
        try:
            returned = ticket.io.close(ticket.fd) is None
        except BaseException:
            self._resource_pending = True
        try:
            ticket.io.fstat(ticket.fd)
        except OSError as error:
            if returned and _errno(error, errno.EBADF):
                ticket.closed = True
                ticket.flock_state = 'closed'
                return
        except BaseException:
            pass
        self._resource_pending = True

    def _close_all(self):
        for ticket in reversed(self._inventory):
            try: self._close_one(ticket)
            except BaseException: self._resource_pending = True

    def _anchors_valid(self):
        if self._tmp_alias is not None:
            self._tmp_alias.authenticate(self, self._anchors[0][0])
        for ticket, parent, name, identity, private, temporary in self._anchors:
            self._check()
            if _directory(self._io.fstat(ticket.fd), private, temporary) != identity:
                _fail('directory_changed')
            if parent is not None and _directory(self._io.stat_at(parent.fd, name), private, temporary) != identity:
                _fail('directory_changed')

    def _tmp_fd(self, ticket):
        self._check()
        if type(ticket) is not _Fd or not any(t is ticket for t in self._inventory) or \
                ticket.io is not self._io or ticket.closed or ticket.attempted or ticket.opening_unknown or \
                not _int(ticket.fd, 0, 0x7fffffff): _fail('invalid_descriptor')
        return ticket.fd

    def _tmp_open_dir(self, parent, name):
        if self._tmp_alias is None or not (name == 'var' and parent is self._anchors[0][0] or
                name == 'volatile' and self._tmp_alias.prefix_tickets and
                parent is self._tmp_alias.prefix_tickets[0]): _fail('unsafe_directory')
        return self._open(self._tmp_fd(parent), name,
            self._flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC'), role='tmp_alias_' + name)

    def _pending_absent(self):
        self._stage = 'pending_readonly'
        self._check()
        if self._owned_marker_binding is not None:
            from mta_client_pending import OwnedMarkerBinding
            binding = self._owned_marker_binding
            if type(binding) is not OwnedMarkerBinding:
                _fail('global_pending_blocked')
            binding.verify(self, self._owned_marker_epoch)
            self._check()
            return
        try: self._io.stat_at(self._anchors[1][0].fd, GLOBAL_PENDING)
        except OSError as error:
            if _errno(error, errno.ENOENT): return
            raise
        _fail('global_pending_blocked')

    def _lock_valid(self, ticket):
        self._check()
        if ticket.closed or ticket.attempted or ticket.opening_unknown or ticket.flock_state != 'acquired':
            _fail('not_acquired')
        if _lock_identity(self._io.fstat(ticket.fd)) != ticket.identity or \
                _lock_identity(self._io.stat_at(ticket.parent.fd, ticket.name)) != ticket.identity:
            _fail('lock_changed')

    def _flock(self, ticket, _strict_success=False):
        while True:
            self._check()
            ticket.flock_state = 'unknown'  # Registered before the call.
            try: result = self._io.flock(ticket.fd, LOCK_FLAGS)
            except BaseException:
                self._lock_unknown, self._resource_pending = True, True
                raise
            if type(result) is not tuple or len(result) != 2 or \
                    type(result[0]) is not int or type(result[1]) is not int or not 0 <= result[1] <= 4095:
                self._lock_unknown, self._resource_pending = True, True
                _fail('flock_unknown')
            code, number = result
            if code == 0:
                if _strict_success and number != 0:
                    self._lock_unknown, self._resource_pending = True, True
                    _fail('flock_unknown')
                ticket.flock_state = 'acquired'
                self._check()
                return
            if code != -1 or number == 0:
                self._lock_unknown, self._resource_pending = True, True
                _fail('flock_unknown')
            ticket.flock_state = 'not_acquired'
            if number not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR): _fail('flock_failed')
            self._check()
            self._io.pause(0.01)  # No retry on any unknown acquisition outcome.

    def _open_lock(self, parent, name, role):
        self._stage = role + '_open'
        self._check()
        before = None
        try: before = _lock_identity(self._io.stat_at(parent.fd, name))
        except OSError as error:
            if not _errno(error, errno.ENOENT): raise
        flags = self._flags('O_RDWR', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC')
        if before is None: flags |= self._flags('O_CREAT', 'O_EXCL')
        try: ticket = self._open(parent.fd, name, flags, 0o600 if before is None else 0, role)
        except OSError as error:
            if before is None and _errno(error, errno.EEXIST): _fail('lock_create_race')
            raise
        current = _lock_identity(self._io.fstat(ticket.fd))
        if before is not None and before != current or \
                _lock_identity(self._io.stat_at(parent.fd, name)) != current:
            _fail('lock_changed')
        ticket.parent, ticket.name, ticket.identity = parent, name, current
        self._stage = role + '_flock'
        self._flock(ticket)
        self._lock_valid(ticket)
        return ticket

    def _owned(self, locks):
        if type(locks) is not LockSet or locks is not self._locks or locks._issuer is not self._issuer:
            _fail('invalid_lockset')
        if self._ended: _fail('not_acquired')
        if self._resource_pending or self._lock_unknown: _fail('resource_pending')
        if self._handoff is not None and self._handoff.stage != 'active':
            _fail('journal_released')

    def _handoff_owned(self, context):
        # Dedicated device-only path; NEVER grants an ordinary released lockset.
        if type(context) is not _JournalHandoff or context is not self._handoff or \
                context.owner is not self or not any(item is context.initial for item in self._locksets) or \
                context.device is not context.initial._device or context.unknown or \
                self._ended or self._resource_pending or self._lock_unknown:
            _fail('handoff_unknown')
        self._anchors_valid()
        self._lock_valid(context.device)
        if context.stage != 'preparing':
            if not context.journal.closed or not context.journal.attempted or context.journal.opening_unknown:
                _fail('close_unverified')
            # Check EBADF before opening. A later owned open may legitimately
            # reuse this numeric FD; never confuse it with the old resource.
            if context.new_ticket is None:
                try: context.journal.io.fstat(context.journal.fd)
                except OSError as error:
                    if not _errno(error, errno.EBADF): raise
                else: _fail('close_unverified')
        if _lock_identity(self._io.stat_at(context.journal.parent.fd, JOURNAL_LOCK)) != context.original_identity:
            _fail('lock_changed')

    def _report(self, error):
        self._reason = error.code if type(error) is CoordinationError else \
            ('io_error' if isinstance(error, Exception) else 'operation_interrupted')
        if type(error) is CoordinationError: raise error from None
        if isinstance(error, Exception): _fail('io_error')
        raise error

    def acquire(self):
        with self._operation():
            if self._attempted or self._ended: _fail('already_attempted')
            self._attempted = True
            try:
                self._begin()
                self._io.validate()
                flags = self._flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
                for name, private, temporary in ((None, False, False), ('tmp', False, True),
                        (BASE, True, False), (self._run, True, False)):
                    self._stage = 'directory_open'
                    parent = self._anchors[-1][0] if self._anchors else None
                    if name == 'tmp' and stat.S_ISLNK(_metadata(self._io.stat_at(parent.fd, name))[2]):
                        self._tmp_alias = tmp_alias.FixedTmpAnchor(self, self._io, parent,
                            self._tmp_fd, self._tmp_open_dir, self._check)
                        self._tmp_alias.prepare()
                        parent = self._tmp_alias.tmp_parent
                    before = None if parent is None else _directory(self._io.stat_at(parent.fd, name), private, temporary)
                    ticket = self._open(None if parent is None else parent.fd, name, flags)
                    identity = _directory(self._io.fstat(ticket.fd), private, temporary)
                    if before is not None and before != identity: _fail('directory_changed')
                    self._anchors.append((ticket, parent, name, identity, private, temporary))
                    if name == 'tmp' and self._tmp_alias is not None: self._tmp_alias.bind_tmp(ticket)
                self._anchors_valid()
                self._pending_absent()
                device = self._open_lock(self._anchors[1][0], DEVICE_LOCK, 'device')
                self._anchors_valid(); self._pending_absent()
                journal = self._open_lock(self._anchors[3][0], JOURNAL_LOCK, 'journal')
                self._anchors_valid(); self._pending_absent()
                self._lock_valid(device); self._lock_valid(journal)
                self._locks = LockSet(self._issuer, device, journal)
                self._locksets.append(self._locks)
                self._stage, self._reason = 'acquired', 'not_recorded'
                return self._locks
            except BaseException as error:
                self._close_all()
                self._report(error)

    def validate(self, locks):
        with self._operation():
            try:
                self._owned(locks); self._begin()
                self._anchors_valid(); self._pending_absent()
                for ticket in (locks._device, locks._journal):
                    self._lock_valid(ticket)
                    self._flock(ticket)  # Current result, not proof of uninterrupted historical ownership.
                    self._lock_valid(ticket)
                self._anchors_valid(); self._pending_absent()
                return True  # Local synchronous validation ONLY, no Executor/OFD/admission proof.
            except BaseException as error: self._report(error)

    def read_pending(self, locks):
        with self._operation():
            try:
                self._owned(locks); self._begin()
                self._anchors_valid(); self._lock_valid(locks._device)
                self._pending_absent()
                result = {'entry_absent_observed': self._owned_marker_binding is None,
                          'pending_modified': False, 'mutation_admission': False}
                if self._owned_marker_binding is not None: result['own_entry_observed'] = True
                return result
            except BaseException as error: self._report(error)

    def release_journal(self, locks):
        with self._operation():
            try:
                self._owned(locks); self._begin()
                self._close_one(locks._journal)
                if not locks._journal.closed: _fail('close_unverified')
                self._stage = 'journal_released'
                return self.status()
            except BaseException as error: self._report(error)

    def release_journal_handoff(self, locks, exact_binding, exact_store_epoch, deadline):
        """Release once under an actual own marker; old release issues no permit."""
        from mta_client_pending import OwnedMarkerBinding
        with self._operation():
            self._owned(locks)
            if self._handoff is not None: _fail('handoff_attempted')
            if type(exact_binding) is not OwnedMarkerBinding or \
                    exact_binding is not self._owned_marker_binding or \
                    exact_store_epoch is not self._owned_marker_epoch or type(exact_store_epoch) is not object:
                _fail('invalid_handoff')
            self._handoff_budget(deadline)
            context = _JournalHandoff(self, locks, exact_binding, exact_store_epoch)
            self._handoff = context  # Before any close; partial context is retained.
            try:
                exact_binding._marker._prepare_journal_handoff(context)
                self._check()
                context.stage = 'releasing'
                self._close_one(context.journal)
                if not context.journal.closed: _fail('close_unverified')
                exact_binding._marker._journal_handoff_live(context)
                self._check()
                context.stage, context.release_verified = 'released', True
                receipt = ReleasedJournal(self._issuer, context)
                context.released = receipt
                self._stage = 'journal_released'
                return receipt
            except BaseException as error:
                context.stage, context.unknown = 'partial', True
                self._report(error)

    def _open_handoff_journal(self, context):
        # Ordinary seventh / fixed-alias ninth slot only; no CREATE or budget broadening.
        self._check()
        if context is not self._handoff or context.stage != 'reacquiring' or \
                context.new_ticket is not None or len(self._inventory) != (
                    FIXED_ALIAS_RESOURCES if self._tmp_alias is not None else MAX_RESOURCES):
            _fail('resource_budget')
        parent = context.journal.parent
        before = _lock_identity(self._io.stat_at(parent.fd, JOURNAL_LOCK))
        if before != context.original_identity: _fail('lock_changed')
        flags = self._flags('O_RDWR', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC')
        ticket = _Fd(self._io, 'journal_handoff')
        context.new_ticket = ticket
        self._inventory.append(ticket)  # Exact creator registered before open.
        try:
            ticket.fd = self._io.open_at(parent.fd, JOURNAL_LOCK, flags, 0)
            if not _int(ticket.fd, 0, 0x7fffffff):
                self._resource_pending = True
                _fail('invalid_descriptor')
            # Real open returns a new descriptor, never an already-live owned
            # one. A malformed internal adapter must not make cleanup close
            # another component's original resource. Closed historical FD
            # numbers may legitimately be reused by this actual new open.
            marker = context.binding._marker
            originals = self._inventory[:-1] + list(context.binding._files._inventory)
            if marker._ticket is not None: originals.append(marker._ticket)
            if any(not original.closed and _int(original.fd, 0, 0x7fffffff) and
                    original.fd == ticket.fd for original in originals):
                self._resource_pending = True
                _fail('invalid_descriptor')
            ticket.opening_unknown = False
        except OSError as error:
            if ticket.fd is None and _int(error.errno, 1, 4095):
                ticket.opening_unknown, ticket.closed = False, True
            else: self._resource_pending = True
            raise
        except BaseException:
            self._resource_pending = True
            raise
        ticket.parent, ticket.name, ticket.identity = parent, JOURNAL_LOCK, before
        self._lock_valid_open_handoff(ticket, before)
        self._flock(ticket, _strict_success=True)
        self._lock_valid(ticket)
        return ticket

    def _lock_valid_open_handoff(self, ticket, identity):
        self._check()
        if _lock_identity(self._io.fstat(ticket.fd)) != identity or \
                _lock_identity(self._io.stat_at(ticket.parent.fd, ticket.name)) != identity:
            _fail('lock_changed')

    def reacquire_journal(self, exact_released_journal, deadline):
        """Once, same original device descriptor; no CREATE or inherited claim."""
        with self._operation():
            context = self._handoff
            if type(exact_released_journal) is not ReleasedJournal or context is None or \
                    exact_released_journal is not context.released or \
                    exact_released_journal._issuer is not self._issuer or \
                    exact_released_journal._context is not context or \
                    context.stage != 'released' or not context.release_verified or context.unknown:
                _fail('invalid_handoff')
            if context.reacquire_attempted: _fail('handoff_attempted')
            self._handoff_budget(deadline)
            context.reacquire_attempted, context.stage = True, 'reacquiring'
            try:
                context.binding._marker._journal_handoff_live(context)
                journal = self._open_handoff_journal(context)
                locks = LockSet(self._issuer, context.device, journal)
                context.new_locks = locks
                self._locksets.append(locks)  # Preserve even a later publish failure.
                receipt = ReacquiredJournal(self._issuer, context, locks)
                context.reacquired = receipt
                context.binding._marker._publish_journal_handoff(context)
                self._check()
                self._stage, self._reason = 'acquired', 'not_recorded'
                return receipt
            except BaseException as error:
                context.stage, context.unknown = 'partial', True
                if context.new_ticket is not None: self._close_one(context.new_ticket)
                self._report(error)

    def read_closed(self, locks=None):
        """Only fstat original recorded FDs; never close/open/flock again."""
        with self._operation():
            if locks is not None and (type(locks) is not LockSet or
                    not any(item is locks for item in self._locksets) or locks._issuer is not self._issuer):
                _fail('invalid_lockset')
            self._begin()
            observed = []
            for ticket in self._inventory:
                self._check()
                closed = ticket.closed and ticket.fd is None and not ticket.opening_unknown
                if _int(ticket.fd, 0, 0x7fffffff) and ticket.attempted:
                    try: ticket.io.fstat(ticket.fd)
                    except OSError as error: closed = _errno(error, errno.EBADF)
                    except BaseException: closed = False
                observed.append(closed)
            return ClosedObservation(self._issuer, tuple(observed),
                sum(t.opening_unknown for t in self._inventory), self._resource_pending or self._lock_unknown or
                bool(self._handoff is not None and self._handoff.unknown))

    def close(self):
        with self._operation():
            self._ended = True
            self._close_all()  # Close all even after clock expiry/readback failure.
            self._stage = 'closed' if not (self._resource_pending or
                self._handoff is not None and self._handoff.unknown) else 'close_unknown'
            return self.status()

    def close_device_last(self):
        """Independent original inventory close; default close is unchanged.

        Trusted Store calls this AFTER marker/FILES close attempts. No unlock,
        reopening or retry of an attempted/unknown descriptor is permitted.
        """
        with self._operation():
            self._ended = True
            device = None
            for ticket in self._inventory:
                if ticket.role == 'device':
                    if device is not None: self._resource_pending = True
                    device = ticket
            for ticket in reversed(self._inventory):
                if ticket is not device:
                    try: self._close_one(ticket)
                    except BaseException: self._resource_pending = True
            if device is not None:
                try: self._close_one(device)
                except BaseException: self._resource_pending = True
            self._stage = 'closed' if not (self._resource_pending or
                self._handoff is not None and self._handoff.unknown) else 'close_unknown'
            return self.status()

    def status(self):
        with self._operation():
            return {'evidence': 'CLIENT_COORDINATION_ONLY', 'stage': self._stage, 'reason': self._reason,
                'known_fd_count': sum(_int(t.fd, 0, 0x7fffffff) for t in self._inventory),
                'unreturned_open_count': sum(t.opening_unknown for t in self._inventory),
                'close_attempted_count': sum(t.attempted for t in self._inventory),
                'all_original_fds_closed': bool(self._inventory and all(t.closed for t in self._inventory)),
                'resource_pending': self._resource_pending or bool(self._handoff is not None and self._handoff.unknown),
                'lock_unknown': self._lock_unknown,
                'pending_modified': False, 'same_ofd_verified': False, 'executor_verified': False,
                'store_implemented': False, 'mutation_admission': False}
