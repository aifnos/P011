"""Private CLIENT journal file primitives, NOT a Store or RF authority.

Construction is pure. Directories are created/reviewed by the outer owner.
Only the fixed root/run and journal names below are supported. The old GLOBAL
pending is observed only: any entry blocks. No flock/Executor/finish/clear API.
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
import mta_client_journal_codec as codec
import mta_client_tmp_alias as tmp_alias
import mta_client_resource_budget as resources


ROOT_COMPONENT = 'p011-mta-client-rfinit'
RUN_PREFIX = 'client-'
JOURNAL = 'journal.json'
GLOBAL_PENDING = 'p011-mta-p2p-device.pending'
MAX_RESOURCES = sum(resources.SOURCE_PROFILE.count_limit(lane, 'FILES_OPEN')
    for lane in (resources.PREPARATION_NETWORK, resources.CLEANUP))
_LEGACY_MAX_RESOURCES = 256
_HEX = frozenset('0123456789abcdef')
_RLOCK_TYPE = type(threading.RLock())
_CODES = frozenset(('invalid_config', 'unsupported_platform', 'unsupported_io',
    'invalid_clock', 'clock_regressed', 'deadline', 'not_open', 'already_open',
    'resource_pending', 'write_pending', 'unsafe_directory', 'directory_changed',
    'unsafe_file', 'file_changed', 'byte_budget', 'invalid_read', 'invalid_write',
    'global_pending_blocked', 'stale_current', 'invalid_expected', 'invalid_record',
    'temp_exists', 'durability_unknown', 'readback_changed', 'close_unverified',
    'io_error', 'operation_interrupted', 'invalid_descriptor', 'resource_budget'))


class ClientFileError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise ClientFileError(code) from None


def _complete_credit_v23(budget, credit, original, payloads, unknown, producer_failed):
    """Always end the actual actor; retain unknown and the producer's first failure."""
    accounting_error = None
    try:
        budget.returned(credit, original, payloads)
    except BaseException as error:
        accounting_error = error
        try: budget.mark_unknown(credit)
        except BaseException: pass
    finally:
        try:
            if unknown: budget.mark_unknown(credit)
        except BaseException as error:
            if accounting_error is None: accounting_error = error
        finally:
            try: budget.settle(credit)
            except BaseException as error:
                if accounting_error is None: accounting_error = error
    if accounting_error is not None and not producer_failed: raise accounting_error


def _integer(value, minimum=0, maximum=(1 << 64) - 1):
    return type(value) is int and minimum <= value <= maximum


def _err(error, number):
    return type(error.errno) is int and error.errno == number


class _DomainLock(object):
    """No new imports/default authority; same outer-first binding transition."""
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
        raise AttributeError('private immutable file observation')

    def __repr__(self):
        return '<CLIENT private file observation>'

    __str__ = __repr__


class CanonicalRecord(_Private):
    __slots__ = ('journal', 'data', 'metadata', '_issuer', '_generation')

    def __init__(self, journal, data, metadata, issuer, generation):
        for name, value in (('journal', journal), ('data', data), ('metadata', metadata),
                            ('_issuer', issuer), ('_generation', generation)):
            object.__setattr__(self, name, value)


class _Fd(object):
    """Registered BEFORE opening. Unknown returned resources keep exact IO refs."""
    __slots__ = ('io', 'fd', 'stage', 'attempted', 'closed', 'opening_unknown')

    def __init__(self, io, stage):
        self.io, self.fd, self.stage = io, None, stage
        self.attempted, self.closed, self.opening_unknown = False, False, True

    def __repr__(self):
        return '<CLIENT private owned file resource>'


class _LinuxIo(object):
    """Actual Linux calls; no library loading or I/O until explicit methods."""
    def __init__(self):
        self.library = None

    def flag(self, name):
        value = getattr(os, name, None)
        if not _integer(value, 0, 0x7fffffff): _fail('unsupported_io')
        return value

    def validate(self):
        if sys.platform != 'linux' or os.geteuid() != 0: _fail('unsupported_platform')
        if os.stat not in getattr(os, 'supports_dir_fd', ()) or \
                os.stat not in getattr(os, 'supports_follow_symlinks', ()):
            _fail('unsupported_io')

    def _libc(self):
        if self.library is None:
            library = ctypes.CDLL(None, use_errno=True)
            library.openat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint)
            library.openat.restype = ctypes.c_int
            library.renameat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
            library.renameat.restype = ctypes.c_int
            self.library = library
        return self.library

    def open_root(self, flags):
        return os.open('/', flags)

    def open_at(self, parent, name, flags, mode=0):
        if os.open in getattr(os, 'supports_dir_fd', ()):
            return os.open(name, flags, mode, dir_fd=parent)
        result = self._libc().openat(parent, name.encode('ascii'), flags, mode)
        if result < 0: raise OSError(ctypes.get_errno(), 'CLIENT fixed open failure')
        return result

    def stat_at(self, parent, name):
        return os.stat(name, dir_fd=parent, follow_symlinks=False)

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

    def rename_at(self, parent, source, target):
        result = self._libc().renameat(parent, source.encode('ascii'), parent, target.encode('ascii'))
        if result != 0: raise OSError(ctypes.get_errno(), 'CLIENT fixed rename failure')

    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, data): return os.write(fd, data)
    def fsync(self, fd): return os.fsync(fd)
    def close(self, fd): return os.close(fd)


def _metadata(value):
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    row = tuple(getattr(value, name, None) for name in fields)
    if any(not _integer(v) for v in row[:7]) or \
            any(not _integer(v, -(1 << 63), (1 << 63) - 1) for v in row[7:]):
        _fail('unsafe_file')
    return row


def _dir_identity(value, private=False, temporary=False):
    row = _metadata(value)
    if not stat.S_ISDIR(row[2]) or row[3] != 0 or row[5] < 1:
        _fail('unsafe_directory')
    mode = stat.S_IMODE(row[2])
    if private:
        if mode != 0o700: _fail('unsafe_directory')
    elif mode & 0o022 and not (temporary and mode & stat.S_ISVTX):
        _fail('unsafe_directory')
    # Directory time/size/link count may change from ordinary entry updates.
    return row[:5]


def _file_metadata(value):
    row = _metadata(value)
    if not stat.S_ISREG(row[2]) or row[3] != 0 or row[5] != 1 or \
            stat.S_IMODE(row[2]) != 0o600 or row[6] > codec.MAX_BYTES:
        _fail('unsafe_file')
    return row


class ClientJournalFiles(object):
    """Fixed existing /tmp/p011-mta-client-rfinit/client-<32hex> only.

    Trusted adapters are HOST/internal, never a UI path/provider option. CAS
    assumes an outer owner serializes ALL writers with its real journal lock.
    This component does not grant that lock or any mutation admission.
    """
    def __init__(self, run_token, identity, timeout=3.0, _io=None, _clock=None,
                 _serialization_lock=None, _resource_budget=None):
        if type(run_token) is not str or len(run_token) != 32 or any(c not in _HEX for c in run_token) or \
                type(identity) is not core.Identity or type(timeout) not in (int, float) or \
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or \
                (_clock is not None and not callable(_clock)) or \
                (_serialization_lock is not None and type(_serialization_lock) is not _RLOCK_TYPE):
            _fail('invalid_config')
        self._run, self._identity, self._timeout = RUN_PREFIX + run_token, identity, float(timeout)
        self._io, self._clock = _io if _io is not None else _LinuxIo(), _clock or time.monotonic
        self._lock, self._issuer = threading.RLock(), object()
        self._serialization_lock = _serialization_lock if _serialization_lock is not None else self._lock
        self._serial_explicit = _serialization_lock is not None
        if _resource_budget is not None and (type(_resource_budget) is not resources.ResourceBudget or
                _resource_budget._mutex is not self._serialization_lock): _fail('invalid_config')
        self._resource_budget_v23 = _resource_budget
        self._owned_marker_binding, self._owned_marker_epoch = None, None
        self._issued_canonicals = []  # Exact public return instances, bounded by FD inventory.
        self._inventory, self._anchors = [], []
        self._tmp_alias = None
        self._opened, self._ended, self._resource_pending, self._write_pending = False, False, False, False
        self._publication_attempted, self._published_unknown = False, False
        self._generation, self._temp_counter = 0, 0
        self._stage, self._reason = 'new', 'not_recorded'
        self._last_clock, self._deadline = None, None

    def _operation(self):
        return _DomainLock(self, self._lock)

    def _begin_budget(self):
        self._last_clock, self._deadline = None, None
        self._deadline = self._check() + self._timeout

    def _check(self):
        value = self._clock()
        if type(value) not in (int, float) or not -1e12 <= value <= 1e12 or not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock: _fail('clock_regressed')
        self._last_clock = value
        if self._deadline is not None and value >= self._deadline: _fail('deadline')
        return value

    def _open_fd(self, parent, name, flags, mode=0):
        self._check()
        if len(self._inventory) >= (MAX_RESOURCES if self._resource_budget_v23 is not None else _LEGACY_MAX_RESOURCES):
            _fail('resource_budget')
        credit = self._reserve_v23('FILES_OPEN', 0)
        ticket = _Fd(self._io, self._stage)
        self._inventory.append(ticket)
        if credit is not None: self._resource_budget_v23.started(credit)
        producer_failed = False
        try:
            ticket.fd = (self._io.open_root(flags) if parent is None else
                         self._io.open_at(parent, name, flags, mode))
            if not _integer(ticket.fd, 0, 0x7fffffff):
                self._resource_pending = True
                _fail('invalid_descriptor')
            if any(t is not ticket and not t.closed and t.fd == ticket.fd for t in self._inventory):
                self._resource_pending = True
                _fail('invalid_descriptor')  # Unknown possibly-borrowed return is never blindly closed.
            ticket.opening_unknown = False
            return ticket
        except OSError as error:
            producer_failed = True
            # Trusted OS open's negative result is known to return no FD.
            if ticket.fd is None and _integer(error.errno, 1, 4095):
                ticket.opening_unknown, ticket.closed = False, True
            else:
                self._resource_pending = True
            raise
        except BaseException:
            producer_failed = True
            self._resource_pending = True
            raise
        finally:
            if credit is not None:
                budget = self._resource_budget_v23
                _complete_credit_v23(budget, credit, ticket, (),
                    ticket.opening_unknown or self._resource_pending, producer_failed)

    def _reserve_v23(self, kind, maximum):
        budget = self._resource_budget_v23
        if budget is None: return None
        return budget.reserve(budget._store._resource_lane_v23, kind, maximum)

    def _close_one(self, ticket):
        if ticket.closed or ticket.attempted: return
        if ticket.opening_unknown or not _integer(ticket.fd, 0, 0x7fffffff):
            self._resource_pending = True
            return
        ticket.attempted = True  # Never repeat close on a possibly reused FD.
        returned = False
        try:
            ticket.io.close(ticket.fd)
            returned = True
        except BaseException:
            self._resource_pending = True
        # Readback is independently attempted even if close raised.
        try:
            ticket.io.fstat(ticket.fd)
        except OSError as error:
            if returned and _err(error, errno.EBADF):
                ticket.closed = True
                return
        except BaseException:
            pass
        self._resource_pending = True

    def _flags(self, *names):
        value = 0
        for name in names: value |= self._io.flag(name)
        return value

    def _anchors_valid(self):
        self._check()
        if self._tmp_alias is not None:
            self._tmp_alias.authenticate(self, self._anchors[0][0])
        for ticket, parent, name, identity, private, temporary in self._anchors:
            current = _dir_identity(self._io.fstat(ticket.fd), private, temporary)
            if current != identity: _fail('directory_changed')
            if parent is not None and _dir_identity(self._io.stat_at(parent.fd, name), private, temporary) != identity:
                _fail('directory_changed')
            self._check()

    def _tmp_fd(self, ticket):
        self._check()
        if type(ticket) is not _Fd or not any(t is ticket for t in self._inventory) or \
                ticket.io is not self._io or ticket.closed or ticket.attempted or ticket.opening_unknown or \
                not _integer(ticket.fd, 0, 0x7fffffff): _fail('invalid_descriptor')
        return ticket.fd

    def _tmp_open_dir(self, parent, name):
        if self._tmp_alias is None or not (name == 'var' and parent is self._anchors[0][0] or
                name == 'volatile' and self._tmp_alias.prefix_tickets and
                parent is self._tmp_alias.prefix_tickets[0]): _fail('unsafe_directory')
        return self._open_fd(self._tmp_fd(parent), name,
            self._flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC'))

    def _pending_absent(self):
        self._stage = 'global_pending_readonly'
        self._check()
        if self._owned_marker_binding is not None:
            from mta_client_pending import OwnedMarkerBinding
            binding = self._owned_marker_binding
            if type(binding) is not OwnedMarkerBinding:
                _fail('global_pending_blocked')
            binding.verify(self, self._owned_marker_epoch)
            self._check()
            return
        try:
            self._io.stat_at(self._anchors[1][0].fd, GLOBAL_PENDING)
        except OSError as error:
            if _err(error, errno.ENOENT): return
            raise
        _fail('global_pending_blocked')  # Any entry, including symlink/unknown version.

    def _ensure_open(self):
        if self._resource_pending: _fail('resource_pending')
        if not self._opened or self._ended: _fail('not_open')

    def open(self):
        with self._operation():
            if self._opened or self._ended or self._inventory: _fail('already_open')
            self._begin_budget()
            try:
                self._io.validate()
                flags = self._flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
                parent = None
                for name, private, temporary in ((None, False, False), ('tmp', False, True),
                        (ROOT_COMPONENT, True, False), (self._run, True, False)):
                    self._stage = 'directory_open'
                    if name == 'tmp' and stat.S_ISLNK(_metadata(self._io.stat_at(parent.fd, name))[2]):
                        self._tmp_alias = tmp_alias.FixedTmpAnchor(self, self._io, parent,
                            self._tmp_fd, self._tmp_open_dir, self._check)
                        self._tmp_alias.prepare()
                        parent = self._tmp_alias.tmp_parent
                    ticket = self._open_fd(None if parent is None else parent.fd, name, flags)
                    try:
                        identity = _dir_identity(self._io.fstat(ticket.fd), private, temporary)
                        if parent is not None and _dir_identity(self._io.stat_at(parent.fd, name), private, temporary) != identity:
                            _fail('directory_changed')
                        self._anchors.append((ticket, parent, name, identity, private, temporary))
                        if name == 'tmp' and self._tmp_alias is not None: self._tmp_alias.bind_tmp(ticket)
                    except BaseException:
                        self._close_one(ticket)
                        raise
                    parent = ticket
                self._anchors_valid()
                self._pending_absent()
                self._opened, self._stage = True, 'opened'
                return self
            except BaseException as error:
                self._reason = error.code if type(error) is ClientFileError else 'io_error'
                self.close()
                if type(error) is ClientFileError: raise
                if isinstance(error, Exception): _fail('io_error')
                raise

    def _read_current(self):
        self._stage = 'journal_read'
        parent = self._anchors[-1][0].fd
        try:
            entry = _file_metadata(self._io.stat_at(parent, JOURNAL))
        except OSError as error:
            if _err(error, errno.ENOENT): return None
            raise
        credit = self._reserve_v23('CANONICAL', entry[6])
        data, metadata, record, result, ticket = b'', None, None, None, None
        if credit is not None: self._resource_budget_v23.started(credit)
        producer_failed = False
        try:
            ticket = self._open_fd(parent, JOURNAL, self._flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
            try:
                metadata = _file_metadata(self._io.fstat(ticket.fd))
                if metadata != entry: _fail('file_changed')
                while True:
                    self._check()
                    requested = min(4096, entry[6] + 1 - len(data))
                    chunk = self._io.read(ticket.fd, requested)
                    if type(chunk) is not bytes or len(chunk) > requested: _fail('invalid_read')
                    data += chunk
                    if len(data) > entry[6]: _fail('file_changed')
                    if not chunk: break
                if _file_metadata(self._io.fstat(ticket.fd)) != metadata or \
                        _file_metadata(self._io.stat_at(parent, JOURNAL)) != metadata:
                    _fail('file_changed')
                record = codec.decode_journal(data)
                if record.identity.key() != self._identity.key(): _fail('invalid_record')
                self._check()
            finally:
                self._close_one(ticket)  # No allocations/audit callbacks before close.
            if not ticket.closed: _fail('close_unverified')
            result = CanonicalRecord(record, data, metadata, self._issuer, self._generation)
            return result
        except BaseException:
            producer_failed = True
            raise
        finally:
            if credit is not None:
                budget = self._resource_budget_v23
                _complete_credit_v23(budget, credit,
                    result if result is not None else (ticket, metadata, data), (data,),
                    self._resource_pending or ticket is not None and ticket.opening_unknown,
                    producer_failed)

    def read_current(self):
        with self._operation():
            self._ensure_open(); self._begin_budget()
            self._anchors_valid()
            try:
                # Existing default read-only behavior is unchanged; a bound
                # consumer always fresh-checks its own marker before reading.
                if self._owned_marker_binding is not None: self._pending_absent()
                result = self._read_current()
                if result is not None: self._issued_canonicals.append(result)
                return result
            except (ClientFileError, resources.ResourceBudgetError): raise
            except Exception: _fail('io_error')

    def _cas(self, expected):
        current = self._read_current()
        if expected is None:
            if current is not None: _fail('stale_current')
        elif current is None or current.data != expected.data or current.metadata != expected.metadata:
            _fail('stale_current')

    def commit(self, expected, record):
        with self._operation():
            self._ensure_open()
            if self._write_pending: _fail('write_pending')
            if expected is not None and (type(expected) is not CanonicalRecord or expected._issuer is not self._issuer or
                    expected._generation != self._generation): _fail('invalid_expected')
            if type(record) is not core.Journal or record.identity.key() != self._identity.key(): _fail('invalid_record')
            try: data = codec.encode_journal(record)
            except Exception: _fail('invalid_record')
            self._begin_budget()
            ticket = None
            try:
                self._anchors_valid(); self._pending_absent(); self._cas(expected)
                self._temp_counter += 1
                if self._temp_counter > 0xffffffff: _fail('write_pending')
                temporary = 'journal.%08x.tmp' % self._temp_counter
                parent = self._anchors[-1][0].fd
                self._stage, self._write_pending = 'temp_create', True
                ticket = self._open_fd(parent, temporary,
                    self._flags('O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC'), 0o600)
                try:
                    created = _file_metadata(self._io.fstat(ticket.fd))
                    if created[6] != 0: _fail('unsafe_file')
                    at = 0
                    self._stage = 'temp_write'
                    while at < len(data):
                        self._check()
                        amount = self._io.write(ticket.fd, data[at:at + 4096])
                        if not _integer(amount, 1, min(4096, len(data) - at)): _fail('invalid_write')
                        at += amount
                    self._stage = 'temp_fsync'; self._check()
                    self._io.fsync(ticket.fd)
                    written = _file_metadata(self._io.fstat(ticket.fd))
                    if written[:6] != created[:6] or written[6] != len(data) or \
                            _file_metadata(self._io.stat_at(parent, temporary)) != written:
                        _fail('file_changed')
                finally:
                    self._close_one(ticket)
                if not ticket.closed: _fail('close_unverified')
                self._anchors_valid(); self._pending_absent(); self._cas(expected)
                if _file_metadata(self._io.stat_at(parent, temporary)) != written: _fail('file_changed')
                self._stage = 'rename'; self._check()
                self._publication_attempted, self._published_unknown = True, True
                self._io.rename_at(parent, temporary, JOURNAL)
                self._stage = 'directory_fsync'; self._check()
                self._io.fsync(parent)
                self._anchors_valid(); self._pending_absent()
                result = self._read_current()
                # Same bytes in another inode are NOT the file we published.
                # rename may update ctime, so bind stable identity and size,
                # not the entire pre-rename timestamp-bearing metadata row.
                if result is None or result.metadata[:7] != written[:7] or \
                        result.data != data or result.journal.key() != record.key():
                    _fail('readback_changed')
                self._generation += 1
                credit = self._reserve_v23('CANONICAL', 0)  # Shares the exact already-retained data object.
                if credit is not None: self._resource_budget_v23.started(credit)
                producer_failed = False
                try:
                    result = CanonicalRecord(result.journal, result.data, result.metadata, self._issuer, self._generation)
                except BaseException:
                    producer_failed = True
                    raise
                finally:
                    if credit is not None:
                        _complete_credit_v23(self._resource_budget_v23, credit, result, (),
                            producer_failed, producer_failed)
                self._write_pending, self._published_unknown = False, False
                self._stage, self._reason = 'committed', 'not_recorded'
                self._issued_canonicals.append(result)
                return result
            except BaseException as error:
                self._reason = error.code if type(error) is ClientFileError else 'durability_unknown'
                if ticket is not None: self._close_one(ticket)
                # Preserve any temp or possibly committed journal. Never retry,
                # unlink, rebase CAS or pretend fsync/close failure rolled back.
                if type(error) is ClientFileError or type(error) is resources.ResourceBudgetError: raise
                if isinstance(error, OSError) and _err(error, errno.EEXIST): _fail('temp_exists')
                if isinstance(error, Exception): _fail('durability_unknown')
                raise

    def close(self):
        with self._operation():
            self._ended, self._opened = True, False
            # Independently attempt EVERY known original resource even after
            # one close/readback/audit error. No new opens, unlink or re-close.
            for ticket in reversed(self._inventory):
                try: self._close_one(ticket)
                except BaseException: self._resource_pending = True
            if self._resource_pending and self._publication_attempted:
                self._published_unknown, self._write_pending = True, True
            return self.status()

    def status(self):
        with self._operation():
            known = sum(_integer(t.fd, 0, 0x7fffffff) for t in self._inventory)
            unknown = sum(t.opening_unknown for t in self._inventory)
            return {'evidence': 'CLIENT_FILES_ONLY', 'stage': self._stage, 'reason': self._reason,
                'opened': self._opened, 'known_fd_count': known,
                'close_attempted_count': sum(t.attempted for t in self._inventory),
                'unresolved_open_count': unknown,
                'all_owned_fds_closed': bool(not unknown and all(t.closed for t in self._inventory)),
                'resource_pending': self._resource_pending, 'write_pending': self._write_pending,
                'published_unknown': self._published_unknown,
                'global_pending_modified': False, 'store_finish_implemented': False,
                'mutation_admission': False}
