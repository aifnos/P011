"""Fixed pre-listen CLIENT publication barrier DATA, never RF admission.

Production entry is Barrier(original_owner). It binds only that Owner's original
_now method/namespace, worker, PID and original service deadline. It does not
extend a cap or build a _PublicationAttempt/Provider/binding. The fixed pending
entry is metadata-only; its content is never opened. The existing CLIENT root
must be a root-owned0700 directory and empty. Any history is refused, not removed,
archived, filled or interpreted. Late Factory/Provider checks remain necessary.

Only the observed /tmp -> /var/tmp -> /var/volatile/tmp aliases are accepted.
Actual directory descriptors form a no-follow anchored physical chain. Two
bounded observations of pending absence and CLIENT emptiness plus anchor
readback describe only a local observation window, not a durable permission.
Every acquired descriptor has one original ticket. Close never checks/renews the
Owner clock and never retries a close; unknown originals remain retained/pending.
Raw stat objects, names, syscall receipts and original errors remain private.
public_facts exports only a finite reason, counts and resource-closure boolean.
Default main does not construct an Owner, perform IO or execute device actions.
"""
import errno
import math
import os
import stat
import sys
import threading
import time
import types

PENDING_PATH = '/var/volatile/tmp/p011-mta-p2p-device.pending'
CLIENT_ROOT = '/var/volatile/tmp/p011-mta-client-rfinit'
PHYSICAL_TMP = '/var/volatile/tmp'
PENDING_NAME = 'p011-mta-p2p-device.pending'
CLIENT_NAME = 'p011-mta-client-rfinit'
MAX_DIRECTORY_ENTRIES = 512
MAX_OBSERVATIONS = 192
MAX_DIRECTORIES = 5
REASONS = frozenset((
    'not_started', 'clear', 'owner_context', 'wrong_worker', 'deadline',
    'unsupported_platform', 'unsafe_anchor', 'anchor_changed', 'alias_changed',
    'pending_exists', 'pending_symlink', 'client_root_missing', 'client_history',
    'inventory_unknown', 'descriptor_unknown', 'io_error', 'close_unknown',
    'already_attempted',
))


class BarrierError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in REASONS else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise BarrierError(code) from None


def _finite(value):
    return (type(value) in (int, float) and 0 <= value < 1e12 and
            math.isfinite(float(value)))


def _meta(raw):
    values = tuple(getattr(raw, name, None) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size',
        'st_mtime_ns', 'st_ctime_ns'))
    if (any(type(value) is not int or not 0 <= value < (1 << 64) for value in values[:7]) or
            any(type(value) is not int or not -(1 << 63) <= value < (1 << 63) for value in values[7:])):
        _fail('unsafe_anchor')
    return values


def _directory(raw, mode):
    meta = _meta(raw)
    if not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[5] < 1:
        _fail('unsafe_anchor')
    if mode is None:
        if stat.S_IMODE(meta[2]) & 0o022: _fail('unsafe_anchor')
    elif stat.S_IMODE(meta[2]) != mode:
        _fail('unsafe_anchor')
    return meta


class _LinuxIo(object):
    """No path parameters from HTTP/UI; only the Barrier's fixed anchored calls."""
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or
                os.uname()[4] != 'armv7l' or os.geteuid() != 0 or os.getegid() != 0 or
                os.O_RDONLY != 0 or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000 or
                type(os.O_DIRECTORY) is not int or os.O_DIRECTORY <= 0):
            _fail('unsupported_platform')
    def pid(self): return os.getpid()
    def stat_root(self): return os.stat('/', follow_symlinks=False)
    def stat_at(self, fd, name): return os.stat(name, dir_fd=fd, follow_symlinks=False)
    def readlink_at(self, fd, name): return os.readlink(name, dir_fd=fd)
    def open_dir(self, fd, name, flags):
        if fd is None:
            if name != '/': _fail('unsafe_anchor')
            return os.open('/', flags)
        return os.open(name, flags, dir_fd=fd)
    def fstat(self, fd): return os.fstat(fd)
    def rewind(self, fd): return os.lseek(fd, 0, os.SEEK_SET)
    def listdir(self, fd): return os.listdir(fd)
    def close(self, fd): return os.close(fd)


class Barrier(object):
    """One-shot, original-owner-bound local DATA observation and FD inventory."""
    def __init__(self, owner):
        # Production has no IO/clock/cap/callback argument and no mutable test IO.
        self._initialize(owner, _LinuxIo(), False)

    def __repr__(self):
        return '<fixed pre-listen CLIENT publication observation>'

    def _initialize(self, owner, io, host_model):
        self.owner = self._owner_original = owner
        self._io = self._io_original = io
        self._host_model_original = host_model
        self._creator_original = Barrier
        self.rows = self._rows_original = []
        self.observations = self._observations_original = []
        self.failures = self._failures_original = []
        self.close_failures = self._close_failures_original = []
        self.alias_rows = self._alias_rows_original = []
        self.rounds = self._rounds_original = []
        self.failure = None
        self.attempted = self.ended = self.close_called = False
        self.reason = 'not_started'
        self.resources_closed = True
        self.last = None
        self.root = self.var = self.volatile = self.tmp = self.client = None
        # No syscall/clock invocation in construction. These are original
        # references from the real Owner whose fixed source is authenticated by
        # its existing loader. The barrier does not sign that loader itself.
        self.check = self._check_original = getattr(owner, '_now', None)
        self.owner_type = type(owner)
        function = getattr(self.check, '__func__', None)
        self.namespace = getattr(function, '__globals__', None)
        self.check_function = function
        self.worker = getattr(owner, 'worker', None)
        self.pid = getattr(owner, 'pid', None)
        self.until = getattr(owner, 'original_until', None)
        self.clock = getattr(owner, 'clock', None)
        self._owner_context()

    def _owner_context(self):
        owner, namespace, function = self._owner_original, self.namespace, self.check_function
        current = getattr(owner, '_now', None)
        if (self.owner is not owner or type(owner) is not self.owner_type or
                type(namespace) is not dict or type(function) is not types.FunctionType or
                getattr(self._check_original, '__self__', None) is not owner or
                getattr(current, '__self__', None) is not owner or
                getattr(current, '__func__', None) is not function or
                getattr(self.owner_type, '_now', None) is not function or
                function.__globals__ is not namespace or
                namespace.get('FixedStateServiceOwner') is not self.owner_type or
                namespace.get('__name__') not in ('mta_client_service_owner', 'startup_readonly_private_owner') or
                getattr(owner, '_startup_namespace_original', None) is not namespace or
                getattr(owner, '_startup_owner_type_original', None) is not self.owner_type or
                getattr(owner, 'worker', None) is not self.worker or
                getattr(owner, 'pid', None) != self.pid or
                type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff or
                getattr(owner, 'original_until', None) is not self.until or
                getattr(owner, 'until', None) is not self.until or
                not _finite(self.until) or getattr(owner, 'clock', None) is not self.clock or
                self.clock is not time.monotonic or
                self._io is not self._io_original or
                self.check is not self._check_original or self._creator_original is not Barrier or
                self.rows is not self._rows_original or self.observations is not self._observations_original or
                self.failures is not self._failures_original or self.close_failures is not self._close_failures_original or
                self.alias_rows is not self._alias_rows_original or self.rounds is not self._rounds_original):
            _fail('owner_context')
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        if (getattr(owner, 'started', None) is not True or
                getattr(owner, 'server_called', None) is not False or
                getattr(owner, 'server', None) is not None or
                getattr(owner, 'close_called', None) is not False):
            _fail('owner_context')
        if self._host_model_original is False and type(self._io_original) is not _LinuxIo:
            _fail('owner_context')

    def _guard(self):
        self._owner_context()
        if self._io_original.pid() != self.pid: _fail('owner_context')
        value = self._check_original()
        if (not _finite(value) or value >= self.until or
                self.last is not None and value < self.last):
            _fail('deadline')
        self.last = value
        return value

    def _call(self, kind, path, function, args=(), opening=None):
        # An original receipt precedes every actual syscall. Open returns are
        # retained before the late-cap check, never lost on a post-open deadline.
        row = {'kind': kind, 'path': path, 'started': False, 'returned': False,
               'value': None, 'failure': None, 'after_failure': None}
        if len(self.observations) >= MAX_OBSERVATIONS: _fail('inventory_unknown')
        self.observations.append(row)
        self._guard()
        row['started'] = True
        if opening is not None: opening['open_started'] = True
        try:
            value = function(*args)
        except BaseException as error:
            row['failure'] = error
            if opening is not None: opening['open_error'] = error
            try: self._guard()
            except BaseException as after_error:
                row['after_failure'] = after_error
                raise
            raise
        row['returned'] = True
        row['value'] = value
        if opening is not None:
            opening['open_returned'] = True
            opening['fd'] = opening['fd_original'] = value
            # A real returned FD must be adopted before the late-cap guard.
            # This bounded original-IO settling read is not a new phase/cap:
            # it preserves actual metadata so an expired operation can still
            # once-close its original descriptor rather than blind-close it.
            self._adopt_open(opening)
        try: self._guard()
        except BaseException as error:
            row['after_failure'] = error
            raise
        return value

    def _adopt_open(self, opening):
        fd = opening['fd_original']
        if (type(fd) is not int or fd < 0 or
                any(row is not opening and row['fd'] == fd and not row['closed']
                    for row in self._rows_original)):
            _fail('descriptor_unknown')
        receipt = {'kind': 'adopt_fstat', 'path': opening['path'], 'started': True,
                   'returned': False, 'value': None, 'failure': None,
                   'after_failure': None, 'opening': opening}
        # At most five real opens; these required settling receipts cannot be
        # prevented by an already-expired clock or ordinary observation budget.
        self._observations_original.append(receipt)
        try:
            raw = self._io_original.fstat(fd)
            receipt['returned'] = True
            receipt['value'] = raw
            opening['metadata_raw'] = raw
            opening['metadata'] = opening['metadata_original'] = _meta(raw)
            if _directory(raw, opening['mode']) != opening['before']:
                _fail('anchor_changed')
        except BaseException as error:
            receipt['failure'] = error
            opening['adoption_error'] = error
            raise

    def _entry(self, parent, name, path):
        if parent is None:
            return self._call('stat', '/', self._io_original.stat_root)
        return self._call('stat', path, self._io_original.stat_at, (self._fd(parent), name))

    def _fd(self, row):
        if (not any(row is original for original in self._rows_original) or
                row['owner'] is not self or row['closed'] or row['close_attempted'] or
                type(row['fd']) is not int or row['fd'] < 0 or row['fd'] != row['fd_original']):
            _fail('descriptor_unknown')
        return row['fd']

    def _open(self, parent, name, path, mode):
        # Fixed parent/name pairs only; no generic resolver or arbitrary path.
        allowed = ((None, '/', '/'), (self.root, 'var', '/var'),
                   (self.var, 'volatile', '/var/volatile'),
                   (self.volatile, 'tmp', PHYSICAL_TMP),
                   (self.tmp, CLIENT_NAME, CLIENT_ROOT))
        if not any(parent is expected and name == n and path == p for expected, n, p in allowed):
            _fail('unsafe_anchor')
        if len(self._rows_original) >= MAX_DIRECTORIES: _fail('inventory_unknown')
        row = {'owner': self, 'parent': parent, 'name': name, 'path': path, 'mode': mode,
               'fd': None, 'fd_original': None, 'flags': None, 'before_raw': None,
               'before': None, 'metadata_raw': None, 'metadata': None,
               'metadata_original': None, 'open_started': False, 'open_returned': False,
               'open_error': None, 'adoption_error': None, 'failure': None, 'known_no_fd': False,
               'close_attempted': False, 'close_return': None, 'close_error': None,
               'ebadf_error': None, 'closed': False, 'unknown': True}
        self.rows.append(row)
        try:
            row['before_raw'] = self._entry(parent, name, path)
            row['before'] = _directory(row['before_raw'], mode)
            parent_fd = None if parent is None else self._fd(parent)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            row['flags'] = flags
            self._call('open', path, self._io_original.open_dir,
                       (parent_fd, name, flags), opening=row)
            if (type(row['fd']) is not int or row['fd'] < 0 or
                    any(other is not row and other['fd'] == row['fd'] and not other['closed']
                        for other in self.rows)):
                _fail('descriptor_unknown')
            if (_directory(row['metadata_raw'], mode) != row['before'] or
                    _directory(self._entry(parent, name, path), mode) != row['before']):
                _fail('anchor_changed')
            row['unknown'] = False
            return row
        except BaseException as error:
            row['failure'] = error
            if row['open_started'] is False:
                row['known_no_fd'] = row['closed'] = True
                row['unknown'] = False
            elif (row['open_returned'] is False and isinstance(row['open_error'], OSError) and
                  type(row['open_error'].errno) is int and 1 <= row['open_error'].errno <= 4095):
                row['known_no_fd'] = row['closed'] = True
                row['unknown'] = False
            raise

    def _alias(self, parent, path, target):
        fd = self._fd(parent)
        first_raw = self._call('stat_alias', path, self._io_original.stat_at, (fd, 'tmp'))
        first = _meta(first_raw)
        if (not stat.S_ISLNK(first[2]) or stat.S_IMODE(first[2]) != 0o777 or
                first[3:6] != (0, 0, 1) or first[6] != len(target)):
            _fail('alias_changed')
        text = self._call('readlink', path, self._io_original.readlink_at, (fd, 'tmp'))
        after_raw = self._call('stat_alias', path, self._io_original.stat_at, (fd, 'tmp'))
        after = _meta(after_raw)
        receipt = {'path': path, 'first_raw': first_raw, 'first': first, 'target': text,
                   'after_raw': after_raw, 'after': after}
        self.alias_rows.append(receipt)
        if type(text) is not str or text != target or after != first:
            _fail('alias_changed')
        return first, text

    def _authenticate(self):
        for row in self.rows:
            fd = self._fd(row)
            raw = self._call('fstat', row['path'], self._io_original.fstat, (fd,))
            held = _directory(raw, row['mode'])
            entry = _directory(self._entry(row['parent'], row['name'], row['path']), row['mode'])
            # Physical prefixes may have unrelated entry updates. Their immutable
            # identities must match; CLIENT full metadata may not change at all.
            expected = row['metadata_original']
            count = 9 if row is self.client else 5
            if held[:count] != expected[:count] or entry[:count] != expected[:count]:
                _fail('anchor_changed')
        aliases = (self._alias(self.root, '/tmp', '/var/tmp'),
                   self._alias(self.var, '/var/tmp', PHYSICAL_TMP))
        if aliases != self._aliases_original: _fail('alias_changed')

    def _pending_absent(self):
        fd = self._fd(self.tmp)
        try:
            raw = self._call('stat_pending', PENDING_PATH, self._io_original.stat_at, (fd, PENDING_NAME))
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                # Original error/receipt remains retained. Only metadata ENOENT
                # under the same held fixed TMP FD constitutes this local absence.
                self.observations[-1]['accepted_absence'] = True
                return
            raise
        meta = _meta(raw)
        _fail('pending_symlink' if stat.S_ISLNK(meta[2]) else 'pending_exists')

    def _empty(self):
        fd = self._fd(self.client)
        returned = self._call('rewind', CLIENT_ROOT, self._io_original.rewind, (fd,))
        if type(returned) is not int or returned != 0: _fail('inventory_unknown')
        names = self._call('listdir', CLIENT_ROOT, self._io_original.listdir, (fd,))
        if (type(names) is not list or len(names) > MAX_DIRECTORY_ENTRIES or
                any(type(name) is not str or not name or name in ('.', '..') or
                    '/' in name or '\x00' in name for name in names) or len(set(names)) != len(names)):
            _fail('inventory_unknown')
        # Do not open/read/stat existing historical entries or interpret a run.
        self.rounds.append({'names': names, 'count': len(names)})
        if names: _fail('client_history')

    def _close(self, row):
        # Never invoke Owner._now while closing. Original FD identity is still
        # required, even when the original service deadline has expired.
        if row['close_attempted']: return row['closed'] is True and row['unknown'] is False
        if row['known_no_fd']:
            return row['fd'] is None and row['open_returned'] is False and row['closed'] is True
        row['close_attempted'] = True
        try:
            if (row['owner'] is not self or type(row['fd']) is not int or row['fd'] < 0 or
                    row['fd'] != row['fd_original'] or row['open_returned'] is not True or
                    row['metadata'] is not row['metadata_original'] or type(row['metadata']) is not tuple):
                _fail('close_unknown')
            actual = _meta(self._io_original.fstat(row['fd']))
            if actual[:5] != row['metadata_original'][:5]: _fail('close_unknown')
            row['close_return'] = self._io_original.close(row['fd'])
            try: self._io_original.fstat(row['fd'])
            except OSError as error:
                row['ebadf_error'] = error
                if (row['close_return'] is None and type(error.errno) is int and
                        error.errno == errno.EBADF):
                    row['closed'] = True
                    row['unknown'] = False
                    return True
            _fail('close_unknown')
        except BaseException as error:
            row['close_error'] = error
            row['unknown'] = True
            self.close_failures.append(error)
        return False

    def _close_all(self):
        if self.close_called: return self.resources_closed
        self.close_called = True
        for row in reversed(self._rows_original):
            self._close(row)  # Independent branches continue after first failure.
        self.resources_closed = all(row['closed'] is True and row['unknown'] is False
                                    for row in self._rows_original)
        return self.resources_closed

    def run(self):
        if self.attempted: _fail('already_attempted')
        self.attempted = True
        try:
            self._guard()
            self._call('platform', '<fixed-linux-profile>', self._io_original.validate)
            self.root = self._open(None, '/', '/', None)
            self.var = self._open(self.root, 'var', '/var', 0o755)
            self.volatile = self._open(self.var, 'volatile', '/var/volatile', 0o1777)
            self.tmp = self._open(self.volatile, 'tmp', PHYSICAL_TMP, 0o1777)
            self._aliases_original = (
                self._alias(self.root, '/tmp', '/var/tmp'),
                self._alias(self.var, '/var/tmp', PHYSICAL_TMP))
            self._pending_absent()
            try: self.client = self._open(self.tmp, CLIENT_NAME, CLIENT_ROOT, 0o700)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.ENOENT:
                    _fail('client_root_missing')
                raise
            for unused in range(2):
                self._authenticate()
                self._pending_absent()
                self._empty()
                self._authenticate()
            self._pending_absent()
            self._guard()
            self.reason = 'clear'
        except BaseException as error:
            self.failure = error
            self.failures.append(error)
            if type(error) is BarrierError:
                self.reason = error.code
            elif type(error) is self.namespace.get('ServiceOwnerError'):
                # Only the actual authenticated Owner's finite classification,
                # never exception text/args or an arbitrary caller's .code.
                code = getattr(error, 'code', None)
                self.reason = ('deadline' if code in ('deadline', 'clock_unknown') else
                               'wrong_worker' if code == 'wrong_worker' else 'owner_context')
            else:
                self.reason = 'io_error'
        finally:
            self._close_all()
            if self.reason == 'clear' and not self.resources_closed:
                self.reason = 'close_unknown'
            self.ended = True
        return self

    def public_facts(self):
        # Passive scalar projection; neither clear nor closed grants readiness.
        return {'reason': self.reason if self.reason in REASONS else 'io_error',
                'opened_count': sum(row['open_returned'] is True for row in self._rows_original),
                'closed_count': sum(row['open_returned'] is True and row['closed'] is True
                                    for row in self._rows_original),
                'observation_count': len(self._observations_original),
                'resources_closed': self.ended is True and self.resources_closed is True}


def _host_model(owner, io):
    """Private test-only construction; explicitly not Linux/actual-owner evidence.

    No production entry accepts this IO. Test callers must label model scope and
    must not feed this object to a real Owner admission/close acceptance path.
    This helper does not publish, perform IO or relax the observation policy.
    """
    value = Barrier.__new__(Barrier)
    value._initialize(owner, io, True)
    return value


def main():
    print('SOURCE_RECEIVE_BARRIER_V1 owner=false io=false rf=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
