"""Bounded Linux /proc identity observations for an internal CLIENT provider.

Pure construction; explicit reads only. No launch/kill/wait/socket/file lock.
An absent PID is NOT an actual wait/reap or ExitProof. Private raw records may
contain identifiers and argv; only public_status() is suitable for publication.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import time
from collections import namedtuple

import mta_p2p_client_init as owner


MAX_PID, MAX_START = 0x7fffffff, (1 << 64) - 1
MAX_STAT, MAX_CMDLINE, MAX_TASKS = 4096, 32768, 128
MAX_TOTAL, MAX_OPEN_FILES, PF_KTHREAD = 2097152, 280, 0x00200000
# Actual retained chunks plus final RawRecord bytes, including one failed tail.
MAX_GENERATION_PAYLOAD = 2 * (MAX_TOTAL + MAX_CMDLINE + 1)
_SELF = object()
_STATES = frozenset(('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I', 'P'))
_HEX = frozenset('0123456789abcdef')
_CODES = frozenset(('invalid_directory_entry', 'invalid_boot_id', 'invalid_expected_boot',
    'invalid_stat', 'invalid_stat_fields', 'invalid_stat_state', 'invalid_stat_number',
    'invalid_stat_identity', 'invalid_budget', 'invalid_clock', 'clock_regressed', 'deadline',
    'invalid_file_metadata', 'record_disappeared', 'invalid_directory_type', 'file_budget',
    'invalid_descriptor', 'invalid_regular_file', 'invalid_read_result', 'read_budget',
    'total_budget', 'file_changed', 'file_close_unverified', 'task_budget', 'duplicate_task',
    'task_directory_changed', 'invalid_executable_link', 'invalid_executable',
    'executable_changed', 'pid_missing', 'invalid_cmdline', 'task_set_incomplete',
    'task_kernel_mismatch', 'pid_reused', 'pid_identity_changed', 'boot_changed',
    'reader_pending_or_active', 'unsupported_platform', 'task_set_changed', 'task_reused',
    'observation_changed', 'expected_actor_changed', 'invalid_expected_actor',
    'unexpected_read_error', 'reader_unbound', 'invalid_deadline'))


class ProcReadError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'unexpected_read_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise ProcReadError(code)


def _uint(value, low, high):
    return type(value) is int and low <= value <= high


def _errno_is(error, values):
    return type(error.errno) is int and error.errno in values


def _pid_text(value):
    if type(value) is not str or not value or len(value) > 10 or \
            any(c not in '0123456789' for c in value) or value[0] == '0':
        _fail('invalid_directory_entry')
    pid = int(value)
    if not 1 <= pid <= MAX_PID:
        _fail('invalid_directory_entry')
    return pid


def _boot(raw):
    if type(raw) is not bytes or len(raw) != 37 or raw[-1:] != b'\n':
        _fail('invalid_boot_id')
    try:
        text = raw[:-1].decode('ascii')
    except UnicodeError:
        _fail('invalid_boot_id')
    if any(text[i] != '-' for i in (8, 13, 18, 23)) or \
            len(text.replace('-', '')) != 32 or any(c not in _HEX for c in text.replace('-', '')):
        _fail('invalid_boot_id')
    return text


def _expected_boot(value):
    if type(value) is not str:
        _fail('invalid_expected_boot')
    try:
        return _boot(value.encode('ascii') + b'\n')
    except (UnicodeError, ProcReadError):
        _fail('invalid_expected_boot')


class _Private(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable proc observation')

    def __repr__(self):
        return '<CLIENT private proc observation>'

    __str__ = __repr__


class RawRecord(_Private):
    __slots__ = ('stage', 'pass_index', 'path', 'data', 'metadata')

    def __init__(self, stage, pass_index, path, data, metadata):
        for name, value in (('stage', stage), ('pass_index', pass_index), ('path', path),
                            ('data', data), ('metadata', metadata)):
            object.__setattr__(self, name, value)


class StatIdentity(namedtuple('_StatIdentity', 'pid start state comm flags ppid threads')):
    __slots__ = ()

    def __repr__(self):
        return '<CLIENT private stat identity>'

    __str__ = __repr__

    def stable_key(self):
        return self.pid, self.start, self.comm, self.flags, self.ppid


def parse_stat(raw, expected_pid):
    """Linux 4.14 stat's comm may contain spaces and parentheses, even newline.

    Only the final ') ' separates comm from fields. Full raw is retained by
    the reader. CPU ticks may change: they are not part of process identity.
    """
    if not _uint(expected_pid, 1, MAX_PID) or type(raw) is not bytes or \
            not 1 <= len(raw) <= MAX_STAT or raw[-1:] != b'\n' or b'\0' in raw:
        _fail('invalid_stat')
    prefix = str(expected_pid).encode('ascii') + b' ('
    end = raw.rfind(b') ')
    if not raw.startswith(prefix) or end < len(prefix) or end - len(prefix) > 15:
        _fail('invalid_stat')
    comm = raw[len(prefix):end]
    fields = raw[end + 2:-1].split(b' ')
    if len(fields) != 50 or any(not token for token in fields):
        _fail('invalid_stat_fields')
    try:
        state = fields[0].decode('ascii')
    except UnicodeError:
        _fail('invalid_stat_state')
    if state not in _STATES:
        _fail('invalid_stat_state')
    values = []
    for token in fields[1:]:
        digits = token[1:] if token[:1] == b'-' else token
        if not digits or len(digits) > 20 or any(c < 48 or c > 57 for c in digits) or \
                (len(digits) > 1 and digits[:1] == b'0') or token == b'-0':
            _fail('invalid_stat_number')
        number = int(token)
        if not -(1 << 63) <= number <= MAX_START:
            _fail('invalid_stat_number')
        values.append(number)
    # values begin at field4; indexes5/16/18 are flags9/threads20/start22.
    ppid, flags, threads, start = values[0], values[5], values[16], values[18]
    if not _uint(ppid, 0, MAX_PID) or not _uint(flags, 0, 0xffffffff) or \
            not _uint(threads, 0, MAX_TASKS) or not _uint(start, 1, MAX_START) or \
            (threads == 0 and state not in ('Z', 'X')):
        _fail('invalid_stat_identity')
    return StatIdentity(expected_pid, start, state, comm, flags, ppid, threads)


class ProcObservation(_Private):
    __slots__ = ('kind', 'reason', 'stage', 'boot', 'actor', 'pid_path_absent',
                 'remaining_tasks', 'same_boot', 'passes', 'raw', 'file_count',
                 'closed_count', 'resource_pending', 'task_count', 'reap_complete')

    def __init__(self, kind, reason, stage, boot, actor, absent, remaining, same_boot,
                 passes, raw, files, closed, pending, tasks):
        for key, value in (('kind', kind), ('reason', reason), ('stage', stage),
                ('boot', boot), ('actor', actor), ('pid_path_absent', absent),
                ('remaining_tasks', remaining), ('same_boot', same_boot), ('passes', passes),
                ('raw', raw), ('file_count', files), ('closed_count', closed),
                ('resource_pending', pending), ('task_count', tasks), ('reap_complete', False)):
            object.__setattr__(self, key, value)

    def public_status(self):
        return {'kind': self.kind, 'reason': self.reason, 'stage': self.stage,
                'actor_available': self.actor is not None,
                'pid_path_absent': self.pid_path_absent, 'same_boot': self.same_boot,
                'observation_count': self.passes, 'task_count': self.task_count,
                'remaining_task_count': len(self.remaining_tasks), 'file_count': self.file_count,
                'files_closed': self.file_count == self.closed_count and not self.resource_pending,
                'resource_pending': self.resource_pending, 'reap_complete': False}


class ProcGeneration(object):
    """Private actual operation registry, never network or recovery permission."""
    def __init__(self, reader, ordinal, credit, absolute_deadline=None):
        self.reader, self._issuer, self.ordinal, self.credit = reader, reader._issuer, ordinal, credit
        self.budget = reader._bound_budget_v24
        self.absolute_deadline = absolute_deadline  # Original tightening-only caller cap.
        self.active, self.ended, self.unknown, self.late = True, False, False, False
        self.observation, self.error = None, None
        self.incoming = None
        self.raw, self.tickets, self.returned_raw = [], [], []
    def __repr__(self): return '<private CLIENT proc generation>'


class ProcOpenTicket(object):
    """Exact pre-open original; numeric descriptor reuse never merges tickets."""
    def __init__(self, reader, generation, credit, fs, path, flags):
        self.reader, self.generation, self._issuer = reader, generation, reader._issuer
        self.ordinal, self.credit = len(generation.tickets), credit
        self.fs, self.path, self.flags, self.creator = fs, path, flags, fs.open
        self.descriptor = None
        self.open_called = self.returned = self.registered = self.failed_without_fd = False
        self.open_error, self.raw, self.incoming, self.data = None, None, None, b''
        self.error = None
        self.chunks = []
        self.close_attempted = self.close_returned = self.ebadf_observed = False
        self.close_result = self.close_error = self.close_readback = self.ebadf_error = self.ebadf_errno = None
        self.unknown = False
    @property
    def fd(self): return self.descriptor
    def __repr__(self): return '<private CLIENT proc open original>'


class ProcReader(object):
    """Actual fixed /proc reader. _fs is trusted HOST/internal injection only.

    An outer owner must serialize its use and account for actual caller life.
    No generic path/root parameter, scan-all-processes, signal or reap API.
    Each call gets fresh raw evidence and two bounded observations.
    """
    def __init__(self, timeout=3.0, _fs=None, _clock=None):
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 10 or \
                not math.isfinite(float(timeout)):
            _fail('invalid_budget')
        if _clock is not None and not callable(_clock):
            _fail('invalid_clock')
        self._timeout, self._fs, self._clock = float(timeout), _fs, _clock or time.monotonic
        self._active = False
        self._issuer, self._history = object(), []
        self._current_generation, self._history_active = None, False
        self._resource_budget_v24 = None
        self._bound_budget_v24 = None  # Original bind reference; current pointer cannot revert to pre-bind None.
        self._resource_error_v24 = None
        self._fd_refs = []  # numeric FDs plus exact filesystem object; never auto-retry close
        self._open_attempt = None  # private exact creator/path/flags, including unknown returns
        self._pending = False
        self._stage, self._pass = 'not_started', 0
        self._raw, self._files, self._closed, self._total, self._task_count = [], 0, 0, 0, 0

    def _check(self):
        if self._current_generation is not None:
            budget = self._current_generation.budget
            try:
                budget._context()
                if self._current_generation.credit.lane == 'PREPARATION_NETWORK' and budget._cancelled:
                    import mta_client_resource_budget as resources
                    resources._fail('network_cancelled')
            except BaseException as error:
                self._resource_error_v24 = error
                self._pending = self._current_generation.unknown = True
                raise
        value = self._clock()
        if type(value) not in (int, float) or not -1e12 <= value <= 1e12 or \
                not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock:
            _fail('clock_regressed')
        self._last_clock = value
        if self._deadline is not None and value >= self._deadline:
            _fail('deadline')
        return value

    def _meta(self, value):
        attrs = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        result = tuple(getattr(value, name, None) for name in attrs)
        if any(type(v) is not int or v < 0 for v in result):
            _fail('invalid_file_metadata')
        return result

    def _record(self, path, data, metadata=()):
        record = RawRecord(self._stage, self._pass, path, data, metadata)
        try:
            self._current_generation.raw.append(record)  # Original before current-round projection.
            self._raw.append(record)
        except BaseException:
            self._pending = self._current_generation.unknown = True
            raise
        return record

    def _retain_return(self, value):
        generation = self._current_generation
        generation.incoming = value  # Exact original before an append can fail.
        try: generation.returned_raw.append(value)
        except BaseException:
            self._pending = generation.unknown = True
            raise
        return value

    def _path_meta(self, path, required=False):
        self._check()
        try:
            value = self._os.lstat(path)
            self._retain_return(value)
        except OSError as error:
            if _errno_is(error, (errno.ENOENT, errno.ESRCH)):
                self._record(path, None)
                if required:
                    _fail('record_disappeared')
                return None
            raise
        metadata = self._meta(value)
        self._record(path, None, metadata)
        return metadata

    def _directory(self, path, required=False):
        value = self._path_meta(path, required)
        if value is not None and not stat.S_ISDIR(value[2]):
            _fail('invalid_directory_type')
        return value

    def _read(self, path, limit):
        self._check()
        if self._files >= MAX_OPEN_FILES:
            _fail('file_budget')
        flags = self._os.O_RDONLY | self._os.O_NOFOLLOW | self._os.O_CLOEXEC
        fs, generation = self._os, self._current_generation
        budget = generation.budget
        try: credit = budget.reserve(budget._store._resource_lane_v23, 'PROC_OPEN')
        except BaseException as error:
            self._resource_error_v24 = error
            if getattr(error, 'code', None) != 'safe_exhaustion':
                self._pending = generation.unknown = True
            raise
        ticket = ProcOpenTicket(self, generation, credit, fs, path, flags)
        generation.tickets.append(ticket)
        self._open_attempt = ticket.__dict__  # Preserve the original current-round dict contract.
        accounting_row = budget._owned(credit)
        descriptor, data, before, error = None, b'', (), None
        try:
            budget.started(credit)
            ticket.open_called = True
            try:
                descriptor = ticket.creator(path, flags)
            except OSError as caught:
                ticket.open_error, ticket.failed_without_fd = caught, True
                raise
            except BaseException as caught:
                ticket.open_error, ticket.unknown = caught, True
                self._pending = generation.unknown = True
                raise
            ticket.descriptor, ticket.returned = descriptor, True  # Before validity/registration checks.
            if not _uint(descriptor, 0, 0x7fffffff):
                ticket.unknown = self._pending = generation.unknown = True
                _fail('invalid_descriptor')
            self._files += 1
            try:
                self._fd_refs.append((fs, descriptor))
                ticket.registered = True
            except BaseException:
                ticket.unknown = self._pending = generation.unknown = True
                raise
            self._check()  # A late open still owns its FD, but starts no new producer metadata read.
            before = self._meta(self._retain_return(fs.fstat(descriptor)))
            if not stat.S_ISREG(before[2]) or before[5] != 1:
                _fail('invalid_regular_file')
            while True:
                self._check()
                requested = min(4096, limit + 1 - len(data))
                chunk = fs.read(descriptor, requested)
                ticket.incoming = chunk  # Bad/unexpected return retained before every check.
                try: ticket.chunks.append(chunk)
                except BaseException:
                    ticket.unknown = self._pending = generation.unknown = True
                    raise
                if type(chunk) is not bytes or len(chunk) > requested:
                    ticket.unknown = self._pending = generation.unknown = True
                    _fail('invalid_read_result')
                data += chunk
                if len(data) > limit:
                    _fail('read_budget')
                if not chunk:
                    break
            self._total += len(data)
            if self._total > MAX_TOTAL:
                _fail('total_budget')
            self._check()
            if self._meta(self._retain_return(fs.fstat(descriptor))) != before:
                _fail('file_changed')
            self._check()
        except BaseException as caught:
            ticket.error = caught
            if not ticket.open_called:
                ticket.unknown = self._pending = generation.unknown = True
                self._resource_error_v24 = caught
            if descriptor is not None and not ticket.registered:
                ticket.unknown = self._pending = generation.unknown = True
            error = caught
        finally:
            ticket.data = data  # Full partial bytes survive even a RawRecord append failure.
            try:
                ticket.raw = self._record(path, data, before)
            except BaseException as caught:
                ticket.unknown = self._pending = generation.unknown = True
                if error is None: error = caught
            finally:
                # Single close always precedes accounting/evidence allocation.
                if descriptor is not None and _uint(descriptor, 0, 0x7fffffff):
                    ticket.close_attempted = True
                    try:
                        ticket.close_result = fs.close(descriptor)
                        ticket.close_returned = True
                    except BaseException as caught:
                        ticket.close_error = caught
                    try:
                        ticket.close_readback = fs.fstat(descriptor)
                        self._retain_return(ticket.close_readback)
                    except OSError as caught:
                        ticket.ebadf_error, ticket.ebadf_errno = caught, caught.errno
                        ticket.ebadf_observed = _errno_is(caught, (errno.EBADF,))
                    except BaseException as caught:
                        if ticket.close_error is None: ticket.close_error = caught
                    if ticket.close_returned and ticket.close_result is None and ticket.ebadf_observed:
                        self._closed += 1
                    else:
                        ticket.unknown = self._pending = generation.unknown = True
                        if error is None: error = ProcReadError('file_close_unverified')
                if not self._pending: self._open_attempt = None
                try:
                    if accounting_row['active']:
                        budget.returned(credit, ticket)
                        if ticket.unknown: budget.mark_unknown(credit)
                except BaseException as caught:
                    ticket.unknown = self._pending = generation.unknown = True
                    if error is None: error = caught
                finally:
                    try:
                        if accounting_row['active'] and budget.settle(credit) is not True:
                            ticket.unknown = self._pending = generation.unknown = True
                            if error is None: error = ProcReadError('reader_pending_or_active')
                    except BaseException as caught:
                        ticket.unknown = self._pending = generation.unknown = True
                        if error is None: error = caught
        if error is not None: raise error
        return data

    def _read_boot(self):
        self._stage = 'boot'
        return _boot(self._read('/proc/sys/kernel/random/boot_id', 64))

    def _tasks(self, root):
        self._stage = 'task_directory'
        before = self._directory(root, True)
        self._check()
        names = self._os.listdir(root)
        self._retain_return(names)
        if type(names) not in (list, tuple) or not 1 <= len(names) <= MAX_TASKS:
            _fail('task_budget')
        tids = tuple(sorted(_pid_text(v) for v in names))
        self._record(root, tuple(names), before)
        if len(set(tids)) != len(tids):
            _fail('duplicate_task')
        if self._directory(root, True) != before:
            _fail('task_directory_changed')
        return tids

    def _exe(self, path):
        self._stage = 'executable'
        before = self._path_meta(path)
        if before is None:
            return None
        if not stat.S_ISLNK(before[2]):
            _fail('invalid_executable_link')
        self._check()
        value = self._os.readlink(path)
        self._retain_return(value)
        self._record(path, value, before)
        if type(value) is not str or not 1 <= len(value) <= 256 or not value.startswith('/') or \
                any(p in ('', '.', '..') for p in value[1:].split('/')) or \
                any(ord(c) < 32 for c in value) or value.endswith(' (deleted)'):
            _fail('invalid_executable')
        if self._path_meta(path, True) != before:
            _fail('executable_changed')
        return value

    def _actor_pass(self, pid):
        boot = self._read_boot()
        root, task_root = '/proc/' + str(pid), '/proc/' + str(pid) + '/task'
        self._stage = 'pid_directory'
        directory = self._directory(root)
        if directory is None:
            _fail('pid_missing')
        self._stage = 'pid_stat'
        first = parse_stat(self._read(root + '/stat', MAX_STAT), pid)
        self._stage = 'cmdline'
        command = self._read(root + '/cmdline', MAX_CMDLINE)
        if command and (command[-1:] != b'\0' or command[:1] == b'\0'):
            _fail('invalid_cmdline')
        exe = self._exe(root + '/exe')
        tids = self._tasks(task_root)
        if pid not in tids or first.threads not in (0, len(tids)):
            _fail('task_set_incomplete')
        tasks = []
        for tid in tids:
            self._stage = 'task_stat'
            task_path = task_root + '/' + str(tid)
            task_dir = self._directory(task_path, True)
            value = parse_stat(self._read(task_path + '/stat', MAX_STAT), tid)
            if self._directory(task_path, True) != task_dir:
                _fail('task_directory_changed')
            if bool(value.flags & PF_KTHREAD) != bool(first.flags & PF_KTHREAD):
                _fail('task_kernel_mismatch')
            if value.threads not in (0, len(tids)):
                _fail('task_set_incomplete')
            tasks.append(value)
        self._task_count = max(self._task_count, len(tasks))
        if self._tasks(task_root) != tids:
            _fail('task_directory_changed')
        self._stage = 'pid_stat'
        last = parse_stat(self._read(root + '/stat', MAX_STAT), pid)
        leader = next(row for row in tasks if row.pid == pid)
        if first.start != last.start or first.start != leader.start:
            _fail('pid_reused')
        if first.stable_key() != last.stable_key() or first.stable_key() != leader.stable_key() or \
                last.threads not in (0, len(tids)) or self._directory(root, True) != directory:
            _fail('pid_identity_changed')
        if self._read_boot() != boot:
            _fail('boot_changed')
        if not command:
            reason = ('empty_kernel' if first.flags & PF_KTHREAD else
                      'empty_user_zombie' if first.state == 'Z' else 'empty_user_unknown')
        elif first.flags & PF_KTHREAD:
            reason = 'kernel_cmdline_unexpected'
        elif exe is None:
            reason = 'executable_missing'
        elif any(row.state in ('Z', 'X') for row in tasks) or first.state in ('Z', 'X') or last.state in ('Z', 'X'):
            reason = 'nonlive_task'
        elif any(row.state == 'P' for row in tasks) or first.state == 'P' or last.state == 'P':
            reason = 'unsupported_actor_state'
        else:
            reason = 'live_actor'
        key = (boot, first.stable_key(), exe, command,
               tuple(row.stable_key() for row in tasks), reason)
        return boot, first, exe, command, tuple(tasks), reason, key

    def _absence_pass(self, actor, expected_boot):
        boot = self._read_boot()
        if boot != expected_boot:
            _fail('boot_changed')
        root = '/proc/' + str(actor.pid)
        self._stage = 'pid_directory'
        present = self._directory(root)
        reason = 'pid_present' if present is not None else 'absence_observed'
        current = None
        if present is not None:
            self._stage = 'pid_stat'
            current = parse_stat(self._read(root + '/stat', MAX_STAT), actor.pid)
            if current.start != actor.start:
                reason = 'pid_reused'
        self._stage = 'task_directory'
        task_present = self._directory(root + '/task')
        remaining, facts = [], []
        for tid, start, _ in actor.tasks:
            self._stage = 'recorded_task'
            task_path = '/proc/' + str(tid)
            value = self._directory(task_path)
            if value is not None:
                identity = parse_stat(self._read(task_path + '/stat', MAX_STAT), tid)
                remaining.append(tid)
                facts.append(identity.stable_key())
                if identity.start != start:
                    if tid == actor.pid:
                        reason = 'pid_reused'
                    elif reason != 'pid_reused':
                        reason = 'task_reused'
            if self._directory(root + '/task/' + str(tid)) is not None:
                if tid not in remaining:
                    remaining.append(tid)
                reason = 'task_present' if reason == 'absence_observed' else reason
        if task_present is not None and reason == 'absence_observed':
            reason = 'task_present'
        if remaining and reason == 'absence_observed':
            reason = 'task_present'
        self._task_count = max(self._task_count, len(actor.tasks))
        if self._read_boot() != boot:
            _fail('boot_changed')
        key = (boot, present, task_present,
               current.stable_key() if current is not None else None, tuple(facts), tuple(sorted(remaining)), reason)
        return boot, present is None, tuple(sorted(remaining)), reason, key

    def _begin(self):
        if self._active or self._pending:
            _fail('reader_pending_or_active')
        self._active = True
        self._fd_refs = []  # previous operation was fully closed; pending never reaches here
        self._os = self._fs if self._fs is not None else os
        self._last_clock = None
        self._deadline = self._current_generation.absolute_deadline
        self._raw, self._files, self._closed, self._total, self._task_count = [], 0, 0, 0, 0
        self._stage, self._pass = 'begin', 0
        if self._fs is None and sys.platform != 'linux':
            _fail('unsupported_platform')
        local_deadline = self._check() + self._timeout
        self._deadline = local_deadline if self._deadline is None else min(self._deadline, local_deadline)
        self._stage = 'proc_root'
        self._directory('/proc', True)

    def _observe_body(self, pid, expected, absence_boot):
        if self._active or self._pending:
            _fail('reader_pending_or_active')
        boot, actual, absent, remaining, same_boot, passes = None, None, False, (), False, 0
        reason, kind = 'read_unknown', 'unknown'
        try:
            self._begin()
            if pid is _SELF:
                self._check()
                pid = self._os.getpid()
                self._retain_return(pid)
                if not _uint(pid, 1, MAX_PID): _fail('invalid_expected_actor')
            observations = []
            for index in (1, 2):
                self._pass = index
                row = (self._absence_pass(expected, absence_boot) if absence_boot is not None else
                       self._actor_pass(pid))
                observations.append(row)
                passes = index
                boot = row[0]
            self._stage = 'identity_compare'
            if observations[0][-1] != observations[1][-1]:
                if observations[0][0] != observations[1][0]:
                    _fail('boot_changed')
                if absence_boot is None:
                    if observations[0][1].start != observations[1][1].start:
                        _fail('pid_reused')
                    old_tasks = {row.pid: row.start for row in observations[0][4]}
                    new_tasks = {row.pid: row.start for row in observations[1][4]}
                    if set(old_tasks) != set(new_tasks):
                        _fail('task_set_changed')
                    if old_tasks != new_tasks:
                        _fail('task_reused')
                _fail('observation_changed')
            same_boot = True
            if absence_boot is not None:
                absent, remaining, reason = observations[1][1:4]
                kind = 'absence' if reason == 'absence_observed' and absent and not remaining else 'opaque'
            else:
                _, first, exe, command, tasks, reason, _ = observations[1]
                if reason == 'live_actor':
                    actual = owner.Actor(pid, first.start, exe, hashlib.sha256(command).hexdigest(),
                                         tuple((row.pid, row.start, row.state) for row in tasks))
                    if expected is not None and actual.key() != expected.key():
                        if actual.start != expected.start:
                            _fail('pid_reused')
                        _fail('expected_actor_changed')
                    kind = 'live_actor'
                else:
                    kind = 'opaque'
            self._check()
            self._stage = 'observed'
        except ProcReadError as error:
            self._current_generation.error = error
            reason, kind, actual, absent = error.code, 'unknown', None, False
        except OSError as error:
            self._current_generation.error = error
            reason = ('permission_denied' if _errno_is(error, (errno.EPERM, errno.EACCES)) else
                      'record_disappeared' if _errno_is(error, (errno.ENOENT, errno.ESRCH)) else 'read_errno')
            kind, actual, absent = 'unknown', None, False
        except Exception as error:
            self._current_generation.error = error
            reason, kind, actual, absent = 'unexpected_read_error', 'unknown', None, False
        except BaseException as error:
            self._current_generation.error = error
            reason, kind, actual, absent = 'interrupted', 'unknown', None, False
        finally:
            self._active = False
        return ProcObservation(kind, reason, self._stage, boot, actual, absent, remaining, same_boot,
                               passes, tuple(self._raw), self._files, self._closed,
                               self._pending, self._task_count)

    @property
    def operation_history(self): return tuple(self._history)

    def owns_generation(self, generation):
        return (type(generation) is ProcGeneration and generation.reader is self and
            generation._issuer is self._issuer and type(generation.ordinal) is int and
            0 <= generation.ordinal < len(self._history) and self._history[generation.ordinal] is generation)

    def owns_open_ticket(self, ticket):
        return (type(ticket) is ProcOpenTicket and ticket.reader is self and ticket._issuer is self._issuer and
            self.owns_generation(ticket.generation) and type(ticket.ordinal) is int and
            0 <= ticket.ordinal < len(ticket.generation.tickets) and
            ticket.generation.tickets[ticket.ordinal] is ticket)

    def closed_open_ticket(self, ticket):
        """Issuer's immediate close evidence only; never fstat/reclose a historical number."""
        if not self.owns_open_ticket(ticket) or ticket.unknown or not ticket.open_called: return False
        if ticket.failed_without_fd:
            return (ticket.descriptor is None and not ticket.returned and not ticket.registered and
                isinstance(ticket.open_error, OSError) and type(ticket.open_error.errno) is int and
                1 <= ticket.open_error.errno <= 4095 and not ticket.close_attempted)
        return (ticket.returned and ticket.registered and _uint(ticket.descriptor, 0, 0x7fffffff) and
            ticket.close_attempted and ticket.close_returned and ticket.close_result is None and
            ticket.ebadf_observed and type(ticket.ebadf_errno) is int and ticket.ebadf_errno == errno.EBADF and
            isinstance(ticket.ebadf_error, OSError) and ticket.close_error is None)

    def history_closed(self):
        """Local original inventory fact, not a CloseProof or network permission."""
        if self._active or self._history_active or self._pending: return False
        return all(self.owns_generation(generation) and generation.ended and not generation.active and
            not generation.unknown and not generation.late and
            all(self.closed_open_ticket(ticket) for ticket in generation.tickets) for generation in self._history)

    def _observe(self, pid, expected, absence_boot, _absolute_deadline=None):
        if _absolute_deadline is not None and (type(_absolute_deadline) not in (int, float) or
                not 0 <= _absolute_deadline < 1e12 or not math.isfinite(float(_absolute_deadline))):
            _fail('invalid_deadline')
        if self._active or self._history_active or self._pending: _fail('reader_pending_or_active')
        budget = self._bound_budget_v24
        if budget is None: _fail('reader_unbound')
        if not budget._mutex.acquire(timeout=0.2): _fail('reader_pending_or_active')
        try:
            budget._context()  # Exact bound-reader pointers are also checked here.
            credit = budget.reserve(budget._store._resource_lane_v23, 'PROC_GENERATION', MAX_GENERATION_PAYLOAD)
            accounting_row = budget._owned(credit)
            generation, failure, result = None, None, None
            self._history_active = True
            try:
                budget.started(credit)
                generation = ProcGeneration(self, len(self._history), credit, _absolute_deadline)
                self._history.append(generation)
                self._current_generation, self._history_active = generation, True
                self._resource_error_v24 = None
                result = self._observe_body(pid, expected, absence_boot)
                generation.observation = result  # Actual immutable original, never rebuilt schema.
            except BaseException as caught:
                failure = caught
                self._resource_error_v24 = caught
                self._pending = True
                if generation is not None: generation.error, generation.unknown = caught, True
            finally:
                payloads, accounting_error, payload_seen = [], None, set()
                if generation is not None:
                    try:
                        for row in generation.raw:
                            if type(row.data) is bytes and id(row.data) not in payload_seen:
                                payloads.append(row.data); payload_seen.add(id(row.data))
                        for ticket in generation.tickets:
                            for value in ticket.chunks + [ticket.data, ticket.incoming]:
                                if type(value) is bytes:
                                    if id(value) not in payload_seen:
                                        payloads.append(value); payload_seen.add(id(value))
                                elif value is not None:
                                    generation.unknown = self._pending = True
                    except BaseException as caught:
                        accounting_error = caught
                        generation.unknown = self._pending = True
                try:
                    if accounting_row['active']: budget.returned(credit, generation, tuple(payloads))
                except BaseException as caught:
                    accounting_error = caught
                    self._pending = True
                    if generation is not None: generation.unknown = True
                finally:
                    try:
                        if accounting_row['active'] and (generation is None or generation.unknown or self._pending):
                            budget.mark_unknown(credit)
                    except BaseException as caught:
                        if accounting_error is None: accounting_error = caught
                    finally:
                        try:
                            if accounting_row['active'] and budget.settle(credit) is not True:
                                self._pending = True
                                if generation is not None: generation.unknown = True
                        except BaseException as caught:
                            self._pending = True
                            if generation is not None: generation.unknown = True
                            if accounting_error is None: accounting_error = caught
                        finally:
                            if generation is not None:
                                generation.active, generation.ended = False, True
                            self._history_active, self._current_generation = False, None
                            if generation is not None: generation.late = accounting_row['late']
                if failure is None and accounting_error is not None: failure = accounting_error
            if failure is not None: raise failure
            if self._resource_error_v24 is not None: raise self._resource_error_v24
            if self._pending and result.resource_pending is not True: _fail('reader_pending_or_active')
            return result
        finally: budget._mutex.release()

    def read_actor(self, pid, expected=None, _absolute_deadline=None):
        if not _uint(pid, 1, MAX_PID) or (expected is not None and
                (type(expected) is not owner.Actor or expected.pid != pid)):
            _fail('invalid_expected_actor')
        return self._observe(pid, expected, None, _absolute_deadline)

    def read_self(self, _absolute_deadline=None):
        return self._observe(_SELF, None, None, _absolute_deadline)

    def read_absence(self, actor, boot, _absolute_deadline=None):
        if type(actor) is not owner.Actor:
            _fail('invalid_expected_actor')
        return self._observe(actor.pid, actor, _expected_boot(boot), _absolute_deadline)
