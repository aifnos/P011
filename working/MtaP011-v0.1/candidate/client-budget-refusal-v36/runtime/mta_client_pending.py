"""Exact current-owner pending file, not RF admission or a complete Store.
V36 keeps only an actual native before-generation refusal diagnostic. It never
returns an observation for a refusal or clears any previous unknown state.

Pure construction. Explicit creation requires this process's already-held
CLIENT device/journal locks. Any pre-existing entry is blocked, never decoded,
overwritten or removed. Only the one original descriptor is read/closed.
The narrow terminal clear requires the exact concrete Store's internal guard
and fresh current canonical. It never closes descriptors or proves RF restore.
"""
import ctypes
import errno
import math
import os
import threading
import time

import p011_json as json
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_proc as proc
import mta_p2p_client_init as core
import mta_client_resource_budget as resources


MAX_BYTES = 32768
_CODES = frozenset(('invalid_config', 'invalid_clock', 'expired', 'clock_regressed',
    'already_attempted', 'invalid_locks', 'owner_unknown', 'owner_changed',
    'global_pending_blocked', 'marker_changed', 'io_unknown', 'create_unknown',
    'resource_pending', 'not_created', 'closed', 'close_unknown',
    'invalid_binding', 'binding_attempted', 'binding_unknown', 'prepared_changed',
    'journal_released', 'invalid_handoff', 'handoff_unknown', 'terminal_sealed',
    'invalid_terminal', 'clear_not_authorized', 'clear_unknown'))


class PendingError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'io_unknown'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise PendingError(code) from None


class _LinuxIo(files._LinuxIo):
    def seek_start(self, fd):
        return os.lseek(fd, 0, os.SEEK_SET)

    def unlink_at(self, parent, name):
        if type(parent) is not int or not 0 <= parent <= 0x7fffffff or \
                type(name) is not str or name != coordination.GLOBAL_PENDING:
            _fail('invalid_terminal')
        library = self._libc()
        library.unlinkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
        library.unlinkat.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = library.unlinkat(parent, coordination.GLOBAL_PENDING.encode('ascii'), 0)
        return result, ctypes.get_errno()


class PendingObservation(object):
    """Private instance observation, never an admission or clear capability."""
    __slots__ = ('_issuer', 'marker_state', 'durable_created', 'owner_observed',
                 'resource_pending', 'creation_unknown')

    def __init__(self, issuer, state, durable, owner, pending, unknown):
        for name, value in (('_issuer', issuer), ('marker_state', state),
                ('durable_created', durable), ('owner_observed', owner),
                ('resource_pending', pending), ('creation_unknown', unknown)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError('private immutable pending observation')

    def __repr__(self):
        return '<CLIENT private pending observation>'

    __str__ = __repr__


class OwnedMarkerBinding(object):
    """Private local file permit; only its issuer registry can activate it."""
    __slots__ = ('_issuer', '_marker', '_coordination', '_files', '_prepared',
                 '_epoch', '_serialization_lock')

    def __init__(self, issuer, marker, coordinator, journal_files, prepared, epoch, shared):
        for key, value in (('_issuer', issuer), ('_marker', marker),
                ('_coordination', coordinator), ('_files', journal_files),
                ('_prepared', prepared), ('_epoch', epoch), ('_serialization_lock', shared)):
            object.__setattr__(self, key, value)

    def __setattr__(self, *unused):
        raise AttributeError('private immutable own-marker binding')

    def __repr__(self):
        return '<CLIENT private local file binding>'

    __str__ = __repr__

    def verify(self, consumer, epoch):
        # No caller-supplied observation, inode, bool or ready flag.
        return self._marker._verify_binding(self, consumer, epoch)


class _BindingTicket(object):
    def __init__(self, journal_files, prepared, epoch, shared):
        self.files, self.prepared, self.epoch, self.shared = journal_files, prepared, epoch, shared
        self.binding, self.ready, self.unknown = None, False, True
        self.journal_epoch, self.handoff = object(), None


class _BindingRefusalV36(object):
    """One current-call denial diagnostic; no observation, credit or permission."""
    __slots__ = ('marker', 'call', 'consumer', 'binding', 'epoch', 'locks', 'worker',
        'budget', 'budget_epoch', 'budget_mutex', 'reader', 'lane', 'reader_facts',
        'accounting_facts', 'error', 'deadline', 'ended', 'coord_seen', 'store_seen')
    def __init__(self, marker, context, reader, budget, reader_facts, accounting_facts, error):
        binding, consumer, epoch, call = context
        for name, value in (('marker', marker), ('call', call), ('consumer', consumer),
                ('binding', binding), ('epoch', epoch), ('locks', marker._locks),
                ('worker', threading.current_thread()), ('budget', budget),
                ('budget_epoch', budget._epoch), ('budget_mutex', budget._mutex),
                ('reader', reader), ('lane', budget._store._resource_lane_v23),
                ('reader_facts', reader_facts), ('accounting_facts', accounting_facts),
                ('error', error), ('deadline', marker._deadline), ('ended', False),
                ('coord_seen', False), ('store_seen', False)):
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('private refusal diagnostic')
    def __repr__(self): return '<private current binding refusal; no permission>'


class ClientPendingMarker(object):
    """One create/read lifetime bound to exact local coordination and locks.

    Actual default Linux I/O; private FakeIO/reader seams are HOST-only. The
    marker carries run/candidate and freshly observed current process identity,
    but does NOT authenticate a frozen manifest, exec chain or inherited OFD.
    bind_files issues only an exact local file exception, never RF admission.
    """
    def __init__(self, coordinator, locks, timeout=3.0, _io=None, _reader=None,
                 _clock=None, _serialization_lock=None):
        if (type(coordinator) is not coordination.ClientCoordination or
                type(locks) is not coordination.LockSet or locks is not coordinator._locks or
                locks._issuer is not coordinator._issuer or type(timeout) not in (int, float) or
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or
                (_clock is not None and not callable(_clock)) or
                (_serialization_lock is not None and
                 _serialization_lock is not coordinator._serialization_lock)):
            _fail('invalid_config')
        self._coordination, self._locks = coordinator, locks
        self._io = _io if _io is not None else _LinuxIo()
        self._reader = _reader if _reader is not None else proc.ProcReader(timeout=timeout)
        self._clock, self._timeout = _clock or time.monotonic, float(timeout)
        self._mutex, self._issuer = threading.RLock(), object()
        self._serialization_lock = coordinator._serialization_lock
        self._serial_explicit = coordinator._serial_explicit
        self._binding_attempted, self._binding_ticket = False, None
        self._binding_call_v36, self._binding_context_v36 = None, None
        self._binding_refusal_v36 = None  # Latest denial only; not a producer/resource ledger.
        self._ticket, self._metadata, self._data, self._owner, self._boot = None, None, None, None, None
        self._parent, self._deadline, self._last_clock = None, None, None
        self._attempted, self._ended, self._durable = False, False, False
        self._creation_unknown, self._resource_pending = False, False
        self._state, self._reason = 'unknown', 'not_recorded'
        self._clear_requested, self._clear_sealed, self._clear_attempted = False, False, False
        self._clear_durability, self._clear_reason, self._clear_refs = 'not_attempted', 'not_recorded', None
        self._clear_fd = None

    def __repr__(self):
        return '<CLIENT private pending owner>'

    def _operation(self):
        return coordination._DomainLock(self, self._mutex)

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock:
            _fail('clock_regressed')
        self._last_clock = value
        if self._deadline is not None and value >= self._deadline:
            _fail('expired')
        return value

    def _begin(self):
        self._deadline = None
        self._deadline = self._now() + self._timeout

    def _guard(self):
        """Caller also holds coordinator mutex throughout each file operation."""
        if self._clear_sealed: _fail('terminal_sealed')
        self._now()
        c = self._coordination
        c._owned(self._locks)
        c._begin()
        c._anchors_valid()
        for ticket in (self._locks._device, self._locks._journal):
            c._lock_valid(ticket)
        if len(c._anchors) != 4:
            _fail('invalid_locks')
        parent = c._anchors[1][0].fd
        if self._parent is not None and self._parent != parent:
            _fail('invalid_locks')
        self._parent = parent
        self._now()

    def _refusal_reader_facts_v36(self, reader):
        fields = ('_fs', '_clock', '_issuer', '_history', '_current_generation', '_history_active',
            '_resource_budget_v24', '_bound_budget_v24', '_resource_error_v24', '_fd_refs',
            '_open_attempt', '_pending', '_stage', '_pass', '_raw', '_files', '_closed',
            '_total', '_task_count', '_deadline', '_last_clock', '_os')
        return (tuple((name, name in reader.__dict__, reader.__dict__.get(name)) for name in fields),
            tuple(reader._history), tuple(reader._fd_refs), tuple(reader._raw))
    def _refusal_accounting_facts_v36(self, budget):
        return (budget._rows, len(budget._rows), None if not budget._rows else budget._rows[-1],
            tuple(tuple(row) for row in budget._used), tuple(budget._retained), tuple(budget._inflight))
    def _same_refusal_facts_v36(self, reader, budget, reader_facts, accounting_facts):
        fields, history, descriptors, raw = reader_facts
        for name, present, original in fields:
            if (name in reader.__dict__) is not present or reader.__dict__.get(name) is not original:
                return False
        if (len(reader._history) != len(history) or any(a is not b for a, b in zip(reader._history, history)) or
                tuple(reader._fd_refs) != descriptors or len(reader._raw) != len(raw) or
                any(a is not b for a, b in zip(reader._raw, raw))): return False
        rows, count, last, used, retained, inflight = accounting_facts
        return (budget._rows is rows and len(rows) == count and
            (None if not rows else rows[-1]) is last and
            tuple(tuple(row) for row in budget._used) == used and
            tuple(budget._retained) == retained and tuple(budget._inflight) == inflight)
    def _refusal_owner_v36(self, reader, budget, context):
        import mta_client_store as stores
        if type(context) is not tuple or len(context) != 4: return False
        binding, consumer, epoch, call = context
        c, ticket, store = self._coordination, self._binding_ticket, budget._store
        if (type(reader) is not proc.ProcReader or type(budget) is not resources.ResourceBudget or
                reader is not self._reader or reader._resource_budget_v24 is not budget or
                reader._bound_budget_v24 is not budget or not any(r is reader for r in budget._readers) or
                type(store) is not stores.DurableClientInitStore or store._resource_budget_v23 is not budget or
                store._proc_reader is not reader or store._proc_reader_original_v24 is not reader or
                store._marker is not self or store._binding is not binding or store._epoch is not epoch or
                store._mutex is not budget._mutex or budget._epoch is not epoch or
                type(budget._mutex) is not coordination._RLOCK_TYPE or
                not callable(getattr(budget._mutex, '_is_owned', None)) or budget._mutex._is_owned() is not True or
                store._resource_lane_v23 != resources.PREPARATION_NETWORK or
                type(binding) is not OwnedMarkerBinding or binding._marker is not self or
                binding._coordination is not c or binding._epoch is not epoch or
                consumer is not c and consumer is not binding._files or
                ticket is None or ticket.binding is not binding or ticket.ready is not True or ticket.unknown is not False or
                self._locks is not c._locks or self._locks is not store._current_locks or
                self._binding_call_v36 is not call or store._unknown or
                c._resource_pending or c._lock_unknown or c._ended or self._ended or
                self._creation_unknown or self._resource_pending or not self._durable or
                binding._files._resource_pending or binding._files._write_pending or binding._files._published_unknown or
                reader._active or reader._history_active or reader._pending or reader._current_generation is not None or
                not reader.history_closed() or budget._owner_changed or budget._overrun): return False
        for bound, method in ((reader.read_self, proc.ProcReader.read_self),
                (reader._observe, proc.ProcReader._observe), (reader._observe_body, proc.ProcReader._observe_body),
                (budget.reserve, resources.ResourceBudget.reserve)):
            if getattr(bound, '__self__', None) not in (reader, budget) or getattr(bound, '__func__', None) is not method:
                return False
        budget._context()
        return True
    def _refusal_capture_v36(self, reader, budget, context, reader_facts, accounting_facts, error):
        try:
            if (type(error) is not resources.ResourceBudgetError or error.code != 'safe_exhaustion' or
                    not self._refusal_owner_v36(reader, budget, context) or
                    budget._exhausted[0] is not True or budget._reason != 'safe_exhaustion' or
                    not self._same_refusal_facts_v36(reader, budget, reader_facts, accounting_facts)):
                return None
            self._now()  # Expiry/clock drift never becomes a known denial receipt.
            row = _BindingRefusalV36(self, context, reader, budget, reader_facts, accounting_facts, error)
            self._binding_refusal_v36 = row
            return row
        except BaseException: return None
    def _refusal_current_v36(self, error, consumer, epoch):
        try:
            row = self._binding_refusal_v36
            if (type(row) is not _BindingRefusalV36 or row.marker is not self or row.error is not error or
                    row.call is not self._binding_call_v36 or row.consumer is not consumer or row.epoch is not epoch or
                    row.worker is not threading.current_thread() or row.ended is not True or
                    row.locks is not self._locks or row.budget_epoch is not row.budget._epoch or
                    row.budget_mutex is not row.budget._mutex or row.deadline is not self._deadline or
                    row.lane != resources.PREPARATION_NETWORK or row.store_seen is not False or
                    type(error) is not resources.ResourceBudgetError or error.code != 'safe_exhaustion' or
                    row.budget._exhausted[0] is not True or row.budget._reason != 'safe_exhaustion' or
                    not self._refusal_owner_v36(row.reader, row.budget,
                        (row.binding, row.consumer, row.epoch, row.call)) or
                    not self._same_refusal_facts_v36(row.reader, row.budget, row.reader_facts, row.accounting_facts)):
                return None
            self._now()
            return row
        except BaseException: return None
    def _consume_refusal_coord_v36(self, error, consumer, epoch):
        row = self._refusal_current_v36(error, consumer, epoch)
        if row is None or consumer is not self._coordination or row.coord_seen is not False: return False
        object.__setattr__(row, 'coord_seen', True)
        return True
    def _consume_refusal_store_v36(self, error, store):
        row = self._binding_refusal_v36
        if type(row) is not _BindingRefusalV36 or row.budget._store is not store: return False
        row = self._refusal_current_v36(error, row.consumer, row.epoch)
        if row is None or (row.consumer is self._coordination and row.coord_seen is not True or
                row.consumer is row.binding._files and row.coord_seen is not False): return False
        object.__setattr__(row, 'store_seen', True)
        return True

    def _observe_self(self):
        self._now()
        context, reader = self._binding_context_v36, self._reader
        budget = reader._bound_budget_v24 if type(reader) is proc.ProcReader else None
        before = None
        try:
            if budget is not None and self._refusal_owner_v36(reader, budget, context):
                before = (self._refusal_reader_facts_v36(reader), self._refusal_accounting_facts_v36(budget))
        except BaseException: before = None
        try:
            value = reader.read_self()
        except BaseException as error:
            if before is not None:
                self._refusal_capture_v36(reader, budget, context, before[0], before[1], error)
            raise
        self._now()
        if (type(value) is not proc.ProcObservation or value.kind != 'live_actor' or
                type(value.actor) is not core.Actor or not value.actor.live() or
                value.passes != 2 or value.same_boot is not True or value.resource_pending is not False or
                type(value.file_count) is not int or value.file_count < 1 or
                value.file_count != value.closed_count):
            _fail('owner_unknown')
        if self._owner is not None and (value.actor.key() != self._owner.key() or value.boot != self._boot):
            _fail('owner_changed')
        if self._owner is None:
            self._owner, self._boot = value.actor, value.boot
        return value.actor

    def _absent(self):
        self._now()
        try:
            self._io.stat_at(self._parent, coordination.GLOBAL_PENDING)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._state = 'absent_observed'
                return
            raise
        _fail('global_pending_blocked')

    def _encode(self):
        # New envelope, not a migration/decoder for old GO or CLIENT journals.
        value = {'version': 1, 'kind': 'p011_client_pending_owner',
                 'run': self._coordination._run, 'boot': self._boot,
                 'identity': list(self._coordination._identity.key()),
                 'owner': list(self._owner.key())}
        data = (json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
        if not 1 <= len(data) <= MAX_BYTES:
            _fail('create_unknown')
        return data

    def _read_owned(self, _handoff=None, _terminal=False):
        if _terminal: self._terminal_resource_guard()
        elif _handoff is None: self._guard()
        else: self._journal_device_guard(_handoff)
        ticket = self._ticket
        if ticket is None or ticket.opening_unknown or ticket.attempted or ticket.closed:
            _fail('resource_pending')
        metadata = files._file_metadata(self._io.fstat(ticket.fd))
        if self._metadata is None or metadata != self._metadata or metadata[6] != len(self._data):
            _fail('marker_changed')
        if files._file_metadata(self._io.stat_at(self._parent, coordination.GLOBAL_PENDING)) != metadata:
            _fail('marker_changed')
        if self._io.seek_start(ticket.fd) != 0:
            _fail('io_unknown')
        data = b''
        while len(data) <= MAX_BYTES:
            self._now()
            chunk = self._io.read(ticket.fd, min(4096, MAX_BYTES + 1 - len(data)))
            if type(chunk) is not bytes or len(chunk) > min(4096, MAX_BYTES + 1 - len(data)):
                _fail('io_unknown')
            data += chunk
            if not chunk:
                break
        if data != self._data or files._file_metadata(self._io.fstat(ticket.fd)) != metadata or \
                files._file_metadata(self._io.stat_at(self._parent, coordination.GLOBAL_PENDING)) != metadata:
            _fail('marker_changed')
        if _terminal: self._terminal_resource_guard()
        elif _handoff is None: self._guard()
        else: self._journal_device_guard(_handoff)
        self._state = 'retained_observed'

    def _record_error(self, error):
        self._reason = error.code if type(error) is PendingError else 'io_unknown'
        self._state = 'unknown'

    def create(self):
        with self._operation(), self._coordination._operation():
            if self._attempted or self._ended:
                _fail('already_attempted')
            self._attempted = True
            try:
                self._begin()
                self._io.validate()
                self._guard()
                self._observe_self()
                self._absent()
                self._data = self._encode()
                flags = 0
                for name in ('O_RDWR', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC'):
                    flags |= self._io.flag(name)
                ticket = files._Fd(self._io, 'pending_create')
                self._ticket = ticket  # Before the actual creation call.
                self._creation_unknown = True
                try:
                    ticket.fd = self._io.open_at(self._parent, coordination.GLOBAL_PENDING, flags, 0o600)
                except OSError as error:
                    if type(error.errno) is int and 0 < error.errno <= 4095:
                        ticket.opening_unknown, ticket.closed = False, True
                        if error.errno == errno.EEXIST:
                            self._creation_unknown = False
                            _fail('global_pending_blocked')
                    raise
                if type(ticket.fd) is not int or not 0 <= ticket.fd <= 0x7fffffff:
                    self._resource_pending = True
                    _fail('create_unknown')
                ticket.opening_unknown = False
                created = files._file_metadata(self._io.fstat(ticket.fd))
                if created[6] != 0:
                    _fail('marker_changed')
                at = 0
                while at < len(self._data):
                    self._now()
                    count = self._io.write(ticket.fd, self._data[at:at + 4096])
                    if type(count) is not int or not 1 <= count <= min(4096, len(self._data) - at):
                        _fail('io_unknown')
                    at += count
                self._now()
                if self._io.fsync(ticket.fd) is not None or self._io.fsync(self._parent) is not None:
                    _fail('create_unknown')
                self._metadata = files._file_metadata(self._io.fstat(ticket.fd))
                if self._metadata[:6] != created[:6]:
                    _fail('marker_changed')
                self._read_owned()
                self._observe_self()
                self._durable, self._creation_unknown = True, False
                return self._observation(True)
            except BaseException as error:
                if self._ticket is not None and self._ticket.opening_unknown:
                    self._resource_pending = True
                self._record_error(error)
                if type(error) is PendingError:
                    raise
                if isinstance(error, Exception):
                    _fail('io_unknown')
                raise

    def verify(self):
        with self._operation(), self._coordination._operation():
            if self._clear_sealed: _fail('terminal_sealed')
            if self._ended:
                _fail('closed')
            if not self._durable or self._creation_unknown:
                _fail('not_created')
            try:
                self._begin()
                self._observe_self()
                self._read_owned()
                self._observe_self()
                return self._observation(True)
            except BaseException as error:
                self._record_error(error)
                if type(error) is PendingError:
                    raise
                if isinstance(error, Exception):
                    _fail('io_unknown')
                raise

    def _observation(self, owner=False):
        return PendingObservation(self._issuer, self._state, self._durable, owner,
                                  self._resource_pending, self._creation_unknown)

    def _binding_inputs(self, journal_files, prepared, epoch, shared):
        c = self._coordination
        if (type(journal_files) is not files.ClientJournalFiles or
                type(prepared) is not files.CanonicalRecord or type(epoch) is not object or
                type(shared) is not coordination._RLOCK_TYPE or
                journal_files._run != c._run or journal_files._identity.key() != c._identity.key() or
                prepared._issuer is not journal_files._issuer or
                type(prepared._generation) is not int or prepared._generation != journal_files._generation or
                not any(item is prepared for item in journal_files._issued_canonicals) or
                journal_files._write_pending or journal_files._published_unknown or
                type(prepared.journal) is not core.Journal or prepared.journal.stage != 'prepared' or
                prepared.journal.ready is not False or prepared.journal.identity.key() != c._identity.key() or
                c._owned_marker_binding is not None or journal_files._owned_marker_binding is not None or
                any(obj._serial_explicit and obj._serialization_lock is not shared
                    for obj in (self, c, journal_files))):
            _fail('invalid_binding')

    def _binding_live(self, binding):
        c, jf = self._coordination, binding._files
        if (self._ended or not self._durable or self._creation_unknown or self._resource_pending or
                self._ticket is None or self._ticket.closed or self._ticket.attempted or self._ticket.opening_unknown or
                jf._ended or not jf._opened or jf._resource_pending or
                len(jf._anchors) != 4 or len(c._anchors) != 4):
            _fail('binding_unknown')
        c._owned(self._locks)
        # Directory identities use dev/inode/mode/owner, not mutable timestamps.
        if any(c._anchors[i][3] != jf._anchors[i][3] for i in range(4)):
            _fail('invalid_binding')
        saved_c, saved_jf = (c._deadline, c._last_clock), (jf._deadline, jf._last_clock)
        try:
            self._begin()
            jf._begin_budget(); jf._anchors_valid()
            self._observe_self(); self._read_owned(); self._observe_self()
            if binding._prepared.journal.baseline.boot != self._boot:
                _fail('owner_changed')
            jf._anchors_valid()
        finally:
            # A nested marker read must not extend an outer transaction budget.
            c._deadline, c._last_clock = saved_c
            jf._deadline, jf._last_clock = saved_jf

    def bind_files(self, exact_journal_files, exact_prepared_canonical,
                   exact_store_epoch_object, shared_serialization_RLock):
        # Reject shape before acquiring an arbitrary object as a lock.
        if type(shared_serialization_RLock) is not coordination._RLOCK_TYPE or \
                type(exact_journal_files) is not files.ClientJournalFiles:
            _fail('invalid_binding')
        c, jf, shared = self._coordination, exact_journal_files, shared_serialization_RLock
        if any(obj._serial_explicit and obj._serialization_lock is not shared for obj in (self, c, jf)):
            _fail('invalid_binding')
        with shared, c._operation(), self._operation(), jf._operation():
            if self._binding_attempted:
                _fail('binding_attempted')
            self._binding_attempted = True
            ticket = _BindingTicket(jf, exact_prepared_canonical, exact_store_epoch_object, shared)
            self._binding_ticket = ticket  # Preserve partial registration; NEVER rollback/rebind.
            try:
                self._binding_inputs(jf, exact_prepared_canonical, exact_store_epoch_object, shared)
                binding = OwnedMarkerBinding(self._issuer, self, c, jf,
                    exact_prepared_canonical, exact_store_epoch_object, shared)
                ticket.binding = binding
                self._binding_live(binding)
                jf._begin_budget()
                current = jf._read_current()  # No pending exception before initial proof exists.
                if (current is None or current.data != exact_prepared_canonical.data or
                        current.metadata != exact_prepared_canonical.metadata or
                        not core._same_journal(current.journal, exact_prepared_canonical.journal)):
                    _fail('prepared_changed')
                # Install both consumers and the common outer domain while all
                # old inner/domain locks are held. Queued old domains recapture.
                for obj in (c, jf):
                    obj._owned_marker_binding, obj._owned_marker_epoch = binding, exact_store_epoch_object
                for obj in (self, c, jf):
                    obj._serialization_lock = shared
                self._binding_live(binding)
                jf._begin_budget()
                final = jf._read_current()
                if (final is None or final.data != exact_prepared_canonical.data or
                        final.metadata != exact_prepared_canonical.metadata or
                        not core._same_journal(final.journal, exact_prepared_canonical.journal)):
                    _fail('prepared_changed')
                ticket.ready, ticket.unknown = True, False
                return binding
            except BaseException as error:
                ticket.ready, ticket.unknown = False, True
                self._record_error(error)
                if type(error) is PendingError: raise
                if isinstance(error, Exception): _fail('binding_unknown')
                raise

    def _verify_binding(self, binding, consumer, epoch):
        with self._operation(), self._coordination._operation():
            if self._clear_sealed: _fail('terminal_sealed')
            ticket = self._binding_ticket
            if (type(binding) is not OwnedMarkerBinding or ticket is None or
                    ticket.binding is not binding or ticket.ready is not True or ticket.unknown is not False or
                    binding._issuer is not self._issuer or binding._marker is not self or
                    binding._coordination is not self._coordination or epoch is not binding._epoch or
                    consumer is not binding._coordination and consumer is not binding._files or
                    any(obj._serialization_lock is not binding._serialization_lock
                        for obj in (self, self._coordination, binding._files)) or
                    any(obj._owned_marker_binding is not binding or obj._owned_marker_epoch is not epoch
                        for obj in (self._coordination, binding._files))):
                _fail('invalid_binding')
            # Released is a known suspended state, not an invitation to rebind.
            # Do not destroy the registry merely for a rejected ordinary call.
            if ticket.handoff is not None and ticket.handoff.stage != 'active':
                _fail('journal_released')
            if ticket.handoff is not None and (ticket.handoff.unknown or
                    ticket.journal_epoch is not ticket.handoff.new_epoch or
                    self._locks is not ticket.handoff.new_locks):
                _fail('handoff_unknown')
            with binding._files._operation():
                call = object()
                self._binding_call_v36 = call
                self._binding_context_v36 = (binding, consumer, epoch, call)
                try:
                    self._binding_live(binding)
                    return self._observation(True)
                except BaseException as error:
                    row = self._binding_refusal_v36
                    if type(row) is _BindingRefusalV36 and row.call is call and row.error is error:
                        # A denied native generation created no observation or
                        # resource. Preserve known originals, but still fail.
                        raise
                    ticket.ready, ticket.unknown = False, True
                    self._record_error(error)
                    if type(error) is PendingError: raise
                    if isinstance(error, Exception): _fail('binding_unknown')
                    raise
                finally:
                    self._binding_context_v36 = None
                    row = self._binding_refusal_v36
                    if type(row) is _BindingRefusalV36 and row.call is call:
                        object.__setattr__(row, 'ended', True)

    def _journal_binding_context(self, context):
        """Exact local registry checks, never caller shape/absence authority."""
        if self._clear_sealed: _fail('terminal_sealed')
        ticket, c = self._binding_ticket, self._coordination
        if (type(context) is not coordination._JournalHandoff or context is not c._handoff or
                context.owner is not c or ticket is None or ticket.binding is not context.binding or
                ticket.ready is not True or ticket.unknown is not False or
                context.binding._issuer is not self._issuer or context.binding._marker is not self or
                context.binding._coordination is not c or context.epoch is not ticket.epoch or
                context.binding._epoch is not context.epoch or
                c._owned_marker_binding is not context.binding or c._owned_marker_epoch is not context.epoch or
                context.binding._files._owned_marker_binding is not context.binding or
                context.binding._files._owned_marker_epoch is not context.epoch or
                any(obj._serialization_lock is not ticket.shared
                    for obj in (self, c, context.binding._files)) or
                ticket.shared is not context.binding._serialization_lock or
                self._ended or not self._durable or self._creation_unknown or self._resource_pending):
            _fail('invalid_handoff')
        if ticket.handoff is not None and ticket.handoff is not context:
            _fail('invalid_handoff')
        return ticket

    def _journal_device_guard(self, context):
        self._now()
        self._journal_binding_context(context)
        c, jf = self._coordination, context.binding._files
        c._handoff_owned(context)
        if (jf._ended or not jf._opened or jf._resource_pending or jf._write_pending or
                jf._published_unknown or len(jf._anchors) != 4 or len(c._anchors) != 4 or
                any(c._anchors[i][3] != jf._anchors[i][3] for i in range(4))):
            _fail('handoff_unknown')
        jf._anchors_valid()
        if self._parent != c._anchors[1][0].fd:
            _fail('invalid_locks')
        if context.stage == 'preparing':
            if self._locks is not context.initial or c._locks is not context.initial:
                _fail('invalid_handoff')
            c._lock_valid(context.journal)
        self._now()

    def _journal_handoff_live(self, context):
        """Fresh original marker/F/boot plus device-only lock while suspended."""
        c, jf = self._coordination, context.binding._files
        with self._operation(), c._operation(), jf._operation():
            self._journal_binding_context(context)
            saved = ((self._deadline, self._last_clock), (jf._deadline, jf._last_clock))
            try:
                self._begin()
                # A nested check must not extend the coordinator's one budget.
                self._deadline = min(self._deadline, c._deadline)
                jf._begin_budget()
                jf._deadline = min(jf._deadline, c._deadline)
                self._observe_self(); self._read_owned(context); self._observe_self()
                if context.binding._prepared.journal.baseline.boot != self._boot:
                    _fail('owner_changed')
                self._journal_device_guard(context)
            finally:
                self._deadline, self._last_clock = saved[0]
                jf._deadline, jf._last_clock = saved[1]

    def _prepare_journal_handoff(self, context):
        with self._operation(), self._coordination._operation():
            ticket = self._journal_binding_context(context)
            if ticket.handoff is not None: _fail('invalid_handoff')
            self._journal_handoff_live(context)
            context.old_epoch = ticket.journal_epoch
            ticket.handoff = context  # Suspend normal consumers before close.

    def _publish_journal_handoff(self, context):
        """Same outer RLock: retain partial swaps, issue readiness only last."""
        c, jf = self._coordination, context.binding._files
        with self._operation(), c._operation(), jf._operation():
            ticket = self._journal_binding_context(context)
            if (ticket.handoff is not context or ticket.journal_epoch is not context.old_epoch or
                    context.stage != 'reacquiring' or context.new_locks is None or
                    context.new_locks._device is not context.device or
                    context.new_locks._journal is not context.new_ticket):
                _fail('invalid_handoff')
            self._journal_handoff_live(context)
            c._lock_valid(context.new_ticket)
            context.stage = 'committing'
            c._locks = context.new_locks
            self._locks = context.new_locks
            ticket.journal_epoch = context.new_epoch
            # No rollback if a subsequent actual observation fails.
            self._journal_handoff_live(context)
            c._lock_valid(context.new_ticket)
            c._check()
            context.stage = 'active'

    def _terminal_context(self, store, binding, canonical):
        ticket, c = self._binding_ticket, self._coordination
        if (type(binding) is not OwnedMarkerBinding or ticket is None or
                ticket.binding is not binding or ticket.ready is not True or ticket.unknown is not False or
                binding._issuer is not self._issuer or binding._marker is not self or
                binding._coordination is not c or type(canonical) is not files.CanonicalRecord):
            _fail('invalid_terminal')
        jf = binding._files
        if (store._marker is not self or store._coordination is not c or store._files is not jf or
                store._binding is not binding or store._epoch is not binding._epoch or
                store._current_locks is not self._locks or self._locks is not c._locks or
                store._journal_epoch is not ticket.journal_epoch or
                store._canonical is not canonical or store._terminal_canonical is not canonical or
                store._finish_sealed is not True or
                store._finish_phase != 'terminal_durable' or
                store._mutex is not binding._serialization_lock or
                any(obj._serialization_lock is not binding._serialization_lock for obj in (self, c, jf)) or
                any(obj._owned_marker_binding is not binding or obj._owned_marker_epoch is not binding._epoch
                    for obj in (c, jf)) or
                canonical._issuer is not jf._issuer or type(canonical._generation) is not int or
                canonical._generation != jf._generation or
                not any(item is canonical for item in jf._issued_canonicals) or
                type(canonical.journal) is not core.Journal or canonical.journal.stage != 'reconciled' or
                canonical.journal.ready is not False or
                canonical.journal.identity.key() != c._identity.key() or
                canonical.journal.baseline.boot != self._boot):
            _fail('invalid_terminal')
        if ticket.handoff is not None and (ticket.handoff.stage != 'active' or ticket.handoff.unknown or
                ticket.journal_epoch is not ticket.handoff.new_epoch or
                self._locks is not ticket.handoff.new_locks):
            _fail('handoff_unknown')

    def _terminal_resource_guard(self):
        self._now()
        self._terminal_context(*self._clear_refs[:3])
        c, jf = self._coordination, self._clear_refs[4]
        if (self._ended or not self._durable or self._creation_unknown or self._resource_pending or
                self._ticket is None or self._ticket.closed or self._ticket.attempted or self._ticket.opening_unknown or
                self._ticket is not self._clear_refs[7] or type(self._ticket.fd) is not int or
                self._ticket.fd != self._clear_fd or self._locks is not self._clear_refs[5] or
                self._binding_ticket.journal_epoch is not self._clear_refs[8] or
                jf._ended or not jf._opened or jf._resource_pending or jf._write_pending or jf._published_unknown or
                len(c._anchors) != 4 or len(jf._anchors) != 4 or
                any(c._anchors[i][3] != jf._anchors[i][3] for i in range(4))):
            _fail('invalid_terminal')
        c._owned(self._locks)
        c._anchors_valid(); jf._anchors_valid()
        for ticket in (self._locks._device, self._locks._journal): c._lock_valid(ticket)
        if self._parent != c._anchors[1][0].fd: _fail('invalid_locks')
        self._now()

    def _terminal_canonical_readback(self, canonical):
        jf = self._clear_refs[4]
        self._terminal_resource_guard()
        current = jf._read_current()  # Dedicated sealed path; no ordinary pending admission.
        self._now()
        if (current is None or current.data != canonical.data or current.metadata != canonical.metadata or
                not core._same_journal(current.journal, canonical.journal)):
            _fail('invalid_terminal')
        self._terminal_resource_guard()

    def _terminal_absence(self):
        self._now()
        try: self._io.stat_at(self._parent, coordination.GLOBAL_PENDING)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._state = 'absent_observed'
                return
            raise
        self._state = 'unknown'  # A post-unlink replacement is not our retained original.
        _fail('marker_changed')

    def _terminal_unlinked_readback(self):
        self._terminal_resource_guard()
        self._observe_self()
        original = self._metadata
        metadata = files._metadata(self._io.fstat(self._ticket.fd))
        # unlink changes nlink and ctime, not original inode/content/mtime.
        if metadata[:5] != original[:5] or metadata[5] != 0 or metadata[6:8] != original[6:8]:
            _fail('marker_changed')
        if self._io.seek_start(self._ticket.fd) != 0: _fail('io_unknown')
        data = b''
        while len(data) <= MAX_BYTES:
            self._now()
            amount = min(4096, MAX_BYTES + 1 - len(data))
            chunk = self._io.read(self._ticket.fd, amount)
            if type(chunk) is not bytes or len(chunk) > amount: _fail('io_unknown')
            data += chunk
            if not chunk: break
        if data != self._data or files._metadata(self._io.fstat(self._ticket.fd)) != metadata:
            _fail('marker_changed')
        self._terminal_absence(); self._terminal_resource_guard(); self._observe_self()

    def _terminal_error_observation(self):
        """Bounded passive fact only; never retry a possibly completed write."""
        self._now()
        try: self._io.stat_at(self._parent, coordination.GLOBAL_PENDING)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._state = 'absent_observed'
                return
            raise
        self._read_owned(_terminal=True)  # Strict original FD/inode/fullbytes, not any entry.

    def _terminal_segment(self, exact_store, deadline):
        # The producer is outside this short segment. All four clocks are
        # renewed together and capped by the same absolute recovery total.
        exact_store._begin_disk(deadline)
        self._begin()
        self._deadline = min(self._deadline, exact_store._io_deadline, float(deadline))
        c, jf = self._coordination, self._clear_refs[4]
        c._begin(); c._deadline = min(c._deadline, self._deadline)
        jf._begin_budget(); jf._deadline = min(jf._deadline, self._deadline)

    def clear_terminal(self, exact_store, exact_binding, exact_terminal_canonical, deadline):
        # Late exact import avoids pending/store construction cycles. A caller
        # cannot substitute a bool, FinishReceipt, duck-typed finisher or subclass.
        from mta_client_store import DurableClientInitStore
        if type(exact_store) is not DurableClientInitStore or \
                type(exact_binding) is not OwnedMarkerBinding or exact_binding._marker is not self or \
                self._binding_ticket is None or self._binding_ticket.binding is not exact_binding or \
                type(exact_binding._files) is not files.ClientJournalFiles:
            _fail('invalid_terminal')
        with self._operation(), self._coordination._operation(), exact_binding._files._operation():
            if self._clear_requested: _fail('already_attempted')
            self._clear_requested = True
            self._clear_refs = (exact_store, exact_binding, exact_terminal_canonical,
                self._coordination, exact_binding._files, self._locks,
                self._binding_ticket, self._ticket, self._binding_ticket.journal_epoch)
            self._clear_fd = None if self._ticket is None else self._ticket.fd
            c, jf = self._coordination, exact_binding._files
            saved = ((self._deadline, self._last_clock), (c._deadline, c._last_clock),
                     (jf._deadline, jf._last_clock), exact_store._io_deadline)
            try:
                if (type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or
                        not math.isfinite(float(deadline)) or deadline != exact_store._finish_deadline):
                    _fail('expired')
                self._terminal_segment(exact_store, deadline)
                self._terminal_context(exact_store, exact_binding, exact_terminal_canonical)
                if exact_store._authorize_terminal_clear(self, exact_binding,
                        exact_terminal_canonical, deadline) is not None:
                    _fail('clear_not_authorized')
                # The exact Store callback performed the third fresh read and
                # authentication. Never charge it to the old short admission
                # budget or reuse its expired clocks for the sole commit.
                self._terminal_segment(exact_store, deadline)
                self._now()
                # Permanent seal before any write; only the dedicated terminal
                # path below may read original resources after this point.
                self._clear_sealed = True
                self._terminal_context(exact_store, exact_binding, exact_terminal_canonical)
                self._observe_self(); self._read_owned(_terminal=True); self._observe_self()
                self._terminal_canonical_readback(exact_terminal_canonical)
                self._terminal_context(exact_store, exact_binding, exact_terminal_canonical)
                self._now()
                self._clear_attempted, self._clear_durability = True, 'unknown'
                self._state = 'unknown'  # Registered before the sole unlink call.
                result = self._io.unlink_at(self._parent, coordination.GLOBAL_PENDING)
                if type(result) is not tuple or len(result) != 2 or \
                        type(result[0]) is not int or type(result[1]) is not int or result != (0, 0):
                    _fail('clear_unknown')
                self._terminal_absence()
                self._now()
                if self._io.fsync(self._parent) is not None: _fail('clear_unknown')
                self._now(); self._terminal_unlinked_readback()
                self._terminal_canonical_readback(exact_terminal_canonical)
                self._clear_durability, self._clear_reason = 'verified', 'not_recorded'
            except BaseException as error:
                self._clear_reason = error.code if type(error) is PendingError else 'clear_not_authorized' \
                    if not self._clear_sealed else 'clear_unknown'
                if self._clear_attempted:
                    # Only passive observation; never retry unlink/fsync/close.
                    try: self._terminal_error_observation()
                    except BaseException: self._state = 'unknown'
                else:
                    self._state = 'unknown'  # Precheck failure is not retained proof.
                if not isinstance(error, Exception): raise
            finally:
                self._clear_sealed = True
                self._deadline, self._last_clock = saved[0]
                c._deadline, c._last_clock = saved[1]
                jf._deadline, jf._last_clock = saved[2]
                exact_store._io_deadline = saved[3]
            return self.clear_status()

    def clear_status(self):
        """Passive fixed facts only; absent/durable never imply FD closure."""
        with self._operation():
            return {'marker_state': self._state, 'clear_durability': self._clear_durability,
                'clear_attempted': self._clear_attempted, 'reason': self._clear_reason,
                'resource_pending': self._resource_pending or bool(self._ticket is not None and
                    self._ticket.opening_unknown)}

    def close(self):
        """Seal forever. Close our original FD once; never unlink the marker."""
        with self._operation():
            self._ended = True
            if self._binding_ticket is not None:
                self._binding_ticket.ready, self._binding_ticket.unknown = False, True
            ticket = self._ticket
            if ticket is not None and not ticket.closed and not ticket.attempted:
                if ticket.opening_unknown or type(ticket.fd) is not int:
                    self._resource_pending = True
                else:
                    ticket.attempted = True
                    returned = False
                    try:
                        returned = ticket.io.close(ticket.fd) is None
                    except BaseException:
                        self._resource_pending = True
                    try:
                        ticket.io.fstat(ticket.fd)
                    except OSError as error:
                        if returned and type(error.errno) is int and error.errno == errno.EBADF:
                            ticket.closed = True
                    except BaseException:
                        pass
                    if not ticket.closed:
                        self._resource_pending = True
            return self._observation(False)

    def status(self):
        with self._operation():
            return {'evidence': 'CLIENT_PENDING_FILE_ONLY', 'creation_attempted': self._attempted,
                    'marker_state': self._state, 'durable_created': self._durable,
                    'creation_unknown': self._creation_unknown, 'resource_pending': self._resource_pending,
                    'closed': self._ended, 'reason': self._reason, 'manifest_authenticated': False,
                    'same_ofd_verified': False, 'marker_clear_implemented': True,
                    'local_binding_attempted': self._binding_attempted,
                    'local_binding_issued': bool(not self._clear_sealed and self._binding_ticket is not None and self._binding_ticket.ready and
                        (self._binding_ticket.handoff is None or self._binding_ticket.handoff.stage == 'active')),
                    'own_marker_admission': False, 'full_store_implemented': False,
                    'send_available': False, 'receive_available': False}
