"""Preparation plus real local durable journal/marker lifecycle.

The preserved ClientPreparationStore only publishes an empty journal's first
prepared checkpoint; it has no pending writer/clear, finish or inheritance.
The added DurableClientInitStore does not supply an actual RF Provider or
default admission/restoration producers. No production gate is opened.
"""
import errno
import math
import threading
import time

import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_journal_codec as codec
import mta_p2p_client_init as core


_HEX = frozenset('0123456789abcdef')
_CODES = frozenset(('invalid_config', 'invalid_session', 'already_attempted',
    'not_open', 'resource_pending', 'invalid_clock', 'clock_regressed', 'expired',
    'invalid_baseline', 'invalid_deadline', 'prepare_already_attempted',
    'current_exists', 'readback_changed', 'component_error', 'close_unknown',
    'operation_interrupted'))


class PreparationError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'component_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise PreparationError(code) from None


def _uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


class _Private(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable preparation observation')

    def __repr__(self):
        return '<CLIENT private preparation observation>'

    __str__ = __repr__


class PreparationSession(_Private):
    """Instance-exact transaction identity, not a run/manifest/Executor grant."""
    __slots__ = ('_issuer', '_generation')

    def __init__(self, issuer, generation):
        object.__setattr__(self, '_issuer', issuer)
        object.__setattr__(self, '_generation', generation)


class PreparedFileReceipt(_Private):
    __slots__ = ('journal', 'canonical', '_issuer', '_session')

    def __init__(self, journal, canonical, issuer, session):
        for key, value in (('journal', journal), ('canonical', canonical),
                           ('_issuer', issuer), ('_session', session)):
            object.__setattr__(self, key, value)


class PreparationCloseObservation(_Private):
    """This owner's local file resources ONLY, never core.CloseProof/finish."""
    __slots__ = ('_issuer', 'scope_attempted', 'files_closed', 'coordination_closed',
                 'resource_pending', 'write_pending', 'published_unknown', 'checkpoint_unverified')

    def __init__(self, issuer, scope_attempted, files_closed, coordination_closed,
                 resource_pending, write_pending, published_unknown, checkpoint_unverified):
        for key, value in (('_issuer', issuer), ('scope_attempted', scope_attempted),
                           ('files_closed', files_closed), ('coordination_closed', coordination_closed),
                           ('resource_pending', resource_pending), ('write_pending', write_pending),
                           ('published_unknown', published_unknown), ('checkpoint_unverified', checkpoint_unverified)):
            object.__setattr__(self, key, value)

    def complete(self):
        return bool(self.scope_attempted and self.files_closed and self.coordination_closed and
                    not self.resource_pending and not self.write_pending and not self.published_unknown and
                    not self.checkpoint_unverified)


class ClientPreparationStore(object):
    """One real synchronous preparation lifetime in an already-reviewed run.

    Whole-method RLock serializes the two owned components together. Neither
    component is exposed to IPC or external concurrent closers. _io seams are
    trusted HOST/internal only; default objects execute their actual Linux I/O.
    No ClientInitStore subclass: partial preparation cannot enter lease.start.
    """
    def __init__(self, run_token, identity, timeout=3.0, _coordination_io=None,
                 _files_io=None, _clock=None):
        if type(run_token) is not str or len(run_token) != 32 or any(c not in _HEX for c in run_token) or \
                type(identity) is not core.Identity or type(timeout) not in (int, float) or \
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or \
                (_clock is not None and not callable(_clock)):
            _fail('invalid_config')
        self._identity, self._timeout = identity, float(timeout)
        self._clock, self._mutex, self._issuer = _clock or time.monotonic, threading.RLock(), object()
        self._deadline, self._last_time, self._expired = None, None, False
        self._coordination = coordination.ClientCoordination(run_token, identity, timeout,
            _io=_coordination_io, _clock=self._component_clock)
        self._files = files.ClientJournalFiles(run_token, identity, timeout,
            _io=_files_io, _clock=self._component_clock)
        self._session, self._locks, self._receipt, self._committed_candidate = None, None, None, None
        self._attempted, self._opened, self._ended = False, False, False
        self._prepare_attempted, self._close_attempted, self._close_unknown = False, False, False
        self._commit_attempted = False
        self._write_pending, self._published_unknown = False, False
        self._close_receipt = None
        self._phase, self._reason = 'new', 'not_recorded'

    def _now(self):
        try: value = self._clock()
        except Exception: _fail('invalid_clock')
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_time is not None and value < self._last_time: _fail('clock_regressed')
        self._last_time = value
        return value

    def _component_clock(self):
        value = self._now()
        if self._deadline is None: _fail('not_open')
        if value >= self._deadline:
            self._expired = True
            _fail('expired')
        return value  # Real clock value; do not fabricate time to fit a budget.

    def _begin(self, journal_deadline=None):
        self._expired = False
        self._deadline = None
        now = self._now()
        if journal_deadline is not None:
            if type(journal_deadline) not in (int, float) or not 0 <= journal_deadline < 1e12 or \
                    not math.isfinite(float(journal_deadline)) or not 0 < journal_deadline - now <= 20:
                _fail('invalid_deadline')
        self._deadline = min(now + self._timeout, float(journal_deadline)) if journal_deadline is not None else now + self._timeout

    def _owned(self, session):
        if type(session) is not PreparationSession or session is not self._session or session._issuer is not self._issuer:
            _fail('invalid_session')
        if not self._opened or self._ended: _fail('not_open')
        if self._close_unknown: _fail('resource_pending')

    def _check(self):
        self._component_clock()

    def _validate(self):
        self._check()
        if self._coordination.validate(self._locks) is not True: _fail('component_error')
        self._check()

    def _record_error(self, error):
        self._reason = 'expired' if self._expired else (error.code if type(error) is PreparationError else
            ('component_error' if isinstance(error, Exception) else 'operation_interrupted'))
        self._phase = 'error'

    def _raise_reported(self, error):
        if isinstance(error, Exception): _fail(self._reason)
        raise error

    def open(self):
        with self._mutex:
            if self._attempted or self._ended: _fail('already_attempted')
            self._attempted, self._phase = True, 'opening'
            self._session = PreparationSession(self._issuer, 1)  # Before component operations.
            try:
                self._begin()
                self._locks = self._coordination.acquire()
                self._check()
                self._files.open()
                self._validate()
                self._opened, self._phase = True, 'opened'
                return self._session
            except BaseException as error:
                self._record_error(error)
                try: self.close()
                finally: self._raise_reported(error)

    def current(self, session):
        with self._mutex:
            self._owned(session)
            try:
                self._begin(); self._phase = 'reading'
                self._validate()
                result = self._files.read_current()
                self._validate()
                self._phase = 'prepared' if self._receipt is not None else 'opened'
                return result  # Private data only; an old ready value is not current RF readiness.
            except BaseException as error:
                self._record_error(error)
                try: self.close(session)
                finally: self._raise_reported(error)

    def prepare_initial(self, session, baseline, deadline):
        with self._mutex:
            self._owned(session)
            if type(baseline) is not core.Snapshot: _fail('invalid_baseline')
            if type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or not math.isfinite(float(deadline)):
                _fail('invalid_deadline')
            if self._prepare_attempted: _fail('prepare_already_attempted')
            self._prepare_attempted, self._phase = True, 'preparing'
            try:
                self._begin(deadline)
                record = core.Journal(self._identity, 'prepared', baseline, deadline)
                self._validate()
                if self._files.read_current() is not None: _fail('current_exists')
                self._validate()
                self._commit_attempted = True  # Not proof that rename occurred; preserve the uncertainty.
                committed = self._files.commit(None, record)  # Actual empty-current CAS and publication.
                self._committed_candidate = committed  # Preserve successful file publication before postchecks.
                self._validate()
                readback = self._files.read_current()
                self._validate()
                if type(committed) is not files.CanonicalRecord or type(readback) is not files.CanonicalRecord or \
                        committed.metadata != readback.metadata or committed.data != readback.data or \
                        committed.journal.key() != record.key() or readback.journal.key() != record.key():
                    _fail('readback_changed')
                result = PreparedFileReceipt(readback.journal, readback, self._issuer, session)
                self._receipt, self._phase, self._reason = result, 'prepared', 'not_recorded'
                return result
            except BaseException as error:
                self._record_error(error)
                try: self.close(session)
                finally: self._raise_reported(error)

    def _files_closed(self):
        """Fresh fstat original FILES tickets; no additional close/open/claim."""
        inventory = self._files._inventory  # Exact fixed component owned by this transaction.
        if type(inventory) is not list or len(inventory) > files.MAX_RESOURCES: return False
        for ticket in inventory:
            self._check()
            if ticket.io is not self._files._io or type(ticket.opening_unknown) is not bool or \
                    type(ticket.attempted) is not bool or type(ticket.closed) is not bool or \
                    ticket.opening_unknown or not ticket.closed:
                return False
            if ticket.fd is None:
                if ticket.attempted: return False
                continue  # Positive direct-open negative-result record, not an unknown creation.
            if not _uint(ticket.fd, 0x7fffffff) or not ticket.attempted: return False
            try: ticket.io.fstat(ticket.fd)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.EBADF: continue
            except BaseException:
                pass
            return False
        return True

    def _observe_close(self):
        file_closed, lock_closed = False, False
        write_pending, published_unknown, pending = True, True, self._close_unknown
        try:
            self._begin()
            file_closed = self._files_closed()
            state = self._files.status()
            if type(state) is not dict or any(type(state.get(key)) is not bool for key in
                    ('resource_pending', 'write_pending', 'published_unknown', 'all_owned_fds_closed')):
                _fail('close_unknown')
            pending = pending or state['resource_pending'] or not file_closed or not state['all_owned_fds_closed']
            write_pending, published_unknown = state['write_pending'], state['published_unknown']
            observed = self._coordination.read_closed(self._locks)
            if type(observed) is not coordination.ClosedObservation or observed._issuer is not self._coordination._issuer or \
                    type(observed.observed) is not tuple or any(type(v) is not bool for v in observed.observed) or \
                    len(observed.observed) != len(self._coordination._inventory) or \
                    type(observed.resource_pending) is not bool or not _uint(observed.unreturned_open_count, coordination.MAX_RESOURCES):
                _fail('close_unknown')
            lock_closed = observed.complete()
            pending = pending or observed.resource_pending or not lock_closed
        except BaseException:
            pending = True
        if pending: self._close_unknown = True
        self._write_pending, self._published_unknown = write_pending, published_unknown
        return PreparationCloseObservation(self._issuer, self._attempted, file_closed, lock_closed,
            pending, write_pending, published_unknown, self._commit_attempted and self._receipt is None)

    def close(self, session=None):
        with self._mutex:
            if session is not None and (type(session) is not PreparationSession or session is not self._session or
                    session._issuer is not self._issuer): _fail('invalid_session')
            self._ended, self._opened = True, False
            if not self._close_attempted:
                self._close_attempted = True
                # No audit allocation/clock/status call may precede attempts.
                # Each component closes independently even after BaseException.
                try: self._files.close()
                except BaseException: self._close_unknown = True
                finally:
                    try: self._coordination.close()
                    except BaseException: self._close_unknown = True
            try:
                self._close_receipt = self._observe_close()
            except BaseException:
                self._close_unknown = True
                raise
            self._phase = 'close_unknown' if self._close_unknown else 'closed'
            return self._close_receipt

    def status(self):
        with self._mutex:
            return {'evidence': 'CLIENT_PREPARATION_STORE_ONLY', 'phase': self._phase, 'reason': self._reason,
                'opened': self._opened, 'prepare_attempted': self._prepare_attempted,
                'prepared_checkpoint': self._receipt is not None,
                'close_attempted': self._close_attempted, 'resource_pending': self._close_unknown,
                'write_pending': self._write_pending, 'published_unknown': self._published_unknown,
                'checkpoint_unverified': self._commit_attempted and self._receipt is None,
                'baseline_authenticated': False, 'executor_verified': False, 'same_ofd_verified': False,
                'pending_modified': False, 'rf_admission': False, 'full_store_implemented': False,
                'receive_available': False, 'send_available': False}


_DURABLE_CODES = frozenset(('invalid_config', 'invalid_clock', 'clock_regressed',
    'invalid_deadline', 'expired', 'invalid_identity', 'invalid_locks', 'already_attempted',
    'not_open', 'sealed', 'resource_pending', 'current_exists', 'stale_current',
    'invalid_record', 'invalid_transition', 'marker_unverified', 'readback_changed',
    'producer_unavailable', 'producer_unknown', 'baseline_changed', 'finish_unknown',
    'component_error', 'operation_interrupted'))


class DurableStoreError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _DURABLE_CODES else 'component_error'
        ValueError.__init__(self, self.code)


def _durable_fail(code):
    raise DurableStoreError(code) from None


def _same_baseline(left, right):
    return type(left) is core.Snapshot and type(right) is core.Snapshot and left.key() == right.key() and \
        tuple(a.tasks for a in left.stock_actors) == tuple(a.tasks for a in right.stock_actors)


_NEXT_STAGES = {
    'prepared': ('watchdog_intent', 'cleanup_intent'),
    'watchdog_intent': ('watchdog_saved', 'cleanup_intent'),
    'watchdog_saved': ('interface_intent', 'cleanup_intent'),
    'interface_intent': ('interface_owned', 'cleanup_intent'),
    'interface_owned': ('controller_intent', 'cleanup_intent'),
    'controller_intent': ('controller_saved', 'cleanup_intent'),
    'controller_saved': ('client_init_ready', 'cleanup_intent'),
    'client_init_ready': ('cleanup_intent',),
    'cleanup_intent': ('cleanup_verified',),
    'cleanup_verified': (), 'reconciled': ()}


class DurableClientInitStore(core.ClientInitStore):
    """Actual local lock/journal/marker lifecycle, not a deployed RF provider.

    Pure ctor. Existing private directories must already be reviewed/created.
    All writers and components share this exact outer RLock. Trusted private
    producers supply ACTUAL historical admission/restoration observations; no
    default producer, external F, inherited executor or production gate exists.
    _restore_reader/_prior_reader are internal injection, NEVER HTTP options.
    """
    def __init__(self, run_token, identity, timeout=3.0, _coordination_io=None,
                 _files_io=None, _pending_io=None, _proc_reader=None, _clock=None,
                 _restore_reader=None, _prior_reader=None):
        if (type(run_token) is not str or len(run_token) != 32 or any(c not in _HEX for c in run_token) or
                type(identity) is not core.Identity or type(timeout) not in (int, float) or
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or
                (_clock is not None and not callable(_clock)) or
                (_restore_reader is not None and any(not callable(getattr(_restore_reader, name, None))
                    for name in ('read_restore', 'authenticate_restore'))) or
                (_prior_reader is not None and any(not callable(getattr(_prior_reader, name, None))
                    for name in ('read_prior', 'authenticate_prior')))):
            _durable_fail('invalid_config')
        self._identity, self._timeout = identity, float(timeout)
        self._mutex, self._epoch = threading.RLock(), object()
        self._clock, self._last_time, self._io_deadline = _clock or time.monotonic, None, None
        self._coordination = coordination.ClientCoordination(run_token, identity, timeout,
            _io=_coordination_io, _clock=self._component_clock, _serialization_lock=self._mutex)
        self._files = files.ClientJournalFiles(run_token, identity, timeout,
            _io=_files_io, _clock=self._component_clock, _serialization_lock=self._mutex)
        self._pending_io, self._proc_reader = _pending_io, _proc_reader
        self._restore_reader, self._prior_reader = _restore_reader, _prior_reader
        self._marker, self._binding, self._journal_epoch = None, None, None
        self._current_locks, self._canonical = None, None
        self._locksets, self._observations, self._records = [], [], []
        self._released, self._reacquired, self._candidate = None, None, None
        self._marker_observation, self._binding_observation = None, None
        self._restore_observations, self._prior_observations = [], []
        self._attempted, self._opened, self._unknown = False, False, False
        self._finish_sealed, self._finish_phase, self._finish_record = False, 'new', None
        self._finish_locks, self._terminal_canonical, self._finish_receipt = None, None, None
        self._clear_observation, self._close_attempted, self._close_unknown = None, False, False
        self._reason, self._restore_verified = 'not_recorded', False

    def _now(self):
        try: value = self._clock()
        except Exception: _durable_fail('invalid_clock')
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
            _durable_fail('invalid_clock')
        value = float(value)
        if self._last_time is not None and value < self._last_time: _durable_fail('clock_regressed')
        self._last_time = value
        return value

    def _begin_io(self, deadline=None):
        if deadline is not None and (type(deadline) not in (int, float) or
                not 0 <= deadline < 1e12 or not math.isfinite(float(deadline))):
            _durable_fail('invalid_deadline')
        self._io_deadline = None
        now = self._now()
        if deadline is not None and not 0 < deadline - now <= 20: _durable_fail('invalid_deadline')
        self._io_deadline = min(now + self._timeout, float(deadline)) if deadline is not None else now + self._timeout

    def _component_clock(self):
        now = self._now()
        if self._io_deadline is None: _durable_fail('not_open')
        if now >= self._io_deadline: _durable_fail('expired')
        return now

    def _identity_valid(self, identity):
        if type(identity) is not core.Identity or identity.key() != self._identity.key():
            _durable_fail('invalid_identity')

    def _owned(self, locks, allow_sealed=False):
        if (type(locks) is not coordination.LockSet or locks is not self._current_locks or
                not any(item is locks for item in self._locksets)):
            _durable_fail('invalid_locks')
        if self._finish_sealed and not allow_sealed: _durable_fail('sealed')
        if not self._opened: _durable_fail('not_open')
        if self._unknown: _durable_fail('resource_pending')
        if self._released is not None and self._reacquired is None:
            _durable_fail('invalid_locks')  # Known suspension must not poison the handoff.

    def _validate(self, locks, allow_sealed=False):
        self._owned(locks, allow_sealed)
        self._component_clock()
        if self._coordination.validate(locks) is not True: _durable_fail('component_error')
        if self._binding is not None:
            observed = self._binding.verify(self._files, self._epoch)
            self._binding_observation = observed
            if (type(observed) is not pending.PendingObservation or self._marker is None or
                    observed._issuer is not self._marker._issuer or observed.marker_state != 'retained_observed' or
                    observed.durable_created is not True or observed.owner_observed is not True or
                    observed.resource_pending is not False or observed.creation_unknown is not False or
                    self._journal_epoch is not self._marker._binding_ticket.journal_epoch):
                _durable_fail('marker_unverified')
        self._component_clock()

    def _canonical_valid(self, value, record):
        if (type(value) is not files.CanonicalRecord or value._issuer is not self._files._issuer or
                type(value._generation) is not int or value._generation != self._files._generation or
                type(value.data) is not bytes or type(value.metadata) is not tuple or len(value.metadata) != 9 or
                any(not _uint(v, (1 << 64) - 1) for v in value.metadata[:7]) or
                any(type(v) is not int or not -(1 << 63) <= v <= (1 << 63) - 1 for v in value.metadata[7:]) or
                not any(item is value for item in self._files._issued_canonicals) or
                value.data != codec.encode_journal(record) or not core._same_journal(value.journal, record)):
            _durable_fail('readback_changed')

    def _read_exact(self):
        actual = self._files.read_current()
        self._observations.append(actual)  # Exact returned reference before any postcheck.
        if self._canonical is None:
            if actual is not None: _durable_fail('current_exists')
        else:
            self._canonical_valid(self._canonical, self._canonical.journal)
            self._canonical_valid(actual, self._canonical.journal)
            if actual.metadata != self._canonical.metadata or actual.data != self._canonical.data:
                _durable_fail('stale_current')
        return actual

    def _report(self, error):
        self._unknown = True
        self._reason = error.code if type(error) is DurableStoreError else \
            ('component_error' if isinstance(error, Exception) else 'operation_interrupted')
        if isinstance(error, Exception): _durable_fail(self._reason)
        raise error

    def acquire(self, identity, deadline, inherited=None):
        with self._mutex:
            self._identity_valid(identity)
            if self._finish_sealed: _durable_fail('sealed')
            if self._unknown: _durable_fail('resource_pending')
            self._begin_io(deadline)
            if self._attempted:
                if (inherited is not self._current_locks or self._released is None or
                        self._reacquired is not None or not self._opened):
                    _durable_fail('already_attempted')
                try:
                    result = self._coordination.reacquire_journal(self._released, self._io_deadline)
                    self._reacquired = result
                    if (type(result) is not coordination.ReacquiredJournal or
                            result is not self._coordination._handoff.reacquired or
                            result._issuer is not self._coordination._issuer or
                            result.locks is not self._coordination._locks): _durable_fail('invalid_locks')
                    self._current_locks = result.locks
                    self._locksets.append(result.locks)
                    self._journal_epoch = self._marker._binding_ticket.journal_epoch
                    self._validate(result.locks)
                    self._read_exact()  # FIRST current load only after actual new journal lock.
                    self._component_clock()
                    return result.locks
                except BaseException as error: self._report(error)
            if inherited is not None: _durable_fail('invalid_locks')
            self._attempted = True
            try:
                locks = self._coordination.acquire()
                self._current_locks = locks
                self._locksets.append(locks)
                if type(locks) is not coordination.LockSet: _durable_fail('invalid_locks')
                self._files.open()
                self._opened = True
                self._validate(locks)
                self._read_exact()
                return locks
            except BaseException as error:
                try: self._report(error)
                finally: self._close_components()

    def lock_valid(self, locks):
        with self._mutex:
            self._owned(locks)
            self._begin_io()
            try: self._validate(locks); return True
            except BaseException as error: self._report(error)

    def current(self, locks):
        with self._mutex:
            self._owned(locks); self._begin_io()
            try:
                self._validate(locks)
                actual = self._read_exact()
                self._validate(locks)
                if actual is None: return None
                self._canonical = actual
                self._records.append(actual.journal)
                return actual.journal
            except BaseException as error: self._report(error)

    def pending_clear(self, locks):
        with self._mutex:
            self._owned(locks); self._begin_io()
            self._validate(locks)
            observed = self._coordination.read_pending(locks)
            return self._binding is None and type(observed) is dict and observed.get('entry_absent_observed') is True

    def prior_clear(self, locks, baseline, deadline):
        with self._mutex:
            self._owned(locks); self._begin_io(deadline); self._validate(locks)
            if type(baseline) is not core.Snapshot: _durable_fail('invalid_record')
            if self._prior_reader is None: return False
            value = self._prior_reader.read_prior(self, locks, baseline, self._io_deadline)
            self._prior_observations.append(value)
            if type(value) is not core.Snapshot or not _same_baseline(value, baseline):
                _durable_fail('producer_unknown')
            if self._prior_reader.authenticate_prior(self, locks, baseline, value, self._io_deadline) is not None:
                _durable_fail('producer_unknown')
            self._validate(locks)
            return True

    def pending_matches(self, locks, record):
        with self._mutex:
            self._owned(locks); self._begin_io(); self._validate(locks)
            if self._binding is None or type(record) is not core.Journal: return False
            actual = self._read_exact()
            return actual is not None and core._same_journal(actual.journal, record)

    def _transition(self, record):
        if type(record) is not core.Journal or record.identity.key() != self._identity.key():
            _durable_fail('invalid_record')
        if self._canonical is None:
            if record.stage != 'prepared' or record.ready or any(getattr(record, key) is not None for key in
                    ('owned', 'interface_ticket', 'controller_ticket', 'controller', 'watchdog_ticket', 'watchdog')):
                _durable_fail('invalid_transition')
            if not 0 < record.deadline - self._now() <= 20: _durable_fail('invalid_deadline')
            return
        old = self._canonical.journal
        if not _same_baseline(record.baseline, old.baseline) or record.deadline != old.deadline or \
                record.stage != old.stage and record.stage not in _NEXT_STAGES.get(old.stage, ()):
            _durable_fail('invalid_transition')
        if record.stage == old.stage and not core._same_journal(record, old): _durable_fail('invalid_transition')
        for key in ('owned', 'interface_ticket', 'controller_ticket', 'controller', 'watchdog_ticket', 'watchdog'):
            previous, value = getattr(old, key), getattr(record, key)
            if previous is not None and (value is None or value.key() != previous.key() or
                    key in ('controller', 'watchdog') and value.tasks != previous.tasks):
                _durable_fail('invalid_transition')
        if record.stage == 'reconciled': _durable_fail('sealed')

    def _publish(self, locks, record, terminal=False):
        self._validate(locks, terminal)
        self._read_exact()
        returned = self._files.commit(self._canonical, record)
        self._candidate = returned  # Never lose a successful/unknown returned publication.
        self._canonical_valid(returned, record)
        self._canonical = returned
        self._validate(locks, terminal)
        actual = self._read_exact()
        self._canonical = actual
        self._records.append(actual.journal)
        self._component_clock()
        return actual.journal

    def commit(self, locks, record):
        with self._mutex:
            self._owned(locks); self._begin_io(); self._transition(record)
            try:
                result = self._publish(locks, record)
                if self._marker is None:
                    marker = pending.ClientPendingMarker(self._coordination, locks, self._timeout,
                        _io=self._pending_io, _reader=self._proc_reader, _clock=self._component_clock,
                        _serialization_lock=self._mutex)
                    self._marker = marker
                    observed = marker.create()
                    self._marker_observation = observed
                    if (type(observed) is not pending.PendingObservation or observed._issuer is not marker._issuer or
                            observed.marker_state != 'retained_observed' or observed.durable_created is not True or
                            observed.owner_observed is not True or observed.resource_pending is not False or
                            observed.creation_unknown is not False): _durable_fail('marker_unverified')
                    binding = marker.bind_files(self._files, self._canonical, self._epoch, self._mutex)
                    self._binding = binding
                    if type(binding) is not pending.OwnedMarkerBinding: _durable_fail('marker_unverified')
                    self._journal_epoch = marker._binding_ticket.journal_epoch
                    self._validate(locks)
                    self._read_exact()
                return result
            except BaseException as error: self._report(error)

    def active_return(self, locks, record):
        with self._mutex:
            self._owned(locks); self._begin_io(); self._validate(locks)
            if self._binding is None or not core._same_journal(self._read_exact().journal, record):
                _durable_fail('invalid_record')
            if self._released is not None: _durable_fail('already_attempted')
            try:
                result = self._coordination.release_journal_handoff(locks, self._binding, self._epoch, self._io_deadline)
                self._released = result
                if (type(result) is not coordination.ReleasedJournal or result is not self._coordination._handoff.released or
                        result._issuer is not self._coordination._issuer): _durable_fail('invalid_locks')
                ticket = locks._journal
                closed = self._fd_closed(ticket)
                return core.CloseProof(1, (ticket.attempted,), (closed,))
            except BaseException as error: self._report(error)

    def _fresh_restore(self, locks, request):
        if self._restore_reader is None: _durable_fail('producer_unavailable')
        value = self._restore_reader.read_restore(self, locks, request, self._io_deadline)
        reused = any(value is previous or type(value) is tuple and len(value) == 2 and
            (value[0] is previous[0] or value[1] is previous[1])
            for previous in self._restore_observations if type(previous) is tuple and len(previous) == 2)
        self._restore_observations.append(value)
        self._component_clock()
        if (reused or type(value) is not tuple or len(value) != 2 or
                type(value[0]) is not core.Snapshot or not _same_baseline(value[0], request.baseline) or
                type(value[1]) is not core.CloseProof or not value[1].complete() or
                value[1].expected < sum(getattr(request, key) is not None for key in ('controller_ticket', 'watchdog_ticket'))):
            _durable_fail('producer_unknown')
        if self._restore_reader.authenticate_restore(self, locks, request, value, self._io_deadline) is not None:
            _durable_fail('producer_unknown')
        self._component_clock()
        self._restore_verified = True

    def _authorize_terminal_clear(self, marker, binding, canonical, deadline):
        """Private Pending callback; normal None means this actual check ran."""
        with self._mutex:
            if (not self._finish_sealed or self._finish_phase != 'terminal_durable' or
                    marker is not self._marker or binding is not self._binding or
                    canonical is not self._terminal_canonical or canonical is not self._canonical or
                    self._finish_locks is not self._current_locks or
                    self._journal_epoch is not marker._binding_ticket.journal_epoch or self._unknown):
                _durable_fail('finish_unknown')
            if type(deadline) not in (int, float) or deadline != self._io_deadline:
                _durable_fail('invalid_deadline')
            self._validate(self._current_locks, True)
            self._canonical_valid(canonical, canonical.journal)
            actual = self._read_exact()
            if not core._same_journal(actual.journal, canonical.journal): _durable_fail('readback_changed')
            self._fresh_restore(self._current_locks, self._finish_record)
            self._validate(self._current_locks, True)
            return None

    def _fd_closed(self, ticket):
        if (any(type(getattr(ticket, name, None)) is not bool for name in ('opening_unknown', 'closed', 'attempted')) or
                ticket.opening_unknown or not ticket.closed): return False
        if ticket.fd is None: return not ticket.attempted
        if not _uint(ticket.fd, 0x7fffffff) or not ticket.attempted: return False
        try: ticket.io.fstat(ticket.fd)
        except OSError as error: return type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: return False
        return False

    def _close_components(self):
        self._opened = False
        if self._close_attempted: return
        self._close_attempted = True
        # No clock/audit/result allocation precedes these independent attempts.
        try:
            if self._marker is not None: self._marker.close()
        except BaseException: self._close_unknown = True
        finally:
            try: self._files.close()
            except BaseException: self._close_unknown = True
            finally:
                try: self._coordination.close_device_last()
                except BaseException: self._close_unknown = True

    def _inventory_closed(self):
        self._component_clock()
        if self._close_unknown: return False
        inventories = (self._coordination._inventory, self._files._inventory)
        if any(type(items) is not list for items in inventories): return False
        if len(inventories[0]) > coordination.MAX_RESOURCES + 1 or len(inventories[1]) > files.MAX_RESOURCES:
            return False
        for items in inventories:
            for ticket in items:
                self._component_clock()
                if not self._fd_closed(ticket): return False
        if self._marker is not None:
            if self._marker._ticket is None or not self._fd_closed(self._marker._ticket): return False
            if self._marker._resource_pending or self._marker._creation_unknown: return False
        if self._coordination.status()['resource_pending'] or self._coordination.status()['lock_unknown'] or \
                self._files._resource_pending: return False
        return not self._unknown  # Sticky failed operation cannot be erased by later EBADF.

    def _retained_marker(self):
        if self._marker is None:
            if not self._coordination._anchors: return 'unknown'
            try: self._coordination._io.stat_at(self._coordination._anchors[1][0].fd, coordination.GLOBAL_PENDING)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.ENOENT: return 'absent_observed'
            return 'unknown'
        try:
            value = self._marker.verify()
            self._marker_observation = value
            if type(value) is pending.PendingObservation and value.marker_state == 'retained_observed':
                return 'retained_observed'
        except BaseException: pass
        return 'unknown'

    def finish(self, locks, record, normal_restored, deadline):
        with self._mutex:
            if self._finish_sealed: _durable_fail('sealed')
            if (locks is not self._current_locks or type(locks) is not coordination.LockSet or
                    not any(item is locks for item in self._locksets) or type(normal_restored) is not bool or
                    record is not None and (type(record) is not core.Journal or
                        not any(item is record for item in self._records) or self._canonical is None or
                        not core._same_journal(record, self._canonical.journal)) or
                    normal_restored and (record is None or record.ready or record.stage not in ('cleanup_verified', 'reconciled'))):
                _durable_fail('finish_unknown')
            self._finish_sealed, self._finish_record, self._finish_locks = True, record, locks
            self._finish_phase = 'sealed'
            final, terminal_durable = record, False
            marker_state, durability, resources_closed = 'unknown', 'not_attempted', False
            try:
                self._begin_io(deadline)
                marker_state = self._retained_marker()
                if normal_restored:
                    self._validate(locks, True)
                    self._fresh_restore(locks, record)
                    terminal = record.replace(stage='reconciled', ready=False)
                    final = self._publish(locks, terminal, True)
                    self._terminal_canonical = self._canonical
                    terminal_durable, self._finish_phase = True, 'terminal_durable'
                    self._fresh_restore(locks, record)
                    clear = self._marker.clear_terminal(self, self._binding, self._terminal_canonical, self._io_deadline)
                    self._clear_observation = clear
                    if (type(clear) is not dict or set(clear) != set(('marker_state', 'clear_durability',
                            'clear_attempted', 'reason', 'resource_pending')) or
                            type(clear['clear_attempted']) is not bool or type(clear['resource_pending']) is not bool or
                            type(clear['marker_state']) is not str or
                            clear['marker_state'] not in ('retained_observed', 'absent_observed', 'unknown') or
                            type(clear['clear_durability']) is not str or
                            clear['clear_durability'] not in ('not_attempted', 'verified', 'unknown') or
                            type(clear['reason']) is not str or clear['reason'] not in pending._CODES | frozenset(('not_recorded',))):
                        _durable_fail('finish_unknown')
                    marker_state, durability = clear['marker_state'], clear['clear_durability']
                    if clear['resource_pending']: self._close_unknown = True
                    self._finish_phase = 'marker_observed'
            except Exception as error:
                self._reason = error.code if type(error) is DurableStoreError else 'component_error'
                if self._clear_observation is None:
                    marker_state = self._retained_marker()
                self._restore_verified = False
            finally:
                try:
                    if self._clear_observation is None and self._marker is not None and self._marker._clear_requested:
                        # Even a non-returned clear keeps the actual component's
                        # passive physical facts; never infer retained on error.
                        self._clear_observation = self._marker.clear_status()
                        value = self._clear_observation
                        if (type(value) is dict and type(value.get('marker_state')) is str and
                                value['marker_state'] in ('retained_observed', 'absent_observed', 'unknown') and
                                type(value.get('clear_durability')) is str and
                                value['clear_durability'] in ('not_attempted', 'verified', 'unknown')):
                            marker_state, durability = value['marker_state'], value['clear_durability']
                finally:
                    self._close_components()
            try: resources_closed = self._inventory_closed()
            except BaseException: self._close_unknown = True
            resource_pending = not resources_closed
            complete = bool(normal_restored and terminal_durable and marker_state == 'absent_observed' and
                durability == 'verified' and resources_closed)
            result = core.FinishReceipt(self, locks, self._identity, record, final, normal_restored,
                terminal_durable, marker_state, durability, resources_closed, resource_pending, complete)
            self._finish_receipt = result
            self._finish_phase = 'finished' if complete else 'finish_incomplete'
            return result

    def authenticate_finish(self, locks, record, receipt, deadline):
        with self._mutex:
            if (type(receipt) is not core.FinishReceipt or receipt is not self._finish_receipt or
                    receipt.store is not self or locks is not self._finish_locks or receipt.locks is not locks or
                    record is not self._finish_record or receipt.request_record is not record or
                    not self._finish_sealed or not self._close_attempted or
                    receipt.identity.key() != self._identity.key()): return False
            self._begin_io(deadline)
            actual = self._inventory_closed()
            return actual == receipt.resources_closed and receipt.resource_pending is (not actual)

    def closed_locks(self, locks, deadline):
        with self._mutex:
            if type(locks) is not coordination.LockSet or not any(item is locks for item in self._locksets):
                _durable_fail('invalid_locks')
            self._begin_io(deadline)
            current = self._current_locks
            if type(current) is not coordination.LockSet: _durable_fail('invalid_locks')
            device, journal = current._device, current._journal
            return core.CloseProof(2, (device.attempted, journal.attempted),
                (self._fd_closed(device), self._fd_closed(journal)))

    def close(self):
        """Emergency local FD closure ONLY; retain marker, no finish/recovery."""
        with self._mutex:
            self._finish_sealed = True
            self._close_components()
            self._finish_phase = 'closed_without_finish' if self._finish_receipt is None else self._finish_phase
            return self.status()

    def status(self):
        with self._mutex:
            return {'evidence': 'CLIENT_DURABLE_FILES_ONLY', 'opened': self._opened,
                'finish_sealed': self._finish_sealed, 'phase': self._finish_phase, 'reason': self._reason,
                'resource_pending': self._unknown or self._close_unknown or self._files._resource_pending or
                    self._coordination.status()['resource_pending'] or
                    bool(self._marker is not None and (self._marker._resource_pending or self._marker._creation_unknown)),
                'prepared_checkpoint': self._canonical is not None, 'restore_observed': self._restore_verified,
                'close_attempted': self._close_attempted, 'finish_issued': self._finish_receipt is not None,
                'production_provider': False, 'baseline_authenticated': False, 'executor_verified': False,
                'same_ofd_verified': False, 'send_available': False, 'receive_available': False}
