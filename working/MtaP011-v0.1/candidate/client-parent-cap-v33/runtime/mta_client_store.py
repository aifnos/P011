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
import mta_client_resource_budget as resources
import mta_client_proc as proc


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
                record = core.Journal(self._identity, 'prepared', baseline, deadline,
                    session_profile=core.TRIAL_SESSION_PROFILE.name, issued_at=self._last_time)
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


def _same_live_baseline(left, right):
    """Fresh observations: stable identity/network plus all original actors live.

    Raw task states remain in each Snapshot and in persisted journal/CAS checks.
    This comparison is only for independently authenticated fresh producers.
    """
    return type(left) is core.Snapshot and type(right) is core.Snapshot and left.key() == right.key() and \
        all(type(actor) is core.Actor and actor.live() is True
            for actor in left.stock_actors + right.stock_actors)


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
                 _restore_reader=None, _prior_reader=None,
                 _session_profile=core.TRIAL_SESSION_PROFILE, _parent_until_v33=None):
        if (type(run_token) is not str or len(run_token) != 32 or any(c not in _HEX for c in run_token) or
                type(identity) is not core.Identity or type(timeout) not in (int, float) or
                not 0.1 <= timeout <= 10 or not math.isfinite(float(timeout)) or
                (_session_profile is not core.TRIAL_SESSION_PROFILE and
                    _session_profile is not core.FORMAL_SESSION_PROFILE) or
                (_clock is not None and not callable(_clock)) or
                (_restore_reader is not None and any(not callable(getattr(_restore_reader, name, None))
                    for name in ('read_restore', 'authenticate_restore'))) or
                (_prior_reader is not None and any(not callable(getattr(_prior_reader, name, None))
                    for name in ('read_prior', 'authenticate_prior')))):
            _durable_fail('invalid_config')
        self._identity, self._timeout = identity, float(timeout)
        self._run_token = run_token  # Exact private Store run, never a caller's association grant.
        self._mutex, self._epoch = threading.RLock(), object()
        self._resource_lane_v23 = resources.PREPARATION_NETWORK
        # Pure fixed internal selection precedes every component and first IO.
        self._session_profile = self._session_profile_original_v28 = _session_profile
        # Native entry data only. The complete future Parent/F/Provider path
        # must establish the actual original Handoff cap before construction.
        # This numeric tightening never authenticates that entry by itself.
        try: parent_until = core._parent_until_v33(_session_profile, _parent_until_v33)
        except core.ClientInitError: _durable_fail('invalid_config')
        self._parent_until_v33 = self._parent_until_original_v33 = parent_until
        self._session_issued_v28 = None  # Original issuance facts retained before publication.
        self._resource_budget_v23 = None
        profile = (resources.SOURCE_PROFILE if _session_profile is core.TRIAL_SESSION_PROFILE
            else resources.FORMAL_PROFILE)
        resources.ResourceBudget(self, profile)
        self._clock, self._last_time, self._io_deadline = _clock or time.monotonic, None, None
        self._coordination = coordination.ClientCoordination(run_token, identity, timeout,
            _io=_coordination_io, _clock=self._component_clock, _serialization_lock=self._mutex)
        self._files = files.ClientJournalFiles(run_token, identity, timeout,
            _io=_files_io, _clock=self._component_clock, _serialization_lock=self._mutex,
            _resource_budget=self._resource_budget_v23)
        self._pending_io = _pending_io
        self._proc_reader = _proc_reader if _proc_reader is not None else proc.ProcReader(
            timeout=self._timeout, _clock=self._component_clock)
        self._proc_reader_original_v24 = self._proc_reader
        # Bind the actual reusable marker reader before its first read. The
        # accounting issuer is this original Store, not a journal generation.
        self._resource_budget_v23.bind_reader(self._proc_reader)
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
        self._finish_deadline = None  # Recovery total, never the RF Journal deadline.
        self._recovery_deadline = None  # Only the exact Lease's serialized restore call.

    def _now(self):
        try: value = self._clock()
        except Exception: _durable_fail('invalid_clock')
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
            _durable_fail('invalid_clock')
        value = float(value)
        if self._last_time is not None and value < self._last_time: _durable_fail('clock_regressed')
        self._last_time = value
        return value

    def _session_context_v28(self):
        self._resource_budget_v23._context()
        selected = self._session_profile_original_v28
        if (self._session_profile is not selected or selected is not core.TRIAL_SESSION_PROFILE and
                selected is not core.FORMAL_SESSION_PROFILE): _durable_fail('invalid_config')
        until = self._parent_until_original_v33
        if self._parent_until_v33 is not until: _durable_fail('invalid_config')
        try:
            if core._parent_until_v33(selected, until) != until: _durable_fail('invalid_config')
        except core.ClientInitError: _durable_fail('invalid_config')
        return selected

    def parent_until_v33(self, profile):
        """Pure retained entry cap; no clock, IO, renewal or authority."""
        selected = self._session_context_v28()
        if profile is not selected: _durable_fail('invalid_config')
        return self._parent_until_original_v33

    def _parent_issuance_v33(self, record, profile):
        """Check tightening without changing the four original issuance facts."""
        until = self._parent_until_original_v33
        if until is None: return True # Unchanged standalone/trial publication bounds.
        try:return record.deadline == core._session_deadline_v33(profile, record.issued_at, until)
        except core.ClientInitError:return False

    def session_issued_v28(self, record, profile, deadline):
        """Pure original Store issuance/readback fact, never network authority.

        Native current() may return another decoded Journal, so identity is
        checked in this Store's retained producer inventory plus full current
        equality. An equal caller reconstruction is not an issued original.
        No clock, filesystem, close, IO slice or resource credit is created.
        """
        try:
            selected = self._session_context_v28()
            canonical, facts = self._canonical, self._session_issued_v28
            if (profile is not selected or type(record) is not core.Journal or
                    self._unknown or self._finish_sealed or
                    type(facts) is not tuple or len(facts) != 4 or facts[0] is not selected or
                    type(canonical) is not files.CanonicalRecord or
                    not any(original is record for original in self._records) or
                    not core._same_journal(record, canonical.journal) or
                    (record.session_profile, record.issued_at, record.deadline) != facts[1:] or
                    record.session_profile != selected.name or deadline != facts[3] or
                    not self._parent_issuance_v33(record, selected)):
                return False
            self._canonical_valid(canonical, canonical.journal)
            return True
        except BaseException:
            return False

    def _trusted_active_deadline_v28(self, deadline, now):
        """Only the actually published current Journal can supply a long cap.

        The returned original total is not a new IO slice, RF grant or lease.
        Caller-shaped numeric deadlines, wire profile names and old canonicals
        cannot select a longer session. Cleanup uses its independent short cap.
        """
        selected = self._session_context_v28()
        facts, canonical = self._session_issued_v28, self._canonical
        if (type(facts) is not tuple or len(facts) != 4 or facts[0] is not selected or
                type(canonical) is not files.CanonicalRecord): _durable_fail('invalid_deadline')
        record = canonical.journal
        if not self.session_issued_v28(record, selected, deadline): _durable_fail('invalid_deadline')
        if (record.session_profile != selected.name or record.session_profile != facts[1] or
                record.issued_at != facts[2] or record.deadline != facts[3] or
                deadline != facts[3] or not record.issued_at <= now < record.deadline):
            _durable_fail('invalid_deadline')
        return record.deadline

    def _peer_io_until_v29(self, deadline):
        """Clamp component/current/lock IO to the actual active peer read only."""
        budget = getattr(self, '_resource_budget_v23', None)
        provider = None if budget is None else budget._provider
        if provider is None: return float(deadline)
        import mta_client_linux_provider as linux
        if type(provider) is not linux.LinuxClientInitProvider or provider._store is not self:
            _durable_fail('invalid_owner')
        return linux.LinuxClientInitProvider._peer_io_until_v29(provider, deadline)

    def _begin_io(self, deadline=None):
        self._session_context_v28()
        if deadline is not None and (type(deadline) not in (int, float) or
                not 0 <= deadline < 1e12 or not math.isfinite(float(deadline))):
            _durable_fail('invalid_deadline')
        self._io_deadline = None
        now = self._now()
        if deadline is not None:
            if deadline <= now: _durable_fail('invalid_deadline')
            if deadline - now > core.PREPARATION_SECONDS:
                self._trusted_active_deadline_v28(deadline, now)
        end = min(now + self._timeout, float(deadline)) if deadline is not None else now + self._timeout
        self._io_deadline = self._peer_io_until_v29(end)
        if self._io_deadline <= now: _durable_fail('expired')
        if self._recovery_deadline is not None:
            if now >= self._recovery_deadline: _durable_fail('expired')
            self._io_deadline = min(self._io_deadline, self._recovery_deadline)

    def _budget_slice(self, deadline, seconds):
        """Short local slice under original cleanup or authenticated active cap."""
        if (type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or
                not math.isfinite(float(deadline))):
            _durable_fail('invalid_deadline')
        now = self._now()
        if (type(seconds) not in (int, float) or not 0 < seconds <= core.PREPARATION_SECONDS or
                not math.isfinite(float(seconds))): _durable_fail('invalid_deadline')
        if deadline <= now: _durable_fail('expired')
        if deadline - now > core.CLEANUP_SECONDS:
            self._trusted_active_deadline_v28(deadline, now)
        return self._peer_io_until_v29(min(float(deadline), now + seconds))

    def _begin_disk(self, deadline):
        self._begin_io(self._budget_slice(deadline, 20))
        # Component methods may establish their own short budget, but the exact
        # Store clock still caps the entire disk segment to _timeout.

    def _producer_context(self, deadline):
        end = self._budget_slice(deadline, 5)
        components = (self._coordination, self._files, self._marker)
        saved = (self._io_deadline, tuple(None if obj is None else obj._deadline for obj in components))
        self._io_deadline = end
        # The fresh read does not consume a previous disk deadline. Any nested
        # component operation still establishes its original short budget
        # beneath this actual five-second Store clock.
        for obj in components:
            if obj is not None: obj._deadline = None
        return end, saved

    def _end_producer(self, saved):
        self._io_deadline = saved[0]
        for obj, deadline in zip((self._coordination, self._files, self._marker), saved[1]):
            if obj is not None: obj._deadline = deadline

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
        # A before-create shortage is not evidence of an unknown FD. No write,
        # publication or genuinely unknown original may be washed clean.
        if type(error) is resources.ResourceBudgetError and error.code == 'safe_exhaustion' and \
                not self._files._resource_pending and not self._files._write_pending and \
                not self._files._published_unknown and not self._unknown:
            self._reason = 'resource_budget'
            raise error
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
            end, saved = self._producer_context(deadline)
            try:
                value = self._prior_reader.read_prior(self, locks, baseline, end)
                self._prior_observations.append(value)
                self._component_clock()
                if type(value) is not core.Snapshot or not _same_live_baseline(value, baseline):
                    _durable_fail('producer_unknown')
                if self._prior_reader.authenticate_prior(self, locks, baseline, value, end) is not None:
                    _durable_fail('producer_unknown')
                self._component_clock()
            finally: self._end_producer(saved)
            self._begin_disk(deadline)
            self._validate(locks)
            return True

    def pending_matches(self, locks, record):
        with self._mutex:
            self._owned(locks); self._begin_io(); self._validate(locks)
            if self._binding is None or type(record) is not core.Journal: return False
            actual = self._read_exact()
            return actual is not None and core._same_journal(actual.journal, record)

    def _association_transition(self, record, old):
        value, previous = record.association, old.association
        if value is not None:
            owner = None if self._marker is None else self._marker._owner
            if (value.binding['run_token'] != self._run_token or type(owner) is not core.Actor or
                    not owner.live() or not value.executor.live() or value.executor.key() != owner.key()):
                _durable_fail('invalid_transition')
        if previous is None:
            if value is None: return
            if record.stage != 'client_init_ready' or old.stage != record.stage or value.phase != 'intent':
                _durable_fail('invalid_transition')
        else:
            if value is None or value.binding != previous.binding or \
                    value.executor.key() != previous.executor.key() or value.executor.tasks != previous.executor.tasks:
                _durable_fail('invalid_transition')
            facts = lambda item: (item.local_mac, item.bssid, item.frequency, item.observed_digest)
            if value.phase == previous.phase:
                if value.key() != previous.key(): _durable_fail('invalid_transition')
                return
            if previous.phase == 'intent' and value.phase == 'confirmed':
                if old.stage != 'client_init_ready' or record.stage != old.stage:
                    _durable_fail('invalid_transition')
            elif previous.phase in ('intent', 'confirmed') and value.phase == 'invalidated':
                if facts(value) != facts(previous): _durable_fail('invalid_transition')
                return  # Revocation/cleanup remains possible after RF expiry.
            else: _durable_fail('invalid_transition')
        if record.deadline <= self._now(): _durable_fail('expired')

    def _client_ip_transition_v28(self, record, old):
        value, previous = record.client_ip, old.client_ip
        if value is None and previous is None: return
        import mta_client_dynamic_ip as dynamic
        if type(value) is not dynamic.DynamicIpRecord: _durable_fail('invalid_transition')
        if (type(record.owned) is not core.Origin or value.owned.key() != record.owned.key() or
                value.allocation_until > record.deadline): _durable_fail('invalid_transition')
        if previous is None:
            if (value.phase != 'intent' or record.stage != 'client_init_ready' or old.stage != record.stage or
                    record.ready is not True or old.ready is not True or
                    old.association is None or old.association.phase != 'confirmed' or
                    record.association is None or record.association.phase != 'confirmed'):
                _durable_fail('invalid_transition')
            if dynamic.snapshot_key(value.baseline) != dynamic.snapshot_key(old.baseline.ipv4):
                _durable_fail('baseline_changed')
        else:
            if (type(previous) is not dynamic.DynamicIpRecord or value.facts_key() != previous.facts_key()):
                _durable_fail('invalid_transition')
            if value.phase == previous.phase:
                if value.key() != previous.key(): _durable_fail('invalid_transition')
                return
            allowed = {'intent': ('applied', 'restored'), 'applied': ('delete_intent',),
                'delete_intent': ('restored',), 'restored': ()}
            if value.phase not in allowed[previous.phase]: _durable_fail('invalid_transition')
            if value.phase in ('delete_intent', 'restored'):
                # The original typed producer still must authorize mutation or
                # zero-mutation readback. A data record never grants deletion.
                if record.stage not in ('cleanup_intent', 'cleanup_verified'):
                    _durable_fail('invalid_transition')
                return
        if not self._now() < min(record.deadline, value.allocation_until): _durable_fail('expired')

    def _transition(self, record):
        selected = self._session_context_v28()
        if type(record) is not core.Journal or record.identity.key() != self._identity.key():
            _durable_fail('invalid_record')
        if self._canonical is None:
            if record.stage != 'prepared' or record.ready or any(getattr(record, key) is not None for key in
                    ('owned', 'interface_ticket', 'controller_ticket', 'controller', 'watchdog_ticket', 'watchdog', 'association', 'client_ip')):
                _durable_fail('invalid_transition')
            now = self._now()
            if (record.session_profile != selected.name or not record.issued_at <= now < record.deadline or
                    not 0 < record.deadline - record.issued_at <= selected.max_active_seconds or
                    not self._parent_issuance_v33(record, selected)):
                _durable_fail('invalid_deadline')
            facts = (selected, record.session_profile, record.issued_at, record.deadline)
            if self._session_issued_v28 is not None and self._session_issued_v28 != facts:
                _durable_fail('invalid_transition')
            self._session_issued_v28 = facts  # Before first actual journal publication.
            return
        old = self._canonical.journal
        facts = self._session_issued_v28
        if (type(facts) is not tuple or len(facts) != 4 or facts[0] is not selected or
                record.session_profile != selected.name or
                (record.session_profile, record.issued_at, record.deadline) != facts[1:]):
            _durable_fail('invalid_transition')
        if (record.session_profile, record.issued_at, record.deadline) != \
                (old.session_profile, old.issued_at, old.deadline): _durable_fail('invalid_transition')
        if not _same_baseline(record.baseline, old.baseline) or record.deadline != old.deadline or \
                record.stage != old.stage and record.stage not in _NEXT_STAGES.get(old.stage, ()):
            _durable_fail('invalid_transition')
        self._association_transition(record, old)
        self._client_ip_transition_v28(record, old)
        if record.stage == old.stage and not core._same_journal(
                record.replace(association=old.association, client_ip=old.client_ip), old):
            _durable_fail('invalid_transition')
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

    def _fresh_restore(self, locks, request, deadline):
        if self._restore_reader is None: _durable_fail('producer_unavailable')
        end, saved = self._producer_context(deadline)
        try:
            value = self._restore_reader.read_restore(self, locks, request, end)
            reused = any(value is previous or type(value) is tuple and len(value) == 2 and
                (value[0] is previous[0] or value[1] is previous[1])
                for previous in self._restore_observations if type(previous) is tuple and len(previous) == 2)
            self._restore_observations.append(value)
            self._component_clock()
            if (reused or type(value) is not tuple or len(value) != 2 or
                    type(value[0]) is not core.Snapshot or not _same_live_baseline(value[0], request.baseline) or
                    type(value[1]) is not core.CloseProof or not value[1].complete() or
                    value[1].expected < sum(getattr(request, key) is not None for key in ('controller_ticket', 'watchdog_ticket'))):
                _durable_fail('producer_unknown')
            if self._restore_reader.authenticate_restore(self, locks, request, value, end) is not None:
                _durable_fail('producer_unknown')
            self._component_clock()
            self._restore_verified = True
        finally: self._end_producer(saved)

    def _authorize_terminal_clear(self, marker, binding, canonical, deadline):
        """Private Pending callback; normal None means this actual check ran."""
        with self._mutex:
            if (not self._finish_sealed or self._finish_phase != 'terminal_durable' or
                    marker is not self._marker or binding is not self._binding or
                    canonical is not self._terminal_canonical or canonical is not self._canonical or
                    self._finish_locks is not self._current_locks or
                    self._journal_epoch is not marker._binding_ticket.journal_epoch or self._unknown):
                _durable_fail('finish_unknown')
            if type(deadline) not in (int, float) or deadline != self._finish_deadline:
                _durable_fail('invalid_deadline')
            self._begin_disk(deadline)
            self._validate(self._current_locks, True)
            self._canonical_valid(canonical, canonical.journal)
            actual = self._read_exact()
            if not core._same_journal(actual.journal, canonical.journal): _durable_fail('readback_changed')
            self._fresh_restore(self._current_locks, self._finish_record, deadline)
            self._begin_disk(deadline)
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

    def _closed_fixed_alias_registry(self):
        """Consume exact closed v11 originals; no open/close/live reauthentication."""
        co, items, anchors = self._coordination, self._coordination._inventory, self._coordination._anchors
        if (type(co) is not coordination.ClientCoordination or type(items) is not list or
                len(items) not in (coordination.FIXED_ALIAS_RESOURCES, coordination.FIXED_ALIAS_RESOURCES + 1) or
                co._identity is not self._identity or co._run != coordination.RUN_PREFIX + self._run_token or
                co._serialization_lock is not self._mutex or type(anchors) is not list or len(anchors) != 4 or
                any(type(row) is not tuple or len(row) != 6 for row in anchors)):
            return False
        alias = co._tmp_alias
        if (type(alias) is not coordination.tmp_alias.FixedTmpAnchor or
                alias._attempted is not True or alias._prepared is not True or alias._bound is not True or
                alias._unknown is not False or type(alias._context) is not tuple or len(alias._context) != 6 or
                type(alias._identities) is not tuple or len(alias._identities) != 4 or
                type(alias._aliases) is not tuple or len(alias._aliases) != 2):
            return False
        root, tmp, base, run = tuple(row[0] for row in anchors)
        prefix = alias.prefix_tickets
        if (type(prefix) is not tuple or len(prefix) != 2 or
                any(type(row) is not tuple or len(row) != 5 or any(not _uint(v, (1 << 64) - 1) for v in row)
                    for row in alias._identities) or
                any(type(row) is not tuple or len(row) != 2 for row in alias._aliases) or
                alias._aliases[0][1] != '/var/tmp' or alias._aliases[1][1] != coordination.tmp_alias.PHYSICAL_TMP):
            return False
        var, volatile = prefix
        context = alias._context
        if (context[0] is not co or context[1] is not co._io or context[2] is not root or
                alias.tmp_ticket is not tmp or alias._var is not var or alias._volatile is not volatile or
                any(getattr(context[index], '__self__', None) is not co or
                    getattr(context[index], '__func__', None) is not getattr(coordination.ClientCoordination, name)
                    for index, name in ((3, '_tmp_fd'), (4, '_tmp_open_dir'), (5, '_check'))) or
                anchors[0][1:] != (None, None, alias._identities[0], False, False) or
                anchors[1][1:] != (volatile, 'tmp', alias._identities[3], False, True) or
                anchors[2][1] is not tmp or anchors[2][2] != coordination.BASE or
                anchors[2][4:] != (True, False) or
                anchors[3][1] is not base or anchors[3][2] != co._run or anchors[3][4:] != (True, False)):
            return False
        if (type(co._locksets) is not list or not co._locksets or
                type(self._locksets) is not list or len(self._locksets) != len(co._locksets) or
                any(left is not right for left, right in zip(self._locksets, co._locksets))):
            return False
        initial = co._locksets[0]
        if type(initial) is not coordination.LockSet or initial._issuer is not co._issuer: return False
        device, journal = initial._device, initial._journal
        expected = (root, var, volatile, tmp, base, run, device, journal)
        if (any(type(ticket) is not coordination._Fd or ticket.io is not co._io for ticket in expected) or
                len(set(id(ticket) for ticket in expected)) != len(expected) or
                tuple(ticket.role for ticket in expected) !=
                ('anchor', 'tmp_alias_var', 'tmp_alias_volatile', 'anchor', 'anchor', 'anchor', 'device', 'journal') or
                device.parent is not tmp or device.name != coordination.DEVICE_LOCK or
                journal.parent is not run or journal.name != coordination.JOURNAL_LOCK or
                type(device.identity) is not tuple or len(device.identity) != 7 or
                type(journal.identity) is not tuple or len(journal.identity) != 7):
            return False
        handoff = co._handoff
        if handoff is None:
            if (len(items) != len(expected) or len(co._locksets) != 1 or co._locks is not initial or
                    self._current_locks is not initial or self._released is not None or self._reacquired is not None):
                return False
        else:
            marker, binding = self._marker, self._binding
            if (type(handoff) is not coordination._JournalHandoff or handoff.owner is not co or
                    handoff.initial is not initial or handoff.device is not device or handoff.journal is not journal or
                    handoff.original_identity != journal.identity or handoff.unknown is not False or
                    handoff.release_verified is not True or
                    type(handoff.released) is not coordination.ReleasedJournal or
                    handoff.released._issuer is not co._issuer or handoff.released._context is not handoff or
                    self._released is not handoff.released or handoff.epoch is not self._epoch or
                    type(binding) is not pending.OwnedMarkerBinding or handoff.binding is not binding or
                    type(marker) is not pending.ClientPendingMarker or binding._marker is not marker or
                    binding._issuer is not marker._issuer or binding._coordination is not co or
                    binding._files is not self._files or binding._epoch is not self._epoch or
                    binding._serialization_lock is not self._mutex or marker._coordination is not co or
                    marker._serialization_lock is not self._mutex or
                    co._owned_marker_binding is not binding or co._owned_marker_epoch is not self._epoch or
                    self._files._owned_marker_binding is not binding or self._files._owned_marker_epoch is not self._epoch):
                return False
            ticket = marker._binding_ticket
            if (type(ticket) is not pending._BindingTicket or ticket.binding is not binding or
                    ticket.handoff is not handoff or ticket.epoch is not self._epoch or ticket.shared is not self._mutex):
                return False
            if len(items) == len(expected):
                if (handoff.stage != 'released' or handoff.reacquire_attempted is not False or
                        handoff.new_ticket is not None or handoff.new_locks is not None or handoff.reacquired is not None or
                        self._reacquired is not None or len(co._locksets) != 1 or co._locks is not initial or
                        self._current_locks is not initial or marker._locks is not initial or
                        self._journal_epoch is not handoff.old_epoch or ticket.journal_epoch is not handoff.old_epoch):
                    return False
            else:
                new, locks = handoff.new_ticket, handoff.new_locks
                if (handoff.stage != 'active' or handoff.reacquire_attempted is not True or
                        type(new) is not coordination._Fd or new.io is not co._io or
                        any(new is old for old in expected) or new.role != 'journal_handoff' or
                        new.parent is not run or new.name != coordination.JOURNAL_LOCK or new.identity != journal.identity or
                        type(locks) is not coordination.LockSet or locks._issuer is not co._issuer or
                        locks._device is not device or locks._journal is not new or
                        len(co._locksets) != 2 or co._locksets[1] is not locks or co._locks is not locks or
                        self._current_locks is not locks or marker._locks is not locks or
                        type(handoff.reacquired) is not coordination.ReacquiredJournal or
                        handoff.reacquired._issuer is not co._issuer or handoff.reacquired._context is not handoff or
                        handoff.reacquired.locks is not locks or self._reacquired is not handoff.reacquired or
                        self._journal_epoch is not handoff.new_epoch or ticket.journal_epoch is not handoff.new_epoch):
                    return False
                expected += (new,)
        return len(items) == len(expected) and all(left is right for left, right in zip(items, expected))

    def _proc_pending_v24(self):
        # Passive original history only: no fstat, deadline renewal or close.
        reader = self._proc_reader
        return (reader is not self._proc_reader_original_v24 or type(reader) is not proc.ProcReader or
            reader._resource_budget_v24 is not self._resource_budget_v23 or
            reader._bound_budget_v24 is not self._resource_budget_v23 or
            not any(r is reader for r in self._resource_budget_v23._readers) or
            self._marker is not None and self._marker._reader is not reader or not reader.history_closed())
    def _inventory_closed(self):
        self._component_clock()
        if self._close_unknown or self._proc_pending_v24(): return False
        reader = self._proc_reader
        if (reader is not self._proc_reader_original_v24 or type(reader) is not proc.ProcReader or
                reader._resource_budget_v24 is not self._resource_budget_v23 or
                not any(r is reader for r in self._resource_budget_v23._readers) or
                self._marker is not None and self._marker._reader is not reader or
                not reader.history_closed()): return False
        inventories = (self._coordination._inventory, self._files._inventory)
        if any(type(items) is not list for items in inventories): return False
        if len(inventories[0]) > coordination.MAX_RESOURCES + 1 and not self._closed_fixed_alias_registry():
            return False
        if len(inventories[1]) > files.MAX_RESOURCES:
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
            self._finish_deadline = deadline
            final, terminal_durable = record, False
            marker_state, durability, resources_closed = 'unknown', 'not_attempted', False
            try:
                self._begin_disk(deadline)
                marker_state = self._retained_marker()
                if normal_restored:
                    self._validate(locks, True)
                    self._fresh_restore(locks, record, deadline)
                    self._begin_disk(deadline)
                    self._validate(locks, True)
                    terminal = record.replace(stage='reconciled', ready=False)
                    final = self._publish(locks, terminal, True)
                    self._terminal_canonical = self._canonical
                    terminal_durable, self._finish_phase = True, 'terminal_durable'
                    self._fresh_restore(locks, record, deadline)
                    self._begin_disk(deadline)
                    clear = self._marker.clear_terminal(self, self._binding, self._terminal_canonical, deadline)
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
            try:
                self._begin_disk(deadline)
                resources_closed = self._inventory_closed()
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
            self._begin_disk(deadline)
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
                'resource_pending': self._proc_pending_v24() or self._unknown or self._close_unknown or self._files._resource_pending or
                    self._coordination.status()['resource_pending'] or
                    bool(self._marker is not None and (self._marker._resource_pending or self._marker._creation_unknown)),
                'prepared_checkpoint': self._canonical is not None, 'restore_observed': self._restore_verified,
                'close_attempted': self._close_attempted, 'finish_issued': self._finish_receipt is not None,
                'production_provider': False, 'baseline_authenticated': False, 'executor_verified': False,
                'same_ofd_verified': False, 'send_available': False, 'receive_available': False}
