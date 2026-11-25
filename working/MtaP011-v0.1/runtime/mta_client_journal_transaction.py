"""Real non-RF prepared journal / retained marker transaction only.

Existing private directories are the caller's responsibility. This owner
serializes actual Coordination / FILES / Pending calls with one RLock, but
is NOT ClientInitStore, Executor proof, inherited OFD proof or RF admission.
There is no finish, marker clear, network restoration or recovery entry.
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
    'not_open', 'invalid_clock', 'clock_regressed', 'expired', 'invalid_deadline',
    'invalid_baseline', 'current_exists', 'prepare_already_attempted',
    'not_prepared', 'invalid_receipt', 'invalid_record', 'baseline_changed',
    'deadline_extended', 'readback_changed', 'marker_unverified',
    'component_error', 'resource_pending', 'close_unknown', 'operation_interrupted'))


class JournalTransactionError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'component_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise JournalTransactionError(code) from None


def _uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


class _Private(object):
    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError('private immutable journal transaction observation')

    def __repr__(self):
        return '<CLIENT private journal transaction observation>'

    __str__ = __repr__


class TransactionSession(_Private):
    """Exact local session, never a manifest or executor capability."""
    __slots__ = ('_issuer',)

    def __init__(self, issuer):
        object.__setattr__(self, '_issuer', issuer)


class TransactionReceipt(_Private):
    """Full canonical checkpoint verified by this exact live transaction."""
    __slots__ = ('journal', 'canonical', '_issuer', '_session', '_epoch')

    def __init__(self, canonical, issuer, session, epoch):
        for name, value in (('journal', canonical.journal), ('canonical', canonical),
                ('_issuer', issuer), ('_session', session), ('_epoch', epoch)):
            object.__setattr__(self, name, value)


class JournalTransactionCloseObservation(_Private):
    """Local original descriptors only. A retained marker is NOT restoration."""
    __slots__ = ('_issuer', 'scope_attempted', 'marker_closed', 'files_closed',
        'coordination_closed', 'resource_pending', 'write_pending',
        'published_unknown', 'checkpoint_unverified', 'marker_unverified')

    def __init__(self, issuer, attempted, marker, journal, locks, resource,
                 write, published, checkpoint, marker_unknown):
        for name, value in (('_issuer', issuer), ('scope_attempted', attempted),
                ('marker_closed', marker), ('files_closed', journal),
                ('coordination_closed', locks), ('resource_pending', resource),
                ('write_pending', write), ('published_unknown', published),
                ('checkpoint_unverified', checkpoint), ('marker_unverified', marker_unknown)):
            object.__setattr__(self, name, value)

    def complete(self):
        return (self.scope_attempted is True and self.marker_closed is True and
            self.files_closed is True and self.coordination_closed is True and
            self.resource_pending is False and self.write_pending is False and
            self.published_unknown is False and self.checkpoint_unverified is False and
            self.marker_unverified is False)


class ClientJournalTransaction(object):
    """Single synchronous lifetime, only prepared / no actors / no RF roles.

    Internal adapters are trusted HOST seams, not UI options. Every public
    operation holds the same exact outer RLock passed to all three components.
    Actual flock and filesystem publication remain in those owned components.
    No directory creation or adoption of a pre-existing journal / marker.
    """
    def __init__(self, run_token, identity, timeout=3.0, _coordination_io=None,
                 _files_io=None, _pending_io=None, _proc_reader=None, _clock=None):
        if (type(run_token) is not str or len(run_token) != 32 or
                any(c not in _HEX for c in run_token) or type(identity) is not core.Identity or
                type(timeout) not in (int, float) or not 0.1 <= timeout <= 10 or
                not math.isfinite(float(timeout)) or (_clock is not None and not callable(_clock))):
            _fail('invalid_config')
        self._identity, self._timeout = identity, float(timeout)
        self._clock, self._mutex = _clock or time.monotonic, threading.RLock()
        self._issuer, self._epoch = object(), object()
        self._deadline, self._last_time, self._expired = None, None, False
        self._coordination = coordination.ClientCoordination(run_token, identity, timeout,
            _io=_coordination_io, _clock=self._component_clock, _serialization_lock=self._mutex)
        self._files = files.ClientJournalFiles(run_token, identity, timeout,
            _io=_files_io, _clock=self._component_clock, _serialization_lock=self._mutex)
        self._pending_io, self._proc_reader = _pending_io, _proc_reader
        self._session, self._locks, self._marker, self._binding = None, None, None, None
        self._canonical, self._receipt, self._candidate = None, None, None
        self._marker_observation, self._binding_observation = None, None
        self._attempted, self._opened, self._ended = False, False, False
        self._prepare_attempted, self._write_attempted, self._checkpoint_unverified = False, False, False
        self._marker_attempted, self._marker_unverified, self._bound_verified = False, False, False
        self._close_attempted, self._close_unknown, self._close_receipt = False, False, None
        self._write_pending, self._published_unknown = False, False
        self._phase, self._reason = 'new', 'not_recorded'

    def _now(self):
        try: value = self._clock()
        except Exception: _fail('invalid_clock')
        if not _finite(value): _fail('invalid_clock')
        value = float(value)
        if self._last_time is not None and value < self._last_time: _fail('clock_regressed')
        self._last_time = value
        return value

    def _begin(self, journal_deadline=None):
        self._deadline, self._expired = None, False
        now = self._now()
        if journal_deadline is not None and (not _finite(journal_deadline) or
                not 0 < journal_deadline - now <= 20): _fail('invalid_deadline')
        self._deadline = min(now + self._timeout, float(journal_deadline)) if journal_deadline is not None else now + self._timeout

    def _component_clock(self):
        now = self._now()
        if self._deadline is None: _fail('not_open')
        if now >= self._deadline:
            self._expired = True
            _fail('expired')
        return now

    def _owned(self, session):
        if type(session) is not TransactionSession or session is not self._session or session._issuer is not self._issuer:
            _fail('invalid_session')
        if self._ended or not self._opened: _fail('not_open')
        if self._close_unknown: _fail('resource_pending')

    def _marker_valid(self, observed):
        if (self._marker is None or type(observed) is not pending.PendingObservation or
                observed._issuer is not self._marker._issuer or type(observed.marker_state) is not str or
                observed.marker_state != 'retained_observed' or
                observed.durable_created is not True or observed.owner_observed is not True or
                observed.resource_pending is not False or observed.creation_unknown is not False):
            _fail('marker_unverified')

    def _validate(self):
        self._component_clock()
        if self._coordination.validate(self._locks) is not True: _fail('component_error')
        if self._binding is not None:
            if type(self._binding) is not pending.OwnedMarkerBinding: _fail('marker_unverified')
            observed = self._binding.verify(self._files, self._epoch)
            self._binding_observation = observed  # Keep returned observation before postchecks.
            self._marker_valid(observed)
            self._bound_verified = True
        self._component_clock()

    def _canonical_valid(self, value, record):
        if (type(value) is not files.CanonicalRecord or value._issuer is not self._files._issuer or
                not _uint(value._generation, 0xffffffff) or value._generation != self._files._generation or
                type(value.data) is not bytes or type(value.metadata) is not tuple or len(value.metadata) != 9 or
                any(not _uint(v, (1 << 64) - 1) for v in value.metadata[:7]) or
                any(type(v) is not int or not -(1 << 63) <= v <= (1 << 63) - 1 for v in value.metadata[7:]) or
                not any(item is value for item in self._files._issued_canonicals) or
                value.data != codec.encode_journal(record) or not core._same_journal(value.journal, record)):
            _fail('readback_changed')

    def _read_exact(self, expected):
        actual = self._files.read_current()
        if expected is None:
            if actual is not None: _fail('current_exists')
        else:
            self._canonical_valid(expected, expected.journal)
            self._canonical_valid(actual, expected.journal)
            if actual.metadata != expected.metadata or actual.data != expected.data:
                _fail('readback_changed')
        return actual

    def _record_error(self, error):
        self._reason = 'expired' if self._expired else (error.code if type(error) is JournalTransactionError else
            ('component_error' if isinstance(error, Exception) else 'operation_interrupted'))
        self._phase = 'error'

    def _abort(self, error):
        # Error formatting / allocations must never skip owned close attempts.
        try: self._record_error(error)
        finally:
            try: self.close(self._session)
            except BaseException: self._close_unknown = True
        if isinstance(error, Exception): _fail(self._reason)
        raise error

    def open(self):
        with self._mutex:
            if self._attempted or self._ended: _fail('already_attempted')
            self._attempted, self._phase = True, 'opening'
            self._session = TransactionSession(self._issuer)
            try:
                self._begin()
                self._locks = self._coordination.acquire()  # Save actual result before validation.
                self._files.open()
                self._validate()
                self._read_exact(None)
                self._validate()
                self._opened, self._phase = True, 'opened'
                return self._session
            except BaseException as error: self._abort(error)

    def current(self, session):
        with self._mutex:
            self._owned(session)
            try:
                self._begin(None if self._canonical is None else self._canonical.journal.deadline)
                self._phase = 'reading'
                self._validate()
                result = self._read_exact(self._canonical)
                self._validate()
                self._phase = 'prepared' if self._receipt is not None else 'opened'
                return result
            except BaseException as error: self._abort(error)

    def prepare_initial(self, session, baseline, deadline):
        with self._mutex:
            self._owned(session)
            if type(baseline) is not core.Snapshot: _fail('invalid_baseline')
            if not _finite(deadline): _fail('invalid_deadline')
            if self._prepare_attempted: _fail('prepare_already_attempted')
            self._prepare_attempted, self._phase = True, 'preparing'
            try:
                self._begin(deadline)
                record = core.Journal(self._identity, 'prepared', baseline, deadline)
                self._validate(); self._read_exact(None); self._validate()
                self._write_attempted, self._checkpoint_unverified = True, True
                self._candidate = self._files.commit(None, record)
                self._canonical_valid(self._candidate, record)
                self._canonical = self._candidate
                self._validate(); self._read_exact(self._canonical); self._validate()
                self._marker = pending.ClientPendingMarker(self._coordination, self._locks, self._timeout,
                    _io=self._pending_io, _reader=self._proc_reader, _clock=self._component_clock,
                    _serialization_lock=self._mutex)
                self._marker_attempted, self._marker_unverified = True, True
                self._marker_observation = self._marker.create()
                self._marker_valid(self._marker_observation)
                self._binding = self._marker.bind_files(self._files, self._canonical, self._epoch, self._mutex)
                # The binding is retained BEFORE any postcheck; it never permits RF.
                if type(self._binding) is not pending.OwnedMarkerBinding: _fail('marker_unverified')
                self._validate(); self._read_exact(self._canonical); self._validate()
                result = TransactionReceipt(self._canonical, self._issuer, session, self._epoch)
                self._receipt = result
                self._checkpoint_unverified, self._marker_unverified = False, False
                self._phase, self._reason = 'prepared', 'not_recorded'
                return result
            except BaseException as error: self._abort(error)

    def _non_rf_record(self, record):
        if (type(record) is not core.Journal or record.identity.key() != self._identity.key() or
                record.stage != 'prepared' or record.ready is not False or any(v is not None for v in
                    (record.owned, record.interface_ticket, record.controller_ticket, record.controller,
                     record.watchdog_ticket, record.watchdog))): _fail('invalid_record')
        original = self._canonical.journal
        compared = core.Journal(record.identity, 'prepared', record.baseline, original.deadline)
        if not core._same_journal(original, compared): _fail('baseline_changed')
        if record.deadline > original.deadline: _fail('deadline_extended')

    def commit(self, session, expected_receipt, record):
        with self._mutex:
            self._owned(session)
            if self._receipt is None: _fail('not_prepared')
            if (type(expected_receipt) is not TransactionReceipt or expected_receipt is not self._receipt or
                    expected_receipt._issuer is not self._issuer or expected_receipt._session is not session or
                    expected_receipt._epoch is not self._epoch): _fail('invalid_receipt')
            self._non_rf_record(record)
            try:
                self._begin(record.deadline)
                self._phase = 'committing'
                self._validate(); self._read_exact(self._canonical); self._validate()
                previous = self._canonical
                self._write_attempted, self._checkpoint_unverified = True, True
                self._candidate = self._files.commit(previous, record)
                self._canonical_valid(self._candidate, record)
                if self._candidate._generation != previous._generation + 1: _fail('readback_changed')
                self._canonical = self._candidate
                self._validate(); self._read_exact(self._canonical); self._validate()
                result = TransactionReceipt(self._canonical, self._issuer, session, self._epoch)
                self._receipt, self._checkpoint_unverified = result, False
                self._phase, self._reason = 'prepared', 'not_recorded'
                return result
            except BaseException as error: self._abort(error)

    def _closed_ticket(self, ticket, io):
        self._component_clock()
        if (ticket.io is not io or type(ticket.opening_unknown) is not bool or
                type(ticket.attempted) is not bool or type(ticket.closed) is not bool or
                ticket.opening_unknown or not ticket.closed): return False
        if ticket.fd is None: return ticket.attempted is False
        if not _uint(ticket.fd, 0x7fffffff) or ticket.attempted is not True: return False
        try: ticket.io.fstat(ticket.fd)
        except OSError as error: return type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: return False
        return False

    def _observe_close(self):
        marker_closed, files_closed, coordination_closed = False, False, False
        write, published = True, True
        resource = self._close_unknown
        try:
            self._begin()
            inventory = self._files._inventory
            if type(inventory) is not list or len(inventory) > files.MAX_RESOURCES: _fail('close_unknown')
            files_closed = all(self._closed_ticket(ticket, self._files._io) for ticket in inventory)
            fs = self._files.status()
            if type(fs) is not dict or any(type(fs.get(k)) is not bool for k in
                    ('resource_pending', 'write_pending', 'published_unknown', 'all_owned_fds_closed')):
                _fail('close_unknown')
            write, published = fs['write_pending'], fs['published_unknown']
            resource = resource or fs['resource_pending'] or not files_closed or not fs['all_owned_fds_closed']
            co = self._coordination.read_closed(self._locks)
            if (type(co) is not coordination.ClosedObservation or co._issuer is not self._coordination._issuer or
                    type(co.observed) is not tuple or any(type(v) is not bool for v in co.observed) or
                    len(co.observed) != len(self._coordination._inventory) or
                    type(co.resource_pending) is not bool or
                    not _uint(co.unreturned_open_count, coordination.MAX_RESOURCES)):
                _fail('close_unknown')
            coordination_closed = (co.resource_pending is False and co.unreturned_open_count == 0 and all(co.observed))
            resource = resource or not coordination_closed
            if self._marker is None:
                marker_closed = not self._marker_attempted
            else:
                ms = self._marker.status()
                if type(ms) is not dict or any(type(ms.get(k)) is not bool for k in
                        ('resource_pending', 'creation_unknown', 'closed')): _fail('close_unknown')
                ticket = self._marker._ticket
                marker_closed = ms['closed'] is True and (ticket is None or self._closed_ticket(ticket, self._marker._io))
                resource = resource or ms['resource_pending'] or not marker_closed
                self._marker_unverified = self._marker_unverified or ms['creation_unknown']
        except BaseException:
            resource = True
        if resource: self._close_unknown = True
        self._write_pending, self._published_unknown = write, published
        return JournalTransactionCloseObservation(self._issuer, self._attempted, marker_closed,
            files_closed, coordination_closed, resource, write, published,
            self._checkpoint_unverified, self._marker_unverified)

    def close(self, session=None):
        with self._mutex:
            if session is not None and (type(session) is not TransactionSession or session is not self._session or
                    session._issuer is not self._issuer): _fail('invalid_session')
            self._ended, self._opened = True, False
            if not self._close_attempted:
                self._close_attempted = True
                # All known component closes precede clock/status/receipt allocation.
                try:
                    if self._marker is not None: self._marker.close()
                except BaseException: self._close_unknown = True
                finally:
                    try: self._files.close()
                    except BaseException: self._close_unknown = True
                    finally:
                        try: self._coordination.close()
                        except BaseException: self._close_unknown = True
            try: self._close_receipt = self._observe_close()
            except BaseException:
                self._close_unknown = True
                raise
            self._phase = 'close_unknown' if self._close_unknown else 'closed'
            return self._close_receipt

    def status(self):
        with self._mutex:
            return {'evidence': 'CLIENT_JOURNAL_TRANSACTION_ONLY', 'phase': self._phase, 'reason': self._reason,
                'opened': self._opened, 'prepare_attempted': self._prepare_attempted,
                'prepared_checkpoint': self._receipt is not None, 'marker_create_attempted': self._marker_attempted,
                'marker_bound': self._bound_verified, 'close_attempted': self._close_attempted,
                'resource_pending': self._close_unknown, 'write_pending': self._write_pending,
                'published_unknown': self._published_unknown, 'checkpoint_unverified': self._checkpoint_unverified,
                'marker_unverified': self._marker_unverified, 'marker_clear_implemented': False,
                'finish_implemented': False, 'baseline_authenticated': False, 'manifest_authenticated': False,
                'executor_verified': False, 'same_ofd_verified': False, 'restore_verified': False,
                'rf_admission': False, 'full_store_implemented': False,
                'receive_available': False, 'send_available': False}
