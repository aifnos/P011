"""Private fixed session resource credits, not network or recovery permission.

Only trusted Store/Provider code may call this API. No external configuration,
IO, threads, close producers or resource proofs are implemented here. Original
issuers remain solely responsible for registration and actual per-FD closure.
Python 3.5. Payload accounting does not bound Python object/allocator heap.
"""

PREPARATION_NETWORK, CLEANUP = 'PREPARATION_NETWORK', 'CLEANUP'
KINDS = ('FILES_OPEN', 'CANONICAL', 'PROC_CALL', 'COLLECTOR', 'KERNEL_READER',
    'CAPS_READER', 'FD_RECEIPT', 'LEGACY_REQUEST', 'LEGACY_PACKET', 'PROC_GENERATION', 'PROC_OPEN')
_LANES = (PREPARATION_NETWORK, CLEANUP)
_COUNTS = ((2304, 2304, 8192, 64, 64, 64, 131072, 2048, 131072, 16384, 262144),
           (256, 256, 512, 16, 8, 8, 32768, 256, 16384, 2048, 65536))
_PAYLOAD_BYTES = (64 * 1024 * 1024, 32 * 1024 * 1024)
_CODES = frozenset(('invalid_owner', 'invalid_profile', 'invalid_lane',
    'invalid_kind', 'invalid_payload_budget', 'already_bound', 'owner_changed',
    'network_cancelled', 'safe_exhaustion', 'invalid_credit', 'invalid_state',
    'invalid_payload', 'payload_overrun', 'invalid_reader'))
_NO_RETURN = object()


class ResourceBudgetError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'invalid_state'
        RuntimeError.__init__(self, self.code)


def _fail(code): raise ResourceBudgetError(code) from None


def _lane(value):
    if type(value) is not str or value not in _LANES: _fail('invalid_lane')
    return _LANES.index(value)


def _kind(value):
    if type(value) is not str or value not in KINDS: _fail('invalid_kind')
    return KINDS.index(value)


class _Profile(object):
    __slots__ = ('identity', 'counts', 'payload_bytes')
    def __init__(self, identity):
        object.__setattr__(self, 'identity', identity)
        object.__setattr__(self, 'counts', _COUNTS)
        object.__setattr__(self, 'payload_bytes', _PAYLOAD_BYTES)
    def __setattr__(self, name, value): raise AttributeError('fixed internal profile')
    def __repr__(self): return '<private fixed CLIENT resource profile; no permission>'
    def count_limit(self, lane, kind): return self.counts[_lane(lane)][_kind(kind)]
    def payload_limit(self, lane): return self.payload_bytes[_lane(lane)]


SOURCE_PROFILE = _Profile('CLIENT_PROC_HISTORY_V24_SOURCE_ONLY')
# Selecting a longer internal session never enlarges credits or byte limits.
FORMAL_PROFILE = _Profile('CLIENT_SESSION_V28_FORMAL_FIXED_ACCOUNTING_SOURCE_ONLY')


class Credit(object):
    """Exact private original, never a FD, CloseProof or caller capability."""
    __slots__ = ('_issuer', '_ordinal', '_store', '_mutex', '_epoch',
        '_journal_epoch', '_locks', '_session_profile', '_profile', 'lane', 'kind', 'max_payload_bytes')
    def __init__(self, issuer, ordinal, store, mutex, epoch, lane, kind, maximum):
        for name, value in (('_issuer', issuer), ('_ordinal', ordinal), ('_store', store),
                ('_mutex', mutex), ('_epoch', epoch),
                ('_journal_epoch', getattr(store, '_journal_epoch', None)),
                ('_locks', getattr(store, '_current_locks', None)),
                ('_session_profile', store._session_profile_original_v28),
                ('_profile', store._resource_budget_v23._profile), ('lane', lane),
                ('kind', kind), ('max_payload_bytes', maximum)):
            object.__setattr__(self, name, value)
    def __setattr__(self, name, value): raise AttributeError('private immutable credit')
    def __repr__(self): return '<private CLIENT accounting credit; no permission>'


class ResourceBudget(object):
    """One immutable Store generation and its original RLock, no renewed TTL.

    Construct before Store._files: imports of Store/Provider are lazy to avoid
    the FILES -> broker -> Store definition cycle. reserve precedes creation;
    started precedes the actual synchronous producer; returned immediately
    preserves original references/payload; settle is its real finally boundary.
    There is deliberately no refund, retire, closure or admission API.
    """
    def __init__(self, store, profile=SOURCE_PROFILE):
        import mta_client_store as stores
        import mta_p2p_client_init as core
        import threading
        if type(store) is not stores.DurableClientInitStore or not hasattr(store, '_mutex') or \
                not hasattr(store, '_epoch') or store._epoch is None:
            _fail('invalid_owner')
        selected = getattr(store, '_session_profile', None)
        original = getattr(store, '_session_profile_original_v28', None)
        if (selected is not original or selected is not core.TRIAL_SESSION_PROFILE and
                selected is not core.FORMAL_SESSION_PROFILE): _fail('invalid_profile')
        expected = SOURCE_PROFILE if selected is core.TRIAL_SESSION_PROFILE else FORMAL_PROFILE
        if profile is not expected: _fail('invalid_profile')
        mutex = store._mutex
        if type(mutex) is not type(threading.RLock()):
            _fail('invalid_owner')
        self._store, self._mutex, self._epoch, self._profile = store, mutex, store._epoch, profile
        self._session_profile = selected
        self._issuer, self._provider, self._rows = object(), None, []
        self._provider_store_seen = False
        self._readers = []  # Exact once-bound originals, never dropped or rebound.
        self._used = [[0 for unused in KINDS] for lane in _LANES]
        self._retained, self._inflight = [0, 0], [0, 0]
        self._cancelled, self._owner_changed, self._overrun = False, False, False
        self._exhausted, self._reason = [False, False], 'not_recorded'
        with mutex:
            if getattr(store, '_resource_budget_v23', None) is not None: _fail('already_bound')
            store._resource_budget_v23 = self

    def __repr__(self): return '<private CLIENT owner credit ledger; no permission>'

    def _context(self):
        import mta_p2p_client_init as core
        store = self._store
        selected = self._session_profile
        expected = (SOURCE_PROFILE if selected is core.TRIAL_SESSION_PROFILE else
            FORMAL_PROFILE if selected is core.FORMAL_SESSION_PROFILE else None)
        provider = self._provider
        if provider is not None and provider._store is store:
            self._provider_store_seen = True  # Once attached, never return to the pre-bind None phase.
        if (expected is None or self._profile is not expected or
                getattr(store, '_session_profile', None) is not selected or
                getattr(store, '_session_profile_original_v28', None) is not selected or
                store._mutex is not self._mutex or store._epoch is not self._epoch or
                getattr(store, '_resource_budget_v23', None) is not self or
                any(reader._resource_budget_v24 is not self or reader._bound_budget_v24 is not self
                    for reader in self._readers) or
                provider is not None and (provider._store is not store and
                    (provider._store is not None or self._provider_store_seen) or
                    getattr(provider, '_resource_budget_v23', None) is not self)):
            self._owner_changed, self._cancelled, self._reason = True, True, 'owner_changed'
            _fail('owner_changed')
        # Current canonical, locks and journal epoch legitimately advance.
        # A credit binds originals only; it never authenticates their live use.

    def bind_provider(self, provider):
        import mta_client_linux_provider as linux
        with self._mutex:
            self._context()
            if type(provider) is not linux.LinuxClientInitProvider or \
                    provider._store is not None and provider._store is not self._store:
                _fail('invalid_owner')
            if self._provider is not None or getattr(provider, '_resource_budget_v23', None) is not None:
                _fail('already_bound')
            self._provider = provider
            self._provider_store_seen = provider._store is self._store
            provider._resource_budget_v23 = self

    def bind_reader(self, reader):
        """Exact pure pre-IO registration, no caller shape/closure callback."""
        import mta_client_proc as proc
        with self._mutex:
            self._context()
            if type(reader) is not proc.ProcReader:
                _fail('invalid_reader')
            if (reader._resource_budget_v24 is not None or reader._bound_budget_v24 is not None or
                    any(item is reader for item in self._readers)):
                _fail('already_bound')
            if (reader._active or reader._pending or reader._history_active or reader._history or
                    reader._stage != 'not_started' or reader._fd_refs or reader._raw or
                    reader._open_attempt is not None):
                _fail('invalid_reader')
            self._readers.append(reader)
            reader._resource_budget_v24 = self
            reader._bound_budget_v24 = self
            return reader

    def _owned(self, credit):
        if (type(credit) is not Credit or credit._issuer is not self._issuer or
                credit._store is not self._store or credit._mutex is not self._mutex or
                credit._epoch is not self._epoch or credit._session_profile is not self._session_profile or
                credit._profile is not self._profile or type(credit._ordinal) is not int or
                not 0 <= credit._ordinal < len(self._rows)):
            _fail('invalid_credit')
        row = self._rows[credit._ordinal]
        if row['credit'] is not credit: _fail('invalid_credit')
        return row

    def reserve(self, lane, kind, retained_payload_bytes=0):
        """Precharge a fixed kind/count and a trusted read's maximum payload.

        Maximum is a payload length bound, not arbitrary resource capacity.
        Exhaustion occurs before a producer or resource ticket is created.
        Existing originals remain retained; known exhaustion is not IO unknown.
        """
        index, column = _lane(lane), _kind(kind)
        if type(retained_payload_bytes) is not int or not 0 <= retained_payload_bytes <= _PAYLOAD_BYTES[index]:
            _fail('invalid_payload_budget')
        with self._mutex:
            self._context()
            if lane == PREPARATION_NETWORK and self._cancelled: _fail('network_cancelled')
            if (self._used[index][column] >= _COUNTS[index][column] or
                    self._retained[index] + self._inflight[index] + retained_payload_bytes > _PAYLOAD_BYTES[index]):
                self._exhausted[index], self._reason = True, 'safe_exhaustion'
                _fail('safe_exhaustion')
            credit = Credit(self._issuer, len(self._rows), self._store, self._mutex,
                self._epoch, lane, kind, retained_payload_bytes)
            row = {'credit': credit, 'active': False, 'started': False, 'settled': False,
                'original': _NO_RETURN, 'payloads': (), 'actual': None,
                'reserved': retained_payload_bytes, 'unknown': False, 'sticky': False, 'late': False}
            self._rows.append(row)  # The before-create registration, never deleted.
            self._used[index][column] += 1
            self._inflight[index] += retained_payload_bytes
            return credit

    def started(self, credit):
        with self._mutex:
            row = self._owned(credit); self._context()
            if credit.lane == PREPARATION_NETWORK and self._cancelled: _fail('network_cancelled')
            if row['started'] or row['settled']: _fail('invalid_state')
            row['started'], row['active'], row['unknown'] = True, True, True

    def _late(self, row):
        try: self._context()
        except ResourceBudgetError: row['late'] = True
        if row['credit'].lane == PREPARATION_NETWORK and self._cancelled: row['late'] = True
        if row['late']: row['sticky'] = True
        return row['late']

    def mark_unknown(self, credit):
        """Original issuer reports uncertain creation/postcheck; never erase it."""
        with self._mutex:
            row = self._owned(credit)
            if not row['active'] or row['settled']: _fail('invalid_state')
            row['unknown'], row['sticky'] = True, True
            self._cancelled = True

    def returned(self, credit, original, retained_payloads=()):
        """Caller passes actual retained raw bytes, not a heap-size estimate.

        No resource proof is consumed here: original may be a producer row or
        its actual per-FD evidence. Even a malformed/late return is retained
        before its subsequent accounting/context checks, never silently lost.
        """
        with self._mutex:
            row = self._owned(credit)
            if not row['active'] or row['original'] is not _NO_RETURN: _fail('invalid_state')
            row['original'], row['payloads'] = original, retained_payloads  # First original return.
            index = _lane(credit.lane)
            if type(retained_payloads) is not tuple or len(retained_payloads) > 4096 or \
                    any(type(value) is not bytes for value in retained_payloads):
                row['unknown'], row['sticky'] = True, True
                self._cancelled, self._reason = True, 'invalid_payload'
                _fail('invalid_payload')
            actual = sum(len(value) for value in retained_payloads)
            row['actual'] = actual
            self._retained[index] += actual  # Actual payload is never refunded.
            if actual > credit.max_payload_bytes:
                row['unknown'], row['sticky'] = True, True
                self._overrun, self._cancelled, self._reason = True, True, 'payload_overrun'
                _fail('payload_overrun')
            if self._late(row) or row['sticky']:
                row['unknown'], row['sticky'] = True, True
            else:
                # Convert only actual-used credit. Unused remains in-flight
                # while the producer/postchecks are still active.
                row['reserved'] -= actual
                self._inflight[index] -= actual
                row['unknown'] = False

    def settle(self, credit):
        """Only after synchronous producer ACTUALLY returns, including finally.

        True denotes measured actor-return accounting, not resource closure.
        Unknown/late keeps all outstanding maximum credit, even after return.
        No history count, original reference or actual payload is retired.
        """
        with self._mutex:
            row = self._owned(credit)
            if not row['active'] or row['settled']: _fail('invalid_state')
            row['active'], row['settled'] = False, True
            if self._late(row) or row['actual'] is None or row['unknown']:
                row['unknown'] = True
                if credit.lane == PREPARATION_NETWORK: self._cancelled = True
                return False
            self._inflight[_lane(credit.lane)] -= row['reserved']
            row['reserved'] = 0
            return True

    def cancel(self):
        with self._mutex:
            self._cancelled = True

    def status(self):
        with self._mutex:
            return {'evidence': 'CLIENT_RESOURCE_ACCOUNTING_SOURCE_ONLY',
                'profile': self._profile.identity, 'network_cancelled': self._cancelled,
                'owner_changed': self._owner_changed, 'payload_overrun': self._overrun,
                'reason': self._reason, 'counts': tuple(tuple(row) for row in self._used),
                'retained_payload_bytes': tuple(self._retained),
                'inflight_payload_bytes': tuple(self._inflight),
                'safe_exhaustion': tuple(self._exhausted), 'original_count': len(self._rows),
                'active_producers': sum(row['active'] for row in self._rows),
                'resource_pending': any(row['unknown'] or row['active'] or row['late'] for row in self._rows),
                'network_authorized': False, 'resources_closed': False,
                'restoration_verified': False, 'send_available': False, 'receive_available': False}
