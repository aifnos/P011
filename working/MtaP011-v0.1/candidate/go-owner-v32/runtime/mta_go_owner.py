"""Single-worker GO owner/F first SOURCE slice; no RF execution entry point.

Implemented: native durable reserve -> V4-compatible GROUP_ADD preparation ->
once cleanup of the original, provably unmutated reservation FD/marker/journal.
NOT implemented: native GO interface/actor/watchdog/control provenance, current
same-channel capability observations, IP/DHCP/association, nine send interfaces.
Prepared command bytes are requested facts, never permission to send them.
No live code, device or HOST model has executed this source revision.
"""
import threading
import mta_go_store as store

# Actual V4 compatible directives. CONFIG_NO_CONFIG_WRITE excludes the old
# update_config setting; no unsupported update_config=0 or generated credentials.
V4_GO_CONFIG_BODY = (b'p2p_no_group_iface=1\nap_scan=2\n'
    b'device_name=P011\ndevice_type=1-0050F204-1\n'
    b'driver_param=mta_p2p_initial=1 control_port=0\n')


class GoOwnerError(RuntimeError):
    def __init__(self, code):
        self.code = code
        RuntimeError.__init__(self, code)


def _fail(code): raise GoOwnerError(code) from None


class GoGroupPreparation(object):
    """Once-issued private preparation, explicitly NOT an RF-ready capability."""
    __slots__ = ('owner', 'reservation', 'canonical', 'frequency', 'wire')
    def __init__(self, owner, reservation, canonical, frequency):
        for name, value in (('owner', owner), ('reservation', reservation), ('canonical', canonical),
                ('frequency', frequency), ('wire', ('P2P_GROUP_ADD freq=%d' % frequency).encode('ascii'))):
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable GO preparation')
    def __repr__(self): return '<private requested GROUP_ADD preparation; RF unavailable>'


class GoRestoreObservation(object):
    """Actual first-slice filesystem facts, never stock/network restoration."""
    __slots__ = ('owner', 'canonical', 'closed_facts', 'marker_cleared', 'unmutated_reconciled')
    def __init__(self, owner):
        native = owner.store
        for name, value in (('owner', owner), ('canonical', native.current),
                ('closed_facts', native.closed_facts()), ('marker_cleared', native.marker_cleared),
                ('unmutated_reconciled', native.logical_restored and all(a and c for a, c in native.closed_facts()))):
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable GO cleanup observation')
    def __repr__(self): return '<private unmutated GO filesystem cleanup observation>'


class GoOwner(object):
    """Original owner retained through one reserve/preparation/restore lifetime.

    This concrete first slice intentionally provides no submit() implementation
    pretending to have a native bootstrap. A future revision must add actual
    create/Actor/watchdog/controller producers before any GROUP_ADD transmission.
    It must consume these original facts, not turn a copied preparation into a
    generic bool/callback/CLIENT or GO ScopeProof permission.
    """
    def __init__(self, run_token, candidate_sha, task_id, original_until, _io=None, _clock=None):
        self.worker = threading.current_thread()
        self.store = store.GoReservationStore(run_token, candidate_sha, task_id,
            original_until, _io=_io, _clock=_clock)
        self.store.bind(self)
        self.reservation = self.preparation = self.restore_observation = None
        self.reserve_called = self.prepare_called = self.restore_called = False
        self.cleanup_until = None
        self.failures = []
    def __repr__(self): return '<private original GO owner; native RF bootstrap unavailable>'

    def _same_worker(self):
        if threading.current_thread() is not self.worker or self.store.owner is not self or self.store.worker is not self.worker:
            _fail('wrong_owner')

    def reserve(self):
        with self.store.mutex:
            self._same_worker()
            if self.reserve_called or self.restore_called: _fail('already_attempted')
            self.reserve_called = True
            try:
                result = self.store.reserve()
                self.reservation = result  # Retain actual source before validation.
                if type(result) is not store.GoCanonical or result is not self.store.current or \
                        result.issuer is not self.store.issuer or result.record.phase != 'reserved' or result.record.rf_requested is not False:
                    _fail('reservation_unknown')
                return result
            except BaseException as error:
                self.failures.append(error); raise

    def prepare_group_add(self, requested_frequency):
        """Persist requested native V4 wire intent; no channel or RF claim."""
        with self.store.mutex:
            self._same_worker()
            if self.prepare_called or self.restore_called or self.reservation is None or \
                    self.reservation is not self.store.current or self.failures:
                _fail('preparation_unavailable')
            self.prepare_called = True
            try:
                canonical = self.store.prepare_group_add(requested_frequency)
                if type(canonical) is not store.GoCanonical or canonical is not self.store.current or \
                        canonical.issuer is not self.store.issuer or canonical.record.phase != 'group_add_prepared' or \
                        canonical.record.facts_key() != self.reservation.record.facts_key():
                    _fail('preparation_unknown')
                self.preparation = GoGroupPreparation(self, self.reservation, canonical, requested_frequency)
                return self.preparation
            except BaseException as error:
                self.failures.append(error); raise

    def submit_group_add(self, original_preparation):
        """Missing real bootstrap is an explicit refusal, not a stub success."""
        self._same_worker()
        if original_preparation is not self.preparation or type(original_preparation) is not GoGroupPreparation or \
                original_preparation.owner is not self:
            _fail('wrong_preparation')
        _fail('native_go_bootstrap_not_implemented')

    def restore(self):
        with self.store.mutex:
            self._same_worker()
            if self.restore_called: _fail('restore_already_attempted')
            self.restore_called = True
            # Independent fixed close/reconcile period issued ONCE. It never
            # updates the original active until or authorizes network activity.
            try: self.cleanup_until = self.store._now(False) + store.CLEANUP_SECONDS
            except BaseException as error: self.failures.append(error)
            # Even an invalid/regressed clock reaches the store's close-only
            # finally. No file mutation is admitted without a valid fixed cap.
            try: self.store.restore_unmutated(self.cleanup_until)
            except BaseException as error: self.failures.append(error)
            self.restore_observation = GoRestoreObservation(self)
            return self.restore_observation

    def status(self):
        value = self.store.status()
        value['group_add_requested_prepared'] = self.preparation is not None
        value['group_add_transmitted'] = False
        value['original_worker_consistent'] = threading.current_thread() is self.worker
        return value
