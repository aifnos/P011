"""One real startup-preparation authorization; no Native/RF/restore grant.

Only the authenticated fixed send Owner constructs this after actual held
source/helper/assets readback and one original Parent readonly collection.
requested is the trusted constructor profile, never HTTP/capability input.
available -> claim -> attach_session -> allows are separate phases: a claimed
task never has to become available again. Original revocation cannot extend a
deadline or block cleanup. Default unrequested policy remains unavailable.
The actual F93 still performs fresh baseline/reservation/all native RF checks.
All cross-thread checks below are passive original-ledger reads plus the same
time.monotonic deadline; no Parent/context/Proc/fs/helper method is invoked.
Python 3.5; no injected IO, clock, path, callback or admission boolean.
"""
import math
import sys
import threading
import time
import types


SCHEMA = 'p011-formal-send-startup-trial-v1'
ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v1/runtime'
MAX_ASSETS = 71
MAX_ROWS = 9


class SendTrialError(ValueError):
    pass


def _fail(code):
    raise SendTrialError(code) from None


class FixedSendTrial(object):
    def __init__(self, owner, requested):
        self.owner = self._owner_original = owner
        self.state = self._state_original = owner.state
        self.requested = self._requested_original = requested
        self.until = self._until_original = owner.original_until
        self.clock = self._clock_original = owner.clock
        self.worker = self._worker_original = owner.worker
        self.loader = self._loader_original = owner.loader
        self.parent = self._parent_original = owner.send_preflight_parent
        self.report = self._report_original = owner.send_preflight_report
        self.claimed = self.session = None
        self.claimed_original = self.session_original = self.claim_originals = None
        self.claim_count = 0
        self.revoked = False
        self.revoke_reason = None
        self._lock = self._lock_original = threading.RLock()
        self.failure = None
        self._retained = []
        self._retained_original = self._retained
        self._epoch = self.state.native_epoch
        self._defs = self._defs_original = []
        self._construction_context()
        self._retain_startup()

    def __repr__(self):
        return '<original one-shot send preparation; Native/RF unverified>'

    def _attr(self, target, name):
        value = getattr(target, name)
        self._retained.append((target, name, value))
        return value

    def _definition(self, target, name):
        value = getattr(target, name)
        self._defs.append((target, name, value))
        return value

    def _construction_context(self):
        owner_module = sys.modules.get('mta_client_service_owner')
        own = sys.modules.get('mta_send_trial')
        service = sys.modules.get('mta_service')
        owner = self.owner
        if (type(own) is not types.ModuleType or own.__dict__ is not globals() or
                own.__file__ != ROOT + '/mta_send_trial.py' or
                own.FixedSendTrial is not FixedSendTrial or
                type(owner_module) is not types.ModuleType or
                owner_module.__file__ != ROOT + '/mta_client_service_owner.py' or
                type(owner) is not owner_module.FixedStateServiceOwner or
                type(owner.io) is not owner_module._LinuxIo or owner.io is not owner.original_io or
                type(service) is not types.ModuleType or
                service.__file__ != ROOT + '/mta_service.py' or type(self.state) is not service.State or
                type(self.requested) is not bool or self.requested is not owner.send_trial_requested or
                owner._send_trial_requested_original is not self.requested or
                owner.worker is not threading.current_thread() or
                type(self.until) is not float or not math.isfinite(self.until) or
                not 0 < self.until < 2 ** 53 or owner.until is not self.until or
                owner.loader._original_until is not self.until or
                owner.clock is not owner.loader.clock or
                self.clock is not time.monotonic or
                owner.started is not True or owner.state_complete is not True or
                owner.server_called is not False or owner.stop_called is not False or
                owner.close_called is not False or owner.send_trial is not self or
                owner._send_trial_original is not self or
                owner.loader.modules.get('mta_send_trial') is not own):
            _fail('send_trial_owner_context')
        ticket = owner.send_trial_ticket
        if (type(ticket) is not dict or ticket['partial'] is not self or
                ticket['creator'] is not FixedSendTrial or ticket['constructor_called'] is not True or
                ticket['constructed'] is not False or ticket['ended'] is not False):
            _fail('send_trial_constructor_ticket')
        self._owner_module = owner_module
        self._own_module = own
        self._service = service
        self._owner_ticket = ticket

    def _retain_startup(self):
        owner, state = self.owner, self.state
        self._asset_rows = self._attr(owner, 'assets')
        self._asset_originals = tuple(self._asset_rows)
        if (type(self._asset_rows) is not list or len(self._asset_rows) != MAX_ASSETS or
                any(row['unknown'] is not False or row['closed'] is not True or
                    type(row['raw']) is not bytes or row['failure'] is not None for row in self._asset_rows)):
            _fail('send_trial_assets_unknown')
        self._asset_facts = tuple(tuple((key, row.get(key)) for key in
            ('path', 'fd', 'metadata', 'raw', 'attempted', 'closed', 'unknown', 'failure'))
            for row in self._asset_rows)
        self._probes = self._attr(owner, 'probe_rows')
        self._probe_originals = tuple(self._probes)
        if state.probe_actors is not self._probes or not self._service.State._probes_closed(state):
            _fail('send_trial_probes_unknown')
        self._probe_facts = tuple(tuple(sorted(row.items())) for row in self._probes)
        for module in (self._owner_module, self._service, self._own_module):
            self._attr(module, '__dict__')
        for name in ('State', 'Operation', 'TransferSession'):
            self._definition(self._service, name)
        for name in ('__init__', '_attr', '_definition', '_construction_context', '_retain_startup',
                     '_parent_inventory_current', '_current', '_live', 'available', 'claim',
                     'attach_session', 'allows', 'revoke', 'closed', 'public_facts'):
            self._definition(FixedSendTrial, name)
        self._attr(state, '_original_service_until')
        self._attr(state, '_service_until_original')
        if state._service_until_original is not self.until or self._epoch != 0:
            _fail('send_trial_initial_state')
        self._preflight_ticket = self._attr(owner, 'send_preflight_ticket')
        if self.requested is False:
            if self.parent is not None or self.report is not None or self._preflight_ticket is not None:
                _fail('send_trial_unrequested_preflight')
            self._parent_rows = self._parent_facts = None
            return
        parent, ticket = self.parent, self._preflight_ticket
        source = self.loader.modules.get('mta_go_readonly_parent')
        if (type(source) is not types.ModuleType or sys.modules.get('mta_go_readonly_parent') is not source or
                source.__file__ != ROOT + '/mta_go_readonly_parent.py' or
                type(parent) is not source.ReadonlyDataParent or type(ticket) is not dict or
                ticket['partial'] is not parent or ticket['returned'] is not parent or
                ticket['constructed'] is not True or ticket['ended'] is not True or
                ticket['unknown'] is not False or ticket['failure'] is not None or
                ticket['collect_return'] is not self.report or
                parent.worker is not self.worker or parent.clock is not self.clock or
                parent.service_until is not self.until or parent.task_until is not self.until or
                parent.closed is not True or parent.unknown is not False or parent.failure is not None or
                parent.ended is not True or parent.close_attempted is not True or
                parent.result is not self.report or parent.report is not self.report or
                parent.result_original is not self.report or
                type(self.report) is not parent.packet_functions_original[4] or
                parent.reader.value is not self.report or parent.reader.ended is not True or
                parent.reader.failure is not None or self.report.source_count != 38 or
                self.report.source_manifest_sha256 !=
                '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'):
            _fail('send_trial_actual_preflight_unknown')
        self._parent_source = source
        self._definition(source, 'ReadonlyDataParent')
        self._parent_rows = self._attr(parent, 'rows')
        if (parent.rows is not parent.rows_original or parent.row_history is not parent.row_history_original or
                len(parent.rows) != MAX_ROWS or len(parent.row_history) != MAX_ROWS or
                any(a is not b for a, b in zip(parent.rows, parent.row_history)) or
                any(row['unknown'] is not False or row['closed'] is not True or
                    row['close_failure'] is not None for row in parent.rows)):
            _fail('send_trial_preflight_inventory')
        self._parent_row_originals = tuple(parent.rows)
        self._parent_facts = tuple(tuple(sorted(row.items())) for row in parent.rows)
        process = self._attr(parent, 'process_attempt')
        if (process is not parent.process_attempt_original or process['returned'] is not True or
                process['unknown'] is not False or process['wait_called'] is not True or
                process['reaped'] is not True or process['waited'] is not True or
                process['wait_return'] != 0 or process['wait_error'] is not None or
                process['wait_ticket'] is not process['wait_ticket_original'] or
                process['pipes'][0]['eof'] is not True or process['pipes'][1]['eof'] is not True or
                process['pipes'][0]['eof_ticket'][-1] != b'' or
                process['pipes'][1]['eof_ticket'][-1] != b''):
            _fail('send_trial_preflight_eof_reap')
        self._process = process
        self._process_facts = tuple(sorted(process.items()))
        self._pipe_originals = tuple(process['pipes'])
        self._pipe_facts = tuple(tuple(sorted(row.items())) for row in process['pipes'])
        self._eof_originals = tuple(row['eof_ticket'] for row in process['pipes'])
        self._wait_original = process['wait_ticket_original']
        self._parent_report_refs = tuple(self._attr(parent, name) for name in
            ('report', 'result', 'result_original', 'packet_functions_original',
             'binding_original', 'period_original', 'reader', 'reader_original',
             'process', 'process_original', 'process_methods', 'rows_original',
             'row_history', 'row_history_original', 'closed', 'unknown', 'failure',
             'ended', 'close_attempted'))
        if not self._parent_inventory_current():
            _fail('send_trial_preflight_closed_ledger')

    def _parent_inventory_current(self):
        # Passive exact saved wait/EOF/FD inventory; do not invoke Parent methods,
        # Popen.poll, wait, fileno, descriptor IO, clock or fresh observation.
        parent, process = self.parent, self._process
        if (process is not parent.process_attempt or process is not parent.process_attempt_original or
                parent.process is not parent.process_original or parent.rows is not parent.rows_original or
                parent.row_history is not parent.row_history_original or
                parent.process.returncode is not process['wait_return'] or process['wait_return'] != 0 or
                process['pipes'] is not dict(self._process_facts)['pipes'] or len(process['pipes']) != 2 or
                parent.close_errors or parent.unknown is not False or parent.closed is not True or
                type(self._wait_original) is not tuple or len(self._wait_original) != 6 or
                process['wait_ticket'] is not self._wait_original or
                self._wait_original[0] is not parent.process or
                self._wait_original[1] is not parent.process_pid or
                self._wait_original[2] is not parent.process_methods[1] or
                self._wait_original[3] is not process['wait_return']):
            return False
        for index, row in enumerate(process['pipes']):
            eof = self._eof_originals[index]
            if (row is not self._pipe_originals[index] or row['eof_ticket'] is not eof or
                    type(eof) is not tuple or len(eof) != 7 or eof[0] is not parent.process or
                    eof[1] is not parent.process_pid or eof[2] is not row or
                    eof[3] is not row['raw_original'] or eof[4] is not row['fd_original'] or
                    eof[5] is not row['metadata_original'] or eof[6] != b'' or
                    self._wait_original[4 + index] is not eof or row['eof'] is not True or
                    row['closed'] is not True or row['unknown'] is not False or
                    row['raw_original'].closed is not True):
                return False
        return True

    def _current(self, state):
        owner = self.owner
        if (self.owner is not self._owner_original or state is not self._state_original or
                self.state is not state or owner.state is not state or
                self.until is not self._until_original or owner.original_until is not self.until or
                owner.until is not self.until or self.clock is not self._clock_original or
                owner.clock is not self.clock or self.loader is not self._loader_original or
                owner.loader is not self.loader or self.requested is not self._requested_original or
                owner.send_trial_requested is not self.requested or
                owner._send_trial_requested_original is not self.requested or
                owner.send_trial is not self or owner._send_trial_original is not self or
                state._send_trial is not self or state._send_trial_original is not self or
                self._lock is not self._lock_original or self._retained is not self._retained_original or
                self._defs is not self._defs_original or self.failure is not None):
            _fail('send_trial_original_changed')
        if any(getattr(target, name, None) is not original for target, name, original in self._retained):
            _fail('send_trial_startup_changed')
        if any(getattr(target, name, None) is not original for target, name, original in self._defs):
            _fail('send_trial_definition_changed')
        if (sys.modules.get('mta_client_service_owner') is not self._owner_module or
                sys.modules.get('mta_service') is not self._service or
                sys.modules.get('mta_send_trial') is not self._own_module or
                len(self._asset_rows) != len(self._asset_originals) or
                any(a is not b for a, b in zip(self._asset_rows, self._asset_originals)) or
                tuple(tuple((key, row.get(key)) for key in
                    ('path', 'fd', 'metadata', 'raw', 'attempted', 'closed', 'unknown', 'failure'))
                    for row in self._asset_rows) != self._asset_facts):
            _fail('send_trial_assets_changed')
        if (state.probe_actors is not self._probes or len(self._probes) < len(self._probe_originals) or
                any(a is not b for a, b in zip(self._probe_originals, self._probes)) or
                tuple(tuple(sorted(row.items())) for row in self._probe_originals) != self._probe_facts or
                any(row['closed'] is not True or row['failure'] is not None or
                    row['spawn_pending'] is not False or row['spawn_unknown'] is not False
                    for row in self._probe_originals)):
            _fail('send_trial_probes_changed')
        if self.requested:
            parent = self.parent
            if (parent is not self._parent_original or self.report is not self._report_original or
                    owner.send_preflight_parent is not parent or owner.send_preflight_report is not self.report or
                    len(parent.rows) != len(self._parent_row_originals) or
                    any(a is not b for a, b in zip(parent.rows, self._parent_row_originals)) or
                    tuple(tuple(sorted(row.items())) for row in parent.rows) != self._parent_facts or
                    tuple(sorted(self._process.items())) != self._process_facts or
                    tuple(tuple(sorted(row.items())) for row in self._process['pipes']) != self._pipe_facts or
                    not self._parent_inventory_current()):
                _fail('send_trial_preflight_changed')
        return True

    def _live(self, state):
        self._current(state)
        now = self.clock()
        return (type(now) is float and math.isfinite(now) and now < self.until and
                self.requested is True and not self.revoked and not state.closing and
                not self.owner.stop_called and not self.owner.close_called)

    def available(self, state):
        with self._lock:
            try:
                return (self._live(state) and self.claim_count == 0 and self.claimed is None and
                        self.session is None and state.native_epoch == self._epoch and
                        state.operation is None and state.session is None and
                        not state.wifi_restore_pending and not state.radio_restore_pending)
            except BaseException:
                return False

    def claim(self, state, operation):
        with self._lock:
            # Claim follows State's newly retained operation; do NOT call
            # available(), whose idle predicate correctly no longer holds.
            if (not self._live(state) or self.claim_count != 0 or self.claimed is not None or
                    type(operation) is not self._service.Operation or operation is not state.operation or
                    operation.kind != 'go_send' or operation.epoch != self._epoch + 1 or
                    state.native_epoch != operation.epoch or operation.session is not None):
                _fail('send_trial_claim_changed')
            self.claimed = self.claimed_original = operation
            self.claim_count = 1
            return operation

    def attach_session(self, state, operation, session):
        with self._lock:
            if (not self._live(state) or operation is not self.claimed_original or
                    self.claimed is not operation or self.claim_count != 1 or
                    self.session is not None or type(session) is not self._service.TransferSession or
                    operation.session is not session or state.session is not session or
                    session._lease_owner is not operation or session.cancelled is not operation.cancelled or
                    session._direction != 'send' or
                    session._absolute_until_original != self.until):
                _fail('send_trial_session_changed')
            self.session = self.session_original = session
            self.claim_originals = (state, operation, session, operation.epoch, operation.cancelled,
                                   session._worker, self.until)
            return session

    def allows(self, state, operation):
        with self._lock:
            try:
                if not self._live(state): return False
                refs = self.claim_originals
                return (self.claim_count == 1 and type(refs) is tuple and len(refs) == 7 and
                        self.claimed is operation and self.claimed_original is operation and
                        self.session is self.session_original and self.session is operation.session and
                        operation is state.operation and operation.kind == 'go_send' and
                        state.session is self.session and operation.epoch == state.native_epoch and
                        refs[0] is state and refs[1] is operation and refs[2] is self.session and
                        refs[3] is operation.epoch and refs[4] is operation.cancelled and
                        refs[5] is self.session._worker and refs[6] is self.until and
                        not operation.cancelled.is_set())
            except BaseException:
                return False

    def revoke(self, state, reason):
        # Stop-only; do not check an expired clock or call any cleanup/IO.
        with self._lock:
            if state is not self._state_original or reason not in (
                    'owner_closed', 'owner_stopped', 'cancelled', 'state_closing',
                    'operation_failed', 'session_failed', 'expired'):
                _fail('send_trial_revoke_context')
            if not self.revoked:
                self.revoked = True
                self.revoke_reason = reason
            return True

    def closed(self, state):
        with self._lock:
            try:
                self._current(state)
                return self.revoked is True and self.claim_count in (0, 1)
            except BaseException:
                return False

    def public_facts(self, state):
        return dict(requested=self.requested, available=self.available(state),
                    claim_count=self.claim_count, revoked=self.revoked,
                    preparation_authorized=self.claim_count == 1,
                    native_started_verified=False, production_admitted=False,
                    restoration_verified=False)
