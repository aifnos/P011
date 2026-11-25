"""Private State worker -> native CLIENT Parent receive bridge, SOURCE only.

No Qt rewrite, legacy WifiBackend, gateway/default TCP connector, plaintext
receive API, signal, alternate recovery or production-availability claim. The
trusted deployment factory is intentionally absent by default. It must load an
actually authenticated fixed candidate bound to this original GATT handoff.
The held-directory F pin below is a SOURCE binding, not full HOST/device approval.
UI threads can enqueue one file-consent choice, never write Parent pipes.
The F owns all network/Receiver/Consent work and restores its own originals;
the original State worker makes Parent.finish actually wait/reap/check closure.
State's helper/key/radio and TransferSession thread closure remain separate.
"""
import math
import threading

import mta_client_connect_handoff as handoffs
import mta_client_control_frame as state_codec
import mta_transfer_session as sessions
import mta_client_receive_factory as receive_factories

PARENT_SOURCE_SHA = '3f046452b5600685bf250a9b6a0091feeac7632b5461f99d820f98498e5355b2'
CODEC_SOURCE_SHA = '66eae58a95eaf8344934d15aca2685de1c176b8408a56786995e9f9078c6032c'
POLL_SECONDS, FINISH_SECONDS = .05, 90.0
_CODES = frozenset(('invalid_owner', 'wrong_worker', 'already_started', 'deployment_unavailable',
    'deployment_unknown', 'parent_unknown', 'choice_changed', 'choice_taken', 'cancelled',
    'expired', 'clock_unknown', 'receive_failed'))


class StateBridgeError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'parent_unknown'
        RuntimeError.__init__(self, self.code)


def _fail(code):
    raise StateBridgeError(code) from None


class StateClientBridge(object):
    """One existing Operation/Session worker, one Parent, one UI choice slot.

    Construct and retain on Operation in the actual State worker after creation
    of its helper/key and ReceiveConnectHandoff. The helper reader captures the
    GATT event through that handoff. Then the same worker calls run(), which
    decrypts/claims only through the original handoff. No method starts threads.
    Source SHA constants document the reviewed dependencies; they are not a
    substitute for the trusted factory and DeploymentLoader authentication.
    """
    def __init__(self, state, operation, exact_handoff, deployment_factory=None):
        if (type(exact_handoff) is not handoffs.ReceiveConnectHandoff or
                exact_handoff.state is not state or exact_handoff.operation is not operation or
                exact_handoff.worker is not threading.current_thread() or
                deployment_factory is not None and not callable(deployment_factory)):
            _fail('invalid_owner')
        self.state, self.operation, self.handoff = state, operation, exact_handoff
        self.session, self.worker = exact_handoff.session, exact_handoff.worker
        self.epoch, self.cancelled = operation.epoch, operation.cancelled
        self.clock = exact_handoff.clock  # Original State/handoff clock, not a separate deadline oracle.
        self._clock_original = self.clock
        self._state_codec = state_codec
        self.deadline = None
        self._last = None
        self._factory = deployment_factory
        self._wake = threading.Event()
        self._prompt = self._choice = None
        self._choice_taken = self._cancel_sent = False
        self._executor = self.deployment = self.parent = None
        self.started = self.running = False
        self.reason = 'not_started'
        self.result = None
        self._restore_snapshot = False  # Display cache only; finalizers call restoration_verified afresh.
        self.failures = []  # Private originals, never public error text.
        self.factory_ticket = {'started': False, 'returned': None, 'authenticated': False}
        self.parent_ticket = {'started': False, 'returned': None}
        self.finish_ticket = {'started': False, 'returned': None, 'complete': False}
        self._receive = {'state': 'not_started', 'prompt': None, 'download_bytes': 0,
            'verified_file_bytes': 0, 'result': None}
        with state.lock:
            if getattr(operation, 'client_bridge', None) is not None: _fail('invalid_owner')
            operation.client_bridge = self  # Retain the actual pure constructor before owner checks.
            self._owners(True)
            exact_handoff._check()

    def __repr__(self):
        return '<private native State receive bridge>'

    def _owners(self, worker=False):
        """Original caller identities only; not network/restore authority."""
        op, state = self.operation, self.state
        if (state.operation is not op or state.session is not self.session or
                state.worker is not self.worker or op.session is not self.session or
                type(self.session) is not sessions.TransferSession or self.session._worker is not self.worker or
                op.cancelled is not self.cancelled or self.session.cancelled is not self.cancelled or
                op.kind != 'receive' or op.consent is not True or
                type(self.epoch) is not int or op.epoch != self.epoch or state.native_epoch != self.epoch or
                type(self.handoff) is not handoffs.ReceiveConnectHandoff or
                self.handoff.state is not state or self.handoff.operation is not op or
                self.handoff.session is not self.session or self.handoff.worker is not self.worker or
                state.helper is not self.handoff.helper or op.helper is not self.handoff.helper or
                state.key is not self.handoff.key or op.key is not self.handoff.key or
                state.crypto is not self.handoff.crypto or op.crypto is not self.handoff.crypto or
                self.clock is not self._clock_original or self.handoff.clock is not self._clock_original or
                self._state_codec is not state_codec or
                self._state_codec.protocol is not self.handoff.claim_frame.__func__.__globals__.get('protocol') or
                getattr(op, 'client_bridge', self) is not self):
            _fail('invalid_owner')
        if worker and threading.current_thread() is not self.worker: _fail('wrong_worker')

    def _now(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(float(now)) or not 0 <= now < 1e12 or
                self._last is not None and now < self._last): _fail('clock_unknown')
        self._last = float(now)
        return self._last

    def submit_choice(self, exact_operation, prompt_id, accepted):
        """Called by State.action under or outside State.lock; no Parent IO."""
        with self.state.lock:
            self._owners()
            prompt = self._prompt
            # UI observes a deadline but does not advance the worker's monotonic
            # observation chain or invoke Parent/Loader/pipe methods.
            now = self.clock()
            if (exact_operation is not self.operation or type(prompt_id) is not str or type(accepted) is not bool or
                    not self.running or self.cancelled.is_set() or self.state.closing or prompt is None or
                    self._receive['state'] != 'awaiting_confirmation' or prompt.prompt_id != prompt_id or
                    type(now) not in (int, float) or not math.isfinite(float(now)) or
                    not 0 <= now < prompt.until): _fail('choice_changed')
            if self._choice is not None or self._choice_taken: _fail('choice_taken')
            self._choice = (prompt, accepted)  # One original prompt, not a copied JSON authority object.
            self._wake.set()
        return True  # Enqueued only, NOT consent acknowledged by F.

    def request_cancel(self, exact_operation):
        """UI only sets the original Event; the original worker writes CANCEL."""
        with self.state.lock:
            self._owners()
            if exact_operation is not self.operation: _fail('invalid_owner')
            self.cancelled.set()
            self._choice = None
            self._wake.set()

    def _cancel_parent(self):
        self._owners(True)
        if self.parent is not None and not self._cancel_sent:
            self._cancel_sent = True
            self._executor.ParentExecutor.cancel(self.parent)

    def _observe(self):
        """Only actual Parent bounded frames. Never read the F's remote socket."""
        self._owners(True)
        parent, executor = self.parent, self._executor
        executor.ParentExecutor.poll(parent)
        if parent.failures: _fail('parent_unknown')
        observed = executor.ParentExecutor.receive_status(parent)
        self._project(observed)
        return observed

    def _project(self, observed):
        """Only a just-returned actual Parent receive observation is projected."""
        with self.state.lock:
            self._owners(True)
            prompt = observed['prompt']
            if prompt is not None:
                if self._prompt is not None and self._prompt is not prompt: _fail('choice_changed')
                self._prompt = prompt
            self._receive = observed
            if observed['result'] is not None:
                self.result = dict(observed['result'])
                self.operation.result = dict(self.result)
            self.state.transfer = {'archiveBytes': observed['download_bytes'],
                'bytes': observed['verified_file_bytes'],
                'totalBytes': prompt.total_size if prompt is not None else 0,
                'totalFiles': prompt.file_count if prompt is not None else 0,
                'filesDone': self.result['file_count'] if self.result is not None and self.result['outcome'] in ('committed', 'saved_failed') else 0,
                'localCommitVerified': self.result is not None and self.result['outcome'] in ('committed', 'saved_failed'),
                'peerAckVerified': self.result is not None and self.result['peer_ack_verified'] is True}
            if observed['state'] == 'awaiting_confirmation' and prompt is not None:
                self.state.request = {'id': prompt.prompt_id, 'name': prompt.sender_name,
                    'fileName': prompt.file_name, 'fileCount': prompt.file_count,
                    'totalBytes': prompt.total_size}
                self.state.state = 'awaiting_confirmation'
            else:
                self.state.request = None
                self.state.state = 'transferring' if observed['state'] in ('accepted', 'receiving') else 'connecting'

    def _answer_queued(self):
        self._owners(True)
        with self.state.lock:
            self._owners(True)
            choice = self._choice
            if choice is None: return
            self._choice = None
            self._choice_taken = True  # Retain the attempt before the original pipe write.
            if (choice[0] is not self._prompt or self.cancelled.is_set() or self.state.closing or
                    self._receive['state'] != 'awaiting_confirmation'): _fail('choice_changed')
        # Do not hold State.lock while Parent takes its private lock and can
        # authenticate deployment/write pipes. UI never calls this method.
        self._executor.ParentExecutor.answer_receive(self.parent, choice[0], choice[1])
        if self.parent.failures: _fail('parent_unknown')

    def run(self):
        """Existing TransferSession task body; no legacy receive fallback."""
        self._owners(True)
        if self.started: _fail('already_started')
        self.started = self.running = True
        failure = None
        try:
            if self._factory is None: _fail('deployment_unavailable')
            self.handoff._check()
            task_until = self.session._task_deadline
            if (type(task_until) not in (int, float) or not math.isfinite(float(task_until)) or
                    self._now() >= min(task_until, self.handoff.deadline)): _fail('expired')
            self.deadline = min(float(task_until), self.handoff.deadline)
            handoffs.ReceiveConnectHandoff.decrypt(self.handoff)
            import mta_client_executor as executor
            self._executor = executor
            self.factory_ticket['started'] = True
            value = self._factory(self.handoff)
            self.factory_ticket['returned'] = value  # Retain even a malformed factory return.
            if (type(value) is not executor.LoadedDeployment or
                    value.modules.get('mta_client_executor') is not executor or
                    value.manifest.executor_sha != PARENT_SOURCE_SHA or
                    executor.CONNECT_CODEC_SHA != CODEC_SOURCE_SHA): _fail('deployment_unknown')
            value.loader.authenticate(value)
            self.factory_ticket['authenticated'] = True
            self.deployment = value
            self._owners(True)
            self.handoff._check()
            self.parent_ticket['started'] = True
            parent = executor.ParentExecutor(value, _clock=self.clock, _handoff=self.handoff,
                _handoff_type=handoffs.ReceiveConnectHandoff,
                # Caller-side codec shares the original handoff protocol. The
                # loaded F codec is a different exact type and independently
                # verifies/decode-checks the wire in Parent.send_connect.
                _handoff_codec=self._state_codec)
            self.parent_ticket['returned'] = self.parent = parent
            # Same public start signature. The pinned Parent itself captures
            # the original Handoff/Session cap under State.lock and puts its
            # canonical --parent-until in argv BEFORE the F can perform RF.
            # No caller/UI deadline or compatibility boolean is passed here.
            executor.ParentExecutor.start(parent, 300)
            while True:
                self._owners(True)
                if self.cancelled.is_set() or self.state.closing or self._now() >= self.deadline:
                    self.reason = 'cancelled' if self.cancelled.is_set() or self.state.closing else 'expired'
                    self._cancel_parent()
                    break
                observed = self._observe()
                if not parent.connect_attempted and parent.frames and parent.frames[-1]['client_init_ready'] is True:
                    executor.ParentExecutor.send_connect(parent, self.handoff)
                    if parent.failures: _fail('parent_unknown')
                if observed['result'] is not None: break
                if parent.frames and parent.frames[-1]['done'] or all(parent.eof.values()): break
                self._answer_queued()
                self._wake.wait(POLL_SECONDS)
                self._wake.clear()
            self.reason = self.result['outcome'] if self.result is not None else self.reason
        except BaseException as error:
            self.failures.append(error)
            self.reason = error.code if type(error) is StateBridgeError else 'parent_unknown'
            failure = error
        finally:
            try:
                self._finish_parent()
            finally:
                with self.state.lock:
                    self.running = False
                    self._choice = None
                    if self.state.operation is self.operation:
                        self.state.request = None
                        self.state.discoverable = False
                        self.state.state = 'restoring'
                self.restoration_verified()  # Outside State.lock; Parent acquires its own lock.
        committed = self.result is not None and self.result['outcome'] == 'committed'
        # A later pipe/restore failure cannot erase an already validated local
        # commit. Its pending Parent remains separately retained and blocks reuse.
        if failure is not None and not committed: raise failure
        if self.result is not None and self.result['outcome'] in ('failed', 'saved_failed'): _fail('receive_failed')
        return sessions.Outcome(dict(self.result) if self.result is not None else None,
            bool(committed), bool(committed and self.result['peer_ack_verified']))

    def _finish_parent(self):
        """Same original worker, once; no kill/restart/renewed restore attempt."""
        self._owners(True)
        if self.parent is None: return
        if self.finish_ticket['started']: _fail('parent_unknown')
        self.finish_ticket['started'] = True
        try:
            value = self._executor.ParentExecutor.finish(self.parent, FINISH_SECONDS)
            self.finish_ticket['returned'] = value
            self.finish_ticket['complete'] = True
            # finish drains late bounded result frames before proving actual
            # exit. Local commit remains separate even when recovery is pending.
            observed = self._executor.ParentExecutor.receive_status(self.parent)
            self._project(observed)
        except BaseException as error:
            self.failures.append(error)

    def _factory_publication_closed_v69(self):
        """Original fixed-factory FD closure only; not success/RF restoration.

        The actual factory retains its failed publication inventory. Generic
        callables cannot certify this pre-Parent branch. No clock, IO, Parent,
        CONNECT claim or active Handoff check is performed by this passive read.
        """
        factory = self._factory
        exact_type = receive_factories.FixedReceiveDeploymentFactory
        if type(factory) is not exact_type or not self.factory_ticket['started']:
            return False
        facts = exact_type.closed_publication_facts(factory, self.handoff)
        if type(facts) is not tuple or len(facts) != 9:
            return False
        attempt = facts[2]
        if type(attempt) is not receive_factories._PublicationAttempt:
            return False
        return (type(factory._attempts) is list and any(attempt is row for row in factory._attempts) and
            attempt.closed_facts is facts and attempt.closed_owners is facts[7] and attempt.ended is True and
            facts[0] is factory and attempt.factory is factory and
            facts[1] is self.handoff and attempt.handoff is self.handoff and
            facts[3] is self and attempt.bridge is self and
            facts[4] is self.session and attempt.session is self.session and
            facts[5] is self.worker and attempt.worker is self.worker and
            type(facts[6]) is int and 1 <= facts[6] <= 0x7fffffff and
            type(attempt.pid) is int and attempt.pid == facts[6] and
            type(facts[7]) is tuple and facts[8] is True)

    def restoration_verified(self):
        """Call outside State.lock; not helper/key/radio/Session closure."""
        verified = False
        try:
            self._owners()
            parent = self.parent
            if self.started and parent is None:
                verified = (not self.running and not self.parent_ticket['started'] and
                    (not self.factory_ticket['started'] or self.factory_ticket['authenticated'] or
                     self._factory_publication_closed_v69()))
            elif (self.started and parent is not None and parent is self.parent_ticket['returned'] and
                    type(parent) is self._executor.ParentExecutor and not self.running and
                    self.finish_ticket['started'] and self.finish_ticket['complete']):
                # Its actual passive status, not a child event, returned join or
                # saved UI label. Do not acquire Parent while holding State.lock.
                value = self._executor.ParentExecutor.status(parent)
                self._owners()
                verified = (value['done'] is True and value['reason'] == 'restored' and
                    value['resource_pending'] is False and value['parent_waited'] is True and
                    value['parent_absence_verified'] is True and value['parent_resources_closed'] is True and
                    value['stdout_eof_observed'] is True and value['stderr_eof_observed'] is True)
        except BaseException:
            verified = False
        with self.state.lock: self._restore_snapshot = bool(verified)
        return bool(verified)

    def status(self):
        """Cached local UI summary only: no Parent/pipe/clock/FS or lock inversion."""
        with self.state.lock:
            verified = self._restore_snapshot
            result = dict(self.result) if self.result is not None else None
            return {'started': self.started, 'running': self.running, 'reason': self.reason,
                'deployment_factory_present': self._factory is not None,
                'choice_queued': self._choice is not None, 'choice_taken': self._choice_taken,
                'local_commit_verified': result is not None and result['outcome'] in ('committed', 'saved_failed'),
                'peer_ack_verified': result is not None and result['peer_ack_verified'] is True,
                'result': result, 'parent_restore_verified': self.parent is not None and verified,
                'no_parent_created_verified': self.parent is None and verified,
                'restore_pending': self.started and not verified,
                'helper_radio_verified': False, 'session_closed': False,
                'send_available': False, 'receive_available': False, 'phone_tested': False}
