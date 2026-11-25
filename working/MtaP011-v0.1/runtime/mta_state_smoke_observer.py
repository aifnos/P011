"""Private production-State no-RF lifecycle observer; not a device checker.

The trusted runner supplies a private synthetic root and pinned native paths.
No UI, admission checker, lock removal, journal recovery or capability override.
The HTTP accept loop is explicitly instrumented, not unchanged minhttp evidence.
"""
import math
import os
import socket
import threading
import time

import mta_service as service


MAX_HISTORY = 128
MAX_REPLY = 65536
CANCEL_BODY = b'{"action":"cancel"}'
PENDING = '/tmp/p011-mta-p2p-device.pending'


class ObserverError(RuntimeError):
    pass


def budget(value):
    if type(value) not in (int, float) or not 0 <= value <= 30 or not math.isfinite(value):
        raise ObserverError('invalid_budget')
    return float(value)


class _Replay:
    def __init__(self, data): self.data = data
    def read(self, size):
        result = self.data[:size]; self.data = self.data[size:]; return result


def _pending_exists():
    try: os.lstat(PENDING)
    except OSError as error:
        if error.errno == 2: return False
        raise
    return True


class _Dependencies:
    State = service.State
    Server = service.Server
    Handler = service.Handler
    socket = socket
    thread = staticmethod(threading.Thread)
    pending_exists = staticmethod(_pending_exists)
    evidence = 'PRODUCTION_OBSERVER_NOT_DEVICE_TEST'


def _server_type(deps):
    class RestrictedHandler(deps.Handler):
        def do_GET(self):
            if self.path not in ('/v1/status', '/v1/files'):
                self.reply(403, {'error': 'Smoke route denied'}); return
            deps.Handler.do_GET(self)

        def do_POST(self):
            # Production authorization, content-type/length/JSON parser and
            # State.action still run. Replay only the exact permitted body.
            if not self.authorized(): self.reply(403, {'error': 'Unauthorized'}); return
            if self.path != '/v1/action': self.reply(403, {'error': 'Smoke route denied'}); return
            if self.headers.get('Content-Length') != str(len(CANCEL_BODY)):
                self.reply(403, {'error': 'Smoke action denied'}); return
            data = self.rfile.read(len(CANCEL_BODY))
            if data != CANCEL_BODY: self.reply(403, {'error': 'Smoke action denied'}); return
            self.rfile = _Replay(data)
            deps.Handler.do_POST(self)

    class ObservedServer(deps.Server):
        def serve_forever(self):
            owner = self.observer
            while not self.stopping.is_set() and not owner._cancel.is_set():
                with owner._lock:
                    if len(owner._sockets) >= MAX_HISTORY:
                        owner._fault('history_limit'); return
                    owner._accepting += 1
                request = None
                try:
                    request, address = self.socket.accept()
                    saved = owner._adopt_socket(request, 'accepted')
                except deps.socket.timeout: continue
                except OSError:
                    if self.stopping.is_set() or owner._cancel.is_set(): return
                    owner._fault('accept_failed'); return
                except BaseException:
                    owner._fault('accept_unknown'); return
                finally:
                    with owner._lock: owner._accepting -= 1
                if self.stopping.is_set() or owner._cancel.is_set():
                    owner._close_socket(saved); continue
                if not self.slots.acquire(False):
                    owner._close_socket(saved); continue
                row = owner._make_thread(self.process, (request, address), 'request')
                if row['thread'] is None:
                    self.slots.release(); owner._close_socket(saved); return
                with self.worker_lock: self.workers[request] = row['thread']
                if not owner._start_thread(row):
                    # Unknown Thread.start may have run; never erase its owner.
                    self.stopping.set(); return

        def process(self, request, address):
            returned = False
            try: deps.Server.process(self, request, address); returned = True
            finally:
                # minhttp.process closes before removing its live map entry.
                # Retain exact socket and historical Thread after that removal.
                self.observer._record_process_close(request, returned)

    ObservedServer.smoke_handler = RestrictedHandler
    return ObservedServer


class StateSmokeObserver:
    def __init__(self, synthetic_root, bluez_helper, network_helper, _host_dependencies=None):
        if any(type(value) is not str or not value for value in (synthetic_root, bluez_helper, network_helper)):
            raise ObserverError('trusted_paths_required')
        self._deps = _host_dependencies if _host_dependencies is not None else _Dependencies()
        if _host_dependencies is not None and self._deps.evidence != 'HOST_FAKE_ONLY':
            raise ObserverError('host_fixture_scope_required')
        self._evidence = 'HOST_FAKE_ONLY' if _host_dependencies is not None else 'PRODUCTION_OBSERVER_NOT_DEVICE_TEST'
        self._root = synthetic_root; self._bluez = bluez_helper; self._network = network_helper
        self._lock = threading.RLock(); self._cancel = threading.Event()
        self.state = None; self.server = None; self._state_ctor_pending = False; self._state_ctor_unknown = False
        self._server_ctor_pending = False; self._server_ctor_unknown = False
        self._threads = []; self._sockets = []; self._sessions = []; self._probes = []
        self._probe_processes_pending = 0; self._probe_pipes_pending = 0
        self._accepting = 0; self._operations = 0; self._generation = 0
        self._opened = False; self._exercised = False; self._closing = False; self._close_running = False
        self._unknown = 0; self._reason = 'not_opened'; self._phase = 'prepared'
        self._ordinary_skipped = False; self._started_cleanup = False; self._http_verified = False
        self._state_closed = False; self._cached = {}
        self._cache(False)

    def _fault(self, reason):
        with self._lock:
            self._reason = reason; self._phase = 'pending'; self._unknown += 1; self._generation += 1
            self._cancel.set(); self._cache(False)

    def _cache(self, closed):
        # Values are filled only by explicit observer operations. status() does
        # not poll a State/backend, invoke callbacks, touch files or close owners.
        self._cached = {'evidence_scope': self._evidence, 'phase': 'closed' if closed else self._phase,
            'reason': self._reason, 'closed': closed is True, 'cleanup_pending': closed is not True,
            'ordinary_cancel_worker_skipped': self._ordinary_skipped,
            'started_cleanup_worker': self._started_cleanup,
            'cleanup_kind': 'SYNTHETIC_CLEANUP_NOT_TRANSFER', 'receive_worker_tested': False,
            'http_requests_verified': self._http_verified, 'state_close_verified': self._state_closed,
            'state_ctor_pending': self._state_ctor_pending, 'state_ctor_unknown': self._state_ctor_unknown,
            'server_ctor_pending': self._server_ctor_pending, 'server_ctor_unknown': self._server_ctor_unknown,
            'historical_threads': len(self._threads), 'historical_sockets': len(self._sockets),
            'historical_sessions': len(self._sessions), 'unknown_owners': self._unknown,
            'historical_probes': len(self._probes), 'probe_processes_pending': self._probe_processes_pending,
            'probe_pipes_pending': self._probe_pipes_pending,
            'probe_poll_observations': sum(row['poll_observed'] is True for row in self._probes),
            'probe_kill_attempts': sum(row['kill_attempted'] is True for row in self._probes),
            'probe_wait_attempts': sum(row['wait_attempted'] is True for row in self._probes),
            'probe_pipe_close_attempts': sum(row[key + '_close_attempted'] is True for row in self._probes for key in ('stdout', 'stderr')),
            'accept_operations_pending': self._accepting, 'exercise_operations_pending': self._operations,
            'rf_operations_requested': False, 'journal_recovery_requested': False}

    def status(self):
        with self._lock: return dict(self._cached)

    def _adopt_socket(self, raw, role):
        row = {'raw': raw, 'role': role, 'close_returned': False, 'unknown': False}
        with self._lock:
            self._sockets.append(row); self._generation += 1
            if len(self._sockets) > MAX_HISTORY: self._fault('history_limit')
        try:
            if type(raw) is not self._deps.socket.socket or raw.family != self._deps.socket.AF_INET or raw.type != self._deps.socket.SOCK_STREAM:
                row['unknown'] = True; self._fault('socket_contract_unknown')
        except BaseException:
            row['unknown'] = True; self._fault('socket_contract_unknown')
        return row

    def _close_socket(self, row):
        try: row['raw'].close(); row['close_returned'] = True
        except BaseException: row['close_returned'] = False
        return self._socket_closed(row)

    @staticmethod
    def _socket_closed(row):
        try:
            raw = row['raw']
            return (row['unknown'] is False and row['close_returned'] is True and raw._closed is True and
                    type(raw.fileno()) is int and raw.fileno() == -1)
        except BaseException: return False

    def _record_process_close(self, request, returned):
        with self._lock: rows = [row for row in self._sockets if row['raw'] is request]
        if len(rows) != 1: self._fault('accepted_identity_unknown'); return
        try:
            if returned is True and request._closed is True and type(request.fileno()) is int and request.fileno() == -1:
                rows[0]['close_returned'] = True
        except BaseException: pass

    def _make_thread(self, target, args, role):
        row = {'thread': None, 'role': role, 'claimed': False, 'resolved': False, 'unknown': False}
        with self._lock:
            self._threads.append(row); self._generation += 1
            if len(self._threads) > MAX_HISTORY: self._fault('history_limit'); row['unknown'] = True; return row
        try:
            row['thread'] = self._deps.thread(target=target, args=args, name='mta-smoke-' + role)
            row['thread'].daemon = True
        except BaseException:
            row['unknown'] = True; self._fault('thread_constructor_unknown')
        return row

    def _start_thread(self, row):
        row['claimed'] = True
        try: row['thread'].start(); return True
        except BaseException:
            row['unknown'] = True; self._fault('thread_start_unknown'); return False
        finally: row['resolved'] = True

    @staticmethod
    def _thread_exited(row):
        try:
            return (row['unknown'] is False and row['claimed'] is True and row['resolved'] is True and
                    row['thread'] is not None and row['thread'].is_alive() is False)
        except BaseException: return False

    def _capture_sessions(self):
        state = self.state
        if state is None: return
        with state.lock:
            operations = list(state.history) + ([state.operation] if state.operation is not None else [])
        for op in operations:
            if any(row['operation'] is op for row in self._sessions): continue
            self._sessions.append({'operation': op, 'session': op.session, 'worker': op.session._worker, 'finalizers': []})
        for row in self._sessions:
            with row['session']._lock: attempts = list(row['session']._attempts)
            for attempt in attempts:
                if not any(saved is attempt for saved in row['finalizers']): row['finalizers'].append(attempt)

    def _capture_probes(self):
        actors = getattr(self.state, 'probe_actors', None)
        if type(actors) is not list: return # Unknown replacement is not an iterable authorization.
        for position, actor in enumerate(actors):
            if not any(saved['actor'] is actor for saved in self._probes):
                self._probes.append({'actor': actor, 'position': position,
                    'process': actor.get('process') if type(actor) is dict else None,
                    'stdout': actor.get('stdout') if type(actor) is dict else None,
                    'stderr': actor.get('stderr') if type(actor) is dict else None,
                    'poll_observed': False, 'exit_verified': False, 'kill_attempted': False, 'kill_returned': False,
                    'wait_attempted': False, 'wait_returned': False,
                    'stdout_close_attempted': False, 'stdout_close_returned': False,
                    'stderr_close_attempted': False, 'stderr_close_returned': False,
                    'stdout_closed': False, 'stderr_closed': False})

    def _probe_known(self, saved):
        # Only the two fixed read-only constructor commands. All identity
        # checks precede each action; a swapped pipe denies the whole actor.
        try:
            actors = self.state.probe_actors; actor = saved['actor']; process = saved['process']; position = saved['position']
            expected = ([self._bluez, '--capabilities', 'hci0'], [self._network, '--capabilities'])
            return (not self._state_ctor_pending and type(actors) is list and len(actors) <= 2 and position in (0, 1) and
                position < len(actors) and actors[position] is actor and type(actor) is dict and
                actor.get('spawn_pending') is False and actor.get('spawn_unknown') is False and process is not None and
                actor.get('process') is process and type(process.args) is list and process.args == expected[position] and
                all(type(value) is str for value in process.args) and
                all(saved[key] is not None and actor.get(key) is saved[key] and getattr(process, key) is saved[key]
                    for key in ('stdout', 'stderr')))
        except BaseException: return False

    @staticmethod
    def _probe_poll(saved):
        try:
            result = saved['process'].poll()
            saved['poll_observed'] = result is None or type(result) is int
            saved['exit_verified'] = type(result) is int
        except BaseException:
            saved['poll_observed'] = False; saved['exit_verified'] = False
        return saved['poll_observed'] is True, saved['exit_verified'] is True

    def _cleanup_probes(self, end):
        # Independent of HTTP/State.close and with no State lock held. Never
        # act on an unknown spawn or a replacement Popen/pipe. No same-call
        # retries: each known actor/pipe gets at most one attempt below.
        self._capture_probes()
        for saved in list(self._probes):
            if not self._probe_known(saved): continue
            observed, exited = self._probe_poll(saved)
            if not observed: continue
            if not exited and time.monotonic() < end and self._probe_known(saved):
                saved['kill_attempted'] = True; saved['kill_returned'] = False
                try: saved['process'].kill(); saved['kill_returned'] = True
                except BaseException: pass
                if time.monotonic() < end and self._probe_known(saved):
                    saved['wait_attempted'] = True; saved['wait_returned'] = False
                    try:
                        result = saved['process'].wait(timeout=min(3, max(0, end - time.monotonic())))
                        saved['wait_returned'] = type(result) is int
                    except BaseException: pass
                if self._probe_known(saved): observed, exited = self._probe_poll(saved)
                else: observed = exited = False
            # A failed process/pipe attempt never suppresses other actors or
            # the other original pipe, but a still-live process is pending.
            for key in ('stdout', 'stderr'):
                if not observed or not exited or not self._probe_known(saved): continue
                try:
                    if saved[key].closed is True: continue # Actual readback only; no repeat close.
                except BaseException: continue
                if time.monotonic() >= end: continue
                saved[key + '_close_attempted'] = True; saved[key + '_close_returned'] = False
                try: saved[key].close(); saved[key + '_close_returned'] = True
                except BaseException: pass
        return self._probes_closed_actual()

    def _probes_closed_actual(self):
        self._capture_probes(); pending_processes = 0; pending_pipes = 0
        actors = getattr(self.state, 'probe_actors', ())
        for saved in self._probes:
            actor = saved['actor']; process = saved['process']
            try:
                process_ok = self._probe_known(saved) and self._probe_poll(saved)[1]
            except BaseException: process_ok = False
            pending_processes += 0 if process_ok else 1
            for key in ('stdout', 'stderr'):
                try:
                    good = (self._probe_known(saved) and process is not None and actor.get(key) is saved[key] and getattr(process, key) is saved[key] and
                        saved[key] is not None and saved[key].closed is True)
                except BaseException: good = False
                saved[key + '_closed'] = good is True
                pending_pipes += 0 if good else 1
        self._probe_processes_pending = pending_processes; self._probe_pipes_pending = pending_pipes
        return type(actors) is list and len(self._probes) == 2 and len(actors) == 2 and pending_processes == pending_pipes == 0

    def _gate(self):
        state = self.state
        if self._deps.pending_exists() is not False or state is None: return False
        recovery = state.wifi_status()
        if type(recovery) is not dict or recovery.get('restorePending') is not False or recovery.get('recoveryLocked') is not False: return False
        probes = self._probes_closed_actual() # poll/pipe readbacks never hold State.lock.
        with state.lock:
            return (state.network_caps.get('receive') is False and state.network_caps.get('send') is False and
                state.receive_available is False and state.send_available is False and state.helper is None and
                state.lease is None and state.transport is None and state.key is None and
                state.wifi_backend._active_lease is None and type(state.wifi_backend._pending) is list and not state.wifi_backend._pending and
                state.wifi_restore_pending is False and state.radio_restore_pending is False and
                state.discoverable is False and state.scanning is False and state._probes_closed() is True and probes)

    def open(self):
        with self._lock:
            if self._opened or self._closing: raise ObserverError('observer_single_use')
            self._opened = True; self._phase = 'opening'; self._state_ctor_pending = True; self._cache(False)
        try:
            if self._deps.pending_exists() is not False: raise ObserverError('pending_gate')
            self.state = self._deps.State.__new__(self._deps.State)
            self._deps.State.__init__(self.state, self._root, self._bluez, self._network)
        except BaseException:
            self._state_ctor_unknown = self.state is not None; self._fault('state_constructor_or_gate'); return False
        finally:
            self._state_ctor_pending = False; self._capture_probes()
        try:
            if not self._gate() or self._cancel.is_set(): raise ObserverError('no_rf_gate')
            kind = _server_type(self._deps); self._server_ctor_pending = True
            self.server = kind.__new__(kind); self.server.observer = self
            self._deps.Server.__init__(self.server, self.state, port=0, bootstrap=False)
            self.server.handler = kind.smoke_handler
            self._adopt_socket(self.server.socket, 'listener')
            row = self._make_thread(self.server.serve_forever, (), 'serve')
            if not self._start_thread(row): return False
            with self._lock: self._phase = 'open'; self._reason = ''; self._cache(False)
            return True
        except BaseException:
            self._server_ctor_unknown = self.server is not None; self._fault('server_constructor_or_gate'); return False
        finally:
            self._server_ctor_pending = False
            if self.server is not None and hasattr(self.server, 'socket') and not any(row['raw'] is self.server.socket for row in self._sockets):
                self._adopt_socket(self.server.socket, 'partial_listener')
            with self._lock: self._cache(False)

    def _request(self, method, path, body=b''):
        # No create_connection, hostname resolution or network fallback.
        if self._cancel.is_set(): raise ObserverError('cancelled')
        raw = None; saved = None
        try:
            raw = self._deps.socket.socket(self._deps.socket.AF_INET, self._deps.socket.SOCK_STREAM)
            saved = self._adopt_socket(raw, 'client')
            if saved['unknown'] or self._cancel.is_set(): raise ObserverError('cancelled')
            raw.settimeout(2); raw.bind(('127.0.0.1', 0)); raw.connect(self.server.server_address)
            if raw.getsockname()[0] != '127.0.0.1' or raw.getpeername() != self.server.server_address: raise ObserverError('loopback_identity')
            text = (method + ' ' + path + ' HTTP/1.1\r\nHost: ' + self.server.expected_host +
                '\r\nX-P011-MTA-Token: ' + self.state.token + '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode('ascii')
            raw.sendall(text + body); data = b''
            while True:
                block = raw.recv(4096)
                if not block: break
                data += block
                if len(data) > MAX_REPLY: raise ObserverError('response_bound')
            head, payload = data.split(b'\r\n\r\n', 1)
            if not head.split(b'\r\n', 1)[0].startswith(b'HTTP/1.0 200 '): raise ObserverError('response_status')
            value = service.json.loads(payload.decode('utf-8'))
            if type(value) is not dict: raise ObserverError('response_shape')
            return value
        except BaseException:
            if raw is None: self._fault('client_constructor_unknown')
            raise
        finally:
            if saved is not None: self._close_socket(saved)

    def _exercise_main(self):
        try:
            if not self._gate(): raise ObserverError('no_rf_gate')
            self._request('GET', '/v1/status'); self._request('GET', '/v1/files')
            self._request('POST', '/v1/action', CANCEL_BODY)
            self._capture_sessions()
            ordinary = self.state.session
            if ordinary is None or ordinary.closed() is not True or ordinary._worker_skipped is not True: raise ObserverError('ordinary_cancel_pending')
            self._ordinary_skipped = True
            if not self._gate() or self._cancel.is_set(): raise ObserverError('no_rf_gate')
            with self.state.lock:
                op = self.state._new_operation_locked('cleanup')
                if any(value is not None for value in (op.helper, op.key, op.lease, op.transport)) or op.recovery_requested:
                    raise ObserverError('cleanup_owner_gate')
            self._capture_sessions() # Core installed exact worker/finalizer before start.
            op.session.start()
            self._started_cleanup = (op.session._worker_start_claimed is True and op.session._worker_start_resolved is True and
                op.session._worker_start_unknown is False and op.session._worker.ident is not None)
            if not self._started_cleanup: raise ObserverError('cleanup_start_unknown')
            if op.session.close(timeout=3) is not True: raise ObserverError('cleanup_pending')
            self._capture_sessions()
            if self.state.worker is not op.session._worker or op.session._worker_skipped is not False or not self._gate(): raise ObserverError('cleanup_identity_gate')
            self._http_verified = True
        except BaseException: self._fault('exercise_failed')
        finally:
            with self._lock: self._operations -= 1; self._cache(False)

    def exercise(self, timeout=10):
        timeout = budget(timeout)
        with self._lock:
            if self._phase != 'open' or self._closing or self._exercised: raise ObserverError('exercise_single_use')
            self._exercised = True; self._operations += 1; self._phase = 'exercising'
            row = self._make_thread(self._exercise_main, (), 'client'); self._cache(False)
        if not self._start_thread(row):
            # A raising start may already be executing; its actual finally owns
            # the decrement. Never assume is_alive=False proves no late start.
            with self._lock: self._cache(False)
            return False
        if row['thread'] is threading.current_thread(): return False
        row['thread'].join(timeout)
        with self._lock:
            if self._thread_exited(row) and self._http_verified and not self._unknown:
                self._phase = 'exercised'; self._cache(False); return True
            self._phase = 'pending'; self._reason = 'exercise_pending'; self._cache(False); return False

    def _sessions_closed(self):
        self._capture_sessions()
        for row in self._sessions:
            session = row['session']; saved = session.status()
            if (session._worker is not row['worker'] or session.closed() is not True or saved.get('closed') is not True or
                    saved.get('worker_start_pending') is not False or saved.get('worker_start_unknown') is not False or
                    saved.get('worker_alive') is not False or any(saved.get(key) != 0 or type(saved.get(key)) is not int for key in
                    ('finalizers_alive', 'finalizer_starts_pending', 'finalizer_starts_unknown', 'callbacks_pending', 'unknown_owner_count',
                     'transport_count', 'handoff_count')) or any(saved.get(key) is not True for key in
                    ('transports_verified', 'release_verified', 'extra_actors_verified', 'restore_verified'))): return False
            if session._worker_skipped is not True and row['worker'].is_alive() is not False: return False
            if session._worker_skipped is True and session._worker_start_claimed is not False: return False
            if any(attempt['claimed'] is not True or attempt['resolved'] is not True or attempt['unknown_start'] is not False or
                attempt['thread'].is_alive() is not False for attempt in row['finalizers']): return False
        return bool(self._sessions)

    def close(self, timeout=10):
        timeout = budget(timeout); end = time.monotonic() + timeout
        with self._lock:
            if self._cached['closed'] is True: return True
            if self._close_running: return False
            self._close_running = True; self._closing = True; self._cancel.set(); self._phase = 'closing'; self._cache(False)
        ok = True; probes_attempted = False
        try:
            if self.server is not None and hasattr(self.server, 'stopping'): self.server.stopping.set()
            with self._lock: sockets = list(self._sockets); threads = list(self._threads)
            for row in sockets:
                try:
                    if row['role'] == 'accepted': row['raw'].shutdown(self._deps.socket.SHUT_RDWR)
                except BaseException: pass
                if not self._close_socket(row): ok = False
            for row in threads:
                if row['thread'] is None or not row['claimed'] or row['thread'] is threading.current_thread(): ok = False; continue
                try: row['thread'].join(max(0, end - time.monotonic()))
                except BaseException: ok = False
            with self._lock:
                ready = self._operations == 0 and self._accepting == 0 and all(self._thread_exited(row) for row in self._threads)
            probes_attempted = True
            self._cleanup_probes(end)
            if (self.state is not None and ready and ok and time.monotonic() < end and self._unknown == 0 and
                    not self._server_ctor_unknown and all(self._socket_closed(row) for row in self._sockets) and
                    not self._state_ctor_unknown and not self._state_ctor_pending and self._gate()):
                self._state_closed = self.state.close() is True and self.state.closed() is True
            else: self._state_closed = False
            with self._lock: generation = self._generation
            # Include late accepted sockets registered while shutdown was in flight.
            for row in list(self._sockets):
                if not any(saved is row for saved in sockets) and not self._socket_closed(row) and not self._close_socket(row): ok = False
            probes = self.state is not None and self.state._probes_closed() is True and self._probes_closed_actual()
            sessions = self._state_closed and self._sessions_closed()
            with self._lock:
                verified = (ok and ready and probes and sessions and self._state_closed and self._unknown == 0 and
                    not self._state_ctor_unknown and not self._server_ctor_unknown and not self._state_ctor_pending and
                    not self._server_ctor_pending and self._generation == generation and
                    all(self._socket_closed(row) for row in self._sockets) and all(self._thread_exited(row) for row in self._threads))
                self._phase = 'closed' if verified else 'pending'; self._reason = '' if verified else 'closure_pending'; self._cache(verified)
                return verified
        except BaseException:
            with self._lock: self._phase = 'pending'; self._reason = 'closure_unknown'; self._cache(False)
            return False
        finally:
            if not probes_attempted:
                # Even partial HTTP/State constructors and earlier cleanup
                # errors do not strand a distinct known read-only probe.
                try: self._cleanup_probes(end)
                except BaseException: pass
                with self._lock: self._cache(False)
            with self._lock: self._close_running = False
