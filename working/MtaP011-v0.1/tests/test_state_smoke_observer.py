"""HOST real threads with isolated production source + fake OS peripherals.

No global Thread/Popen/socket monkeypatch; no ADB, real socket, RF or user data.
"""
import ast
import builtins
import copy
import io
from pathlib import Path
import queue
import sys
import tempfile
import threading
import time
import types
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'runtime'))
import mta_state_smoke_observer as observer
import mta_wifi
import p011_json as json


def private_module(name, path, replacements):
    module = types.ModuleType(name)
    original = builtins.__import__
    def importer(key, *args, **kwargs):
        return replacements[key] if key in replacements else original(key, *args, **kwargs)
    module.__dict__.update(__builtins__=dict(vars(builtins), __import__=importer), __file__=str(path))
    exec(compile(path.read_text(encoding='utf-8'), str(path), 'exec'), module.__dict__)
    return module


class Environment:
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(); self.base = Path(self.directory.name)
        self.user = self.base / 'synthetic-user'; self.user.mkdir()
        (self.user / 'readme.txt').write_bytes(b'HOST SYNTHETIC!!')
        self.bluez = self.base / 'bluez'; self.network = self.base / 'network'
        self.bluez.write_bytes(b'HOST fixture only'); self.network.write_bytes(b'HOST fixture only')
        self.pending = False; self.processes = []; self.raws = []; self.port = 20000; self.listeners = {}
        self.native_receive = False; self.native_send = False; self.probe_unknown = False
        self.probe_timeout = False; self.probe_initial_kill_error = False
        self.active = None; self.journals = []; self.restore_calls = 0
        self.fail_ctor = False; self.close_error = False; self.close_noeffect = False
        self.late_accept = None; self.process_block = None; self.process_entered = threading.Event()
        self.start_fail_role = None; self.start_after_role = None; self.thread_refs = []
        env = self
        class ProbePipe:
            def __init__(self): self.closed = False; self.close_calls = 0; self.fail_close = False
            def close(self):
                self.close_calls += 1
                if self.fail_close: raise OSError('HOST_PRIVATE_PROBE_PIPE_CLOSE')
                self.closed = True
        class Timeout(OSError): pass
        class Raw:
            def __init__(self, family, kind):
                self.family = family; self.type = kind; self.proto = 0; self._closed = False; self.fd = len(env.raws) + 50
                self.timeout = 2; self.address = None; self.peer = None; self.buffer = b''; self.eof = False
                self.condition = threading.Condition(); self.accepted = queue.Queue(); env.raws.append(self)
                if env.fail_ctor: raise OSError('HOST_PRIVATE_CTOR')
            def fileno(self): return self.fd
            def bind(self, address):
                if address[0] != '127.0.0.1': raise AssertionError('HOST network fallback')
                env.port += 1; self.address = (address[0], address[1] or env.port)
            def listen(self, count): env.listeners[self.address] = self
            def getsockname(self): return self.address
            def getpeername(self): return self.peer.address
            def settimeout(self, value): self.timeout = value
            def connect(self, address):
                if address not in env.listeners: raise OSError('HOST_PRIVATE_NO_LISTENER')
                listener = env.listeners[address]; accepted = Raw(2, 1)
                accepted.address = address; accepted.peer = self; self.peer = accepted
                listener.accepted.put((accepted, self.address))
            def accept(self):
                if self._closed: raise OSError('HOST_PRIVATE_CLOSED')
                try: result = self.accepted.get(timeout=self.timeout)
                except queue.Empty: raise Timeout()
                if env.late_accept is not None:
                    env.late_accept[0].set(); env.late_accept[1].wait(2)
                return result
            def sendall(self, value):
                if self._closed or self.peer is None: raise OSError('HOST_PRIVATE_CLOSED')
                with self.peer.condition: self.peer.buffer += value; self.peer.condition.notify_all()
            def recv(self, count):
                end = time.monotonic() + self.timeout
                with self.condition:
                    while not self.buffer and not self.eof and not self._closed:
                        left = end - time.monotonic()
                        if left <= 0: raise Timeout()
                        self.condition.wait(left)
                    result = self.buffer[:count]; self.buffer = self.buffer[count:]; return result
            def shutdown(self, mode):
                with self.condition: self.eof = True; self.condition.notify_all()
            def close(self):
                if env.close_error: raise OSError('HOST_PRIVATE_CLOSE')
                if env.close_noeffect: return
                self._closed = True; self.fd = -1
                with self.condition: self.eof = True; self.condition.notify_all()
                if self.peer is not None:
                    with self.peer.condition: self.peer.eof = True; self.peer.condition.notify_all()
        self.socket = types.SimpleNamespace(socket=Raw, AF_INET=2, SOCK_STREAM=1, SHUT_RDWR=2, timeout=Timeout)
        mini = private_module('HOST_private_minhttp', PROJECT / 'runtime/minhttp.py', {'socket': self.socket})
        class Popen:
            def __init__(self, argv, stdout, stderr):
                if argv not in ([str(env.bluez), '--capabilities', 'hci0'], [str(env.network), '--capabilities']):
                    raise AssertionError('HOST unexpected native command')
                self.argv = list(argv); self.args = list(argv); self.stdout = ProbePipe(); self.stderr = ProbePipe(); self.returncode = None
                self.killed = False; self.kill_calls = 0; self.wait_calls = []; self.poll_calls = 0
                self.kill_error = env.probe_initial_kill_error; self.wait_error = False; env.processes.append(self)
                if env.probe_unknown: raise OSError('HOST_PRIVATE_POPEN')
            def communicate(self, timeout):
                if env.probe_timeout: raise TimeoutError('HOST_PRIVATE_PROBE_COMMUNICATE')
                value = ({'powered': True, 'features': True, 'connectable_advert': True, 'bredr_enabled': True,
                    'le_enabled': True, 'global_advertising': False, 'max_adv': 31, 'max_scan': 31,
                    'bluez_advertising_known': True, 'bluez_advertising_active': False, 'active_instances': 0}
                    if self.argv[0] == str(env.bluez) else {'ok': True, 'receive': env.native_receive, 'send': env.native_send})
                self.returncode = 0; self.stdout.close(); self.stderr.close()
                return (json.dumps(value) + '\n').encode('utf-8'), b''
            def poll(self): self.poll_calls += 1; return self.returncode
            def kill(self):
                self.kill_calls += 1
                if self.kill_error: raise OSError('HOST_PRIVATE_PROBE_KILL')
                self.killed = True; self.returncode = -9
            def wait(self, timeout):
                self.wait_calls.append(timeout)
                if self.wait_error or self.returncode is None: raise TimeoutError('HOST_PRIVATE_PROBE_WAIT')
                return self.returncode
        class Wifi:
            def __init__(self, helper):
                self._active_lease = env.active; self._pending = list(env.journals)
            def status(self): return {'restorePending': bool(self._pending), 'recoveryLocked': bool(self._pending)}
            def restore_active(self):
                env.restore_calls += 1
                if self._active_lease is not None or self._pending: raise AssertionError('HOST forbidden network restore')
                return True
            def recover_pending(self): raise AssertionError('HOST recover forbidden')
        source = private_module('HOST_private_mta_service', PROJECT / 'runtime/mta_service.py', {
            'minhttp': mini, 'subprocess': types.SimpleNamespace(Popen=Popen, PIPE=-1),
            'mta_wifi': types.SimpleNamespace(WifiBackend=Wifi, NetworkInfo=mta_wifi.NetworkInfo)})
        original_process = source.Server.process
        # Isolated class override pauses after the actual minhttp map removal.
        def process(server, request, address):
            original_process(server, request, address)
            if env.process_block is not None:
                env.process_entered.set(); env.process_block.wait(2)
        class Server(source.Server):
            pass
        Server.process = process
        def thread_factory(**kwargs):
            thread = threading.Thread(**kwargs); env.thread_refs.append(thread)
            role = kwargs['name'].rsplit('-', 1)[1]
            if role in (env.start_fail_role, env.start_after_role):
                original_start = thread.start
                def start():
                    if role == env.start_after_role: original_start()
                    raise RuntimeError('HOST_PRIVATE_START_UNKNOWN')
                thread.start = start
            return thread
        self.deps = types.SimpleNamespace(State=source.State, Server=Server, Handler=source.Handler,
            socket=self.socket, thread=thread_factory, pending_exists=lambda: self.pending, evidence='HOST_FAKE_ONLY')
        self.object = observer.StateSmokeObserver(str(self.user), str(self.bluez), str(self.network), _host_dependencies=self.deps)

    def dispose(self):
        self.close_error = False; self.close_noeffect = False
        if self.process_block is not None: self.process_block.set()
        if self.late_accept is not None: self.late_accept[1].set()
        self.object._cancel.set()
        if self.object.server is not None and hasattr(self.object.server, 'stopping'): self.object.server.stopping.set()
        for raw in self.raws: raw.close()
        for thread in self.thread_refs:
            if thread.ident is not None and thread is not threading.current_thread(): thread.join(3)
        self.directory.cleanup()


class ObserverTests(unittest.TestCase):
    def make(self):
        env = Environment(); self.addCleanup(env.dispose); return env

    def test_real_threads_production_state_cancel_and_started_cleanup_are_distinct(self):
        env = self.make(); obj = env.object
        self.assertTrue(obj.open()); self.assertTrue(obj.exercise()); self.assertTrue(obj.close())
        status = obj.status(); self.assertTrue(status['closed']); self.assertFalse(status['cleanup_pending'])
        self.assertTrue(status['ordinary_cancel_worker_skipped']); self.assertTrue(status['started_cleanup_worker'])
        self.assertEqual(status['cleanup_kind'], 'SYNTHETIC_CLEANUP_NOT_TRANSFER'); self.assertFalse(status['receive_worker_tested'])
        self.assertEqual(len(obj._sessions), 2); self.assertIs(obj._sessions[-1]['worker'], obj.state.worker)
        self.assertTrue(all(row['thread'].is_alive() is False for row in obj._threads))
        self.assertTrue(all(row['raw']._closed for row in obj._sockets)); self.assertEqual(len(env.processes), 2)
        self.assertTrue(all(item.poll() is not None and item.stdout.closed and item.stderr.closed for item in env.processes))
        self.assertGreaterEqual(env.restore_calls, 2); self.assertIsNone(obj.state.helper); self.assertIsNone(obj.state.lease)
        self.assertFalse(obj.state.send_available); self.assertFalse(obj.state.receive_available); self.assertTrue(obj.state.scan_available)

    def test_default_public_status_is_passive_private_and_cannot_invoke_io(self):
        env = self.make(); obj = env.object
        before = obj.status(); self.assertEqual(before['evidence_scope'], 'HOST_FAKE_ONLY')
        env.deps.pending_exists = lambda: (_ for _ in ()).throw(AssertionError('HOST I/O'))
        self.assertEqual(before, obj.status()); self.assertEqual(env.processes, []); self.assertEqual(env.raws, [])
        public = json.dumps(before)
        for private in (str(env.base), 'token', 'PID', 'HOST_PRIVATE', 'SSID'): self.assertNotIn(private, public)
        env.deps.evidence = 'HOST_PRIVATE_CHANGED' # Public scope is captured fixed enum, not late fixture text.
        env.deps.pending_exists = lambda: False
        self.assertTrue(obj.open()); entered = threading.Event(); release = threading.Event()
        original_poll = env.processes[0].poll
        def poll(): entered.set(); release.wait(2); return original_poll()
        env.processes[0].poll = poll
        self.assertFalse(obj.exercise(timeout=.01)); self.assertTrue(entered.wait(1))
        self.assertTrue(obj.state.lock.acquire(False)); obj.state.lock.release()
        self.assertFalse(obj.status()['closed']) # Cached status never polls the blocked process.
        release.set(); env.processes[0].poll = original_poll
        client = next(row['thread'] for row in obj._threads if row['role'] == 'client')
        client.join(3); self.assertFalse(client.is_alive())
        self.assertTrue(obj.close(timeout=3))
        self.assertEqual(obj.status()['evidence_scope'], 'HOST_FAKE_ONLY')

    def test_global_pending_blocks_before_production_ctor_or_socket(self):
        env = self.make(); env.pending = True
        self.assertFalse(env.object.open()); self.assertEqual(env.processes, []); self.assertEqual(env.raws, [])
        self.assertFalse(env.object.close()); self.assertFalse(env.object.status()['closed'])

    def test_native_receive_send_unknown_journal_and_active_owner_gate_no_restore(self):
        for mode in ('receive', 'send', 'journal', 'active', 'probe'):
            env = self.make()
            if mode == 'receive': env.native_receive = True
            elif mode == 'send': env.native_send = True
            elif mode == 'journal': env.journals = ['HOST_PRIVATE_JOURNAL']
            elif mode == 'active': env.active = object()
            else: env.probe_unknown = True
            self.assertFalse(env.object.open()); self.assertFalse(env.object.close()); self.assertEqual(env.restore_calls, 0)
            self.assertIsNotNone(env.object.state); self.assertFalse(env.object.status()['closed'])

    def test_production_authorization_and_exact_action_route_whitelist(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open())
        for action in ('scan', 'discover_start', 'recover', 'rename', 'send', 'accept', 'reject'):
            with self.assertRaises(observer.ObserverError): obj._request('POST', '/v1/action', json.dumps({'action': action}).encode())
        with self.assertRaises(observer.ObserverError): obj._request('GET', '/v1/bootstrap')
        saved = obj.state.token; obj.state.token = 'HOST_WRONG_TOKEN'
        # The internal client derives token from the same State, so test auth
        # directly through a fixed raw request with a definitely wrong token.
        raw = env.socket.socket(2, 1); raw.bind(('127.0.0.1', 0)); raw.connect(obj.server.server_address)
        raw.sendall(('GET /v1/status HTTP/1.1\r\nHost: ' + obj.server.expected_host + '\r\nX-P011-MTA-Token: WRONG\r\n\r\n').encode())
        self.assertIn(b'403', raw.recv(4096)); raw.close(); obj.state.token = saved
        self.assertIsNone(obj.state.operation); self.assertIsNone(obj.state.helper); self.assertEqual(obj.state.event_counts, {})
        self.assertTrue(obj.close())

    def test_map_empty_while_actual_request_thread_alive_is_not_closure(self):
        env = self.make(); env.process_block = threading.Event(); obj = env.object
        self.assertTrue(obj.open()); obj._request('GET', '/v1/status')
        self.assertTrue(env.process_entered.wait(1)); self.assertEqual(obj.server.workers, {})
        self.assertFalse(obj.close(timeout=.02)); self.assertFalse(obj.status()['closed'])
        self.assertTrue(any(row['role'] == 'request' and row['thread'].is_alive() for row in obj._threads))
        env.process_block.set(); self.assertTrue(obj.close(timeout=3))

    def test_request_start_unknown_even_false_alive_never_dropped(self):
        env = self.make(); env.start_fail_role = 'request'; obj = env.object; self.assertTrue(obj.open())
        with self.assertRaises(BaseException): obj._request('GET', '/v1/status')
        self.assertFalse(obj.close()); rows = [row for row in obj._threads if row['role'] == 'request']
        self.assertEqual(len(rows), 1); self.assertTrue(rows[0]['unknown']); self.assertFalse(rows[0]['thread'].is_alive())
        self.assertFalse(obj.status()['closed']); self.assertGreater(obj.status()['unknown_owners'], 0)

    def test_start_after_real_thread_execution_exception_keeps_unknown(self):
        env = self.make(); env.start_after_role = 'serve'; obj = env.object
        self.assertFalse(obj.open()); self.assertFalse(obj.close()); self.assertTrue(obj._threads[0]['unknown'])
        self.assertIsNotNone(obj._threads[0]['thread']); self.assertFalse(obj.status()['closed'])

    def test_client_start_unknown_cannot_clear_inflight_as_unstarted_exit(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); env.start_fail_role = 'client'
        self.assertFalse(obj.exercise()); self.assertFalse(obj.close())
        self.assertEqual(obj.status()['exercise_operations_pending'], 1); self.assertFalse(obj.status()['closed'])

    def test_close_error_attempts_other_resources_and_next_explicit_close_rechecks(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); self.assertTrue(obj.exercise())
        env.close_error = True; self.assertFalse(obj.close(timeout=.3)); self.assertFalse(obj.status()['closed'])
        self.assertTrue(all(row['raw'] in env.raws for row in obj._sockets)); self.assertIsNotNone(obj.state)
        env.close_error = False; self.assertTrue(obj.close()); self.assertTrue(obj.close())

    def test_noeffect_close_does_not_prove_closed_and_refs_remain(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); env.close_noeffect = True
        self.assertFalse(obj.close(timeout=.3)); self.assertFalse(obj.status()['closed'])
        env.close_noeffect = False; self.assertTrue(obj.close())

    def test_partial_server_constructor_and_probe_unknown_never_claim_no_owners(self):
        env = self.make(); env.fail_ctor = True; obj = env.object
        self.assertFalse(obj.open()); self.assertIsNotNone(obj.server); self.assertFalse(obj.close())
        self.assertTrue(obj.status()['server_ctor_unknown']); self.assertGreater(obj.status()['unknown_owners'], 0)
        self.assertIsNotNone(obj.state); self.assertEqual(env.restore_calls, 0)

    def test_late_accept_after_close_is_retained_until_actual_serve_exit(self):
        env = self.make(); env.late_accept = (threading.Event(), threading.Event()); obj = env.object
        self.assertTrue(obj.open()); raw = env.socket.socket(2, 1); raw.bind(('127.0.0.1', 0)); raw.connect(obj.server.server_address)
        self.assertTrue(env.late_accept[0].wait(1)); self.assertFalse(obj.close(timeout=.02))
        env.late_accept[1].set(); raw.close(); self.assertTrue(obj.close(timeout=3))
        self.assertTrue(any(row['role'] == 'accepted' for row in obj._sockets)); self.assertTrue(all(row['raw']._closed for row in obj._sockets))

    def test_slot_rejected_accepted_socket_is_still_recorded_and_closed(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open())
        for unused in range(4): self.assertTrue(obj.server.slots.acquire(False))
        raw = env.socket.socket(2, 1); raw.bind(('127.0.0.1', 0)); raw.connect(obj.server.server_address)
        self.assertEqual(raw.recv(1), b''); raw.close(); self.assertTrue(obj.close())
        accepted = [row for row in obj._sockets if row['role'] == 'accepted']; self.assertEqual(len(accepted), 1)
        self.assertTrue(accepted[0]['close_returned']); self.assertEqual(len([row for row in obj._threads if row['role'] == 'request']), 0)

    def test_pending_appearing_before_close_prevents_empty_restore_call(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); env.pending = True
        self.assertFalse(obj.close()); self.assertEqual(env.restore_calls, 0); self.assertIsNotNone(obj.state)

    def test_started_worker_and_finalizer_full_schema_and_identity_are_required(self):
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); self.assertTrue(obj.exercise())
        op = obj.state.operation; old = op.session.status
        def incomplete():
            value = old(); del value['restore_verified']; return value
        op.session.status = incomplete
        self.assertFalse(obj.close()); self.assertFalse(obj.status()['closed'])
        op.session.status = old; self.assertTrue(obj.close())
        env = self.make(); obj = env.object; self.assertTrue(obj.open())
        original = obj.state._new_operation_locked
        def create(kind):
            value = original(kind)
            def unknown_start(): raise RuntimeError('HOST_PRIVATE_WORKER_START')
            value.session._worker.start = unknown_start
            return value
        # Only this isolated exact State/Thread gets a fault; no global patch.
        obj.state._new_operation_locked = create
        self.assertFalse(obj.exercise()); self.assertFalse(obj.status()['started_cleanup_worker'])
        self.assertFalse(obj.close()); self.assertIsNotNone(obj.state.session)
        env = self.make(); obj = env.object; self.assertTrue(obj.open()); self.assertTrue(obj.exercise())
        actor = obj.state.probe_actors[0]; exact_pipe = actor['stdout']
        actor['process'].stdout = io.BytesIO() # Cached State.closed flag alone is insufficient.
        self.assertFalse(obj.close()); self.assertFalse(obj.status()['closed'])
        self.assertGreater(obj.status()['probe_pipes_pending'], 0)
        self.assertIs(obj._probes[0]['stdout'], exact_pipe)
        actor['process'].stdout.close(); actor['process'].stdout = exact_pipe
        self.assertTrue(obj.close())

    def test_python35_ast_budget_and_no_global_monkeypatch_or_runners(self):
        path = PROJECT / 'runtime/mta_state_smoke_observer.py'; tree = ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        self.assertNotIn(target.value.id, ('threading', 'socket', 'service'))
        for value in (True, -1, 31, float('nan'), float('inf'), 10 ** 1000):
            with self.assertRaises(observer.ObserverError): observer.budget(value)
        self.assertEqual(observer.budget(0), 0)
        with self.assertRaises(observer.ObserverError): observer.StateSmokeObserver('root', 'bluez', 'network', _host_dependencies=types.SimpleNamespace(evidence='DEVICE'))

    def test_http_and_state_ctor_unknown_independently_close_exact_known_probes(self):
        for state_unknown in (False, True):
            env = self.make(); obj = env.object
            if state_unknown:
                base = env.deps.State
                class PartialState(base):
                    def __init__(self, *args):
                        base.__init__(self, *args)
                        raise RuntimeError('HOST_PRIVATE_PARTIAL_STATE')
                env.deps.State = PartialState
            else: env.fail_ctor = True
            self.assertFalse(obj.open()); self.assertEqual(len(env.processes), 2)
            # Fault-injected exact fake child/pipe liveness, not a claim that
            # an exited native child can revive. The saved owner is unchanged.
            for process in env.processes:
                process.returncode = None; process.stdout.closed = False; process.stderr.closed = False
            self.assertFalse(obj.close(timeout=1)); self.assertEqual(env.restore_calls, 0)
            self.assertFalse(obj.status()['closed']); self.assertEqual(obj.status()['probe_processes_pending'], 0)
            self.assertEqual(obj.status()['probe_pipes_pending'], 0)
            for saved, process in zip(obj._probes, env.processes):
                self.assertIs(saved['process'], process); self.assertEqual(process.kill_calls, 1)
                self.assertEqual(len(process.wait_calls), 1); self.assertTrue(0 <= process.wait_calls[0] <= 1)
                self.assertTrue(saved['poll_observed']); self.assertTrue(saved['exit_verified'])
                self.assertTrue(saved['kill_returned']); self.assertTrue(saved['wait_returned'])
                for key in ('stdout', 'stderr'):
                    self.assertTrue(saved[key + '_close_attempted']); self.assertTrue(saved[key + '_close_returned'])
                    self.assertTrue(saved[key + '_closed']); self.assertEqual(getattr(process, key).close_calls, 2)
            counts = [(item.kill_calls, len(item.wait_calls), item.stdout.close_calls, item.stderr.close_calls) for item in env.processes]
            self.assertFalse(obj.close(timeout=1)) # Unknown HTTP/ctor is still pending, no retry of closed owners.
            self.assertEqual(counts, [(item.kill_calls, len(item.wait_calls), item.stdout.close_calls, item.stderr.close_calls) for item in env.processes])
        env = self.make(); obj = env.object; env.probe_timeout = True; env.probe_initial_kill_error = True
        # Real constructor control flow: first communicate fails and its own
        # kill fails, so State retains one known live probe and no network probe.
        self.assertFalse(obj.open()); self.assertEqual(len(env.processes), 1)
        process = env.processes[0]; self.assertIsNone(process.poll()); self.assertEqual(process.kill_calls, 1)
        self.assertFalse(process.stdout.closed); self.assertFalse(process.stderr.closed)
        process.kill_error = False
        self.assertFalse(obj.close(timeout=1)); self.assertEqual(env.restore_calls, 0)
        self.assertEqual(process.kill_calls, 2); self.assertEqual(len(process.wait_calls), 1)
        self.assertTrue(process.stdout.closed); self.assertTrue(process.stderr.closed)
        self.assertTrue(obj._probes[0]['exit_verified']); self.assertEqual(obj.status()['historical_probes'], 1)
        self.assertEqual(obj.status()['probe_processes_pending'], 0); self.assertEqual(obj.status()['probe_pipes_pending'], 0)
        self.assertFalse(obj.status()['closed']) # No missing second actor or ctor gate is upgraded.

    def test_probe_close_failure_preserves_pending_and_other_actor_pipe_attempts(self):
        env = self.make(); obj = env.object; env.fail_ctor = True; self.assertFalse(obj.open())
        for process in env.processes:
            process.returncode = None; process.stdout.closed = False; process.stderr.closed = False
        first = env.processes[0]; first.stdout.fail_close = True
        self.assertFalse(obj.close(timeout=1)); self.assertEqual(env.restore_calls, 0)
        self.assertFalse(first.stdout.closed); self.assertTrue(first.stderr.closed)
        self.assertTrue(env.processes[1].stdout.closed); self.assertTrue(env.processes[1].stderr.closed)
        self.assertEqual(first.stdout.close_calls, 2) # One initial constructor close, one failing cleanup; no retry.
        self.assertEqual(obj.status()['probe_pipes_pending'], 1)
        self.assertFalse(obj._probes[0]['stdout_close_returned']); self.assertTrue(obj._probes[0]['stderr_close_returned'])
        self.assertTrue(obj._probes[1]['wait_returned']); self.assertEqual(obj.status()['probe_pipe_close_attempts'], 4)
        first.stdout.fail_close = False
        self.assertFalse(obj.close(timeout=1)); self.assertEqual(first.stdout.close_calls, 3)
        self.assertEqual(env.processes[1].stdout.close_calls, 2); self.assertEqual(first.kill_calls, 1)
        self.assertEqual(obj.status()['probe_pipes_pending'], 0)
        env = self.make(); obj = env.object; env.fail_ctor = True; self.assertFalse(obj.open())
        for process in env.processes:
            process.returncode = None; process.stdout.closed = False; process.stderr.closed = False
        env.processes[0].kill_error = True; env.processes[0].wait_error = True
        self.assertFalse(obj.close(timeout=1)); self.assertEqual(env.processes[0].kill_calls, 1)
        self.assertEqual(len(env.processes[0].wait_calls), 1); self.assertFalse(env.processes[0].stdout.closed)
        self.assertTrue(env.processes[1].stdout.closed); self.assertTrue(env.processes[1].stderr.closed)
        self.assertEqual(obj.status()['probe_processes_pending'], 1); self.assertEqual(obj.status()['probe_pipes_pending'], 2)

    def test_probe_foreign_swap_unknown_spawn_or_command_cannot_be_cleaned(self):
        for mode in ('pipe', 'process', 'command', 'spawn_pending', 'spawn_unknown', 'actor_table'):
            env = self.make(); obj = env.object; env.fail_ctor = True; self.assertFalse(obj.open())
            process = env.processes[0]; actor = obj.state.probe_actors[0]; foreign = io.BytesIO()
            self.addCleanup(foreign.close)
            for item in env.processes:
                item.returncode = None; item.stdout.closed = False; item.stderr.closed = False
            original = process.stdout
            if mode == 'pipe': process.stdout = foreign
            elif mode == 'process': actor['process'] = object()
            elif mode == 'command': process.args = [str(env.bluez), '--serve', 'hci0']
            elif mode == 'actor_table': obj.state.probe_actors = None
            else: actor[mode] = True
            self.assertFalse(obj.close(timeout=1)); self.assertEqual(env.restore_calls, 0)
            self.assertFalse(foreign.closed); self.assertEqual(process.kill_calls, 0)
            self.assertFalse(original.closed); self.assertEqual(original.close_calls, 1)
            if mode == 'actor_table':
                self.assertFalse(env.processes[1].stdout.closed); self.assertEqual(env.processes[1].kill_calls, 0)
            else:
                self.assertTrue(env.processes[1].stdout.closed); self.assertTrue(env.processes[1].stderr.closed)
            self.assertIs(obj._probes[0]['process'], process); self.assertIs(obj._probes[0]['stdout'], original)
            self.assertFalse(obj.status()['closed']); self.assertGreater(obj.status()['probe_processes_pending'], 0)


if __name__ == '__main__': unittest.main()
