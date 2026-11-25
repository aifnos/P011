"""One new HOST cleanup method; selected actual AST, explicit dependencies.

No whole State/Owner startup, Boot load, Popen, OS descriptors, socket/network,
Session worker/finalizer, Native, UI, target or phone runs. None of the older
State16/Gate18 methods are invoked. Every process/clock/FD/HTTP/Session/Trial/
Loader/outer-Owner dependency below is a HOST model, not an admission receipt.
Actual Python RLock/Event/current-thread objects are local HOST primitives.
"""
import ast
import errno
import hashlib
import math
from pathlib import Path
import stat
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
STATE = 'candidate/formal-send-v1/runtime/mta_service.py'
OWNER = 'candidate/formal-send-v1/runtime/mta_client_service_owner.py'
OUTER = 'candidate/formal-send-v1/runtime/formal_send_session.py'
PINS = {
    STATE: (145518, '4c580381a6ed2988ea6fa8f968e8145d3ac21748b49e7e5e9eff7809c55b8c43'),
    OWNER: (46866, '60a5010c02d9e545b437877a939f73eb93fb1262dfeec37e3bf8d714ecf553bc'),
    OUTER: (21984, '290aa340a0aa646563625a2c64297886f11393f6f1e9986920fa9daee63aca19'),
}
STATE_METHODS = ('_close_probes', '_probes_closed', '_cleanup_session_locked', 'close', 'closed')
OWNER_METHODS = ('_context', '_stop_server', '_close_socket', '_close_send_trial',
                 '_cleanup_remaining', '_closed', 'close')
OUTER_METHODS = ('__init__', 'window_current', '_context', 'check', '_close_row', '_closed', 'close')
CASES = (
    'state_join_clipped_to_original_remaining', 'state_join_clipped_to_caller_remaining',
    'state_expiry_zero_wait_still_revokes_and_closes', 'state_partial_session_not_closed',
    'state_changed_original_cap_never_waits', 'state_invalid_budget_starts_nothing',
    'probe_shared_deadline_and_per_actor_remaining', 'probe_expiry_zero_wait_known_actor',
    'probe_unknown_spawn_has_no_actor_operations', 'probe_cached_closed_missing_process_refused',
    'probe_known_unspawned_inventory_not_misclassified', 'probe_foreign_process_never_touched',
    'probe_foreign_pipe_never_touched', 'probe_communicate_failure_keeps_original_error_and_raw',
    'probe_invalid_budget_starts_nothing', 'owner_remaining_clip_and_original_cap_retained',
    'owner_expiry_zero_wait_still_closes_known_socket', 'owner_known_failure_not_erased',
    'owner_idempotent_close_never_renews', 'outer_expiry_still_owner_loader_and_fd_close',
    'outer_owner_failure_still_closes_known_fd', 'outer_fd_failure_retained_other_fd_closed',
    'outer_unknown_fd_not_touched', 'outer_partial_owner_not_invoked_known_fd_closed',
    'outer_idempotent_failure_keeps_originals', 'outer_changed_window_refused_before_foreign_io',
)


class InjectedFailure(RuntimeError):
    pass


class ClockModel:
    """Synthetic monotonic samples; no delay or real clock budget claim."""
    def __init__(self, now=100.0, values=None):
        self.now = float(now)
        self.values = list(values or [])

    def __call__(self):
        if self.values: self.now = float(self.values.pop(0))
        return self.now


class PipeModel:
    def __init__(self):
        self.closed, self.close_calls = False, 0

    def close(self):
        self.close_calls += 1
        self.closed = True


class ProcessModel:
    """Not Popen. Exit/EOF/pipe observations are deliberate HOST assumptions."""
    def __init__(self, argv):
        self.args = argv
        self.stdout, self.stderr = PipeModel(), PipeModel()
        self.returncode = None
        self.calls, self.error = [], None

    def poll(self):
        self.calls.append(('poll',))
        return self.returncode

    def kill(self):
        self.calls.append(('kill',))

    def communicate(self, timeout):
        self.calls.append(('communicate', timeout))
        if self.error is not None: raise self.error
        self.returncode = 0
        return b'HOST_MODEL_OUT', b''


class SessionModel:
    """Not Session78. The actual Session.close/finalizer does not run here."""
    def __init__(self):
        self.calls = []
        self.done = False
        self.error = None

    def close(self, timeout):
        self.calls.append(timeout)
        if self.error is not None: raise self.error
        self.done = True
        return True

    def closed(self):
        return self.done


class TrialModel:
    @staticmethod
    def revoke(value, state, reason):
        value.calls.append(reason)
        value.revoked = True
        return True

    @staticmethod
    def closed(value, state):
        return value.revoked


class BridgeModel:
    pass


class ThreadModel:
    def __init__(self, error=None):
        self.calls, self.error, self.alive = [], error, True

    def join(self, timeout):
        self.calls.append(timeout)
        if self.error is not None: raise self.error
        if timeout > 0: self.alive = False

    def is_alive(self):
        return self.alive


def fixed_source(path):
    raw = (ROOT / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[path]:
        raise ValueError('fixed_cleanup_source_changed')
    return ast.parse(raw, feature_version=(3, 5))


def selected_class(tree, name, methods):
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)
    selected = [node for node in original.body if isinstance(node, ast.FunctionDef) and node.name in methods]
    if len(selected) != len(methods) or set(node.name for node in selected) != set(methods):
        raise ValueError('selected_cleanup_methods_changed')
    return ast.ClassDef(name=name, bases=[ast.Name(id='object', ctx=ast.Load())],
                        keywords=[], body=selected, decorator_list=[])


def execute_selected(path, class_name, methods, namespace, functions=(), classes=(), constants=()):
    tree = fixed_source(path)
    body = [node for node in tree.body if
            isinstance(node, ast.FunctionDef) and node.name in functions or
            isinstance(node, ast.ClassDef) and node.name in classes or
            isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in constants
                                                for target in node.targets)]
    found_functions = {node.name for node in body if isinstance(node, ast.FunctionDef)}
    found_classes = {node.name for node in body if isinstance(node, ast.ClassDef)}
    found_constants = {target.id for node in body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
    if (found_functions != set(functions) or found_classes != set(classes) or
            found_constants != set(constants)):
        raise ValueError('selected_cleanup_helpers_changed')
    body.append(selected_class(tree, class_name, methods))
    unit = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    exec(compile(unit, path, 'exec'), namespace)
    return namespace[class_name]


class StateFixture:
    def __init__(self, cap=110.0, clock=None):
        self.clock = clock or ClockModel()
        self.creator = object()  # Explicit capability-creator identity model.
        self.ns = dict(math=math, time=types.SimpleNamespace(monotonic=self.clock),
                       TransferSession=SessionModel, StateClientBridge=BridgeModel,
                       StateBridgeError=InjectedFailure,
                       send_trial=types.SimpleNamespace(FixedSendTrial=TrialModel),
                       _CAPABILITY_CREATOR=self.creator)
        self.State = execute_selected(STATE, 'State', STATE_METHODS, self.ns, functions=('_probe_closed',))
        self.state = self.State()  # Selected class has no production __init__.
        s = self.state
        s.lock = threading.RLock()
        s._send_trial = types.SimpleNamespace(calls=[], revoked=False)
        s.closing = False
        s.cancelled, s.decision = threading.Event(), threading.Event()
        s.operation = s.session = None
        s.helper = s.key = s.crypto = s.lease = s.transport = s.worker = None
        s.wifi_restore_pending = s.radio_restore_pending = False
        s.probe_actors = s._probe_actors_original = []
        s._probe_creator_original = self.creator
        s._bluez_path_original = 'HOST_MODEL_BLUEZ'
        s.network_path = 'HOST_MODEL_NETWORK'
        s._service_cleanup_until_original = s._original_service_cleanup_until = float(cap)

    def session(self, complete=True):
        s = self.state
        session = SessionModel()
        ticket = dict(creator=SessionModel, partial=session, returned=complete, unknown=not complete)
        s.session = session
        s.operation = types.SimpleNamespace(kind='go_send', session=session, client_bridge=None,
            scan=None, input_ready=threading.Event(), send_ready=threading.Event(),
            go_session_ctor_ticket=ticket)
        return session

    def actor(self, spawned=True, closed=False):
        actors = self.state.probe_actors
        argv = ['HOST_MODEL_BLUEZ', '--capabilities', 'hci0']
        process = ProcessModel(argv) if spawned else None
        popen_identity = object()
        row = dict(creator=self.creator, _creator_original=self.creator, actors=actors,
            _actors_original=actors, process=process, _process_original=process,
            stdout=None if process is None else process.stdout,
            stderr=None if process is None else process.stderr,
            _stdout_original=None if process is None else process.stdout,
            _stderr_original=None if process is None else process.stderr,
            argv=argv, _argv_original=argv, argv_snapshot=tuple(argv),
            popen_creator=popen_identity, _popen_creator_original=popen_identity,
            spawn_pending=False, spawn_unknown=False, spawn_called=spawned, spawn_returned=spawned,
            communicate_called=False, closed=closed, cleanup_calls=[], cleanup_failures=[],
            returncode=None, failure=None, out=b'HOST_ORIGINAL_FIRST_RAW', _out_original=None)
        row['_argv_snapshot_original'] = row['argv_snapshot']
        row['_out_original'] = row['out']
        actors.append(row)
        return row, process


class DescriptorModel:
    """Not OS descriptors. fstat/close/EBADF are explicit inventory models."""
    def __init__(self):
        self.rows, self.closed, self.calls, self.close_errors = {}, set(), [], {}

    def add(self, fd, mode=stat.S_IFREG | 0o400):
        values = (1, fd + 1000, mode, 0, 0, 1, 8)
        self.rows[fd] = types.SimpleNamespace(**dict(zip(
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'), values)))
        return values

    def fstat(self, fd):
        self.calls.append(('fstat', fd))
        if fd in self.closed: raise OSError(errno.EBADF, 'HOST_MODEL_CLOSED')
        return self.rows[fd]

    def close(self, fd):
        self.calls.append(('close', fd))
        if fd in self.close_errors: raise self.close_errors[fd]
        self.closed.add(fd)
        return None

    def pid(self):
        return 900


class SocketModel:
    def __init__(self, descriptors, fd):
        self.descriptors, self.fd, self.shutdown_calls = descriptors, fd, []

    def fileno(self):
        return self.fd

    def close(self):
        return self.descriptors.close(self.fd)

    def shutdown(self, how):
        self.shutdown_calls.append(how)


class OwnerFixture:
    """Execute actual Owner cleanup helpers; startup/IO/HTTP/Trial are modeled."""
    def __init__(self, now=100.0, until=110.0):
        self.clock = ClockModel(now)
        self.descriptors = DescriptorModel()
        self.sys_model = types.SimpleNamespace(modules={})
        ns = dict(math=math, errno=errno, threading=threading, stat=stat,
                  socket=types.SimpleNamespace(SHUT_RDWR=2), sys=self.sys_model, CLEANUP_SECONDS=60.0)
        self.Owner = execute_selected(OWNER, 'FixedStateServiceOwner', OWNER_METHODS, ns,
            functions=('_finite', '_meta', '_fail'), classes=('ServiceOwnerError',))
        self.owner = self.Owner()
        o = self.owner
        self.state_fixture = StateFixture(float(until) + 60.0, self.clock)
        o.state = self.state_fixture.state
        # Owner's idle State has no startup preparation claim or RF inventory.
        o.state._send_trial = None
        o.service = types.SimpleNamespace(State=self.state_fixture.State)
        o.clock = self.clock
        o.worker = threading.current_thread()
        o.lock = threading.RLock()
        o.io = o.original_io = self.descriptors
        o.pid = 900
        o.until = o.original_until = float(until)
        o.boot = types.SimpleNamespace()
        self.sys_model.modules['mta_client_receive_boot'] = o.boot
        o.loader = types.SimpleNamespace(_original_until=o.original_until, clock=o.clock, modules={})
        o.close_called = o.close_complete = o.stop_called = False
        o.cleanup_until = o._cleanup_until_original = None
        o.cleanup_deadline_expired = False
        o.cleanup_clock_failure = None
        o.last = float(now)
        o.state_called = o.state_complete = True
        o.server_called = o.server_complete = False
        o.state_close_called = False
        o.state_close_return = None
        o.server = o.listener = None
        o.probe_rows = o.state.probe_actors
        o.assets, o.requests, o.threads, o.failures = [], [], [], []
        o.send_trial = o.send_trial_ticket = o.send_preflight_ticket = None
        o.send_preflight_parent = None

    def listener(self):
        o = self.owner
        metadata = self.descriptors.add(41, stat.S_IFSOCK | 0o600)
        raw = SocketModel(self.descriptors, 41)
        o.listener = dict(socket=raw, fd=41, metadata=metadata, attempted=False,
                          closed=False, unknown=False, failure=None)
        return o.listener

    def thread(self, error=None):
        value = ThreadModel(error)
        ticket = dict(thread=value, initialized=True, called=True, returned=True,
                      ended=False, unknown=False, failure=None)
        self.owner.threads.append(ticket)
        return value, ticket


class OuterOwnerModel:
    """Only the outer Owner dependency is modeled, never an RF producer."""
    def __init__(self, error=None):
        self.calls, self.error, self.close_complete = [], error, False

    @staticmethod
    def close(value):
        value.calls.append('close')
        if value.error is not None: raise value.error
        value.close_complete = True
        return True


class LoaderModel:
    @staticmethod
    def _close_row(value, row):
        value.calls.append(row)
        if row.get('error') is not None: raise row['error']
        row['closed'] = True
        return True


class OuterFixture:
    def __init__(self):
        self.clock = ClockModel()
        self.descriptors = DescriptorModel()
        self.ns = dict(math=math, errno=errno, threading=threading,
            time=types.SimpleNamespace(monotonic=self.clock),
            os=types.SimpleNamespace(getpid=self.descriptors.pid, fstat=self.descriptors.fstat,
                                     close=self.descriptors.close),
            sys=types.SimpleNamespace(modules={}))
        self.Outer = execute_selected(OUTER, 'FixedSendSession', OUTER_METHODS, self.ns,
            functions=('_finite', '_meta', '_fail'), classes=('SendSessionError',),
            constants=('ROOT', 'RUNTIME', 'PROFILES'))
        self.outer = self.Outer()  # Actual selected constructor, synthetic clock/PID only.
        o = self.outer
        o.owner = OuterOwnerModel()
        o.owner_ticket = dict(creator=OuterOwnerModel, constructed=True,
                             close_called=False, close_return=None, close_failure=None)
        o.loader = types.SimpleNamespace(rows=[dict(closed=False, unknown=False)],
                                        pending=False, calls=[])
        o.loader_ticket = dict(constructed=True)
        o.boot = types.SimpleNamespace(BootSourceLoader=LoaderModel)

    def fd(self, fd, unknown=False):
        metadata = self.descriptors.add(fd)
        row = dict(fd=fd, metadata=metadata, attempted=False, closed=False, unknown=unknown,
                   close_return=None, close_error=None, close_failure=None)
        self.outer.rows.append(row)
        return row


class CleanupBudgetTests(unittest.TestCase):
    def test_new_cleanup_budget_contracts(self):
        cases = []

        def case(name, callback):
            with self.subTest(contract=name): callback()
            cases.append(name)
            print('HOST_SEND_CLEANUP_BUDGET_CASE=' + name)

        def state_remaining():
            f = StateFixture(101.25); session = f.session()
            self.assertTrue(f.state.close())
            self.assertEqual(session.calls, [1.25])
            self.assertTrue(f.state.cancelled.is_set())
            self.assertTrue(f.state.operation.input_ready.is_set())
            self.assertEqual(f.state._send_trial.calls, ['state_closing'])
        case(CASES[0], state_remaining)

        def caller_remaining():
            f = StateFixture(110.0); session = f.session()
            self.assertTrue(f.state.close(timeout=0.25))
            self.assertEqual(session.calls, [0.25])
        case(CASES[1], caller_remaining)

        def state_expired():
            f = StateFixture(99.0); session = f.session()
            self.assertTrue(f.state.close())  # Only model-local closure, not restoration.
            self.assertEqual(session.calls, [0.0])
            self.assertTrue(f.state.cancelled.is_set())
            self.assertTrue(f.state._send_trial.revoked)
            self.assertTrue(f.state.operation.send_ready.is_set())
        case(CASES[2], state_expired)

        def partial_session():
            f = StateFixture(); session = f.session(complete=False)
            original = f.state.operation.go_session_ctor_ticket
            self.assertFalse(f.state.close())
            self.assertEqual(session.calls, [])
            self.assertIs(f.state.operation.go_session_ctor_ticket, original)
            self.assertIs(f.state.session, session)
            self.assertTrue(f.state.cancelled.is_set())
        case(CASES[3], partial_session)

        def changed_cap():
            f = StateFixture(110.0); session = f.session()
            original = f.state._original_service_cleanup_until
            f.state._service_cleanup_until_original = float('110.0')
            self.assertIsNot(f.state._service_cleanup_until_original, original)
            self.assertTrue(f.state.close())
            self.assertEqual(session.calls, [0.0])
        case(CASES[4], changed_cap)

        def invalid_state_budget():
            f = StateFixture(); session = f.session()
            for value in (-1, 31, True, float('nan')):
                with self.assertRaises(ValueError): f.state.close(timeout=value)
            self.assertEqual(session.calls, [])
            self.assertFalse(f.state.cancelled.is_set())
        case(CASES[5], invalid_state_budget)

        def shared_probe_cap():
            f = StateFixture(110.0, ClockModel(values=[100, 100.2, 100.6]))
            first, p1 = f.actor(); second, p2 = f.actor()
            self.assertTrue(f.state._close_probes(timeout=3, cleanup_until=101.0))
            waits = [next(row[1] for row in p.calls if row[0] == 'communicate') for p in (p1, p2)]
            self.assertAlmostEqual(waits[0], 0.8)
            self.assertAlmostEqual(waits[1], 0.4)
            self.assertEqual(first['cleanup_calls'][0]['cleanup_until'], 101.0)
            self.assertEqual(second['cleanup_calls'][0]['cleanup_until'], 101.0)
        case(CASES[6], shared_probe_cap)

        def expired_probe():
            f = StateFixture(99.0); row, process = f.actor()
            self.assertTrue(f.state._close_probes())
            self.assertIn(('kill',), process.calls)
            self.assertIn(('communicate', 0.0), process.calls)
            self.assertTrue(row['closed'])
        case(CASES[7], expired_probe)

        def unknown_spawn():
            f = StateFixture(); row, process = f.actor(closed=True)
            row['spawn_unknown'] = True
            self.assertFalse(f.state._close_probes())
            self.assertEqual(process.calls, [])
            self.assertFalse(row['closed'])
            self.assertEqual(row['cleanup_calls'], [])
            self.assertTrue(row['cleanup_failures'])
        case(CASES[8], unknown_spawn)

        def missing_process():
            f = StateFixture(); row, process = f.actor(closed=True)
            row['process'] = None
            self.assertFalse(f.state._close_probes())
            self.assertEqual(process.calls, [])
            self.assertIs(row['_process_original'], process)
            self.assertFalse(row['closed'])
        case(CASES[9], missing_process)

        def never_spawned():
            f = StateFixture(); row, process = f.actor(spawned=False, closed=True)
            self.assertIsNone(process)
            self.assertTrue(f.state._close_probes())
            self.assertEqual(row['cleanup_calls'], [])
            self.assertEqual(row['cleanup_failures'], [])
        case(CASES[10], never_spawned)

        def foreign_process():
            f = StateFixture(); row, original = f.actor()
            foreign = ProcessModel(list(original.args)); row['process'] = foreign
            self.assertFalse(f.state._close_probes())
            self.assertEqual(foreign.calls, [])
            self.assertEqual(original.calls, [])
            self.assertIs(row['_process_original'], original)
            self.assertTrue(row['cleanup_failures'])
        case(CASES[11], foreign_process)

        def foreign_pipe():
            f = StateFixture(); row, process = f.actor()
            original = row['_stdout_original']; process.stdout = PipeModel()
            self.assertFalse(f.state._close_probes())
            self.assertEqual(process.calls, [])
            self.assertEqual(process.stdout.close_calls, 0)
            self.assertIs(row['_stdout_original'], original)
        case(CASES[12], foreign_pipe)

        def communicate_failure():
            f = StateFixture(99.0); row, process = f.actor()
            original_raw = row['out']; original_error = InjectedFailure('HOST_first_failure')
            row['failure'] = original_error
            failure = process.error = InjectedFailure('HOST_communicate_failure')
            self.assertFalse(f.state._close_probes())
            self.assertIs(row['cleanup_calls'][0]['error'], failure)
            self.assertIn(failure, row['cleanup_failures'])
            self.assertIs(row['failure'], original_error)
            self.assertIs(row['out'], original_raw)
            self.assertIs(row['_out_original'], original_raw)
            self.assertIn(('communicate', 0.0), process.calls)
            self.assertFalse(row['closed'])
        case(CASES[13], communicate_failure)

        def invalid_probe_budget():
            f = StateFixture(); row, process = f.actor()
            for value in (-1, 4, True, float('nan')):
                with self.assertRaises(ValueError): f.state._close_probes(timeout=value)
            self.assertEqual(process.calls, [])
            self.assertEqual(row['cleanup_calls'], [])
        case(CASES[14], invalid_probe_budget)

        def owner_remaining():
            f = OwnerFixture(now=169.5, until=110.0)
            # Explicit previous idle-Session model, not a native GO.
            session = SessionModel(); f.owner.state.session = session
            thread, ticket = f.thread()
            self.assertTrue(f.owner.close())
            self.assertEqual(session.calls, [0.5])
            self.assertEqual(thread.calls, [0.5])
            self.assertEqual(f.owner.cleanup_until, 170.0)
            self.assertIs(f.owner.cleanup_until, f.owner._cleanup_until_original)
            self.assertTrue(ticket['ended'])
        case(CASES[15], owner_remaining)

        def owner_expired():
            f = OwnerFixture(now=171.0, until=110.0)
            session = SessionModel(); f.owner.state.session = session
            listener = f.listener(); thread, ticket = f.thread()
            self.assertFalse(f.owner.close())
            self.assertEqual(session.calls, [0.0])
            self.assertEqual(thread.calls, [0.0])
            self.assertTrue(listener['closed'])
            self.assertTrue(f.owner.cleanup_deadline_expired)
            self.assertTrue(f.owner.state_close_called)
            self.assertFalse(ticket['ended'])
        case(CASES[16], owner_expired)

        def owner_failure():
            f = OwnerFixture(now=171.0, until=110.0)
            failure = InjectedFailure('HOST_join_failure')
            listener = f.listener(); thread, ticket = f.thread(failure)
            self.assertFalse(f.owner.close())
            self.assertIs(ticket['failure'], failure)
            self.assertIn(failure, f.owner.failures)
            self.assertTrue(listener['closed'])
            self.assertEqual(thread.calls, [0.0])
        case(CASES[17], owner_failure)

        def owner_idempotent():
            f = OwnerFixture(now=171.0, until=110.0); thread, ticket = f.thread()
            self.assertFalse(f.owner.close())
            original = f.owner.cleanup_until
            f.clock.now = 200.0
            self.assertFalse(f.owner.close())
            self.assertIs(f.owner.cleanup_until, original)
            self.assertEqual(thread.calls, [0.0])
        case(CASES[18], owner_idempotent)

        def outer_expired():
            f = OuterFixture(); row = f.fd(71); f.clock.now = 221.0
            self.assertFalse(f.outer.close())
            self.assertEqual(f.outer.owner.calls, ['close'])
            self.assertEqual(f.outer.loader.calls, f.outer.loader.rows)
            self.assertTrue(row['closed'])
            self.assertTrue(f.outer.owner_ticket['close_called'])
            self.assertEqual(f.outer.close_failure.code, 'deadline')
            self.assertTrue(f.outer.pending)
        case(CASES[19], outer_expired)

        def outer_owner_failure():
            f = OuterFixture(); row = f.fd(72)
            failure = f.outer.owner.error = InjectedFailure('HOST_outer_owner_failure')
            self.assertFalse(f.outer.close())
            self.assertIs(f.outer.owner_ticket['close_failure'], failure)
            self.assertIs(f.outer.close_failure, failure)
            self.assertTrue(row['closed'])
            self.assertTrue(f.outer.loader.rows[0]['closed'])
        case(CASES[20], outer_owner_failure)

        def outer_fd_failure():
            f = OuterFixture(); good = f.fd(73); failed = f.fd(74)
            failure = InjectedFailure('HOST_descriptor_close_failure')
            f.descriptors.close_errors[74] = failure
            self.assertFalse(f.outer.close())
            self.assertIs(failed['close_failure'], failure)
            self.assertTrue(failed['unknown'])
            self.assertFalse(failed['closed'])
            self.assertTrue(good['closed'])
            self.assertEqual(f.outer.owner.calls, ['close'])
        case(CASES[21], outer_fd_failure)

        def outer_unknown_fd():
            f = OuterFixture(); row = f.fd(75, unknown=True)
            self.assertFalse(f.outer.close())
            self.assertEqual(f.descriptors.calls, [])
            self.assertFalse(row['closed'])
            self.assertTrue(row['unknown'])
        case(CASES[22], outer_unknown_fd)

        def outer_partial_owner():
            f = OuterFixture(); row = f.fd(76)
            f.outer.owner_ticket['constructed'] = False
            self.assertFalse(f.outer.close())
            self.assertEqual(f.outer.owner.calls, [])
            self.assertTrue(row['closed'])
            self.assertEqual(f.outer.close_failure.code, 'owner_constructor_unknown')
        case(CASES[23], outer_partial_owner)

        def outer_idempotent():
            f = OuterFixture(); row = f.fd(77); f.clock.now = 221.0
            self.assertFalse(f.outer.close())
            original = f.outer.close_failure; calls = list(f.descriptors.calls)
            f.clock.now = 300.0
            self.assertFalse(f.outer.close())
            self.assertIs(f.outer.close_failure, original)
            self.assertEqual(f.descriptors.calls, calls)
            self.assertEqual(f.outer.owner.calls, ['close'])
            self.assertTrue(row['closed'])
        case(CASES[24], outer_idempotent)

        def changed_window():
            f = OuterFixture(); row = f.fd(78)
            original = f.outer.until
            f.outer.until = float(str(original))
            self.assertIsNot(f.outer.until, original)
            with self.assertRaisesRegex(ValueError, 'original_owner_changed'): f.outer.close()
            self.assertEqual(f.descriptors.calls, [])
            self.assertFalse(row['closed'])
        case(CASES[25], changed_window)
        self.assertEqual(tuple(cases), CASES)
        print('FORMAL_SEND_CLEANUP_BUDGET_CONTRACTS=' + str(len(cases)))


if __name__ == '__main__':
    unittest.main()
