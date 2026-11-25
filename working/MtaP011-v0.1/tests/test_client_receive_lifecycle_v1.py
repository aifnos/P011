"""Narrow HOST function tests for the independent receive lifecycle candidate.

One new method, no old HOST98 method, full Boot load or native graph replay.
Only fixed changed runtime sources are parsed. The original affected State/
Owner methods and original Operation class are extracted, not reimplemented;
Session78 definitions/constructor/start/close are actual. State/Owner constructors,
Factory, F, filesystem authority, HTTP actors and native restoration are NOT
tested. Those inputs are explicitly inert HOST fixtures. A closed HOST Session
never proves radio/network/device/phone restoration or receive admission.

SOURCE author did not run Python/AST/import/tests. ROOT is the sole executor.
Run from project root: python tests/test_client_receive_lifecycle_v1.py
"""
import ast
import copy
import hashlib
import math
from pathlib import Path
import socket
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
RUNTIME = 'candidate/client-receive-lifecycle-v1/runtime/'
PINS = {
    'state': (RUNTIME + 'mta_service.py', 101435,
              '53103737bae89ec0ca3ee5fcda0a975d6dabdf7a056d7b9e1344b93c9111537c'),
    'boot': (RUNTIME + 'mta_client_receive_boot.py', 19091,
             '93b234e76938544bf5f2fd9880f36cff97a140d4b8a583e9c948dc02d10d05f1'),
    'owner': (RUNTIME + 'mta_client_service_owner.py', 29671,
              '56dff1cc82e2ee9260250dc443de05d6db5169ae2718d2ca3ff6ef43c6303425'),
    'session': ('candidate/go-send-state-v78/runtime/mta_transfer_session.py', 20633,
                'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859'),
}
METHOD = 'test_receive_lifecycle'
MARKER = ('HOST_RECEIVE_LIFECYCLE new_methods=1 old_methods=0 cases=6 '
          'functions_only=true session78_actual=true full_graph=false '
          'fs_fixture=true http_actor_fixture=true native_restore_fixture=true '
          'receive_admission=false device=false phone=false\n')


def _raw(name):
    path, size, digest = PINS[name]
    data = (BASE / path).read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != (size, digest):
        raise ValueError('fixed_source_changed:' + name)
    return data


def _module(nodes):
    value = ast.Module(body=copy.deepcopy(nodes), type_ignores=[])
    return ast.fix_missing_locations(value)


def _class(tree, name):
    values = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
    if len(values) != 1:
        raise ValueError('class_identity:' + name)
    return values[0]


def _selected_class(tree, name, methods):
    original = _class(tree, name)
    selected = copy.deepcopy(original)
    selected.body = [copy.deepcopy(n) for n in original.body
                     if isinstance(n, ast.FunctionDef) and n.name in methods]
    if {n.name for n in selected.body} != set(methods):
        raise ValueError('method_identity:' + name)
    return selected


def _assigned(tree, name):
    values = [n.value for n in tree.body if isinstance(n, ast.Assign) and
              any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    if len(values) != 1:
        raise ValueError('constant_identity:' + name)
    return ast.literal_eval(values[0])


class _BridgeFixture:
    """Unused dependency identity only; never a native constructor."""
    def __init__(self, *args, **kwargs):
        raise AssertionError('HOST must not construct a native bridge')


class _BridgeErrorFixture(Exception):
    pass


def _functions():
    state_tree = ast.parse(_raw('state').decode('utf-8'), filename=PINS['state'][0])
    owner_tree = ast.parse(_raw('owner').decode('utf-8'), filename=PINS['owner'][0])
    boot_tree = ast.parse(_raw('boot').decode('utf-8'), filename=PINS['boot'][0])
    # Static assembly only: no BootSourceLoader/load/authenticate/main execution.
    boot_rows = _boot_rows(boot_tree)
    if len(boot_rows) != 28 or boot_rows[-1] != ('mta_service',) + PINS['state'][1:]:
        raise ValueError('state_pin_not_assembled')
    if _assigned(owner_tree, 'BOOT_PIN') != PINS['boot'][1:]:
        raise ValueError('boot_pin_not_assembled')
    state_init = next(n for n in _class(state_tree, 'State').body
                      if isinstance(n, ast.FunctionDef) and n.name == '__init__')
    if not any(isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and
               n.value.value is False and any(isinstance(t, ast.Attribute) and
               isinstance(t.value, ast.Name) and t.value.id == 'self' and
               t.attr == 'receive_available' for t in n.targets)
               for n in ast.walk(state_init)):
        raise ValueError('receive_gate_not_false')
    session = types.ModuleType('actual_session78_lifecycle_private')
    exec(compile(_raw('session').decode('utf-8'), PINS['session'][0], 'exec'),
         session.__dict__)
    service = types.ModuleType('receive_lifecycle_functions_private')
    service.__dict__.update(threading=threading, math=math,
        TransferSession=session.TransferSession, StateClientBridge=_BridgeFixture,
        StateBridgeError=_BridgeErrorFixture)
    nodes = [_class(state_tree, 'Operation'),
             _selected_class(state_tree, 'State', (
                 '_new_operation_locked', '_cleanup_session_locked',
                 '_probes_closed', 'close', 'closed'))]
    exec(compile(_module(nodes), PINS['state'][0], 'exec'), service.__dict__)
    owner = types.ModuleType('receive_owner_functions_private')
    owner.__dict__.update(threading=threading, socket=socket, math=math,
                          CLEANUP_SECONDS=60.0)
    helper_names = ('ServiceOwnerError', '_fail', '_finite')
    helpers = [n for n in owner_tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
               and n.name in helper_names]
    if {n.name for n in helpers} != set(helper_names):
        raise ValueError('owner_helpers_identity')
    nodes = helpers + [_selected_class(owner_tree, 'FixedStateServiceOwner', (
        '_now', '_stop_server', 'close', '_state_closed', '_closed'))]
    exec(compile(_module(nodes), PINS['owner'][0], 'exec'), owner.__dict__)
    return session, service, owner


def _boot_rows(tree):
    """Resolve only tuple literals plus its existing F37_SHA scalar."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id == 'SOURCE_PINS' for t in node.targets):
            value = copy.deepcopy(node.value)
            for row in value.elts:
                for index, item in enumerate(row.elts):
                    if isinstance(item, ast.Name) and item.id == 'F37_SHA':
                        row.elts[index] = ast.Constant(value=_assigned(tree, 'F37_SHA'))
            return ast.literal_eval(value)
    raise ValueError('boot_pins_missing')


class _JoinFixture:
    """HTTP thread inventory fixture; no socket/thread is started."""
    def __init__(self, events, state):
        self.events, self.state = events, state
    def join(self, timeout):
        if self.state.closing is not True:
            raise AssertionError('HTTP join preceded State.close')
        self.events.append(('http_join_fixture', timeout))
    def is_alive(self):
        return False


class ReceiveLifecycleTest(unittest.TestCase):
    def test_receive_lifecycle(self):
        # Narrow static readback plus methods. Native actors remain fixtures.
        session, service, owner_module = _functions()
        restore_reads = []
        service.State._restore_receive_owner = (
            lambda state, op: restore_reads.append((state, op)) or True)
        completed = []

        def new_state(until):
            state = service.State.__new__(service.State)
            state.lock = threading.RLock()
            state.session = state.operation = state.worker = None
            state.helper = state.key = state.crypto = state.lease = state.transport = None
            state.history = []
            state.native_epoch = 0
            state.wifi_backend = object()  # Inert, never receives a method call.
            state._trusted_receive_deployment_factory = object()  # Not callable/admission.
            state._service_until_original = until
            state.cancelled = threading.Event()
            state.decision = threading.Event()
            state.closing = False
            state.wifi_restore_pending = state.radio_restore_pending = False
            state.probe_actors = []
            state.receive_available = False
            state._run_operation = mock.Mock(side_effect=AssertionError('no HOST RF task'))
            # Actual Session78 invokes these only in explicit HOST closure.
            # They do NOT model native restoration or filesystem ownership.
            state._restore_owner = mock.Mock(return_value=True)
            state._close_extra = mock.Mock(return_value=True)
            return state

        def new_receive(until):
            state = new_state(until)
            with state.lock:
                op = state._new_operation_locked('receive')
            self.assertIs(type(op), service.Operation)
            self.assertIs(type(op.session), session.TransferSession)
            self.assertIs(op, state.operation)
            self.assertIs(op.session, state.session)
            self.assertIs(state.worker, op.session._worker)
            self.assertIs(op.receive_factory, state._trusted_receive_deployment_factory)
            self.assertIsNone(op.backend)
            self.assertIs(state.receive_available, False)
            return state, op

        def new_owner(state, events, clock_value=100.0, until=110.0):
            value = owner_module.FixedStateServiceOwner.__new__(
                owner_module.FixedStateServiceOwner)
            value.service = service
            value.state = state
            value.factory = state._trusted_receive_deployment_factory
            value.worker = threading.current_thread()
            value.clock = lambda: clock_value
            value.until = until
            value.lock = threading.RLock()
            value.last = value.cleanup_until = None
            # _context filesystem/loader authorization intentionally untested.
            value._context = mock.Mock(return_value=None)
            value.close_called = value.close_complete = value.stop_called = False
            value.state_called = value.state_complete = True
            value.server_called = value.server_complete = False
            value.state_close_called = False
            value.state_close_return = None
            value.assets = []; value.requests = []; value.listener = None
            value.failures = []
            value.probe_rows = state.probe_actors
            thread = _JoinFixture(events, state)
            value.threads = [{'thread': thread, 'initialized': True, 'called': True,
                             'returned': True, 'ended': False, 'unknown': False}]
            return value

        # No native probe actor is executed. This explicit fixture only supplies
        # the empty/already-known actor-list behavior for Owner ordering tests.
        def close_probes_fixture(state):
            for row in state.probe_actors:
                row['closed'] = True
            return state._probes_closed()
        service.State._close_probes = close_probes_fixture

        with self.subTest(case='original_receive_absolute_cap'):
            state, op = new_receive(150.0)
            value = op.session
            starts = []
            with mock.patch.object(threading.Thread, 'start', autospec=True,
                    side_effect=lambda actor: starts.append(actor)), \
                    mock.patch.object(session.time, 'monotonic', return_value=100.0):
                self.assertIs(value.start(), value)
            self.assertEqual(150.0, value._absolute_until_original)
            self.assertEqual(150.0, value._task_deadline)
            self.assertIs(value._task_deadline, value._absolute_until_original)
            self.assertEqual([value._worker, value._attempts[0]['thread']], starts)
            self.assertEqual(120.0, value.finalize_timeout)  # Cleanup wait, NOT renewed task activity.
            self.assertFalse(value.closed())  # Intercepted starts do not prove exit.
            self.assertEqual(0, state._run_operation.call_count)
            self.assertEqual(0, state._restore_owner.call_count)
            self.assertFalse(value._restore_done)
            self.assertFalse(value._all_stages_done)
            for actor in starts:
                self.assertIsNone(actor.ident)
            expired_state, expired_op = new_receive(100.0)
            with mock.patch.object(threading.Thread, 'start', autospec=True) as start, \
                    mock.patch.object(session.time, 'monotonic', return_value=100.0):
                with self.assertRaisesRegex(session.SessionError, 'absolute_until_expired'):
                    expired_op.session.start()
            self.assertEqual(0, start.call_count)
            self.assertFalse(expired_op.session._worker_start_claimed)
            completed.append('original_receive_absolute_cap')

        with self.subTest(case='state_shortened_close_and_invalid_budget'):
            state, op = new_receive(time.monotonic() + 10.0)
            original = (state.operation, state.session, state.worker)
            with mock.patch.object(op.session, 'close', return_value=False) as close:
                self.assertFalse(state.close(timeout=0.125))
            self.assertEqual(mock.call(timeout=0.125), close.call_args)
            self.assertTrue(state.closing)
            self.assertTrue(op.cancelled.is_set())
            self.assertTrue(op.input_ready.is_set())
            self.assertTrue(op.send_ready.is_set())
            self.assertTrue(all(actual is prior for actual, prior in zip(
                (state.operation, state.session, state.worker), original)))
            invalids = (True, -1, 30.01, float('nan'), float('inf'), '1')
            with mock.patch.object(op.session, 'close') as close:
                for invalid in invalids:
                    with self.assertRaisesRegex(ValueError, 'Invalid State close budget'):
                        state.close(timeout=invalid)
            self.assertEqual(0, close.call_count)
            completed.append('state_shortened_close_and_invalid_budget')

        with self.subTest(case='owner_original_state_session_close_before_http_join'):
            events = []
            state, op = new_receive(time.monotonic() + 10.0)
            state._close_extra.side_effect = lambda original: events.append(('session_extra_fixture', original)) or True
            state._restore_owner.side_effect = lambda original: events.append(('session_restore_fixture', original)) or True
            value = new_owner(state, events, clock_value=105.0, until=50.0)
            originals = (state.operation, state.session, state.worker,
                         state.helper, state.key, state.crypto, state.lease, state.transport)
            # Original cleanup_until=min(now+60,service_until+60)=110; only 5s
            # is handed to actual State.close/Session.close, not a new 30s cap.
            with mock.patch.object(service.State, 'close', autospec=True,
                    side_effect=service.State.close) as actual_close:
                self.assertTrue(value.close())
            self.assertEqual(mock.call(state, timeout=5.0), actual_close.call_args)
            self.assertEqual(['session_extra_fixture', 'session_restore_fixture', 'http_join_fixture'],
                             [row[0] for row in events])
            self.assertTrue(op.session.closed())
            self.assertIs(value.state_close_return, True)
            self.assertEqual(1, state._restore_owner.call_count)
            self.assertEqual([(state, op)], restore_reads)
            self.assertTrue(all(actual is prior for actual, prior in zip(
                (state.operation, state.session, state.worker,
                 state.helper, state.key, state.crypto, state.lease, state.transport), originals)))
            before = list(events)
            self.assertTrue(value.close())
            self.assertEqual(before, events)  # Once close, no renewed callbacks.
            completed.append('owner_original_state_session_close_before_http_join')

        with self.subTest(case='owner_wrong_original_identity_rejected'):
            # The already-closed actual HOST Session provides only the local
            # Session exit fact. Exact identity checks still precede fixture
            # native restoration, whose call count must not change on denies.
            before = len(restore_reads)
            op_session, worker, epoch, factory, kind = (
                op.session, state.worker, state.native_epoch, op.receive_factory, op.kind)
            for name, install, revert in (
                    ('operation_session', lambda: setattr(op, 'session', object()),
                     lambda: setattr(op, 'session', op_session)),
                    ('worker', lambda: setattr(state, 'worker', object()),
                     lambda: setattr(state, 'worker', worker)),
                    ('epoch', lambda: setattr(state, 'native_epoch', epoch + 1),
                     lambda: setattr(state, 'native_epoch', epoch)),
                    ('factory', lambda: setattr(op, 'receive_factory', object()),
                     lambda: setattr(op, 'receive_factory', factory)),
                    ('kind', lambda: setattr(op, 'kind', 'send'),
                     lambda: setattr(op, 'kind', kind))):
                with self.subTest(identity=name):
                    install()
                    try:
                        self.assertFalse(value._state_closed())
                        self.assertEqual(before, len(restore_reads))
                    finally:
                        revert()
            derived = type('DerivedState', (service.State,), {})
            wrong_state = derived.__new__(derived)
            wrong_state.__dict__.update(state.__dict__)
            value.state = wrong_state
            try:
                self.assertFalse(value._state_closed())
                self.assertEqual(before, len(restore_reads))
            finally:
                value.state = state
            completed.append('owner_wrong_original_identity_rejected')

        with self.subTest(case='owner_false_restore_or_changed_retained_object_not_closed'):
            native_ref = service.State._restore_receive_owner
            try:
                service.State._restore_receive_owner = lambda state, op: False
                self.assertFalse(value._state_closed())
                changed = object()
                def changed_fixture(current, original):
                    current.helper = changed
                    return True
                service.State._restore_receive_owner = changed_fixture
                self.assertFalse(value._state_closed())
                self.assertIs(state.helper, changed)  # Never erase fixture unknown to get None.
            finally:
                service.State._restore_receive_owner = native_ref
            completed.append('owner_false_restore_or_changed_retained_object_not_closed')

        with self.subTest(case='probe_late_close_never_upgrades_false_state_close'):
            events = []
            state, op = new_receive(time.monotonic() + 10.0)
            state.probe_actors.append({'spawn_pending': False, 'spawn_unknown': False, 'closed': False})
            value = new_owner(state, events)
            retained = (state.operation, state.session, state.worker)
            before_reads = len(restore_reads)
            self.assertFalse(value.close())
            self.assertIs(value.state_close_return, False)
            self.assertTrue(state.session.closed())  # Actual local finalizer did run.
            self.assertEqual(1, state._restore_owner.call_count)
            self.assertTrue(state._probes_closed())  # Later explicit fixture cleanup.
            self.assertTrue(state.closed())  # Passive local State now closed.
            self.assertFalse(value._state_closed())  # Original False return retained.
            self.assertFalse(value._closed())
            self.assertFalse(value.close())  # Once close does not invent a recheck entry.
            self.assertEqual(before_reads, len(restore_reads))
            self.assertTrue(all(actual is prior for actual, prior in zip(
                (state.operation, state.session, state.worker), retained)))
            completed.append('probe_late_close_never_upgrades_false_state_close')

        self.assertEqual(6, len(completed))


def _main():
    if sys.argv[1:] not in ([], ['-q']):
        return 2
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(
        unittest.TestSuite([ReceiveLifecycleTest(METHOD)]))
    if result.wasSuccessful():
        sys.stdout.write(MARKER)
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(_main())
