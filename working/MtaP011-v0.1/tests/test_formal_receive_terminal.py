"""Focused HOST scope of the new passive receive terminal gates.

Extract only the actual new State terminal methods/context, actual Operation
definition and runner idle/terminal method. Never construct the production
State/Owner, collect a baseline, start a Parent/helper, grant admission or RF.
Network classes/normalizer/comparison are the actual pinned producer. Their
finished no-actor call inventories and native DATA are explicit HOST models.
State.closed/probes, TransferSession stages, Owner and Parent/reap are explicit
ancestry models, not receipts or device restoration. A real joined HOST Thread
supplies original worker identity. No old consumer/finalizer tests are invoked.
"""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
STATE = BASE / 'candidate/formal-receive-v1/runtime/mta_service.py'
STATE_PIN = (125890, 'ea9db41a5f2c529ac8193381359e578336a2ffdcfcd5c32e5787c25b3d2067ee')
RUNNER = BASE / 'candidate/formal-receive-v1/runtime/mta_formal_receive_session.py'
RUNNER_PIN = (73287, '3d67fa640e9b16844d938d8da07c51ac863fe611b04bc9b70d646267a304c4a9')
NETWORK = BASE / 'runtime/mta_receive_network.py'
NETWORK_PIN = (15860, '1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6')
CODEC = BASE / 'runtime/p011_json.py'
CODEC_PIN = (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
SPEC = ('/HOST/never-executed-observer', 52, '0' * 64)


def fixed_bytes(path, pin):
    raw = path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
        raise AssertionError('Focused fixed SOURCE differs')
    return raw


def module_at(path, pin, name):
    fixed_bytes(path, pin)
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def forbidden(*args, **kwargs):
    raise AssertionError('Passive gate attempted active close/observe/restore')


class StateClosureScopeModel(object):
    """Only pre-existing resource stages: not actual State/daemon evidence."""
    def closed(self):
        return self.state_closed_known

    def _probes_closed(self):
        return self.probes_closed_known

    def _restore_owner(self, op):
        return forbidden()

    def _close_extra(self, op):
        return forbidden()


class SessionClosureScopeModel(object):
    def __init__(self, state, op, worker, until):
        self.cancelled = op.cancelled
        self._worker = worker
        self._lease_owner = op
        self._absolute_until = self._absolute_until_original = until
        self._task_deadline = until
        self._restore, self._extra = state._restore_owner, state._close_extra
        self._restore_done = self._extra_done = True
        self.closed_known = True
        self.status_overrides = {}

    def closed(self):
        return (self.closed_known and not self._worker.is_alive() and
                self._restore_done and self._extra_done)

    def status(self):
        row = dict((key, True) for key in ('transports_verified', 'release_verified',
                   'extra_actors_verified', 'restore_verified'))
        row['closed'] = self.closed()
        row.update(dict((key, 0) for key in ('finalizers_alive', 'finalizer_starts_pending',
            'finalizer_starts_unknown', 'callbacks_pending', 'transport_count',
            'handoff_count', 'unknown_owner_count')))
        row.update({'worker_alive': self._worker.is_alive(),
                    'worker_start_pending': False, 'worker_start_unknown': False})
        row.update(self.status_overrides)
        return row


class BridgeClosureScopeModel(object):
    """Explicit retained Parent/reap model; child DATA is never consumed."""
    def __init__(self, state, op):
        self.state, self.operation = state, op
        self.handoff = op.client_handoff = object()
        self.started, self.running = True, False
        self.parent, self.deployment = object(), object()
        self.parent_reaped = True
        self.cached_child_restored = True
        self.checks = 0

    @staticmethod
    def _owners(bridge):
        if bridge.operation is not bridge.state.operation:
            raise AssertionError('Original HOST Bridge ancestry changed')

    @staticmethod
    def restoration_verified(bridge):
        bridge.checks += 1
        return bridge.parent_reaped


def load_methods():
    codec = module_at(CODEC, CODEC_PIN, '_host_formal_terminal_codec')
    with mock.patch.dict(sys.modules, {'p011_json': codec}):
        network = module_at(NETWORK, NETWORK_PIN, '_host_formal_terminal_network')
    tree = ast.parse(fixed_bytes(STATE, STATE_PIN).decode('utf-8'), filename=str(STATE))
    operation = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Operation']
    state = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'State']
    wanted = ('_receive_network_context', '_receive_network_terminal_closed', '_receive_terminal_closed')
    if len(operation) != 1 or len(state) != 1:
        raise AssertionError('Actual Operation/State SOURCE missing')
    selected = [node for node in state[0].body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    if len(selected) != len(wanted) or {node.name for node in selected} != set(wanted):
        raise AssertionError('Actual passive State methods missing')
    state[0].body = selected
    state[0].bases = [ast.Name(id='StateClosureScopeModel', ctx=ast.Load())]
    namespace = {'__name__': '_host_actual_formal_terminal', 'threading': threading, 'time': time,
                 'network_restore': network, 'StateClosureScopeModel': StateClosureScopeModel,
                 'TransferSession': SessionClosureScopeModel, 'StateClientBridge': BridgeClosureScopeModel}
    unit = ast.Module(body=operation + state, type_ignores=[])
    ast.fix_missing_locations(unit)
    exec(compile(unit, str(STATE), 'exec'), namespace)
    rtree = ast.parse(fixed_bytes(RUNNER, RUNNER_PIN).decode('utf-8'), filename=str(RUNNER))
    runners = [node for node in rtree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedSession']
    if len(runners) != 1:
        raise AssertionError('Actual FixedSession SOURCE missing')
    wanted_runner = {'idle', 'terminal_inventory_closed'}
    runners[0].body = [node for node in runners[0].body if isinstance(node, ast.FunctionDef)
                       and node.name in wanted_runner]
    if {node.name for node in runners[0].body} != wanted_runner:
        raise AssertionError('Actual runner terminal methods missing')
    unit = ast.Module(body=runners, type_ignores=[])
    ast.fix_missing_locations(unit)
    exec(compile(unit, str(RUNNER), 'exec'), namespace)
    return namespace['Operation'], namespace['State'], namespace['FixedSession'], network


def native_data():
    return {'event': 'network_observation', 'network_schema': 'p011-connman-network-baseline-v1',
            'ok': True, 'identity_known': True, 'technologies_known': True, 'services_known': True,
            'bus_closed': True, 'proc_files_closed': True, 'profile_bytes_observed': False, 'reason': 'ok',
            'connman_owner': ':1.8', 'boot_id': '00000000-0000-0000-0000-000000000001',
            'connman_exe': '/HOST/connmand-never-executed', 'connman_exe_sha256': '1' * 64,
            'connman_pid': 123, 'connman_start': 456,
            'technologies': [{'path': '/net/connman/technology/wifi', 'powered': True}], 'services': []}


class FormalReceiveTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operation_type, cls.state_type, cls.runner_type, cls.network = load_methods()

    def fixture(self, used=False):
        state = self.state_type.__new__(self.state_type)
        state.lock = threading.RLock()
        state.native_epoch = 7
        state.closing = state.state_closed_known = state.probes_closed_known = True
        state.receive_available = state.send_available = state.scan_available = False
        state.discoverable = state.scanning = False
        state.radio_restore_pending = state.wifi_restore_pending = False
        state.helper = state.key = state.crypto = state.transport = state.lease = None
        state._network_observer_spec = state._network_observer_spec_original = SPEC
        until, cleanup = 100.0, 160.0  # Deliberately expired: passive closure must not renew/check time.
        state._original_service_until = state._service_until_original = until
        state._original_service_cleanup_until = state._service_cleanup_until_original = cleanup
        worker = threading.Thread(target=lambda: None, name='HOST-terminal-ended-worker')
        worker.start(); worker.join(2.0)
        self.assertFalse(worker.is_alive())
        op = self.operation_type(None, 7, 'receive')
        state.worker = worker
        state.operation = op
        state.session = op.session = SessionClosureScopeModel(state, op, worker, until)
        state._trusted_receive_deployment_factory = op.receive_factory = forbidden
        op.receive_extra_verified = True
        op.receive_network_spec = SPEC
        op.receive_network_clock = time.monotonic
        op.receive_network_until, op.receive_network_task_until = cleanup, until
        op.receive_network_zero_known = not used
        if used:
            bridge = BridgeClosureScopeModel(state, op)
            op.client_bridge = bridge
            op.receive_bridge_ticket = {'started': True, 'returned': bridge}
            observer = self.network.NetworkObserver(*(SPEC + (cleanup, time.monotonic)))
            op.receive_network_observer = op._receive_network_observer_original = observer
            op.receive_network_ctor_called = op.receive_network_ctor_returned = True
            op.receive_network_before_called = op.receive_network_after_called = True
            before = self.network.NetworkObservation(observer, until)
            after = self.network.NetworkObservation(observer, cleanup)
            for row in (before, after):
                # HOST model: no open/spawn was ever called; finished DATA from
                # normalization is not proof of device observation/restoration.
                row._ticket['finished'] = True
                row.valid, row.baseline = True, self.network.normalize(native_data())
            observer._calls.extend((before, after))
            op.receive_network_before, op.receive_network_after = before, after
            op.receive_network_close_called = op.receive_network_close_result = True
            op.receive_network_verified = True
        return state, op

    def runner(self, state):
        runner = self.runner_type.__new__(self.runner_type)
        service = types.SimpleNamespace(State=self.state_type, Operation=self.operation_type,
                                        TransferSession=SessionClosureScopeModel)
        owner = types.SimpleNamespace(state=state, service=service, _state_original=state, gate_known=True)
        def state_gate_model():
            return (owner.gate_known and (state.operation is None and state.session is None or
                    state._receive_terminal_closed(state.operation)))
        owner._state_closed = state_gate_model
        runner.owner = owner
        runner.loader = types.SimpleNamespace(modules={'mta_service': service})
        return runner

    def test_new_passive_terminal_contracts(self):
        cases = []
        def case(name, result, expected):
            self.assertIs(result, expected, name)
            cases.append(name)
        with mock.patch.object(self.network.NetworkObserver, 'observe', forbidden), \
             mock.patch.object(self.network.NetworkObserver, 'close', forbidden):
            state, op = self.fixture()
            originals = (state.operation, state.session, state.worker)
            case('known-zero-ended-originals', state._receive_terminal_closed(op), True)
            self.assertTrue(all(now is original for now, original in zip(
                (state.operation, state.session, state.worker), originals)))
            op.receive_network_zero_known = False
            case('zero-no-issuer-boolean', state._receive_terminal_closed(op), False)

            state, op = self.fixture(used=True)
            originals = (op.receive_network_observer, op.receive_network_before, op.receive_network_after)
            case('closed-receive-after-original-cap', state._receive_terminal_closed(op), True)
            self.assertTrue(all(now is original for now, original in zip(
                (op.receive_network_observer, op.receive_network_before, op.receive_network_after), originals)))
            op.client_bridge.parent_reaped = False
            case('child-restored-data-not-parent-close', state._receive_terminal_closed(op), False)
            op.client_bridge.parent_reaped = True
            altered = native_data(); altered['connman_owner'] = ':1.9'
            op.receive_network_after.baseline = self.network.normalize(altered)
            case('verified-boolean-not-original-compare', state._receive_terminal_closed(op), False)
            op.receive_network_after.baseline = op.receive_network_before.baseline
            op.receive_network_after._ticket['finished'] = False
            case('observation-unclosed', state._receive_terminal_closed(op), False)

            state, op = self.fixture()
            op.session._extra_done = False
            case('session-finalizer-not-ended', state._receive_terminal_closed(op), False)
            op.session._extra_done = True
            op.session._restore = lambda *args: forbidden()
            case('foreign-restore-callback', state._receive_terminal_closed(op), False)
            op.session._restore = state._restore_owner
            state.radio_restore_pending = True
            case('pending-radio-original', state._receive_terminal_closed(op), False)

            state, op = self.fixture(used=True)
            runner = self.runner(state)
            self.assertIs(runner.idle(), False)
            case('runner-retained-closed-receive-not-idle', runner.terminal_inventory_closed(), True)
            runner.owner.gate_known = False
            case('runner-owner-close-unknown', runner.terminal_inventory_closed(), False)
            runner.owner.gate_known = True
            for kind in ('send', 'go'):
                op.kind = kind
                case('runner-reject-' + kind, runner.terminal_inventory_closed(), False)
            op.kind = 'receive'
            runner.loader.modules['mta_service'] = types.SimpleNamespace()
            case('runner-foreign-realm', runner.terminal_inventory_closed(), False)

            state, op = self.fixture()
            state.operation = state.session = state.worker = None
            runner = self.runner(state)
            case('runner-empty-startup-remains-strict-idle', runner.terminal_inventory_closed(), True)
            state.helper = object()
            case('runner-empty-with-unknown-inventory', runner.terminal_inventory_closed(), False)
        self.assertEqual(len(cases), 16)
        print('FORMAL_RECEIVE_TERMINAL_CONTRACTS=' + repr({'cases': len(cases),
            'actual_state_methods': 3, 'actual_runner_methods': 2, 'host_scope_models': True,
            'full_graph': False, 'device': False, 'admission': False, 'rf': False}), flush=True)


if __name__ == '__main__':
    unittest.main()
