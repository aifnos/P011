"""SOURCE-scoped HOST contracts for the actual receive network consumer.

Only the new actual State and Operation class definitions are extracted. The
NetworkObserver/NetworkObservation classes, normalization and comparison are
the real fixed producer. Actual HOST Thread/Event objects exercise worker and
retained-finalizer identity. Session, Bridge/Parent restoration, radio/probes
and native observation DATA are explicit scope models, not device evidence.
The observer's native observe call is replaced by a named DATA/inventory model;
no native binary, Parent, State constructor IO, radio or files are executed.
This does not certify production admission, a full graph or network recovery.
"""
import ast
import copy
import hashlib
import importlib.util
import math
from pathlib import Path
import re
import sys
import threading
import time
import types
import unittest
from collections import namedtuple
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/receive-network-consumer-v1/runtime/mta_service.py'
SOURCE_PIN = (116624, 'b96c91517b337a9e919d16e287683ed793f309ba7d1919816a77971c98025bf2')
NETWORK = BASE / 'runtime/mta_receive_network.py'
NETWORK_PIN = (15860, '1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6')
CODEC = BASE / 'runtime/p011_json.py'
CODEC_PIN = (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
SPEC = ('/HOST/pinned-arm-fixture-never-executed', 52, '0' * 64)
OutcomeModel = namedtuple('OutcomeModel', 'transfer completed restored')


def fixed_bytes(path, pin):
    data = path.read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != pin:
        raise AssertionError('HOST fixed SOURCE changed')
    return data


def module_at(path, pin, name):
    fixed_bytes(path, pin)
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def denied(*args, **kwargs):
    raise AssertionError('Native/FD/Parent operation outside HOST scope')


class SessionScopeModel(object):
    """Original scope fields only; not a real TransferSession restoration."""
    def __init__(self, owner, op, service_until):
        self.cancelled = op.cancelled
        self._lease_owner = op
        self._restore = owner._restore_owner
        self._absolute_until = self._absolute_until_original = service_until
        self._task_deadline = service_until
        self._attempts = []
        self._worker = None

    def status(self):
        return {'worker_alive': self._worker.is_alive(),
                'worker_start_pending': False, 'worker_start_unknown': False,
                'transport_count': 0, 'handoff_count': 0, 'unknown_owner_count': 0}


class BridgeScopeModel(object):
    """Explicit Parent/reap scope model; cached child DATA cannot grant it."""
    def __init__(self, state, op, used=True, parent_reaped=True):
        self.state, self.operation = state, op
        self.handoff = op.client_handoff = object()
        self.started, self.running = used, False
        self.parent = object() if used else None
        self.deployment = object() if used else None
        self.factory_ticket = {'started': used, 'returned': self.deployment, 'authenticated': used}
        self.parent_ticket = {'started': used, 'returned': self.parent}
        self.finish_ticket = {'started': used}
        self.parent_reaped = parent_reaped
        self.cached_child_restored = True  # Deliberately never consumed by State.
        self.restoration_calls = []

    @staticmethod
    def _owners(value):
        if value.operation is not value.state.operation:
            raise AssertionError('HOST Bridge scope identity changed')

    @staticmethod
    def restoration_verified(value):
        value.restoration_calls.append(threading.current_thread())
        value.state.events.append('bridge-reap-model')
        return value.parent_reaped


def load_actual():
    codec = module_at(CODEC, CODEC_PIN, '_host_network_consumer_codec')
    with mock.patch.dict(sys.modules, {'p011_json': codec}):
        network = module_at(NETWORK, NETWORK_PIN, '_host_actual_receive_network')
    tree = ast.parse(fixed_bytes(SOURCE, SOURCE_PIN).decode('utf-8'), filename=str(SOURCE))
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef)
             and node.name in ('Operation', 'State')]
    if len(nodes) != 2 or {node.name for node in nodes} != {'Operation', 'State'}:
        raise AssertionError('Actual SOURCE consumer definitions absent')
    namespace = {'__name__': '_host_actual_receive_consumer', 'threading': threading,
                 'time': time, 'math': math, 're': re, 'types': types,
                 'TransferSession': SessionScopeModel, 'StateClientBridge': BridgeScopeModel,
                 'network_restore': network, 'Outcome': OutcomeModel, 'OpenSslCrypto': denied}
    actual = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(actual)
    exec(compile(actual, str(SOURCE), 'exec'), namespace)
    return namespace['Operation'], namespace['State'], network


def native_data():
    absent = {'present': False, 'value': None}
    service = {'path': '/net/connman/service/wifi_HOST_fixture', 'state': 'online'}
    for key in ('auto_connect', 'favorite', 'immutable', 'ipv4', 'ipv6',
                'ipv4_configuration', 'ipv6_configuration', 'nameservers',
                'nameservers_configuration'):
        service[key] = copy.deepcopy(absent)
    service['ipv4'] = {'present': True, 'value': {'Method': 'dhcp', 'Address': '192.0.2.1'}}
    service['nameservers'] = {'present': True, 'value': ['192.0.2.53', '192.0.2.54']}
    return {'event': 'network_observation', 'network_schema': 'p011-connman-network-baseline-v1',
            'ok': True, 'identity_known': True, 'technologies_known': True,
            'services_known': True, 'bus_closed': True, 'proc_files_closed': True,
            'profile_bytes_observed': False, 'reason': 'ok', 'connman_owner': ':1.8',
            'boot_id': '00000000-0000-0000-0000-000000000001',
            'connman_exe': '/HOST/connmand-not-executed', 'connman_exe_sha256': '1' * 64,
            'connman_pid': 123, 'connman_start': 456,
            'technologies': [{'path': '/net/connman/technology/wifi', 'powered': True}],
            'services': [service]}


class ReceiveNetworkConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operation_type, cls.state_type, cls.network = load_actual()

    def fixture(self, spec=SPEC, service_until=None):
        state = self.state_type.__new__(self.state_type)
        state.lock = threading.RLock()
        state.native_epoch = 1
        state.events = []
        state._network_observer_spec = state._network_observer_spec_original = spec
        until = float(time.monotonic() + 30.0) if service_until is None else service_until
        state._original_service_until = state._service_until_original = until
        cleanup = until + 60.0
        state._original_service_cleanup_until = state._service_cleanup_until_original = cleanup
        op = self.operation_type(None, 1, 'receive')
        state.operation = op
        state.session = op.session = SessionScopeModel(state, op, until)
        state._trusted_receive_deployment_factory = op.receive_factory = lambda *args: denied()
        op.receive_network_spec, op.receive_network_clock, op.receive_network_until = spec, time.monotonic, cleanup
        state.helper = state.key = state.crypto = state.lease = state.transport = None
        state.probe_actors = []  # Explicit model: no actual radio/probe actor created.
        state.radio_restore_pending = False
        op.receive_extra_verified = True  # Explicit model of pre-existing extra-actor close stage.
        state.wifi_restore_pending = True
        state.receive_available = state.send_available = False
        state.receive_reason = 'HOST scope, admission remains closed'
        return state, op

    def run_worker(self, state, op, callback=None):
        errors, returns = [], []
        def job():
            try:
                returns.append(callback() if callback is not None
                               else state._receive_network_begin(op, op.session))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=job, name='HOST-consumer-original-worker')
        op.session._worker = state.worker = worker
        worker.start()
        worker.join(2.0)
        self.assertFalse(worker.is_alive())
        return errors, returns

    def run_finalizer(self, state, op, retained=True):
        errors, returns = [], []
        def job():
            try: returns.append(state._restore_owner(op))
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=job, name='HOST-consumer-original-finalizer')
        row = {'thread': thread, 'claimed': True, 'resolved': True, 'failed': False, 'unknown_start': False}
        if retained: op.session._attempts.append(row)
        thread.start()
        thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(returns), 1)
        return returns[0]

    def attach_bridge(self, state, op, used=True, parent_reaped=True):
        bridge = BridgeScopeModel(state, op, used=used, parent_reaped=parent_reaped)
        op.client_bridge = bridge
        op.receive_bridge_ticket['started'] = True
        op.receive_bridge_ticket['returned'] = bridge
        return bridge

    def observe_model(self, state, rows, unknown_at=None, bad_return_at=None, expired_check=False):
        """Actual call objects with modeled native DATA/finished inventory.

        No file or process was created in these fixtures. finished=False or
        close_error=True explicitly models unknown resources rather than closing
        a real native actor. This is not a production success producer.
        """
        network = self.network
        calls = []
        def observe(observer, phase_until):
            observed = network.NetworkObservation(observer, phase_until)
            observer._calls.append(observed)
            calls.append((observer, phase_until, threading.current_thread(), observed))
            state.events.append('network-read-model')
            index = len(calls) - 1
            if expired_check:
                try: observer._remaining(phase_until)
                except network.NetworkObservationError as error: observed.error = error.code
            if observed.error is None:
                observed.baseline = network.normalize(copy.deepcopy(rows[min(index, len(rows)-1)]))
                observed.valid = True
            observed._ticket['finished'] = True
            if unknown_at == index:
                observed._ticket['close_error'] = True
                # Even a corrupt valid flag must not hide unknown resources.
                observed.valid = True
            if bad_return_at == index:
                return {'restored': True, 'valid': True, 'resources_closed': True}
            return observed
        return observe, calls

    def seed_historical_before(self, state, op):
        """Explicit earlier DATA fixture; not a read at an expired current cap."""
        observer = self.network.NetworkObserver(*SPEC, op.receive_network_until, clock=time.monotonic)
        op.receive_network_observer = op._receive_network_observer_original = observer
        op.receive_network_ctor_called = op.receive_network_ctor_returned = True
        op.receive_network_task_until = op.session._task_deadline
        before = self.network.NetworkObservation(observer, op.receive_network_task_until)
        before.baseline = self.network.normalize(native_data())
        before.valid = True
        before._ticket['finished'] = True
        observer._calls.append(before)
        op.receive_network_before_called, op.receive_network_before = True, before

    def test_actual_consumer_scoped_contracts(self):
        # These tripwires are private module seams, not shared os/subprocess
        # monkeypatches. No native/FS operation is within this HOST method.
        with mock.patch.object(self.network, 'os', types.SimpleNamespace(open=denied)), \
             mock.patch.object(self.network, 'subprocess', types.SimpleNamespace(Popen=denied)):
            with self.subTest('closed-gate-does-not-create-observer'):
                state, op = self.fixture()
                errors, returned = self.run_worker(state, op, lambda: state._run_receive_native(op, op.session))
                self.assertEqual(errors, [])
                self.assertEqual(returned, [OutcomeModel(None, False, False)])
                self.assertFalse(op.receive_network_ctor_called)
                self.assertTrue(self.run_finalizer(state, op))
                self.assertTrue(op.receive_network_zero_known)
                self.assertFalse(state.receive_available)

            with self.subTest('actual-observations-original-caps-and-terminal-order'):
                state, op = self.fixture()
                observe, calls = self.observe_model(state, [native_data()])
                original_close = self.network.NetworkObserver.close
                close_calls = []
                def close(observer):
                    close_calls.append(observer)
                    return original_close(observer)
                with mock.patch.object(self.network.NetworkObserver, 'observe', observe), \
                     mock.patch.object(self.network.NetworkObserver, 'close', close):
                    errors, _ = self.run_worker(state, op)
                    self.assertEqual(errors, [])
                    bridge = self.attach_bridge(state, op)
                    self.assertTrue(self.run_finalizer(state, op))
                    self.assertTrue(self.run_finalizer(state, op))
                self.assertEqual(len(calls), 2)
                self.assertIs(calls[0][1], op.session._task_deadline)
                self.assertIs(calls[1][1], state._service_cleanup_until_original)
                self.assertIsNot(calls[0][3], calls[1][3])
                self.assertEqual(state.events[:3], ['network-read-model', 'bridge-reap-model', 'network-read-model'])
                self.assertEqual(close_calls, [op.receive_network_observer])
                self.assertEqual(len(bridge.restoration_calls), 2)
                self.assertTrue(op.receive_network_verified)
                self.assertFalse(op.receive_network_zero_known)
                self.assertFalse(state.receive_available)

            for changed in ('owner', 'ip', 'dns-order'):
                with self.subTest('strict-terminal-delta-' + changed):
                    first, after = native_data(), native_data()
                    if changed == 'owner': after['connman_owner'] = ':1.9'
                    if changed == 'ip': after['services'][0]['ipv4']['value']['Address'] = '192.0.2.2'
                    if changed == 'dns-order': after['services'][0]['nameservers']['value'].reverse()
                    state, op = self.fixture()
                    observe, calls = self.observe_model(state, [first, after])
                    with mock.patch.object(self.network.NetworkObserver, 'observe', observe):
                        self.assertEqual(self.run_worker(state, op)[0], [])
                        self.attach_bridge(state, op)
                        self.assertFalse(self.run_finalizer(state, op))
                    self.assertEqual(len(calls), 2)
                    self.assertTrue(state.wifi_restore_pending)
                    self.assertFalse(op.receive_network_verified)
                    self.assertTrue(op.receive_network_observer.resources_closed())

            for failed in ('parent-unreaped', 'dictionary', 'unknown-resources', 'foreign-finalizer'):
                with self.subTest('refuse-' + failed):
                    state, op = self.fixture()
                    observe, calls = self.observe_model(state, [native_data()],
                        unknown_at=1 if failed == 'unknown-resources' else None,
                        bad_return_at=1 if failed == 'dictionary' else None)
                    with mock.patch.object(self.network.NetworkObserver, 'observe', observe):
                        self.assertEqual(self.run_worker(state, op)[0], [])
                        self.attach_bridge(state, op, parent_reaped=failed != 'parent-unreaped')
                        self.assertFalse(self.run_finalizer(state, op, retained=failed != 'foreign-finalizer'))
                    self.assertEqual(len(calls), 1 if failed in ('parent-unreaped', 'foreign-finalizer') else 2)
                    self.assertTrue(state.wifi_restore_pending)
                    self.assertFalse(op.receive_network_verified)

            with self.subTest('pure-constructor-failure-keeps-primary-but-closes-known-zero'):
                state, op = self.fixture()
                original_init = self.network.NetworkObserver.__init__
                primary = ValueError('HOST fault after real pure constructor')
                def failing_init(observer, *args, **kwargs):
                    original_init(observer, *args, **kwargs)
                    raise primary
                with mock.patch.object(self.network.NetworkObserver, '__init__', failing_init):
                    errors, _ = self.run_worker(state, op)
                self.assertEqual(errors, [primary])
                self.assertIs(op.receive_network_ctor_error, primary)
                self.assertIs(op.receive_network_error, primary)
                self.assertFalse(op.receive_network_ctor_returned)
                self.assertTrue(self.run_finalizer(state, op))
                self.assertTrue(op.receive_network_zero_known)
                self.assertIs(op.receive_network_error, primary)
                self.assertEqual(op.receive_network_observer._calls, [])

            for kind in ('bare-new', 'unknown-bridge-constructor', 'called-parent-before-run'):
                with self.subTest('unknown-zero-inventory-' + kind):
                    state, op = self.fixture()
                    self.run_worker(state, op, lambda: None)
                    if kind == 'bare-new':
                        op.receive_network_ctor_called = True
                        observer = self.network.NetworkObserver.__new__(self.network.NetworkObserver)
                        op.receive_network_observer = op._receive_network_observer_original = observer
                    elif kind == 'unknown-bridge-constructor':
                        op.receive_bridge_ticket['started'] = True
                    else:
                        bridge = self.attach_bridge(state, op, used=False)
                        bridge.parent_ticket['started'] = True
                    self.assertFalse(self.run_finalizer(state, op))
                    self.assertTrue(state.wifi_restore_pending)
                    self.assertFalse(op.receive_network_zero_known)

            with self.subTest('zero-before-run-closes-original-baseline-without-terminal-read'):
                state, op = self.fixture()
                observe, calls = self.observe_model(state, [native_data()])
                with mock.patch.object(self.network.NetworkObserver, 'observe', observe):
                    self.assertEqual(self.run_worker(state, op)[0], [])
                    self.attach_bridge(state, op, used=False)
                    self.assertTrue(self.run_finalizer(state, op))
                self.assertEqual(len(calls), 1)
                self.assertTrue(op.receive_network_zero_known)
                self.assertFalse(op.receive_network_verified)
                self.assertTrue(op.receive_network_close_result)

            with self.subTest('expired-original-cleanup-cap-not-renewed'):
                state, op = self.fixture(service_until=float(time.monotonic() - 61.0))
                self.run_worker(state, op, lambda: None)
                self.seed_historical_before(state, op)
                self.attach_bridge(state, op)
                observe, calls = self.observe_model(state, [native_data()], expired_check=True)
                with mock.patch.object(self.network.NetworkObserver, 'observe', observe):
                    self.assertFalse(self.run_finalizer(state, op))
                self.assertEqual(len(calls), 0)
                self.assertFalse(op.receive_network_after_called)
                self.assertIsNone(op.receive_network_after)
                self.assertTrue(op.receive_network_observer.resources_closed())
                self.assertTrue(state.wifi_restore_pending)

            with self.subTest('expired-cap-does-not-reuse-historical-valid-terminal-data'):
                state, op = self.fixture(service_until=float(time.monotonic() - 61.0))
                self.run_worker(state, op, lambda: None)
                self.seed_historical_before(state, op)
                observer = op.receive_network_observer
                after = self.network.NetworkObservation(observer, op.receive_network_until)
                after.baseline, after.valid = op.receive_network_before.baseline, True
                after._ticket['finished'] = True
                observer._calls.append(after)
                op.receive_network_after_called, op.receive_network_after = True, after
                self.assertTrue(self.network.compare_observations(op.receive_network_before, after))
                self.attach_bridge(state, op)
                with mock.patch.object(self.network.NetworkObserver, 'observe', denied):
                    self.assertFalse(self.run_finalizer(state, op))
                self.assertFalse(op.receive_network_verified)
                self.assertTrue(op.receive_network_close_result)
                self.assertTrue(state.wifi_restore_pending)

            with self.subTest('zero-closure-not-blocked-by-expired-period'):
                state, op = self.fixture(service_until=float(time.monotonic() - 61.0))
                self.run_worker(state, op, lambda: None)
                self.seed_historical_before(state, op)
                self.assertTrue(self.run_finalizer(state, op))
                self.assertTrue(op.receive_network_zero_known)
                self.assertTrue(op.receive_network_close_result)

        print('RECEIVE_NETWORK_CONSUMER_SCOPE_OK=1')


if __name__ == '__main__':
    unittest.main()
