"""One HOST method executing the complete fixed receive Gate SOURCE.

Only Gate, bundled JSON, radio DATA parser and Barrier definitions are actual
complete fixed sources. Owner, startup/private realm, FD/probe/asset receipts,
clock and Session are explicitly labeled HOST contract models. None is a real
P011 startup, original OS resource, RF grant, restoration or phone result. The
models cannot be supplied through a production Gate API. No LoadedDeployment,
handoff/publication, pending writer, receiver, helper or network is constructed.

Read and hash the four fixed inputs before constructing scoped private canonical
model namespaces. Model IO, Owner._now and active startup methods are tripwires;
global os/socket/Popen are never modified. The one real HOST Thread only checks
Gate's worker identity with a model Session; it never runs a transfer task.
Only this new method is run, not historical probe/barrier/State/Owner tests.
"""
import errno
import hashlib
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
INPUTS = (
    ('mta_receive_trial', 'runtime/mta_receive_trial.py', 57128,
     'f3f62ff3dea8cd61bc350315291380bf48b79db98cac89e2bc429370d1cc992d'),
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_receive_radio_baseline', 'runtime/mta_receive_radio_baseline.py', 3971,
     '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c'),
    ('mta_receive_barrier', 'candidate/formal-receive-v2/runtime/mta_receive_barrier.py', 24113,
     'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397'),
)
PUBLIC_KEYS = frozenset(('reason', 'requested', 'available', 'claimed', 'claim_count',
    'session_attached', 'revoked', 'expired', 'startup_verified', 'probe_verified',
    'radio_known', 'barrier_clear', 'network_spec_verified', 'restoration_verified', 'phone_verified'))


def fixed_sources():
    result = {}
    for name, relative, size, sha in INPUTS:
        raw = (BASE / relative).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, sha):
            raise AssertionError('Fixed Gate HOST input is not sealed: ' + name)
        result[name] = (raw, str(BASE / relative))
    return result


def module_model(name, source, values=None):
    module = types.ModuleType(name)
    module.__file__ = '/HOST-contract-model/' + name + '.py'
    if values: module.__dict__.update(values)
    exec(compile(source, '<HOST-contract-model-' + name + '>', 'exec'), module.__dict__)
    return module


OWNER_MODEL_SOURCE = '''
class _LinuxIo(object):
    def open(self,*unused):raise AssertionError('HOST model cannot open a resource')
class FixedStateServiceOwner(object):
    def _now(self,*unused):raise AssertionError('Gate entered Owner clock/lock')
    def _context(self):raise AssertionError('Gate entered active Owner context')
    def _startup_readonly(self):raise AssertionError('Gate recollected startup')
    def _close_startup(self):raise AssertionError('Gate attempted startup close')
    def close(self):raise AssertionError('Gate attempted Owner close')
'''

FACTORY_MODEL_SOURCE = '''
SOURCE_MANIFEST_SHA='a'*64
class FixedReceiveDeploymentFactory(object):pass
class _StartupReadScope(object):
    def closed(self):
        assert fixture['startup_checks_allowed']
        assert threading.current_thread() is self.worker
        fixture['startup_checks']+=1
        return fixture['startup_closed']
    def close(self):raise AssertionError('Gate attempted active Scope.close')
'''

STARTUP_MODEL_SOURCE = '''
def collect(unused):raise AssertionError('Gate recollected startup')
class StartupCollection(object):
    def resources_closed(self):
        assert fixture['startup_checks_allowed']
        assert threading.current_thread() is self.scope.worker
        fixture['startup_checks']+=1
        return fixture['startup_closed']
    def _definitions_now(self):return fixture['private_definitions']
'''

STATE_MODEL_SOURCE = '''
def capability(*unused):raise AssertionError('Gate started a capability child')
_CAPABILITY_CREATOR=capability
class PrivateHelper(object):pass
class Operation(object):pass
class State(object):
    def __init__(self):pass
    def _run_operation(self,*unused):raise AssertionError('HOST model ran receive')
    def _restore_owner(self,*unused):raise AssertionError('Gate entered active restore')
    def _close_extra(self,*unused):raise AssertionError('Gate entered actor cleanup')
    def _new_operation_locked(self,op):
        task=lambda original_session:self._run_operation(op,original_session)
        return task
'''

SESSION_MODEL_SOURCE = '''
class TransferSession(object):
    def __init__(self,task,restore,lease_owner,extra_actor_close=None,cancelled=None,
                 absolute_until=None,worker=None):
        self._task,self._restore,self._extra=task,restore,extra_actor_close
        self._lease_owner,self.cancelled=lease_owner,cancelled
        self._absolute_until=self._absolute_until_original=absolute_until
        self._worker=worker
        self._direction='receive';self._scoped_owner=self._release=None
        self._started=self._worker_start_claimed=self._worker_start_resolved=False
        self._worker_start_unknown=False;self._task_deadline=None
    def start(self):raise AssertionError('HOST model must not start a production Session')
'''


class ProbeChildModel(object):
    def __init__(self, argv):
        self.args, self.returncode = argv, 0
        self.stdout, self.stderr = types.SimpleNamespace(closed=True), types.SimpleNamespace(closed=True)
    def poll(self): raise AssertionError('Gate polled a probe')
    def wait(self, *unused): raise AssertionError('Gate waited for a probe')
    def communicate(self, *unused): raise AssertionError('Gate read a pipe')


def make_probe(service, codec, actors, path, args, result):
    args, argv = list(args), [path] + list(args)
    args_snapshot, argv_snapshot = tuple(args), tuple(argv)
    process = ProbeChildModel(argv)
    text = codec.dumps(result, sort_keys=True)
    out, err = (text + '\n').encode('utf-8'), b''
    actor = {'creator': service.capability, '_creator_original': service.capability,
        'actors': actors, '_actors_original': actors, 'args_original': args, '_args_original': args,
        'args_snapshot': args_snapshot, '_args_snapshot_original': args_snapshot,
        'argv': argv, '_argv_original': argv, 'argv_snapshot': argv_snapshot, '_argv_snapshot_original': argv_snapshot,
        'popen_creator': ProbeChildModel, '_popen_creator_original': ProbeChildModel,
        'process': process, '_process_original': process, 'stdout': process.stdout, '_stdout_original': process.stdout,
        'stderr': process.stderr, '_stderr_original': process.stderr, 'spawn_called': True, 'spawn_returned': True,
        'spawn_pending': False, 'spawn_unknown': False, 'communicate_called': True, 'communicate_returned': True,
        'closed': True, 'failure': None, 'cleanup_calls': [], 'cleanup_failures': [],
        'out': out, '_out_original': out, 'err': err, '_err_original': err, 'returncode': 0,
        'json_input': text, '_json_input_original': text, 'loads_creator': codec.loads, '_loads_creator_original': codec.loads,
        'snapshot_creator': codec.dumps, '_snapshot_creator_original': codec.dumps,
        'parsed': result, '_parsed_original': result, 'returned': result, '_returned_original': result,
        'parsed_snapshot': text, '_parsed_snapshot_original': text}
    actors.append(actor)
    return actor


def radio_model(kind='ready'):
    value = dict(event='capabilities', radio_schema='p011-bluez-radio-baseline-v1',
        mgmt_info=True, features=True, bluez_advertising_known=True, adapter_properties_known=True,
        connected_devices_known=True, powered=True, bredr_enabled=True, le_enabled=True,
        global_advertising=False, bluez_advertising_active=False, connectable_advert=True,
        discovering=False, discoverable=False, pairable=True, max_adv=31, max_scan=31,
        max_instances=5, active_instances=0, active_instance_ids=[], connected_devices=[],
        current_settings=(1 << 0) | (1 << 7) | (1 << 9), bluez_owner=':1.42')
    if kind == 'unknown': value['connected_devices_known'] = False
    elif kind == 'busy': value['connected_devices'].append('/org/bluez/hci0/dev_00_11_22_33_44_55')
    elif kind == 'off': value['powered'] = False; value['current_settings'] &= ~1
    return value


def proc_reader_model(budget):
    return types.SimpleNamespace(_bound_budget_v24=budget, _resource_budget_v24=budget,
        _active=False, _history_active=False, _pending=False, _history=[], _current_generation=None, _issuer=object())


def fixture_models(actual, requested=True, barrier_reason='clear', radio_kind='ready'):
    fixture = dict(now=10.0, startup_checks=0, startup_checks_allowed=True,
                   startup_closed=True, private_definitions=(object(), object()))
    def model_clock(): return float(fixture['now'])
    clock_module = types.SimpleNamespace(monotonic=model_clock)
    gate = actual['mta_receive_trial']
    gate.time = clock_module  # Module-local HOST clock model, never global time.
    owner_module = module_model('startup_readonly_private_owner', OWNER_MODEL_SOURCE)
    factory_module = module_model('mta_client_receive_factory', FACTORY_MODEL_SOURCE,
                                 dict(fixture=fixture, threading=threading))
    startup_module = module_model('mta_client_startup_readonly', STARTUP_MODEL_SOURCE,
                                 dict(fixture=fixture, threading=threading))
    state_module = module_model('mta_service', STATE_MODEL_SOURCE)
    session_module = module_model('mta_transfer_session', SESSION_MODEL_SOURCE)
    storage_module = module_model('mta_storage', 'class DirectoryBinding(object):pass\n')
    boot_module = module_model('mta_client_receive_boot', 'class BootSourceLoader(object):pass\n')
    bridge_module = module_model('mta_client_state_bridge', 'class StateClientBridge(object):pass\n')
    handoff_module = module_model('mta_client_connect_handoff', 'class ReceiveConnectHandoff(object):pass\n')
    state_module.StateClientBridge = bridge_module.StateClientBridge
    state_module.ReceiveConnectHandoff = handoff_module.ReceiveConnectHandoff
    state_module.json = actual['p011_json']
    state_module.subprocess = types.SimpleNamespace(Popen=ProbeChildModel)
    modules = dict(actual)
    modules.update((m.__name__, m) for m in (owner_module, factory_module, startup_module,
        state_module, session_module, storage_module, boot_module, bridge_module, handoff_module))
    for name in ('mta_receive_network', 'mta_client_executor'):
        modules[name] = module_model(name, '')
    private = {'mta_p2p_client_init': module_model('private_core_model', 'class Snapshot(object):pass\n')}
    snapshot = private['mta_p2p_client_init'].Snapshot()
    owner = owner_module.FixedStateServiceOwner()
    loader = boot_module.BootSourceLoader()
    until = 100.0
    loader._original_until, loader.clock, loader.modules = until, model_clock, modules
    owner.boot, owner.loader, owner.io = boot_module, loader, owner_module._LinuxIo()
    owner.original_io = owner.io
    owner.worker, owner.pid, owner.clock = threading.current_thread(), 123, model_clock
    owner.original_until = owner.until = until
    owner.started = owner.state_complete = owner.startup_called = owner.startup_complete = True
    owner.startup_window_closed = True
    owner.startup_failure = owner.server = owner.thread = None
    owner.server_called = owner.stop_called = owner.close_called = owner.start_complete = False
    owner._startup_namespace_original, owner._startup_owner_type_original = owner_module.__dict__, type(owner)
    owner.receive_trial_requested = owner._receive_trial_requested_original = requested
    state = state_module.State()
    state._service_until_original = state._original_service_until = until
    state._service_cleanup_until_original = until + 60.0
    state._original_service_cleanup_until = state._service_cleanup_until_original
    state.state, state.native_epoch = 'idle', 0
    state.operation = state.session = state.worker = state.helper = None
    state.closing = state.wifi_restore_pending = state.radio_restore_pending = False
    state.cancelled = threading.Event()
    state._receive_trial = state._receive_trial_original = None
    owner.state = owner._state_original = state
    owner.service = state_module
    factory = factory_module.FixedReceiveDeploymentFactory()
    owner.factory = owner._startup_factory_original = state._trusted_receive_deployment_factory = factory
    received = storage_module.DirectoryBinding()
    received.absolute_until, received.clock = until, model_clock
    owner.received_directory = owner._received_directory_original = received
    state._received_binding_original = state._original_received_binding = received
    scope = factory_module._StartupReadScope()
    owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope
    scope.owner, scope.state, scope.factory, scope.loader = owner, state, factory, loader
    scope.worker, scope.pid, scope.clock = owner.worker, owner.pid, model_clock
    scope.original_until, scope.received_directory = until, received
    scope.close_called = scope.close_complete = scope.success = scope.read_ended = scope.collector_called = True
    scope.failure = None
    scope.source_manifest_sha = scope._source_manifest_sha_original = factory_module.SOURCE_MANIFEST_SHA
    scope.private_modules = scope._private_modules_original = private
    scope.module_originals = tuple((name, value, value.__dict__) for name, value in private.items())
    files = types.SimpleNamespace(attempt=scope, rows=[dict(closed=True, unknown=False, fd=41)],
                                  raw=[b'HOST-model-source'], pending=False, close_attempted=True)
    scope.files = scope._files_original = files
    collection = startup_module.StartupCollection()
    collection.scope = collection._scope_original = scope
    collection.modules = collection._modules_original = private
    collection.profile = collection._profile_original = {}
    collection.clock = collection._clock_original = model_clock
    collection.until = collection._until_original = until
    collection._definitions = fixture['private_definitions']
    collection.attempted = collection.ended = collection.success = collection.close_attempted = True
    collection.io_started = collection._io_started_original = True
    collection.failure = collection.close_failure = None
    budget = types.SimpleNamespace(_store=None, _provider=None, _readers=[],
        _rows=[dict(active=False, settled=True, unknown=False, sticky=False, late=False)])
    readers = [proc_reader_model(budget) for unused in range(4)]
    budget._readers.extend(readers)
    store = types.SimpleNamespace(_resource_budget_v23=budget, _attempted=False, _opened=False,
        _unknown=False, _marker=None, _current_locks=None, _proc_reader=readers[0])
    budget._store = store
    collection.store = collection._store_original = store
    collection.budget = collection._budget_original = budget
    collector = types.SimpleNamespace(_tickets=[dict(fd=57, closed=True, unknown=False, attempted=True)],
        _ended=True, _pending=False, _snapshot=snapshot, _rounds=[private['mta_p2p_client_init'].Snapshot(), snapshot])
    collection.collector = collection._collector_original = collector
    collection.snapshot = snapshot
    collection.reader_rows = [dict(value=value, bound=True) for value in readers[1:]]
    collection.status_rows = []
    for index in range(2):
        status_files = types.SimpleNamespace(_pending=False, _tickets=[dict(fd=None, closed=True, unknown=False)])
        status_files._tickets_original = status_files._tickets
        status_files._io = status_files._io_original = object()
        source = types.SimpleNamespace(_pending=False, _consumer=None, _reader=readers[index + 2],
            _files=[status_files], _actor_calls=[], _issued=[])
        status_reader = types.SimpleNamespace(_source=source, _ended=True, _pending=False,
            _socket_unknown=False, _source_unknown=False, _receive_unknown=False,
            _socket=None, _socket_closed=True, _rights=[], _sources=[])
        source._consumer = status_reader
        result = object()
        status_reader._sources.append(result)
        source._issued.append((status_reader, result, object(), status_files))
        collection.status_rows.append(dict(reader=status_reader, source=source, value=result, failure=None))
    scope.collector_ticket = dict(creator=startup_module.StartupCollection, returned=collection,
                                  started=True, ended=True, failure=None)
    owner.startup_result = collection
    owner._startup_module_original = startup_module
    owner._startup_collect_original = startup_module.collect
    owner._startup_collection_type_original = startup_module.StartupCollection
    owner._startup_window_scope_original, owner._startup_window_collection_original = scope, collection
    owner.probe_rows = state.probe_actors = state._probe_actors_original = []
    state._probe_creator_original = state_module.capability
    state.bluez_path = state._bluez_path_original = '/HOST-model/native/bluez'
    state.network_path = state._network_path_original = '/HOST-model/native/network'
    state.bluetooth_caps = state._bluetooth_caps_original = radio_model(radio_kind)
    state.network_caps = state._network_caps_original = dict(event='capabilities', ok=True, connman=True)
    state.bluetooth_probe_actor = state._bluetooth_probe_actor_original = make_probe(state_module,
        actual['p011_json'], state.probe_actors, state.bluez_path, ('--capabilities', 'hci0'), state.bluetooth_caps)
    state.network_probe_actor = state._network_probe_actor_original = make_probe(state_module,
        actual['p011_json'], state.probe_actors, state.network_path, ('--capabilities',), state.network_caps)
    state.radio_restore_probes = []
    assets, pins = [], []
    paths = (state.bluez_path, state.network_path, '/HOST-model/connman-observer')
    for index, path in enumerate(paths):
        raw = b'HOST-model-ELF-' + bytes((index,))
        pin = len(raw), hashlib.sha256(raw).hexdigest()
        pins.append(pin)
        assets.append(dict(path=path, fd=71 + index, raw=raw, attempted=True, closed=True, unknown=False, failure=None))
    owner.assets = assets
    owner_module.BLUEZ, owner_module.NETWORK, owner_module.CONNMAN = paths
    owner_module.HELPER_PINS, owner_module.CONNMAN_PIN = tuple(pins[:2]), pins[2]
    spec = (paths[2],) + pins[2]
    owner.network_observer_spec = owner._network_observer_spec_original = spec
    owner._network_observer_asset_original = assets[2]
    state._network_observer_spec = state._network_observer_spec_original = spec
    barrier_module = actual['mta_receive_barrier']
    barrier = barrier_module.Barrier.__new__(barrier_module.Barrier)
    barrier.owner = barrier._owner_original = owner
    barrier._io = barrier._io_original = barrier_module._LinuxIo()
    barrier._host_model_original = False  # Contract shape only; no real Linux call/receipt.
    barrier._creator_original = barrier_module.Barrier
    barrier.worker, barrier.pid, barrier.clock, barrier.until = owner.worker, owner.pid, model_clock, until
    barrier.namespace, barrier.owner_type = owner_module.__dict__, type(owner)
    barrier.attempted = barrier.ended = barrier.close_called = barrier.resources_closed = True
    barrier.check = barrier._check_original = owner._now
    barrier.check_function = type(owner)._now
    barrier.reason = barrier_reason
    barrier.failure = None if barrier_reason == 'clear' else barrier_module.BarrierError(barrier_reason)
    barrier.failures = barrier._failures_original = [] if barrier.failure is None else [barrier.failure]
    barrier.close_failures = barrier._close_failures_original = []
    barrier.alias_rows = barrier._alias_rows_original = []
    barrier.rows = barrier._rows_original = []
    for index in range(5 if barrier_reason == 'clear' else 4):
        fd = 90 + index
        barrier.rows.append(dict(owner=barrier, fd=fd, fd_original=fd, open_returned=True,
            closed=True, unknown=False, close_attempted=True, close_return=None,
            close_error=None, ebadf_error=OSError(errno.EBADF, 'HOST-model-EBADF')))
    barrier.observations = barrier._observations_original = [
        dict(kind='stat_pending', accepted_absence=True) for unused in range(4 if barrier_reason == 'clear' else 0)]
    barrier.rounds = barrier._rounds_original = [dict(names=[], count=0), dict(names=[], count=0)] if barrier_reason == 'clear' else []
    owner.receive_barrier = owner._receive_barrier_original = barrier
    owner._receive_barrier_module_original, owner._receive_barrier_type_original = barrier_module, barrier_module.Barrier
    owner._receive_barrier_ticket = owner._receive_barrier_ticket_original = dict(creator=barrier_module.Barrier,
        partial=barrier, constructor_called=True, constructed=True, returned=barrier, ended=True, failure=None, unknown=False)
    fixture.update(owner=owner, state=state, scope=scope, collection=collection, barrier=barrier,
        modules=modules, gate=gate, session_module=session_module, state_module=state_module, clock=model_clock)
    return fixture


def prepare_gate(fixture, requested=None):
    owner, gate, state = fixture['owner'], fixture['gate'], fixture['state']
    value = gate.FixedReceiveTrial.__new__(gate.FixedReceiveTrial)
    owner.receive_trial = owner._receive_trial_original = value
    owner._receive_trial_module_original, owner._receive_trial_type_original = gate, gate.FixedReceiveTrial
    ticket = dict(creator=gate.FixedReceiveTrial, partial=value, constructor_called=True,
        constructed=False, returned=None, ended=False, failure=None, unknown=True,
        bind_called=False, bind_returned=None)
    owner._receive_trial_ticket = owner._receive_trial_ticket_original = ticket
    requested = owner.receive_trial_requested if requested is None else requested
    gate.FixedReceiveTrial.__init__(value, owner, fixture['barrier'], requested)
    ticket.update(constructed=True, returned=value, ended=True, unknown=False, bind_called=True)
    if value.binds(state) is not True: raise AssertionError('Original model Gate must permit initial bind')
    state._receive_trial = state._receive_trial_original = value
    ticket['bind_returned'] = value
    owner.start_complete = True
    fixture['startup_checks_allowed'] = False
    fixture['trial'] = value
    return value


def claim_model(fixture):
    state, gate = fixture['state'], fixture['trial']
    op = fixture['state_module'].Operation()
    op.kind, op.backend, op.epoch, op.consent = 'receive', None, state.native_epoch + 1, True
    op.cancelled = threading.Event()
    op.receive_factory = fixture['owner'].factory
    op.receive_network_spec, op.receive_network_clock = state._network_observer_spec, fixture['clock']
    op.receive_network_until = state._service_cleanup_until_original
    op.receive_trial = op._receive_trial_original = gate
    op.session = op.helper = op.client_bridge = op.client_handoff = None
    op.receive_bridge_ticket = dict(started=False, returned=None)
    op.actor_unknown = False
    state.native_epoch, state.operation, state.cancelled = op.epoch, op, op.cancelled
    returned = gate.claim(state, op)
    if returned is not op: raise AssertionError('Model claim must return original Operation')
    fixture['op'] = op
    return op


def attach_model(fixture):
    state, trial, op, module = (fixture[name] for name in ('state', 'trial', 'op', 'session_module'))
    cls = module.TransferSession
    session = cls.__new__(cls)
    ticket = dict(creator=cls, initializer=cls.__init__, namespace=module.__dict__, new_called=True,
        new_returned=True, value_original=session, init_called=True, init_returned=False, init_error=None,
        attach_called=False, attach_returned=False, attach_error=None)
    op.receive_session_ticket = op._receive_session_ticket_original = ticket
    state.session = op.session = session
    worker_result = []
    worker = threading.Thread(target=lambda: worker_result.append(trial.allows(state, op, session)),
                              name='HOST-model-Gate-worker')
    task = state._new_operation_locked(op)
    cls.__init__(session, task, state._restore_owner, op, extra_actor_close=state._close_extra,
        cancelled=op.cancelled, absolute_until=fixture['owner'].until, worker=worker)
    state.worker = worker
    ticket.update(init_returned=True, attach_called=True)
    if trial.attach_session(state, op, session) is not session:
        raise AssertionError('Model attachment must retain original Session')
    ticket['attach_returned'] = True
    fixture.update(session=session, worker=worker, worker_result=worker_result)
    return session


class ReceiveTrialGateTests(unittest.TestCase):
    def test_fixed_gate_contracts(self):
        sources = fixed_sources()
        actual = {}
        for name, (raw, path) in sources.items():
            module = types.ModuleType(name)
            module.__file__ = path
            exec(compile(raw.decode('utf-8'), path, 'exec'), module.__dict__)
            actual[name] = module
        cases = 0

        def fixture(requested=True, barrier='clear', radio='ready'):
            return fixture_models(actual, requested, barrier, radio)

        def in_scope(value):
            return mock.patch.dict(sys.modules, value['modules'])

        with self.subTest(domain='actual_full_module_initial_bind_ready'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f)
                self.assertTrue(trial.available(f['state']))
                self.assertEqual(f['startup_checks'], 2)
                facts = trial.public_facts()
                self.assertEqual(set(facts), PUBLIC_KEYS)
                self.assertEqual(facts['reason'], 'ready')
                self.assertFalse(facts['restoration_verified'])
                self.assertFalse(facts['phone_verified'])
                self.assertTrue(trial.binds(f['state']))
            cases += 1
        for domain, requested, barrier, radio, reason in (
                ('not_requested', False, 'clear', 'ready', 'not_requested'),
                ('old_pending_preserved', True, 'pending_exists', 'ready', 'pending_exists'),
                ('client_history_preserved', True, 'client_history', 'ready', 'client_history'),
                ('radio_unknown_not_empty', True, 'clear', 'unknown', 'radio_unknown'),
                ('connected_peer_busy', True, 'clear', 'busy', 'radio_busy'),
                ('powered_off_no_enable', True, 'clear', 'off', 'radio_unavailable')):
            with self.subTest(domain=domain):
                f = fixture(requested, barrier, radio)
                with in_scope(f):
                    trial = prepare_gate(f)
                    self.assertFalse(trial.available(f['state']))
                    self.assertEqual(trial.public_facts()['reason'], reason)
                    self.assertEqual(trial.claim_count, 0)
                cases += 1
        with self.subTest(domain='in_place_busy_cap_edit_cannot_admit'):
            f = fixture(radio='busy')
            with in_scope(f):
                trial = prepare_gate(f)
                f['state'].bluetooth_caps['connected_devices'].clear()
                self.assertFalse(trial.binds(f['state']))
                self.assertFalse(trial.available(f['state']))
            cases += 1
        for domain, mutate in (
                ('equal_cap_dict_copy_rejected', lambda f: setattr(f['state'], 'bluetooth_caps', dict(f['state'].bluetooth_caps))),
                ('equal_service_cap_object_rejected', lambda f: setattr(f['owner'], 'until', float(str(f['owner'].until)))),
                ('original_closed_ticket_changed', lambda f: f['scope'].files.rows[0].update(closed=False)),
                ('original_creator_changed', lambda f: f['gate'].__dict__.update(FixedReceiveTrial=object))):
            with self.subTest(domain=domain):
                f = fixture()
                with in_scope(f):
                    trial = prepare_gate(f)
                    mutate(f)
                    self.assertFalse(trial.binds(f['state']))
                    self.assertFalse(trial.available(f['state']))
                # Each fixture uses fresh actual Gate below after a class binding fault.
                if domain == 'original_creator_changed':
                    raw, path = sources['mta_receive_trial']
                    restored = types.ModuleType('mta_receive_trial'); restored.__file__ = path
                    exec(compile(raw.decode('utf-8'), path, 'exec'), restored.__dict__)
                    actual['mta_receive_trial'] = restored
                cases += 1
        with self.subTest(domain='host_barrier_model_flag_refused'):
            f = fixture()
            f['barrier']._host_model_original = True
            with in_scope(f):
                with self.assertRaises(f['gate'].ReceiveTrialError) as failure:
                    prepare_gate(f)
                self.assertEqual(failure.exception.code, 'barrier_unknown')
                self.assertIs(f['owner']._receive_trial_ticket['partial'], f['owner'].receive_trial)
            cases += 1
        with self.subTest(domain='policy_argument_not_owner_requested'):
            f = fixture(requested=True)
            with in_scope(f):
                with self.assertRaises(f['gate'].ReceiveTrialError): prepare_gate(f, requested=False)
            cases += 1
        with self.subTest(domain='construction_must_use_original_owner_worker'):
            f = fixture()
            failures = []
            def wrong_worker():
                try: prepare_gate(f)
                except BaseException as error: failures.append(error)
            with in_scope(f):
                worker = threading.Thread(target=wrong_worker, name='HOST-model-wrong-startup-worker')
                worker.start(); worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(failures), 1)
                self.assertIs(type(failures[0]), f['gate'].ReceiveTrialError)
                self.assertEqual(failures[0].code, 'owner_context')
                self.assertIs(f['owner'].receive_trial.failure, failures[0])
            cases += 1
        with self.subTest(domain='claim_once_and_constructor_partial_retained'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f); op = claim_model(f)
                self.assertFalse(trial.available(f['state']))
                with self.assertRaises(f['gate'].ReceiveTrialError): trial.claim(f['state'], op)
                self.assertIs(trial.claimed_operation, op)
                self.assertTrue(trial.revoke(f['state'], 'cancelled'))
                self.assertTrue(trial.closed(f['state']))
                self.assertEqual(trial.claim_count, 1)
                self.assertFalse(trial.public_facts()['restoration_verified'])
            cases += 1
        with self.subTest(domain='actual_host_worker_identity_for_model_session'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f); op = claim_model(f); session = attach_model(f)
                session._started = session._worker_start_claimed = session._worker_start_resolved = True
                session._task_deadline = 90.0
                self.assertFalse(trial.allows(f['state'], op, session))
                f['worker'].start(); f['worker'].join(5)
                self.assertFalse(f['worker'].is_alive())
                self.assertEqual(f['worker_result'], [True])
                with self.assertRaises(f['gate'].ReceiveTrialError): trial.attach_session(f['state'], op, session)
                self.assertTrue(trial.revoke(f['state'], 'owner_stopped'))
                self.assertTrue(trial.revoke(f['state'], 'owner_closed'))
                self.assertTrue(trial.closed(f['state']))
                self.assertIs(trial.session, session)
                self.assertEqual(f['startup_checks'], 2)
            cases += 1
        with self.subTest(domain='only_original_operation_owns_radio_pending'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f); op = claim_model(f); session = attach_model(f)
                helper = f['state_module'].PrivateHelper()
                helper.path, helper.spawn_resolved, helper.spawn_unknown = f['state'].bluez_path, True, False
                f['state'].helper = op.helper = helper
                bridge = f['modules']['mta_client_state_bridge'].StateClientBridge()
                handoff = f['modules']['mta_client_connect_handoff'].ReceiveConnectHandoff()
                handoff.state, handoff.operation, handoff.session, handoff.worker, handoff.helper = (
                    f['state'], op, session, session._worker, helper)
                bridge.state, bridge.operation, bridge.session, bridge.worker = f['state'], op, session, session._worker
                bridge.epoch, bridge.cancelled, bridge._factory, bridge.handoff = op.epoch, op.cancelled, f['owner'].factory, handoff
                op.client_bridge, op.client_handoff = bridge, handoff
                op.receive_bridge_ticket.update(started=True, returned=bridge)
                f['state'].radio_restore_pending = True
                self.assertTrue(trial._own_radio_pending(f['state'], op, session))
                bridge.operation = object()
                self.assertFalse(trial._own_radio_pending(f['state'], op, session))
            cases += 1
        with self.subTest(domain='restore_probe_append_preserves_prefix_not_rf_proof'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f)
                actor = dict(creator=f['state_module'].capability, _creator_original=f['state_module'].capability,
                    actors=f['state'].probe_actors, _actors_original=f['state'].probe_actors)
                f['state'].radio_restore_probes.append(dict(creator=f['state_module'].capability,
                    actors=f['state'].probe_actors, before_actor=f['state'].bluetooth_probe_actor,
                    before=f['state'].bluetooth_caps, current_actor=actor))
                f['state'].probe_actors.append(actor)
                self.assertTrue(trial.binds(f['state']))
                self.assertTrue(trial.revoke(f['state'], 'owner_closed'))
                self.assertTrue(trial.closed(f['state']))
                f['state'].probe_actors.append(dict(actor))
                self.assertFalse(trial.closed(f['state']))
            cases += 1
        with self.subTest(domain='expiry_revokes_without_preventing_original_closure'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f); op = claim_model(f); session = attach_model(f)
                f['now'] = 100.0
                self.assertFalse(trial.available(f['state']))
                self.assertTrue(trial.expired)
                self.assertTrue(trial.revoke(f['state'], 'owner_closed'))
                self.assertTrue(trial.closed(f['state']))
                self.assertIs(trial.claimed_operation, op)
                self.assertIs(trial.session, session)
                self.assertEqual(f['startup_checks'], 2)
            cases += 1
        with self.subTest(domain='session_cap_equal_replacement_refused'):
            f = fixture()
            with in_scope(f):
                trial = prepare_gate(f); op = claim_model(f); session = attach_model(f)
                session._absolute_until = float(str(session._absolute_until))
                self.assertTrue(trial.revoke(f['state'], 'cancelled'))
                self.assertFalse(trial.closed(f['state']))
                self.assertIs(trial.session, session)
            cases += 1
        print('TRIAL_GATE_CONTRACTS=' + str(cases))


if __name__ == '__main__':
    unittest.main()
