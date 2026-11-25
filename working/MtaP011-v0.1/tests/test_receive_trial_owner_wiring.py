"""One focused HOST method for the actual V2 Owner lifecycle wiring.

Only the named Owner methods and its pure error definitions are extracted from
fixed SOURCE. Window/collection, canonical Barrier/Gate/State definitions, IO,
HTTP shutdown and the original resource closure are explicit HOST control
models. Model receipts below are not actual baseline, FD, radio, admission,
Session finalization or device evidence. No production constructor, listener,
process, helper, network or filesystem operation is invoked by the test body.
Source input is read before the scoped runtime IO tripwires are armed. Private
canonical model modules are scoped and restored; no installed namespace is
replaced. Only this one new method is run; no historical tests are replayed.
"""
import ast
import errno
import hashlib
from pathlib import Path
import socket
import subprocess
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/formal-receive-v2/runtime/mta_client_service_owner.py'
SOURCE_PIN = (72084, '87261afc8b7c7eb795e925388e81dbf587916373e1442e80dbac78e1cb9ece7e')
METHODS = ('__init__', '_close_startup', '_startup_closed', '_seal_startup_window',
           '_receive_definitions', '_receive_sources_held', '_prepare_receive_trial',
           '_receive_barrier_closed', '_revoke_receive_trial', '_receive_trial_closed',
           '_startup_window_passive_closed', '_receive_status', '_stop_server',
           'close', 'status')


class OwnerClosureControlModel(object):
    """Never authenticates an OS resource; logs only control-flow calls."""
    def _now(self, cleanup=False):
        self.fixture['events'].append(('clock', cleanup))
        return 10.0

    def _close_directories(self):
        self.fixture['events'].append(('directories_close_model',))
        self.directory_close_complete = self._receive_trial_closed()
        return self.directory_close_complete

    def _closed(self):
        self.fixture['events'].append(('owner_closed_model',))
        return (self.state_close_return is True and self.directory_close_complete is True
                and self._receive_trial_closed() and self._startup_window_passive_closed())

    def _close_socket(self, row):
        raise AssertionError('HOST scope must never close a real socket')


class CollectionWindowModel(object):
    def __init__(self, scope, fixture):
        self.scope, self.fixture = scope, fixture
        self.success = self.ended = self.close_attempted = True
        self.failure = None

    def resources_closed(self):
        if self.fixture['scope_methods_forbidden']:
            raise AssertionError('off-worker status entered a collection method')
        self.fixture['events'].append(('collection_closed_model',))
        return True


class StartupWindowModel(object):
    def __init__(self, fixture):
        self.fixture = fixture
        self.close_called = self.close_complete = False
        self.read_ended = True
        self.collector_ticket = None

    def closed(self):
        if self.fixture['scope_methods_forbidden']:
            raise AssertionError('off-worker status entered a Scope method')
        self.fixture['events'].append(('scope_closed_model',))
        return True

    def close(self):
        if self.fixture['scope_methods_forbidden']:
            raise AssertionError('off-worker status entered Scope.close')
        if not self.close_called:
            self.fixture['events'].append(('scope_close_model',))
        self.close_called = self.close_complete = True
        return True


BARRIER_MODEL_SOURCE = '''
REASONS=frozenset(('clear','pending_exists','not_started'))
class Barrier(object):
    def __init__(self,owner):
        fixture['events'].append(('barrier_ctor_model',))
        assert owner.startup_scope.close_called is True
        assert owner.startup_scope.close_complete is True
        assert owner.startup_window_closed is True
        assert owner.receive_barrier is self is owner._receive_barrier_original
        assert owner._receive_barrier_ticket['partial'] is self
        self.owner=self._owner_original=owner
        self._host_model_original=False  # HOST contract shape, not a Linux FD proof.
        self.rows=self._rows_original=[]
        self.close_failures=self._close_failures_original=[]
        self.failure=None;self.ended=self.close_called=self.resources_closed=False
        self.reason='not_started'
        if fixture['mode']=='barrier_ctor_fail':raise fixture['fault']
    def run(self):
        fixture['events'].append(('barrier_run_model',))
        self.ended=self.close_called=self.resources_closed=True
        self.reason='pending_exists' if fixture['mode']=='pending' else 'clear'
        if self.reason=='pending_exists':self.failure=fixture['barrier_refusal']
        return self
    def public_facts(self):
        return {'reason':self.reason,'resources_closed':self.resources_closed}
'''


GATE_MODEL_SOURCE = '''
REASONS=frozenset(('ready','not_requested','pending_exists','owner_stopped','owner_closed'))
class FixedReceiveTrial(object):
    def __init__(self,owner,barrier,requested):
        fixture['events'].append(('gate_ctor_model',))
        assert owner.startup_scope.close_called is True
        assert owner.startup_window_closed is True
        assert owner.receive_trial is self is owner._receive_trial_original
        ticket=owner._receive_trial_ticket
        assert ticket['partial'] is self and ticket['constructor_called'] is True
        assert ticket['constructed'] is False and ticket['ended'] is False
        assert ticket['returned'] is None and ticket['unknown'] is True
        self.owner,self.barrier,self.requested=owner,barrier,requested
        self.state=owner.state;self.revoked=False;self.initialized=False
        self.claimed=self.session=None
        if fixture['mode']=='gate_ctor_fail':raise fixture['fault']
        if owner._receive_barrier_ticket['constructed'] is not True:
            raise fixture['partial_barrier_fault']
        self.reason=('not_requested' if not requested else
                     'pending_exists' if barrier.reason=='pending_exists' else 'ready')
        self.initialized=True
    def binds(self,state):
        return self.initialized and state is self.state
    def available(self,state):
        return self.binds(state) and self.reason=='ready' and not self.revoked and self.claimed is None
    def revoke(self,state,reason):
        assert state is self.state
        fixture['events'].append(('gate_revoke_model',reason))
        self.revoked=True
        if self.initialized:self.reason=reason
        return True
    def closed(self,state):
        return self.initialized and state is self.state and self.revoked
    def public_facts(self):
        return {'reason':self.reason,'requested':self.requested,
                'available':self.available(self.state),'claimed':self.claimed is not None,
                'claim_count':int(self.claimed is not None),'revoked':self.revoked}
'''


STATE_MODEL_SOURCE = '''
class State(object):
    def _bind_receive_trial(self,gate):
        fixture['events'].append(('state_bind_model',))
        ticket=fixture['owner']._receive_trial_ticket
        assert ticket['constructed'] is True and ticket['ended'] is True
        assert ticket['returned'] is gate and ticket['unknown'] is False
        self._receive_trial=self._receive_trial_original=gate
        self._receive_trial_module_original=gate_module
        return gate
    def _receive_trial_available(self):
        fixture['events'].append(('state_available_model',))
        gate=self._receive_trial_original
        return gate is not None and gate.available(self)
    def close(self,timeout=30):
        fixture['events'].append(('state_close_model',timeout))
        self.closing=True
        return True
'''


HTTP_MODEL_SOURCE = '''
class HTTPServer(object):
    def shutdown(server):
        fixture['events'].append(('http_shutdown_model',))
'''


def fixed_scope():
    raw = SOURCE.read_bytes()
    if SOURCE_PIN is None or (len(raw), hashlib.sha256(raw).hexdigest()) != SOURCE_PIN:
        raise AssertionError('Focused Owner SOURCE is not sealed')
    tree = ast.parse(raw.decode('utf-8'), str(SOURCE))
    original = next(row for row in tree.body if isinstance(row, ast.ClassDef)
                    and row.name == 'FixedStateServiceOwner')
    methods = [row for row in original.body if isinstance(row, ast.FunctionDef) and row.name in METHODS]
    if tuple(row.name for row in methods) != METHODS:
        raise AssertionError('Focused actual Owner method inventory changed')
    start = next(row for row in original.body if isinstance(row, ast.FunctionDef) and row.name == 'start')
    starts = [row for row in ast.walk(start) if isinstance(row, ast.Call)
              and isinstance(row.func, ast.Attribute) and isinstance(row.func.value, ast.Name)
              and row.func.value.id == 'self' and row.func.attr in ('_startup_readonly','_prepare_receive_trial')]
    if len(starts) != 2 or [row.func.attr for row in starts] != ['_startup_readonly','_prepare_receive_trial']:
        raise AssertionError('Actual startup-to-trial call edge changed')
    server_line = next(row.lineno for row in ast.walk(start) if isinstance(row, ast.Assign)
                       and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                               and target.value.id == 'self' and target.attr == 'server_called'
                               for target in row.targets))
    if not starts[0].lineno < starts[1].lineno < server_line:
        raise AssertionError('Actual trial must precede the first listener constructor')
    pure = [row for row in tree.body if
            isinstance(row, ast.ClassDef) and row.name == 'ServiceOwnerError' or
            isinstance(row, ast.FunctionDef) and row.name == '_fail']
    model_class = ast.ClassDef(name='FixedStateServiceOwner',
                              bases=[ast.Name(id='OwnerClosureControlModel', ctx=ast.Load())],
                              keywords=[], body=methods, decorator_list=[])
    focused = ast.fix_missing_locations(ast.Module(body=pure + [model_class], type_ignores=[]))
    return compile(focused, str(SOURCE), 'exec')


def make_scope(code, mode='ok', requested=False):
    fixture = dict(mode=mode, events=[], scope_methods_forbidden=False,
                   fault=RuntimeError('HOST original constructor fault'),
                   partial_barrier_fault=RuntimeError('HOST unknown original Barrier'),
                   barrier_refusal=ValueError('HOST pending metadata refusal'))
    barrier_module = types.ModuleType('mta_receive_barrier')
    barrier_module.fixture = fixture
    gate_module = types.ModuleType('mta_receive_trial')
    gate_module.fixture = fixture
    service = types.ModuleType('mta_service')
    service.fixture, service.gate_module = fixture, gate_module
    http = types.ModuleType('HOST_receive_trial_http_model')
    http.fixture = fixture
    for module, source in ((barrier_module,BARRIER_MODEL_SOURCE),(gate_module,GATE_MODEL_SOURCE),
                           (service,STATE_MODEL_SOURCE),(http,HTTP_MODEL_SOURCE)):
        exec(source, module.__dict__)
    root = '/tmp/p011-mta-formal-receive-v2'
    for module in (barrier_module,gate_module,service):
        module.__file__ = root + '/runtime/' + module.__name__ + '.py'
    realm = dict(__name__='HOST_receive_trial_owner_model', ROOT=root, CLEANUP_SECONDS=60.0,
                 OwnerClosureControlModel=OwnerClosureControlModel, threading=threading,
                 types=types, errno=errno, sys=sys, socket=socket)
    exec(code, realm)
    owner = realm['FixedStateServiceOwner'].__new__(realm['FixedStateServiceOwner'])
    fixture['owner'] = owner;owner.fixture = fixture
    owner.worker = threading.current_thread();owner.lock = threading.RLock()
    owner.clock = lambda: 10.0
    owner.until = owner.original_until = 100.0
    owner.cleanup_until = None
    owner.loader = types.SimpleNamespace(modules={module.__name__:module for module in
                                                 (barrier_module,gate_module,service)})
    owner.service, owner.http = service, http
    owner.state = owner._state_original = service.State.__new__(service.State)
    owner.state._receive_trial = owner.state._receive_trial_original = None
    owner.state._receive_trial_module_original = None
    owner.state.closing = False
    owner.state.operation = object();owner.state.session = object()
    owner.state_complete = owner.startup_called = owner.startup_complete = True
    owner.startup_failure = None
    owner.startup_scope = owner._startup_scope_original = StartupWindowModel(fixture)
    owner.startup_result = CollectionWindowModel(owner.startup_scope, fixture)
    owner._startup_collection_type_original = CollectionWindowModel
    owner.startup_scope.collector_ticket = dict(creator=CollectionWindowModel,
                                               returned=owner.startup_result,ended=True,failure=None)
    owner.startup_window_closed = False
    owner._startup_window_scope_original = owner._startup_window_collection_original = None
    owner.receive_trial_requested = owner._receive_trial_requested_original = requested
    for kind in ('barrier','trial'):
        setattr(owner,'receive_'+kind,None);setattr(owner,'_receive_'+kind+'_original',None)
        for suffix in ('module_original','type_original','definitions_original','ticket','ticket_original'):
            setattr(owner,'_receive_'+kind+'_'+suffix,None)
        setattr(owner,'receive_'+kind+'_called',False);setattr(owner,'receive_'+kind+'_failure',None)
    owner.receive_trial_revoke_rows = owner._receive_trial_revoke_rows_original = []
    owner.started = True;owner.start_complete = owner.server_called = owner.server_complete = False
    owner.server = owner.thread = owner.listener = None
    owner.stop_called = owner.close_called = owner.close_complete = False
    owner.state_close_called = False;owner.state_close_return = None
    owner.assets, owner.requests, owner.threads, owner.failures = [], [], [], []
    owner.probe_rows = None
    owner.directory_close_complete = False
    owner.loop_failure = owner.failure = None
    modules = {module.__name__:module for module in (barrier_module,gate_module,service)}
    return realm, owner, fixture, modules


class ReceiveTrialOwnerWiringTests(unittest.TestCase):
    def test_actual_window_gate_and_original_close_control(self):
        code = fixed_scope()
        completed = 0
        for mode in ('ok','pending','barrier_ctor_fail','gate_ctor_fail','stop_close','external_status'):
            with self.subTest(mode=mode):
                realm, owner, fixture, modules = make_scope(code, mode, requested=mode != 'ok')
                original_state, original_operation, original_session = owner.state, owner.state.operation, owner.state.session
                with mock.patch.dict(sys.modules, modules), \
                        mock.patch('os.open', side_effect=AssertionError('unexpected HOST filesystem IO')), \
                        mock.patch.object(socket, 'socket', side_effect=AssertionError('unexpected HOST socket')), \
                        mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected HOST process')), \
                        mock.patch.object(threading.Thread, 'start', side_effect=AssertionError('unexpected HOST thread')):
                    with self.assertRaises(ValueError):realm['FixedStateServiceOwner'].__init__(owner,None,100.0,receive_trial_requested=1)
                    self.assertIsNone(owner._prepare_receive_trial())
                    events = fixture['events']
                    names = [row[0] for row in events]
                    self.assertLess(names.index('scope_close_model'),names.index('barrier_ctor_model'))
                    self.assertLess(names.index('barrier_ctor_model'),names.index('gate_ctor_model'))
                    self.assertTrue(owner.startup_window_closed)
                    self.assertIs(owner._startup_window_scope_original,owner.startup_scope)
                    self.assertIs(owner._startup_window_collection_original,owner.startup_result)
                    self.assertIs(owner._receive_barrier_ticket['partial'],owner.receive_barrier)
                    self.assertIs(owner._receive_trial_ticket['partial'],owner.receive_trial)
                    if mode in ('barrier_ctor_fail','gate_ctor_fail'):
                        if mode == 'barrier_ctor_fail':
                            self.assertIs(owner._receive_barrier_ticket['failure'],fixture['fault'])
                            self.assertFalse(owner._receive_barrier_ticket['constructed'])
                        else:
                            self.assertIs(owner._receive_trial_ticket['failure'],fixture['fault'])
                        self.assertTrue(owner._receive_trial_ticket['unknown'])
                        self.assertIsNone(owner.state._receive_trial)
                        self.assertFalse(owner._receive_trial_closed())
                        self.assertFalse(owner.close())
                        self.assertEqual(sum(row[0]=='state_close_model' for row in events),1)
                        self.assertIs(owner.state,original_state)
                        self.assertIs(owner.state.operation,original_operation)
                        self.assertIs(owner.state.session,original_session)
                    else:
                        gate = owner.receive_trial
                        self.assertIs(owner._receive_trial_ticket['bind_returned'],gate)
                        self.assertIs(owner.state._receive_trial_original,gate)
                        self.assertIs(owner.state._receive_trial_module_original,modules['mta_receive_trial'])
                        self.assertFalse(owner._receive_trial_ticket['unknown'])
                        self.assertIsNone(owner._receive_trial_ticket['failure'])
                        self.assertTrue(owner._receive_barrier_closed())
                        self.assertFalse(owner._receive_trial_closed())
                        self.assertEqual(sum(row[0]=='state_bind_model' for row in events),1)
                        self.assertIsNone(owner.server)  # SOURCE checks the actual pre-listen edge.
                        if mode == 'pending':
                            self.assertEqual(owner._receive_status()['receive_barrier_reason'],'pending_exists')
                            self.assertFalse(owner._receive_status()['receive_trial_available'])
                            self.assertIs(owner.receive_barrier_failure,fixture['barrier_refusal'])
                            self.assertIsNone(owner.receive_trial_failure)
                            self.assertEqual(owner.failures,[])
                        elif mode == 'ok':
                            self.assertFalse(owner._receive_status()['receive_trial_requested'])
                            self.assertEqual(owner._receive_status()['receive_trial_reason'],'not_requested')
                        elif mode == 'external_status':
                            fixture['scope_methods_forbidden'] = True
                            clock_calls = sum(row[0]=='clock' for row in events)
                            with mock.patch.object(threading,'current_thread',return_value=object()):
                                facts = owner.status()
                            self.assertTrue(facts['startup_readonly_resources_closed'])
                            self.assertTrue(facts['receive_available'])
                            self.assertTrue(facts['startup_window_closed'])
                            self.assertEqual(sum(row[0]=='clock' for row in events),clock_calls)
                            fixture['scope_methods_forbidden'] = False
                        else:
                            gate.claimed,gate.session = original_operation,original_session
                            owner.server_complete = True;owner.server = object()
                            owner._stop_server()
                            order = [row[0] for row in events]
                            self.assertLess(order.index('gate_revoke_model'),order.index('http_shutdown_model'))
                            revoke_count = sum(row[0]=='gate_revoke_model' for row in events)
                            owner._stop_server()
                            self.assertEqual(sum(row[0]=='gate_revoke_model' for row in events),revoke_count)
                        self.assertTrue(owner.close())
                        close_index = next(index for index,row in enumerate(events) if row[0]=='state_close_model')
                        self.assertTrue(any(index<close_index and row==('gate_revoke_model','owner_closed')
                                            for index,row in enumerate(events)))
                        self.assertEqual(sum(row[0]=='state_close_model' for row in events),1)
                        self.assertTrue(owner._receive_trial_closed())
                        self.assertIs(owner.state,original_state)
                        self.assertIs(owner.state.operation,original_operation)
                        self.assertIs(owner.state.session,original_session)
                        if mode == 'stop_close':
                            self.assertIs(gate.claimed,original_operation)
                            self.assertIs(gate.session,original_session)
                        self.assertTrue(owner.close())
                        self.assertEqual(sum(row[0]=='state_close_model' for row in events),1)
                completed += 1
        self.assertEqual(completed,6)
        print('TRIAL_OWNER_CONTRACTS=6')


if __name__ == '__main__':
    unittest.main()
