"""Focused HOST models for actual V2 State once-owned construction methods.

Only the selected State methods are extracted from fixed SOURCE. Gate, Session,
Operation, original State ancestry and closure are explicit HOST models; these
are not actual RF admission, Session finalization, FD/Parent restore or device
evidence. No production State/Gate/Session constructor or helper is invoked.
Models are private ModuleType namespaces; sys.modules changes are scoped and
restored, never a fake installed module. No old methods/tests are replayed.
"""
import ast
import hashlib
import math
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/formal-receive-v2/runtime/mta_service.py'
SOURCE_PIN = (150241, '797a6395c33fee35dc61fe6daeabbc4ce8b71cd3c5540db83e9853954e0d5ab2')
METHODS = ('_bind_receive_trial', '_receive_trial_exact', '_receive_trial_available',
           '_revoke_receive_trial', '_receive_session_constructed',
           '_receive_trial_allows', '_receive_constructor_pending',
           '_new_operation_locked', '_cleanup_session_locked', 'close', 'closed')


class AncestorStateModel(object):
    def _run_operation(self, op, session):
        raise AssertionError('HOST construction scope must never start a task')

    def _restore_owner(self, op):
        raise AssertionError('HOST models cannot certify active restore')

    def _close_extra(self, op):
        raise AssertionError('HOST models cannot certify helper closure')

    def _probes_closed(self):
        return self.fixture_probes_closed


class OperationScopeModel(object):
    def __init__(self, backend, epoch, kind):
        self.backend, self.epoch, self.kind = backend, epoch, kind
        self.cancelled = threading.Event()
        self.input_ready, self.send_ready = threading.Event(), threading.Event()
        self.session = self.client_bridge = self.scan = None
        self.helper = self.key = self.crypto = self.transport = self.lease = None
        self.receive_trial = self._receive_trial_original = None
        self.receive_claim_ticket = self._receive_claim_ticket_original = None
        self.receive_session_ticket = self._receive_session_ticket_original = None


SESSION_MODEL_SOURCE = '''
class TransferSession(object):
    def __new__(cls):
        if fixture['mode']=='new_fail':raise RuntimeError('HOST new fault')
        fixture['new_calls']+=1
        return object.__new__(cls)
    def __init__(self,task,restore,lease_owner,extra_actor_close=None,
                 task_timeout=300,finalize_timeout=120,cancelled=None,
                 direction='receive',scoped_owner=None,scoped_release=None,
                 absolute_until=None):
        fixture['init_calls']+=1
        assert lease_owner is fixture['state'].operation
        assert self is lease_owner.session is fixture['state'].session
        self._task,self._restore,self._extra=task,restore,extra_actor_close
        self._lease_owner,self.cancelled=lease_owner,cancelled
        self._absolute_until=self._absolute_until_original=absolute_until
        self._worker=object()
        self.fixture_initialized=False;self.fixture_closed=False
        if fixture['mode']=='init_fail':raise RuntimeError('HOST init fault')
        self.fixture_initialized=True
    def closed(self):
        assert self.fixture_initialized is True
        fixture['closed_calls']+=1
        return self.fixture_closed
    def close(self,timeout=30):
        assert self.fixture_initialized is True
        fixture['close_calls']+=1
        self.cancelled.set();self.fixture_closed=True
        return True
'''


GATE_MODEL_SOURCE = '''
class FixedReceiveTrial(object):
    def __init__(self,state):
        self.state=state;self.claimed=None;self.session=None;self.revoked=False
        self.claim_history=[];self.attach_history=[]
    def binds(self,state):return state is self.state
    def available(self,state):
        return self.binds(state) and self.claimed is None and not self.revoked
    def claim(self,state,op):
        assert state is self.state and state.operation is op
        assert op.epoch==state.native_epoch and op.receive_trial is self
        assert op.receive_claim_ticket['called'] is True
        self.claim_history.append(op)
        self.claimed=op
        if fixture['mode']=='claim_fail':raise RuntimeError('HOST claim fault')
        return op
    def attach_session(self,state,op,session):
        assert state is self.state and self.claimed is op
        assert session is state.session is op.session
        ticket=op.receive_session_ticket
        assert ticket['init_returned'] is True and ticket['attach_called'] is True
        assert ticket['attach_returned'] is False
        self.attach_history.append(session)
        if fixture['mode']=='attach_fail':raise RuntimeError('HOST attach fault')
        self.session=session
        return session
    def allows(self,state,op,session):
        return (self.binds(state) and op is self.claimed and session is self.session
                and not self.revoked and not op.cancelled.is_set())
    def revoke(self,state,reason):
        assert state is self.state
        self.revoked=True
        return True
    def closed(self,state):return self.binds(state) and self.revoked
'''


def fixed_scope():
    raw = SOURCE.read_bytes()
    if SOURCE_PIN is None or (len(raw), hashlib.sha256(raw).hexdigest()) != SOURCE_PIN:
        raise AssertionError('Focused State SOURCE is not sealed')
    tree = ast.parse(raw.decode('utf-8'), str(SOURCE))
    original = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'State')
    selected = [row for row in original.body if isinstance(row, ast.FunctionDef) and row.name in METHODS]
    if tuple(row.name for row in selected) != METHODS:
        raise AssertionError('Focused actual State method inventory changed')
    model_class = ast.ClassDef(name='State', bases=[ast.Name(id='AncestorStateModel', ctx=ast.Load())],
                              keywords=[], body=selected, decorator_list=[])
    model_tree = ast.fix_missing_locations(ast.Module(body=[model_class], type_ignores=[]))
    return compile(model_tree, str(SOURCE), 'exec')


def make_scope(code, mode='ok'):
    fixture = dict(mode=mode, new_calls=0, init_calls=0, close_calls=0, closed_calls=0)
    session_module = types.ModuleType('mta_transfer_session')
    session_module.fixture = fixture
    exec(SESSION_MODEL_SOURCE, session_module.__dict__)
    gate_module = types.ModuleType('mta_receive_trial')
    gate_module.fixture = fixture
    exec(GATE_MODEL_SOURCE, gate_module.__dict__)
    realm = dict(__name__='HOST_receive_trial_state_model', AncestorStateModel=AncestorStateModel,
                 Operation=OperationScopeModel, TransferSession=session_module.TransferSession,
                 receive_trial=gate_module, threading=threading, sys=sys, types=types, math=math, time=time,
                 StateClientBridge=type('NeverCreatedBridgeModel', (), {}))
    exec(code, realm)
    state = realm['State'].__new__(realm['State'])
    fixture['state'] = state
    state.lock = threading.RLock()
    state._receive_trial = state._receive_trial_original = None
    state._receive_trial_module_original = state._receive_trial_error = None
    state.operation = state.session = state.worker = None
    state.helper = state.key = state.crypto = state.lease = state.transport = None
    state.closing = False;state.wifi_restore_pending = state.radio_restore_pending = False
    state.fixture_probes_closed = True;state.history = [];state.native_epoch = 0
    state.wifi_backend = object();state._trusted_receive_deployment_factory = object()
    state._network_observer_spec_original = object()
    state._service_until_original = 100.0;state._service_cleanup_until_original = 160.0
    state.cancelled = threading.Event();state.decision = threading.Event()
    modules = {'mta_receive_trial': gate_module, 'mta_transfer_session': session_module}
    trial = gate_module.FixedReceiveTrial(state)
    return realm, state, trial, fixture, modules


class ReceiveTrialStateWiringTests(unittest.TestCase):
    def test_actual_once_owned_construction_and_retained_failures(self):
        code = fixed_scope()
        completed = 0
        for mode in ('ok', 'claim_fail', 'new_fail', 'init_fail', 'attach_fail', 'second_refused'):
            with self.subTest(mode=mode):
                realm, state, trial, facts, modules = make_scope(code, mode)
                with mock.patch.dict(sys.modules, modules):
                    self.assertIs(state._bind_receive_trial(trial), trial)
                    self.assertTrue(state._receive_trial_available())
                    if mode in ('ok', 'second_refused'):
                        with state.lock:op = state._new_operation_locked('receive')
                        self.assertIs(state.operation, op)
                        self.assertIs(trial.claimed, op)
                        self.assertIs(op.receive_claim_ticket['result'], op)
                        self.assertIs(op.receive_session_ticket['value_original'], op.session)
                        self.assertIs(trial.session, op.session)
                        self.assertTrue(state._receive_session_constructed(op))
                        self.assertTrue(state._receive_trial_allows(op, op.session))
                        self.assertFalse(state._receive_trial_available())
                        self.assertIs(state._cleanup_session_locked(), op.session)
                        if mode == 'second_refused':
                            original_epoch = state.native_epoch
                            op.session.fixture_closed = True
                            state.receive_available = True  # A browser-style boolean is never authority.
                            with self.assertRaises(ValueError):state._new_operation_locked('receive')
                            self.assertIs(state.operation, op)
                            self.assertEqual(state.native_epoch, original_epoch)
                            self.assertEqual(state.history, [])
                            self.assertEqual(len(trial.claim_history), 1)
                        self.assertTrue(state.close(0))
                        self.assertIs(trial.claimed, op)
                        self.assertIs(op.session, trial.session)
                        self.assertEqual(facts['close_calls'], 1)
                    else:
                        with self.assertRaises(RuntimeError):
                            with state.lock:state._new_operation_locked('receive')
                        op = state.operation
                        self.assertIs(trial.claimed, op)
                        self.assertIs(trial.claim_history[0], op)
                        self.assertIs(op.receive_trial, trial)
                        self.assertIs(op.receive_claim_ticket, op._receive_claim_ticket_original)
                        self.assertFalse(state._receive_trial_available())
                        if mode == 'attach_fail':
                            self.assertTrue(state._receive_session_constructed(op))
                            self.assertIs(state._cleanup_session_locked(), op.session)
                            self.assertIs(op.receive_session_ticket['value_original'], op.session)
                            self.assertIs(trial.attach_history[0], op.session)
                            self.assertFalse(state._receive_trial_allows(op, op.session))
                            self.assertTrue(state.close(0))
                            self.assertEqual(facts['close_calls'], 1)
                            self.assertIsNotNone(op.receive_session_ticket['attach_error'])
                        else:
                            self.assertTrue(state._receive_constructor_pending())
                            self.assertFalse(state._receive_session_constructed(op))
                            self.assertFalse(state.closed())
                            with self.assertRaises(ValueError):state._cleanup_session_locked()
                            self.assertEqual(facts['close_calls'], 0)
                            self.assertEqual(facts['closed_calls'], 0)
                            if mode == 'claim_fail':
                                self.assertIsNone(op.session)
                                self.assertFalse(op.receive_session_ticket['new_called'])
                                self.assertIsNotNone(op.receive_claim_ticket['error'])
                            elif mode == 'new_fail':
                                self.assertIsNone(op.session)
                                self.assertTrue(op.receive_session_ticket['new_called'])
                                self.assertFalse(op.receive_session_ticket['new_returned'])
                            else:
                                self.assertIs(op.session, state.session)
                                self.assertIs(op.receive_session_ticket['value_original'], op.session)
                                self.assertTrue(op.receive_session_ticket['init_called'])
                                self.assertFalse(op.receive_session_ticket['init_returned'])
                                self.assertIsNotNone(op.receive_session_ticket['init_error'])
                                self.assertIs(state.worker, op.session._worker)
                completed += 1
        self.assertEqual(completed, 6)
        print('TRIAL_STATE_CONTRACTS=6')


if __name__ == '__main__':
    unittest.main()
