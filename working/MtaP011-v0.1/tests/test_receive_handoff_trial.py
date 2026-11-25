"""One new HOST method for original claimed Handoff DATA, never an RF test.

Gate, Handoff, bundled JSON, radio parser, Barrier definitions, wire protocol and
CONNECT codec are full actual sources. Ten State methods and Operation are
extracted from V3's exact source into a private canonical model realm. Original
Owner/startup/probe/FD ledgers and Session/crypto/Bridge/helper IO are explicit
HOST models. Two real HOST threads exercise the original worker/reader roles;
they do not run Session.start, spawn helpers, open sockets, publish a deployment
or touch P011. The old Gate test's pinned pure fixture builder is reused, but no
old test method or old Gate source is executed. No production injection API.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import math
from pathlib import Path
import queue
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PINS = (
    ('mta_receive_trial', 'candidate/formal-receive-v3/runtime/mta_receive_trial.py', 64493,
     'b3ffef7c593d254c375f8f4f0f97aa97cb7027db03e88861db639294dd1de13a'),
    ('mta_client_connect_handoff', 'candidate/formal-receive-v3/runtime/mta_client_connect_handoff.py', 12094,
     'cfff0f59520cfa074492e5bccca70dbf12b24d7252787702170fb0f0a63d7fc1'),
    ('state_source', 'candidate/formal-receive-v3/runtime/mta_service.py', 155732,
     '76f48871bb4c2a3b72bb308e9bef56b3d509f01ef45c7ac2808d210acedd6960'),
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_receive_radio_baseline', 'runtime/mta_receive_radio_baseline.py', 3971,
     '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c'),
    ('mta_receive_barrier', 'candidate/formal-receive-v2/runtime/mta_receive_barrier.py', 24113,
     'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397'),
    ('mta_protocol', 'runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 'candidate/client-integrated-v37/runtime/mta_client_control_frame.py', 20942,
     'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('fixture_source', 'tests/test_receive_trial_gate.py', 36261,
     '3705ae262b052dadefb0739cdca56182ed9986ce7b77242a9c407dde60651d6a'),
)
STATE_METHODS = frozenset(('_receive_trial_exact', '_receive_trial_available',
    '_receive_session_constructed', '_receive_trial_allows', '_receive_constructor_pending',
    '_receive_handoff_constructed', '_receive_handoff_data_allowed', '_new_receive_handoff',
    '_new_operation_locked', '_close_extra'))


def inputs():
    result = {}
    for name, relative, length, digest in PINS:
        raw = (BASE / relative).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (length, digest):
            raise AssertionError('New Handoff source input is not sealed: ' + name)
        result[name] = (raw, str(BASE / relative))
    return result


def actual_module(name, raw, path, scope):
    value = types.ModuleType(name)
    value.__file__ = path
    with mock.patch.dict(sys.modules, scope):
        exec(compile(raw.decode('utf-8'), path, 'exec'), value.__dict__)
    return value


def model_loop(commands):
    while True:
        entry = commands.get(timeout=5)
        if entry is None:
            return
        function, result = entry
        try:
            result.put((True, function()))
        except BaseException as error:
            result.put((False, error))


def call(commands, function):
    result = queue.Queue()
    commands.put((function, result))
    good, value = result.get(timeout=5)
    if not good:
        raise value
    return value


SESSION_MODEL = '''
class TransferSession(object):
    def __init__(self,task,restore,lease_owner,extra_actor_close=None,
                 task_timeout=300,finalize_timeout=120,cancelled=None,
                 direction='receive',scoped_owner=None,scoped_release=None,absolute_until=None):
        self._task,self._restore,self._extra=task,restore,extra_actor_close
        self._lease_owner,self.cancelled=lease_owner,cancelled
        self._absolute_until=self._absolute_until_original=absolute_until
        self._direction,self._scoped_owner,self._release=direction,scoped_owner,scoped_release
        self._started=self._worker_start_claimed=self._worker_start_resolved=False
        self._worker_start_unknown=False;self._task_deadline=None
        self._worker=threading.Thread(target=model_loop,args=(fixture['worker_commands'],),
                                      name='HOST-model-original-Session-worker')
    def closed(self):return False
    def start(self):raise AssertionError('No original RF task is run by this HOST model')
'''
CRYPTO_MODEL = '''
class OpenSslCrypto(object):
    def __init__(self):self._lib=object();self.decrypt_calls=0
    def decrypt_credentials(self,encrypted,key):
        assert type(encrypted) is protocol.P2pInfo and encrypted.key is not None
        assert type(key) is KeyPair and key._owner is self._lib and not key.closed
        self.decrypt_calls+=1
        return protocol.P2pInfo('HOST-DATA-MODEL','HOST-model-key','00:11:22:33:44:55',12345)
class KeyPair(object):
    def __init__(self,owner):self._owner=owner;self.closed=False
    def close(self):self.closed=True
'''
MODEL_STATE_ANCESTOR = '''
def _model_probes(self):return True
def _model_verify_radio(self):return True
State._probes_closed=State._close_probes=_model_probes
State.verify_radio_restore=_model_verify_radio
AncestorStateModel=State
'''


@contextmanager
def scope(source, helper_builder, barrier='clear'):
    actual = {}
    for name in ('mta_receive_trial', 'p011_json', 'mta_receive_radio_baseline', 'mta_receive_barrier'):
        raw, path = source[name]
        actual[name] = actual_module(name, raw, path, actual)
    f = helper_builder.fixture_models(actual, barrier_reason=barrier)
    modules, service, session_module = f['modules'], f['state_module'], f['session_module']
    f['worker_commands'], f['reader_commands'] = queue.Queue(), queue.Queue()
    session_module.__dict__.update(fixture=f, threading=threading, model_loop=model_loop)
    exec(SESSION_MODEL, session_module.__dict__)
    raw, path = source['mta_protocol']
    protocol = actual_module('mta_protocol', raw, path, modules)
    modules['mta_protocol'] = protocol
    crypto = helper_builder.module_model('mta_crypto', CRYPTO_MODEL, dict(protocol=protocol))
    modules['mta_crypto'] = crypto
    raw, path = source['mta_client_connect_handoff']
    handoffs = actual_module('mta_client_connect_handoff', raw, path, modules)
    handoffs.time = types.SimpleNamespace(monotonic=f['clock'])  # Module-local HOST clock only.
    modules['mta_client_connect_handoff'] = handoffs
    raw, path = source['mta_client_control_frame']
    codec = actual_module('mta_client_control_frame', raw, path, modules)
    modules['mta_client_control_frame'] = codec
    service.__dict__.update(threading=threading, sys=sys, types=types, math=math,
        time=types.SimpleNamespace(monotonic=f['clock']), receive_trial=f['gate'],
        TransferSession=session_module.TransferSession, ReceiveConnectHandoff=handoffs.ReceiveConnectHandoff)
    exec(MODEL_STATE_ANCESTOR, service.__dict__)
    raw, path = source['state_source']
    tree = ast.parse(raw.decode('utf-8'), path)
    original = next(value for value in tree.body if isinstance(value, ast.ClassDef) and value.name == 'State')
    selected = [value for value in original.body if isinstance(value, ast.FunctionDef) and value.name in STATE_METHODS]
    if set(value.name for value in selected) != STATE_METHODS:
        raise AssertionError('New State method inventory changed')
    state_class = ast.ClassDef(name='State', bases=[ast.Name(id='AncestorStateModel',ctx=ast.Load())],
                              keywords=[],body=selected,decorator_list=[])
    operation = next(value for value in tree.body if isinstance(value, ast.ClassDef) and value.name == 'Operation')
    extracted = ast.fix_missing_locations(ast.Module(body=[operation,state_class],type_ignores=[]))
    exec(compile(extracted,path,'exec'),service.__dict__)
    state = f['state']; state.__class__ = service.State
    state.lock=threading.RLock();state.history=[]
    state.receive_available=state.send_available=False;state.receive_reason='HOST model'
    state.key=state.crypto=state.lease=state.transport=None
    state._receive_trial_module_original=f['gate']
    f.update(handoffs=handoffs,crypto_module=crypto,codec=codec)
    threads=[]
    with mock.patch.dict(sys.modules,modules):
        helper_builder.prepare_gate(f)
        if barrier == 'clear':
            op=state._new_operation_locked('receive')
            session=op.session
            session._started=session._worker_start_claimed=session._worker_start_resolved=True
            session._task_deadline=90.0
            helper=service.PrivateHelper()
            helper.path=state.bluez_path;helper.spawn_resolved=True;helper.spawn_unknown=False
            helper.closed=False;helper.close_calls=0
            def close_model():
                helper.close_calls+=1;helper.closed=True;return True
            helper.close=close_model;helper.closure_verified=lambda:helper.closed
            helper.thread=threading.Thread(target=model_loop,args=(f['reader_commands'],),
                                           name='HOST-model-original-helper-reader')
            state.helper=op.helper=helper
            state.crypto=op.crypto=crypto.OpenSslCrypto()
            state.key=op.key=crypto.KeyPair(op.crypto._lib)
            state.radio_restore_pending=True
            state.discoverable=False
            threads=[session._worker,helper.thread]
            for value in threads:value.start()
            f.update(op=op,session=session,helper=helper)
        try:
            yield f
        finally:
            if threads:
                f['worker_commands'].put(None);f['reader_commands'].put(None)
                for value in threads:value.join(5)
                if any(value.is_alive() for value in threads):
                    raise AssertionError('HOST model original worker/reader did not exit')


def construct(f):
    return call(f['worker_commands'],lambda:f['state']._new_receive_handoff(f['op'],f['session'],f['helper']))


def capture(f,handoff,commands=None):
    f['op'].stage='advertising';f['state'].discoverable=True
    wire=f['modules']['mta_protocol'].P2pInfo('eA==','eA==','eA==',12345,key='eA==').to_bytes()
    event=dict(event='p2p',session=1,payload_b64=base64.b64encode(wire).decode('ascii'))
    return call(commands or f['reader_commands'],lambda:handoff.capture(event,f['helper'],f['op'].epoch,f['op'].epoch))


def original_bridge(f,handoff):
    bridge=f['modules']['mta_client_state_bridge'].StateClientBridge()
    bridge.state,bridge.operation,bridge.session=f['state'],f['op'],f['session']
    bridge.worker=f['session']._worker;bridge.cancelled=f['op'].cancelled
    bridge.epoch=f['op'].epoch;bridge._factory=f['owner'].factory;bridge.handoff=handoff
    bridge.started=bridge.running=True
    f['op'].client_bridge=bridge
    f['op'].receive_bridge_ticket.update(started=True,returned=bridge)
    f['state'].wifi_restore_pending=True
    return bridge


class ReceiveHandoffTrialTests(unittest.TestCase):
    def test_original_claimed_handoff_data(self):
        source=inputs()
        raw,path=source['fixture_source']
        # Import the fixed model-builder definitions only. Do not call any old
        # test or fixed_sources(), which would load/test the historical Gate.
        builder=types.ModuleType('private_reused_gate_fixture_models');builder.__file__=path
        exec(compile(raw.decode('utf-8'),path,'exec'),builder.__dict__)
        cases=0
        with self.subTest(domain='actual_constructor_false_sentinel_radio_pending_no_bridge'):
            with scope(source,builder) as f:
                handoff=construct(f)
                self.assertIs(handoff,f['op'].client_handoff)
                self.assertIs(f['op'].receive_handoff_ticket['value_original'],handoff)
                self.assertTrue(f['state']._receive_handoff_constructed(f['op']))
                self.assertFalse(f['state'].receive_available)
                self.assertFalse(f['trial'].available(f['state']))
                self.assertIsNone(f['op'].client_bridge)
                self.assertTrue(call(f['worker_commands'],lambda:f['state']._receive_handoff_data_allowed(
                    f['op'],f['session'],handoff,'worker')))
                self.assertEqual(f['trial'].claim_count,1)
                self.assertEqual(f['helper'].close_calls,0)
                with self.assertRaises(ValueError):construct(f)
            cases+=1
        with self.subTest(domain='actual_reader_capture_worker_decrypt_claim_wifi_pending'):
            with scope(source,builder) as f:
                handoff=construct(f)
                self.assertTrue(capture(f,handoff))
                self.assertFalse(f['state'].discoverable)
                original_bridge(f,handoff)
                self.assertFalse(call(f['worker_commands'],lambda:f['trial'].allows(f['state'],f['op'],f['session'])))
                self.assertTrue(call(f['worker_commands'],handoff.decrypt))
                frame=call(f['worker_commands'],lambda:handoff.claim_frame(f['codec'],'a'*32,'b'*64,'HOST-handoff'))
                decoder=f['codec'].ControlFrameDecoder(handoff.binding);decoder.feed(frame)
                request=decoder.take_connect()
                self.assertEqual(request.private_info().ssid,'HOST-DATA-MODEL')
                self.assertEqual(f['op'].crypto.decrypt_calls,1)
                self.assertFalse(f['state'].receive_available)
                self.assertFalse(f['trial'].available(f['state']))
                self.assertIsNone(handoff._plain)
                with self.assertRaises(f['handoffs'].HandoffError):
                    call(f['worker_commands'],lambda:handoff.claim_frame(f['codec'],'a'*32,'b'*64,'HOST-handoff'))
            cases+=1
        for domain,role in (('worker_cannot_capture','worker'),('external_thread_cannot_capture','external'),
                            ('reader_cannot_decrypt','reader')):
            with self.subTest(domain=domain):
                with scope(source,builder) as f:
                    handoff=construct(f)
                    with self.assertRaises(f['handoffs'].HandoffError):
                        if role=='worker':capture(f,handoff,f['worker_commands'])
                        elif role=='reader':call(f['reader_commands'],handoff.decrypt)
                        else:handoff.capture({},f['helper'],f['op'].epoch,f['op'].epoch)
                cases+=1
        for domain,mutate in (
            ('wrong_original_session',lambda f,h:setattr(f['state'],'session',object())),
            ('changed_epoch',lambda f,h:setattr(f['state'],'native_epoch',f['op'].epoch+1)),
            ('revoked_claim',lambda f,h:f['trial'].revoke(f['state'],'cancelled')),
            ('original_task_expired',lambda f,h:f.update(now=90.0)),
            ('original_service_expired',lambda f,h:f.update(now=100.0)),
            ('renewed_task_deadline_rejected',lambda f,h:setattr(f['session'],'_task_deadline',91.0)),
            ('changed_owner_clock',lambda f,h:setattr(f['owner'],'clock',lambda:10.0)),
            ('foreign_reader',lambda f,h:setattr(f['helper'],'thread',threading.Thread())),
            ('wifi_pending_without_original_bridge',lambda f,h:setattr(f['state'],'wifi_restore_pending',True)),
            ('constructor_ticket_changed',lambda f,h:f['op'].receive_handoff_ticket.update(value_original=object())),
            ('claimed_operation_cancelled',lambda f,h:f['op'].cancelled.set()),
        ):
            with self.subTest(domain=domain):
                with scope(source,builder) as f:
                    handoff=construct(f);mutate(f,handoff)
                    with self.assertRaises(f['handoffs'].HandoffError):
                        call(f['worker_commands'],handoff._check)
                    self.assertIs(f['op'].client_handoff,handoff)
                    self.assertEqual(f['trial'].claim_count,1)
                    self.assertFalse(f['state'].receive_available)
                cases+=1
        with self.subTest(domain='changed_handoff_clock_not_called'):
            with scope(source,builder) as f:
                handoff=construct(f);calls=[]
                handoff.clock=lambda:calls.append(True) or 10.0
                with self.assertRaises(f['handoffs'].HandoffError):call(f['worker_commands'],handoff._check)
                self.assertEqual(calls,[])
            cases+=1
        with self.subTest(domain='changed_state_authorizer_not_called'):
            with scope(source,builder) as f:
                handoff=construct(f)
                exec('def _changed_authorizer(*unused):\n    raise AssertionError("changed authority called")\n',
                     f['state_module'].__dict__)
                f['state_module'].State._receive_handoff_data_allowed=f['state_module']._changed_authorizer
                with self.assertRaises(f['handoffs'].HandoffError):call(f['worker_commands'],handoff._check)
            cases+=1
        with self.subTest(domain='partial_constructor_retained_no_partial_cancel'):
            with scope(source,builder) as f:
                self.assertTrue(f['trial'].revoke(f['state'],'cancelled'))
                with self.assertRaises(f['handoffs'].HandoffError) as failure:construct(f)
                ticket=f['op'].receive_handoff_ticket;partial=f['op'].client_handoff
                self.assertIs(ticket['value_original'],partial)
                self.assertIs(ticket['init_error'],failure.exception)
                self.assertFalse(ticket['init_returned'])
                self.assertTrue(f['op'].actor_unknown)
                self.assertFalse(f['state']._receive_handoff_constructed(f['op']))
                self.assertFalse(partial._cancelled)
                self.assertFalse(f['state']._close_extra(f['op']))
                self.assertFalse(partial._cancelled)
                self.assertEqual(f['helper'].close_calls,1)
                self.assertTrue(f['state'].radio_restore_pending)
                self.assertIs(f['op'].client_handoff,partial)
            cases+=1
        with self.subTest(domain='old_pending_cannot_claim_or_construct'):
            with scope(source,builder,barrier='pending_exists') as f:
                self.assertFalse(f['trial'].available(f['state']))
                with self.assertRaises(ValueError):f['state']._new_operation_locked('receive')
                self.assertEqual(f['trial'].claim_count,0)
                self.assertIsNone(f['state'].operation)
                self.assertEqual(f['trial'].reason,'pending_exists')
            cases+=1
        self.assertEqual(cases,20)
        print('RECEIVE_HANDOFF_DATA_CONTRACTS='+str(cases))
        print('NEW_METHODS_EXECUTED=1')


if __name__=='__main__':
    unittest.main()
