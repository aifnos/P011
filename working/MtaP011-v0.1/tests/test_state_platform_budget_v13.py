"""New isolated State budget HOST tests; actual worker/session over Fake IO."""
import ast
import contextlib
import hashlib
import importlib.util
import pathlib
import sys
import threading
import unittest
from unittest import mock

BASE=pathlib.Path(__file__).absolute().parents[1]
sys.path.insert(0,str(BASE/'runtime'));sys.path.insert(0,str(BASE/'tests'))
import test_state_send_integration as fixture
import mta_send_worker as worker

PATH=BASE/'candidate/state-platform-budget-v13/mta_service.py'
spec=importlib.util.spec_from_file_location('isolated_state_platform_budget_v13',str(PATH))
service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)


class Clock:
    def __init__(self):self.value=100.0;self.calls=0;self.gaps={}
    def __call__(self):
        self.calls+=1;self.value+=self.gaps.get(self.calls,0);return self.value
    def advance(self,value):self.value+=value


class Provider(fixture.Provider):
    def __init__(self,clock):
        super().__init__();self.clock=clock;self.restore_duration=6;self.fresh_duration=1
        self.budgets=[];self.mode='good';self.restore_entered=threading.Event();self.held=None
    def restore_owned(self,lease,epoch,task_id,budget):
        self.restore_count+=1;self.budgets.append(('restore',budget));self.restore_threads.append(threading.current_thread())
        op=self.state.operation
        if (op.session._worker.is_alive() or op.send_worker._run_thread.is_alive() or
                not op.transport.closed() or not op.send_worker.status()['scope_released'] or
                not op.send_worker.status()['extra_resources_closed'] or self.state.lock._is_owned()):
            raise AssertionError('actual State/worker external restore order')
        self.restore_entered.set()
        if self.held is not None:self.held.wait(2)
        self.clock.advance(self.restore_duration)
        receipt=service.SendRestoreReceipt(self,lease,epoch,task_id,True,True,True,True)
        if self.mode=='old_class':receipt=fixture.service.SendRestoreReceipt(*receipt)
        elif self.mode=='wrong_task':receipt=receipt._replace(task_id='other-task')
        elif self.mode=='wrong_epoch':receipt=receipt._replace(operation_epoch=epoch+1)
        elif self.mode=='nonbool':receipt=receipt._replace(resources_closed=1)
        elif self.mode=='mutated_epoch':self.state.native_epoch+=1
        self.restore_receipt=receipt;return receipt
    def read_restored(self,receipt,budget):
        self.budgets.append(('fresh',budget));self.clock.advance(self.fresh_duration)
        self.read_receipt=receipt if self.mode=='cached' else service.SendRestoreReceipt(*receipt)
        return self.read_receipt


class Harness:
    def __init__(self,budget=None):
        self.clock=Clock();self.provider=Provider(self.clock);self.registry=fixture.Registry()
        self.crypto=fixture.fixture.FakeCrypto();self.stack=contextlib.ExitStack();self.sender=None
        self.scan_ready=threading.Event();harness=self
        class Helper(fixture.Helper):
            def send(self,command):
                super().send(command)
                if command['cmd']=='scan':harness.scan_ready.set()
        for name,value in (('FileRegistry',lambda *a:self.registry),('SafeZipReceiver',lambda *a:object()),
                ('WifiBackend',fixture.Wifi),('PrivateHelper',Helper),('capability',lambda *a,**k:dict(fixture.CAPS))):
            self.stack.enter_context(mock.patch.object(service,name,value))
        self.stack.enter_context(mock.patch.object(service.os.path,'exists',return_value=True))
        self.stack.enter_context(mock.patch.object(service.os,'urandom',side_effect=lambda count:b'\x01'*count))
        for name in ('mkdir','kill','waitpid'):
            self.stack.enter_context(mock.patch.object(service.os,name,side_effect=AssertionError('no actual OS/RF')))
        self.stack.enter_context(mock.patch.object(service.subprocess,'Popen',side_effect=AssertionError('no process')))
        self.stack.enter_context(mock.patch('mta_scoped_sockets.socket.socket',side_effect=AssertionError('no socket')))
        self.stack.enter_context(mock.patch.object(worker,'OpenSslCrypto',side_effect=AssertionError('no native crypto')))
        self.stack.enter_context(mock.patch.object(worker,'SenderTransport',side_effect=AssertionError('no native sender')))
        self.stack.enter_context(mock.patch.object(service.State,'_make_send_worker',lambda state,op:self.make_worker(op)))
        self.state=service.State('/HOST/users','/HOST/bluez','/HOST/network',send_provider=self.provider,
            send_restore_budget=budget,send_restore_clock=self.clock)
        self.provider.state=self.state
    def make_worker(self,op):
        state=self.state
        return worker.SendWorker(op.send_intent.handoff,state.registry,list(op.send_intent.file_ids),
            provider=op.send_provider,cancelled=op.cancelled,timeout=3,
            crypto_factory=lambda path:self.crypto,transport_factory=self.make_sender)
    def make_sender(self,*args,**kwargs):
        self.sender=fixture.Sender(*args,**kwargs);self.sender.state=self.state;return self.sender
    def start(self):
        self.state.send_available=True # Explicit Fake-only admission, never production.
        self.state.action({'action':'scan'})
        # Registration + both callbacks precede this deterministic Fake event.
        if not self.scan_ready.wait(1):raise AssertionError('Fake scan not registered')
        self.state.action({'action':'send','deviceId':'7','fileIds':['file-id']})
        return self.state.operation
    def settle(self):
        op=self.state.operation;op.session._worker.join(2)
        for row in tuple(op.session._attempts):row['thread'].join(2)
        return self.state.status()
    def close(self):
        if self.provider.held is not None:self.provider.held.set()
        if self.state.operation is not None:
            self.state.close();op=self.state.operation
            if op.session._worker.ident is not None:op.session._worker.join(2)
            for row in tuple(op.session._attempts):
                if row['thread'].ident is not None:row['thread'].join(2)
            if op.session._worker.is_alive() or any(r['thread'].is_alive() for r in op.session._attempts):
                raise AssertionError('Fake original threads still live')
        self.stack.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class StatePlatformBudgetV13Tests(unittest.TestCase):
    def test_constructor_finite_private_policy_default_deny_before_io(self):
        bad=(True,(75,60,15),service.SendRestoreBudget(0,1,1),service.SendRestoreBudget(121,60,15),
            service.SendRestoreBudget(75,61,1),service.SendRestoreBudget(75,40,31),
            service.SendRestoreBudget(5,4,2),service.SendRestoreBudget(75,True,1),
            service.SendRestoreBudget(float('nan'),1,1),service.SendRestoreBudget(float('inf'),1,1),
            service.SendRestoreBudget(10**1000,1,1))
        with mock.patch.object(service,'FileRegistry',side_effect=AssertionError('bad budget before IO')):
            for value in bad:
                with self.subTest(value=repr(value)),self.assertRaises(ValueError):
                    service.State('/unused','/unused','/unused',send_restore_budget=value)
            with self.assertRaises(ValueError):service.State('/unused','/unused','/unused',send_restore_clock=True)
        with Harness() as h:
            self.assertFalse(h.state.send_available)
            self.assertEqual(h.state._send_restore_budget,service.SendRestoreBudget(75,60,15))
            self.assertEqual(h.provider.budgets,[])

    def test_actual_worker_session_restore_over_old_five_and_fresh_point_two(self):
        with Harness() as h:
            op=h.start();status=h.settle();window=op.send_restore_budget_owner
            self.assertTrue(status['sessionLifecycle']['closed']);self.assertFalse(status['restorePending'])
            self.assertIs(type(op.send_restore_receipt),service.SendRestoreReceipt)
            self.assertIsNot(op.send_restore_receipt,op.send_restore_readback)
            self.assertIs(op.send_worker.__class__,worker.SendWorker)
            self.assertEqual(h.provider.budgets,[('restore',60.0),('fresh',15.0)])
            self.assertEqual(window.deadline,175);self.assertTrue(window.complete)
            self.assertIs(window.session,op.session);self.assertIs(window.worker,op.send_worker)
            self.assertNotEqual(h.provider.restore_threads,[op.session._worker])
            self.assertFalse(op.send_worker.status()['platform_available'])
            self.assertNotIn('SendRestoreBudget',repr(status))

    def test_absolute_total_remaining_late_return_pending_no_renew_or_retry(self):
        with Harness(service.SendRestoreBudget(6,4,2)) as h:
            h.provider.restore_duration=3;h.provider.fresh_duration=1.1;h.clock.gaps[4]=2
            op=h.start();status=h.settle();window=op.send_restore_budget_owner
            self.assertEqual(h.provider.budgets,[('restore',4.0),('fresh',1.0)])
            self.assertEqual(window.deadline,106);self.assertTrue(window.failed)
            self.assertIsNotNone(op.send_restore_readback)
            self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
            op.session.close(.1)
            for row in tuple(op.session._attempts):row['thread'].join(1)
            self.assertEqual(h.provider.restore_count,1);self.assertEqual(window.deadline,106)
        with Harness(service.SendRestoreBudget(6,4,2)) as h:
            h.provider.restore_duration=4.1;h.provider.fresh_duration=0
            op=h.start();status=h.settle()
            self.assertEqual(h.provider.budgets,[('restore',4.0)])
            self.assertTrue(status['restorePending']);self.assertIsNotNone(op.send_restore_receipt)

    def test_exact_new_receipt_bindings_cached_epoch_change_and_clock_regression_fail_closed(self):
        for mode in ('old_class','wrong_task','wrong_epoch','nonbool','mutated_epoch','cached'):
            with self.subTest(mode=mode),Harness() as h:
                h.provider.mode=mode;op=h.start();status=h.settle()
                self.assertTrue(status['restorePending']);self.assertFalse(status['sessionLifecycle']['closed'])
                self.assertFalse(h.state.send_available);self.assertIsNotNone(op.send_restore_receipt)
        with Harness() as h:
            h.provider.restore_duration=0;h.clock.gaps[3]=-1
            op=h.start();status=h.settle()
            self.assertTrue(status['restorePending']);self.assertIsNone(op.send_restore_readback)
            self.assertEqual(h.provider.restore_count,1)

    def test_exact_phase_deadline_restore_and_fresh_returns_stay_pending(self):
        with Harness(service.SendRestoreBudget(7,4,2)) as h:
            h.provider.restore_duration=4;h.provider.fresh_duration=0
            op=h.start();status=h.settle()
            self.assertEqual(h.provider.budgets,[('restore',4.0)])
            self.assertEqual(h.clock.value,op.send_restore_budget_owner.phase_deadline)
            self.assertIsNotNone(op.send_restore_receipt);self.assertIsNone(op.send_restore_readback)
            self.assertTrue(status['restorePending']);self.assertFalse(status['sessionLifecycle']['closed'])
        with Harness(service.SendRestoreBudget(7,4,2)) as h:
            h.provider.restore_duration=0;h.provider.fresh_duration=2
            op=h.start();status=h.settle()
            self.assertEqual(h.provider.budgets,[('restore',4.0),('fresh',2.0)])
            self.assertEqual(h.clock.value,op.send_restore_budget_owner.phase_deadline)
            self.assertLess(h.clock.value,op.send_restore_budget_owner.deadline)
            self.assertIsNotNone(op.send_restore_readback)
            self.assertTrue(status['restorePending']);self.assertFalse(status['sessionLifecycle']['closed'])

    def test_inflight_finalizer_and_reentrant_call_never_false_complete_or_second_restore(self):
        with Harness() as h:
            h.provider.held=threading.Event();op=h.start()
            self.assertTrue(h.provider.restore_entered.wait(1))
            self.assertTrue(op.send_restore_budget_owner.active)
            self.assertFalse(op.session.closed());self.assertTrue(h.state.status()['restorePending'])
            self.assertFalse(h.state._restore_owner(op));self.assertEqual(h.provider.restore_count,1)
            h.provider.held.set();status=h.settle()
            self.assertTrue(status['sessionLifecycle']['closed']);self.assertEqual(h.provider.restore_count,1)

    def test_py35_ast_original_unchanged_and_nonbudget_functions_exact(self):
        original=(BASE/'runtime/mta_service.py').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),'361fc0b6fdacd982c42dd596e01f0f219189e7326055514dc2951a65a9383c5d')
        old=ast.parse(original,feature_version=(3,5));new=ast.parse(PATH.read_bytes(),feature_version=(3,5))
        def functions(tree):
            result={}
            for node in tree.body:
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):result[node.name]=ast.dump(node,include_attributes=False)
                if isinstance(node,ast.ClassDef):
                    for function in node.body:
                        if isinstance(function,ast.FunctionDef):result[node.name+'.'+function.name]=ast.dump(function,include_attributes=False)
            return result
        old_functions,new_functions=functions(old),functions(new)
        changed={'Operation.__init__','State.__init__','State._restore_send_owner'}
        self.assertEqual({name for name,value in old_functions.items() if new_functions[name]!=value},changed)
        self.assertIs(service.SendWorker,worker.SendWorker)


if __name__=='__main__':unittest.main()
