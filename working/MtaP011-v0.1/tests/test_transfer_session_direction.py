"""HOST real Python threads + fake owners; no OS/network/RF/phone proof."""
import ast
from collections import namedtuple
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock

BASE=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
import mta_transfer_session as module
from mta_transfer_session import TransferSession,Outcome,SendOutcome,SessionError
from test_transfer_session import FakeTransport

RECEIVE_FIELDS=frozenset(('phase','reason','closed','cancel_requested',
    'local_commit_verified','peer_ack_verified','result_available','task_failed',
    'worker_alive','worker_start_pending','worker_start_unknown','finalizers_alive',
    'finalizer_starts_pending','finalizer_starts_unknown','finalizer_attempts',
    'callbacks_pending','transport_count','handoff_count','unknown_owner_count',
    'transports_verified','release_verified','extra_actors_verified','restore_verified','restore_pending'))


class DirectionTests(unittest.TestCase):
    def setUp(self):
        self.sessions=[];self.events=[];self.calls=[]
        for target in ('socket.socket','subprocess.Popen','subprocess.run'):
            blocker=mock.patch(target,side_effect=AssertionError('actual OS/network forbidden'))
            blocker.start();self.addCleanup(blocker.stop)
        for name in ('open','kill','waitpid','mkdir','unlink','rename','replace'):
            if hasattr(os,name):
                blocker=mock.patch.object(os,name,side_effect=AssertionError('actual filesystem/process forbidden'))
                blocker.start();self.addCleanup(blocker.stop)

    def tearDown(self):
        for event in self.events:event.set()
        for value in self.sessions:value.cancel()
        for value in self.sessions:
            if value._worker.ident is not None:value._worker.join(2)
            for row in value._attempts:
                if row['thread'].ident is not None:row['thread'].join(2)
            self.assertFalse(value._worker.is_alive(),'HOST worker leaked')
            self.assertFalse(any(row['thread'].is_alive() for row in value._attempts),'HOST finalizer leaked')

    def event(self):
        value=threading.Event();self.events.append(value);return value

    def make(self,task=None,direction='send',scoped=False,**options):
        lease=object();scope=object() if scoped else None
        def extra(owner):
            self.assertIs(owner,lease);self.calls.append('extra');return True
        def restore(owner):
            self.assertIs(owner,lease);self.calls.append('restore');return True
        def release(owner,handoffs,snapshots):
            self.assertIs(owner,scope);self.assertEqual(len(handoffs),len(snapshots))
            self.calls.append('release');return True
        arguments={'task':task or (lambda owner:SendOutcome({'PRIVATE':'secret /private/path'},True,True)),
            'restore':restore,'lease_owner':lease,'extra_actor_close':extra,
            'scoped_owner':scope,'scoped_release':release if scoped else None,
            'task_timeout':2,'finalize_timeout':1,'direction':direction}
        arguments.update(options)
        value=TransferSession(**arguments);self.sessions.append(value);return value

    def settled(self,value):
        if value._worker.ident is not None:value._worker.join(2)
        for row in list(value._attempts):
            if row['thread'].ident is not None:row['thread'].join(2)
        return value.status()

    def check_send(self,status):
        self.assertEqual(status['direction'],'send')
        self.assertIs(status['local_commit_verified'],False)
        self.assertIs(type(status['local_bytes_verified']),bool)
        self.assertNotIn('saved',status['phase']);self.assertNotIn('received',status['phase'])

    def test_constructor_direction_exact_internal_enum_and_no_start(self):
        class StrSubclass(str):pass
        for direction in (None,True,1,[],{},'SEND','both','',StrSubclass('send')):
            with mock.patch.object(threading,'Thread',side_effect=AssertionError('invalid direction must precede actor construction')):
                with self.assertRaisesRegex(SessionError,'invalid_direction'):self.make(direction=direction)
        with mock.patch.object(threading.Thread,'start',side_effect=AssertionError('constructor cannot start')):
            value=self.make()
        self.assertIsNone(value._worker.ident);self.assertIsNone(value._attempts[0]['thread'].ident)
        self.assertEqual(self.calls,[])

    def test_default_receive_api_keyset_and_completion_are_unchanged(self):
        fields=('payload','local_commit_verified','peer_ack_verified')
        self.assertEqual(Outcome._fields,fields)
        value=TransferSession(lambda owner:Outcome(None,True,True),lambda owner:True,
            object(),extra_actor_close=lambda owner:True,task_timeout=2,finalize_timeout=1)
        self.sessions.append(value);value.start();status=self.settled(value)
        self.assertEqual(frozenset(status),RECEIVE_FIELDS)
        self.assertTrue(status['closed']);self.assertEqual(status['phase'],'completed')
        self.assertIs(status['local_commit_verified'],True);self.assertIs(status['peer_ack_verified'],True)

    def test_explicit_receive_keeps_saved_unconfirmed_and_no_send_fields(self):
        value=self.make(lambda owner:Outcome({},True,False),direction='receive')
        value.start();status=self.settled(value)
        self.assertEqual(status['phase'],'saved_unconfirmed');self.assertEqual(frozenset(status),RECEIVE_FIELDS)
        self.assertNotIn('local_bytes_verified',status);self.assertNotIn('direction',status)

    def test_send_complete_only_after_all_closed_with_zero_local_commit(self):
        payload=object();result=SendOutcome(payload,True,True)
        value=self.make(lambda owner:result);value.start();status=self.settled(value)
        self.check_send(status);self.assertTrue(status['closed']);self.assertEqual(status['phase'],'completed')
        self.assertTrue(status['local_bytes_verified']);self.assertTrue(status['peer_ack_verified'])
        self.assertTrue(status['restore_verified']);self.assertFalse(status['restore_pending'])
        self.assertIs(value._outcome,result);self.assertIs(value._outcome.payload,payload)
        self.assertEqual(set(status),set(RECEIVE_FIELDS)|{'direction','local_bytes_verified'})

    def test_actual_bytes_without_peer_ack_are_sent_unconfirmed_not_saved(self):
        value=self.make(lambda owner:SendOutcome({},True,False));value.start();status=self.settled(value)
        self.check_send(status);self.assertTrue(status['closed']);self.assertEqual(status['phase'],'sent_unconfirmed')
        self.assertTrue(status['local_bytes_verified']);self.assertFalse(status['peer_ack_verified'])

    def test_peer_ack_without_verified_bytes_never_completes(self):
        for ack in (True,False):
            with self.subTest(ack=ack):
                value=self.make(lambda owner:SendOutcome({},False,ack));value.start();status=self.settled(value)
                self.check_send(status);self.assertFalse(status['local_bytes_verified'])
                self.assertNotIn(status['phase'],('completed','sent_unconfirmed'))

    def test_wrong_result_type_is_retained_and_not_reinterpreted_as_direction(self):
        class SendSubclass(SendOutcome):pass
        Other=namedtuple('Other','payload local_bytes_verified peer_ack_verified')
        cases=((Outcome({},True,True),'send'),(SendOutcome({},True,True),'receive'),
            (SendSubclass({},True,True),'send'),(Other({},True,True),'send'),
            ({'payload':None,'local_bytes_verified':True,'peer_ack_verified':True},'send'))
        for result,direction in cases:
            with self.subTest(direction=direction,result_type=type(result).__name__):
                value=self.make(lambda owner:result,direction=direction);value.start();status=self.settled(value)
                self.assertEqual(status['phase'],'failed');self.assertIs(value._invalid_result,result)
                self.assertFalse(status['result_available']);self.assertFalse(status['peer_ack_verified'])
                self.assertFalse(status['local_commit_verified'])
                if direction=='send':self.assertFalse(status['local_bytes_verified'])

    def test_send_flags_require_exact_bools_and_invalid_private_values_never_publish(self):
        for flag in (0,1,None,'true',0.0,1.0,object()):
            for field in ('local_bytes_verified','peer_ack_verified'):
                with self.subTest(field=field,flag_type=type(flag).__name__):
                    result=SendOutcome({},flag if field=='local_bytes_verified' else True,
                        flag if field=='peer_ack_verified' else True)
                    value=self.make(lambda owner:result);value.start();status=self.settled(value)
                    self.check_send(status);self.assertEqual(status['phase'],'failed')
                    self.assertFalse(status['local_bytes_verified']);self.assertFalse(status['peer_ack_verified'])
                    self.assertIs(value._invalid_result,result)

    def test_failed_send_task_keeps_safe_failure_no_result_or_commit(self):
        def failed(owner):raise ValueError('PRIVATE secret /private/path')
        value=self.make(failed);value.start();status=self.settled(value)
        self.check_send(status);self.assertEqual(status['phase'],'failed');self.assertTrue(status['closed'])
        self.assertFalse(status['result_available']);self.assertEqual(self.calls,['extra','restore'])
        self.assertNotIn('PRIVATE',repr(status));self.assertNotIn('secret',repr(status))

    def test_transport_pending_preserves_send_facts_but_cannot_restore_or_complete(self):
        transport=FakeTransport();transport.close_result=False
        def task(owner):owner.attach_transport(transport);return SendOutcome({},True,True)
        value=self.make(task);value.start();status=self.settled(value)
        self.check_send(status);self.assertTrue(status['local_bytes_verified']);self.assertTrue(status['peer_ack_verified'])
        self.assertFalse(status['closed']);self.assertEqual(status['phase'],'pending');self.assertEqual(self.calls,[])
        self.assertIs(value._transports[0],transport)
        transport.close_result=True;self.assertTrue(value.close(1))
        self.assertEqual(value.status()['phase'],'completed');self.assertEqual(self.calls,['extra','restore'])

    def test_release_extra_or_restore_false_stays_pending_without_auto_retry(self):
        for stage,expected_calls in (('release',[]),('extra',['release']),('restore',['release','extra'])):
            with self.subTest(stage=stage):
                self.calls=[]
                options={'scoped_release' if stage=='release' else 'extra_actor_close' if stage=='extra' else 'restore':lambda *args:False}
                value=self.make(scoped=True,**options);value.start();status=self.settled(value)
                self.check_send(status);self.assertEqual(status['phase'],'pending');self.assertFalse(status['closed'])
                self.assertTrue(status['restore_pending']);self.assertEqual(self.calls,expected_calls)
                attempts=len(value._attempts)
                for _ in range(3):value.status()
                self.assertEqual(attempts,len(value._attempts));self.assertEqual(self.calls,expected_calls)

    def test_returned_send_result_is_not_actual_worker_exit(self):
        transport=FakeTransport();entered=self.event();finish=self.event()
        def held_close(timeout):
            if threading.current_thread().name=='mta-transfer-worker':entered.set();finish.wait(2)
        transport.hook=held_close
        def task(owner):owner.attach_transport(transport);return SendOutcome({},True,True)
        value=self.make(task);value.start();self.assertTrue(entered.wait(1));status=value.status()
        self.check_send(status);self.assertTrue(status['worker_alive']);self.assertFalse(status['closed'])
        self.assertTrue(status['local_bytes_verified']);self.assertNotEqual(status['phase'],'completed')
        self.assertEqual(self.calls,[]);finish.set();self.assertEqual(self.settled(value)['phase'],'completed')

    def test_returned_finalizer_stages_still_need_actual_finalizer_exit(self):
        entered=self.event();finish=self.event();original=TransferSession._finalizer_main
        def held(owner,row):original(owner,row);entered.set();finish.wait(2)
        with mock.patch.object(TransferSession,'_finalizer_main',held):value=self.make()
        value.start();self.assertTrue(entered.wait(1));status=value.status()
        self.check_send(status);self.assertTrue(status['restore_verified']);self.assertFalse(status['closed'])
        self.assertEqual(status['finalizers_alive'],1);self.assertNotEqual(status['phase'],'completed')
        finish.set();self.assertEqual(self.settled(value)['phase'],'completed')

    def test_send_handoff_close_proof_does_not_get_direction_bypass(self):
        transport=FakeTransport();raw=object();transport.proof['all_actors_exited']=False
        def task(owner):
            owner.attach_transport(transport);transport.raws.append(raw);owner.register_handoff(transport,raw)
            return SendOutcome({},True,True)
        value=self.make(task,scoped=True);value.start();status=self.settled(value)
        self.check_send(status);self.assertFalse(status['closed']);self.assertEqual(self.calls,[])
        self.assertIs(value._handoffs[0][1],raw);self.assertEqual(status['phase'],'pending')

    def test_send_transport_release_extra_restore_order_unchanged_and_external(self):
        transport=FakeTransport();raw=object()
        def task(owner):
            owner.attach_transport(transport);transport.raws.append(raw);owner.register_handoff(transport,raw)
            return SendOutcome({},True,True)
        value=self.make(task,scoped=True);value.start();status=self.settled(value)
        self.check_send(status);self.assertEqual(self.calls,['release','extra','restore'])
        self.assertEqual([row[0] for row in transport.close_calls],[value._worker,value._attempts[0]['thread']])
        self.assertTrue(status['closed']);self.assertEqual(status['phase'],'completed')

    def test_cancelled_send_preserves_verified_bytes_without_forging_ack(self):
        entered=self.event()
        def task(owner):entered.set();owner.cancelled.wait(2);return SendOutcome({},True,False)
        value=self.make(task);value.start();self.assertTrue(entered.wait(1));self.assertTrue(value.close(1))
        status=value.status();self.check_send(status);self.assertEqual(status['phase'],'sent_unconfirmed')
        self.assertTrue(status['cancel_requested']);self.assertFalse(status['peer_ack_verified'])

    def test_send_close_before_start_never_calls_task_or_publishes_result(self):
        task=mock.Mock(side_effect=AssertionError('skipped send cannot run'))
        value=self.make(task);self.assertTrue(value.close(1));task.assert_not_called()
        status=value.status();self.check_send(status);self.assertFalse(status['result_available'])
        self.assertFalse(status['local_bytes_verified']);self.assertEqual(status['phase'],'cancelled')

    def test_late_unknown_owner_remains_pending_despite_send_result(self):
        foreign=object()
        def task(owner):
            try:owner.attach_transport(foreign)
            except SessionError:pass
            return SendOutcome({},True,True)
        value=self.make(task);value.start();status=self.settled(value)
        self.check_send(status);self.assertFalse(status['closed']);self.assertTrue(status['unknown_owner_count'])
        self.assertIs(value._unknown[0],foreign);self.assertEqual(self.calls,[])
        self.assertNotEqual(status['phase'],'completed')

    def test_send_status_is_passive_fixed_fields_and_never_serializes_payload(self):
        value=self.make();value.start();self.settled(value);before=list(self.calls)
        for _ in range(4):
            status=value.status();self.check_send(status)
            self.assertTrue(all(type(item) in (str,int,bool) for item in status.values()))
            self.assertNotIn('secret',repr(status));self.assertNotIn('/private',repr(status))
        self.assertEqual(self.calls,before)

    def test_python35_ast_no_io_import_or_runtime_assert(self):
        source=(BASE/'runtime/mta_transfer_session.py').read_text(encoding='utf-8')
        tree=ast.parse(source,feature_version=(3,5))
        self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        imports=[node.names[0].name for node in tree.body if isinstance(node,ast.Import)]
        self.assertEqual(imports,['math','threading','time'])
        for forbidden in ('import socket','subprocess','mta_service','SendWorker','send_available'):
            self.assertNotIn(forbidden,source)


if __name__=='__main__':unittest.main()
