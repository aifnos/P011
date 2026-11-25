"""HOST real threads + explicit fake owners; no sockets, RF, device or State."""
import ast
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import mta_transfer_session as module
from mta_transfer_session import TransferSession,Outcome,SessionError


class FakeTransport:
    def __init__(self):
        self.raws=[];self.close_calls=[];self.close_result=True;self.closed_result=True
        self.lifecycle={'closing':True,'socket_records':0,'sockets_pending':0,'actors_pending':0,'threads_pending':0,
            'wrappers_pending':0,'unknown_wrappers':0,'unknown_resources':0,'processes_pending':0,
            'close_verified':True,'cleanup_pending':False}
        self.proof=dict(self.lifecycle,recognized_raw=True,all_sockets_closed=True,all_actors_exited=True)
        self.hook=None;self.close_error=False
    def close(self,timeout):
        self.close_calls.append((threading.current_thread(),timeout))
        if self.hook:self.hook(timeout)
        if self.close_error:raise OSError('HOST_PRIVATE_CLOSE')
        return self.close_result
    def closed(self):return self.closed_result
    def lifecycle_status(self):
        value=dict(self.lifecycle)
        if type(value.get('socket_records')) is int and value['socket_records']==0:value['socket_records']=len(self.raws)
        return value
    def closure_snapshot(self,raw):
        value=dict(self.proof)
        if type(value.get('socket_records')) is int and value['socket_records']==0:value['socket_records']=len(self.raws)
        if not any(item is raw for item in self.raws):value['recognized_raw']=False
        return value


class SessionTests(unittest.TestCase):
    def setUp(self):self.sessions=[];self.events=[];self.outside=[];self.calls=[]
    def event(self):
        value=threading.Event();self.events.append(value);return value
    def tearDown(self):
        for event in self.events:event.set()
        for session in self.sessions:session.cancel()
        for thread in self.outside:
            thread.join(2);self.assertFalse(thread.is_alive(),'HOST outside fixture thread leaked')
        for session in self.sessions:
            if session._worker.ident is not None:session._worker.join(2)
            for row in session._attempts:
                if row['thread'].ident is not None:row['thread'].join(2)
            self.assertFalse(session._worker.is_alive(),'HOST worker leaked')
            self.assertFalse(any(row['thread'].is_alive() for row in session._attempts),'HOST finalizer leaked')

    def session(self,task=None,scoped=False,**options):
        lease=object();owner=object() if scoped else None
        def extra(value):self.assertIs(value,lease);self.calls.append('extra');return True
        def restore(value):self.assertIs(value,lease);self.calls.append('restore');return True
        def release(value,handoffs,snapshots):
            self.assertIs(value,owner);self.assertEqual(len(handoffs),len(snapshots));self.calls.append('release');return True
        if task is None:task=lambda session:Outcome({'PRIVATE':'192.168.49.2 /private/path'},True,True)
        arguments={'task':task,'restore':restore,'lease_owner':lease,'scoped_owner':owner,
            'scoped_release':release if scoped else None,'extra_actor_close':extra,'task_timeout':1,'finalize_timeout':1}
        arguments.update(options);value=TransferSession(**arguments);self.sessions.append(value);return value

    @staticmethod
    def settled(session):
        if session._worker.ident is not None:session._worker.join(2)
        for row in list(session._attempts):
            if row['thread'].ident is not None:row['thread'].join(2)
        return session.status()

    def attach_task(self,transport,raw=None,result=None):
        def task(session):
            session.attach_transport(transport)
            if raw is not None:transport.raws.append(raw);session.register_handoff(transport,raw)
            return result if result is not None else Outcome({'PRIVATE':'HOST'},True,True)
        return task

    def test_exact_worker_finalizer_owners_are_registered_before_start_and_retained(self):
        value=self.session();worker=value._worker;finalizer=value._attempts[0]['thread'];lease=value._lease_owner
        self.assertIsNone(worker.ident);self.assertIsNone(finalizer.ident);self.assertFalse(value.closed())
        value.start();status=self.settled(value)
        self.assertTrue(status['closed']);self.assertEqual(status['phase'],'completed')
        self.assertIs(value._worker,worker);self.assertIs(value._attempts[0]['thread'],finalizer)
        self.assertIs(value._lease_owner,lease);self.assertEqual(self.calls,['extra','restore'])

    def test_transport_full_close_and_raw_proofs_precede_scoped_extra_restore(self):
        transport=FakeTransport();raw=object()
        value=self.session(self.attach_task(transport,raw),scoped=True);value.start();status=self.settled(value)
        self.assertEqual(self.calls,['release','extra','restore']);self.assertTrue(status['closed'])
        self.assertEqual([row[0] for row in transport.close_calls],[value._worker,value._attempts[0]['thread']])
        self.assertEqual(transport.close_calls[0][1],0);self.assertIs(value._handoffs[0][1],raw)

    def test_worker_result_is_not_exit_and_no_restore_while_worker_finally_is_alive(self):
        transport=FakeTransport();entered=self.event();finish=self.event()
        def hook(timeout):
            if threading.current_thread().name=='mta-transfer-worker':entered.set();finish.wait(2)
        transport.hook=hook;value=self.session(self.attach_task(transport));value.start()
        self.assertTrue(entered.wait(1));status=value.status()
        self.assertTrue(status['local_commit_verified']);self.assertTrue(status['worker_alive'])
        self.assertFalse(status['closed']);self.assertEqual(self.calls,[])
        finish.set();self.assertTrue(self.settled(value)['closed'])

    def test_finalizer_done_stages_are_not_closed_while_actual_finalizer_is_alive(self):
        entered=self.event();finish=self.event();original=TransferSession._finalizer_main
        def held(owner,row):original(owner,row);entered.set();finish.wait(2)
        with mock.patch.object(TransferSession,'_finalizer_main',held):value=self.session()
        value.start();self.assertTrue(entered.wait(1))
        self.assertTrue(value.status()['restore_verified']);self.assertFalse(value.closed())
        self.assertEqual(value.status()['finalizers_alive'],1)
        finish.set();self.assertTrue(self.settled(value)['closed'])

    def test_normal_cancellation_uses_same_finalizer_and_preserves_real_outcome(self):
        entered=self.event()
        def task(owner):entered.set();owner.cancelled.wait(2);return Outcome({'PRIVATE':'commit'},True,False)
        value=self.session(task);value.start();self.assertTrue(entered.wait(1))
        self.assertTrue(value.close(1));self.assertEqual(len(value._attempts),1)
        status=value.status();self.assertEqual(status['phase'],'saved_unconfirmed')
        self.assertTrue(status['local_commit_verified']);self.assertFalse(status['peer_ack_verified'])

    def test_cancelled_exception_does_not_forge_transfer_success(self):
        entered=self.event()
        def task(owner):entered.set();owner.cancelled.wait(2);raise RuntimeError('HOST_PRIVATE_CANCEL')
        value=self.session(task);value.start();self.assertTrue(entered.wait(1));self.assertTrue(value.close(1))
        self.assertEqual(value.status()['phase'],'cancelled');self.assertFalse(value.status()['result_available'])

    def test_task_timeout_only_cancels_blocked_worker_and_explicit_close_rechecks(self):
        entered=self.event();finish=self.event()
        def task(owner):entered.set();finish.wait(2);return Outcome({'PRIVATE':'late'},True,True)
        # Give the real HOST scheduler room to resolve Thread.start before the
        # task budget expires; the timeout still must not kill this held task.
        value=self.session(task,task_timeout=.15,finalize_timeout=.03);value.start()
        self.assertTrue(entered.wait(1));value._attempts[0]['thread'].join(1)
        self.assertFalse(value.closed());self.assertTrue(value.status()['worker_alive'])
        self.assertTrue(value.cancelled.is_set());self.assertEqual(self.calls,[])
        finish.set();value._worker.join(1)
        self.assertFalse(value.status()['closed']);self.assertEqual(self.calls,[]) # No automatic retry.
        self.assertTrue(value.close(1));self.assertEqual(len(value._attempts),2)
        self.assertTrue(all(not row['thread'].is_alive() for row in value._attempts))

    def test_zero_task_timeout_does_not_call_task_or_fake_alive_thread_dead(self):
        called=[];value=self.session(lambda owner:called.append(True),task_timeout=0)
        value.start();status=self.settled(value)
        self.assertEqual(called,[]);self.assertTrue(status['closed']);self.assertEqual(status['phase'],'cancelled')

    def test_transport_failure_keeps_all_owners_and_commit_ack_without_restore(self):
        transport=FakeTransport();transport.close_result=False
        value=self.session(self.attach_task(transport));value.start();status=self.settled(value)
        self.assertFalse(status['closed']);self.assertTrue(status['local_commit_verified']);self.assertTrue(status['peer_ack_verified'])
        self.assertEqual(self.calls,[]);self.assertIs(value._transports[0],transport)
        transport.close_result=True;self.assertTrue(value.close(1));self.assertEqual(self.calls,['extra','restore'])

    def test_one_transport_close_error_does_not_skip_other_owned_transports(self):
        first=FakeTransport();first.close_error=True;second=FakeTransport()
        def task(owner):owner.attach_transport(first);owner.attach_transport(second);return Outcome({},True,True)
        value=self.session(task);value.start();self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(len(second.close_calls),2);self.assertEqual(self.calls,[])
        first.close_error=False;self.assertTrue(value.close(1))

    def test_strict_transport_close_closed_and_full_lifecycle_fields(self):
        cases=[('close_result',1),('closed_result',1),('close_result',False),('closed_result',False)]
        for name,invalid in cases:
            with self.subTest(name=name,invalid=invalid):
                transport=FakeTransport();setattr(transport,name,invalid)
                value=self.session(self.attach_task(transport));value.start();self.assertFalse(self.settled(value)['closed'])
        for field in ('close_verified','cleanup_pending'):
            for invalid in (None,1,'HOST',False if field=='close_verified' else True):
                with self.subTest(field=field,invalid=invalid):
                    transport=FakeTransport();transport.lifecycle[field]=invalid
                    value=self.session(self.attach_task(transport));value.start();self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[])

    def test_each_exact_handoff_proof_field_is_strict_and_missing_is_pending(self):
        for field in ('recognized_raw','all_sockets_closed','all_actors_exited','close_verified','cleanup_pending'):
            for invalid in (None,1,'HOST',False if field!='cleanup_pending' else True,'MISSING'):
                with self.subTest(field=field,invalid=invalid):
                    transport=FakeTransport();raw=object()
                    if invalid=='MISSING':transport.proof.pop(field)
                    else:transport.proof[field]=invalid
                    value=self.session(self.attach_task(transport,raw),scoped=True);value.start()
                    self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[])

    def test_all_lifecycle_pending_counters_require_present_exact_integer_zero(self):
        for target in ('lifecycle','proof'):
            for field in module._PENDING_FIELDS:
                for invalid in (None,True,False,-1,1,0.0,'0','MISSING'):
                    with self.subTest(target=target,field=field,invalid=invalid):
                        transport=FakeTransport();raw=object() if target=='proof' else None
                        fields=getattr(transport,target)
                        if invalid=='MISSING':fields.pop(field)
                        else:fields[field]=invalid
                        value=self.session(self.attach_task(transport,raw),scoped=target=='proof');value.start()
                        self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[])

    def test_lifecycle_and_raw_proof_require_closing_and_exact_record_count(self):
        for target in ('lifecycle','proof'):
            for field in ('closing','socket_records'):
                invalids=(None,1,False,'MISSING') if field=='closing' else (None,True,False,-1,0.0,'1','MISSING')
                for invalid in invalids:
                    with self.subTest(target=target,field=field,invalid=invalid):
                        transport=FakeTransport();raw=object()
                        fields=getattr(transport,target)
                        if invalid=='MISSING':fields.pop(field)
                        else:fields[field]=invalid
                        value=self.session(self.attach_task(transport,raw),scoped=True);value.start()
                        self.assertFalse(self.settled(value)['closed'])
        # Each ledger must cover all of this transport's exact handoffs.
        for target in ('lifecycle','proof'):
            with self.subTest(target=target,too_few_records=True):
                transport=FakeTransport();raws=[object(),object()];getattr(transport,target)['socket_records']=1
                def task(owner):
                    owner.attach_transport(transport)
                    for raw in raws:transport.raws.append(raw);owner.register_handoff(transport,raw)
                    return Outcome({},True,True)
                value=self.session(task,scoped=True);value.start();self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[])

    def test_foreign_raw_cannot_use_other_object_closure_proof(self):
        transport=FakeTransport();raw=object()
        def task(owner):owner.attach_transport(transport);owner.register_handoff(transport,raw);return Outcome({},True,True)
        value=self.session(task,scoped=True);value.start();self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[])

    def test_scoped_no_handoffs_still_requires_producer_extra_gate(self):
        value=self.session(scoped=True,extra_actor_close=lambda owner:False);value.start()
        status=self.settled(value);self.assertFalse(status['closed']);self.assertEqual(self.calls,['release'])
        self.assertTrue(status['release_verified']);self.assertFalse(status['restore_verified'])

    def test_release_extra_restore_callbacks_are_strict_true_and_exception_safe(self):
        for stage in ('scoped_release','extra_actor_close','restore'):
            for invalid in (False,None,1,'HOST','EXCEPTION'):
                with self.subTest(stage=stage,invalid=invalid):
                    def failed(*args):
                        if invalid=='EXCEPTION':raise OSError('HOST_PRIVATE_CALLBACK')
                        return invalid
                    value=self.session(scoped=True,**{stage:failed});value.start()
                    status=self.settled(value);self.assertFalse(status['closed']);self.assertTrue(status['restore_pending'])
                    self.assertTrue(status['local_commit_verified']);self.assertTrue(status['peer_ack_verified'])

    def test_explicit_retry_retains_refs_and_does_not_repeat_confirmed_stages(self):
        calls=[];allow=[False]
        def restore(owner):calls.append(owner);return allow[0]
        value=self.session(scoped=True,restore=restore);value.start();self.assertFalse(self.settled(value)['closed'])
        first=value._attempts[0]['thread'];self.assertEqual(self.calls,['release','extra'])
        allow[0]=True;self.assertTrue(value.close(1));self.assertEqual(self.calls,['release','extra'])
        self.assertEqual(len(calls),2);self.assertIs(calls[0],calls[1]);self.assertIs(value._attempts[0]['thread'],first)
        self.assertTrue(value.close(1));self.assertEqual(len(calls),2);self.assertEqual(len(value._attempts),2)

    def test_no_parallel_finalizer_or_restore_when_callback_is_blocked(self):
        entered=self.event();finish=self.event();calls=[]
        def restore(owner):calls.append(owner);entered.set();finish.wait(2);return True
        value=self.session(restore=restore);value.start();self.assertTrue(entered.wait(1))
        self.assertFalse(value.close(.01));self.assertFalse(value.close(.01))
        self.assertEqual(value.status()['callbacks_pending'],1);self.assertEqual(len(value._attempts),1);self.assertEqual(len(calls),1)
        finish.set();self.assertTrue(self.settled(value)['closed'])

    def test_callback_over_budget_is_retained_pending_not_hard_killed(self):
        entered=self.event();finish=self.event();calls=[]
        def restore(owner):calls.append(owner);entered.set();finish.wait(2);return True
        value=self.session(restore=restore,finalize_timeout=.02);value.start();self.assertTrue(entered.wait(1))
        time.sleep(.03);self.assertFalse(value.close(.005));self.assertTrue(value.status()['finalizers_alive'])
        finish.set();self.assertFalse(self.settled(value)['closed']);self.assertEqual(value.status()['reason'],'cleanup_deadline')
        value.finalize_timeout=1 # HOST fixture sets a safe recheck budget, not production configuration.
        self.assertTrue(value.close(1));self.assertEqual(len(calls),2)

    def test_explicit_finalizer_attempt_limit_has_no_automatic_retry(self):
        value=self.session(restore=lambda owner:False);value.start();self.settled(value)
        for _ in range(module.MAX_ATTEMPTS-1):self.assertFalse(value.close(1))
        self.assertEqual(len(value._attempts),8);self.assertFalse(value.close(1));self.assertEqual(len(value._attempts),8)
        self.assertEqual(value.status()['reason'],'finalizer_attempt_limit')

    def test_late_transport_registration_changes_generation_and_blocks_restore(self):
        first=FakeTransport();late=FakeTransport();entered=self.event();finish=self.event()
        def held(timeout):
            if threading.current_thread().name=='mta-transfer-finalizer':entered.set();finish.wait(2)
        first.hook=held;value=self.session(self.attach_task(first));value.start();self.assertTrue(entered.wait(1))
        value.attach_transport(late);finish.set();self.assertFalse(self.settled(value)['closed'])
        self.assertEqual(self.calls,[]);self.assertIs(value._transports[1],late)
        self.assertTrue(value.close(1));self.assertTrue(late.close_calls)

    def test_late_registration_after_release_is_retained_unknown_not_recovered_silently(self):
        entered=self.event();finish=self.event();late=FakeTransport()
        def extra(owner):entered.set();finish.wait(2);return True
        value=self.session(scoped=True,extra_actor_close=extra);value.start();self.assertTrue(entered.wait(1))
        with self.assertRaises(SessionError):value.attach_transport(late)
        finish.set();self.assertFalse(self.settled(value)['closed']);self.assertEqual(self.calls,['release'])
        self.assertIs(value._transports[0],late);self.assertTrue(value.status()['unknown_owner_count'])
        self.assertFalse(value.close(1));self.assertEqual(self.calls,['release'])

    def test_duplicate_transport_and_handoff_or_missing_owner_keep_unknown_refs(self):
        for mode in ('transport','handoff','owner','mismatch'):
            with self.subTest(mode=mode):
                transport=FakeTransport();raw=object()
                def task(owner):
                    owner.attach_transport(transport)
                    if mode=='transport':owner.attach_transport(transport)
                    elif mode=='mismatch':owner.register_handoff(FakeTransport(),raw)
                    else:
                        owner.register_handoff(transport,raw)
                        if mode=='handoff':owner.register_handoff(transport,raw)
                    return Outcome({},True,True)
                value=self.session(task,scoped=mode!='owner');value.start();status=self.settled(value)
                self.assertFalse(status['closed']);self.assertTrue(status['unknown_owner_count']);self.assertTrue(value._unknown)
        self.assertEqual(self.calls,[])

    def test_malformed_transport_is_not_dropped_or_claimed_closed(self):
        resource=object()
        value=self.session(lambda owner:owner.attach_transport(resource));value.start();status=self.settled(value)
        self.assertFalse(status['closed']);self.assertIs(value._unknown[0],resource);self.assertEqual(self.calls,[])

    def test_unknown_quarantine_deduplicates_exact_object_but_never_drops_distinct_refs(self):
        resource=object();other=object();value=self.session()
        for item in (resource,resource,other,resource):
            with self.assertRaises(SessionError):value.attach_transport(item)
        self.assertEqual(value.status()['unknown_owner_count'],2)
        self.assertIs(value._unknown[0],resource);self.assertIs(value._unknown[1],other)
        self.assertEqual(value._generation,4);self.assertFalse(value.close(1));self.assertEqual(self.calls,[])

    def test_unknown_quarantine_deduplicates_exact_handoff_pair_not_raw_alone(self):
        transport=FakeTransport();other=FakeTransport();raw=object();value=self.session(scoped=True)
        for owner in (transport,transport,other,transport):
            with self.assertRaises(SessionError):value.register_handoff(owner,raw)
        self.assertEqual(value.status()['unknown_owner_count'],2)
        self.assertIs(value._unknown[0][0],transport);self.assertIs(value._unknown[0][1],raw)
        self.assertIs(value._unknown[1][0],other);self.assertIs(value._unknown[1][1],raw)
        self.assertEqual(value._generation,4);self.assertFalse(value.close(1));self.assertEqual(self.calls,[])

    def test_transport_limit_retains_overflow_reference(self):
        transports=[FakeTransport() for _ in range(9)]
        def task(owner):
            for transport in transports:owner.attach_transport(transport)
            return Outcome({},True,True)
        value=self.session(task);value.start();status=self.settled(value)
        self.assertFalse(status['closed']);self.assertEqual(status['transport_count'],8)
        self.assertIs(value._unknown[0],transports[-1]);self.assertEqual(self.calls,[])

    def test_handoff_limit_retains_overflow_reference_and_does_not_restore(self):
        transport=FakeTransport();raws=[object() for _ in range(65)]
        def task(owner):
            owner.attach_transport(transport)
            for raw in raws:transport.raws.append(raw);owner.register_handoff(transport,raw)
            return Outcome({},True,True)
        value=self.session(task,scoped=True);value.start();status=self.settled(value)
        self.assertFalse(status['closed']);self.assertEqual(status['handoff_count'],64)
        self.assertIs(value._unknown[0][1],raws[-1]);self.assertEqual(self.calls,[])

    def test_close_before_start_skips_task_but_closes_registered_owners(self):
        task=mock.Mock();value=self.session(task);self.assertTrue(value.close(1));task.assert_not_called()
        self.assertTrue(value.status()['closed']);self.assertEqual(value.status()['phase'],'cancelled')
        with self.assertRaises(SessionError):value.start()

    def test_worker_self_close_does_not_join_finalizer_waiting_for_that_worker(self):
        observed=[]
        def task(owner):
            started=time.monotonic();observed.append(owner.close(1));observed.append(time.monotonic()-started)
            return Outcome({},True,True)
        value=self.session(task);value.start();status=self.settled(value)
        self.assertEqual(observed[0],False);self.assertLess(observed[1],.2);self.assertTrue(status['closed'])

    def test_finalizer_self_close_does_not_join_itself_or_forge_closed(self):
        observed=[];holder=[]
        def restore(owner):observed.append(holder[0].close(1));return True
        value=self.session(restore=restore);holder.append(value);value.start();status=self.settled(value)
        self.assertEqual(observed,[False]);self.assertTrue(status['closed'])

    def test_unresolved_worker_start_actor_cannot_be_misread_as_dead(self):
        entered=self.event();finish=self.event();value=self.session();original=value._worker.start
        def held():entered.set();finish.wait(2);original()
        value._worker.start=held
        thread=threading.Thread(target=value.start);self.outside.append(thread);thread.start();self.assertTrue(entered.wait(1))
        self.assertTrue(value.status()['worker_start_pending']);self.assertFalse(value.close(.01))
        self.assertEqual(self.calls,[]);finish.set();thread.join(1);self.assertTrue(self.settled(value)['closed'])

    def test_worker_start_failure_retains_unknown_identity_even_if_looks_unstarted(self):
        task=mock.Mock();value=self.session(task);worker=value._worker
        value._worker.start=mock.Mock(side_effect=OSError('HOST_PRIVATE_START_FAILED'))
        value.start();status=self.settled(value)
        self.assertIs(value._worker,worker);self.assertFalse(status['closed']);self.assertTrue(status['task_failed'])
        self.assertTrue(status['worker_start_unknown']);task.assert_not_called();self.assertEqual(self.calls,[])
        self.assertFalse(value.close(.1));self.assertEqual(self.calls,[])

    def test_finalizer_start_failure_stays_unknown_without_parallel_attempt(self):
        value=self.session();failed=value._attempts[0]['thread']
        failed.start=mock.Mock(side_effect=OSError('HOST_PRIVATE_FINALIZER_FAILED'))
        value.start();value._worker.join(1)
        self.assertFalse(value.closed());self.assertEqual(self.calls,[]);self.assertEqual(len(value._attempts),1)
        self.assertFalse(value.close(1));self.assertIs(value._attempts[0]['thread'],failed)
        self.assertEqual(len(value._attempts),1);self.assertEqual(self.calls,[])
        self.assertEqual(value.status()['finalizer_starts_unknown'],1)

    def test_worker_start_created_real_thread_then_interrupt_keeps_unknown_after_exit(self):
        task=mock.Mock();value=self.session(task);worker=value._worker;original=worker.start
        observed=[]
        def interrupted():
            original();observed.append(worker.is_alive());raise KeyboardInterrupt('HOST_PRIVATE_START_INTERRUPT')
        worker.start=interrupted;value.start();status=self.settled(value)
        self.assertEqual(observed,[True]);self.assertIs(value._worker,worker);self.assertIsNotNone(worker.ident)
        self.assertFalse(status['worker_alive']);self.assertTrue(status['worker_start_unknown'])
        self.assertFalse(status['closed']);task.assert_not_called();self.assertEqual(self.calls,[])
        self.assertFalse(value.close(.1));self.assertEqual(self.calls,[])

    def test_finalizer_start_created_real_thread_then_interrupt_cannot_restore_or_retry(self):
        value=self.session();thread=value._attempts[0]['thread'];original=thread.start;observed=[]
        def interrupted():
            original();observed.append(thread.is_alive());raise KeyboardInterrupt('HOST_PRIVATE_START_INTERRUPT')
        thread.start=interrupted;value.start();status=self.settled(value)
        self.assertEqual(observed,[True]);self.assertIsNotNone(thread.ident);self.assertFalse(thread.is_alive())
        self.assertFalse(status['closed']);self.assertEqual(status['finalizer_starts_unknown'],1)
        self.assertFalse(value.close(.1));self.assertEqual(len(value._attempts),1);self.assertEqual(self.calls,[])

    def test_created_worker_start_call_still_pending_blocks_task_and_restoration(self):
        entered=self.event();finish=self.event();task=mock.Mock();value=self.session(task);original=value._worker.start
        def held():original();entered.set();finish.wait(2)
        value._worker.start=held;starter=threading.Thread(target=value.start);self.outside.append(starter);starter.start()
        self.assertTrue(entered.wait(1));self.assertTrue(value._worker.is_alive())
        self.assertTrue(value.status()['worker_start_pending']);task.assert_not_called()
        self.assertFalse(value.close(.01));self.assertEqual(self.calls,[])
        finish.set();starter.join(1);self.assertTrue(self.settled(value)['closed']);task.assert_not_called()

    def test_created_finalizer_start_call_still_pending_blocks_cleanup_and_restore(self):
        entered=self.event();finish=self.event();value=self.session();thread=value._attempts[0]['thread'];original=thread.start
        def held():original();entered.set();finish.wait(2)
        thread.start=held;starter=threading.Thread(target=value.start);self.outside.append(starter);starter.start()
        self.assertTrue(entered.wait(1));self.assertTrue(thread.is_alive())
        self.assertEqual(value.status()['finalizer_starts_pending'],1);self.assertEqual(self.calls,[])
        self.assertFalse(value.close(.01));self.assertEqual(len(value._attempts),1);self.assertEqual(self.calls,[])
        finish.set();starter.join(1);self.assertTrue(self.settled(value)['closed'])

    def test_unresolved_finalizer_start_actor_and_concurrent_close_do_not_start_second_attempt(self):
        entered=self.event();finish=self.event();value=self.session();thread=value._attempts[0]['thread'];original=thread.start
        def held():entered.set();finish.wait(2);original()
        thread.start=held;starter=threading.Thread(target=value.start);self.outside.append(starter);starter.start()
        self.assertTrue(entered.wait(1));self.assertEqual(value.status()['finalizer_starts_pending'],1)
        self.assertFalse(value.close(.01));self.assertEqual(len(value._attempts),1)
        finish.set();starter.join(1);self.assertTrue(self.settled(value)['closed'])

    def test_close_wait_does_not_hold_session_lock_or_block_status(self):
        entered=self.event();finish=self.event()
        def task(owner):entered.set();finish.wait(2);return Outcome({},True,True)
        value=self.session(task);value.start();self.assertTrue(entered.wait(1));observed=[]
        closer=threading.Thread(target=lambda:observed.append(value.close(.1)));self.outside.append(closer);closer.start()
        started=time.monotonic();self.assertTrue(value.status()['worker_alive']);self.assertLess(time.monotonic()-started,.05)
        finish.set();closer.join(1);self.settled(value)

    def test_external_cancel_event_shortens_wait_without_claiming_blocked_worker_dead(self):
        entered=self.event();finish=self.event();cancel=self.event()
        def task(owner):entered.set();finish.wait(2);return Outcome({},True,False)
        value=self.session(task,cancelled=cancel,task_timeout=1,finalize_timeout=.02);value.start()
        self.assertTrue(entered.wait(1));cancel.set();value._attempts[0]['thread'].join(1)
        self.assertFalse(value.closed());self.assertTrue(value.status()['worker_alive']);self.assertEqual(self.calls,[])
        finish.set();value._worker.join(1);self.assertTrue(value.close(1))

    def test_maximum_admitted_transports_and_handoffs_have_exact_release_records(self):
        transports=[FakeTransport() for _ in range(8)];raws=[object() for _ in range(64)]
        def task(owner):
            for transport in transports:owner.attach_transport(transport)
            for index,raw in enumerate(raws):
                transport=transports[index%8];transport.raws.append(raw);owner.register_handoff(transport,raw)
            return Outcome({},True,True)
        value=self.session(task,scoped=True);value.start();status=self.settled(value)
        self.assertTrue(status['closed']);self.assertEqual((status['transport_count'],status['handoff_count']),(8,64))
        self.assertEqual(self.calls,['release','extra','restore'])

    def test_public_status_is_passive_fixed_counts_and_contains_no_private_result_or_error(self):
        calls=[]
        def failed(owner):raise RuntimeError('/private/HOST 192.168.49.2 SECRET')
        value=self.session(failed,restore=lambda owner:calls.append(owner) or True);value.start();self.settled(value)
        before=len(calls)
        for _ in range(4):
            status=value.status();self.assertNotIn('SECRET',repr(status));self.assertNotIn('/private',repr(status))
            self.assertNotIn('192.168',repr(status));self.assertTrue(all(type(item) in (str,int,bool) for item in status.values()))
        self.assertEqual(len(calls),before);self.assertEqual(status['phase'],'failed')

    def test_invalid_outcome_flags_do_not_publish_local_commit_or_ack(self):
        value=self.session(lambda owner:Outcome({'PRIVATE':'do not publish'},1,True));value.start();status=self.settled(value)
        self.assertTrue(status['closed']);self.assertFalse(status['local_commit_verified']);self.assertFalse(status['peer_ack_verified'])
        self.assertEqual(status['phase'],'failed');self.assertIsNotNone(value._invalid_result)

    def test_constructor_and_wait_budgets_are_finite_non_bool_and_callbacks_are_internal(self):
        class IntSubclass(int):pass
        class FloatSubclass(float):pass
        for invalid in (True,-1,301,10**1000,float('inf'),float('nan'),'1',IntSubclass(1),FloatSubclass(1)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SessionError):self.session(task_timeout=invalid)
        value=self.session()
        for invalid in (True,-1,31,10**1000,float('inf'),float('nan'),'1',IntSubclass(1),FloatSubclass(1)):
            with self.assertRaises(SessionError):value.close(invalid)
        for invalid in (True,-1,121,10**1000,float('inf'),float('nan'),'1',IntSubclass(1),FloatSubclass(1)):
            with self.assertRaises(SessionError):self.session(finalize_timeout=invalid)
        for options in ({'extra_actor_close':None},{'lease_owner':None},{'task':'shell'},
                        {'scoped_owner':object(),'scoped_release':None},{'cancelled':lambda:False}):
            with self.assertRaises(SessionError):self.session(**options)

    def test_source_parses_python35_and_imports_no_network_state_or_scoped_modules(self):
        source=Path(module.__file__).read_text(encoding='utf-8');tree=ast.parse(source,feature_version=(3,5))
        names=[row.names[0].name for row in tree.body if isinstance(row,ast.Import)]
        self.assertEqual(names,['math','threading','time'])
        self.assertNotIn('mta_service',source);self.assertNotIn('import socket',source)
        self.assertNotIn('subprocess',source);self.assertNotIn('killall',source)


if __name__=='__main__':unittest.main()
