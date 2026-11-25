"""HOST actual State/ScanSession/SendWorker/TransferSession, fake external IO.

No OS files/process/socket/native crypto/RF. Explicit host_gate is only a test
fixture; constructing a provider does not enable the default platform gate.
"""
import ast
import base64
import pathlib
import sys
import threading
import time
import unittest
from unittest import mock

BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'));sys.path.insert(0,str(BASE/'tests'))
import mta_service as service
import mta_send_worker as worker
import test_send_worker as fixture
import test_service_integration as receive_fixture
from mta_scoped_sockets import OwnedContext,ScopedDataSockets


CAPS={'powered':True,'features':True,'connectable_advert':True,'bredr_enabled':True,
      'le_enabled':True,'global_advertising':False,'max_adv':31,'max_scan':31,
      'bluez_advertising_known':True,'bluez_advertising_active':False,'active_instances':0,
      'receive':False,'ok':True}


class Registry(fixture.FakeRegistry):
    def list_files(self):return []


class Wifi:
    def __init__(self,*unused):self._active_lease=None;self.restores=0
    def status(self):return {'restorePending':False,'recoveryLocked':False,'reason':''}
    def restore_active(self):self.restores+=1;return True


class Helper:
    instances=[]
    ready=True
    cached=False
    started=None
    def __init__(self,path,callback):
        self.callback=callback;self.closed=False;self.calls=[];self.command_note=None
        self.close_count=0;self.threads=[];self.started=threading.Event()
        self.instances.append(self)
    def start(self):self.started.set()
    def send(self,command):
        self.threads.append(threading.current_thread())
        if self.command_note is not None:self.command_note(command)
        self.calls.append(dict(command))
        if command['cmd']=='scan':
            if self.ready:self.callback({'event':'scan','code':'ready'})
            self.callback({'event':'discovered','peer':7,'cached':self.cached,
                           'name_b64':base64.b64encode(b'HOST-FIXTURE').decode('ascii'),'service_data':[]})
        elif command['cmd']=='client_read':
            # Real native sequence stops its own scan before delivering GATT.
            self.callback({'event':'scan','code':'own_session_stopped'})
            wire=service.DeviceInfo('00:AA:BB:CC:DD:EE',base64.b64encode(b'peer-public').decode('ascii')).to_bytes()
            self.callback({'event':'client_status','peer':7,'payload_b64':base64.b64encode(wire).decode('ascii')})
        elif command['cmd']=='client_write':
            self.callback({'event':'client_write','code':'accepted_by_bluez_not_file_transfer_complete'})
    def close(self):
        self.close_count+=1;self.closed=True;self.callback({'event':'closed'});return True
    def closure_verified(self):return self.closed


class Provider(fixture.Provider):
    def __init__(self):
        fixture.Provider.__init__(self,time.monotonic)
        self.state=None;self.restore_mode='good';self.read_mode='good'
        self.restore_receipt=None;self.read_receipt=None;self.restore_threads=[]
        self.reserve_held=None;self.reserve_entered=threading.Event()
    def reserve(self,handoff,deadline,cancelled):
        self.reserve_entered.set()
        if self.reserve_held is not None:self.reserve_held.wait(2)
        return fixture.Provider.reserve(self,handoff,deadline,cancelled)
    def activate(self,lease,handoff,info,deadline,cancelled):
        self.log.append('activate')
        if self.activation_error:raise self.activation_error
        context=OwnedContext('00000000-0000-0000-0000-000000000001',
            handoff.operation_epoch,handoff.native_epoch,0,8,9,'mta12345678','go',
            '192.168.88.1',24,deadline,'a'*64)
        scope=ScopedDataSockets(context,lambda c,p,b:self.scope_proof(c),cancelled.is_set,
            threading.RLock(),clock=time.monotonic,socket_factory=fixture.Raw,
            if_nametoindex=lambda name:9,raw_socket_type=fixture.Raw)
        self.dhcp._deadline=deadline;self.dhcp.expiry=deadline
        self.network=worker.NetworkReceipt(lease,context,scope,self.dhcp,
            'HOST-FIXTURE','host-only-pass','02:00:00:00:00:01')
        return self.network
    def restore_owned(self,lease,epoch,task_id,budget):
        self.log.append('restore');self.restore_count+=1;self.restore_threads.append(threading.current_thread())
        op=self.state.operation
        if (op.session._worker.is_alive() or op.send_worker._run_thread.is_alive() or
            not op.transport.closed() or not op.send_worker.status()['scope_released'] or
            not op.send_worker.status()['extra_resources_closed'] or self.state.lock._is_owned()):
            raise AssertionError('HOST restore ordering')
        receipt=service.SendRestoreReceipt(self,lease,epoch,task_id,True,True,True,True)
        if self.restore_mode=='bool':receipt=True
        elif self.restore_mode=='foreign':receipt=receipt._replace(provider=object())
        elif self.restore_mode=='wrong_lease':receipt=receipt._replace(lease=object())
        elif self.restore_mode=='wrong_epoch':receipt=receipt._replace(operation_epoch=epoch+1)
        elif self.restore_mode=='wrong_task':receipt=receipt._replace(task_id='other-task')
        elif self.restore_mode=='nonbool':receipt=receipt._replace(baseline_verified=1)
        elif self.restore_mode=='pending':receipt=receipt._replace(journal_reconciled=False)
        self.restore_receipt=receipt;return receipt
    def read_restored(self,receipt,budget):
        self.log.append('restore_readback')
        if self.read_mode=='cached':fresh=receipt
        elif self.read_mode=='slow':time.sleep(.21);fresh=receipt._replace()
        elif self.read_mode=='foreign':fresh=receipt._replace(resources_closed=False)
        else:fresh=service.SendRestoreReceipt(*receipt)
        self.read_receipt=fresh;return fresh


class Sender(fixture.FakeSender):
    def __init__(self,*args,**options):
        fixture.FakeSender.__init__(self,*args,**options)
        self.entered=threading.Event();self.held=None;self.missing_ack=False
        self.close_fault=False;self.state=None
    def start(self):
        # Hooks registered the exact transport BEFORE listener creation.
        op=self.state.operation
        if op.transport is not self or not any(value is self for value in op.session._transports):
            raise AssertionError('HOST transport was not attached')
        return fixture.FakeSender.start(self)
    def wait(self):
        self.entered.set()
        if self.held is not None:self.held.wait(2)
        if self.options['cancelled']():raise worker.SendWorkerError('cancelled')
        if self.missing_ack:
            self.options['state_callback']('transferring',{'bytes':100,'archiveSize':100})
            self.options['state_callback']('awaiting_result',{'archiveBytesSent':100})
            raise worker.SendWorkerError('native_timeout')
        return fixture.FakeSender.wait(self)
    def close(self,timeout=2):
        if self.close_fault:return False
        return fixture.FakeSender.close(self,timeout)


class StateSendIntegrationTests(unittest.TestCase):
    def setUp(self):
        Helper.instances=[];Helper.ready=True;Helper.cached=False
        self.registry=Registry();self.provider=Provider();self.crypto=fixture.FakeCrypto()
        self.state=None;self.sender=None;self.holds=[];self.patchers=[]
        self.sender_held=None;self.sender_missing_ack=False;self.sender_close_fault=False
        self.source_closed=[]
        def patch(target,**options):
            value=mock.patch(target,**options);value.start();self.patchers.append(value);self.addCleanup(value.stop)
        patch('mta_service.FileRegistry',return_value=self.registry)
        patch('mta_service.SafeZipReceiver',return_value=object())
        patch('mta_service.WifiBackend',new=Wifi)
        patch('mta_service.PrivateHelper',new=Helper)
        patch('mta_service.capability',side_effect=lambda *a,**kw:dict(CAPS))
        patch('mta_service.os.path.exists',return_value=True)
        patch('mta_service.os.urandom',side_effect=lambda count:b'\x01'*count)
        # Hard tripwires: the combination must never fall through to OS IO.
        patch('mta_service.os.mkdir',side_effect=AssertionError('HOST no mkdir'))
        patch('mta_service.subprocess.Popen',side_effect=AssertionError('HOST no process'))
        patch('mta_send_worker.OpenSslCrypto',side_effect=AssertionError('HOST no native crypto'))
        patch('mta_send_worker.SenderTransport',side_effect=AssertionError('HOST no real sender'))
        patch('mta_scoped_sockets.socket.socket',side_effect=AssertionError('HOST no socket'))
        patch('mta_service.State._make_send_worker',new=lambda state,op:self.make_worker(state,op))
        self.state=service.State('/host-fixture/users','/host-fixture/bluez','/host-fixture/network',send_provider=self.provider)
        self.provider.state=self.state
    def tearDown(self):
        for event in self.holds:event.set()
        if self.state is not None:
            self.state.close()
            for op in [self.state.operation]+self.state.history:
                if op is None:continue
                if op.session._worker.ident is not None:op.session._worker.join(2)
                for row in op.session._attempts:
                    if row['thread'].ident is not None:row['thread'].join(2)
                self.assertFalse(op.session._worker.is_alive())
                self.assertFalse(any(row['thread'].is_alive() for row in op.session._attempts))
        for patcher in reversed(self.patchers):patcher.stop()
    def make_worker(self,state,op):
        return worker.SendWorker(op.send_intent.handoff,state.registry,list(op.send_intent.file_ids),
            provider=op.send_provider,openssl=state.openssl,sender_name=state.nickname,
            cancelled=op.cancelled,timeout=3,crypto_factory=lambda path:self.crypto,transport_factory=self.make_sender)
    def make_sender(self,*args,**options):
        self.sender=Sender(*args,**options);self.sender.state=self.state
        self.sender.held=self.sender_held;self.sender.missing_ack=self.sender_missing_ack
        self.sender.close_fault=self.sender_close_fault;return self.sender
    def hold(self):
        event=threading.Event();self.holds.append(event);return event
    def scan(self,host_gate=True):
        if host_gate:self.state.send_available=True # Explicit HOST-only simulated platform admission.
        self.state.action({'action':'scan'})
        stop=time.monotonic()+1
        while time.monotonic()<stop:
            op=self.state.operation
            if op.helper is not None and any(value['cmd']=='scan' for value in op.helper.calls):return op
            time.sleep(.002)
        self.fail('HOST scan did not start')
    def send(self):
        return self.state.action({'action':'send','deviceId':'7','fileIds':['file-id']})
    def settle(self):
        op=self.state.operation;op.session._worker.join(2)
        for row in tuple(op.session._attempts):row['thread'].join(2)
        self.assertFalse(op.session._worker.is_alive())
        return self.state.status()
    def assert_zero_send_io(self):
        self.assertEqual(self.registry.calls,0);self.assertEqual(self.provider.log,[])
        self.assertEqual([value['cmd'] for value in self.state.operation.helper.calls],['scan'])

    def test_default_provider_never_enables_send_and_rejects_before_io(self):
        op=self.scan(False);self.assertFalse(self.state.status()['capabilities']['send']['available'])
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io();self.assertIsNone(op.send_intent)
    def test_missing_provider_rejected_even_with_host_gate(self):
        self.state._send_provider=None;self.scan()
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io()
    def test_missing_restore_contract_rejected_before_file_and_gatt(self):
        self.provider.read_restored=None;self.scan()
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io()
    def test_scan_not_ready_cannot_claim_intent(self):
        Helper.ready=False;self.scan()
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io();self.assertFalse(self.state.scanning)
    def test_cached_peer_cannot_enable_send(self):
        Helper.cached=True;self.scan()
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io();self.assertEqual(self.state.status()['devices'],[])
    def test_expired_peer_blocks_before_file_or_gatt(self):
        op=self.scan()
        with op.scan._lock:
            op.scan._peers[7]=time.monotonic()-16
        with self.assertRaises(ValueError):self.send()
        self.assert_zero_send_io()
    def test_cancelled_scan_leaves_no_send_facts_and_closes_exact_helper_once(self):
        op=self.scan();self.state.action({'action':'scan_stop'});status=self.settle()
        self.assertTrue(status['sessionLifecycle']['closed']);self.assertEqual(status['state'],'idle')
        self.assertFalse(status['sessionLifecycle']['local_bytes_verified'])
        self.assertEqual(op.helper.close_count,1);self.assertIsNone(op.send_worker)
    def test_send_ready_then_cancel_before_factory_closes_exact_zero_execution_owner(self):
        entered=threading.Event();finish=self.hold();original=Helper.send
        def barrier(helper,command):
            original(helper,command)
            if command['cmd']=='scan':entered.set();finish.wait(2)
        with mock.patch.object(Helper,'send',barrier):
            op=self.scan();self.assertTrue(entered.wait(1));self.send()
            self.assertTrue(op.send_ready.is_set());self.assertIsNotNone(op.send_intent)
            self.assertIsNone(op.send_factory);self.assertIsNone(op._send_skip)
            self.assertFalse(self.state._release_send(op,(),()))
            op.session.finalize_timeout=.03;self.state.action({'action':'cancel'})
            self.assertTrue(op.session._worker.is_alive());self.assertEqual(op.helper.close_count,0)
            finish.set();op.session._worker.join(1)
            self.assertTrue(op.session.close(1));status=self.settle()
        self.assertTrue(self.state._send_skip_exact(op));self.assertIs(op._send_skip.thread,op.session._worker)
        self.assertEqual(op.helper.close_count,1);self.assertEqual(self.registry.calls,0)
        self.assertEqual([value['cmd'] for value in op.helper.calls],['scan'])
        self.assertEqual(self.provider.log,[]);self.assertEqual(self.state.wifi_backend.restores,0)
        self.assertEqual(status['sessionLifecycle']['phase'],'cancelled')
        self.assertTrue(status['sessionLifecycle']['closed']);self.assertFalse(status['restorePending'])
        self.assertFalse(status['sessionLifecycle']['local_bytes_verified']);self.assertNotEqual(status['state'],'completed')
        # The private record cannot authorize a later/unknown factory branch.
        op.send_factory=lambda value:None
        self.assertFalse(self.state._send_skip_exact(op));op.send_factory=None
        op.send_construct_unknown=True
        self.assertFalse(self.state._send_skip_exact(op));op.send_construct_unknown=False
    def test_actual_combination_single_owner_tickets_and_independent_restore_order(self):
        op=self.scan();self.send();status=self.settle()
        self.assertEqual(status['state'],'completed');self.assertTrue(status['sessionLifecycle']['closed'])
        self.assertIs(self.state.session,op.session);self.assertIs(self.state.helper,op.helper)
        self.assertIs(self.state.worker,op.send_worker._run_thread)
        self.assertTrue(all(thread is self.state.worker for thread in op.helper.threads))
        self.assertEqual([value['cmd'] for value in op.helper.calls],['scan','client_read','client_write'])
        records=op.send_worker.private_owner_records()
        self.assertEqual(tuple(op.send_tickets),records)
        self.assertTrue(all(type(row) is worker.CreationTicket and row.claimed and row.resolved for row in records))
        self.assertEqual(op.session.status()['transport_count'],1);self.assertEqual(op.session.status()['handoff_count'],1)
        self.assertEqual(op.helper.close_count,1);self.assertEqual(self.registry.selection.close_count,1)
        self.assertEqual(self.state.wifi_backend.restores,0)
        self.assertLess(self.provider.log.index('close_extra'),self.provider.log.index('restore'))
        self.assertLess(self.provider.log.index('restore'),self.provider.log.index('restore_readback'))
        self.assertIs(op.send_restore_receipt,self.provider.restore_receipt)
        self.assertIs(op.send_restore_readback,self.provider.read_receipt)
        self.assertIsNot(op.send_restore_receipt,op.send_restore_readback)
        self.assertNotEqual(self.provider.restore_threads,[self.state.worker])
    def test_send_results_and_progress_are_not_received_or_local_commit(self):
        self.scan();self.send();status=self.settle()
        self.assertEqual(status['received'],[]);self.assertFalse(status['sessionLifecycle']['local_commit_verified'])
        self.assertTrue(status['sessionLifecycle']['local_bytes_verified'])
        self.assertEqual(status['transfer']['direction'],'send');self.assertEqual(status['transfer']['archiveBytesSent'],100)
        self.assertTrue(status['transfer']['localBytesVerified']);self.assertTrue(status['transfer']['peerCompletionVerified'])
        self.assertNotIn('localCommitVerified',status['transfer']);self.assertNotIn('文件已保存',status['reason'])
    def test_redundant_recover_does_not_reclose_worker_owners_or_use_wifi_backend(self):
        op=self.scan();self.send();self.settle();self.state.action({'action':'recover'})
        self.assertIs(self.state.operation,op);self.assertEqual(op.helper.close_count,1)
        self.assertEqual(self.registry.selection.close_count,1);self.assertEqual(self.state.wifi_backend.restores,0)
    def test_second_intent_cannot_replace_inflight_operation(self):
        self.sender_held=self.hold();op=self.scan();self.send()
        stop=time.monotonic()+1
        while self.sender is None and time.monotonic()<stop:time.sleep(.002)
        self.assertTrue(self.sender.entered.wait(1));intent=op.send_intent
        with self.assertRaises(ValueError):self.send()
        self.assertIs(op.send_intent,intent);self.assertEqual(self.registry.calls,1)
        self.sender_held.set();self.settle()
    def test_stale_epoch_foreign_helper_and_bool_epoch_cannot_update_native_route(self):
        op=self.scan();old_counts=dict(self.state.event_counts)
        event={'event':'error','code':'late-fixture'}
        self.state.native_event(event,op.epoch+1,op.helper)
        self.state.native_event(event,op.epoch,object());self.state.native_event(event,True,op.helper)
        self.assertEqual(self.state.event_counts,old_counts);self.assertFalse(op.cancelled.is_set())
        self.send();self.assertEqual(self.settle()['state'],'completed')
    def test_own_scan_stopped_handoff_keeps_intent_but_not_fake_active(self):
        self.sender_held=self.hold();op=self.scan();self.send()
        stop=time.monotonic()+1
        while self.sender is None and time.monotonic()<stop:time.sleep(.002)
        self.assertTrue(self.sender.entered.wait(1));status=self.state.status()
        self.assertFalse(status['scanning']);self.assertFalse(status['scanLifecycle']['native_scan_active'])
        self.assertTrue(status['scanLifecycle']['intent_valid']);self.assertTrue(status['scanLifecycle']['client_read_noted'])
        self.assertFalse(op.cancelled.is_set());self.sender_held.set();self.settle()
    def test_native_lease_expiry_cancels_without_reader_cleanup_or_restore(self):
        self.sender_held=self.hold();op=self.scan();self.send()
        stop=time.monotonic()+1
        while self.sender is None and time.monotonic()<stop:time.sleep(.002)
        self.assertTrue(self.sender.entered.wait(1))
        op.helper.callback({'event':'scan','code':'lease_expired'})
        self.assertTrue(op.cancelled.is_set());self.assertEqual(op.helper.close_count,0)
        self.assertEqual(self.provider.restore_count,0);self.assertTrue(op.session._worker.is_alive())
        self.sender_held.set();status=self.settle();self.assertTrue(status['sessionLifecycle']['closed'])
    def test_actual_live_worker_blocks_release_extra_and_restore_after_cancel(self):
        self.sender_held=self.hold();op=self.scan();self.send()
        stop=time.monotonic()+1
        while self.sender is None and time.monotonic()<stop:time.sleep(.002)
        self.assertTrue(self.sender.entered.wait(1));op.session.finalize_timeout=.03;op.session.cancel()
        op.session._attempts[0]['thread'].join(1)
        self.assertTrue(op.session._worker.is_alive());self.assertEqual(op.helper.close_count,0)
        self.assertEqual(self.provider.restore_count,0);self.assertFalse(op.session.closed())
        self.sender_held.set();op.session._worker.join(1);self.assertTrue(op.session.close(1))
    def test_bool_foreign_binding_and_unreconciled_restore_receipts_stay_pending(self):
        # Each malformed case uses a fresh independent HOST combination.
        self.provider.restore_mode='nonbool';self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
        self.assertIsNotNone(self.state.operation.send_restore_receipt)
        self.assertEqual(self.state.wifi_backend.restores,0);self.assertFalse(self.state.send_available)
    def test_foreign_provider_receipt_stays_pending(self):
        self.provider.restore_mode='foreign';self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertNotIn('restore_readback',self.provider.log)
    def test_cached_restore_readback_is_not_fresh_evidence(self):
        self.provider.read_mode='cached';self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
    def test_readback_budget_exceeded_does_not_clear_pending(self):
        self.provider.read_mode='slow';self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
    def test_strict_receipt_match_all_private_bindings_without_io(self):
        op=self.scan();self.send();self.settle();receipt=op.send_restore_receipt
        for changes in ({'lease':object()},{'operation_epoch':True},{'operation_epoch':op.epoch+1},
                        {'task_id':'other-task'},{'actors_closed':1},{'resources_closed':False}):
            with self.subTest(changes=list(changes)):
                self.assertFalse(self.state._send_receipt_exact(receipt._replace(**changes),op,op.send_lease))
        self.assertFalse(self.state._send_receipt_exact(True,op,op.send_lease))
    def test_bytes_without_peer_ack_are_sent_unconfirmed_not_saved_or_completed(self):
        self.sender_missing_ack=True;self.scan();self.send();status=self.settle()
        self.assertEqual(status['sessionLifecycle']['phase'],'sent_unconfirmed');self.assertEqual(status['state'],'error')
        self.assertTrue(status['sessionLifecycle']['local_bytes_verified']);self.assertFalse(status['sessionLifecycle']['peer_ack_verified'])
        self.assertEqual(status['received'],[]);self.assertFalse(status['sessionLifecycle']['local_commit_verified'])
    def test_verified_bytes_with_transport_cleanup_pending_are_not_completed(self):
        self.sender_missing_ack=True;self.sender_close_fault=True
        op=self.scan();self.send();status=self.settle()
        self.assertTrue(op.send_bytes_observed);self.assertTrue(status['sessionLifecycle']['local_bytes_verified'])
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
        self.assertEqual(status['state'],'restoring');self.assertEqual(self.provider.restore_count,0)
    def test_unknown_exception_status_cannot_promote_bytes_or_completion(self):
        self.sender_missing_ack=True;unknown=[];original=self.make_worker
        def changed(state,op):
            value=original(state,op);read=value.status
            def status():
                if value._run_returned and value._stage=='failed' and not unknown:
                    unknown.append(True);return {'localBytesVerified':True}
                return read()
            value.status=status;return value
        with mock.patch.object(service.State,'_make_send_worker',new=lambda state,op:changed(state,op)):
            op=self.scan();self.send();status=self.settle()
        self.assertEqual(unknown,[True]);self.assertFalse(op.send_bytes_observed)
        self.assertFalse(status['sessionLifecycle']['local_bytes_verified'])
        self.assertFalse(status['sessionLifecycle']['peer_ack_verified']);self.assertNotEqual(status['state'],'completed')
    def test_known_failure_before_reserve_is_zero_network_restore_not_legacy_restore(self):
        self.crypto.reject=True;op=self.scan();self.send();status=self.settle()
        self.assertTrue(status['sessionLifecycle']['closed']);self.assertEqual(status['sessionLifecycle']['phase'],'failed')
        self.assertIsNone(op.send_lease);self.assertEqual(self.provider.restore_count,0)
        self.assertEqual(self.state.wifi_backend.restores,0);self.assertEqual(op.helper.close_count,1)
    def test_unknown_reserve_is_not_zero_network_branch_and_strong_ticket_retained(self):
        self.provider.reserve=lambda *args:(_ for _ in ()).throw(KeyboardInterrupt('HOST PRIVATE UNKNOWN'))
        op=self.scan();self.send();status=self.settle()
        self.assertIsNone(op.send_worker.lease);self.assertFalse(status['sessionLifecycle']['closed'])
        self.assertTrue(any(row.kind=='lease' and row.unknown for row in op.send_tickets))
        self.assertEqual(self.provider.restore_count,0);self.assertEqual(self.state.wifi_backend.restores,0)
        self.assertTrue(status['restorePending'])
    def test_adopt_failure_retains_lease_resource_before_worker_lease_assignment(self):
        original=service._SendHooks.adopt
        def failed(hooks,ticket):
            original(hooks,ticket)
            if ticket.kind=='lease':raise ValueError('HOST adopt failed')
            return ticket
        with mock.patch.object(service._SendHooks,'adopt',failed):
            op=self.scan();self.send();status=self.settle()
        self.assertIsNone(op.send_worker.lease);self.assertIs(op.send_lease,self.provider.lease)
        ticket=next(row for row in op.send_tickets if row.kind=='lease')
        self.assertIs(ticket.resource,self.provider.lease);self.assertTrue(ticket.unknown)
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertEqual(self.provider.restore_count,0)
    def test_constructor_unknown_retains_factory_and_does_not_report_closed(self):
        with mock.patch.object(service.State,'_make_send_worker',side_effect=KeyboardInterrupt('HOST unknown ctor')):
            op=self.scan();self.send();status=self.settle()
        self.assertTrue(op.send_construct_unknown);self.assertIsNotNone(op.send_factory)
        self.assertTrue(status['restorePending']);self.assertFalse(status['sessionLifecycle']['closed'])
        self.assertEqual(self.registry.calls,0);self.assertEqual(self.provider.restore_count,0)
    def test_selection_close_failure_does_not_retry_original_or_restore_early(self):
        self.registry.selection.pending=True;op=self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertEqual(self.registry.selection.close_count,1)
        self.assertEqual(op.helper.close_count,1);self.assertTrue(self.crypto.key.closed);self.assertTrue(self.provider.dhcp.closed)
        self.assertEqual(self.provider.restore_count,0);self.assertTrue(status['restorePending'])
        op.session.close(.1);self.assertEqual(self.registry.selection.close_count,1)
    def test_incomplete_transport_proof_blocks_release_extra_and_network_restore(self):
        self.sender_close_fault=True;op=self.scan();self.send();status=self.settle()
        self.assertFalse(status['sessionLifecycle']['closed']);self.assertFalse(status['sessionLifecycle']['release_verified'])
        self.assertEqual(op.helper.close_count,0);self.assertEqual(self.provider.restore_count,0)
        self.assertIs(op.transport,self.sender);self.assertTrue(status['restorePending'])
    def test_public_status_has_no_lease_credentials_private_tickets_or_task_identity(self):
        op=self.scan();self.send();text=repr(self.settle())
        for private in ('host-only-pass','192.168.88.1',op.send_intent.handoff.task_id,'peer-public','SendRestoreReceipt'):
            self.assertNotIn(private,text)
    def test_public_action_shape_does_not_accept_provider_direction_or_task_fields(self):
        self.scan()
        for key in ('provider','direction','taskId','send_available'):
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.state.action(dict(action='send',deviceId='7',fileIds=['file-id'],**{key:True}))
        self.assert_zero_send_io()
    def test_receive_confirmation_result_contract_unchanged_named_old_method(self):
        # Exact affected old request/confirmation methods, new zero-OS fixture.
        receive_fixture.ServiceIntegrationTests.test_wrong_request_id_cannot_accept_new_request(self)
        self.state.decision.clear()
        receive_fixture.ServiceIntegrationTests.test_reject_confirmation_unblocks_without_transferring(self)
    def test_receive_outcome_default_session_keyset_remains_receive(self):
        op=self.state._new_operation_locked('cleanup')
        self.assertEqual(op.session._direction,'receive');self.assertTrue(op.session.close(1))
        status=op.session.status()
        self.assertNotIn('direction',status);self.assertNotIn('local_bytes_verified',status)
        self.assertFalse(status['local_commit_verified']);self.assertFalse(status['peer_ack_verified'])
    def test_python35_ast_and_default_production_factories_remain_actual(self):
        source=(BASE/'runtime'/'mta_service.py').read_text(encoding='utf-8')
        ast.parse(source,feature_version=(3,5))
        self.assertIn('self.send_available=False',source)
        self.assertIs(service.SendWorker,worker.SendWorker)


if __name__=='__main__':unittest.main()
