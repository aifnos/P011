"""HOST actual Python threads + explicit fake radio/network/filesystem.

No ADB, subprocess, real socket/TLS, credentials, RF or phone acceptance.
"""
import ast
import base64
import os
from pathlib import Path
import queue
import stat
import sys
import threading
import time
import types
import unittest
from unittest import mock

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'));sys.path.insert(0,str(BASE/'tests'))
import mta_service as service
import mta_ui_session as ui
import mta_toolbox_session as toolbox
import mta_wifi as wifi
import test_service_integration as fixtures
from mta_protocol import P2pInfo
REAL_HELPER=service.PrivateHelper
REAL_WATCHDOG=service.State.start_watchdog
REAL_CAPABILITY=service.capability


class HostPipe:
    def __init__(self,process,output=False):
        self.process=process;self.output=output;self.closed=False;self.lines=queue.Queue();self.fail_close=False
    def readline(self,maximum):return self.lines.get(timeout=2)
    def write(self,data):
        if b'"stop"' in data:self.process.finish()
        return len(data)
    def flush(self):pass
    def close(self):
        if self.fail_close:raise OSError('HOST_PRIVATE_PIPE_CLOSE')
        self.closed=True


class HostProcess:
    def __init__(self):
        self.stdin=HostPipe(self);self.stdout=HostPipe(self,True);self.returncode=None;self.pid=123
        self.terminated=False;self.killed=False
    def finish(self):self.returncode=0;self.stdout.lines.put(b'')
    def poll(self):return self.returncode
    def wait(self,timeout):
        if self.returncode is None:raise service.subprocess.TimeoutExpired('HOST_FIXED_HELPER',timeout)
        return self.returncode
    def terminate(self):self.terminated=True;self.finish()
    def kill(self):self.killed=True;self.finish()


class ProbeProcess(HostProcess):
    def __init__(self):
        super(ProbeProcess,self).__init__();self.stderr=HostPipe(self,True);self.communicate_fault=False;self.exit_on_kill=True
    def kill(self):
        self.killed=True
        if self.exit_on_kill:self.finish()
    def communicate(self,timeout):
        if self.communicate_fault:raise KeyboardInterrupt('HOST_PRIVATE_COMMUNICATE')
        self.finish();self.stdout.close();self.stderr.close();return b'{"powered":true}\n',b''


class StateLifecycleTests(unittest.TestCase):
    begin_receive=fixtures.ServiceIntegrationTests.begin_receive
    run_receive=fixtures.ServiceIntegrationTests.run_receive
    settle_operation=fixtures.ServiceIntegrationTests.settle_operation
    scan_ready=fixtures.ServiceIntegrationTests.scan_ready
    attach_helper=fixtures.ServiceIntegrationTests.attach_helper
    def setUp(self):
        fixtures.ServiceIntegrationTests.setUp(self);self.holds=[];self.outside=[]
    def event(self):
        event=threading.Event();self.holds.append(event);return event
    def tearDown(self):
        for event in self.holds:event.set()
        for thread in self.outside:thread.join(2);self.assertFalse(thread.is_alive())
        fixtures.ServiceIntegrationTests.tearDown(self)
        if self.state.session:
            worker=self.state.session._worker
            if worker.ident is not None:worker.join(2)
            for row in self.state.session._attempts:
                if row['thread'].ident is not None:row['thread'].join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(any(row['thread'].is_alive() for row in self.state.session._attempts))

    def test_receive_requires_explicit_owned_preparation_no_fallback(self):
        with self.assertRaises(ValueError):self.state.receive(self.info)
        self.assertEqual(fixtures.FakeWifi.instances[0].receive_calls,0)
        self.assertIsNone(fixtures.FakeWifi.instances[0]._active_lease)

    def test_reserve_registers_exact_lease_before_prepare_failure_and_retains_it(self):
        fixtures.FakeWifi.fail_prepare=True
        self.state.action({'action':'discover_start'});status=self.settle_operation()
        op=self.state.operation
        self.assertIsNotNone(op.lease);self.assertIs(self.state.lease,op.lease)
        self.assertTrue(op.lease.actors_closed());self.assertTrue(status['sessionLifecycle']['closed'])
        self.assertIs(self.state.worker,op.session._worker);self.assertFalse(self.state.worker.is_alive())
        self.assertEqual(fixtures.FakeHelper.instances,[])

    def test_receiver_is_registered_before_run_and_restores_after_actual_worker_exit(self):
        original=fixtures.FakeReceiver.run;seen=[]
        def checked(receiver,*args,**kwargs):
            op=self.state.operation;seen.append(op)
            self.assertIs(op.transport,receiver);self.assertIs(self.state.transport,receiver)
            self.assertIs(op.session._transports[0],receiver)
            return original(receiver,*args,**kwargs)
        lease_restore=fixtures.FakeLease.close
        def restore(lease):
            self.assertFalse(self.state.worker.is_alive());self.assertFalse(self.state.lock._is_owned())
            return lease_restore(lease)
        with mock.patch.object(fixtures.FakeReceiver,'run',checked),mock.patch.object(fixtures.FakeLease,'restore',restore):
            status=self.run_receive()
        self.assertEqual(len(seen),1);self.assertTrue(status['sessionLifecycle']['closed'])

    def test_legacy_backend_receive_is_never_called_by_worker(self):
        with mock.patch.object(fixtures.FakeWifi,'receive',side_effect=AssertionError('HOST fallback forbidden')):
            status=self.run_receive()
        self.assertEqual(status['state'],'completed')
        self.assertEqual(fixtures.FakeWifi.instances[0].prepare_calls,1)

    def test_cancelled_worker_still_alive_keeps_lease_and_no_restore(self):
        entered=self.event();finish=self.event()
        def held(receiver,*args):receiver.run_thread=threading.current_thread();entered.set();finish.wait(2);return {'fileCount':1,'totalSize':1,'peer_ack_verified':False}
        with mock.patch.object(fixtures.FakeReceiver,'run',held):
            self.begin_receive();self.state.receive(self.info);self.assertTrue(entered.wait(1))
            op=self.state.operation;op.session.finalize_timeout=.03;op.session.cancel()
            op.session._attempts[0]['thread'].join(1)
            self.assertTrue(op.session.status()['worker_alive']);self.assertFalse(op.session.closed())
            self.assertEqual(op.lease.close_calls,0);self.assertIs(self.state.worker,op.session._worker)
            finish.set();op.session._worker.join(1)
            self.assertFalse(op.session.closed());self.assertTrue(self.state.close())

    def test_native_closed_callback_only_cancels_while_worker_alive(self):
        entered=self.event();finish=self.event()
        def held(receiver,*args):receiver.run_thread=threading.current_thread();entered.set();finish.wait(2);raise service.SessionError('HOST held transfer')
        with mock.patch.object(fixtures.FakeReceiver,'run',held):
            self.begin_receive();self.state.receive(self.info);self.assertTrue(entered.wait(1));op=self.state.operation
            op.helper.callback({'event':'closed'})
            self.assertTrue(op.cancelled.is_set());self.assertEqual(op.lease.close_calls,0)
            self.assertTrue(op.session._worker.is_alive());self.assertFalse(self.state.status()['sessionLifecycle']['closed'])
            finish.set();self.settle_operation()

    def test_status_is_passive_even_past_deadline_and_pending_recovery(self):
        self.attach_helper(scanning=True);self.state.radio_deadline=time.monotonic()-1
        self.state.wifi_backend._restore_failed=True;before=list(fixtures.HOST_EVENTS)
        for _ in range(5):
            status=self.state.status();self.assertTrue(status['restorePending'])
            self.assertNotIn('fixture-password',repr(status))
        self.assertEqual(fixtures.HOST_EVENTS,before);self.assertFalse(self.state.cancelled.is_set())

    def test_no_detached_watchdog_and_helper_close_is_outside_state_lock(self):
        original=fixtures.FakeHelper.close
        def checked(helper):self.assertFalse(self.state.lock._is_owned());return original(helper)
        with mock.patch.object(fixtures.FakeHelper,'close',checked):
            self.scan_ready();op=self.state.operation;self.assertIsNone(REAL_WATCHDOG(self.state))
            self.state.action({'action':'scan_stop'});self.assertTrue(op.session.closed())

    def test_missing_transport_lifecycle_cannot_restore_or_clear_exact_owner(self):
        with mock.patch.object(fixtures.FakeReceiver,'lifecycle_status',return_value={'close_verified':True,'cleanup_pending':False}):
            status=self.run_receive()
            self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(status['restorePending'])
            self.assertEqual(self.state.operation.lease.close_calls,0)
            self.assertIs(self.state.operation.transport,self.state.session._transports[0])
        self.assertTrue(self.state.close())

    def test_none_helper_close_does_not_count_as_success(self):
        self.attach_helper(scanning=True)
        with mock.patch.object(fixtures.FakeHelper,'close',return_value=None):
            self.assertFalse(self.state.stop_radio());self.assertFalse(self.state.session.closed())
            self.assertIsNotNone(self.state.operation.helper)
        self.assertTrue(self.state.close())

    def test_network_reader_proof_required_after_reported_native_restore(self):
        with mock.patch.object(fixtures.FakeLease,'actors_closed',return_value=False):
            status=self.run_receive();self.assertFalse(status['sessionLifecycle']['closed'])
            self.assertTrue(status['transfer']['localCommitVerified']);self.assertTrue(status['transfer']['peerAckVerified'])
        self.assertTrue(self.state.close())

    def test_key_close_exception_even_after_closed_flag_retains_unknown_owner(self):
        original=fixtures.FakeKey.close
        def failed(key):original(key);raise OSError('HOST_PRIVATE_FREE_FAILED')
        with mock.patch.object(fixtures.FakeKey,'close',failed):
            status=self.run_receive();self.assertFalse(status['sessionLifecycle']['closed'])
            self.assertTrue(self.state.operation.key.closed);self.assertTrue(self.state.operation.actor_unknown)
            self.assertEqual(self.state.operation.lease.close_calls,0)
        self.assertFalse(self.state.close());self.assertIsNotNone(self.state.operation.key)

    def test_restore_status_missing_or_truthy_bool_is_not_verified(self):
        original=fixtures.FakeWifi.status
        for bad in ({'restorePending':False},{'restorePending':0,'recoveryLocked':False}):
            with mock.patch.object(fixtures.FakeWifi,'status',return_value=bad):
                self.assertFalse(self.state.close());self.assertFalse(self.state.closed())
            self.assertTrue(self.state.close())
            self.assertEqual(original(self.state.wifi_backend)['restorePending'],False)
            # A fresh explicit cleanup owner tests the next malformed report.
            self.state.wifi_restore_pending=True

    def test_saved_without_ack_is_not_public_completed_but_can_close(self):
        original=fixtures.FakeReceiver.run
        def without_ack(receiver,*args):result=original(receiver,*args);result['peer_ack_verified']=False;return result
        with mock.patch.object(fixtures.FakeReceiver,'run',without_ack):status=self.run_receive()
        self.assertEqual(status['state'],'error');self.assertFalse(status['restorePending'])
        self.assertTrue(status['transfer']['localCommitVerified']);self.assertFalse(status['transfer']['peerAckVerified'])
        self.assertEqual(status['sessionLifecycle']['phase'],'saved_unconfirmed')

    def test_recover_is_explicit_same_owner_no_passive_or_cancel_automatic_recovery(self):
        backend=self.state.wifi_backend;backend._restore_failed=True;calls=[]
        def recover():calls.append(backend);backend._restore_failed=False;return True
        with mock.patch.object(backend,'recover_pending',recover):
            self.state.status();self.state.action({'action':'cancel'});self.assertEqual(calls,[])
            first=self.state.session;self.assertFalse(first.closed())
            self.state.action({'action':'recover'});self.assertIs(self.state.session,first)
            self.assertEqual(calls,[backend]);self.assertTrue(first.closed())

    def test_closed_failed_lease_recovery_is_explicit_same_session_and_preserves_history(self):
        calls=[];original=fixtures.FakeLease.restore
        def failed(lease):
            lease.close_calls+=1;lease.closed=True;lease.restored=False;lease.backend._restore_failed=True;return False
        def recover():
            calls.append(self.state.operation);self.state.wifi_backend._restore_failed=False
            self.state.wifi_backend._active_lease=None;return True
        with mock.patch.object(fixtures.FakeLease,'restore',failed),mock.patch.object(self.state.wifi_backend,'recover_pending',recover):
            status=self.run_receive();op=self.state.operation;session=op.session;lease=op.lease
            self.assertFalse(status['sessionLifecycle']['closed']);self.assertTrue(lease.closed)
            self.state.status();self.state.action({'action':'cancel'});self.assertEqual(calls,[])
            self.state.action({'action':'recover'})
            self.assertEqual(calls,[op]);self.assertIs(self.state.session,session);self.assertTrue(session.closed())
            self.assertIs(self.state.lease,lease);self.assertFalse(lease.restored)

    def test_failed_recovery_retains_exact_owner_no_parallel_retry_and_unknown_actors_block(self):
        entered=self.event();release=self.event();calls=[]
        def failed(lease):lease.closed=True;lease.restored=False;lease.backend._restore_failed=True;return False
        def recover():calls.append(self.state.operation);entered.set();release.wait(2);return False
        with mock.patch.object(fixtures.FakeLease,'restore',failed),mock.patch.object(self.state.wifi_backend,'recover_pending',recover):
            self.run_receive();op=self.state.operation;op.recovery_requested=True
            closing=threading.Thread(target=lambda:op.session.close(timeout=.01));self.outside.append(closing);closing.start()
            self.assertTrue(entered.wait(1));self.assertFalse(op.session.close(timeout=.01));self.assertEqual(calls,[op])
            self.assertIs(self.state.operation,op);self.assertFalse(self.state.status()['sessionLifecycle']['closed'])
            release.set();closing.join(1)
            for attempt in op.session._attempts:attempt['thread'].join(1)
            with mock.patch.object(op.lease,'actors_closed',return_value=False):
                self.assertFalse(self.state.close());self.assertEqual(calls,[op])
        self.state.wifi_backend.restore_ok=True
        self.assertTrue(self.state.close())

    def test_blocked_advert_worker_does_not_block_native_callbacks_status_or_cancel_event(self):
        entered=self.event();release=self.event();original=fixtures.FakeHelper.send;seen=[]
        def held(helper,value):
            self.assertFalse(self.state.lock._is_owned());seen.append(threading.current_thread())
            if value.get('cmd')=='advert':entered.set();release.wait(2)
            return original(helper,value)
        with mock.patch.object(fixtures.FakeHelper,'send',held),mock.patch('builtins.open',mock.mock_open(read_data='02:00:00:00:00:01\n')):
            self.state.action({'action':'discover_start'});self.assertTrue(entered.wait(1));op=self.state.operation
            for _ in range(3):self.state.native_event({'event':'listen','code':'ready'},op.epoch)
            self.state.native_event({'event':'advert','code':'ready'},op.epoch-1)
            self.assertFalse(self.state.status()['discoverable']);self.assertEqual(op.stage,'advert_pending')
            cancel=threading.Thread(target=lambda:self.state.action({'action':'cancel'}));self.outside.append(cancel);cancel.start()
            self.assertTrue(op.cancelled.wait(.2));self.assertTrue(self.state.status()['restorePending'])
            self.assertEqual(op.lease.close_calls,0);release.set();cancel.join(1);self.settle_operation()
            self.assertEqual(sum(row.get('cmd')=='advert' for row in op.helper.commands),1)
            self.assertTrue(all(thread is op.session._worker for thread in seen))
            self.state.native_event({'event':'listen','code':'ready'},op.epoch)
            self.state.native_event({'event':'advert','code':'ready'},op.epoch)
            self.assertFalse(self.state.status()['discoverable'])

    def test_superseded_epoch_cannot_cancel_or_insert_current_operation(self):
        self.scan_ready();old=self.state.operation
        self.state.action({'action':'scan_stop'});self.scan_ready();current=self.state.operation
        self.state.native_event({'event':'closed'},old.epoch)
        self.state.native_event({'event':'discovered','peer':3,'cached':False},old.epoch)
        self.assertFalse(current.cancelled.is_set());self.assertEqual(self.state.devices,{})
        self.assertIn(old,self.state.history)

    def test_boot_production_network_and_send_gates_are_unchanged(self):
        source=(BASE/'native/mta_network.c').read_text(encoding='utf-8')
        self.assertIn('#define MTA_CONNMAN_STA_VERIFIED 0',source)
        self.assertFalse(self.state.status()['capabilities']['send']['available'])
        with self.assertRaises(ValueError):self.state.action({'action':'send','deviceId':'1','fileIds':['opaque']})

    def test_actual_helper_reader_process_pipes_are_closed_before_network_callback(self):
        process=HostProcess()
        with mock.patch.object(service,'PrivateHelper',REAL_HELPER),mock.patch.object(service.subprocess,'Popen',return_value=process):
            self.scan_ready();helper=self.state.operation.helper
            self.assertTrue(helper.thread.is_alive());self.state.action({'action':'scan_stop'})
            self.assertTrue(helper.closure_verified());self.assertFalse(helper.thread.is_alive())
            self.assertTrue(process.stdin.closed);self.assertTrue(process.stdout.closed)
            self.assertTrue(self.state.session.closed())

    def test_helper_thread_start_real_created_then_interrupt_stays_owned_unknown(self):
        process=HostProcess();holder=[];original=REAL_HELPER.start
        def interrupted(helper):
            holder.append(helper);start=helper.thread.start
            def fail():start();raise KeyboardInterrupt('HOST_PRIVATE_START_INTERRUPT')
            helper.thread.start=fail;return original(helper)
        with mock.patch.object(service,'PrivateHelper',REAL_HELPER),mock.patch.object(service.subprocess,'Popen',return_value=process),mock.patch.object(REAL_HELPER,'start',interrupted):
            self.state.action({'action':'scan'});status=self.settle_operation();helper=holder[0]
            self.assertIs(self.state.operation.helper,helper);self.assertFalse(helper.thread.is_alive())
            self.assertTrue(helper.reader_unknown);self.assertFalse(status['sessionLifecycle']['closed'])
            self.assertFalse(self.state.close());self.assertTrue(self.state.status()['restorePending'])

    def test_helper_popen_exception_has_unknown_owner_no_false_unstarted_success(self):
        with mock.patch.object(service,'PrivateHelper',REAL_HELPER),mock.patch.object(service.subprocess,'Popen',side_effect=KeyboardInterrupt('HOST_PRIVATE_SPAWN')):
            self.state.action({'action':'scan'});status=self.settle_operation()
            helper=self.state.operation.helper;self.assertIsNotNone(helper)
            self.assertTrue(helper.spawn_unknown);self.assertIsNone(helper.process)
            self.assertFalse(status['sessionLifecycle']['closed']);self.assertFalse(helper.closure_verified())

    def test_helper_pipe_close_failure_retains_owner_and_tries_stdout_cleanup(self):
        process=HostProcess();process.stdin.fail_close=True
        with mock.patch.object(service,'PrivateHelper',REAL_HELPER),mock.patch.object(service.subprocess,'Popen',return_value=process):
            self.scan_ready();self.state.action({'action':'scan_stop'});helper=self.state.operation.helper
            self.assertFalse(self.state.session.closed());self.assertIs(self.state.helper,helper)
            self.assertTrue(process.stdout.closed);self.assertFalse(process.stdin.closed)
            process.stdin.fail_close=False;self.assertTrue(self.state.close())

    def test_helper_wait_exception_still_tries_reader_and_both_pipe_cleanup(self):
        process=HostProcess()
        with mock.patch.object(service,'PrivateHelper',REAL_HELPER),mock.patch.object(service.subprocess,'Popen',return_value=process):
            self.scan_ready()
            with mock.patch.object(process,'wait',side_effect=OSError('HOST_PRIVATE_WAIT')):
                self.state.action({'action':'scan_stop'})
            self.assertFalse(self.state.helper.thread.is_alive());self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed);self.assertTrue(self.state.session.closed())

    def probe(self,process):
        with mock.patch.object(service.os.path,'isfile',return_value=True),mock.patch.object(service.subprocess,'Popen',return_value=process):
            return REAL_CAPABILITY('/HOST/helper',['--capabilities'],actors=self.state.probe_actors)

    def test_probe_actor_precedes_popen_unknown_start_locks_without_respawn(self):
        def interrupted(*args,**kwargs):
            self.assertEqual(len(self.state.probe_actors),1);self.assertTrue(self.state.probe_actors[0]['spawn_pending'])
            raise KeyboardInterrupt('HOST_PRIVATE_PROBE_START')
        with mock.patch.object(service.os.path,'isfile',return_value=True),mock.patch.object(service.subprocess,'Popen',side_effect=interrupted) as spawn:
            self.assertEqual(REAL_CAPABILITY('/HOST/helper',['--capabilities'],actors=self.state.probe_actors),{})
            for _ in range(3):self.assertTrue(self.state.status()['restorePending']);self.assertFalse(self.state.verify_radio_restore())
            self.assertFalse(self.state.close());spawn.assert_called_once()
        self.assertIsNone(self.state.probe_actors[0]['process']);self.assertTrue(self.state.probe_actors[0]['spawn_unknown'])

    def test_probe_communicate_unknown_keeps_handle_until_exact_exit_and_two_pipes_closed(self):
        process=ProbeProcess();process.communicate_fault=True;process.exit_on_kill=False
        self.assertEqual(self.probe(process),{});row=self.state.probe_actors[0]
        self.assertIs(row['process'],process);self.assertFalse(row['closed']);self.assertTrue(self.state.status()['restorePending'])
        original=process.communicate
        def checked(timeout):self.assertFalse(self.state.lock._is_owned());return original(timeout)
        process.finish();process.stdout.fail_close=True
        with mock.patch.object(process,'communicate',checked):self.assertFalse(self.state.close())
        self.assertFalse(process.stdout.closed);self.assertTrue(process.stderr.closed);self.assertIs(row['stdout'],process.stdout)
        process.stdout.fail_close=False;self.assertTrue(self.state.close());self.assertTrue(row['closed'])

    def test_probe_pipe_identity_swap_never_claims_closure_or_closes_foreign_pipe(self):
        process=ProbeProcess();process.communicate_fault=True;process.exit_on_kill=False;self.probe(process)
        row=self.state.probe_actors[0];original=row['stderr'];foreign=HostPipe(process)
        process.stderr=foreign;process.finish();self.assertFalse(self.state._close_probes())
        self.assertFalse(foreign.closed);self.assertFalse(row['closed']);self.assertIs(row['stderr'],original)
        process.stderr=original;self.assertTrue(self.state.close())

    def test_constructor_unknown_probe_does_not_spawn_second_probe_or_enable_capability(self):
        with mock.patch.object(service,'capability',REAL_CAPABILITY),mock.patch.object(service.os.path,'isfile',return_value=True),mock.patch.object(service.subprocess,'Popen',side_effect=KeyboardInterrupt('HOST_PRIVATE_INIT_PROBE')) as spawn:
            state=service.State(self.root,'/HOST/bluez','/HOST/network');spawn.assert_called_once()
            self.assertFalse(state.receive_available);self.assertFalse(state.scan_available)
            for _ in range(2):self.assertTrue(state.status()['restorePending'])
            self.assertFalse(state.close());spawn.assert_called_once();self.assertIsNotNone(state.operation)


class FakeFile:
    def __init__(self,ino,mode):
        self.st_dev=1;self.st_ino=ino;self.st_uid=77;self.st_mode=mode;self.st_nlink=1;self.contents=b''


class FakeText:
    def __init__(self,filesystem,fd):self.fs=filesystem;self.fd=fd
    def __enter__(self):return self
    def __exit__(self,*unused):self.fs.close(self.fd)
    def write(self,text):self.fs.fds[self.fd].contents+=text.encode('utf-8')
    def flush(self):pass
    def fileno(self):return self.fd


class FakeOS:
    O_WRONLY=1;O_RDONLY=0;O_CREAT=2;O_EXCL=4;O_NOFOLLOW=8
    def __init__(self):
        self.items={};self.fds={};self.serial=10;self.removed=[];self.redirect={}
        self.path=types.SimpleNamespace(realpath=lambda path:self.redirect.get(path,path))
    def getpid(self):return 77
    def mkdir(self,path,mode):self.serial+=1;self.items[path]=FakeFile(self.serial,stat.S_IFDIR|mode)
    def lstat(self,path):return self.items[path]
    def listdir(self,path):return [name[len(path)+1:] for name in self.items if name.startswith(path+'/')]
    def open(self,path,flags,mode=None):
        if flags&self.O_CREAT:
            if path in self.items:raise OSError('HOST exists')
            self.serial+=1;self.items[path]=FakeFile(self.serial,stat.S_IFREG|mode)
        self.serial+=1;self.fds[self.serial]=self.items[path];return self.serial
    def fdopen(self,fd,*unused,**kwargs):return FakeText(self,fd)
    def fstat(self,fd):return self.fds[fd]
    def fsync(self,fd):pass
    def read(self,fd,limit):return self.fds[fd].contents[:limit]
    def close(self,fd):self.fds.pop(fd)
    def unlink(self,path):self.removed.append(path);self.items.pop(path)
    def rmdir(self,path):
        if self.listdir(path):raise OSError('HOST not empty')
        self.removed.append(path);self.items.pop(path)


class UiOccupancyTests(unittest.TestCase):
    def setUp(self):
        self.fs=FakeOS();self.owner={'pid':77,'starttime':'HOST1','exe':'/HOST/python'}
        self.patches=[mock.patch.object(ui,'os',self.fs),mock.patch.object(ui,'AREA','/HOST'),
                      mock.patch.object(ui,'identity',lambda pid:dict(self.owner))]
        for patch in self.patches:patch.start()
        self.record=ui.acquire_lock('/HOST/sessions/mta-ui-20261001-000000-01234567','HOST_CANDIDATE')
    def tearDown(self):
        for patch in reversed(self.patches):patch.stop()
        self.assertEqual(self.fs.fds,{})
    def test_exact_complete_owner_can_release_only_own_fixed_members(self):
        self.assertTrue(ui.release_lock(self.record,True));self.assertEqual(self.fs.items,{})
        self.assertEqual(set(self.fs.removed),{'/HOST/mta-ui.lock/session.txt','/HOST/mta-ui.lock/owner.json','/HOST/mta-ui.lock'})
    def test_pending_none_truthy_non_bool_never_removes_anything(self):
        for value in (False,None,1,'true'):
            self.assertFalse(ui.release_lock(self.record,value));self.assertEqual(self.fs.removed,[])
    def test_directory_swap_symlink_mode_or_current_process_identity_fails_closed(self):
        value=self.fs.items['/HOST/mta-ui.lock'];saved=vars(value).copy()
        for field,new in (('st_ino',999),('st_uid',88),('st_mode',stat.S_IFLNK|0o700),('st_mode',stat.S_IFDIR|0o777)):
            vars(value).update(saved);setattr(value,field,new)
            self.assertFalse(ui.release_lock(self.record,True));self.assertEqual(self.fs.removed,[])
        vars(value).update(saved);self.owner['starttime']='HOST_OTHER'
        self.assertFalse(ui.release_lock(self.record,True));self.assertEqual(self.fs.removed,[])
    def test_every_file_is_validated_before_first_unlink(self):
        file=self.fs.items['/HOST/mta-ui.lock/owner.json'];file.contents=b'HOST_SWAP'
        self.assertFalse(ui.release_lock(self.record,True));self.assertEqual(self.fs.removed,[])
    def test_link_unknown_member_or_redirect_never_deletes_foreign_objects(self):
        file=self.fs.items['/HOST/mta-ui.lock/session.txt'];file.st_nlink=2
        self.assertFalse(ui.release_lock(self.record,True));file.st_nlink=1
        self.fs.items['/HOST/mta-ui.lock/FOREIGN']=FakeFile(500,stat.S_IFREG|0o600)
        self.assertFalse(ui.release_lock(self.record,True));self.fs.items.pop('/HOST/mta-ui.lock/FOREIGN')
        self.fs.redirect['/HOST/mta-ui.lock']='/FOREIGN'
        self.assertFalse(ui.release_lock(self.record,True));self.assertEqual(self.fs.removed,[])
    def test_child_inode_owner_mode_or_symlink_replacement_is_rejected(self):
        file=self.fs.items['/HOST/mta-ui.lock/session.txt'];saved=vars(file).copy()
        for field,new in (('st_ino',500),('st_uid',88),('st_mode',stat.S_IFREG|0o644),('st_mode',stat.S_IFLNK|0o600)):
            vars(file).update(saved);setattr(file,field,new)
            self.assertFalse(ui.release_lock(self.record,True));self.assertEqual(self.fs.removed,[])
    def test_entry_sources_use_strict_cleanup_gate_and_python35_ast(self):
        for module in (service,wifi,ui,toolbox):ast.parse(Path(module.__file__).read_text(encoding='utf-8'),feature_version=(3,5))
        for module in (ui,toolbox):
            source=Path(module.__file__).read_text(encoding='utf-8')
            self.assertIn('release_lock(lock_record,cleanup)',source)
            self.assertIn('is True',source);self.assertIn("result['cleanup_pending']",source)
            self.assertNotIn("if ours:os.unlink",source)
            self.assertIn('child_spawn_unknown',source);self.assertIn('worker_start_unknown',source)

    def test_http_cleanup_retains_exact_actual_threads_even_when_server_close_raises(self):
        class HostServer:
            def __init__(self):
                self.worker_lock=threading.Lock();self.workers={};self.stopping=threading.Event()
                self.socket=types.SimpleNamespace(_closed=False);self.entered=threading.Event();self.fail=False
            def serve(self):self.entered.set();self.stopping.wait(1)
            def server_close(self):
                self.stopping.set();self.socket._closed=True
                if self.fail:raise OSError('HOST_PRIVATE_HTTP_CLOSE')
        for fail in (False,True):
            server=HostServer();server.fail=fail;thread=threading.Thread(target=server.serve)
            server.workers={1:thread};thread.start();self.assertTrue(server.entered.wait(1))
            # Simulate the existing HTTP map being cleared while the exact actor
            # is retained through bound target identity and explicit worker.
            server.workers={}
            self.assertIs(ui.close_http(server,thread),not fail)
            self.assertFalse(thread.is_alive());self.assertFalse(thread is threading.current_thread())


if __name__=='__main__':unittest.main()
