"""HOST fake TCP/TLS/files/threads only; no real socket, subprocess, P011 or RF."""
import ast
import hashlib
import io
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import mta_transport as transport
import mta_sender as sender_module
from mta_files import FileRegistry
from mta_protocol import WsMessage

HOST,PORT='192.168.77.1',8899
SOURCE='192.168.77.2'


class FakeSocket:
    family=socket.AF_INET
    created=[]

    def __init__(self,*args):
        self.number=len(self.created)
        self.created.append(self)
        self.fd=100+self.number
        self.address=(HOST,PORT)
        self.peer=(HOST,PORT)
        self.close_error=False
        self.close_hook=None
        self.close_calls=0
        self.shutdown_calls=0
        self.detached=False
        self.data=b''
        self.sent=b''
        self.accepted=[]
        self.accept_hook=None

    def fileno(self):return -1 if self.detached else self.fd
    def settimeout(self,value):self.timeout=value
    def getsockopt(self,level,option):return int(socket.SOCK_STREAM) if option==socket.SO_TYPE else 0
    def setsockopt(self,*args):pass
    def getpeername(self):return self.peer
    def getsockname(self):return self.address
    def bind(self,value):self.address=(value[0],value[1] or (40000+self.number));self.peer=None
    def listen(self,value):pass
    def shutdown(self,how):self.shutdown_calls+=1
    def close(self):
        self.close_calls+=1
        if self.close_hook:self.close_hook()
        if self.close_error:raise OSError('HOST_PRIVATE_CLOSE_VALUE')
        self.fd=-1
    def recv(self,count):value,self.data=self.data[:count],self.data[count:];return value
    def send(self,value):self.sent+=value;return len(value)
    def accept(self):
        if self.accept_hook:self.accept_hook()
        if self.accepted:return self.accepted.pop(0)
        raise OSError('HOST_LISTENER_END')


class FakeTLS(FakeSocket):
    def __init__(self,raw):
        FakeSocket.__init__(self)
        self.raw=raw
        self.cert=b'HOST_FIXED_CERTIFICATE'
        self.handshake_hook=None
    def do_handshake(self):
        if self.handshake_hook:self.handshake_hook()
    def getpeercert(self,binary_form=False):return self.cert


class FakeContext:
    def __init__(self,*args):self.wrap_hook=None;self.wrappers=[]
    def set_ciphers(self,*args):pass
    def load_cert_chain(self,*args):pass
    def wrap_socket(self,raw,**options):
        if self.wrap_hook:return self.wrap_hook(raw)
        raw.detached=True
        tls=FakeTLS(raw)
        self.wrappers.append(tls)
        return tls


class FakeThread:
    """Controlled worker state fixture, not a real thread completion result."""
    def __init__(self,target=None,args=(),name=None):
        self.target=target;self.args=args;self.name=name
        self.alive=False;self.daemon=False;self.joins=[];self.blocked=False
        self.start_hook=None;self.join_hook=None
    def start(self):
        if self.start_hook:self.start_hook()
        self.alive=True
    def is_alive(self):return self.alive
    def join(self,budget):
        self.joins.append(budget)
        if self.join_hook:self.join_hook(budget)
        if not self.blocked:self.alive=False


class LifeTests(unittest.TestCase):
    def setUp(self):FakeSocket.created=[];self.life=transport.SocketLifecycle()

    def test_raw_successful_close_and_repeated_close_are_exact_and_idempotent(self):
        raw=FakeSocket();self.life.adopt(raw)
        self.assertTrue(self.life.close(0))
        calls=raw.close_calls
        self.assertTrue(self.life.close(0))
        self.assertEqual(raw.close_calls,calls)
        self.assertTrue(self.life.snapshot(raw)['recognized_raw'])
        self.assertFalse(self.life.snapshot(FakeSocket())['recognized_raw'])
        self.assertFalse(self.life.snapshot(None)['recognized_raw'])

    def test_failure_of_one_close_still_closes_all_other_resources(self):
        first,second=FakeSocket(),FakeSocket()
        first.close_error=True
        self.life.adopt(first);self.life.adopt(second)
        self.assertFalse(self.life.close(0))
        self.assertEqual(second.fileno(),-1)
        self.assertEqual(self.life.snapshot()['sockets_pending'],1)
        first.close_error=False
        self.assertTrue(self.life.close(0))

    def test_tls_raw_detach_never_proves_owned_wrapper_closed(self):
        raw=FakeSocket();self.life.adopt(raw);self.life.begin_wrap(raw)
        raw.detached=True
        tls=FakeTLS(raw);self.life.finish_wrap(raw,tls)
        self.assertEqual(raw.fileno(),-1)
        self.assertFalse(self.life.snapshot(raw)['all_sockets_closed'])
        tls.close_error=True
        self.assertFalse(self.life.close(0))
        self.assertEqual(tls.fileno(),100+tls.number)
        tls.close_error=False
        self.assertTrue(self.life.close(0))
        self.assertTrue(self.life.snapshot(raw)['all_sockets_closed'])

    def test_wrap_pending_keeps_raw_and_late_wrapper_until_closed(self):
        raw=FakeSocket();self.life.adopt(raw);self.life.begin_wrap(raw)
        raw.detached=True
        self.assertFalse(self.life.close(0))
        self.assertEqual(self.life.snapshot()['wrappers_pending'],1)
        tls=FakeTLS(raw);self.life.finish_wrap(raw,tls)
        self.assertFalse(self.life.snapshot()['close_verified'])
        self.assertTrue(self.life.close(0))
        self.assertEqual(tls.fileno(),-1)

    def test_wrap_exception_after_detach_is_unknown_not_force_cleared(self):
        raw=FakeSocket();self.life.adopt(raw);self.life.begin_wrap(raw)
        raw.detached=True;self.life.failed_wrap(raw)
        self.assertFalse(self.life.close(0))
        self.assertFalse(self.life.close(0))
        self.assertEqual(self.life.snapshot()['unknown_wrappers'],1)

    def test_wrap_exception_before_detach_can_close_exact_owned_raw(self):
        raw=FakeSocket();self.life.adopt(raw);self.life.begin_wrap(raw)
        self.life.failed_wrap(raw)
        self.assertTrue(self.life.close(0))
        self.assertEqual(raw.fileno(),-1)

    def test_external_fd_minus_one_without_managed_close_is_unproven(self):
        raw=FakeSocket();self.life.adopt(raw);raw.detached=True
        self.assertFalse(self.life.close(0))
        self.assertEqual(self.life.snapshot()['sockets_pending'],1)

    def test_pending_actor_prevents_close_before_any_socket_created(self):
        actor=self.life.begin('create')
        self.assertFalse(self.life.close(0))
        self.assertEqual(self.life.snapshot()['actors_pending'],1)
        raw=FakeSocket();self.life.adopt(raw)
        self.assertFalse(self.life.close(0))
        self.life.end(actor)
        self.assertTrue(self.life.close(0))

    def test_live_worker_after_bounded_join_is_kept_until_actual_exit(self):
        worker=FakeThread();worker.blocked=True
        self.life.start_thread(worker)
        self.assertFalse(self.life.close(.01))
        self.assertTrue(worker.alive)
        self.assertEqual(self.life.snapshot()['threads_pending'],1)
        worker.alive=False
        self.assertTrue(self.life.close(0))

    def test_join_budget_is_total_not_two_seconds_per_worker(self):
        workers=[FakeThread() for _ in range(3)]
        for worker in workers:self.life.start_thread(worker)
        clock=[100.0]
        for worker in workers:
            worker.join_hook=lambda budget:clock.__setitem__(0,clock[0]+budget)
        with mock.patch.object(transport.time,'monotonic',side_effect=lambda:clock[0]):
            self.assertFalse(self.life.close(2))
        self.assertEqual(len(workers[0].joins),1)
        self.assertEqual(workers[1].joins,[])
        self.assertEqual(workers[2].joins,[])

    def test_thread_start_pending_cannot_be_misread_as_unstarted_dead(self):
        entered,finish=threading.Event(),threading.Event()
        worker=FakeThread()
        worker.start_hook=lambda:(entered.set(),finish.wait(2))
        launch=threading.Thread(target=lambda:self.life.start_thread(worker))
        launch.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(self.life.close(0))
            self.assertEqual(self.life.snapshot()['threads_pending'],1)
        finally:finish.set();launch.join(2)
        self.assertTrue(self.life.close(.01))

    def test_actual_current_worker_close_is_false_until_thread_really_exits(self):
        observed=[]
        def run():
            actor=self.life.begin('worker')
            self.life.end(actor)
            observed.append(self.life.close(0))
            observed.append(self.life.snapshot()['all_actors_exited'] if 'all_actors_exited' in self.life.snapshot() else False)
        worker=threading.Thread(target=run)
        self.life.start_thread(worker);worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(observed,[False,False])
        self.assertTrue(self.life.close(0))

    def test_concurrent_blocked_socket_close_actor_cannot_false_pass(self):
        raw=FakeSocket();self.life.adopt(raw)
        entered,finish=threading.Event(),threading.Event()
        raw.close_hook=lambda:(entered.set(),finish.wait(2))
        answers=[]
        closer=threading.Thread(target=lambda:answers.append(self.life.close(0)))
        closer.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(self.life.close(0))
            self.assertTrue(self.life.snapshot()['actors_pending'])
        finally:finish.set();closer.join(2)
        self.assertEqual(answers,[True])
        self.assertTrue(self.life.close(0))

    def test_live_owned_certificate_process_prevents_cleanup_and_close_proof(self):
        process=mock.Mock();process.poll.return_value=None
        self.life.adopt_process(process)
        self.assertFalse(self.life.close(0))
        self.assertFalse(self.life.actors_quiet())
        self.assertEqual(self.life.snapshot()['processes_pending'],1)
        process.poll.return_value=0
        self.assertTrue(self.life.close(0))

    def test_public_counts_are_safe_and_unknown_objects_do_not_match(self):
        raw=FakeSocket();self.life.adopt(raw)
        status=self.life.snapshot()
        self.assertEqual(set(status),{'closing','socket_records','sockets_pending','actors_pending',
            'threads_pending','wrappers_pending','unknown_wrappers','unknown_resources','processes_pending','close_verified'})
        self.assertNotIn(HOST,repr(status))
        self.assertFalse(self.life.close_socket(None))
        for budget in (-1,3,True,float('nan')):
            with self.assertRaises(transport.TransportError):self.life.close(budget)


class TransportTests(unittest.TestCase):
    def setUp(self):
        FakeSocket.created=[]
        self.base=tempfile.TemporaryDirectory(prefix='mta-host-lifecycle-')
        self.patches=[mock.patch.object(transport.socket,'socket',FakeSocket),
            mock.patch.object(transport.ssl,'SSLSocket',FakeTLS),
            mock.patch.object(transport.ssl,'SSLContext',FakeContext),
            mock.patch.object(transport.socket,'create_connection',side_effect=AssertionError('HOST real network forbidden')),
            mock.patch.object(sender_module.subprocess,'Popen',side_effect=AssertionError('HOST subprocess forbidden'))]
        for patch in self.patches:patch.start()
        self.transports=[]
        self.selections=[]

    def tearDown(self):
        for value in self.transports:value.close(0)
        for selection in self.selections:selection.close()
        for patch in reversed(self.patches):patch.stop()
        self.base.cleanup()

    def receiver(self,factory=None):
        def create(host,port,timeout):
            raw=FakeSocket();raw.address=(SOURCE,40000+raw.number);return raw
        storage=mock.Mock();storage.root=self.base.name
        value=transport.ReceiverTransport(HOST,PORT,storage,socket_factory=factory or create,source_ip=SOURCE)
        self.transports.append(value)
        return value

    def sender(self):
        user=Path(self.base.name)/'user';(user/'Music').mkdir(parents=True,exist_ok=True)
        (user/'Music'/'HOST.txt').write_bytes(b'HOST')
        registry=FileRegistry(str(user))
        selection=registry.open_selection([registry.list_files()[0]['id']])
        self.selections.append(selection)
        value=sender_module.SenderTransport(HOST,0,selection,str(Path(__file__).resolve()),temp_root=self.base.name)
        value._prepare_archive=lambda:None
        value._certificate=lambda:setattr(value,'_context',FakeContext())
        self.transports.append(value)
        return value

    def start_sender(self):
        value=self.sender()
        with mock.patch.object(sender_module.threading,'Thread',FakeThread):value.start()
        return value

    @staticmethod
    def register_temporary(receiver,path):
        value=os.lstat(str(path))
        receiver._temporary_paths[str(path)]=(value.st_dev,value.st_ino,
            os.path.realpath(str(path.parent)),os.path.realpath(str(path)))

    @staticmethod
    def negotiation():
        request={'taskId':'host-task','id':'host-task','fileName':'HOST.txt','fileCount':1,'totalSize':4,
            'senderId':'0011','senderName':'HOST','mimeType':'application/octet-stream'}
        ws=mock.Mock();ws.receive.side_effect=[WsMessage('action',0,'versionNegotiation',{'version':1}),
            WsMessage('action',1,'sendRequest',request),WsMessage('ack',2,'status',None)]
        return ws

    def test_receiver_connect_retains_raw_tls_and_exact_closure_snapshot(self):
        receiver=self.receiver();stream=receiver.connect();raw=receiver.context.wrappers[0].raw
        self.assertEqual(receiver.fingerprint,hashlib.sha256(stream.socket.cert).digest())
        self.assertEqual(raw.fileno(),-1)
        self.assertFalse(receiver.closure_snapshot(raw)['close_verified'])
        self.assertTrue(receiver.close(0))
        self.assertTrue(receiver.closure_snapshot(raw)['recognized_raw'])
        self.assertTrue(receiver.closure_snapshot(raw)['all_sockets_closed'])
        self.assertFalse(receiver.closure_snapshot(FakeSocket())['recognized_raw'])

    def test_receiver_one_tls_close_error_does_not_skip_other_connection(self):
        receiver=self.receiver();first=receiver.connect();second=receiver.connect()
        first.socket.close_error=True
        self.assertFalse(receiver.close(0))
        self.assertEqual(second.socket.fileno(),-1)
        self.assertEqual(receiver.lifecycle_status()['sockets_pending'],1)
        first.socket.close_error=False
        self.assertTrue(receiver.close(0))

    def test_receiver_blocked_late_factory_retained_until_return_and_thread_exit(self):
        entered,finish=threading.Event(),threading.Event();raw=FakeSocket();raw.address=(SOURCE,40001)
        def factory(*args):entered.set();finish.wait(2);return raw
        receiver=self.receiver(factory);errors=[]
        worker=threading.Thread(target=lambda:self.capture_connect(receiver,errors));worker.start()
        try:
            self.assertTrue(entered.wait(1));self.assertFalse(receiver.close(0))
            self.assertTrue(receiver.lifecycle_status()['actors_pending'])
        finally:finish.set();worker.join(2)
        self.assertEqual(errors,[transport.Cancelled])
        self.assertEqual(raw.fileno(),-1)
        self.assertTrue(receiver.close(0))

    @staticmethod
    def capture_connect(receiver,errors):
        try:receiver.connect()
        except Exception as error:errors.append(type(error))

    def test_receiver_wrap_blocked_after_detach_retains_late_tls(self):
        entered,finish=threading.Event(),threading.Event();created=[]
        receiver=self.receiver();errors=[]
        def wrap(raw):
            raw.detached=True;entered.set();finish.wait(2)
            tls=FakeTLS(raw);created.append(tls);return tls
        receiver.context.wrap_hook=wrap
        worker=threading.Thread(target=lambda:self.capture_connect(receiver,errors));worker.start()
        try:
            self.assertTrue(entered.wait(1));self.assertFalse(receiver.close(0))
            self.assertEqual(receiver.lifecycle_status()['wrappers_pending'],1)
        finally:finish.set();worker.join(2)
        self.assertEqual(errors,[transport.Cancelled])
        self.assertEqual(created[0].fileno(),-1)
        self.assertTrue(receiver.close(0))

    def test_receiver_wrap_exception_after_detach_keeps_unknown_owner(self):
        receiver=self.receiver()
        def bad(raw):raw.detached=True;raise OSError('HOST_PRIVATE_WRAP_ERROR')
        receiver.context.wrap_hook=bad
        with self.assertRaises(OSError):receiver.connect()
        self.assertFalse(receiver.close(0))
        self.assertEqual(receiver.lifecycle_status()['unknown_wrappers'],1)

    def test_receiver_factory_exception_does_not_default_retry_and_can_close(self):
        receiver=self.receiver(lambda *args:(_ for _ in ()).throw(OSError('HOST_FAILURE')))
        with self.assertRaises(OSError):receiver.connect()
        self.assertTrue(receiver.close(0))
        self.assertEqual(receiver.lifecycle_status()['socket_records'],0)

    def test_receiver_certificate_first_pin_rotation_rule_unchanged(self):
        receiver=self.receiver();initial=receiver.connect();pinned=receiver.fingerprint
        def replacement(raw):
            raw.detached=True;tls=FakeTLS(raw);tls.cert=b'HOST_OTHER_CERT';return tls
        receiver.context.wrap_hook=replacement
        with self.assertRaisesRegex(transport.TransportError,'certificate changed'):receiver.connect()
        self.assertEqual(receiver.fingerprint,pinned)
        self.assertEqual(initial.socket.fileno(),-1)
        self.assertTrue(receiver.close(0))

    def test_receiver_current_worker_return_waits_actual_thread_identity(self):
        receiver=self.receiver();observed=[]
        def run():
            receiver.connect()
            observed.append(receiver.close(0))
            observed.append(receiver.closed())
        worker=threading.Thread(target=run);worker.start();worker.join(2)
        self.assertFalse(worker.is_alive());self.assertEqual(observed,[False,False])
        self.assertTrue(receiver.close(0))

    def test_receiver_confirm_pause_close_has_pending_run_actor_and_no_success(self):
        receiver=self.receiver();entered,finish=threading.Event(),threading.Event();errors=[]
        request={'taskId':'host-task','id':'host-task','fileName':'HOST.txt','fileCount':1,'totalSize':4,
            'senderId':'0011','senderName':'HOST','mimeType':'application/octet-stream'}
        ws=mock.Mock();ws.receive.side_effect=[WsMessage('action',0,'versionNegotiation',{'version':1}),
            WsMessage('action',1,'sendRequest',request)]
        def confirm(value):entered.set();finish.wait(2);return False
        def run():
            try:receiver.run(confirm)
            except Exception as error:errors.append(type(error))
        with mock.patch.object(transport,'websocket_client',return_value=ws):
            worker=threading.Thread(target=run);worker.start()
            try:
                self.assertTrue(entered.wait(1));self.assertFalse(receiver.close(0))
                self.assertTrue(receiver.lifecycle_status()['actors_pending'])
            finally:finish.set();worker.join(2)
        self.assertEqual(errors,[transport.Cancelled])
        self.assertTrue(receiver.close(0))

    def test_receiver_run_cleanup_still_attempts_temporary_after_socket_error(self):
        receiver=self.receiver();temporary=Path(self.base.name)/'.mta-download-HOST.zip'
        temporary.write_bytes(b'HOST')
        raw=FakeSocket();receiver._life.adopt(raw);raw.close_error=True
        self.register_temporary(receiver,temporary)
        def implementation(*args):return {'peer_ack_verified':False,'fileCount':1}
        with mock.patch.object(receiver,'_run_impl',side_effect=implementation):
            result=receiver.run(lambda value:True)
        self.assertFalse(result['peer_ack_verified'])
        self.assertFalse(temporary.exists())
        self.assertFalse(receiver.closed())
        raw.close_error=False;self.assertTrue(receiver.close(0))

    def test_receiver_failed_unlink_is_retained_then_exact_retry_succeeds(self):
        receiver=self.receiver();temporary=Path(self.base.name)/'.mta-download-HOST.zip'
        temporary.write_bytes(b'HOST');self.register_temporary(receiver,temporary)
        with mock.patch.object(transport.os,'unlink',side_effect=OSError('HOST_PRIVATE_UNLINK')):
            self.assertFalse(receiver.close(0))
        self.assertTrue(receiver.lifecycle_status()['cleanup_pending'])
        self.assertTrue(temporary.exists())
        self.assertTrue(receiver.close(0));self.assertFalse(temporary.exists())

    def test_sender_close_preserves_exact_listener_and_default_denyall(self):
        sender=self.start_sender();raw=sender._listener
        self.assertIsNone(sender.allowed_peer_ip)
        self.assertTrue(sender.close(0) is False)  # Worker is still alive; no forced dead flag.
        self.assertTrue(sender.close(.01))
        self.assertTrue(sender.closed())
        self.assertTrue(sender.closure_snapshot(raw)['recognized_raw'])
        self.assertEqual(raw.fileno(),-1)

    def test_actual_receiver_run_attempts_both_tls_closes_and_preserves_local_ack_result(self):
        receiver=self.receiver();created=[]
        def wrapper(raw):
            raw.detached=True;tls=FakeTLS(raw);created.append(tls)
            tls.close_error=len(created)==1;tls.data=b'HOST'
            return tls
        receiver.context.wrap_hook=wrapper
        receiver.receiver.receive.return_value={'fileCount':1,'localCommit':True}
        with mock.patch.object(transport,'websocket_client',return_value=self.negotiation()), \
                mock.patch.object(transport,'read_headers',return_value=(b'HTTP/1.1 200 OK',{'content-length':'4'})):
            result=receiver.run(lambda request:True)
        self.assertTrue(result['localCommit']);self.assertTrue(result['peer_ack_verified'])
        self.assertEqual(created[1].fileno(),-1);self.assertGreater(created[0].close_calls,0)
        self.assertEqual(receiver._temporary_paths,{})
        self.assertFalse(receiver.closed())
        created[0].close_error=False;self.assertTrue(receiver.close(0))

    def test_receiver_fstat_failure_retains_unknown_fd_and_file_identity(self):
        receiver=self.receiver()
        with mock.patch.object(transport,'websocket_client',return_value=self.negotiation()), \
                mock.patch.object(transport.os,'fstat',side_effect=OSError('HOST_FSTAT_FAILED')):
            with self.assertRaises(OSError):receiver.run(lambda request:True)
        self.assertFalse(receiver.closed());self.assertTrue(receiver.lifecycle_status()['cleanup_pending'])
        self.assertEqual(len(receiver._temporary_fds),1)
        path,identity=next(iter(receiver._temporary_fds.items()))
        self.assertIsNone(receiver._temporary_paths[path]);self.assertEqual(identity[1:],(None,None))
        # Test fixture owns this actual HOST fd; the runtime does not claim a
        # successful cleanup without its missing creation identity evidence.
        os.close(identity[0])
        self.assertFalse(receiver.close(0));self.assertTrue(Path(path).exists())

    def test_receiver_replaced_temporary_file_is_not_unlinked(self):
        receiver=self.receiver();path=Path(self.base.name)/'.mta-download-HOST.zip'
        path.write_bytes(b'HOST');self.register_temporary(receiver,path)
        backup=path.with_suffix('.owned');path.rename(backup);path.write_bytes(b'FOREIGN')
        self.assertFalse(receiver.close(0));self.assertEqual(path.read_bytes(),b'FOREIGN')
        self.assertTrue(receiver.lifecycle_status()['cleanup_pending'])
        path.unlink();backup.rename(path)
        self.assertTrue(receiver.close(0));self.assertFalse(path.exists())

    def test_receiver_symlink_swap_is_not_unlinked(self):
        receiver=self.receiver();path=Path(self.base.name)/'.mta-download-HOST.zip'
        path.write_bytes(b'HOST');self.register_temporary(receiver,path)
        value=os.lstat(str(path))
        changed=mock.Mock(st_mode=0o120777,st_dev=value.st_dev,st_ino=value.st_ino)
        with mock.patch.object(transport.os,'lstat',return_value=changed):self.assertFalse(receiver.close(0))
        self.assertEqual(path.read_bytes(),b'HOST');self.assertTrue(receiver.close(0))

    def test_invalid_receiver_factory_resource_is_closed_but_cannot_claim_verified(self):
        class Unknown:
            def __init__(self):self.calls=0
            def close(self):self.calls+=1
        resource=Unknown();receiver=self.receiver(lambda *args:resource)
        with self.assertRaises(transport.TransportError):receiver.connect()
        self.assertGreater(resource.calls,0);self.assertFalse(receiver.close(0))
        self.assertEqual(receiver.lifecycle_status()['unknown_resources'],1)
        self.assertFalse(receiver.closure_snapshot(resource)['all_sockets_closed'])

    def test_sender_factory_exception_has_no_default_retry(self):
        sender=self.sender()
        sender.listener_factory=lambda *args:(_ for _ in ()).throw(OSError('HOST_FACTORY_FAILED'))
        with self.assertRaises(OSError):sender.start()
        self.assertEqual(sender.lifecycle_status()['socket_records'],0)
        self.assertTrue(sender.close(0));self.assertIsNone(sender._private_directory)

    def test_sender_invalid_factory_resource_is_retained_and_closed(self):
        resource=mock.Mock(spec=['close']);sender=self.sender();sender.listener_factory=lambda *args:resource
        with self.assertRaises(sender_module.SenderError):sender.start()
        resource.close.assert_called();self.assertFalse(sender.close(0))
        self.assertEqual(sender.lifecycle_status()['unknown_resources'],1)
        self.assertFalse(sender.closure_snapshot(resource)['all_sockets_closed'])

    def test_sender_non_socket_with_fd_is_owned_and_exactly_closed(self):
        class NotSocket:
            def __init__(self):self.fd=456;self.calls=0
            def fileno(self):return self.fd
            def close(self):self.calls+=1;self.fd=-1
        resource=NotSocket();sender=self.sender();sender.listener_factory=lambda *args:resource
        with self.assertRaises(sender_module.SenderError):sender.start()
        self.assertEqual(resource.fd,-1);self.assertGreater(resource.calls,0)
        self.assertTrue(sender.close(0));self.assertTrue(sender.closure_snapshot(resource)['recognized_raw'])

    def test_sender_failed_private_cleanup_retries_exact_owned_directory(self):
        sender=self.start_sender();path=sender._private_directory
        with mock.patch.object(sender_module.shutil,'rmtree',side_effect=OSError('HOST_CLEANUP_FAILED')):
            self.assertFalse(sender.close(.01))
        self.assertEqual(sender._private_directory,path);self.assertTrue(os.path.isdir(path))
        self.assertTrue(sender.close(0));self.assertFalse(os.path.lexists(path))

    def test_sender_replaced_private_directory_is_not_removed(self):
        sender=self.start_sender();path=Path(sender._private_directory);backup=Path(str(path)+'.owned')
        path.rename(backup);path.mkdir();(path/'FOREIGN.txt').write_bytes(b'FOREIGN')
        self.assertFalse(sender.close(.01));self.assertTrue((path/'FOREIGN.txt').exists())
        (path/'FOREIGN.txt').unlink();path.rmdir();backup.rename(path)
        self.assertTrue(sender.close(0));self.assertFalse(path.exists())

    def test_sender_symlink_private_directory_is_not_removed(self):
        sender=self.start_sender();path=sender._private_directory
        with mock.patch.object(sender_module.os.path,'islink',return_value=True):self.assertFalse(sender.close(.01))
        self.assertTrue(os.path.isdir(path));self.assertTrue(sender.close(0))

    def test_sender_blocked_listener_worker_is_kept_not_force_cleared(self):
        sender=self.start_sender();sender._listener_thread.blocked=True
        self.assertFalse(sender.close(.01));self.assertTrue(sender._listener_thread.alive)
        self.assertTrue(sender.lifecycle_status()['threads_pending'])
        self.assertIsNotNone(sender._private_directory)
        sender._listener_thread.alive=False
        self.assertTrue(sender.close(0));self.assertIsNone(sender._private_directory)

    def test_sender_late_factory_close_before_adoption_is_retained_and_cleaned(self):
        sender=self.sender();entered,finish=threading.Event(),threading.Event();created=[];errors=[]
        def factory(host,port):
            raw=FakeSocket();raw.bind((host,port));created.append(raw)
            entered.set();finish.wait(2);return raw
        sender.listener_factory=factory
        def run():
            try:sender.start()
            except Exception as error:errors.append(type(error))
        worker=threading.Thread(target=run);worker.start()
        try:
            self.assertTrue(entered.wait(1));self.assertFalse(sender.close(0))
            self.assertTrue(sender.lifecycle_status()['actors_pending'])
        finally:finish.set();worker.join(2)
        self.assertEqual(errors,[transport.Cancelled]);self.assertEqual(created[0].fileno(),-1)
        self.assertIsNone(sender._listener_thread)
        self.assertIsNone(sender._private_directory)
        self.assertTrue(sender.close(0))

    def test_sender_denied_accepted_socket_is_owned_and_never_creates_tls_worker(self):
        sender=self.start_sender();raw=FakeSocket();sender._listener.accepted=[(raw,(SOURCE,55555))]
        sender._accept_loop()
        self.assertEqual(raw.fileno(),-1);self.assertEqual(sender._workers,[])
        self.assertFalse(sender._accepted);self.assertIsNone(sender.result)
        self.assertTrue(sender.close(.01))
        self.assertTrue(sender.closure_snapshot(sender._listener)['all_sockets_closed'])

    def test_sender_accepted_after_close_does_not_launch_worker(self):
        sender=self.start_sender();raw=FakeSocket();sender._allowed_peer_ip=SOURCE
        sender._listener.accepted=[(raw,(SOURCE,55555))]
        sender._listener.accept_hook=lambda:sender.close(0)
        sender._accept_loop()
        self.assertEqual(raw.fileno(),-1);self.assertEqual(sender._workers,[])
        self.assertTrue(sender.close(.01))

    def test_sender_peer_raw_tls_are_retained_for_listener_closure_proof(self):
        sender=self.start_sender();raw=FakeSocket();raw.data=b'GET /other HTTP/1.1\r\n\r\n'
        sender._life.adopt(raw);sender._connections.add(raw)
        def wrapper(value):
            value.detached=True;tls=FakeTLS(value);tls.data=b'GET /other HTTP/1.1\r\n\r\n'
            sender._context.wrappers.append(tls);return tls
        sender._context.wrap_hook=wrapper
        sender._handle_connection(raw,SOURCE)
        self.assertEqual(raw.fileno(),-1)
        self.assertEqual(sender._context.wrappers[0].fileno(),-1)
        self.assertTrue(sender.close(.01))
        self.assertTrue(sender.closure_snapshot(sender._listener)['all_sockets_closed'])

    def test_sender_close_errors_do_not_skip_other_tls_or_private_cleanup(self):
        sender=self.start_sender();raw=FakeSocket();sender._life.adopt(raw);raw.close_error=True
        other=FakeSocket();sender._life.adopt(other)
        self.assertFalse(sender.close(.01));self.assertEqual(other.fileno(),-1)
        self.assertIsNone(sender._private_directory)
        raw.close_error=False;self.assertTrue(sender.close(0))

    def test_sender_current_actual_worker_is_not_joined_or_declared_exited(self):
        sender=self.sender();observed=[]
        def run():
            actor=sender._life.begin('HOST-peer')
            sender._life.end(actor)
            observed.append(sender.close(0));observed.append(sender.closed())
        worker=threading.Thread(target=run);sender._life.start_thread(worker);worker.join(2)
        self.assertFalse(worker.is_alive());self.assertEqual(observed,[False,False])
        self.assertTrue(sender.close(0))

    def test_sender_callback_exception_does_not_skip_closing_owned_sockets(self):
        sender=self.start_sender();sender.callback=lambda *args:(_ for _ in ()).throw(RuntimeError('HOST_PRIVATE_CALLBACK'))
        self.assertTrue(sender.close(.01));self.assertEqual(sender._listener.fileno(),-1)
        self.assertNotIn('HOST_PRIVATE',repr(sender.lifecycle_status()))

    def test_sender_completed_result_is_not_replaced_by_lifecycle_close(self):
        sender=self.start_sender();sender._accepted=True;sender._download_complete=True
        sender._archive_size=4;sender._downloaded_bytes=4;sender._file_count=1;sender._actual_bytes=4
        ws=mock.Mock()
        sender._status(ws,WsMessage('action',2,'status',{'taskId':sender.task_id,'id':sender.task_id,'type':1}))
        self.assertTrue(sender.result['peer_completion_verified']);saved=dict(sender.result)
        self.assertTrue(sender.close(.01));self.assertEqual(sender.result,saved);self.assertEqual(sender.state,'completed')

    def test_receiver_or_sender_public_status_has_no_socket_path_peer_identifiers(self):
        receiver=self.receiver();receiver.connect();sender=self.start_sender()
        for value in (receiver,sender):
            status=value.lifecycle_status()
            self.assertNotIn(self.base.name,repr(status));self.assertNotIn(HOST,repr(status))
            self.assertTrue(set(status).issubset({'closing','socket_records','sockets_pending','actors_pending',
                'threads_pending','wrappers_pending','unknown_wrappers','unknown_resources','processes_pending','close_verified','cleanup_pending'}))

    def test_runtime_sources_still_parse_python35_without_scoped_or_global_ops(self):
        for module in (transport,sender_module):
            source=Path(module.__file__).read_text(encoding='utf-8')
            ast.parse(source,feature_version=(3,5))
            self.assertNotIn('import mta_scoped_sockets',source)
            self.assertNotIn('killall',source)
            self.assertNotIn('net.connman',source)


if __name__=='__main__':unittest.main()
