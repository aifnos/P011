"""Fixed-action loopback service. Booting it does not change radio state."""
import base64
import hmac
import os
import re
import subprocess
import threading
import time
import uuid
from collections import namedtuple

import p011_json as json
import minhttp
from mta_crypto import OpenSslCrypto
from mta_files import FileRegistry,MAX_TOTAL
from mta_protocol import DeviceInfo, P2pInfo, encode_advertisement
from mta_storage import SafeZipReceiver
from mta_transport import ReceiverTransport
from mta_wifi import WifiBackend,NetworkInfo
from mta_transfer_session import TransferSession,Outcome,SendOutcome,SessionError
from mta_scan_handoff import ScanSession,SendIntent,ScanHandoffError
from mta_send_worker import SendWorker,SendResult,SendWorkerError,CreationTicket


SendRestoreReceipt=namedtuple('SendRestoreReceipt',
    'provider lease operation_epoch task_id baseline_verified journal_reconciled actors_closed resources_closed')
_SEND_STATUS_FIELDS=frozenset(('stage','reason','cancel_requested','run_returned','creation_pending','creation_unknown',
    'unresolved_unknown','owner_records','handoff_count','ignored_native_events','scope_released','extra_resources_closed',
    'network_restore_required','archiveBytesSent','bytes','archiveSize','fileCount','totalSize','localBytesVerified',
    'peerCompletionVerified','platform_available'))
_SendSkipped=namedtuple('_SendSkipped','owner session helper scan intent epoch thread')


class _SendHooks(object):
    """Exact private ticket registration; no callback=True owner grants."""
    def __init__(self,state,op):self.state=state;self.op=op
    def _exact(self,ticket):
        state,op=self.state,self.op
        if (op is not state.operation or op.session is not state.session or op.epoch!=state.native_epoch or
            type(ticket) is not CreationTicket or ticket.worker is not op.send_worker):
            op.actor_unknown=True;raise ValueError('Send owner changed')
    def claim(self,ticket):
        with self.state.lock:
            self.op.send_tickets.append(ticket) # Retain even an invalid registration result.
            self._exact(ticket)
            if len(self.op.send_tickets)>32:raise ValueError('Send owner limit')
            return ticket
    def adopt(self,ticket):
        with self.state.lock:
            self._exact(ticket)
            if not any(value is ticket for value in self.op.send_tickets):raise ValueError('Send ticket missing')
            if ticket.kind=='lease':
                if self.op.send_lease is not None and self.op.send_lease is not ticket.resource:
                    self.op.actor_unknown=True;raise ValueError('Send lease changed')
                self.op.send_lease=ticket.resource
                self.state.wifi_restore_pending=True
            return ticket
    def attach_transport(self,ticket,transport):
        with self.state.lock:
            self._exact(ticket)
            if ticket.resource is not transport:raise ValueError('Send transport changed')
            self.op.transport=transport;self.state.transport=transport;session=self.op.session
        session.attach_transport(transport)
        return ticket
    def handoff(self,ticket,transport,raw):
        with self.state.lock:
            self._exact(ticket)
            if ticket.resource is not raw or transport is not self.op.transport:raise ValueError('Send raw changed')
            session=self.op.session
        session.register_handoff(transport,raw)
        return ticket


def _probe_closed(actor):
    process=actor['process']
    try:
        return (actor['spawn_pending'] is False and actor['spawn_unknown'] is False and process is not None and
                process.poll() is not None and process.stdout is actor['stdout'] and process.stderr is actor['stderr'] and
                actor['stdout'].closed is True and actor['stderr'].closed is True)
    except BaseException:return False


def capability(helper,args,actors=None):
    if not os.path.isabs(helper) or not os.path.isfile(helper):return {}
    actor={'process':None,'stdout':None,'stderr':None,'spawn_pending':True,'spawn_unknown':False,'closed':False}
    if actors is not None:actors.append(actor)
    try:
        try:
            process=subprocess.Popen([helper]+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            actor['process']=process
            actor['stdout']=process.stdout;actor['stderr']=process.stderr
        except BaseException:actor['spawn_unknown']=True;raise
        finally:actor['spawn_pending']=False
        out,err=process.communicate(timeout=12)
        if process.returncode or len(out)>16384:return {}
        lines=out.decode('utf-8').splitlines()
        if len(lines)!=1:return {}
        result=json.loads(lines[0])
        return result if isinstance(result,dict) else {}
    except BaseException:
        process=actor['process']
        if process is not None:
            try:process.kill();process.communicate(timeout=3)
            except BaseException:pass
        return {}
    finally:
        actor['closed']=_probe_closed(actor)


class PrivateHelper(object):
    def __init__(self,path,callback):
        self.path=path;self.callback=callback;self.lock=threading.RLock();self.closed=False
        self.command_note=None
        self.process=None;self.spawn_claimed=False;self.spawn_resolved=False;self.spawn_unknown=False
        self.reader_claimed=False;self.reader_resolved=False;self.reader_unknown=False
        self.thread=threading.Thread(target=self.read);self.thread.daemon=True

    def start(self):
        # State retains this pure owner before Popen or Thread.start can act.
        with self.lock:
            if self.spawn_claimed:raise ValueError('Helper cannot start twice')
            self.spawn_claimed=True
        try:
            self.process=subprocess.Popen([self.path,'--serve','hci0'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        except BaseException:self.spawn_unknown=True;raise
        finally:self.spawn_resolved=True
        self.reader_claimed=True
        try:self.thread.start()
        except BaseException:self.reader_unknown=True;raise
        finally:self.reader_resolved=True

    def read(self):
        try:
            while not self.reader_resolved:
                if self.reader_unknown:return
                time.sleep(.005)
            if self.reader_unknown:return
            while not self.closed:
                line=self.process.stdout.readline(16385)
                if not line:break
                if len(line)>16384 or not line.endswith(b'\n'):raise ValueError('Native IPC limit')
                event=json.loads(line.decode('utf-8'))
                if not isinstance(event,dict):raise ValueError('Native IPC object required')
                self.callback(event)
        except (ValueError,OSError):self.callback({'event':'error','code':'native_ipc_invalid'})
        finally:
            self.callback({'event':'closed'})

    def send(self,value):
        with self.lock:
            if self.closed or self.process is None or self.process.poll() is not None:raise ValueError('Native helper is not running')
            if self.command_note is not None:self.command_note(value)
            data=(json.dumps(value)+'\n').encode('ascii')
            if len(data)>8192:raise ValueError('Native IPC limit')
            self.process.stdin.write(data);self.process.stdin.flush()

    def close(self):
        with self.lock:
            if self.process is None:return self.closure_verified()
            if not self.closed:
                try:self.send({'cmd':'stop'})
                except (OSError,ValueError):pass
            self.closed=True
            try:self.process.stdin.close()
            except (OSError,ValueError):pass
        try:
            try:self.process.wait(timeout=18)
            except subprocess.TimeoutExpired:
                # Terminate only our own Popen handle, never kill by global name.
                self.process.terminate()
                try:self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        except BaseException:pass # Keep ownership and still try independent pipe/reader cleanup.
        if self.thread is not threading.current_thread() and self.reader_resolved:
            try:self.thread.join(2)
            except (RuntimeError,ValueError):pass
        if not self.thread.is_alive():
            try:self.process.stdout.close()
            except (OSError,ValueError):pass
        return self.closure_verified()

    def closure_verified(self):
        if self.spawn_unknown or self.reader_unknown:return False
        if self.spawn_claimed and not self.spawn_resolved:return False
        if self.reader_claimed and not self.reader_resolved:return False
        if self.thread.is_alive():return False
        if self.process is None:return not self.spawn_claimed
        try:return (self.process.poll() is not None and self.process.stdin.closed is True and
                    self.process.stdout.closed is True)
        except Exception:return False


class Operation(object):
    """Private exact owner; no identifiers or payloads reach public status."""
    def __init__(self,backend,epoch,kind):
        self.backend=backend;self.epoch=epoch;self.kind=kind
        self.cancelled=threading.Event();self.input_ready=threading.Event();self.listen_ready=threading.Event()
        self.lease=None;self.helper=None;self.key=None;self.crypto=None;self.transport=None
        self.info=None;self.result=None;self.failure='';self.session=None
        self.stage='connecting';self.actor_unknown=False;self.consent=kind=='receive'
        self.recovery_requested=False
        self.scan=None;self.send_ready=threading.Event();self.send_intent=None;self.send_worker=None
        self.send_provider=None;self.send_lease=None;self.send_tickets=[];self.send_result=None
        self.send_factory=None;self.send_construct_pending=False;self.send_construct_unknown=False
        self.send_restore_receipt=None;self.send_restore_readback=None
        self.send_bytes_observed=False
        self._send_skip=None # Saved only by the actual task's pre-factory return.
        self.lock=threading.RLock()


class State(object):
    def __init__(self,user_root,bluez_helper,network_helper,openssl='/usr/bin/openssl',send_provider=None):
        self.lock=threading.RLock();self.token=uuid.uuid4().hex+uuid.uuid4().hex
        self.registry=FileRegistry(user_root)
        self.received_root=os.path.join(user_root,'Received')
        if not os.path.exists(self.received_root):os.mkdir(self.received_root,0o700)
        self.receiver=SafeZipReceiver(self.received_root)
        self.bluez_path=bluez_helper;self.network_path=network_helper;self.openssl=openssl
        self.nickname='P011';self.sender_id=os.urandom(2)
        self.helper=None;self.key=None;self.crypto=None;self.lease=None;self.worker=None
        self.session=None;self.operation=None;self.transport=None;self.history=[]
        self.wifi_backend=WifiBackend(network_helper)
        self.wifi_restore_pending=False;self.radio_restore_pending=False;self.native_epoch=0
        self.cancelled=threading.Event();self.decision=threading.Event();self.accepted=False
        self.devices={};self.peer_seen={};self.request=None;self.transfer={};self.received=[]
        self.state='idle';self.reason='';self.discoverable=False;self.scanning=False
        self.radio_deadline=0;self.event_counts={};self.closing=False
        self.probe_actors=[]
        self.bluetooth_caps=capability(bluez_helper,['--capabilities','hci0'],actors=self.probe_actors)
        self.network_caps=capability(network_helper,['--capabilities'],actors=self.probe_actors) if self._probes_closed() else {}
        self.receive_available=bool(self.bluetooth_caps.get('powered') and self.bluetooth_caps.get('features') and self.bluetooth_caps.get('connectable_advert') and
                                    self.bluetooth_caps.get('bredr_enabled') is True and self.bluetooth_caps.get('le_enabled') is True and
                                    self.bluetooth_caps.get('global_advertising') is False and
                                    self.bluetooth_caps.get('max_adv',0)>=31 and self.bluetooth_caps.get('max_scan',0)>=31 and
                                    self.bluetooth_caps.get('bluez_advertising_known') and not self.bluetooth_caps.get('bluez_advertising_active') and
                                    self.bluetooth_caps.get('active_instances')==0 and self.network_caps.get('receive'))
        self.scan_available=bool(self.bluetooth_caps.get('powered'))
        self.send_available=False # Explicit until verified P2P/network sender backend exists.
        self._send_provider=send_provider # Trusted internal only; presence never enables the public gate.
        if not self._probes_closed():
            self.receive_available=False;self.scan_available=False;self.radio_restore_pending=True
        if not self.receive_available:self.reason='广播或网络接收能力尚未就绪；未修改系统无线状态'
        if self.bluetooth_caps.get('powered') and self.network_caps.get('ok') and not self.network_caps.get('receive'):
            self.reason='蓝牙可用；网络接收的归属与恢复尚未确认，暂不切换 Wi-Fi'
        pending=self.wifi_status()
        if pending.get('restorePending') or pending.get('recoveryLocked'):
            self.wifi_restore_pending=True;self.receive_available=False
            self.state='error';self.reason=pending.get('reason') or '上次网络租约恢复待核验，请先检查恢复'

    def wifi_status(self):
        try:return self.wifi_backend.status()
        except Exception:return {'restorePending':True,'recoveryLocked':True,'reason':'网络恢复记录无法核实'}

    def _probes_closed(self):
        return all(row['spawn_pending'] is False and row['spawn_unknown'] is False and row['closed'] is True
                   for row in self.probe_actors)

    def _close_probes(self):
        # Explicit finalizer only; these fixed --capabilities actors are
        # read-only. Never terminate a receive/mutation helper in this path.
        for row in self.probe_actors:
            if row['closed'] is True:continue
            process=row['process']
            if row['spawn_pending'] or row['spawn_unknown'] or process is None:continue
            try:
                if process.poll() is None:process.kill()
                process.communicate(timeout=3)
            except BaseException:pass
            for name in ('stdout','stderr'):
                try:
                    if process.poll() is not None and getattr(process,name) is row[name]:row[name].close()
                except BaseException:pass
            row['closed']=_probe_closed(row)
        return self._probes_closed()

    def status(self):
        with self.lock:
            now=time.monotonic()
            session=self.session.status() if self.session is not None else None
            op=self.operation
            scan=op.scan.status() if op is not None and op.scan is not None else None
            sending=op is not None and op.kind=='send'
            send_status=op.send_worker.status() if sending and isinstance(op.send_worker,SendWorker) else None
            state=self.state;reason=self.reason;pending=self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()
            discoverable=self.discoverable;scanning=self.scanning
            if session is not None:
                pending=pending or not session['closed']
                if session['closed']:
                    discoverable=False;scanning=False
                    if sending and session['phase']=='completed':state='completed';reason='已发送并收到对端协议完成；手机界面仍需人工核对'
                    elif sending and session['phase']=='sent_unconfirmed':state='error';reason='已发送字节；未收到对端完成确认，请勿重复发送'
                    elif sending and session['phase']=='failed':state='error';reason='发送未完成；资源已关闭，没有报告成功'
                    elif session['phase']=='completed':state='completed';reason='文件已保存；手机端完成提示仍需人工核对'
                    elif session['phase']=='saved_unconfirmed':state='error';reason='文件已保存；未收到手机完成确认，请勿重复传输'
                    elif session['phase']=='failed':state='error';reason='接收未完成；资源已关闭，没有报告传输成功'
                    else:state='idle'
                elif session['phase'] in ('pending','awaiting_finalizer_exit','transport_close','release','extra','restore'):
                    state='restoring';reason='资源关闭与网络恢复仍待核验；请勿重复开启互传'
            transfer=dict(self.transfer)
            if send_status is not None:
                transfer={'direction':'send','bytes':send_status['bytes'],'totalBytes':send_status['archiveSize'],
                    'archiveBytesSent':send_status['archiveBytesSent'],'totalFiles':send_status['fileCount'],
                    'payloadTotalBytes':send_status['totalSize'],'localBytesVerified':send_status['localBytesVerified'],
                    'peerCompletionVerified':send_status['peerCompletionVerified']}
                if session is not None and not session['closed'] and not state=='restoring':
                    state='transferring' if send_status['stage']=='transferring' else 'connecting'
            devices=[]
            for key,row in self.devices.items():
                devices.append(dict(row,available=scanning and (scan is None or scan['selectable']) and now-self.peer_seen.get(key,0)<15))
            return {'state':state,'nickname':self.nickname,'devices':devices,
                    'request':dict(self.request) if self.request else None,'transfer':transfer,
                    'received':list(self.received),'reason':reason,
                    'discoverable':discoverable,'scanning':scanning,
                    'restorePending':pending,'sessionLifecycle':session,
                    'scanLifecycle':scan,'sendLifecycle':send_status,
                    'networkRecovery':self.wifi_status(),
                    'capabilities':{'receive':{'available':self.receive_available,'reason':self.reason},
                                    'send':{'available':self.send_available,'reason':'发送端 P2P/AP 与恢复能力尚未实机验证'},
                                    'scan':self.scan_available,'rename':not pending and not discoverable and not scanning}}

    def action(self,value):
        if not isinstance(value,dict):raise ValueError('Action object required')
        action=value.get('action')
        fields={'discover_start':set(),'discover_stop':set(),'scan':set(),'scan_stop':set(),
                'accept':{'requestId'},'reject':{'requestId'},'cancel':set(),'recover':set(),'send':{'deviceId','fileIds'},'rename':{'nickname'}}
        if action not in fields or set(value)!=fields[action]|{'action'}:raise ValueError('Action not permitted')
        operation=None;close_session=None
        with self.lock:
            if self.closing:raise ValueError('Service is closing')
            busy=(self.session is not None and not self.session.closed()) or self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()
            if action in ('accept','reject'):
                if not self.request or value['requestId']!=self.request['id']:raise ValueError('Incoming request changed')
                self.accepted=action=='accept';self.decision.set()
            elif action in ('cancel','discover_stop','scan_stop'):
                self.cancelled.set();self.decision.set()
                if self.operation:
                    self.operation.input_ready.set();self.operation.send_ready.set()
                    if self.operation.scan is not None:self.operation.scan.cancel()
                close_session=self._cleanup_session_locked()
            elif action=='recover':
                close_session=self._cleanup_session_locked(recovery=True)
                self.operation.recovery_requested=True
            elif action=='rename':
                if busy:raise ValueError('Stop discovery before changing the device name')
                name=value['nickname']
                if not isinstance(name,str) or not name.strip() or len(name.encode('utf-8'))>64 or any(ord(c)<32 for c in name):raise ValueError('Invalid nickname')
                self.nickname=name.strip()
            elif action=='discover_start':
                if busy or not self.receive_available:raise ValueError('Receive unavailable or busy')
                operation=self._new_operation_locked('receive')
            elif action=='scan':
                if busy or not self.scan_available:raise ValueError('Scan unavailable or busy')
                self.devices={};self.peer_seen={};operation=self._new_operation_locked('scan')
            elif action=='send':
                op=self.operation
                if (not self.send_available or not self._send_provider_ready() or op is None or op.kind!='scan' or
                    op.scan is None or op.session is not self.session or op.epoch!=self.native_epoch or
                    op.cancelled.is_set() or self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()):
                    raise ValueError('Sender network backend is not yet verified')
                try:op.send_intent=op.scan.claim_intent(value['deviceId'],value['fileIds'],uuid.uuid4().hex)
                except ScanHandoffError:raise ValueError('Fresh scan selection required')
                op.send_provider=self._send_provider;op.kind='send';self.transfer={};self.state='connecting'
                op.send_ready.set()
        # Thread start, joins, helper stop and restoration never hold State.lock.
        if operation:
            try:operation.session.start()
            except SessionError:
                if not operation.cancelled.is_set():raise ValueError('Owned session could not start')
        if close_session:close_session.close(timeout=2)
        return self.status()

    def start_receive(self):
        return self.action({'action':'discover_start'})

    def _new_operation_locked(self,kind):
        if self.session is not None and not self.session.closed():raise ValueError('Owned session cleanup pending')
        if self.operation is not None:self.history.append(self.operation)
        self.native_epoch+=1
        op=Operation(self.wifi_backend,self.native_epoch,kind)
        op.session=TransferSession(lambda session:self._run_operation(op,session),self._restore_owner,op,
                                   extra_actor_close=self._close_extra,task_timeout=300,finalize_timeout=120,
                                   cancelled=op.cancelled,direction='send' if kind=='scan' else 'receive',
                                   scoped_owner=op if kind=='scan' else None,
                                   scoped_release=self._release_send if kind=='scan' else None)
        self.operation=op;self.session=op.session;self.worker=op.session._worker
        self.helper=None;self.key=None;self.crypto=None;self.lease=None;self.transport=None
        self.cancelled=op.cancelled;self.decision=threading.Event();self.accepted=False;self.request=None
        self.discoverable=False;self.scanning=False;self.state='connecting';self.reason=''
        return op

    def _cleanup_session_locked(self,recovery=False):
        if self.session is not None and not self.session.closed():return self.session
        # A send owner must never be projected into the receive cleanup aliases,
        # even by a redundant recover request after it already closed.
        if self.session is not None and self.operation.kind=='send':return self.session
        if self.session is not None and not recovery and not self.wifi_restore_pending and not self.radio_restore_pending:return self.session
        # Explicit cleanup of legacy exact aliases, not a new radio/network task.
        helper,key,lease=self.helper,self.key,self.lease
        op=self._new_operation_locked('cleanup')
        op.helper=helper;op.key=key;op.lease=lease
        self.helper=helper;self.key=key;self.lease=lease
        return op.session

    def new_helper(self,op=None):
        op=op or self.operation
        if op is None or op is not self.operation or op.helper is not None:raise ValueError('Exact helper owner required')
        helper=PrivateHelper(self.bluez_path,lambda event:self.native_event(event,op.epoch,helper))
        helper.command_note=lambda value:self._note_send_command(op,helper,value)
        op.helper=helper
        with self.lock:self.helper=helper
        helper.start()
        return helper

    def _note_send_command(self,op,helper,value):
        if value.get('cmd')=='client_read':
            if (op is not self.operation or helper is not op.helper or op.epoch!=self.native_epoch or
                op.scan is None or type(op.send_intent) is not SendIntent):raise ValueError('Scan owner changed')
            if op.scan.note_client_read(op.send_intent.handoff,value) is not op.send_intent:
                raise ValueError('Scan command registration changed')

    def _make_send_worker(self,op):
        intent=op.send_intent
        return SendWorker(intent.handoff,self.registry,list(intent.file_ids),provider=op.send_provider,
                          openssl=self.openssl,sender_name=self.nickname,cancelled=op.cancelled)

    def _send_provider_ready(self):
        try:
            return self._send_provider is not None and all(callable(getattr(self._send_provider,name,None)) for name in
                ('reserve','activate','read_network','wait_association','read_association','close_extra','extra_closed',
                 'restore_owned','read_restored'))
        except BaseException:return False

    def _run_scan_send(self,op,session):
        helper=self.new_helper(op)
        start=time.monotonic()
        op.scan=ScanSession(helper,op.epoch,op.epoch,start,ttl=30,cancelled=op.cancelled)
        helper.send({'cmd':'scan','adapter':'hci0','ttl':30})
        stop=start+35
        while not op.cancelled.is_set() and time.monotonic()<stop:
            if op.send_ready.wait(.1):break
        if op.cancelled.is_set() or op.send_intent is None:
            op._send_skip=_SendSkipped(op,session,helper,op.scan,op.send_intent,op.epoch,threading.current_thread())
            return SendOutcome(None,False,False)
        with self.lock:
            if op is not self.operation or op.epoch!=self.native_epoch:raise ValueError('Send operation changed')
            op.send_factory=self._make_send_worker;op.send_construct_pending=True
        try:
            op.send_worker=op.send_factory(op) # Retain before hooks or task execution.
            if not isinstance(op.send_worker,SendWorker):raise ValueError('Send worker contract changed')
        except BaseException:
            op.send_construct_unknown=True;raise
        finally:op.send_construct_pending=False
        try:result=op.send_worker.run(_SendHooks(self,op))
        except SendWorkerError:
            # Preserve actual ZIP-byte evidence when completion is missing.
            # No exception or progress label can manufacture a peer ACK.
            try:
                observed=op.send_worker.status()
                bytes_known=(type(observed) is dict and set(observed)==_SEND_STATUS_FIELDS and
                    observed['run_returned'] is True and observed['localBytesVerified'] is True and
                    observed['peerCompletionVerified'] is False and
                    all(type(observed[key]) is int and 0<observed[key]<=MAX_TOTAL for key in
                        ('bytes','archiveSize','archiveBytesSent')) and
                    observed['bytes']==observed['archiveSize']==observed['archiveBytesSent'])
            except BaseException:bytes_known=False
            op.send_bytes_observed=bytes_known
            if bytes_known:
                op.failure='已发送字节；没有对端完成确认'
                return SendOutcome(None,True,False)
            raise
        op.send_result=result
        if type(result) is not SendResult or type(result.local_bytes_verified) is not bool or type(result.peer_completion_verified) is not bool:
            raise ValueError('Send result changed')
        op.send_bytes_observed=result.local_bytes_verified
        return SendOutcome(result,result.local_bytes_verified,result.peer_completion_verified)

    def _release_send(self,op,handoffs,snapshots):
        if op is not self.operation or op.send_construct_pending or op.send_construct_unknown or op.actor_unknown:return False
        if op.send_worker is None:
            if op.kind=='send':return not handoffs and not snapshots and self._send_skip_exact(op)
            return op.send_intent is None and not handoffs and not op.send_tickets
        return op.send_worker.release_scoped() is True

    def _send_skip_exact(self,op):
        # This is a saved execution fact, never a caller/UI ready bool. A task
        # returning early is not enough until its exact real thread has exited.
        try:
            row=op._send_skip;session=op.session
            status=session.status()
            return (type(row) is _SendSkipped and row.owner is op and op is self.operation and
                row.session is session and session is self.session and row.helper is op.helper and
                row.helper is self.helper and row.scan is op.scan and type(row.scan) is ScanSession and
                row.intent is op.send_intent and type(row.intent) is SendIntent and
                type(row.epoch) is int and row.epoch==op.epoch==self.native_epoch and
                row.thread is session._worker and row.thread is self.worker and row.thread.is_alive() is False and
                status['worker_alive'] is False and status['worker_start_pending'] is False and
                status['worker_start_unknown'] is False and
                all(type(status[key]) is int and status[key]==0 for key in
                    ('transport_count','handoff_count','unknown_owner_count')) and
                op.send_factory is None and op.send_worker is None and op.send_construct_pending is False and
                op.send_construct_unknown is False and op.actor_unknown is False and
                type(op.send_tickets) is list and not op.send_tickets and
                op.transport is None and self.transport is None and op.send_lease is None and
                op.lease is None and self.lease is None and op.key is None and op.crypto is None and
                op.backend is self.wifi_backend and op.backend._active_lease is None)
        except BaseException:return False

    def start_watchdog(self):
        # Deadline/cancellation lives in the exact Session worker; no detached
        # watchdog may restore while the worker or a late producer is alive.
        return None

    def _run_operation(self,op,session):
        if op.kind=='cleanup':return Outcome(None,False,False)
        try:
            if op.kind in ('scan','send'):return self._run_scan_send(op,session)
            # Exact lease is registered BEFORE spawn, including prepare failure.
            op.lease=op.backend.begin_prepare(op.cancelled.is_set,timeout=180)
            with self.lock:self.lease=op.lease;self.wifi_restore_pending=True
            op.lease.prepare()
            if op.cancelled.is_set():return Outcome(None,False,False)
            op.crypto=OpenSslCrypto(self.openssl);op.key=op.crypto.generate_keypair()
            with self.lock:self.crypto=op.crypto;self.key=op.key
            with open('/sys/class/net/wlan0/address') as source:mac=source.read(64).strip()
            status=DeviceInfo(mac,op.key.public_key).to_bytes()
            helper=self.new_helper(op)
            with self.lock:op.stage='listen_pending'
            helper.send({'cmd':'listen','adapter':'hci0','status_b64':base64.b64encode(status).decode('ascii')})
            deadline=time.monotonic()+120
            while not op.cancelled.is_set() and time.monotonic()<deadline:
                if op.listen_ready.wait(.1):break
            with self.lock:
                if (op is not self.operation or op.epoch!=self.native_epoch or op.helper is not helper or
                    op.cancelled.is_set() or not op.listen_ready.is_set() or op.stage!='listen_ready'):
                    return Outcome(None,False,False)
                packet=encode_advertisement(self.sender_id,1,self.nickname,False)
                op.stage='advert_pending'
            # Reader callbacks only signal readiness; pipe IO belongs to this exact worker.
            helper.send({'cmd':'advert','adapter':'hci0','adv_b64':base64.b64encode(packet['adv_data']).decode('ascii'),
                         'scan_b64':base64.b64encode(packet['scan_rsp']).decode('ascii'),'ttl':120})
            while not op.cancelled.is_set() and time.monotonic()<deadline:
                if op.input_ready.wait(.1):break
            if op.cancelled.is_set() or not op.input_ready.is_set() or op.info is None:return Outcome(None,False,False)
            info=op.crypto.decrypt_credentials(op.info,op.key) if op.info.key is not None else op.info
            network=NetworkInfo.from_p2p_info(info)
            with self.lock:
                if op is not self.operation or op.epoch!=self.native_epoch or not op.consent or not self.receive_available:
                    raise ValueError('Receive consent or owner changed')
                self.discoverable=False;self.state='connecting'
            if op.backend._active_lease is not op.lease or not op.lease.prepared or op.cancelled.is_set():
                raise ValueError('Prepared exact lease required')
            # No backend.receive fallback or exception-triggered inline restore.
            op.lease.connect(network)
            transport=ReceiverTransport(op.lease.gateway,info.port,self.receiver,op.cancelled.is_set)
            op.transport=transport;session.attach_transport(transport)
            with self.lock:self.transport=transport
            def progress(count):
                with self.lock:
                    if op is self.operation:self.transfer['archiveBytes']=count
            def files_progress(count,total):
                with self.lock:
                    if op is self.operation:self.transfer['bytes']=count
            result=transport.run(self.confirm,progress,files_progress)
            op.result=result
            with self.lock:
                self.transfer.update(bytes=result.get('totalSize',0),filesDone=result.get('fileCount',0),
                                     localCommitVerified=True,peerAckVerified=result.get('peer_ack_verified') is True)
                try:self.received=[f for f in self.registry.list_files() if f['name'].startswith('Received/')]
                except (ValueError,OSError):self.reason='文件已保存；目录刷新失败，可进入文件中心查看'
            return Outcome(result,True,result.get('peer_ack_verified') is True)
        except BaseException:
            op.failure='发送未完成；未报告传输成功' if op.kind=='send' else '接收未完成；未报告传输成功'
            raise
        finally:
            with self.lock:
                if op is self.operation:self.state='restoring';self.request=None

    def native_event(self,event,epoch=None,helper=None):
        if type(event) is not dict or (epoch is not None and type(epoch) is not int):return
        name=event.get('event');code=event.get('code')
        with self.lock:
            op=self.operation
            if (op is None or op.helper is None or self.closing or (helper is not None and helper is not op.helper) or
                (epoch is not None and epoch!=op.epoch) or op.epoch!=self.native_epoch):return
            scan_accepted=None
            if op.scan is not None:
                scan_accepted=op.scan.native_event(event,op.helper if helper is None else helper,op.epoch,op.epoch)
                scan=op.scan.status();self.scanning=scan['native_scan_active'] and not scan['invalidated']
                if self.scanning and op.kind=='scan':self.state='scanning'
            if op.send_worker is not None:
                op.send_worker.native_event(event,op.helper if helper is None else helper,op.epoch,op.epoch)
            if name in ('listen','advert','scan','peer','discovered','p2p','error','closed','stop'):
                self.event_counts[name]=self.event_counts.get(name,0)+1
            if name=='listen' and code=='ready' and op.kind=='receive' and op.key is not None and not self.cancelled.is_set() and op.stage=='listen_pending':
                op.stage='listen_ready';op.listen_ready.set()
            elif name=='advert' and code=='ready' and op.kind=='receive' and not self.cancelled.is_set() and op.stage=='advert_pending':
                op.stage='advertising';self.state='advertising';self.discoverable=True
            elif name=='p2p' and self.discoverable and not op.cancelled.is_set() and not op.input_ready.is_set():
                try:
                    wire=base64.b64decode(event['payload_b64'].encode('ascii'),validate=True)
                    info=P2pInfo.from_bytes(wire)
                    if not info.key:raise ValueError('Encrypted credential exchange is required')
                    self.discoverable=False;self.state='connecting'
                    op.info=info;op.input_ready.set()
                except Exception:self.reason='握手字段或加密校验未通过；没有连接该网络'
            elif name=='discovered':
                # Native scanner must mark cached=false; stale cache never enables send.
                if self.scanning and scan_accepted is not False and event.get('cached') is False and isinstance(event.get('peer'),int) and not isinstance(event.get('peer'),bool) and 1<=event['peer']<=65535:
                    key=str(event['peer'])
                    try:label=base64.b64decode(event.get('name_b64','').encode('ascii'),validate=True).decode('utf-8')
                    except (ValueError,UnicodeError):label='附近互传设备'
                    self.devices[key]={'id':key,'name':label[:80]};self.peer_seen[key]=time.monotonic()
            elif name in ('closed','stop'):
                self.cancelled.set();self.decision.set()
                op.input_ready.set();self.discoverable=False;self.scanning=False
            elif name=='error':
                self.reason='无线辅助进程未完成操作；正在核验资源恢复'
                self.cancelled.set();self.decision.set();op.input_ready.set()

    def confirm(self,request):
        with self.lock:
            self.request={'id':request['taskId'],'name':request['senderName'],
                          'fileCount':request['fileCount'],'totalBytes':request['totalSize']}
            self.transfer={'bytes':0,'totalBytes':request['totalSize'],'filesDone':0,'totalFiles':request['fileCount']}
            self.state='awaiting_confirmation';self.accepted=False;self.decision.clear()
        deadline=time.monotonic()+60
        while not self.cancelled.is_set() and time.monotonic()<deadline:
            if self.decision.wait(.25):break
        with self.lock:
            allowed=self.accepted and not self.cancelled.is_set() and time.monotonic()<deadline
            self.request=None
            if allowed:self.state='transferring'
            return allowed

    def receive(self,info):
        # Trusted already-decrypted producer API, never an HTTP/QML action.
        NetworkInfo.from_p2p_info(info)
        with self.lock:
            op=self.operation
            if (op is None or op.kind!='receive' or not op.consent or not self.receive_available or
                op.lease is None or not op.lease.prepared or op.cancelled.is_set() or op.input_ready.is_set()):
                raise ValueError('Explicit prepared receive session required')
            op.info=info;op.input_ready.set();self.discoverable=False;self.state='connecting'
        return op.session

    def restore_network(self):
        # Compatibility entry also converges on the external same-owner path.
        with self.lock:session=self._cleanup_session_locked()
        return session.close(timeout=2) is True

    def stop_radio(self):
        with self.lock:session=self._cleanup_session_locked()
        return session.close(timeout=2) is True

    def _close_extra(self,op):
        if op is not self.operation or op.backend is not self.wifi_backend:return False
        helper_ok=True
        send_ok=True
        if op.send_worker is not None:
            # SendWorker is the sole closer for helper/key/selection/provider
            # actors. Do not re-close its originals through receive aliases.
            try:
                send_ok=(op.send_worker.close_extra() is True and
                         op.send_worker.status()['extra_resources_closed'] is True)
                helper_ok=op.helper is not None and op.helper.closure_verified() is True
            except BaseException:send_ok=False;helper_ok=False
        elif op.helper is not None:
            try:helper_ok=op.helper.close() is True and op.helper.closure_verified() is True
            except BaseException:helper_ok=False
        key_ok=True
        if op.key is not None and op.send_worker is None:
            if not helper_ok:key_ok=False
            else:
                try:op.key.close();key_ok=op.key.closed is True
                except BaseException:op.actor_unknown=True;key_ok=False
        probes=self._close_probes();radio=True
        if helper_ok and probes and (op.helper is not None or self.radio_restore_pending):radio=self.verify_radio_restore()
        with self.lock:
            self.discoverable=False;self.scanning=False;self.radio_deadline=0
            self.radio_restore_pending=not (helper_ok and key_ok and radio and probes and send_ok) or op.actor_unknown
        return (helper_ok and key_ok and radio and not op.actor_unknown and probes and self._probes_closed()
                and send_ok and not op.send_construct_pending and not op.send_construct_unknown)

    @staticmethod
    def _send_receipt_exact(receipt,op,lease):
        return (type(receipt) is SendRestoreReceipt and receipt.provider is op.send_provider and
                receipt.lease is lease and type(receipt.operation_epoch) is int and receipt.operation_epoch==op.epoch and
                type(op.send_intent) is SendIntent and type(receipt.task_id) is str and
                receipt.task_id==op.send_intent.handoff.task_id and
                all(value is True for value in (receipt.baseline_verified,receipt.journal_reconciled,
                                               receipt.actors_closed,receipt.resources_closed)))

    def _restore_send_owner(self,op):
        # Typed bindings are a private contract, not kernel authentication.
        # A real provider must implement durable restoration + fresh readback;
        # this slice does not implement/enable that production platform.
        worker=op.send_worker
        if worker is None:
            return (self._send_skip_exact(op) and op.helper.closure_verified() is True and
                    self._probes_closed() and self.radio_restore_pending is False)
        if (worker is None or op.send_provider is None or worker.provider is not op.send_provider or
            op.send_construct_pending or op.send_construct_unknown or op.actor_unknown):return False
        status=worker.status();records=worker.private_owner_records()
        if (status['run_returned'] is not True or status['scope_released'] is not True or
            status['extra_resources_closed'] is not True or type(records) is not tuple or
            len(records)!=len(op.send_tickets) or any(row is not saved for row,saved in zip(records,op.send_tickets)) or
            any(type(row) is not CreationTicket or row.worker is not worker or row.claimed is not True or
                row.resolved is not True or type(row.unknown) is not bool or type(row.unknown_closed) is not bool or
                (row.unknown and not row.unknown_closed) for row in records)):
            return False
        lease=op.send_lease
        if worker.lease is not lease:return False
        lease_records=[row for row in records if row.kind=='lease']
        if lease is None:
            # reserve/adopt exceptions can leave children even if worker.lease
            # is None. Only the no-attempt branch is network-zero-mutation.
            return not lease_records and status['unresolved_unknown']==0
        if (len(lease_records)!=1 or lease_records[0].resource is not lease or lease_records[0].unknown or
            not callable(getattr(op.send_provider,'restore_owned',None)) or
            not callable(getattr(op.send_provider,'read_restored',None))):return False
        start=time.monotonic()
        receipt=op.send_provider.restore_owned(lease,op.epoch,op.send_intent.handoff.task_id,5)
        op.send_restore_receipt=receipt # Retain a malformed return as private evidence.
        elapsed=time.monotonic()-start
        if not 0<=elapsed<=5 or not self._send_receipt_exact(receipt,op,lease):return False
        start=time.monotonic()
        fresh=op.send_provider.read_restored(receipt,.2)
        op.send_restore_readback=fresh
        elapsed=time.monotonic()-start
        return (fresh is not receipt and 0<=elapsed<=.2 and self._send_receipt_exact(fresh,op,lease))

    def _restore_owner(self,op):
        # Only the exact Session external finalizer calls this mutation point.
        if op is not self.operation or op.backend is not self.wifi_backend or op.actor_unknown:return False
        if op.kind=='send':
            try:restored=self._restore_send_owner(op) is True
            except BaseException:restored=False
            with self.lock:
                self.wifi_restore_pending=not restored
                if not restored:self.receive_available=False;self.send_available=False
            return restored
        active=getattr(op.backend,'_active_lease',None)
        if active is not None and active is not op.lease:return False
        try:
            if op.recovery_requested and op.lease is None:
                restored=op.backend.recover_pending() is True
            elif (op.recovery_requested and active is op.lease and op.lease.closed is True and
                  op.lease.actors_closed() is True):
                # Explicit same-owner journal recheck only after every old native actor exited.
                # Do not rewrite the old lease's failed-restoration historical fact.
                restored=op.backend.recover_pending() is True
            elif op.lease is not None:
                restored=op.lease.restore() is True and op.lease.actors_closed() is True
            else:restored=op.backend.restore_active() is True
            pending=op.backend.status()
            restored=(restored and type(pending) is dict and pending.get('restorePending') is False and
                      pending.get('recoveryLocked') is False)
        except BaseException:restored=False
        with self.lock:
            self.wifi_restore_pending=not restored
            if not restored:self.receive_available=False;self.send_available=False
        return restored

    def verify_radio_restore(self):
        if not self._probes_closed():return False
        current=capability(self.bluez_path,['--capabilities','hci0'],actors=self.probe_actors)
        verified=bool(current and current.get('powered')==self.bluetooth_caps.get('powered') and
                      current.get('bredr_enabled')==self.bluetooth_caps.get('bredr_enabled') and
                      current.get('le_enabled')==self.bluetooth_caps.get('le_enabled') and
                      current.get('global_advertising')==self.bluetooth_caps.get('global_advertising') and
                      current.get('active_instances')==self.bluetooth_caps.get('active_instances') and
                      current.get('bluez_advertising_active')==self.bluetooth_caps.get('bluez_advertising_active'))
        if not verified:
            self.state='error';self.receive_available=False
            self.reason='蓝牙资源恢复尚未通过独立检查；请勿重复开启互传'
        self.radio_restore_pending=not verified
        if self.state not in ('error','completed'):self.state='idle'
        return verified

    def close(self):
        with self.lock:
            self.closing=True;self.cancelled.set();self.decision.set()
            if self.operation:
                self.operation.input_ready.set();self.operation.send_ready.set()
                if self.operation.scan is not None:self.operation.scan.cancel()
            session=self._cleanup_session_locked()
        return session.close(timeout=30) is True and self.closed()

    def closed(self):
        with self.lock:
            return (self.session is not None and self.session.closed() is True and
                    not self.wifi_restore_pending and not self.radio_restore_pending and self._probes_closed())


class Handler(minhttp.BaseHTTPRequestHandler):
    def reply(self,code,value):
        data=json.dumps(value).encode('utf-8')
        self.send_response(code);self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)))
        self.end_headers();self.wfile.write(data)

    def authorized(self,bootstrap=False):
        if (self.client_address[0]!='127.0.0.1' or self.headers.get_all('Host')!=[self.server.expected_host] or
            self.headers.get_all('Origin') or len(self.headers.get_all('X-P011-MTA-Token',[]))>1):return False
        if bootstrap:return self.server.bootstrap_deadline>time.monotonic() and not self.server.bootstrap_used
        value=self.headers.get('X-P011-MTA-Token','')
        return len(value)<=256 and re.match(r'^[A-Za-z0-9_-]*$',value) is not None and hmac.compare_digest(value,self.server.state.token)

    def do_GET(self):
        if self.path=='/v1/bootstrap':
            with self.server.bootstrap_lock:
                if not self.authorized(True):self.reply(403,{'error':'Unauthorized'});return
                self.server.bootstrap_used=True
                self.reply(200,{'token':self.server.state.token});return
        if not self.authorized():self.reply(403,{'error':'Unauthorized'});return
        if self.path=='/v1/status':self.reply(200,self.server.state.status())
        elif self.path=='/v1/files':self.reply(200,{'files':self.server.state.registry.list_files()})
        else:self.reply(404,{'error':'Unknown route'})

    def do_POST(self):
        if not self.authorized():self.reply(403,{'error':'Unauthorized'});return
        if self.path!='/v1/action':self.reply(404,{'error':'Unknown route'});return
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':self.reply(400,{'error':'JSON required'});return
        length=int(self.headers.get('Content-Length','0'))
        if not 1<=length<=4096:self.reply(413,{'error':'Action byte limit'});return
        try:
            value=json.loads(self.rfile.read(length).decode('utf-8'))
            self.reply(200,self.server.state.action(value))
        except (ValueError,UnicodeError):self.reply(409,{'error':'Action invalid or capability unavailable'})


class Server(minhttp.HTTPServer):
    def __init__(self,state,port=0,bootstrap=False):
        minhttp.HTTPServer.__init__(self,('127.0.0.1',port),Handler)
        self.state=state;self.expected_host='127.0.0.1:'+str(self.server_address[1])
        self.bootstrap_deadline=time.monotonic()+30 if bootstrap else 0
        self.bootstrap_used=False;self.bootstrap_lock=threading.Lock()
