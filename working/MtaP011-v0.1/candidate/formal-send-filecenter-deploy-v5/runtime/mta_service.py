"""Independent formal-send-v1 SOURCE candidate.

The trusted once-owned startup trial authorizes preparation only, not Native/RF
success. The unchanged fixed F93 creates and restores actual native resources.
The same original GO worker consumes original Pub/preflight and Terminal95
ledgers, closed Bridge/F EOF+reap, full terminal journal/snapshot/absence DATA,
plus original closed ConnMan and BlueZ before/after observations. An outside
Session finalizer only consumes that retained original proof; no boolean,
child RESULT.restored or key equality alone issues restoration. Single trial
per service process. Default receive and send remain closed without the exact
Owner preparation ticket. SOURCE not staged or executed.
"""
import base64
import hmac
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
import types
import uuid
from collections import namedtuple

import p011_json as json
import minhttp
from mta_crypto import OpenSslCrypto
from mta_files import FileRegistry,MAX_TOTAL
from mta_protocol import DeviceInfo, encode_advertisement
from mta_wifi import WifiBackend
from mta_transfer_session import TransferSession,Outcome,SendOutcome,SessionError
from mta_scan_handoff import ScanSession,SendIntent,ScanHandoffError
from mta_send_worker import SendWorker,SendResult,SendWorkerError,CreationTicket
from mta_client_connect_handoff import ReceiveConnectHandoff
from mta_client_state_bridge import StateClientBridge,StateBridgeError
import mta_receive_radio_baseline as radio_baseline
import mta_receive_network as network_restore
import mta_send_trial as send_trial
import mta_send_terminal_consumer as terminal_consumer


SendRestoreReceipt=namedtuple('SendRestoreReceipt',
    'provider lease operation_epoch task_id baseline_verified journal_reconciled actors_closed resources_closed')
_SEND_STATUS_FIELDS=frozenset(('stage','reason','cancel_requested','run_returned','creation_pending','creation_unknown',
    'unresolved_unknown','owner_records','handoff_count','ignored_native_events','scope_released','extra_resources_closed',
    'network_restore_required','archiveBytesSent','bytes','archiveSize','fileCount','totalSize','localBytesVerified',
    'peerCompletionVerified','platform_available'))
_SendSkipped=namedtuple('_SendSkipped','owner session helper scan intent epoch thread')
_GO_STATE_ROOT='/tmp/p011-mta-formal-send-filecenter-deploy-v5'
_GO_USER_ROOT='/mnt/data/p011-toolbox/user'
_GO_PREPARATION_ROOT='/var/volatile/tmp/p011-mta-go-send-v78-prepared'
_GO_TERMINAL_ROLE='mta_go_readonly_terminal_parent'
_GO_PROGRESS_FIELDS=frozenset(('state','accepted','archiveBytesSent','archiveSize','download_complete',
    'peer_completion_verified','connection_attempts','socket_cleanup_pending','fileCount','totalSize'))
_GO_PROGRESS_STATES=frozenset(('waiting','negotiating','awaiting_confirmation','accepted','transferring',
    'awaiting_result','completed','cancelled','failed'))
_GO_NETWORK_DEFINITIONS=(network_restore,network_restore.__dict__,network_restore.NetworkObserver,
    network_restore.NetworkObservation,network_restore.NetworkObserver.__init__,
    network_restore.NetworkObserver.observe,network_restore.NetworkObserver.close,
    network_restore.NetworkObserver.resources_closed,network_restore.NetworkObservation.resources_closed,
    network_restore.compare_observations)
_GO_RADIO_DEFINITIONS=(radio_baseline,radio_baseline.__dict__,radio_baseline.normalize,radio_baseline.matches)
_GO_CONSUMER_DEFINITIONS=(terminal_consumer,terminal_consumer.__dict__,
    terminal_consumer.consume_terminal_data,terminal_consumer.TerminalConsumptionData)


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
    # Closure and usable capability DATA are separate facts. Failure/nonzero
    # output may close physically, but can never authenticate a result.
    try:
        if (type(actor) is not dict or actor['creator'] is not _CAPABILITY_CREATOR or
                actor['creator'] is not actor['_creator_original'] or
                actor['actors'] is not actor['_actors_original'] or
                actor['actors'] is not None and (type(actor['actors']) is not list or
                    not any(row is actor for row in actor['actors'])) or
                actor['spawn_pending'] is not False or actor['spawn_unknown'] is not False):
            return False
        process=actor['process']
        if actor['spawn_called'] is False:
            return (actor['spawn_returned'] is False and process is None and
                    actor['_process_original'] is None and actor['stdout'] is None and
                    actor['stderr'] is None and actor['_stdout_original'] is None and
                    actor['_stderr_original'] is None and actor['communicate_called'] is False and
                    not actor['cleanup_calls'])
        if (actor['spawn_called'] is not True or actor['spawn_returned'] is not True or
                process is None or process is not actor['_process_original'] or
                actor['popen_creator'] is not actor['_popen_creator_original'] or
                actor['argv'] is not actor['_argv_original'] or
                actor['argv_snapshot'] is not actor['_argv_snapshot_original'] or
                type(actor['argv']) is not list or tuple(actor['argv'])!=actor['argv_snapshot'] or
                process.args is not actor['_argv_original'] or
                process.stdout is not actor['stdout'] or process.stderr is not actor['stderr'] or
                actor['stdout'] is not actor['_stdout_original'] or actor['stderr'] is not actor['_stderr_original']):
            return False
        code=process.poll()
        return (type(code) is int and type(actor['returncode']) is int and code==actor['returncode'] and
                actor['stdout'].closed is True and actor['stderr'].closed is True)
    except BaseException:return False


def _probe_result(actor,result,helper,args):
    # Pure provenance check: no new Popen, loads, wait, clock or pipe read.
    try:
        return (_probe_closed(actor) is True and actor['closed'] is True and
                actor['spawn_called'] is True and actor['spawn_returned'] is True and
                actor['failure'] is None and not actor['cleanup_failures'] and
                actor['argv_snapshot']==tuple([helper]+args) and
                actor['args_original'] is actor['_args_original'] and
                actor['args_snapshot'] is actor['_args_snapshot_original'] and
                tuple(actor['args_original'])==actor['args_snapshot'] and
                actor['communicate_called'] is True and actor['communicate_returned'] is True and
                actor['out'] is actor['_out_original'] and actor['err'] is actor['_err_original'] and
                type(actor['out']) is bytes and len(actor['out'])<=16384 and
                type(actor['err']) is bytes and actor['err']==b'' and actor['returncode']==0 and
                actor['json_input'] is actor['_json_input_original'] and
                type(actor['json_input']) is str and
                actor['out'].decode('utf-8').splitlines()==[actor['json_input']] and
                actor['loads_creator'] is actor['_loads_creator_original'] and
                actor['loads_creator'] is json.loads and
                actor['snapshot_creator'] is actor['_snapshot_creator_original'] and
                actor['snapshot_creator'] is json.dumps and
                type(result) is dict and result is actor['parsed'] and result is actor['_parsed_original'] and
                result is actor['returned'] and result is actor['_returned_original'] and
                actor['parsed_snapshot'] is actor['_parsed_snapshot_original'] and
                type(actor['parsed_snapshot']) is str and
                actor['snapshot_creator'](result,sort_keys=True)==actor['parsed_snapshot'])
    except BaseException:return False


def _probe_cleanup_call(actor,process):
    # Durable original cleanup attempt; never overwrites the first raw output
    # or first failure, including a TimeoutExpired partial communicate output.
    call={'process':process,'stdout':actor['_stdout_original'],'stderr':actor['_stderr_original'],
          'kill_called':False,'kill_returned':False,'communicate_called':False,
          'communicate_returned':False,'out':None,'err':None,'returncode':None,'error':None}
    actor['cleanup_calls'].append(call)
    try:
        if (process is not actor['_process_original'] or
                process.args is not actor['_argv_original'] or
                tuple(process.args)!=actor['_argv_snapshot_original'] or
                process.stdout is not actor['_stdout_original'] or
                process.stderr is not actor['_stderr_original']):
            raise ValueError('Original capability cleanup actor changed')
        call['kill_called']=True
        process.kill();call['kill_returned']=True
        call['communicate_called']=True
        call['out'],call['err']=process.communicate(timeout=3)
        call['communicate_returned']=True
    except BaseException as error:
        call['error']=error;actor['cleanup_failures'].append(error)
    finally:
        call['returncode']=process.returncode
        actor['returncode']=process.returncode
    return call


def capability(helper,args,actors=None):
    empty={}
    actor={'creator':_CAPABILITY_CREATOR,'_creator_original':_CAPABILITY_CREATOR,
           'actors':actors,'_actors_original':actors,'args_original':args,'_args_original':args,
           'args_snapshot':None,'_args_snapshot_original':None,
           'argv':None,'_argv_original':None,'argv_snapshot':None,'_argv_snapshot_original':None,
           'popen_creator':None,'_popen_creator_original':None,'process':None,'_process_original':None,
           'stdout':None,'_stdout_original':None,'stderr':None,'_stderr_original':None,
           'spawn_called':False,'spawn_returned':False,'spawn_pending':False,'spawn_unknown':False,'closed':False,
           'communicate_called':False,'communicate_returned':False,
           'out':None,'_out_original':None,'err':None,'_err_original':None,'returncode':None,
           'loads_creator':None,'_loads_creator_original':None,'json_input':None,'_json_input_original':None,
           'parsed':None,'_parsed_original':None,'parsed_snapshot':None,'_parsed_snapshot_original':None,
           'snapshot_creator':None,'_snapshot_creator_original':None,
           'returned':empty,'_returned_original':empty,'failure':None,
           'cleanup_calls':[],'cleanup_failures':[]}
    if actors is not None:actors.append(actor) # Strong retention before any probe IO.
    try:
        if capability is not _CAPABILITY_CREATOR:
            actor['failure']=ValueError('Capability creator changed');return empty
        actor['args_snapshot']=actor['_args_snapshot_original']=tuple(args)
        argv=[helper]+args
        actor['argv']=actor['_argv_original']=argv
        actor['argv_snapshot']=actor['_argv_snapshot_original']=tuple(argv)
        if not os.path.isabs(helper) or not os.path.isfile(helper):
            actor['failure']=ValueError('Capability helper unavailable');return empty
        actor['popen_creator']=actor['_popen_creator_original']=subprocess.Popen
        actor['spawn_called']=actor['spawn_pending']=True
        try:
            process=actor['popen_creator'](argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            actor['process']=actor['_process_original']=process;actor['spawn_returned']=True
            actor['stdout']=actor['_stdout_original']=process.stdout
            actor['stderr']=actor['_stderr_original']=process.stderr
        except BaseException:
            actor['spawn_unknown']=True;raise
        finally:actor['spawn_pending']=False
        actor['communicate_called']=True
        out,err=process.communicate(timeout=12)
        actor['communicate_returned']=True
        actor['out']=actor['_out_original']=out;actor['err']=actor['_err_original']=err
        actor['returncode']=process.returncode
        if type(out) is not bytes or type(err) is not bytes or process.returncode or len(out)>16384:
            actor['failure']=ValueError('Capability output or exit invalid');return empty
        lines=out.decode('utf-8').splitlines()
        if len(lines)!=1:
            actor['failure']=ValueError('Capability output lines invalid');return empty
        actor['json_input']=actor['_json_input_original']=lines[0]
        actor['loads_creator']=actor['_loads_creator_original']=json.loads
        result=actor['loads_creator'](lines[0])
        actor['parsed']=actor['_parsed_original']=result
        if not isinstance(result,dict):
            actor['failure']=ValueError('Capability JSON object required');return empty
        actor['snapshot_creator']=actor['_snapshot_creator_original']=json.dumps
        actor['parsed_snapshot']=actor['_parsed_snapshot_original']=actor['snapshot_creator'](result,sort_keys=True)
        actor['returned']=actor['_returned_original']=result
        return result # The original parsed dictionary, never a copy.
    except BaseException as error:
        if actor['failure'] is None:actor['failure']=error
        if isinstance(error,subprocess.TimeoutExpired):
            actor['out']=actor['_out_original']=error.output
            actor['err']=actor['_err_original']=getattr(error,'stderr',None)
        process=actor['process']
        if process is not None:_probe_cleanup_call(actor,process)
        return empty
    finally:
        process=actor['process']
        if process is not None:actor['returncode']=process.returncode
        actor['closed']=_probe_closed(actor)


_CAPABILITY_CREATOR=capability


class PrivateHelper(object):
    """Original helper IPC owner; close requests never stop the EOF reader.

    This candidate proves local process/pipe/thread closure only. Native cleanup
    events still reach the original callback; exit/EOF are not radio restoration.
    """
    def __init__(self,path,callback):
        self.path=path;self.callback=callback;self.lock=threading.RLock();self.closed=False
        self.command_note=None
        self.process=None;self.spawn_claimed=False;self.spawn_resolved=False;self.spawn_unknown=False
        self.reader_claimed=False;self.reader_resolved=False;self.reader_unknown=False
        self.thread=threading.Thread(target=self.read);self.thread.daemon=True
        self._reader_original=self.thread
        self._process_original=self._stdin_original=self._stdout_original=None
        self.stdout_eof=False;self.reader_error=None;self.returncode=None
        self._close_claimed=False;self._wait_timeout=False;self.close_errors=[]

    def start(self):
        # State retains this pure owner before Popen or Thread.start can act.
        with self.lock:
            if self.spawn_claimed:raise ValueError('Helper cannot start twice')
            self.spawn_claimed=True
        try:
            self.process=subprocess.Popen([self.path,'--serve','hci0'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            self._process_original=self.process
            self._stdin_original=self.process.stdin;self._stdout_original=self.process.stdout
        except BaseException:self.spawn_unknown=True;raise
        finally:self.spawn_resolved=True
        self.reader_claimed=True
        try:self._reader_original.start()
        except BaseException:self.reader_unknown=True;raise
        finally:self.reader_resolved=True

    def read(self):
        try:
            while not self.reader_resolved:
                if self.reader_unknown:return
                time.sleep(.005)
            if self.reader_unknown:return
            # closed revokes commands, not this original private stdout reader.
            # Continue through late cleanup/ownership events until physical EOF.
            while True:
                if (self.process is not self._process_original or
                        self._process_original.stdout is not self._stdout_original):
                    raise ValueError('Original native output changed')
                line=self._stdout_original.readline(16385)
                if type(line) is not bytes:raise ValueError('Native IPC bytes required')
                if line==b'':
                    self.stdout_eof=True
                    break
                if len(line)>16384 or not line.endswith(b'\n'):raise ValueError('Native IPC limit')
                event=json.loads(line.decode('utf-8'))
                if not isinstance(event,dict):raise ValueError('Native IPC object required')
                self.callback(event)
        except BaseException as error:
            if self.reader_error is None:self.reader_error=error
            try:self.callback({'event':'error','code':'native_ipc_invalid'})
            except BaseException as callback_error:
                if self.reader_error is None:self.reader_error=callback_error
        finally:
            # Compatibility notification only; never substitutes for stdout_eof.
            try:self.callback({'event':'closed'})
            except BaseException as error:
                if self.reader_error is None:self.reader_error=error

    def send(self,value):
        with self.lock:
            if (self.closed or self.process is None or self.process is not self._process_original or
                    self.process.stdin is not self._stdin_original or self.process.poll() is not None):
                raise ValueError('Native helper is not running')
            if self.command_note is not None:self.command_note(value)
            data=(json.dumps(value)+'\n').encode('ascii')
            if len(data)>8192:raise ValueError('Native IPC limit')
            self._stdin_original.write(data);self._stdin_original.flush()

    def close(self):
        with self.lock:
            process=self._process_original
            if process is None:return self.closure_verified()
            if self._close_claimed:return self.closure_verified()
            self._close_claimed=True
            try:
                if not self.closed and process.poll() is None:self.send({'cmd':'stop'})
            except BaseException as error:self.close_errors.append(error)
            self.closed=True
            try:
                if not self._stdin_original.closed:self._stdin_original.close()
            except BaseException as error:self.close_errors.append(error)
        try:
            try:self.returncode=process.wait(timeout=18)
            except subprocess.TimeoutExpired:
                self._wait_timeout=True
                # Terminate only our retained Popen, never kill by global name.
                process.terminate()
                try:self.returncode=process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill();self.returncode=process.wait(timeout=3)
        except BaseException as error:
            self.close_errors.append(error)
        # The reader owns stdout until it has consumed the real EOF or failed.
        if self._reader_original is not threading.current_thread() and self.reader_resolved:
            try:self._reader_original.join(2)
            except BaseException as error:self.close_errors.append(error)
        if not self._reader_original.is_alive():
            try:
                if not self._stdout_original.closed:self._stdout_original.close()
            except BaseException as error:self.close_errors.append(error)
        return self.closure_verified()

    def closure_verified(self):
        if self.spawn_unknown or self.reader_unknown:return False
        if self.spawn_claimed and not self.spawn_resolved:return False
        if self.reader_claimed and not self.reader_resolved:return False
        if self.thread is not self._reader_original or self._reader_original.is_alive():return False
        if self._process_original is None:
            return self.process is None and not self.spawn_claimed and not self.reader_claimed
        try:
            process=self._process_original
            return (self.process is process and process.stdin is self._stdin_original and
                    process.stdout is self._stdout_original and self.stdout_eof is True and
                    self.reader_error is None and not self.close_errors and not self._wait_timeout and
                    type(self.returncode) is int and self.returncode==0 and
                    type(process.returncode) is int and process.returncode==0 and process.poll()==0 and
                    self._stdin_original.closed is True and self._stdout_original.closed is True)
        except BaseException:return False

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
        self.client_handoff=self.client_bridge=None
        self.receive_bridge_ticket={'started':False,'returned':None}
        self.receive_factory=None
        self.receive_extra_verified=False
        # Strong worker-local originals, never a provider lease or receipt.
        self.send_file_ids=self.send_task_id=None
        self.send_selection=self.send_prepared=self.send_publication=self.send_bridge=None
        self.go_selection_original=self.go_helper_original=None
        self.go_modules=self.go_source_dicts=self.go_creators=self.go_originals=None
        self.go_tickets=[];self.go_errors=[];self.go_gatt_events=[]
        self.go_worker=self.go_until=self.go_cleanup_until=self.go_closed_facts=None
        self.go_started=self.go_returned=self.go_cleanup_unknown=False
        self.go_helper_close_called=self.go_helper_closed=self.go_radio_verified=False
        self.go_helper_close_ticket=self.go_gatt_teardown_original=None
        self.go_child_called=False;self.go_native_restore_verified=False
        self.go_terminal_source=self.go_terminal_parent=self.go_terminal_original=None
        self.go_terminal_ticket=self.go_terminal_facts=self.go_terminal_result=self.go_terminal_error=None
        self.go_terminal_attempted=self.go_terminal_unavailable=False
        self.go_network_observer=self.go_network_original=None
        self.go_network_before=self.go_network_after=None
        self.go_network_ticket=self.go_network_refs=None
        self.go_restoration_consumption=self.go_restoration_refs=self.go_restoration_error=None
        self.go_restoration_completion=None
        self.go_restoration_attempted=False
        self.go_radio_probe_original=None
        self.go_session_ctor_ticket=None
        self.lock=threading.RLock()


class State(object):
    def __init__(self,user_root,bluez_helper,network_helper,openssl='/usr/bin/openssl',send_provider=None,
                 trusted_receive_deployment_factory=None,original_service_until=None,network_observer_spec=None):
        if trusted_receive_deployment_factory is not None and not callable(trusted_receive_deployment_factory):
            raise ValueError('Trusted receive deployment factory required')
        if original_service_until is not None and (type(original_service_until) is not float or
                not math.isfinite(original_service_until) or not 0<original_service_until<2**53):
            raise ValueError('Original finite service cap required')
        self._original_service_until=self._service_until_original=original_service_until
        self._send_trial=self._send_trial_original=None
        self._network_observer_spec=self._network_observer_spec_original=network_observer_spec
        if network_observer_spec is not None and (type(network_observer_spec) is not tuple or
                len(network_observer_spec)!=3 or network_observer_spec[0]!=_GO_STATE_ROOT+'/mta-connman-observer' or
                network_observer_spec[1:]!=(46008,'5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2')):
            raise ValueError('Original fixed network observer spec required')
        self._original_service_cleanup_until=self._service_cleanup_until_original=(
            None if original_service_until is None else original_service_until+60.0)
        self.lock=threading.RLock();self.token=uuid.uuid4().hex+uuid.uuid4().hex
        self.registry=FileRegistry(user_root)
        self.received_root=os.path.join(user_root,'Received')
        if not os.path.exists(self.received_root):os.mkdir(self.received_root,0o700)
        self.bluez_path=self._bluez_path_original=bluez_helper;self.network_path=network_helper;self.openssl=openssl
        self.nickname='P011';self.sender_id=os.urandom(2)
        self.helper=None;self.key=None;self.crypto=None;self.lease=None;self.worker=None
        self.session=None;self.operation=None;self.transport=None;self.history=[]
        self.wifi_backend=WifiBackend(network_helper)
        self.wifi_restore_pending=False;self.radio_restore_pending=False;self.native_epoch=0
        self.cancelled=threading.Event();self.decision=threading.Event();self.accepted=False
        self.devices={};self.peer_seen={};self.request=None;self.transfer={};self.received=[]
        self.state='idle';self.reason='';self.discoverable=False;self.scanning=False
        self.radio_deadline=0;self.event_counts={};self.closing=False
        self.probe_actors=self._probe_actors_original=[]
        self._probe_creator_original=_CAPABILITY_CREATOR
        self.bluetooth_probe_actor=self._bluetooth_probe_actor_original=None
        self.network_probe_actor=self._network_probe_actor_original=None
        self.radio_restore_probes=[]
        self.bluetooth_caps=capability(bluez_helper,['--capabilities','hci0'],actors=self.probe_actors)
        if len(self.probe_actors)==1:
            self.bluetooth_probe_actor=self._bluetooth_probe_actor_original=self.probe_actors[0]
        self._bluetooth_caps_original=self.bluetooth_caps
        network_start=len(self.probe_actors)
        self.network_caps=capability(network_helper,['--capabilities'],actors=self.probe_actors) if self._probes_closed() else {}
        if len(self.probe_actors)==network_start+1:
            self.network_probe_actor=self._network_probe_actor_original=self.probe_actors[network_start]
        self._network_caps_original=self.network_caps
        self._trusted_receive_deployment_factory=trusted_receive_deployment_factory
        # Factory/API/AP-capability presence is not native P011 startup/restore
        # admission. This SOURCE candidate does not implement/open that gate.
        self.receive_available=False
        self.receive_reason=('原生接收部署工厂未配置；接收功能未开放' if trusted_receive_deployment_factory is None else
                             '原生接收尚缺实际启动与恢复准入验证；接收功能未开放')
        self.scan_available=bool(self.bluetooth_caps.get('powered'))
        self.send_available=False # Explicit until verified P2P/network sender backend exists.
        self._send_provider=send_provider # Trusted internal only; presence never enables the public gate.
        if not self._probes_closed():
            self.receive_available=False;self.scan_available=False;self.radio_restore_pending=True
        if not self.receive_available:self.reason=self.receive_reason
        pending=self.wifi_status()
        if pending.get('restorePending') or pending.get('recoveryLocked'):
            self.wifi_restore_pending=True;self.receive_available=False
            self.state='error';self.reason=pending.get('reason') or '上次网络租约恢复待核验，请先检查恢复'

    def wifi_status(self):
        op=self.operation
        if op is not None and op.kind=='go_send':
            pending=self.wifi_restore_pending or op.go_cleanup_unknown or (op.go_child_called and not self._go_restoration_current(op))
            return {'restorePending':pending,'recoveryLocked':pending,'backend':'native-go-send',
                    'reason':'发送恢复原件尚未闭合' if pending else '原件恢复核对完成；本服务只允许一次发送试验'}
        if op is not None and op.kind=='receive':
            bridge=op.client_bridge
            native=bridge.status() if type(bridge) is StateClientBridge else None
            pending=self.wifi_restore_pending or bool(native and native['restore_pending'])
            return {'restorePending':pending,'recoveryLocked':pending,'backend':'native-client',
                    'reason':'原生接收资源与恢复仍待核验' if pending else self.receive_reason}
        try:return self.wifi_backend.status()
        except Exception:return {'restorePending':True,'recoveryLocked':True,'reason':'网络恢复记录无法核实'}

    def _probes_closed(self):
        return all(row['spawn_pending'] is False and row['spawn_unknown'] is False and row['closed'] is True
                   for row in self.probe_actors)

    def _close_probes(self,timeout=3.0,cleanup_until=None):
        # Explicit finalizer only; these fixed --capabilities actors are
        # read-only. Time-only clipping never extends any original cap.
        if (type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<=timeout<=3 or
                cleanup_until is not None and (type(cleanup_until) not in (int,float) or
                    not math.isfinite(cleanup_until) or not 0<=cleanup_until<2**53)):
            raise ValueError('Original capability close time budget required')
        start=time.monotonic()
        original=self._service_cleanup_until_original
        end=min(start+float(timeout),float(cleanup_until) if cleanup_until is not None else start+float(timeout),
                original if type(original) is float and math.isfinite(original) and
                    self._original_service_cleanup_until is original else start)

        def same_actor(row,process):
            return (self.probe_actors is self._probe_actors_original and
                row['actors'] is self.probe_actors and row['_actors_original'] is self.probe_actors and
                row['creator'] is self._probe_creator_original and row['creator'] is _CAPABILITY_CREATOR and
                row['creator'] is row['_creator_original'] and
                row['popen_creator'] is row['_popen_creator_original'] and
                row['spawn_pending'] is False and row['spawn_unknown'] is False and
                row['spawn_called'] is True and row['spawn_returned'] is True and
                process is not None and process is row['process'] and process is row['_process_original'] and
                row['argv'] is row['_argv_original'] and process.args is row['_argv_original'] and
                type(row['argv']) is list and
                row['argv_snapshot'] is row['_argv_snapshot_original'] and
                tuple(process.args)==row['_argv_snapshot_original'] and
                row['_argv_snapshot_original'] in ((self._bluez_path_original,'--capabilities','hci0'),
                    (self.network_path,'--capabilities')) and
                process.stdout is row['stdout'] and process.stdout is row['_stdout_original'] and
                process.stderr is row['stderr'] and process.stderr is row['_stderr_original'])

        for row in self.probe_actors:
            if row['closed'] is True and _probe_closed(row) is True:continue
            process=row['process']
            if row['spawn_pending'] or row['spawn_unknown'] or process is None:continue
            call={'process':process,'stdout':row['_stdout_original'],'stderr':row['_stderr_original'],
                'kill_called':False,'kill_returned':False,'communicate_called':False,
                'communicate_returned':False,'out':None,'err':None,'returncode':None,'error':None,
                'cleanup_until':end,'timeout':None,'stdout_close_error':None,'stderr_close_error':None}
            row['cleanup_calls'].append(call)
            try:
                if not same_actor(row,process):raise ValueError('Original capability close actor changed')
                if process.poll() is None:
                    if not same_actor(row,process):raise ValueError('Original capability close actor changed')
                    call['kill_called']=True;process.kill();call['kill_returned']=True
                if not same_actor(row,process):raise ValueError('Original capability close actor changed')
                now=time.monotonic()
                wait=max(0.0,min(3.0,end-now)) if math.isfinite(now) and now>=start else 0.0
                call['timeout']=wait;call['communicate_called']=True
                call['out'],call['err']=process.communicate(timeout=wait)
                call['communicate_returned']=True
            except BaseException as error:
                call['error']=error;row['cleanup_failures'].append(error)
            finally:
                try:
                    if same_actor(row,process):
                        call['returncode']=row['returncode']=process.returncode
                        for name in ('stdout','stderr'):
                            try:
                                if same_actor(row,process) and process.poll() is not None:
                                    row[name].close()
                            except BaseException as error:
                                call[name+'_close_error']=error;row['cleanup_failures'].append(error)
                except BaseException as error:
                    row['cleanup_failures'].append(error)
            row['closed']=(_probe_closed(row) is True and call['communicate_returned'] is True and
                call['error'] is None and call['stdout_close_error'] is None and call['stderr_close_error'] is None)
        verified=self.probe_actors is self._probe_actors_original
        # Cached closed=True is not a terminal original-actor proof. Include
        # skipped unknown actors without retrying them; the original helper
        # also correctly distinguishes a never-spawned known empty inventory.
        for row in self._probe_actors_original:
            if _probe_closed(row) is not True:
                verified=False
                if type(row) is dict:
                    row['closed']=False
                    row['cleanup_failures'].append(ValueError('Original capability terminal close proof missing'))
        return verified and self._probes_closed()

    def status(self):
        with self.lock:
            now=time.monotonic()
            session=self.session.status() if self.session is not None else None
            op=self.operation
            scan=op.scan.status() if op is not None and op.scan is not None else None
            sending=op is not None and op.kind in ('send','go_send')
            send_status=op.send_worker.status() if sending and isinstance(op.send_worker,SendWorker) else None
            go_status=self._go_public_status(op) if op is not None and op.kind=='go_send' else None
            receive_status=op.client_bridge.status() if op is not None and type(op.client_bridge) is StateClientBridge else None
            state=self.state;reason=self.reason;pending=self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()
            pending=pending or bool(receive_status and receive_status['restore_pending'])
            pending=pending or bool(go_status and go_status['resource_pending'])
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
                    elif receive_status is not None and receive_status['result'] is not None:
                        outcome=receive_status['result']['outcome']
                        state='idle' if outcome in ('refused','cancelled') else 'error'
                        reason={'refused':'已拒绝接收；原生资源已关闭',
                            'confirmation_timeout':'文件确认已超时；没有接收文件',
                            'cancelled':'已取消接收；原生资源已关闭',
                            'unavailable':'原生接收条件未满足；没有报告传输成功',
                            'failed':'接收未完成；资源已关闭，没有报告传输成功'}.get(outcome,'接收结果待核实')
                    else:state='idle'
                elif session['phase'] in ('pending','awaiting_finalizer_exit','transport_close','release','extra','restore'):
                    state='restoring';reason='资源关闭与网络恢复仍待核验；请勿重复开启互传'
            transfer=dict(self.transfer)
            if go_status is not None and go_status['progress'] is not None:
                progress=go_status['progress']
                transfer={'direction':'send','bytes':progress['archiveBytesSent'],
                    'archiveBytesSent':progress['archiveBytesSent'],'totalBytes':progress['archiveSize'],
                    'totalFiles':progress['fileCount'],'payloadTotalBytes':progress['totalSize'],
                    'peerCompletionReported':progress['peer_completion_verified'],
                    'nativeRestoreVerified':False}
                if session is not None and not session['closed'] and state!='restoring':
                    state='transferring' if progress['state']=='transferring' else 'connecting'
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
                    'scanLifecycle':scan,'sendLifecycle':send_status,'goSendLifecycle':go_status,'receiveLifecycle':receive_status,
                    'networkRecovery':self.wifi_status(),
                    'capabilities':{'receive':{'available':self.receive_available,'reason':self.receive_reason},
                                    'send':{'available':self._go_send_admitted(),
                                            'reason':'一次发送试验：原生启动由实际 F 核验，完成仍需终态原件核对'},
                                    'scan':self.scan_available,'rename':not pending and not discoverable and not scanning}}

    def action(self,value):
        if not isinstance(value,dict):raise ValueError('Action object required')
        action=value.get('action')
        fields={'discover_start':set(),'discover_stop':set(),'scan':set(),'scan_stop':set(),
                'accept':{'requestId'},'reject':{'requestId'},'cancel':set(),'recover':set(),
                'send_prepare':{'fileIds'},'send':{'deviceId','fileIds'},'rename':{'nickname'}}
        if action not in fields or set(value)!=fields[action]|{'action'}:raise ValueError('Action not permitted')
        operation=None;close_session=None
        with self.lock:
            if self.closing:raise ValueError('Service is closing')
            busy=(self.session is not None and not self.session.closed()) or self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()
            if action in ('accept','reject'):
                if not self.request or value['requestId']!=self.request['id']:raise ValueError('Incoming request changed')
                op=self.operation
                if op is None or op.kind!='receive' or type(op.client_bridge) is not StateClientBridge:
                    raise ValueError('Native incoming request owner required')
                try:op.client_bridge.submit_choice(op,value['requestId'],action=='accept')
                except StateBridgeError:raise ValueError('Incoming request changed or choice unavailable')
            elif action in ('cancel','discover_stop','scan_stop'):
                self.cancelled.set();self.decision.set()
                if self.operation:
                    if type(self.operation.client_bridge) is StateClientBridge:
                        try:self.operation.client_bridge.request_cancel(self.operation)
                        except StateBridgeError:pass # The exact original Event above still requests cancellation.
                    self.operation.input_ready.set();self.operation.send_ready.set()
                    if self.operation.scan is not None:self.operation.scan.cancel()
                close_session=self._cleanup_session_locked()
            elif action=='recover':
                close_session=self._cleanup_session_locked(recovery=True)
                if self.operation is not None:self.operation.recovery_requested=True
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
            elif action=='send_prepare':
                ids=self._go_file_ids(value['fileIds'])
                if busy or not self._go_send_admitted():
                    raise ValueError('Actual native sender admission producer is absent')
                self.devices={};self.peer_seen={}
                operation=self._new_operation_locked('go_send')
                operation.send_file_ids=ids;operation.send_task_id=uuid.uuid4().hex
                self.state='preparing';self.reason='正在准备原选中文件；尚未开启无线发送'
            elif action=='send':
                op=self.operation
                if op is not None and op.kind=='go_send':
                    ids=self._go_file_ids(value['fileIds'])
                    if (not self._go_send_admitted() or ids!=op.send_file_ids or op.scan is None or
                        op.session is not self.session or op.epoch!=self.native_epoch or op.send_intent is not None or
                        op.cancelled.is_set() or self.wifi_restore_pending or self.radio_restore_pending):
                        raise ValueError('Original prepared GO task selection required')
                    self._go_bridge(op) # Exact ordinary module/creator/original, not callable readiness.
                    try:op.send_intent=op.scan.claim_intent(value['deviceId'],list(ids),op.send_task_id)
                    except ScanHandoffError:raise ValueError('Fresh scan selection required')
                    op.send_ready.set();self.scanning=False;self.state='connecting'
                else:
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
        op=Operation(None if kind in ('receive','go_send') else self.wifi_backend,self.native_epoch,kind)
        if kind=='receive':op.receive_factory=self._trusted_receive_deployment_factory
        if kind=='go_send':
            # Retain Operation before claim, and the actual Session before attach.
            # Claim does not re-require available after this idle transition.
            self.operation=op
            send_trial.FixedSendTrial.claim(self._send_trial,self,op)
        options={'absolute_until':self._service_until_original} if kind=='go_send' else {}
        if kind=='go_send':
            ticket={'creator':TransferSession,'partial':None,'called':True,'returned':False,
                    'unknown':True,'error':None}
            op.go_session_ctor_ticket=ticket
            try:
                session=object.__new__(TransferSession)
                ticket['partial']=op.session=self.session=session
                TransferSession.__init__(session,lambda actual:self._run_operation(op,actual),self._restore_owner,op,
                    extra_actor_close=self._close_extra,task_timeout=300,finalize_timeout=120,
                    cancelled=op.cancelled,direction='send',**options)
                ticket['returned']=True;ticket['unknown']=False
            except BaseException as error:
                ticket['error']=error;op.actor_unknown=True;op.cancelled.set()
                send_trial.FixedSendTrial.revoke(self._send_trial,self,'session_failed');raise
        else:
            op.session=TransferSession(lambda session:self._run_operation(op,session),self._restore_owner,op,
                                       extra_actor_close=self._close_extra,task_timeout=300,finalize_timeout=120,
                                       cancelled=op.cancelled,direction='send' if kind=='scan' else 'receive',
                                       scoped_owner=op if kind=='scan' else None,
                                       scoped_release=self._release_send if kind=='scan' else None,**options)
        self.operation=op;self.session=op.session;self.worker=op.session._worker
        if kind=='go_send':
            try:send_trial.FixedSendTrial.attach_session(self._send_trial,self,op,op.session)
            except BaseException:
                op.cancelled.set();send_trial.FixedSendTrial.revoke(self._send_trial,self,'session_failed');raise
        self.helper=None;self.key=None;self.crypto=None;self.lease=None;self.transport=None
        self.cancelled=op.cancelled;self.decision=threading.Event();self.accepted=False;self.request=None
        self.discoverable=False;self.scanning=False;self.state='connecting';self.reason=''
        return op

    def _cleanup_session_locked(self,recovery=False):
        # Explicit close/recover can recheck only the original Session. Never
        # manufacture a legacy receive/cleanup lease or gateway restoration.
        if self.session is not None:return self.session
        if (self.operation is not None or any(value is not None for value in
                (self.helper,self.key,self.crypto,self.lease,self.transport,self.worker)) or
                self.wifi_restore_pending or self.radio_restore_pending or not self._probes_closed()):
            raise ValueError('Retained original recovery owner required')
        return None # Known no-operation inventory, not a claimed native restoration.

    def new_helper(self,op=None):
        op=op or self.operation
        if op is None or op is not self.operation or op.helper is not None:raise ValueError('Exact helper owner required')
        helper=PrivateHelper(self.bluez_path,lambda event:self.native_event(event,op.epoch,helper))
        helper.command_note=lambda value:self._note_send_command(op,helper,value)
        op.helper=helper
        if op.kind=='go_send':op.go_helper_original=helper # Before its real Popen/reader start.
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

    @staticmethod
    def _go_file_ids(value):
        if (type(value) is not list or not 1<=len(value)<=256 or
            any(type(v) is not str or not 1<=len(v)<=128 or re.fullmatch('[A-Za-z0-9_-]+',v) is None for v in value) or
            len(set(value))!=len(value)):
            raise ValueError('Original selected file IDs required')
        return tuple(value)

    def _go_send_admitted(self):
        trial=self._send_trial
        if (trial is None or trial is not self._send_trial_original or
                type(trial) is not send_trial.FixedSendTrial):
            return False
        op=self.operation
        return (send_trial.FixedSendTrial.available(trial,self) if op is None else
                op.kind=='go_send' and send_trial.FixedSendTrial.allows(trial,self,op))

    def _go_check(self,op,session):
        cap=self._service_until_original
        if (op is not self.operation or op.kind!='go_send' or op.session is not session or self.session is not session or
            threading.current_thread() is not session._worker or op.go_worker is not session._worker or
            op.epoch!=self.native_epoch or self._original_service_until is not cap or type(cap) is not float or
            type(session._task_deadline) is not float or not 0<session._task_deadline<=cap or
            op.go_until is not session._task_deadline or op.cancelled.is_set() or self.closing):
            raise ValueError('Original GO State worker/cap changed or stopped')
        now=time.monotonic()
        if not math.isfinite(now) or now>=op.go_until:raise ValueError('Original GO task expired')
        return now

    def _go_network_source_current(self):
        n=_GO_NETWORK_DEFINITIONS;r=_GO_RADIO_DEFINITIONS;c=_GO_CONSUMER_DEFINITIONS
        for name,module,namespace in (('mta_receive_network',n[0],n[1]),
                ('mta_receive_radio_baseline',r[0],r[1]),('mta_send_terminal_consumer',c[0],c[1])):
            if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                    module.__dict__ is not namespace or
                    module.__file__!=_GO_STATE_ROOT+'/runtime/'+name+'.py'):
                raise ValueError('send_restore_source_changed')
        if ((network_restore.NetworkObserver,network_restore.NetworkObservation,
                network_restore.NetworkObserver.__init__,network_restore.NetworkObserver.observe,
                network_restore.NetworkObserver.close,network_restore.NetworkObserver.resources_closed,
                network_restore.NetworkObservation.resources_closed,network_restore.compare_observations)!=n[2:] or
                (radio_baseline.normalize,radio_baseline.matches)!=r[2:] or
                (terminal_consumer.consume_terminal_data,terminal_consumer.TerminalConsumptionData)!=c[2:]):
            raise ValueError('send_restore_definition_changed')
        return n

    def _go_network_begin(self,op,session):
        n=self._go_network_source_current()
        if (threading.current_thread() is not op.go_worker or op.go_worker is not session._worker or
                op is not self.operation or session is not op.session or op.go_network_ticket is not None or
                self._network_observer_spec is not self._network_observer_spec_original or
                self._network_observer_spec_original is None):
            raise ValueError('send_network_original_worker')
        spec=self._network_observer_spec_original;until=self._service_cleanup_until_original
        if type(until) is not float or until!=self._service_until_original+60.0:
            raise ValueError('send_network_original_period')
        ticket={'creator':n[2],'ctor_called':True,'ctor_returned':False,'observer':None,
                'before_called':False,'before':None,'after_called':False,'after':None,
                'close_called':False,'close_return':None,'error':None,'unknown':True,
                'spec':spec,'lifetime_until':until,'task_until':op.go_until,'after_until':None}
        op.go_network_ticket=ticket
        try:
            observer=object.__new__(n[2])
            ticket['observer']=op.go_network_observer=op.go_network_original=observer
            n[4](observer,spec[0],spec[1],spec[2],until,clock=time.monotonic)
            ticket['ctor_returned']=True;ticket['unknown']=False
            ticket['before_called']=True
            before=n[5](observer,op.go_until)
            ticket['before']=op.go_network_before=before
            if (type(before) is not n[3] or before._owner is not observer or before.phase_until is not op.go_until or
                    before.valid is not True or n[8](before) is not True or
                    observer._calls!=[before] or n[7](observer) is not True):
                raise ValueError('send_network_baseline_missing')
            return before
        except BaseException as error:
            ticket['error']=error;raise

    def _go_network_finish(self,op):
        # Original GO worker only; no observation is delegated to an external
        # finalizer, and the already issued GO cleanup cap is never renewed.
        ticket=op.go_network_ticket
        if ticket is None:
            return (op.go_network_observer is None and op.go_network_before is None and
                    op.go_network_after is None and op.go_child_called is False)
        try:
            n=self._go_network_source_current();observer=op.go_network_observer
            if (threading.current_thread() is not op.go_worker or type(ticket) is not dict or
                    ticket['observer'] is not observer or observer is not op.go_network_original or
                    ticket['ctor_returned'] is not True or ticket['unknown'] is not False or
                    type(observer) is not n[2] or ticket['spec'] is not self._network_observer_spec_original or
                    observer._original_spec!=(ticket['spec']+(ticket['lifetime_until'],time.monotonic))):
                return False
            before=op.go_network_before
            if op.go_child_called:
                if (ticket['error'] is not None or ticket['before'] is not before or
                        type(before) is not n[3] or before.valid is not True or
                        before.phase_until is not op.go_until or n[8](before) is not True or
                        ticket['after_called'] is not False or time.monotonic()>=op.go_cleanup_until):
                    return False
                ticket['after_until']=op.go_cleanup_until;ticket['after_called']=True
                after=n[5](observer,ticket['after_until'])
                ticket['after']=op.go_network_after=after
                if (type(after) is not n[3] or after._owner is not observer or
                        after.phase_until is not ticket['after_until'] or
                        observer._calls!=[before,after] or n[9](before,after) is not True):
                    raise ValueError('send_network_restored_observation_missing')
            ticket['close_called']=True;ticket['close_return']=n[6](observer)
            closed=ticket['close_return'] is True and n[7](observer) is True
            op.go_network_refs=(ticket,observer,observer._calls,tuple(observer._calls),
                before,op.go_network_after,ticket['spec'],ticket['lifetime_until'],
                ticket['task_until'],ticket['after_until'],tuple(sorted(ticket.items())))
            return closed and time.monotonic()<op.go_cleanup_until
        except BaseException as error:
            if ticket['error'] is None:ticket['error']=error
            op.go_errors.append(error)
            return False
        finally:
            observer=op.go_network_observer
            if ticket['ctor_returned'] is True and not ticket['close_called']:
                ticket['close_called']=True
                try:ticket['close_return']=_GO_NETWORK_DEFINITIONS[6](observer)
                except BaseException as error:
                    if ticket['error'] is None:ticket['error']=error

    def _go_network_closed_current(self,op):
        n=self._go_network_source_current();f=op.go_network_refs
        if op.go_network_ticket is None:
            return not op.go_child_called and op.go_network_observer is None and f is None
        if type(f) is not tuple or len(f)!=11:return False
        ticket,observer,calls,callrefs,before,after,spec,until,task,after_until,saved=f
        return (ticket is op.go_network_ticket and observer is op.go_network_observer and
            observer is op.go_network_original and type(observer) is n[2] and
            calls is observer._calls and len(calls)==len(callrefs) and
            all(a is b for a,b in zip(calls,callrefs)) and before is op.go_network_before and
            after is op.go_network_after and spec is self._network_observer_spec_original and
            ticket['spec'] is spec and ticket['lifetime_until'] is until and
            until is self._service_cleanup_until_original and task is op.go_until and
            tuple(sorted(ticket.items()))==saved and ticket['unknown'] is False and
            ticket['close_called'] is True and ticket['close_return'] is True and
            n[7](observer) is True and (op.go_child_called is False or
                ticket['error'] is None and len(calls)==2 and type(before) is n[3] and type(after) is n[3] and
                before.phase_until is task and after.phase_until is after_until and
                after_until is op.go_cleanup_until and n[9](before,after) is True))

    def _go_pub_preflight_current(self,op):
        # Pure consumption of actual Pub original Parent inventory after its
        # close. Never invoke Pub._check/Parent._context or a renewed probe.
        pub=op.send_publication;report=pub.observer_report;parent=pub.observer_owner
        refs=pub.observer_refs;ticket=pub.observer_attempt
        self._go_private_definitions_current(parent,False)
        if (type(pub) is not op.go_creators[1] or pub.observer_failure is not None or
                pub.observer_called is not True or type(refs) is not tuple or len(refs)<14 or
                refs[0] is not parent or refs[1] is not report or
                type(parent) is not op.go_modules[1]._OBSERVER_ORIGINAL[1] or
                parent.report is not report or parent.result is not report or parent.result_original is not report or
                type(report) is not parent.packet_functions_original[4] or
                parent.reader.value is not report or parent.reader.ended is not True or parent.reader.failure is not None or
                parent.worker is not op.go_worker or parent.closed is not True or parent.unknown is not False or
                parent.failure is not None or parent.close_errors or parent.stderr_bytes!=0 or
                ticket['value'] is not parent or ticket['returned'] is not True or ticket['unknown'] is not False or
                ticket['error'] is not None or parent.process_attempt is not refs[6] or
                parent.rows is not parent.rows_original or parent.row_history is not parent.row_history_original or
                len(parent.rows)!=9 or len(parent.row_history)!=9 or
                any(a is not b for a,b in zip(parent.rows,parent.row_history)) or
                any(row['closed'] is not True or row['unknown'] is not False or row['close_failure'] is not None
                    for row in parent.rows)):
            raise ValueError('send_pub_preflight_original_missing')
        p=parent.process_attempt;wait=p['wait_ticket_original']
        if (p['returned'] is not True or p['unknown'] is not False or p['reaped'] is not True or
                p['wait_called'] is not True or p['waited'] is not True or p['wait_return']!=0 or
                parent.process.returncode is not p['wait_return'] or p['wait_error'] is not None or
                type(wait) is not tuple or len(wait)!=6 or wait is not p['wait_ticket'] or
                wait[0] is not parent.process or wait[1] is not parent.process_pid or
                wait[2] is not parent.process_methods[1] or wait[3] is not p['wait_return']):
            raise ValueError('send_pub_preflight_wait_missing')
        for index,row in enumerate(p['pipes']):
            eof=row['eof_ticket']
            if (type(eof) is not tuple or len(eof)!=7 or wait[4+index] is not eof or
                    eof[0] is not parent.process or eof[1] is not parent.process_pid or eof[2] is not row or
                    eof[3] is not row['raw_original'] or eof[4] is not row['fd_original'] or
                    eof[5] is not row['metadata_original'] or eof[6]!=b'' or row['eof'] is not True or
                    row['raw_original'].closed is not True):
                raise ValueError('send_pub_preflight_eof_missing')
        return pub,parent,report,refs,ticket,p,wait

    @staticmethod
    def _go_private_definitions_current(parent,terminal):
        # Mirror original private Parent definition inventory without _context
        # or io.pid. These exact five modules were really held/read by Parent.
        if (parent.modules is not parent.modules_original or
                parent.module_originals is not parent.definitions_original or
                len(parent.modules)!=5 or len(parent.module_originals)!=5 or
                parent.packet_functions is not parent.packet_functions_original):
            raise ValueError('send_private_definitions_missing')
        for name,module,namespace,raw,functions in parent.module_originals:
            if (type(module) is not types.ModuleType or parent.modules.get(name) is not module or
                    module.__dict__ is not namespace or type(raw) is not bytes or
                    module.__file__!='/var/volatile/tmp/p011-mta-go-observer-libc-v1/runtime/'+name+'.py' or
                    any(namespace.get(key) is not value for key,value in functions)):
                raise ValueError('send_private_definitions_changed')
        f=parent.packet_functions_original;packet=f[0]
        names=('TerminalPacketReader','TerminalPacketData') if terminal else ('ObserverPacketReader','ObserverPacketData')
        cls=getattr(packet,names[0]);data=getattr(packet,names[1])
        if (parent.modules.get('mta_observer_packet') is not packet or cls is not f[1] or
                cls.feed is not f[2] or cls.finish is not f[3] or data is not f[4] or
                type(parent.reader) is not cls):
            raise ValueError('send_private_packet_changed')
        if terminal and (packet.encode_terminal_request is not f[5] or packet.decode_terminal_request is not f[6] or
                packet.TerminalRequestData is not f[7] or f[7].private_request_ascii is not f[8] or
                f[7].private_finish_ascii is not f[9] or data.private_finish_ascii is not f[10]):
            raise ValueError('send_private_terminal_changed')
        return True

    def _verify_go_terminal_restoration(self,op):
        # This is the actual same-worker terminal consumer, not a bool producer
        # or a Native reconstruction. All constituent originals must be present.
        if (threading.current_thread() is not op.go_worker or op.go_worker is not op.session._worker or
                op is not self.operation or op.go_restoration_attempted):
            raise ValueError('send_terminal_original_worker')
        op.go_restoration_attempted=True
        self._go_network_source_current()
        consumed=_GO_CONSUMER_DEFINITIONS[2](self,op)
        op.go_restoration_consumption=consumed # Retain the actual return before checks.
        self._go_private_definitions_current(op.go_terminal_parent,True)
        pub,parent,before,refs,ticket,process,wait=self._go_pub_preflight_current(op)
        data=consumed.terminal;finish=consumed.finish
        if (type(consumed) is not _GO_CONSUMER_DEFINITIONS[3] or consumed.state is not self or
                consumed.operation is not op or consumed.bridge is not op.send_bridge or
                consumed.parent is not op.go_terminal_parent or data is not op.go_terminal_result or
                data.snapshot.stable_key!=before.snapshot.stable_key or
                data.snapshot.key_sha!=before.snapshot.key_sha or
                data.stable_key_sha256!=before.snapshot.key_sha or
                data.finish_data!=self._go_freeze(finish.data) or
                not self._go_network_closed_current(op) or
                op.go_radio_verified is not True or op.go_helper_closed is not True or
                self._probes_closed() is not True):
            raise ValueError('send_terminal_full_originals_missing')
        radio=op.go_radio_probe_original
        if (type(radio) is not dict or not any(row is radio for row in self.radio_restore_probes) or
                radio['before_actor'] is not self._bluetooth_probe_actor_original or
                radio['before'] is not self._bluetooth_caps_original or radio['call_returned'] is not True or
                radio['error'] is not None or
                _probe_result(radio['before_actor'],radio['before'],self.bluez_path,['--capabilities','hci0']) is not True or
                _probe_result(radio['current_actor'],radio['current'],self.bluez_path,['--capabilities','hci0']) is not True or
                radio_baseline.matches(radio['before'],radio['current']) is not True):
            raise ValueError('send_terminal_radio_originals_missing')
        op.go_restoration_refs=(self,op,consumed,op.go_terminal_facts,op.go_network_refs,
            pub,parent,before,refs,ticket,process,wait,radio,tuple(sorted(radio.items())),
            radio['before_actor'],radio['current_actor'],
            tuple(sorted(radio['before_actor'].items())),tuple(sorted(radio['current_actor'].items())),
            radio_baseline.normalize(radio['before']),radio_baseline.normalize(radio['current']),
            tuple(parent.rows),tuple(tuple(sorted(row.items())) for row in parent.rows),
            tuple(sorted(process.items())),tuple(tuple(sorted(row.items())) for row in process['pipes']),
            op.go_terminal_parent.write_ticket,tuple(sorted(op.go_terminal_parent.write_ticket.items())),
            op.go_terminal_parent.input_close_ticket,tuple(sorted(op.go_terminal_parent.input_row.items())))
        if time.monotonic()>=op.go_cleanup_until:
            raise ValueError('send_terminal_original_cleanup_expired')
        # Saved references are not a success ticket: issue this exact completion
        # only after the final original deadline check returned successfully.
        op.go_restoration_completion=(self,op,op.go_worker,op.go_restoration_refs)
        return self._go_restoration_current(op)

    @staticmethod
    def _go_freeze(value):
        if type(value) is dict:return tuple((k,State._go_freeze(value[k])) for k in sorted(value))
        if type(value) in (list,tuple):return tuple(State._go_freeze(v) for v in value)
        return value

    def _go_restoration_current(self,op):
        # Finalizers and Owner only inspect retained original proofs. No clock,
        # source IO, Parent methods, Proc polling, wait or repeat observer call.
        try:
            self._go_network_source_current();f=op.go_restoration_refs;c=op.go_restoration_consumption
            self._go_private_definitions_current(op.go_terminal_parent,True)
            done=op.go_restoration_completion
            if (op.go_restoration_error is not None or op.go_cleanup_unknown is not False or
                    type(done) is not tuple or len(done)!=4 or done[0] is not self or done[1] is not op or
                    done[2] is not op.go_worker or done[3] is not f or
                    type(f) is not tuple or len(f)!=28 or f[0] is not self or f[1] is not op or f[2] is not c or
                    type(c) is not _GO_CONSUMER_DEFINITIONS[3] or c.state is not self or c.operation is not op or
                    f[3] is not op.go_terminal_facts or f[4] is not op.go_network_refs or
                    c.terminal is not op.go_terminal_result or c.bridge is not op.send_bridge or
                    c.parent is not op.go_terminal_parent or self._go_terminal_closed(op) is not True or
                    self._go_network_closed_current(op) is not True or
                    any(a is not b for a,b in zip(self._go_pub_preflight_current(op),f[5:12]))):return False
            radio=f[12]
            if (radio is not op.go_radio_probe_original or tuple(sorted(radio.items()))!=f[13] or
                    radio['before_actor'] is not f[14] or radio['current_actor'] is not f[15] or
                    tuple(sorted(f[14].items()))!=f[16] or tuple(sorted(f[15].items()))!=f[17] or
                    radio_baseline.normalize(radio['before'])!=f[18] or
                    radio_baseline.normalize(radio['current'])!=f[19] or f[18]!=f[19] or
                    any(a is not b for a,b in zip(f[6].rows,f[20])) or len(f[6].rows)!=len(f[20]) or
                    tuple(tuple(sorted(row.items())) for row in f[6].rows)!=f[21] or
                    tuple(sorted(f[10].items()))!=f[22] or
                    tuple(tuple(sorted(row.items())) for row in f[10]['pipes'])!=f[23] or
                    op.go_terminal_parent.write_ticket is not f[24] or
                    tuple(sorted(f[24].items()))!=f[25] or
                    op.go_terminal_parent.input_close_ticket is not f[26] or
                    tuple(sorted(op.go_terminal_parent.input_row.items()))!=f[27] or
                    any(row['closed'] is not True for row in self.probe_actors)):
                return False
            return True
        except BaseException:return False

    def _go_sources(self,op):
        # Future authenticated Boot must PRELOAD ordinary fixed definitions.
        # Missing modules reject: never import/search/fallback through sys.path,
        # and never substitute the private F copies or a caller source flag.
        names=('mta_send_preparation','mta_go_send_publication','mta_go_send_bridge')
        modules=tuple(sys.modules.get(name) for name in names)
        own=sys.modules.get('mta_service')
        if (type(own) is not types.ModuleType or own.__dict__ is not globals() or
            own.__file__!=_GO_STATE_ROOT+'/runtime/mta_service.py' or self.registry.root!=_GO_USER_ROOT or
            self.bluez_path!=_GO_STATE_ROOT+'/native/mta-bluez-helper' or
            self.network_path!=_GO_STATE_ROOT+'/native/mta-network-helper' or self.openssl!='/usr/bin/openssl'):
            raise ValueError('Fixed ordinary State/helper/user sources required')
        for name,module in zip(names,modules):
            if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                module.__name__!=name or module.__file__!=_GO_STATE_ROOT+'/runtime/'+name+'.py'):
                raise ValueError('Fixed ordinary GO parent source required')
        preparation,publication,bridge=modules
        creators=(preparation.PreparedSend,publication.FixedGoSendPublication,bridge.GoSendBridge)
        for module,creator in zip(modules,creators):
            if (type(creator) is not type or type(creator.__init__) is not types.FunctionType or
                creator.__init__.__globals__ is not module.__dict__):
                raise ValueError('Actual ordinary source definition required')
        temp=os.lstat(_GO_PREPARATION_ROOT)
        if (not stat.S_ISDIR(temp.st_mode) or stat.S_IMODE(temp.st_mode)!=0o700 or
            (temp.st_uid,temp.st_gid)!=(0,0) or os.path.realpath(_GO_PREPARATION_ROOT)!=_GO_PREPARATION_ROOT):
            raise ValueError('Existing private preparation root required')
        op.go_modules=modules
        op.go_source_dicts=tuple(module.__dict__ for module in modules)
        op.go_creators=creators
        op.go_originals=(self,op,op.session,op.go_worker,op.go_until,op.send_file_ids,op.send_task_id,
            modules,op.go_creators,bridge.GoSendBridge.status,bridge.GoSendBridge.native_event,
            bridge.GoSendBridge.consumed_gatt_event,bridge.GoSendBridge._consumed_gatt_current,op.go_source_dicts)
        self._go_terminal_sources(op) # Separate ordinary role; never replace Pub's preflight Parent.
        return modules

    def _go_terminal_sources(self,op):
        module=sys.modules.get(_GO_TERMINAL_ROLE);bridge=op.go_modules[2]
        if (type(module) is not types.ModuleType or module.__name__!=_GO_TERMINAL_ROLE or
            module.__file__!=_GO_STATE_ROOT+'/runtime/'+_GO_TERMINAL_ROLE+'.py'):
            raise ValueError('Fixed ordinary terminal Parent source required')
        creator=getattr(module,'ReadonlyTerminalParent',None)
        if (type(creator) is not type or type(creator.__init__) is not types.FunctionType or
            creator.__init__.__globals__ is not module.__dict__):
            raise ValueError('Actual terminal Parent definition required')
        functions=(creator.__init__,creator.collect,creator.close,creator._closed_facts,
            bridge.GoSendBridge.close,bridge.GoSendBridge.finish_report,bridge._finish_wire_v86)
        if any(type(f) is not types.FunctionType for f in functions):
            raise ValueError('Original terminal DATA functions required')
        op.go_terminal_source=(module,module.__dict__,creator,functions,bridge,
            bridge.GoSendBridge,bridge._FinishReportV86)
        self._go_terminal_source_current(op)

    def _go_terminal_source_current(self,op):
        s=op.go_terminal_source
        if type(s) is not tuple or len(s)!=7:raise ValueError('Original terminal source missing')
        module,namespace,creator,functions,bridge,bridge_type,report_type=s
        if (type(module) is not types.ModuleType or sys.modules.get(_GO_TERMINAL_ROLE) is not module or
            module.__dict__ is not namespace or module.__name__!=_GO_TERMINAL_ROLE or
            module.__file__!=_GO_STATE_ROOT+'/runtime/'+_GO_TERMINAL_ROLE+'.py' or
            module.ReadonlyTerminalParent is not creator or type(functions) is not tuple or len(functions)!=7 or
            creator.__init__ is not functions[0] or creator.collect is not functions[1] or
            creator.close is not functions[2] or creator._closed_facts is not functions[3] or
            creator.__init__.__globals__ is not namespace or op.go_modules[2] is not bridge or
            bridge.GoSendBridge is not bridge_type or bridge_type is not op.go_creators[2] or
            bridge_type.close is not functions[4] or bridge_type.finish_report is not functions[5] or
            bridge._finish_wire_v86 is not functions[6] or bridge._FinishReportV86 is not report_type):
            raise ValueError('Original terminal source changed')
        return s

    def _go_terminal_report_current(self,op,bridge,report,original=None):
        s=self._go_terminal_source_current(op);getter,wire=s[3][5:7]
        if type(report) is not s[6] or getter(bridge) is not report or wire(report.data)!=report.raw:
            raise ValueError('Original returned F finish DATA required')
        refs=(report,report.raw,report.data,report.originals,report.reap,report.stdout_eof,report.stderr_eof)
        if original is not None and (type(original) is not tuple or len(original)!=7 or
            any(a is not b for a,b in zip(refs,original))):
            raise ValueError('Original F finish DATA changed')
        return refs

    def _collect_go_terminal(self,op,bridge):
        # Only the original GO worker owns new IO. Cancellation/task expiry do
        # not create a task period here; all IO is clipped by original cleanup.
        if op.go_terminal_attempted:raise ValueError('Terminal collection already attempted')
        op.go_terminal_attempted=True
        if (op is not self.operation or op.session is not self.session or op.epoch!=self.native_epoch or
            threading.current_thread() is not op.go_worker or op.go_worker is not op.session._worker or
            op.go_until is not op.session._task_deadline or bridge is not op.send_bridge or bridge.closed is not True):
            raise ValueError('Original closed GO worker required')
        s=self._go_terminal_source_current(op);creator,functions=s[2],s[3]
        actual,current=self._go_bridge(op)
        if actual is not s[5] or current is not bridge:raise ValueError('Actual original closed Bridge required')
        report=functions[5](bridge)
        if report is None:
            op.go_terminal_unavailable=True
            op.go_terminal_facts=(s,bridge,None) # No terminal ctor/FD/process was called.
            return True
        report_refs=self._go_terminal_report_current(op,bridge,report)
        service=self._service_until_original;service_cleanup=self._service_cleanup_until_original
        if (self._original_service_until is not service or self._original_service_cleanup_until is not service_cleanup or
            type(service) is not float or type(service_cleanup) is not float or service_cleanup!=service+60.0 or
            type(op.go_cleanup_until) is not float or type(report.data['cleanup_until']) is not float):
            raise ValueError('Original terminal cleanup DATA required')
        launch={k:bridge.binding[k] for k in ('run','manifest','task','nonce','native_epoch','operation_epoch','until')}
        launch.update(candidate_sha=bridge.deployment.manifest.candidate_sha,child_pid=bridge._process_pid)
        limits=dict(task_until=op.go_until,service_until=service,go_cleanup_until=op.go_cleanup_until,
                    service_cleanup_until=service_cleanup)
        args=(op.send_task_id,self.native_epoch,op.epoch,op.go_until,service,launch,report.raw,limits,
              report.data['cleanup_until'])
        snapshots=(tuple(sorted(launch.items())),tuple(sorted(limits.items())))
        row={'creator':creator,'name':'go_terminal_parent','value':None,'called':True,'returned':False,
             'unknown':False,'error':None,'collect_called':False,'collect_return':None,'collect_error':None}
        op.go_terminal_ticket=row;op.go_tickets.append(row) # Before __new__/__init__ or any terminal IO.
        parent=None;known=False
        try:
            parent=object.__new__(creator)
            row['value']=op.go_terminal_parent=op.go_terminal_original=parent
            functions[0](parent,*args);row['returned']=True
            self._go_terminal_report_current(op,bridge,report,report_refs)
            if time.monotonic()>=min(op.go_cleanup_until,service_cleanup,args[8]):
                raise ValueError('Original terminal cleanup expired')
            row['collect_called']=True
            returned=functions[1](parent)
            row['collect_return']=op.go_terminal_result=returned # Preserve a late/malformed actual return.
            self._go_terminal_report_current(op,bridge,report,report_refs)
            if (parent.report is not returned or parent.result is not returned or parent.result_original is not returned or
                type(returned) is not parent.packet_functions_original[4] or
                parent.packet_functions_original[10](returned)!=report.raw or
                tuple(sorted(launch.items()))!=snapshots[0] or tuple(sorted(limits.items()))!=snapshots[1]):
                raise ValueError('Original terminal returned DATA changed')
        except BaseException as error:
            if row['error'] is None:row['error']=error
            if row['collect_called']:row['collect_error']=error
            if not row['returned']:row['unknown']=True
            if op.go_terminal_error is None:op.go_terminal_error=error
            raise
        finally:
            if parent is not None and row['returned'] is True:
                try:
                    # collect's finally normally closed it already. Never call
                    # close again or repeat any physical IO merely to recheck.
                    if parent.close_attempted is False:functions[2](parent)
                    known=parent.closed is True and functions[3](parent) is True
                    if not known:row['unknown']=True
                    parent_refs=(parent,parent.rows,tuple(parent.rows),parent.row_history,parent.process,
                        parent.process_original,parent.process_attempt,parent.process_methods,parent.period_original,
                        parent.input_close_ticket,parent.binding_original,parent.packet_functions_original,
                        parent.result_original,parent.request_data_original,
                        None if parent.process_attempt is None else parent.process_attempt['wait_ticket_original'],
                        None if parent.process_attempt is None else parent.process_attempt['pipes'][0]['eof_ticket'],
                        None if parent.process_attempt is None else parent.process_attempt['pipes'][1]['eof_ticket'])
                    row_refs=tuple((r,r['fd_original'],r['metadata_original'],r['raw_original'],r['close_return'],
                                    r['close_error'],r['close_failure']) for r in parent.rows)
                    op.go_terminal_facts=(s,bridge,report_refs,args,snapshots,row,parent_refs,row_refs,known)
                except BaseException as error:
                    row['unknown']=True
                    if op.go_terminal_error is None:op.go_terminal_error=error
                    op.go_errors.append(error)
            elif parent is not None:row['unknown']=True
        if not known:raise ValueError('Terminal Parent inventory pending')
        return True

    def _go_terminal_closed(self,op):
        # External finalizers read saved originals only. No Parent method,
        # fileno/fstat/Popen/wait/clock/collector or mutable ready flag is used.
        if op.go_terminal_attempted is False:
            return op.go_terminal_parent is None and op.go_terminal_ticket is None and op.go_terminal_facts is None
        try:
            f=op.go_terminal_facts;s=self._go_terminal_source_current(op)
            actual,bridge=self._go_bridge(op)
            if actual is not s[5] or bridge is not op.send_bridge:return False
            if type(f) is not tuple or f[0] is not s or f[1] is not op.send_bridge:return False
            if len(f)==3:
                return f[2] is None and op.go_terminal_unavailable is True and op.go_terminal_parent is None and op.go_terminal_ticket is None
            if len(f)!=9 or f[8] is not True:return False
            refs,args,snapshots,row,p,rows=f[2:8]
            if (row is not op.go_terminal_ticket or row['creator'] is not s[2] or row['returned'] is not True or
                row['unknown'] is not False or row['value'] is not op.go_terminal_parent or
                op.go_terminal_parent is not op.go_terminal_original or p[0] is not op.go_terminal_parent or
                type(p[0]) is not s[2] or p[0].worker is not op.go_worker or p[0].closed is not True or
                p[0].unknown is not False or p[0].close_attempted is not True or
                p[1] is not p[0].rows or p[1] is not p[0].rows_original or
                p[3] is not p[0].row_history or p[3] is not p[0].row_history_original or len(p[2])!=len(p[1]) or
                any(a is not b for a,b in zip(p[2],p[1])) or len(p[3])!=len(p[1]) or
                any(a is not b for a,b in zip(p[3],p[1])) or
                p[4] is not p[0].process or p[5] is not p[0].process_original or
                p[6] is not p[0].process_attempt or p[7] is not p[0].process_methods or
                p[8] is not p[0].period_original or p[9] is not p[0].input_close_ticket or
                p[10] is not p[0].binding_original or p[11] is not p[0].packet_functions_original or
                p[12] is not p[0].result_original or p[13] is not p[0].request_data_original or
                row['collect_return'] is not op.go_terminal_result or
                args[3] is not op.go_until or args[4] is not self._service_until_original or
                self._original_service_until is not self._service_until_original or
                self._original_service_cleanup_until is not self._service_cleanup_until_original or
                args[7]['go_cleanup_until'] is not op.go_cleanup_until or
                args[7]['service_cleanup_until'] is not self._service_cleanup_until_original or
                tuple(sorted(args[5].items()))!=snapshots[0] or tuple(sorted(args[7].items()))!=snapshots[1]):return False
            report=refs[0]
            if (report.raw is not refs[1] or report.data is not refs[2] or report.originals is not refs[3] or
                report.reap is not refs[4] or report.stdout_eof is not refs[5] or report.stderr_eof is not refs[6] or
                s[3][6](report.data)!=refs[1] or report.data['cleanup_until'] is not args[8] or
                len(rows)!=len(p[1])):return False
            if op.go_terminal_result is not None and (op.go_terminal_result is not p[12] or
                p[0].result is not p[12] or p[0].report is not p[12] or
                type(p[12]) is not p[11][4] or p[11][10](p[12])!=refs[1]):return False
            for r,fd,metadata,raw,returned,error,failure in rows:
                if (not any(r is current for current in p[1]) or r['closed'] is not True or r['unknown'] is not False or
                    r['close_failure'] is not failure or failure is not None or r['fd_original'] is not fd or
                    r['metadata_original'] is not metadata or r['raw_original'] is not raw or
                    r['close_return'] is not returned or r['close_error'] is not error):return False
            ticket=p[6]
            return (ticket is None or ticket['called'] is False and p[4] is None or
                ticket['returned'] is True and ticket['unknown'] is False and ticket['reaped'] is True and
                ticket['waited'] is True and ticket['wait_called'] is True and ticket['wait_error'] is None and
                ticket['wait_ticket'] is p[14] and ticket['wait_ticket_original'] is p[14] and
                ticket['pipes'][0]['eof_ticket'] is p[15] and ticket['pipes'][1]['eof_ticket'] is p[16] and
                ticket['wait_ticket'][0] is p[4] and ticket['wait_ticket'][1] is p[0].process_pid and
                ticket['wait_ticket'][2] is p[7][1] and ticket['wait_ticket'][3] is ticket['wait_return'] and
                ticket['wait_ticket'][4] is ticket['pipes'][0]['eof_ticket'] and
                ticket['wait_ticket'][5] is ticket['pipes'][1]['eof_ticket'])
        except BaseException:return False

    def _go_bridge(self,op):
        facts=op.go_originals
        if type(facts) is not tuple or len(facts)!=14:raise ValueError('Original GO bridge definitions required')
        modules=op.go_modules;creators=op.go_creators
        if (facts[0] is not self or facts[1] is not op or facts[2] is not op.session or facts[3] is not op.go_worker or
            facts[4] is not op.go_until or facts[5] is not op.send_file_ids or facts[6] is not op.send_task_id or
            facts[7] is not modules or facts[8] is not creators or type(modules) is not tuple or len(modules)!=3 or
            type(creators) is not tuple or len(creators)!=3 or facts[13] is not op.go_source_dicts or
            type(facts[13]) is not tuple or len(facts[13])!=3):raise ValueError('Original GO bridge references changed')
        for name,module,original in zip(('mta_send_preparation','mta_go_send_publication','mta_go_send_bridge'),modules,facts[13]):
            if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                module.__dict__ is not original or module.__file__!=_GO_STATE_ROOT+'/runtime/'+name+'.py'):
                raise ValueError('Ordinary GO parent domain changed')
        creator=creators[2];bridge=op.send_bridge
        if (modules[0].PreparedSend is not creators[0] or modules[1].FixedGoSendPublication is not creators[1] or
            modules[2].GoSendBridge is not creator or creator.status is not facts[9] or
            creator.native_event is not facts[10] or creator.consumed_gatt_event is not facts[11] or
            creator._consumed_gatt_current is not facts[12] or
            type(bridge) is not creator or bridge.state is not self or bridge.operation is not op or
            bridge.worker is not op.go_worker or bridge.prepared is not op.send_prepared or
            bridge.until!=op.go_until or not any(t['value'] is bridge and t['returned'] is True and
                t['unknown'] is False and t['creator'] is creator for t in op.go_tickets)):
            raise ValueError('Actual original GO bridge required')
        return creator,bridge

    def _go_teardown_event(self,op,event):
        # Pure DATA classification, not current GATT/TCP/RF permission or FD
        # closure. Only an actual original worker's helper.close call permits
        # own teardown reports to bypass a finished Bridge/Scan._fail.
        t=op.go_helper_close_ticket
        if (type(t) is not tuple or len(t)!=7 or t[0] is not self or t[1] is not op or t[2] is not op.helper or
            t[2] is not op.go_helper_original or
            t[3] is not op.go_worker or t[3] is not op.session._worker or t[4]!=op.epoch or t[5]!=self.native_epoch or
            t[6] is not op.go_cleanup_until or op.go_helper_close_called is not True):return False
        if event=={'event':'closed'} or event=={'event':'stop','code':'resources_released_or_cleanup_reported'}:
            return True
        if (set(event)!={'event','code'} or event['event']!='client' or event['code'] not in
            ('lease_or_services_timeout','own_connection_disconnect_requested')):return False
        f=op.go_gatt_teardown_original
        if type(f) is not tuple or len(f)!=12:return False
        creator,bridge=self._go_bridge(op)
        accepted,intent,handoff=f[1],f[3],f[4]
        return (f is bridge._consumed_gatt_original and f[0] is bridge and f[2] is op.helper and
            type(intent) is SendIntent and intent is op.send_intent and intent is bridge.intent and
            type(handoff) is bridge._consumed_handoff_type and intent.handoff is handoff and
            handoff.helper is op.helper and handoff.task_id==op.send_task_id and
            f[5] is op.scan and f[5] is bridge.scan and type(f[6]) is int and type(f[7]) is int and
            f[6]==self.native_epoch and f[7]==op.epoch and handoff.native_epoch==f[6] and handoff.operation_epoch==f[7] and
            f[8] is op and f[9] is self and f[10] is bridge.binding and
            bridge.binding['native_epoch']==f[6] and bridge.binding['operation_epoch']==f[7] and
            type(accepted) is dict and set(accepted)=={'event','code'} and
            type(accepted['event']) is str and type(accepted['code']) is str and
            accepted=={'event':'client_write','code':'accepted_by_bluez_not_file_transfer_complete'} and
            type(f[11]) is tuple and f[11]==tuple(sorted(accepted.items())))

    def _go_construct(self,op,index,name,args,kwargs=None):
        creator=op.go_creators[index]
        row={'creator':creator,'name':name,'value':None,'called':True,'returned':False,'unknown':False,'error':None}
        op.go_tickets.append(row) # Before __new__/__init__, including partial originals.
        try:
            value=object.__new__(creator);row['value']=value;setattr(op,name,value)
            creator.__init__(value,*args,**(kwargs or {}))
            row['returned']=True
            return value
        except BaseException as error:row['error']=error;row['unknown']=True;raise

    def _run_go_send(self,op,session):
        if op.go_started:raise ValueError('GO worker cannot start twice')
        op.go_started=True;op.go_worker=threading.current_thread();op.go_until=session._task_deadline
        try:
            self._go_check(op,session)
            if not self._go_send_admitted():raise ValueError('Actual sender admission issuer is absent')
            self._go_sources(op);self._go_check(op,session)
            self._go_network_begin(op,session);self._go_check(op,session)
            op.send_selection=self.registry.open_selection(list(op.send_file_ids))
            op.go_selection_original=op.send_selection # Before fstat/callbacks/prepare.
            self._go_check(op,session)
            prepared=self._go_construct(op,0,'send_prepared',(op.send_selection,self.openssl,op.send_task_id,
                self.nickname,op.go_until,_GO_PREPARATION_ROOT),{'cancelled':op.cancelled.is_set,'clock':time.monotonic})
            op.go_creators[0].prepare(prepared);self._go_check(op,session)
            publication=self._go_construct(op,1,'send_publication',(self,op,prepared))
            deployment=op.go_creators[1].publish(publication);self._go_check(op,session)
            bridge=self._go_construct(op,2,'send_bridge',(self,op,prepared,deployment))
            op.go_creators[2].start(bridge) # Actual F/listener BEFORE the 30s helper scan.
            self._go_check(op,session)
            op.go_creators[2].begin_scan(bridge)
            with self.lock:
                if op is not self.operation:raise ValueError('GO operation changed')
                self.state='scanning';self.reason='网络已准备，等待选择实际附近设备';op.stage='go_scanning'
            while op.send_intent is None:
                now=self._go_check(op,session)
                if op.send_ready.wait(min(.1,op.go_until-now)):break
            self._go_check(op,session)
            if type(op.send_intent) is not SendIntent:raise ValueError('Original actual scan selection required')
            with self.lock:op.stage='go_transferring';self.state='connecting'
            result=op.go_creators[2].run_selected(bridge,op.send_intent)
            op.send_result=result;op.send_bytes_observed=True
            # Actual child completion DATA; no independently verified network
            # restoration receipt is created, even if result['restored'] is True.
            return SendOutcome(result,True,True)
        except BaseException as error:
            op.go_errors.append(error);raise
        finally:
            try:self._close_go_worker(op)
            except BaseException as error:op.go_errors.append(error);op.go_cleanup_unknown=True
            finally:op.go_returned=True # Cleanup must not replace the original business exception.

    def _close_go_worker(self,op):
        # The Session external finalizer MUST NOT call this IO-owning method.
        if threading.current_thread() is not op.go_worker or op.go_worker is not op.session._worker:
            op.go_cleanup_unknown=True;return False
        now=time.monotonic();cap=op.go_until
        if type(cap) is not float or not math.isfinite(cap):op.go_cleanup_unknown=True;return False
        if op.go_cleanup_until is None:op.go_cleanup_until=min(now+60,cap+60)
        end=op.go_cleanup_until
        local_ok=now<end
        refs=[]
        # Fixed order: original Bridge/key/child/pipes, same-worker terminal
        # collection/known close, Pub/Prepared owners, selection, own helper.
        for index,name in ((2,'send_bridge'),(1,'send_publication'),(0,'send_prepared')):
            value=getattr(op,name);refs.append(value)
            rows=[t for t in op.go_tickets if t['name']==name]
            if value is None:
                if rows:local_ok=False
                continue
            if (len(rows)!=1 or rows[0]['value'] is not value or rows[0]['returned'] is not True or rows[0]['unknown']):
                local_ok=False;continue
            try:
                if time.monotonic()>=end:raise ValueError('Original GO parent cleanup expired')
                creator=op.go_creators[index]
                if index==2:
                    self._go_terminal_source_current(op) # Before the actual original Bridge close.
                    actual,original=self._go_bridge(op)
                    if actual._consumed_gatt_current(original) is True:
                        # Retain the actual original fact BEFORE close changes
                        # its active predicates. Never reconstruct it later.
                        op.go_gatt_teardown_original=original._consumed_gatt_original
                if index==1:
                    known=creator.close(value) is True
                    # Both bundle reader and actual Loader file owners matter.
                    for reader in (value.reader,None if value.loader is None else value.loader.owner):
                        if reader is not None and (reader.unknown or not all(
                                r['closed'] is True and r['unknown'] is False for r in reader.rows)):known=False
                else:known=creator.close(value,end) is True
                if index==2 and known:
                    try:self._collect_go_terminal(op,value)
                    except BaseException as error:
                        if op.go_terminal_error is None:op.go_terminal_error=error
                        op.go_errors.append(error)
                    # DATA failure is retained separately; actual unknown/new
                    # child/FD closure still makes local resource closure fail.
                    known=self._go_terminal_closed(op) is True
                if time.monotonic()>=end:known=False
                local_ok=local_ok and known
            except BaseException as error:op.go_errors.append(error);local_ok=False
        bridge=op.send_bridge
        op.go_child_called=bool(bridge is not None and (getattr(bridge,'process_called',False) or
            getattr(bridge,'process_unknown',False)))
        selection=op.send_selection;selection_ok=selection is None and op.go_selection_original is None
        if selection is not None:
            try:
                if selection is not op.go_selection_original:raise ValueError('Original selection changed')
                if time.monotonic()>=end:raise ValueError('Selected FD cleanup expired')
                selection.close();selection_ok=selection.lifecycle_status()['closure_verified'] is True
            except BaseException as error:op.go_errors.append(error);selection_ok=False
        else:selection_ok=selection_ok and self.registry.lifecycle_status()['closure_verified'] is True
        helper=op.helper;helper_ok=helper is None and op.go_helper_original is None
        if helper is not None:
            try:
                if helper is not op.go_helper_original:raise ValueError('Original helper changed')
                if time.monotonic()>=end:raise ValueError('Original helper cleanup expired')
                with self.lock:
                    op.go_helper_close_ticket=(self,op,helper,op.go_worker,op.epoch,self.native_epoch,end)
                    op.go_helper_close_called=True
                helper_ok=helper.close() is True and helper.closure_verified() is True
                if time.monotonic()>=end:helper_ok=False
            except BaseException as error:op.go_errors.append(error);helper_ok=False
        op.go_helper_closed=helper_ok;radio=helper is None and op.go_helper_original is None
        if helper is not None and helper_ok:
            try:
                if time.monotonic()>=end:raise ValueError('Read-only radio verification expired')
                radio=self.verify_radio_restore() is True and time.monotonic()<end
            except BaseException as error:op.go_errors.append(error);radio=False
        op.go_radio_verified=radio
        if radio and self.radio_restore_probes:
            op.go_radio_probe_original=self.radio_restore_probes[-1]
        network_ok=self._go_network_finish(op)
        local_ok=network_ok and local_ok and self._go_terminal_closed(op) and selection_ok and helper_ok and radio and self._probes_closed()
        if local_ok and op.go_child_called:
            try:local_ok=self._verify_go_terminal_restoration(op) is True
            except BaseException as error:
                op.go_restoration_error=error;op.go_errors.append(error);local_ok=False
        if not local_ok:op.go_cleanup_unknown=True
        # Strong same-owner facts are only local resource closure observations.
        op.go_closed_facts=(self,op,op.session,op.go_worker,op.go_until,op.go_cleanup_until,
            tuple(op.go_tickets),tuple(refs),selection,helper,local_ok,op.go_child_called)
        with self.lock:
            self.scanning=False;self.discoverable=False
            self.radio_restore_pending=not (helper_ok and radio and self._probes_closed())
            self.wifi_restore_pending=not local_ok or (op.go_child_called and not self._go_restoration_current(op))
        return local_ok

    def _go_local_closed(self,op):
        # Passive external-finalizer read: never close or fstat on another worker.
        if op.go_started is False:return self._go_zero_closed(op)
        f=op.go_closed_facts
        return (op is self.operation and type(f) is tuple and len(f)==12 and f[0] is self and f[1] is op and
            f[2] is op.session and f[3] is op.go_worker and f[3] is op.session._worker and
            f[4] is op.go_until and f[5] is op.go_cleanup_until and op.go_returned is True and
            not op.go_worker.is_alive() and f[10] is True and op.go_cleanup_unknown is False and
            len(f[6])==len(op.go_tickets) and all(a is b for a,b in zip(f[6],op.go_tickets)) and
            all(type(t) is dict and t['returned'] is True and t['unknown'] is False for t in f[6]) and
            f[7][0] is op.send_bridge and f[7][1] is op.send_publication and f[7][2] is op.send_prepared and
            f[8] is op.send_selection and f[8] is op.go_selection_original and
            f[9] is op.helper and f[9] is op.go_helper_original and f[11] is op.go_child_called and
            self._go_terminal_closed(op) is True)

    def _go_zero_closed(self,op):
        # Actual unstarted/skipped or ended-before-GO Session inventory only;
        # never label this zero-creator path native restoration or RF success.
        try:
            session=op.session;ticket=op.go_session_ctor_ticket
            return (op is self.operation and op.kind=='go_send' and session is self.session and
                type(ticket) is dict and ticket['creator'] is TransferSession and ticket['partial'] is session and
                ticket['returned'] is True and ticket['unknown'] is False and ticket['error'] is None and
                self._send_trial.claimed_original is op and self._send_trial.session_original is session and
                session._lease_owner is op and session.cancelled is op.cancelled and
                session._worker_start_resolved is True and session._worker_start_unknown is False and
                session._worker_start_failed is False and session._worker.is_alive() is False and
                op.go_started is False and op.go_returned is False and op.go_worker is None and
                op.go_child_called is False and op.go_cleanup_unknown is False and op.go_terminal_attempted is False and
                op.go_network_ticket is None and op.go_restoration_consumption is None and not op.go_tickets and
                all(value is None for value in (op.send_selection,op.send_prepared,op.send_publication,op.send_bridge,
                    op.helper,op.key,op.crypto,op.lease,op.transport,op.go_terminal_parent)) and
                self._probes_closed() is True)
        except BaseException:return False

    def _go_public_status(self,op):
        progress=None;report=False;consumed=False;pending=not self._go_local_closed(op)
        try:
            creator,bridge=self._go_bridge(op)
            value=creator.status(bridge)
            if type(value) is dict:
                report=value.get('peer_completion_reported') is True
                consumed=value.get('gatt_credentials_consumed') is True
                p=value.get('latest_progress')
                if (type(p) is dict and set(p)==_GO_PROGRESS_FIELDS and type(p['state']) is str and
                    p['state'] in _GO_PROGRESS_STATES and all(type(p[k]) is bool for k in
                    ('accepted','download_complete','peer_completion_verified','socket_cleanup_pending')) and
                    all(type(p[k]) is int and 0<=p[k]<=MAX_TOTAL+17*1024*1024 for k in
                    ('archiveBytesSent','archiveSize','fileCount','totalSize','connection_attempts')) and
                    p['archiveBytesSent']<=p['archiveSize'] and p['connection_attempts']<=2 and p['fileCount']<=256):
                    progress=dict(p)
        except BaseException:pass
        return {'stage':op.stage,'progress':progress,'peerCompletionReported':report,
            'gattCredentialsConsumed':consumed,'resource_pending':pending or (op.go_child_called and not self._go_restoration_current(op)),
            'parent_resources_closed':not pending,'native_restore_verified':False,'production_admitted':False,
            'terminal_data_observed':op.go_terminal_result is not None,
            'terminal_collection_failed':op.go_terminal_error is not None,
            'independent_restore_verified':self._go_restoration_current(op),
            'admissionBlocked':not self._go_send_admitted(),'sameWorkerClosureReturned':op.go_returned}

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

    def _refresh_received(self,op):
        bridge=op.client_bridge
        if type(bridge) is not StateClientBridge:return
        # This cached field comes from a validated actual Parent result frame,
        # not bytes/progress/EOF. A saved-but-unacknowledged result stays saved.
        if bridge.status()['local_commit_verified'] is not True:return
        try:files=[row for row in self.registry.list_files() if row['name'].startswith('Received/')]
        except (ValueError,OSError):
            with self.lock:
                if op is self.operation:self.reason='文件已保存；目录刷新失败，可进入文件中心查看'
            return
        with self.lock:
            if op is self.operation:self.received=files

    def _run_receive_native(self,op,session):
        # All creation and Parent pipe IO stay on this original State worker.
        # No WifiBackend.prepare/connect, gateway or State-local TCP receiver.
        with self.lock:
            if (op is not self.operation or op.kind!='receive' or op.backend is not None or
                    session is not op.session or session is not self.session or
                    threading.current_thread() is not session._worker or self.worker is not session._worker or
                    op.epoch!=self.native_epoch or op.consent is not True or
                    op.receive_factory is not self._trusted_receive_deployment_factory):
                raise ValueError('Original native receive worker required')
            if op.receive_factory is None:
                self.reason=self.receive_reason
                return Outcome(None,False,False)
            if not self.receive_available or op.cancelled.is_set():return Outcome(None,False,False)
        op.crypto=OpenSslCrypto(self.openssl)
        with self.lock:self.crypto=op.crypto
        op.key=op.crypto.generate_keypair()
        with self.lock:self.key=op.key
        with open('/sys/class/net/wlan0/address') as source:mac=source.read(64).strip()
        status=DeviceInfo(mac,op.key.public_key).to_bytes()
        helper=self.new_helper(op)
        with self.lock:
            if op is not self.operation or op.cancelled.is_set():return Outcome(None,False,False)
            self.radio_restore_pending=True
            # Preserve the Session's original absolute task cap, not now+300.
            op.client_handoff=ReceiveConnectHandoff(self,op,session._task_deadline)
            op.receive_bridge_ticket['started']=True
            bridge=StateClientBridge(self,op,op.client_handoff,op.receive_factory)
            op.receive_bridge_ticket['returned']=bridge
            if type(bridge) is not StateClientBridge or op.client_bridge is not bridge:
                raise ValueError('Native receive bridge owner changed')
            op.stage='listen_pending'
        helper.send({'cmd':'listen','adapter':'hci0','status_b64':base64.b64encode(status).decode('ascii')})
        deadline=min(session._task_deadline,time.monotonic()+120)
        while not op.cancelled.is_set() and time.monotonic()<deadline:
            if op.listen_ready.wait(.1):break
        with self.lock:
            if (op is not self.operation or op.epoch!=self.native_epoch or op.helper is not helper or
                    op.cancelled.is_set() or not op.listen_ready.is_set() or op.stage!='listen_ready'):
                return Outcome(None,False,False)
            packet=encode_advertisement(self.sender_id,1,self.nickname,False)
            op.stage='advert_pending'
        # Actual helper reader only captures/signals; this worker writes pipes.
        helper.send({'cmd':'advert','adapter':'hci0','adv_b64':base64.b64encode(packet['adv_data']).decode('ascii'),
                     'scan_b64':base64.b64encode(packet['scan_rsp']).decode('ascii'),'ttl':120})
        while not op.cancelled.is_set() and time.monotonic()<deadline:
            if op.input_ready.wait(.1):break
        if (op.cancelled.is_set() or not op.input_ready.is_set() or
                op.client_handoff.status()['received'] is not True):return Outcome(None,False,False)
        with self.lock:
            if op is not self.operation or op.epoch!=self.native_epoch or op.client_bridge is not bridge:
                raise ValueError('Native receive bridge changed')
            self.discoverable=False;self.state='connecting';self.wifi_restore_pending=True
        # Bridge decrypts/claims the actual GATT handoff and makes the actual
        # Parent/F own TLS, Receiver and Consent. Remote sockets are never added
        # to this State's local TransferSession transport inventory.
        try:return bridge.run()
        finally:self._refresh_received(op)

    def _run_operation(self,op,session):
        try:
            if op.kind=='go_send':return self._run_go_send(op,session)
            if op.kind in ('scan','send'):return self._run_scan_send(op,session)
            if op.kind=='receive':return self._run_receive_native(op,session)
            raise ValueError('Native operation kind required')
        except BaseException:
            op.failure='发送未完成；未报告传输成功' if op.kind in ('send','go_send') else '接收未完成；未报告传输成功'
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
            if op.kind=='go_send':
                if self._go_teardown_event(op,event) is True:
                    # Original helper.close is already in the same worker's
                    # inventory. Do not feed its expected own-close event back
                    # into the finished bridge or Scan._fail. Actual closure is
                    # still proved by the original helper/process/reader facts.
                    self.scanning=False
                    return
                try:
                    creator,bridge=self._go_bridge(op)
                    if creator.consumed_gatt_event(bridge,event,op.helper,op.epoch,op.epoch) is True:
                        # Accepted original write is already retained by Bridge77.
                        # Scan._fail would otherwise cancel this SAME operation.
                        # This ignores only the two known client lifecycle DATA
                        # reports; cancellation and all other errors stay intact.
                        if len(op.go_gatt_events)<2:op.go_gatt_events.append(event)
                        self.scanning=False
                        return
                    creator.native_event(bridge,event,op.helper,op.epoch,op.epoch)
                except BaseException as error:
                    op.go_errors.append(error);op.go_cleanup_unknown=True;op.cancelled.set()
                if name in ('closed','error','stop','cleanup','client'):
                    op.go_cleanup_unknown=True;op.cancelled.set();op.send_ready.set()
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
            elif (name=='p2p' and op.kind=='receive' and helper is op.helper and
                    type(op.client_handoff) is ReceiveConnectHandoff and self.discoverable and
                    not op.cancelled.is_set() and not op.input_ready.is_set()):
                try:
                    # The exact helper reader owns capture. No plain P2pInfo or
                    # HTTP/UI producer can set the native CONNECT credentials.
                    ReceiveConnectHandoff.capture(op.client_handoff,event,helper,op.epoch,op.epoch)
                    self.discoverable=False;self.state='connecting'
                    op.input_ready.set()
                except Exception:
                    self.reason='原始握手字段或来源校验未通过；没有连接该网络'
                    op.cancelled.set();op.input_ready.set()
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
        # Only F's actual Receiver/Consent prompt and the bridge choice queue
        # are used. This obsolete direct-confirm entry cannot grant consent.
        raise ValueError('Native Parent receive prompt required')

    def receive(self,info):
        raise ValueError('Plaintext receive disabled; original GATT handoff required')

    def restore_network(self):
        # Compatibility entry also converges on the external same-owner path.
        with self.lock:session=self._cleanup_session_locked()
        return self.closed() if session is None else session.close(timeout=2) is True

    def stop_radio(self):
        with self.lock:session=self._cleanup_session_locked()
        return self.closed() if session is None else session.close(timeout=2) is True

    def _close_extra(self,op):
        if op is self.operation and op.kind=='go_send':
            return self._go_local_closed(op) # Saved SAME-worker facts only; no IO/close here.
        if (op is not self.operation or (op.kind=='receive' and op.backend is not None) or
                (op.kind!='receive' and op.backend is not self.wifi_backend)):return False
        if op.kind=='receive':
            op.receive_extra_verified=False
            if type(op.client_handoff) is ReceiveConnectHandoff:
                # Forget retained credentials only. This is not F/network close.
                try:ReceiveConnectHandoff.cancel(op.client_handoff)
                except BaseException:op.actor_unknown=True
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
        closed=(helper_ok and key_ok and radio and not op.actor_unknown and probes and self._probes_closed()
                and send_ok and not op.send_construct_pending and not op.send_construct_unknown)
        if op.kind=='receive':op.receive_extra_verified=bool(closed)
        return closed

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

    def _restore_receive_owner(self,op):
        # Parent/F restoration, extra actors and the original Session exit are
        # distinct facts. The Session finalizer is still alive in this callback;
        # requiring Session.closed() here would make closure circular.
        session=op.session
        if (op is not self.operation or op.kind!='receive' or op.backend is not None or
                op.actor_unknown or session is not self.session or type(session) is not TransferSession or
                self.worker is not session._worker or session._worker.is_alive() is not False or
                op.epoch!=self.native_epoch or op.cancelled is not session.cancelled or
                op.receive_factory is not self._trusted_receive_deployment_factory):return False
        observed=session.status()
        if (observed['worker_alive'] is not False or observed['worker_start_pending'] is not False or
                observed['worker_start_unknown'] is not False or
                any(type(observed[key]) is not int or observed[key]!=0 for key in
                    ('transport_count','handoff_count','unknown_owner_count')) or
                op.transport is not None or self.transport is not None or op.lease is not None or self.lease is not None or
                op.helper is not self.helper or op.key is not self.key or op.crypto is not self.crypto or
                op.receive_extra_verified is not True or self.radio_restore_pending or not self._probes_closed() or
                op.helper is not None and op.helper.closure_verified() is not True or
                op.key is not None and op.key.closed is not True):return False
        ticket=op.receive_bridge_ticket
        if (type(ticket) is not dict or set(ticket)!={'started','returned'} or
                type(ticket['started']) is not bool):return False
        bridge=op.client_bridge
        if bridge is None:
            # Actual constructor was never invoked, so no Parent/F creator was
            # reached. This proves zero F inventory only, not device admission.
            return ticket['started'] is False and ticket['returned'] is None
        if (type(bridge) is not StateClientBridge or ticket['started'] is not True or
                ticket['returned'] is not bridge or bridge.handoff is not op.client_handoff):return False
        try:
            StateClientBridge._owners(bridge)
            if bridge.started:
                # Actual retained Parent wait/reap/absence/EOF/resources and F
                # restore are rechecked outside State.lock, never from UI flags.
                return StateClientBridge.restoration_verified(bridge) is True
            # Pre-run cancellation/listen timeout: no deployment or Parent
            # creator was called. Do not run a new Parent just to get a proof.
            return (bridge.running is False and bridge.parent is None and bridge.deployment is None and
                bridge.factory_ticket['started'] is False and bridge.factory_ticket['returned'] is None and
                bridge.factory_ticket['authenticated'] is False and bridge.parent_ticket['started'] is False and
                bridge.parent_ticket['returned'] is None and bridge.finish_ticket['started'] is False)
        except BaseException:return False

    def _restore_owner(self,op):
        # Only the exact Session external finalizer calls this point. Receive
        # recover rechecks the retained Parent; there is no legacy fallback.
        if op is not self.operation or op.actor_unknown:return False
        try:
            if op.kind=='go_send':
                # A child restored report is not an actual same-source Native
                # receipt. Known no-F early failure is zero-RF inventory only.
                restored=self._go_local_closed(op) and (op.go_child_called is False or self._go_restoration_current(op))
            elif op.kind=='receive':restored=self._restore_receive_owner(op) is True
            elif op.backend is not self.wifi_backend:restored=False
            elif op.kind=='send':restored=self._restore_send_owner(op) is True
            elif op.kind=='scan' and op.lease is None and op.backend._active_lease is None:
                # Scanner performs no Wi-Fi mutation; only the backend's fresh
                # read-only status is inspected. Never restore_active/recover.
                pending=op.backend.status()
                restored=(type(pending) is dict and pending.get('restorePending') is False and
                          pending.get('recoveryLocked') is False)
            else:restored=False
        except BaseException:restored=False
        with self.lock:
            self.wifi_restore_pending=not restored
            if not restored:self.receive_available=False;self.send_available=False
        return restored

    def verify_radio_restore(self):
        if not self._probes_closed():return False
        before_actor=self.bluetooth_probe_actor;before=self.bluetooth_caps
        probe={'creator':_CAPABILITY_CREATOR,'actors':self.probe_actors,'before_actor':before_actor,
               'before':before,'current_actor':None,'current':None,'call_returned':False,'error':None}
        self.radio_restore_probes.append(probe) # Retain before the new capability call.
        start=len(self.probe_actors)
        try:
            if (self.bluez_path!=self._bluez_path_original or
                    before_actor is not self._bluetooth_probe_actor_original or before is not self._bluetooth_caps_original or
                    _probe_result(before_actor,before,self._bluez_path_original,['--capabilities','hci0']) is not True):
                raise ValueError('Original Bluetooth capability baseline required')
            current=capability(self.bluez_path,['--capabilities','hci0'],actors=self.probe_actors)
            probe['current']=current;probe['call_returned']=True
            if len(self.probe_actors)==start+1:probe['current_actor']=self.probe_actors[start]
            current_actor=probe['current_actor']
            verified=(self._probes_closed() is True and
                      self.probe_actors is self._probe_actors_original and
                      before_actor is self._bluetooth_probe_actor_original and before is self._bluetooth_caps_original and
                      probe['creator'] is self._probe_creator_original and
                      current_actor is not None and current_actor is not before_actor and
                      _probe_result(before_actor,before,self.bluez_path,['--capabilities','hci0']) is True and
                      _probe_result(current_actor,current,self.bluez_path,['--capabilities','hci0']) is True and
                      radio_baseline.matches(before,current) is True)
        except BaseException as error:
            probe['error']=error;verified=False
        if not verified:
            self.state='error';self.receive_available=False
            self.reason='蓝牙资源恢复尚未通过独立检查；请勿重复开启互传'
        self.radio_restore_pending=not verified
        if self.state not in ('error','completed'):self.state='idle'
        return verified

    def close(self,timeout=30.0):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<=timeout<=30:
            raise ValueError('Original Session close time budget required')
        with self.lock:
            if self._send_trial is not None:
                send_trial.FixedSendTrial.revoke(self._send_trial,self,'state_closing')
            self.closing=True;self.cancelled.set();self.decision.set()
            if self.operation:
                if type(self.operation.client_bridge) is StateClientBridge:
                    try:self.operation.client_bridge.request_cancel(self.operation)
                    except StateBridgeError:pass
                self.operation.input_ready.set();self.operation.send_ready.set()
                if self.operation.scan is not None:self.operation.scan.cancel()
                if self.operation.kind=='go_send':
                    ticket=self.operation.go_session_ctor_ticket
                    if (type(ticket) is not dict or ticket.get('returned') is not True or
                            ticket.get('unknown') is not False or ticket.get('creator') is not TransferSession or
                            ticket.get('partial') is not self.operation.session or
                            self.session is not self.operation.session):
                        return False # Retain partial inventory; never call its incomplete cancel/close.
            session=self._cleanup_session_locked()
        if session is None:return self.closed()
        now=time.monotonic();cap=self._service_cleanup_until_original
        wait=(max(0.0,min(float(timeout),cap-now)) if
            type(cap) is float and math.isfinite(cap) and
            self._original_service_cleanup_until is cap and math.isfinite(now) else 0.0)
        # Even expiry still requests known original cancellation/closure;
        # it gives the original Session zero wait, never a renewed cap.
        return session.close(timeout=wait) is True and self.closed()

    def closed(self):
        with self.lock:
            if self.session is None:
                return (self.operation is None and all(value is None for value in
                    (self.helper,self.key,self.crypto,self.lease,self.transport,self.worker)) and
                    not self.wifi_restore_pending and not self.radio_restore_pending and self._probes_closed())
            return (self.session.closed() is True and not self.wifi_restore_pending and
                    not self.radio_restore_pending and self._probes_closed())


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
