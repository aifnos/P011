"""Private two-stage transfer owner, Python 3.5; not production State wiring.

Callbacks are trusted lease/coordinator interfaces, never UI inputs. A result,
done Event, TLS detach, requested close or returned join is not an exit proof.
"""
import math
import threading
import time
from collections import namedtuple


Outcome=namedtuple('Outcome','payload local_commit_verified peer_ack_verified')
SendOutcome=namedtuple('SendOutcome','payload local_bytes_verified peer_ack_verified')
MAX_TRANSPORTS=8
MAX_HANDOFFS=64
MAX_ATTEMPTS=8
_PROOF_FIELDS=('recognized_raw','all_sockets_closed','all_actors_exited','close_verified')
_PENDING_FIELDS=('sockets_pending','actors_pending','threads_pending','wrappers_pending',
                 'unknown_wrappers','unknown_resources','processes_pending')


class SessionError(RuntimeError):
    pass


def _budget(value,maximum):
    if type(value) not in (int,float) or not 0<=value<=maximum or not math.isfinite(value):
        raise SessionError('invalid_budget')
    return float(value)


class TransferSession(object):
    """One task, one active finalizer, retained exact historical owners.

    task(session) returns Outcome for receive or SendOutcome for explicit send.
    Direction is a trusted constructor choice, never a UI capability flag.
    Register each dynamically returned transport
    and every factory handoff immediately. Extra actor cleanup must prove any
    producer which did not hand off a socket; an empty handoff list is no proof.
    Failed cleanup can be rechecked only by the next explicit close() call.
    """
    def __init__(self,task,restore,lease_owner,scoped_owner=None,scoped_release=None,
                 extra_actor_close=None,cancelled=None,task_timeout=300,finalize_timeout=30,direction='receive'):
        if type(direction) is not str or direction not in ('receive','send'):
            raise SessionError('invalid_direction')
        if not callable(task) or not callable(restore) or not callable(extra_actor_close) or lease_owner is None:
            raise SessionError('trusted_callbacks_and_lease_required')
        if (scoped_owner is None)!=(scoped_release is None) or (scoped_release is not None and not callable(scoped_release)):
            raise SessionError('scoped_owner_and_release_required')
        if cancelled is not None and not isinstance(cancelled,threading.Event):raise SessionError('cancel_event_required')
        self.task_timeout=_budget(task_timeout,300)
        self.finalize_timeout=_budget(finalize_timeout,120)
        self.cancelled=cancelled if cancelled is not None else threading.Event()
        self._lock=threading.RLock()
        self._direction=direction
        self._task=task;self._restore=restore;self._release=scoped_release;self._extra=extra_actor_close
        self._lease_owner=lease_owner;self._scoped_owner=scoped_owner
        self._transports=[];self._handoffs=[];self._unknown=[];self._generation=0
        self._outcome=None;self._invalid_result=None;self._task_failed=False
        self._reason='not_started';self._phase='prepared';self._callback_pending=0
        self._started=False;self._worker_start_claimed=False;self._worker_start_resolved=False
        self._worker_start_failed=False;self._worker_skipped=False
        self._worker_start_unknown=False
        self._task_deadline=None;self._cancel_at=None
        self._release_done=False;self._extra_done=False;self._restore_done=False
        self._transports_done=False;self._all_stages_done=False
        # Exact worker and initial finalizer are installed before any start.
        self._worker=threading.Thread(target=self._worker_main,name='mta-transfer-worker')
        self._worker.daemon=True
        self._attempts=[]
        self._new_attempt_locked()

    def _new_attempt_locked(self):
        row={'thread':None,'claimed':False,'resolved':False,'failed':False,'unknown_start':False}
        thread=threading.Thread(target=self._finalizer_main,args=(row,),name='mta-transfer-finalizer')
        thread.daemon=True;row['thread']=thread;self._attempts.append(row)
        return row

    @staticmethod
    def _alive(thread):
        try:return thread.is_alive() is not False
        except Exception:return True

    def _pending(self,reason):
        with self._lock:
            self._phase='pending';self._reason=reason;self._all_stages_done=False

    def _register(self,resource,invalid=None):
        self._generation+=1;self._transports_done=False;self._all_stages_done=False
        if self._release_done or self._extra_done or self._restore_done:
            invalid=invalid or 'registration_after_release'
        if invalid:
            def same(value):
                if value is resource:return True
                return (type(value) is tuple and type(resource) is tuple and len(value)==len(resource)==2
                        and value[0] is resource[0] and value[1] is resource[1])
            if not any(same(value) for value in self._unknown):self._unknown.append(resource)
            self._phase='pending';self._reason=invalid
            self.cancelled.set()
            raise SessionError(invalid)

    def attach_transport(self,transport):
        with self._lock:
            invalid=None
            try:
                valid=all(callable(getattr(transport,name,None)) for name in ('close','closed','lifecycle_status','closure_snapshot'))
            except Exception:valid=False
            if not valid:invalid='transport_contract_unknown'
            elif any(item is transport for item in self._transports):invalid='duplicate_transport'
            elif len(self._transports)>=MAX_TRANSPORTS:invalid='transport_limit'
            if invalid:self._register(transport,invalid)
            self._transports.append(transport)
            self._register(transport)
        return transport

    def register_handoff(self,transport,raw):
        with self._lock:
            invalid=None
            if self._scoped_owner is None:invalid='handoff_owner_missing'
            elif not any(item is transport for item in self._transports) or raw is None:invalid='handoff_identity_unknown'
            elif any(item[1] is raw for item in self._handoffs):invalid='duplicate_handoff'
            elif len(self._handoffs)>=MAX_HANDOFFS:invalid='handoff_limit'
            if invalid:self._register((transport,raw),invalid)
            self._handoffs.append((transport,raw));self._register((transport,raw))
        return raw

    def _start_attempt(self,row):
        with self._lock:
            if row['claimed']:return
            row['claimed']=True
        try:row['thread'].start()
        except BaseException:
            with self._lock:row['failed']=True;row['unknown_start']=True
            self._pending('finalizer_start_unknown')
        finally:
            with self._lock:row['resolved']=True

    def start(self):
        with self._lock:
            if self._started:raise SessionError('session_already_started')
            self._started=True;self._worker_start_claimed=True
            self._task_deadline=time.monotonic()+self.task_timeout
            self._phase='running';self._reason=''
        try:self._worker.start()
        except BaseException:
            with self._lock:self._worker_start_failed=True;self._worker_start_unknown=True;self._task_failed=True
            self.cancel();self._pending('worker_start_unknown')
        finally:
            with self._lock:self._worker_start_resolved=True
        self._start_attempt(self._attempts[0])
        return self

    def cancel(self):
        with self._lock:
            if self._cancel_at is None:self._cancel_at=time.monotonic()
        self.cancelled.set()

    def _worker_main(self):
        try:
            while True:
                with self._lock:resolved=self._worker_start_resolved;unknown=self._worker_start_unknown
                if unknown or self.cancelled.is_set():return
                if resolved:break
                if time.monotonic()>=self._task_deadline:self.cancel();return
                time.sleep(.005)
            if self.cancelled.is_set():return
            if time.monotonic()>=self._task_deadline:
                self.cancel();return
            result=self._task(self)
            with self._lock:
                valid=(self._direction=='receive' and type(result) is Outcome and
                       type(result.local_commit_verified) is bool and type(result.peer_ack_verified) is bool)
                valid=valid or (self._direction=='send' and type(result) is SendOutcome and
                       type(result.local_bytes_verified) is bool and type(result.peer_ack_verified) is bool)
                if valid:
                    self._outcome=result
                else:
                    self._invalid_result=result;self._task_failed=not self.cancelled.is_set()
                    self._reason='task_cancelled' if self.cancelled.is_set() else 'task_result_unknown'
        except BaseException:
            with self._lock:
                self._task_failed=not self.cancelled.is_set()
                self._reason='task_cancelled' if self.cancelled.is_set() else 'task_failed'
        finally:
            # Only request transport cleanup here, never restore/clear owners.
            with self._lock:transports=list(self._transports)
            for transport in transports:
                try:transport.close(timeout=0)
                except BaseException:pass

    def _wait_worker(self):
        while True:
            with self._lock:
                resolved=self._worker_start_resolved
                task_end=self._task_deadline
                cancel_at=self._cancel_at
                skipped=self._worker_skipped
                unknown=self._worker_start_unknown
            if unknown:self._pending('worker_start_unknown');return False
            if resolved and (skipped or not self._alive(self._worker)):return True
            now=time.monotonic()
            if self.cancelled.is_set() and cancel_at is None:
                self.cancel();continue
            if task_end is not None and now>=task_end and cancel_at is None:
                self.cancel();continue
            end=(cancel_at+self.finalize_timeout) if cancel_at is not None else task_end
            if end is not None and now>=end:
                self._pending('worker_exit_pending');return False
            if self._worker is threading.current_thread():
                self._pending('worker_self_join_forbidden');return False
            if resolved:
                try:self._worker.join(min(.05,max(0,end-now)) if end is not None else .05)
                except (RuntimeError,ValueError):pass
            else:time.sleep(.005)

    def _generation_ok(self,generation):
        with self._lock:return self._generation==generation and not self._unknown

    @staticmethod
    def _full_lifecycle(value,minimum_records=0):
        return (type(value) is dict and value.get('closing') is True and
                value.get('close_verified') is True and value.get('cleanup_pending') is False and
                type(value.get('socket_records')) is int and value['socket_records']>=minimum_records and
                all(type(value.get(name)) is int and value[name]==0 for name in _PENDING_FIELDS))

    def _check_transports(self,transports,handoffs,generation,deadline):
        ok=True;snapshots=[]
        for transport in transports:
            try:
                remaining=max(0,deadline-time.monotonic())
                closed=transport.close(timeout=min(2,remaining)) is True
                still_closed=transport.closed() is True
                status=transport.lifecycle_status()
                minimum=sum(pair[0] is transport for pair in handoffs)
                verified=self._full_lifecycle(status,minimum)
                ok=closed and still_closed and verified and ok
            except BaseException:ok=False
        for transport,raw in handoffs:
            try:
                proof=transport.closure_snapshot(raw)
                minimum=sum(pair[0] is transport for pair in handoffs)
                valid=(self._full_lifecycle(proof,minimum) and all(proof.get(name) is True for name in _PROOF_FIELDS)
                       and proof.get('cleanup_pending') is False)
                snapshots.append((transport,raw,dict(proof) if type(proof) is dict else None))
                ok=valid and ok
            except BaseException:ok=False;snapshots.append((transport,raw,None))
        if not ok:self._pending('transport_close_pending');return None
        if time.monotonic()>deadline:self._pending('cleanup_deadline');return None
        if not self._generation_ok(generation):self._pending('registration_changed');return None
        return tuple(snapshots)

    def _stage(self,name,callback,args,generation,deadline):
        with self._lock:
            if getattr(self,'_'+name+'_done'):return True
            if self._generation!=generation or self._unknown:
                self._pending('registration_changed');return False
            if time.monotonic()>=deadline:
                self._pending('cleanup_deadline');return False
            self._phase=name;self._callback_pending+=1
        success=False
        try:success=callback(*args) is True
        except BaseException:pass
        finally:
            with self._lock:self._callback_pending-=1
        with self._lock:
            if not success:self._pending(name+'_pending');return False
            if time.monotonic()>deadline:self._pending('cleanup_deadline');return False
            if self._generation!=generation or self._unknown:
                self._pending('registration_changed');return False
            setattr(self,'_'+name+'_done',True)
            return True

    def _finalizer_main(self,row):
        try:
            start_deadline=time.monotonic()+self.finalize_timeout
            while True:
                with self._lock:resolved=row['resolved'];unknown=row['unknown_start']
                if unknown:self._pending('finalizer_start_unknown');return
                if resolved:break
                if time.monotonic()>=start_deadline:self._pending('finalizer_start_pending');return
                time.sleep(.005)
            if not self._wait_worker():return
            deadline=time.monotonic()+self.finalize_timeout
            with self._lock:
                generation=self._generation;transports=tuple(self._transports);handoffs=tuple(self._handoffs)
                self._phase='transport_close'
            snapshots=self._check_transports(transports,handoffs,generation,deadline)
            if snapshots is None:return
            with self._lock:self._transports_done=True
            if self._scoped_owner is None:
                with self._lock:self._release_done=True
            elif not self._stage('release',self._release,(self._scoped_owner,handoffs,snapshots),generation,deadline):return
            if not self._stage('extra',self._extra,(self._lease_owner,),generation,deadline):return
            if not self._stage('restore',self._restore,(self._lease_owner,),generation,deadline):return
            with self._lock:
                if self._generation!=generation or self._unknown:
                    self._pending('registration_changed');return
                self._all_stages_done=True;self._phase='awaiting_finalizer_exit';self._reason=''
            # This thread is still alive here. Only an external passive observer
            # can see its actual exit and derive a fully closed Session.
        except BaseException:self._pending('finalizer_failed')

    def _closed_locked(self):
        return (self._started and self._worker_start_resolved and not self._alive(self._worker) and
                not self._worker_start_unknown and self._all_stages_done and not self._unknown and not self._callback_pending and
                all(row['claimed'] and row['resolved'] and not row['unknown_start'] and not self._alive(row['thread']) for row in self._attempts))

    def close(self,timeout=2):
        timeout=_budget(timeout,30)
        with self._lock:
            if self._closed_locked():return True
        self.cancel()
        with self._lock:
            if not self._started:
                self._started=True;self._worker_skipped=True;self._worker_start_resolved=True
                self._task_deadline=time.monotonic()
            row=self._attempts[-1]
            if row['unknown_start']:
                self._pending('finalizer_start_unknown');return False
            if row['claimed'] and row['resolved'] and not self._alive(row['thread']):
                if len(self._attempts)>=MAX_ATTEMPTS:
                    self._pending('finalizer_attempt_limit');return False
                row=self._new_attempt_locked()
        self._start_attempt(row)
        if threading.current_thread() is self._worker:return False
        if row['thread'] is not threading.current_thread():
            try:row['thread'].join(timeout)
            except (RuntimeError,ValueError):pass
        return self.closed()

    def closed(self):
        with self._lock:return self._closed_locked()

    def status(self):
        # No close, callback, network mutation or owner clearing in this method.
        with self._lock:
            closed=self._closed_locked();outcome=self._outcome
            commit=bool(self._direction=='receive' and outcome and outcome.local_commit_verified is True)
            sent=bool(self._direction=='send' and outcome and outcome.local_bytes_verified is True)
            ack=bool(outcome and outcome.peer_ack_verified is True)
            phase=self._phase
            if closed:
                if self._direction=='send':
                    phase='completed' if sent and ack else 'sent_unconfirmed' if sent else 'failed' if self._task_failed else 'cancelled'
                else:
                    phase='completed' if commit and ack else 'saved_unconfirmed' if commit else 'failed' if self._task_failed else 'cancelled'
            result={'phase':phase,'reason':self._reason,'closed':closed,'cancel_requested':self.cancelled.is_set(),
                    'local_commit_verified':commit,'peer_ack_verified':ack,'result_available':outcome is not None,
                    'task_failed':self._task_failed,'worker_alive':self._alive(self._worker),
                    'worker_start_pending':self._worker_start_claimed and not self._worker_start_resolved,
                    'worker_start_unknown':self._worker_start_unknown,
                    'finalizers_alive':sum(self._alive(row['thread']) for row in self._attempts),
                    'finalizer_starts_pending':sum(row['claimed'] and not row['resolved'] for row in self._attempts),
                    'finalizer_starts_unknown':sum(row['unknown_start'] for row in self._attempts),
                    'finalizer_attempts':len(self._attempts),'callbacks_pending':self._callback_pending,
                    'transport_count':len(self._transports),'handoff_count':len(self._handoffs),'unknown_owner_count':len(self._unknown),
                    'transports_verified':self._transports_done,'release_verified':self._release_done,
                    'extra_actors_verified':self._extra_done,'restore_verified':self._restore_done,
                    'restore_pending':not closed}
            if self._direction=='send':
                result.update(direction='send',local_bytes_verified=sent)
            return result
