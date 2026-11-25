"""Synthetic HOST contracts only; no device/provider, sockets or subprocesses."""
import ast
import os
import sys
import unittest

ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0,os.path.join(ROOT,'runtime'))
import mta_p2p_client_init as c
import mta_ip as ip

BOOT='12345678-1234-1234-1234-123456789abc'
IDENTITY=c.Identity('a'*64)  # HOST-only synthetic manifest, never a frozen ID.
STA=c.Origin(0,1,22,'wlan0',2)
OWN=c.Origin(0,2,23,'mta1234abcd',8)
RULES=(ip.RuleRecord(0,255),ip.RuleRecord(32766,254),ip.RuleRecord(32767,253))
IP=ip.IpSnapshot((),(),RULES)
STATUS=(b'wpa_state=INACTIVE\np2p_device_address=02:11:22:33:44:55\n'
        b'address=02:66:77:88:99:aa\nuuid=12345678-1234-1234-1234-123456789abc\n')


def actor(pid,exe='/usr/bin/python3.5',argv='b'*64,tasks=None):
    return c.Actor(pid,100,exe,argv,((pid,100,'S'),) if tasks is None else tasks)


STOCK=(actor(11,'/usr/bin/Z03'),actor(12,'/usr/bin/control_engine'),actor(13,'/usr/bin/weston'))


def snapshot(owned=None,ipv4=IP,ipv6_addresses=(),ipv6_routes=(),boot=BOOT,sha='c'*64):
    return c.Snapshot(boot,c.STOCK_PINS,STOCK,STA,sha,2412,
                      (STA,) if owned is None else (STA,owned),ipv4,ipv6_addresses,ipv6_routes,True)


def caps():
    return {'complete':True,'phys':({'index':0,'iftypes':(2,3,8,9,10),'software_iftypes':(),
        'unknown_constraints':(),'combinations':({'max_interfaces':3,'num_channels':2,
        'radar_widths':0,'radar_regions':0,'beacon_match':False,'limits':(
            {'types':(2,3),'max':1},{'types':(8,9),'max':1},{'types':(10,),'max':1})},)},)}


class Clock(object):
    def __init__(self): self.value=10.0
    def __call__(self): return self.value


class Store(c.ClientInitStore):
    """NOT a durable Store. Records/fd/locks below are explicit HOST fixtures."""
    def __init__(self):
        self.record=None; self.pending=False; self.locked=False; self.calls=[]
        self.prior=True; self.pending_override=None; self.save_fail=False
        self.active_close=True; self.final_close=True; self.stale=False
        self.lock=object(); self.inherited=[]
        self.finish_exception=False; self.lock_readback=False; self.readback_exception=False
        self.identity=None; self.issued_receipt=None; self.authenticate=True
        self.terminal_publish=True; self.marker_observation=None; self.clear_observation=None

    def acquire(self,identity,deadline,inherited=None):
        self.calls.append('acquire'); self.inherited.append(inherited)
        self.identity=identity
        self.locked=True; return self.lock
    def lock_valid(self,locks): return self.locked and locks is self.lock
    def current(self,locks):
        self.calls.append('current')
        if not self.lock_valid(locks): raise c.ClientInitError('invalid_locks')
        if self.stale and self.record is not None:
            return self.record.replace(deadline=self.record.deadline+1)
        return self.record
    def pending_clear(self,locks): return not self.pending if self.pending_override is None else self.pending_override
    def prior_clear(self,locks,baseline,deadline): return self.prior
    def pending_matches(self,locks,record): return self.pending and record is self.record
    def commit(self,locks,record):
        if not self.lock_valid(locks): raise c.ClientInitError('invalid_locks')
        self.calls.append('commit:'+record.stage)
        if self.save_fail: raise c.ClientInitError('durability_unknown')
        self.record=record; self.pending=True; return record
    def active_return(self,locks,record):
        self.calls.append('active_return'); self.locked=False
        return c.CloseProof(1,(True,),(self.active_close,))
    def finish(self,locks,record,normal_restored,deadline):
        self.calls.append('finish')
        if self.finish_exception: raise OSError('SECRET_FINISH_FD')
        terminal=normal_restored and self.terminal_publish
        result=record.replace(stage='reconciled',ready=False) if terminal else record
        state=self.marker_observation or ('absent_observed' if terminal or not self.pending else 'retained_observed')
        clear=self.clear_observation or ('verified' if terminal and state=='absent_observed' else 'not_attempted')
        if record is not None: self.record=result
        if state!='unknown': self.pending=state=='retained_observed'
        self.locked=not self.final_close
        complete=bool(normal_restored and terminal and state=='absent_observed' and clear=='verified' and self.final_close)
        receipt=c.FinishReceipt(self,locks,self.identity,record,result,normal_restored,terminal,
            state,clear,self.final_close,not self.final_close,complete)
        self.issued_receipt=receipt  # Only synthetic issuer registry, NOT OS proof.
        return receipt
    def authenticate_finish(self,locks,record,receipt,deadline):
        self.calls.append('authenticate_finish')
        return bool(self.authenticate and receipt is self.issued_receipt and locks is self.lock and
                    receipt.request_record is record and receipt.identity is self.identity)
    def closed_locks(self,locks,deadline):
        self.calls.append('closed_locks')
        if self.readback_exception: raise OSError('SECRET_READBACK_FD')
        if locks is not self.lock: raise c.ClientInitError('invalid_locks')
        return c.CloseProof(2,(True,True),(self.lock_readback,self.lock_readback))


def changed_receipt(receipt, **changes):
    """Fault injection: no private issuer registration unless test does so."""
    values=dict((key,getattr(receipt,key)) for key in c.FinishReceipt.__slots__)
    values.update(changes)
    return c.FinishReceipt(**values)


class Provider(c.ClientInitProvider):
    """NOT a Linux implementation. Every returned observation is synthetic."""
    def __init__(self,clock):
        self.clock=clock; self.calls=[]; self.owned=None; self.handles={}
        self.caps_data=caps(); self.status_data=STATUS; self.origin_ok=True; self.actor_ok=True
        self.reap=True; self.close_ok=True; self.close_exception=False; self.create_type=8
        self.create_error=False; self.spawn_error=False; self.late_spawn=False; self.base_changed=False
        self.return_actor_z=False; self.exit_tasks=(); self.absent=True; self.other_ip=False
        self.close_calls=0; self.fail_free_text=False; self.durable_seen=[]; self.store=None
        self.late_registration=False; self.change_current_on_status=False
        self.executor_role='owner'; self.executor_actor=actor(201); self.executor_ofd=True

    def executor(self,deadline):
        self.calls.append('executor')
        return c.ExecutorProof(self.executor_role,self.executor_actor,self.executor_ofd)
    def snapshot(self,deadline):
        self.calls.append('snapshot')
        ipv4=IP
        if self.other_ip:
            ipv4=ip.IpSnapshot((ip.AddressRecord(23,0x0a010102,0x0a010102,24,0x80,0,None,None,
                                                 (0xffffffff,0xffffffff,1,1)),),(),RULES)
        return snapshot(self.owned,ipv4=ipv4,sha='d'*64 if self.base_changed else 'c'*64)
    def caps(self,deadline): self.calls.append('caps'); return self.caps_data
    def original_actors(self,baseline,deadline): self.calls.append('original_actors'); return self.actor_ok
    def register(self,role,identity,boot,deadline):
        self.calls.append('register:'+role)
        if self.late_registration: self.clock.value=40
        return c.Ticket(('1' if role=='watchdog' else '2')*32,role,boot,
                        '/usr/bin/python3.5' if role=='watchdog' else '/private/mta-wpa-supplicant','b'*64)
    def _launch(self,ticket):
        handle=c.Handle(ticket,actor(101 if ticket.role=='watchdog' else 102,ticket.exe,ticket.argv_sha),object())
        self.handles[ticket.role]=handle; return handle
    def launch_watchdog(self,ticket,record,inherited_locks,deadline):
        self.calls.append('launch_watchdog')
        self.durable_seen.append(record.stage=='watchdog_intent')
        return self._launch(ticket)
    def register_interface(self,identity,baseline,deadline):
        self.calls.append('register_interface'); return c.InterfaceTicket(BOOT,0,OWN.name,10,99)
    def create_client(self,ticket,deadline):
        self.calls.append('create_client')
        self.durable_seen.append(self.store.record.stage=='interface_intent')
        if self.create_error: raise c.ClientInitError('origin_changed')
        self.owned=c.Origin(OWN.phy,OWN.wdev,OWN.ifindex,OWN.name,self.create_type)
        return self.owned
    def origin_up(self,owned,deadline): self.calls.append('origin_up'); return self.origin_ok
    def launch_controller(self,ticket,owned,config,deadline):
        self.calls.append('launch_controller')
        if config!=c.CLIENT_CONFIG: raise c.ClientInitError('invalid_status')
        handle=self._launch(ticket)
        if self.spawn_error: raise c.ClientInitError('actor_unknown')
        if self.late_spawn: self.clock.value=40
        return handle
    def release_exec(self,handle,deadline):
        self.calls.append('release:'+handle.ticket.role)
        self.durable_seen.append(self.store.record.stage in ('watchdog_saved','controller_saved'))
        return True
    def live_actor(self,handle,deadline):
        self.calls.append('live:'+handle.ticket.role)
        if self.return_actor_z:
            return actor(handle.actor.pid,handle.actor.exe,handle.actor.argv_sha,
                         ((handle.actor.pid,100,'Z'),(555,101,'S')))
        return handle.actor
    def status(self,handle,owned,deadline):
        self.calls.append('status')
        if self.change_current_on_status:
            self.store.record=self.store.record.replace(deadline=self.store.record.deadline+1)
        if self.fail_free_text: raise OSError('SECRET_PACKET_NEVER_PUBLIC')
        return self.status_data
    def resolve(self,ticket,deadline):
        self.calls.append('resolve:'+ticket.role)
        if ticket.role not in self.handles:
            return c.UnlaunchedProof(ticket,True,True)  # explicit synthetic registry, not stage inference
        return self.handles[ticket.role]
    def stop_and_reap(self,handle,deadline):
        self.calls.append('reap:'+handle.ticket.role)
        return c.ExitProof(handle.actor,self.absent,self.exit_tasks,self.reap,0 if self.reap else None)
    def exit_proof(self,handle,deadline):
        self.calls.append('exit_proof:'+handle.ticket.role)
        return c.ExitProof(handle.actor,self.absent,self.exit_tasks,self.reap,0 if self.reap else None)
    def delete_client(self,owned,deadline):
        self.calls.append('delete_client')
        if not self.origin_ok: return False
        self.owned=None; return True
    def origin_absent(self,owned,deadline): self.calls.append('origin_absent'); return self.owned is None
    def close_resources(self,handles,deadline):
        self.calls.append('close_resources'); self.close_calls+=1
        if self.close_exception: raise c.ClientInitError('resource_close_unknown')
        return c.CloseProof(2,(True,True),(self.close_ok,True))
    def closed_resources(self,handles,deadline):
        self.calls.append('closed_resources')
        return c.CloseProof(2,(True,True),(self.close_ok,True))


class ClientInitTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock(); self.store=Store(); self.provider=Provider(self.clock); self.provider.store=self.store
        self.lease=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)

    def error(self,code,call):
        with self.assertRaises(c.ClientInitError) as caught: call()
        self.assertEqual(code,caught.exception.code)

    def ready(self):
        result=self.lease.start(); self.assertTrue(result['client_init_ready']); return result

    def test_construct_has_no_callback_or_io(self):
        self.assertEqual([],self.provider.calls); self.assertEqual([],self.store.calls)

    def test_arbitrary_provider_and_store_rejected(self):
        self.error('invalid_provider',lambda:c.ClientInitLease(object(),self.store,IDENTITY,self.clock))
        self.error('invalid_store',lambda:c.ClientInitLease(self.provider,object(),IDENTITY,self.clock))

    def test_unimplemented_provider_failclosed(self):
        lease=c.ClientInitLease(c.ClientInitProvider(),self.store,IDENTITY,self.clock)
        self.assertEqual('provider_unavailable',lease.start()['reason'])

    def test_unimplemented_store_failclosed(self):
        lease=c.ClientInitLease(self.provider,c.ClientInitStore(),IDENTITY,self.clock)
        self.assertEqual('store_unavailable',lease.start()['reason'])

    def test_full_success_is_host_only_and_capabilities_false(self):
        result=self.ready(); self.assertEqual('HOST_OWNER_CONTRACT_ONLY',result['evidence'])
        for field in ('association_verified','ip_ready','dhcp_ready','data_ready','phone_tested','receive_available','send_available'):
            self.assertIs(result[field],False)
        self.assertTrue(result['rf_init_possible']); self.assertTrue(all(self.provider.durable_seen))

    def test_registered_tickets_and_exec_gate_order(self):
        self.ready()
        calls=self.provider.calls
        self.assertLess(calls.index('register:watchdog'),calls.index('launch_watchdog'))
        self.assertLess(calls.index('register_interface'),calls.index('create_client'))
        self.assertLess(calls.index('register:controller'),calls.index('launch_controller'))
        self.assertLess(calls.index('launch_controller'),calls.index('release:controller'))

    def test_restore_reaps_both_actors_then_deletes_exact_client(self):
        self.ready(); self.provider.calls=[]
        result=self.lease.restore(); self.assertTrue(result['cleanup_complete']); self.assertFalse(result['pending_retained'])
        self.assertEqual('reconciled',result['stage'])
        for role in ('controller','watchdog'):
            self.assertLess(self.provider.calls.index('reap:'+role),self.provider.calls.index('delete_client'))

    def test_recovery_reads_current_only_after_lock(self):
        self.ready(); recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.store.calls=[]
        self.assertTrue(recovered.recover_current()['cleanup_complete'])
        self.assertEqual(['acquire','current'],self.store.calls[:2])

    def test_external_finalizer_inherited_ofd_direct_child_host_contract(self):
        self.ready(); recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.provider.executor_role='external_finalizer'
        ticket=self.store.lock
        self.assertTrue(recovered.recover_current(inherited=ticket)['cleanup_complete'])
        self.assertIs(self.store.inherited[-1],ticket)
        # Synthetic direct-child waited proofs only; not real orphan recovery.

    def test_existing_go_record_blocks_new_role(self):
        self.store.record={'version':3,'kind':'go_ip_only'}
        self.assertEqual('current_blocked',self.lease.start()['reason']); self.assertNotIn('create_client',self.provider.calls)

    def test_pending_old_role_blocks(self):
        self.store.pending=True
        self.assertEqual('pending_blocked',self.lease.start()['reason']); self.assertEqual(['executor'],self.provider.calls)

    def test_unknown_prior_blocks(self):
        self.store.prior=False
        self.assertEqual('pending_blocked',self.lease.start()['reason']); self.assertNotIn('create_client',self.provider.calls)

    def test_type9_is_not_client_ready_and_never_deleted(self):
        self.provider.create_type=9
        self.assertEqual('invalid_origin',self.lease.start()['reason'])
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertNotIn('delete_client',self.provider.calls)

    def test_type2_is_not_client_ready_and_never_deleted(self):
        self.provider.create_type=2
        self.assertEqual('invalid_origin',self.lease.start()['reason'])
        self.lease.restore(); self.assertNotIn('delete_client',self.provider.calls)

    def test_unknown_create_ack_does_not_infer_origin(self):
        self.provider.create_error=True
        self.assertFalse(self.lease.start()['client_init_ready'])
        self.assertIsNone(self.store.record.owned); self.assertIsNotNone(self.store.record.interface_ticket)
        self.assertNotIn('launch_controller',self.provider.calls)

    def test_spawn_exception_resolves_pre_registered_ticket(self):
        self.provider.spawn_error=True
        self.assertEqual('actor_unknown',self.lease.start()['reason'])
        self.assertIsNotNone(self.store.record.controller_ticket)
        self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.assertIn('resolve:controller',self.provider.calls)

    def test_late_spawn_saved_before_expiry_no_exec_release(self):
        self.provider.late_spawn=True
        self.assertEqual('expired',self.lease.start()['reason'])
        self.assertIsNotNone(self.store.record.controller)
        self.assertNotIn('release:controller',self.provider.calls)
        self.assertTrue(self.lease.restore()['cleanup_complete'])

    def test_late_registered_ticket_never_launches_after_deadline(self):
        self.provider.late_registration=True
        self.assertEqual('expired',self.lease.start()['reason'])
        self.assertIsNotNone(self.store.record.watchdog_ticket)
        self.assertNotIn('launch_watchdog',self.provider.calls); self.assertNotIn('create_client',self.provider.calls)
        self.assertTrue(self.lease.restore()['cleanup_complete'])

    def test_changed_current_after_status_never_overwritten_ready(self):
        self.provider.change_current_on_status=True
        self.assertEqual('stale_current',self.lease.start()['reason'])
        self.assertFalse(self.store.record.ready); self.assertEqual('controller_saved',self.store.record.stage)

    def test_invalid_and_nonfinite_ttl(self):
        for value in (True,False,0,-1,21,float('nan'),float('inf'),10**30,'20'):
            self.error('invalid_budget',lambda value=value:self.lease.start(value))
        self.assertEqual([],self.provider.calls)

    def test_nonmonotonic_clock_fails(self):
        self.lease._now(); self.clock.value=9
        self.error('invalid_clock',self.lease._now)

    def test_clock_exception_never_exposes_free_text(self):
        def failed_clock(): raise OSError('SECRET_CLOCK_PATH')
        lease=c.ClientInitLease(self.provider,self.store,IDENTITY,failed_clock)
        self.error('invalid_clock',lease.start)
        self.assertEqual([],self.provider.calls)

    def test_cancel_before_any_provider_action(self):
        self.assertEqual('cancelled',self.lease.start(cancelled=lambda:True)['reason'])
        self.assertEqual([],self.provider.calls)

    def test_cancel_callback_cannot_return_bool_like_integer(self):
        self.assertEqual('invalid_budget',self.lease.start(cancelled=lambda:1)['reason'])

    def test_stale_current_blocks_before_mutation(self):
        self.store.stale=True
        self.assertEqual('stale_current',self.lease.start()['reason']); self.assertNotIn('create_client',self.provider.calls)

    def test_baseline_change_blocks_delete(self):
        self.ready(); self.provider.base_changed=True
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertNotIn('delete_client',self.provider.calls)

    def test_owned_ipv4_unexpected_blocks_delete(self):
        self.ready(); self.provider.other_ip=True
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertNotIn('delete_client',self.provider.calls)

    def test_origin_read_unknown_blocks_delete(self):
        self.ready(); self.provider.origin_ok=False
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertNotIn('delete_client',self.provider.calls)

    def test_pid_exists_unreadable_never_gone(self):
        self.ready(); self.provider.absent=False
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertTrue(self.store.pending)
        self.assertNotIn('delete_client',self.provider.calls)

    def test_leader_z_with_other_thread_alive_is_not_live_ready(self):
        self.provider.return_actor_z=True
        self.assertEqual('actor_unknown',self.lease.start()['reason'])

    def test_exit_with_remaining_thread_blocks_delete(self):
        self.ready(); self.provider.exit_tasks=(555,)
        self.assertEqual('actor_reap_unknown',self.lease.restore()['reason']); self.assertNotIn('delete_client',self.provider.calls)

    def test_wait_or_reap_unknown_retains_pending(self):
        self.ready(); self.provider.reap=False
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertTrue(self.store.pending)

    def test_each_close_attempted_once_unknown_retains_pending(self):
        self.ready(); self.provider.close_exception=True
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertEqual(1,self.provider.close_calls)
        self.assertTrue(self.store.pending)

    def test_partial_resource_close_not_complete(self):
        self.ready(); self.provider.close_ok=False
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertTrue(self.store.pending)

    def test_zero_close_inventory_cannot_hide_owned_handles(self):
        self.ready()
        self.provider.close_resources=lambda handles,deadline:c.CloseProof(0,(),())
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertTrue(self.store.pending)

    def test_store_final_close_unknown_not_complete(self):
        self.ready(); self.store.final_close=False
        result=self.lease.restore(); self.assertFalse(result['cleanup_complete']); self.assertIs(result['pending_retained'],False)
        self.assertEqual('absent_observed',result['marker_state']); self.assertTrue(result['normal_restored'])
        self.assertTrue(result['terminal_durable']); self.assertTrue(result['resource_pending'])
        self.assertIs(self.lease.locks,self.store.lock); self.assertTrue(result['locks_close_unverified'])

    def test_watchdog_start_rejected_before_store_acquire(self):
        self.provider.executor_role='watchdog'
        result=self.lease.start()
        self.assertEqual('executor_role_forbidden',result['reason'])
        self.assertEqual(['executor'],self.provider.calls); self.assertEqual([],self.store.calls)
        self.assertFalse(result['cleanup_complete']); self.assertIsNone(result['pending_retained'])

    def test_watchdog_restore_and_recover_never_self_reap_or_finish(self):
        self.ready(); locks=self.lease.locks; self.provider.executor_role='watchdog'
        for method in (self.lease.restore,self.lease.recover_current):
            self.provider.calls=[]; self.store.calls=[]
            result=method()
            self.assertEqual('executor_role_forbidden',result['reason'])
            self.assertEqual(['executor'],self.provider.calls); self.assertEqual([],self.store.calls)
            self.assertIs(self.lease.locks,locks); self.assertTrue(result['pending_retained'])

    def test_mislabeled_current_watchdog_cannot_be_external_finalizer(self):
        self.ready(); recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.provider.executor_actor=self.store.record.watchdog
        self.provider.calls=[]; self.store.calls=[]
        result=recovered.recover_current(inherited=self.store.lock)
        self.assertEqual('self_actor_recovery',result['reason'])
        self.assertEqual(['executor'],self.provider.calls)
        self.assertEqual(['acquire','current'],self.store.calls)
        self.assertIs(recovered.locks,self.store.lock); self.assertTrue(result['locks_close_unverified'])
        self.assertIsNone(result['pending_retained']); self.assertFalse(result['cleanup_complete'])

    def test_current_controller_identity_also_cannot_finalize_itself(self):
        self.ready(); self.provider.executor_actor=self.store.record.controller
        self.provider.calls=[]; self.store.calls=[]
        result=self.lease.restore()
        self.assertEqual('self_actor_recovery',result['reason'])
        self.assertEqual(['executor'],self.provider.calls); self.assertEqual([],self.store.calls)
        self.assertIs(self.lease.locks,self.store.lock); self.assertFalse(result['cleanup_complete'])

    def test_external_finalizer_requires_same_inherited_ofd(self):
        self.ready(); self.provider.executor_role='external_finalizer'
        for inherited,verified in ((None,True),(self.store.lock,False)):
            recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
            self.provider.executor_ofd=verified; self.provider.calls=[]; self.store.calls=[]
            result=recovered.recover_current(inherited=inherited)
            self.assertEqual('external_finalizer_lock_unverified',result['reason'])
            self.assertEqual(['executor'],self.provider.calls); self.assertEqual([],self.store.calls)
            self.assertIsNone(result['pending_retained']); self.assertFalse(result['cleanup_complete'])

    def test_external_finalizer_unknown_wait_is_not_orphan_recovery(self):
        self.ready(); self.provider.executor_role='external_finalizer'; self.provider.reap=False
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.provider.calls=[]
        result=recovered.recover_current(inherited=self.store.lock)
        self.assertEqual('actor_reap_unknown',result['reason'])
        self.assertNotIn('delete_client',self.provider.calls)
        self.assertFalse(result['cleanup_complete']); self.assertTrue(result['pending_retained'])

    def test_finish_exception_preserves_exact_lock_reference(self):
        self.ready(); locks=self.lease.locks; self.store.finish_exception=True
        result=self.lease.restore()
        self.assertEqual('store_finish_unknown',result['reason'])
        self.assertIs(self.lease.locks,locks); self.assertTrue(result['locks_close_unverified'])
        self.assertIsNone(result['pending_retained']); self.assertFalse(result['cleanup_complete'])
        self.assertNotIn('SECRET_FINISH_FD',repr(result))

    def test_finish_exception_retry_only_reads_original_lock_closure(self):
        self.ready(); locks=self.lease.locks; self.store.finish_exception=True; self.lease.restore()
        self.provider.calls=[]; self.store.calls=[]
        result=self.lease.restore()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks); self.assertIsNone(result['pending_retained'])

    def test_partial_finish_recover_retry_does_not_reopen_or_reclose(self):
        self.ready(); locks=self.lease.locks; self.store.final_close=False; self.lease.restore()
        self.provider.calls=[]; self.store.calls=[]
        result=self.lease.recover_current()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks); self.assertFalse(result['cleanup_complete'])

    def test_unknown_locks_block_new_start_without_finish_or_acquire(self):
        self.ready(); locks=self.lease.locks; self.store.final_close=False; self.lease.restore()
        self.provider.calls=[]; self.store.calls=[]
        result=self.lease.start()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks)

    def test_unknown_lock_readback_exception_preserves_reference(self):
        self.ready(); locks=self.lease.locks; self.store.final_close=False; self.lease.restore()
        self.store.readback_exception=True; self.provider.calls=[]; self.store.calls=[]
        result=self.lease.restore()
        self.assertEqual('unexpected_provider_error',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks); self.assertTrue(result['locks_close_unverified'])
        self.assertNotIn('SECRET_READBACK_FD',repr(result))

    def test_unknown_lock_inventory_must_prove_both_original_references(self):
        self.ready(); locks=self.lease.locks; self.store.final_close=False; self.lease.restore()
        self.store.closed_locks=lambda value,deadline:c.CloseProof(1,(True,),(True,))
        result=self.lease.restore()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertIs(self.lease.locks,locks); self.assertFalse(result['pending_retained'])

    def test_two_closed_locks_cannot_erase_sealed_whole_store_unknown(self):
        self.ready(); locks=self.lease.locks; self.store.final_close=False; self.lease.restore()
        self.store.lock_readback=True; self.provider.calls=[]; self.store.calls=[]
        self.error('finish_sealed',lambda:self.lease._known_locks_before_acquire(self.clock.value+20))
        self.assertIs(self.lease.locks,locks); self.assertTrue(self.lease.locks_uncertain)
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertTrue(self.lease.status()['resource_pending'])  # two locks do not prove whole Store inventory

    def test_unsealed_active_return_unknown_can_only_release_after_original_readback(self):
        self.store.active_close=False; self.lease.start(); locks=self.lease.locks
        self.store.lock_readback=True; self.store.calls=[]
        self.lease._known_locks_before_acquire(self.clock.value+20)
        self.assertIsNone(self.lease.locks); self.assertFalse(self.lease.locks_uncertain)
        self.assertEqual(['closed_locks'],self.store.calls); self.assertIs(locks,self.store.lock)

    def test_prepared_failure_finish_unknown_is_not_reopened_on_retry(self):
        self.store.pending=True; self.store.final_close=False
        result=self.lease.start(); locks=self.lease.locks
        self.assertTrue(result['locks_close_unverified']); self.assertIs(locks,self.store.lock)
        self.store.calls=[]; self.provider.calls=[]
        result=self.lease.start()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks)

    def _assert_original_refs_retry_readonly(self,locks,method):
        self.assertIs(self.lease.locks,locks)
        state=self.lease.status()
        self.assertTrue(state['locks_close_unverified']); self.assertTrue(state['cleanup_unresolved'])
        self.assertFalse(state['cleanup_complete']); self.assertFalse(state['client_init_ready'])
        self.provider.calls=[]; self.store.calls=[]
        result=method()
        self.assertEqual('locks_close_unverified',result['reason'])
        self.assertEqual(['closed_locks'],self.store.calls); self.assertEqual([],self.provider.calls)
        self.assertIs(self.lease.locks,locks)

    def test_semantic_finish_contradictory_pending_keeps_refs_and_retry_readonly(self):
        self.ready(); locks=self.lease.locks; finish=self.store.finish
        def invalid(held,record,complete,deadline):
            final=finish(held,record,complete,deadline)
            return changed_receipt(final,marker_state='retained_observed')
        self.store.finish=invalid
        result=self.lease.restore()
        self.assertEqual('store_finish_unknown',result['reason'])
        self.assertEqual('cleanup_verified',self.lease.record.stage)
        self._assert_original_refs_retry_readonly(locks,self.lease.restore)

    def test_semantic_finish_wrong_stage_keeps_refs_and_retry_readonly(self):
        self.ready(); locks=self.lease.locks; finish=self.store.finish
        def invalid(held,record,complete,deadline):
            final=finish(held,record,complete,deadline)
            return changed_receipt(final,record=record)  # cleanup_verified is not reconciled
        self.store.finish=invalid
        self.assertEqual('store_finish_unknown',self.lease.restore()['reason'])
        self.assertEqual('cleanup_verified',self.lease.record.stage)
        self._assert_original_refs_retry_readonly(locks,self.lease.recover_current)

    def test_semantic_finish_wrong_identity_keeps_refs_and_retry_readonly(self):
        self.ready(); locks=self.lease.locks; finish=self.store.finish
        def invalid(held,record,complete,deadline):
            final=finish(held,record,complete,deadline)
            return changed_receipt(final,record=final.record.replace(identity=c.Identity('f'*64)))
        self.store.finish=invalid
        self.assertEqual('store_finish_unknown',self.lease.restore()['reason'])
        self.assertEqual(IDENTITY.key(),self.lease.record.identity.key())
        self._assert_original_refs_retry_readonly(locks,self.lease.start)

    def test_no_record_finish_complete_true_keeps_refs_and_retry_readonly(self):
        self.store.pending=True; finish=self.store.finish
        def invalid(held,record,complete,deadline):
            final=finish(held,record,complete,deadline)
            return changed_receipt(final,complete=True)
        self.store.finish=invalid
        result=self.lease.start()
        self.assertEqual('store_finish_unknown',result['reason']); self.assertIsNone(self.lease.record)
        self._assert_original_refs_retry_readonly(self.store.lock,self.lease.start)

    def test_no_record_finish_wrong_record_keeps_refs_and_retry_readonly(self):
        self.store.pending=True; finish=self.store.finish
        def invalid(held,record,complete,deadline):
            final=finish(held,record,complete,deadline)
            return changed_receipt(final,record=c.Journal(IDENTITY,'prepared',snapshot(),deadline))
        self.store.finish=invalid
        result=self.lease.start()
        self.assertEqual('store_finish_unknown',result['reason']); self.assertIsNone(self.lease.record)
        self._assert_original_refs_retry_readonly(self.store.lock,self.lease.recover_current)

    def test_ready_active_return_keyboardinterrupt_keeps_refs_and_retry_readonly(self):
        def interrupted(held,record):
            self.store.calls.append('active_return')
            raise KeyboardInterrupt('SECRET_ACTIVE_INTERRUPT')
        self.store.active_return=interrupted
        with self.assertRaises(KeyboardInterrupt): self.lease.start()
        self.assertEqual('resource_close_unknown',self.lease.status()['reason'])
        self.assertEqual(1,self.store.calls.count('active_return'))
        self.assertNotIn('SECRET_ACTIVE_INTERRUPT',repr(self.lease.status()))
        self._assert_original_refs_retry_readonly(self.store.lock,self.lease.restore)

    def test_failure_active_return_systemexit_keeps_refs_and_retry_readonly(self):
        self.provider.fail_free_text=True
        def interrupted(held,record):
            self.store.calls.append('active_return')
            raise SystemExit('SECRET_FAILURE_ACTIVE_INTERRUPT')
        self.store.active_return=interrupted
        with self.assertRaises(SystemExit): self.lease.start()
        self.assertEqual('resource_close_unknown',self.lease.status()['reason'])
        self.assertEqual(1,self.store.calls.count('active_return')); self.assertNotIn('finish',self.store.calls)
        self._assert_original_refs_retry_readonly(self.store.lock,self.lease.recover_current)

    def test_no_record_finish_keyboardinterrupt_keeps_refs_and_retry_readonly(self):
        self.store.pending=True
        def interrupted(held,record,complete,deadline):
            self.store.calls.append('finish')
            raise KeyboardInterrupt('SECRET_EMPTY_FINISH_INTERRUPT')
        self.store.finish=interrupted
        with self.assertRaises(KeyboardInterrupt): self.lease.start()
        self.assertIsNone(self.lease.record); self.assertEqual(1,self.store.calls.count('finish'))
        self.assertEqual('store_finish_unknown',self.lease.status()['reason'])
        self._assert_original_refs_retry_readonly(self.store.lock,self.lease.start)

    def test_restore_finish_systemexit_keeps_refs_and_retry_readonly(self):
        self.ready(); locks=self.lease.locks
        def interrupted(held,record,complete,deadline):
            self.store.calls.append('finish')
            raise SystemExit('SECRET_FINAL_FINISH_INTERRUPT')
        self.store.finish=interrupted
        with self.assertRaises(SystemExit): self.lease.restore()
        self.assertEqual('store_finish_unknown',self.lease.status()['reason'])
        self.assertEqual(1,self.store.calls.count('finish')); self.assertEqual('cleanup_verified',self.lease.record.stage)
        self.assertNotIn('SECRET_FINAL_FINISH_INTERRUPT',repr(self.lease.status()))
        self._assert_original_refs_retry_readonly(locks,self.lease.restore)

    def test_active_journal_close_failure_is_not_ready(self):
        self.store.active_close=False
        result=self.lease.start(); self.assertFalse(result['client_init_ready'])
        self.assertEqual(1,self.store.calls.count('active_return'))
        self.assertNotIn('finish',self.store.calls)

    def test_durability_failure_prevents_launch(self):
        self.store.save_fail=True
        self.assertEqual('durability_unknown',self.lease.start()['reason']); self.assertNotIn('launch_watchdog',self.provider.calls)

    def test_reconciled_shortcut_fresh_full_readback_no_redelete(self):
        self.ready(); self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.store.pending=True; self.provider.calls=[]
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.assertTrue(recovered.recover_current()['cleanup_complete'])
        self.assertIn('snapshot',self.provider.calls); self.assertIn('origin_absent',self.provider.calls)
        self.assertNotIn('delete_client',self.provider.calls)

    def test_already_cleared_reconciled_is_checked_without_reap_or_close_write(self):
        self.ready(); self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.provider.calls=[]; self.store.calls=[]
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        result=recovered.recover_current()
        self.assertTrue(result['cleanup_complete']); self.assertFalse(result['pending_retained'])
        self.assertIn('exit_proof:controller',self.provider.calls); self.assertIn('exit_proof:watchdog',self.provider.calls)
        self.assertIn('closed_resources',self.provider.calls); self.assertIn('snapshot',self.provider.calls)
        self.assertFalse(set(self.provider.calls)&{'reap:controller','reap:watchdog','delete_client','close_resources'})
        self.assertFalse(any(call.startswith('commit:') for call in self.store.calls))

    def test_reconciled_new_owned_presence_is_not_cached_success(self):
        self.ready(); self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.provider.owned=OWN; self.provider.calls=[]
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.assertFalse(recovered.recover_current()['cleanup_complete'])
        self.assertNotIn('delete_client',self.provider.calls); self.assertNotIn('close_resources',self.provider.calls)

    def test_reconciled_changed_baseline_or_unknown_exit_retains_pending(self):
        self.ready(); self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.provider.base_changed=True; self.provider.calls=[]
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.assertFalse(recovered.recover_current()['cleanup_complete'])
        self.assertNotIn('delete_client',self.provider.calls)
        self.provider.base_changed=False; self.provider.reap=False; self.provider.calls=[]
        recovered=c.ClientInitLease(self.provider,self.store,IDENTITY,self.clock)
        self.assertFalse(recovered.recover_current()['cleanup_complete'])
        self.assertIn('exit_proof:controller',self.provider.calls); self.assertNotIn('reap:controller',self.provider.calls)

    def test_wrong_manifest_current_not_adopted(self):
        self.ready(); self.store.record=self.store.record.replace(identity=c.Identity('f'*64))
        self.assertFalse(self.lease.restore()['cleanup_complete']); self.assertNotIn('delete_client',self.provider.calls)

    def test_no_free_exception_text_or_identifiers_public(self):
        self.provider.fail_free_text=True
        result=self.lease.start(); self.assertEqual('unexpected_provider_error',result['reason'])
        for private in ('SECRET_PACKET',OWN.name,BOOT,'02:','/private/','a'*64): self.assertNotIn(private,repr(result))
        for value in (OWN,IDENTITY,snapshot(),actor(44),self.store.record):
            self.assertEqual('<CLIENT RF-init private record>',repr(value))

    def test_finish_old_dict_shape_cannot_issue_producer_receipt(self):
        self.ready(); locks=self.lease.locks
        self.store.finish=lambda *args:{'record':self.lease.record,'complete':True,
            'pending_retained':False,'locks_closed':True}
        result=self.lease.restore()
        self.assertEqual('store_finish_unknown',result['reason']); self.assertIs(self.lease.locks,locks)
        self.assertIsNone(result['pending_retained']); self.assertNotIn('authenticate_finish',self.store.calls)

    def test_finish_exact_store_locks_request_and_identity_bound(self):
        for field,value in (('store',Store()),('locks',object()),
                ('request_record',None),('identity',c.Identity('f'*64))):
            self.setUp(); self.ready(); locks=self.lease.locks; finish=self.store.finish
            def wrong(held,record,normal,deadline,field=field,value=value):
                return changed_receipt(finish(held,record,normal,deadline),**{field:value})
            self.store.finish=wrong
            self.assertEqual('store_finish_unknown',self.lease.restore()['reason'])
            self.assertIs(self.lease.locks,locks); self.assertTrue(self.lease.sealed)

    def test_correct_typed_copy_not_registered_by_fixed_issuer_is_rejected(self):
        self.ready(); finish=self.store.finish; locks=self.lease.locks
        self.store.finish=lambda *args:changed_receipt(finish(*args))
        result=self.lease.restore()
        self.assertEqual('store_finish_unknown',result['reason'])
        self.assertIs(self.lease.locks,locks); self.assertEqual(1,self.store.calls.count('authenticate_finish'))
        self.assertFalse(result['cleanup_complete'])

    def test_authenticate_bool_like_integer_does_not_release(self):
        self.ready(); locks=self.lease.locks
        self.store.authenticate_finish=lambda *args:1
        result=self.lease.restore()
        self.assertEqual('store_finish_unknown',result['reason']); self.assertIs(self.lease.locks,locks)

    def test_authenticate_baseexception_preserves_exact_report_and_original_refs(self):
        self.ready(); locks=self.lease.locks
        def interrupted(*args): raise KeyboardInterrupt('SECRET_AUTH_INTERRUPT')
        self.store.authenticate_finish=interrupted
        with self.assertRaises(KeyboardInterrupt): self.lease.restore()
        self.assertIs(self.lease.finish_receipt,self.store.issued_receipt)
        self.assertIs(self.lease.locks,locks); self.assertTrue(self.lease.sealed)
        self.assertIsNone(self.lease.status()['pending_retained'])
        self.assertNotIn('SECRET_AUTH_INTERRUPT',repr(self.lease.status()))
        self._assert_original_refs_retry_readonly(locks,self.lease.restore)

    def test_terminal_publish_failure_retains_marker_not_resource_fake(self):
        self.ready(); self.store.terminal_publish=False
        result=self.lease.restore()
        self.assertTrue(result['normal_restored']); self.assertFalse(result['terminal_durable'])
        self.assertEqual('cleanup_verified',result['stage']); self.assertTrue(result['pending_retained'])
        self.assertEqual('not_attempted',result['clear_durability']); self.assertFalse(result['resource_pending'])
        self.assertTrue(result['cleanup_unresolved']); self.assertFalse(result['cleanup_complete'])
        self.assertIsNone(self.lease.locks); self.assertFalse(result['client_init_ready'])

    def test_marker_unlink_observation_unknown_is_not_retained_true(self):
        self.ready(); self.store.marker_observation='unknown'; self.store.clear_observation='unknown'
        result=self.lease.restore()
        self.assertIsNone(result['pending_retained']); self.assertEqual('unknown',result['marker_state'])
        self.assertEqual('unknown',result['clear_durability']); self.assertFalse(result['resource_pending'])
        self.assertTrue(result['cleanup_unresolved']); self.assertFalse(result['cleanup_complete'])

    def test_absent_marker_directory_fsync_unknown_remains_truthful_partial(self):
        self.ready(); self.store.clear_observation='unknown'
        result=self.lease.restore()
        self.assertFalse(result['pending_retained']); self.assertEqual('absent_observed',result['marker_state'])
        self.assertFalse(result['resource_pending']); self.assertTrue(result['cleanup_unresolved'])
        self.assertFalse(result['cleanup_complete']); self.assertEqual('reconciled',result['stage'])

    def test_terminal_published_readback_without_durability_can_report_current_record(self):
        self.ready(); self.store.terminal_publish=False; finish=self.store.finish
        def partial(*args):
            original=finish(*args)
            final=changed_receipt(original,record=original.record.replace(stage='reconciled',ready=False))
            self.store.issued_receipt=final  # Explicit synthetic readback/provenance only.
            return final
        self.store.finish=partial
        result=self.lease.restore()
        self.assertEqual('reconciled',result['stage']); self.assertFalse(result['terminal_durable'])
        self.assertTrue(result['pending_retained']); self.assertFalse(result['cleanup_complete'])

    def test_finish_semantic_fault_combinations_cannot_submit_close_flag(self):
        cases=({'normal_restored':False},{'terminal_durable':False},
               {'clear_durability':'not_attempted'},{'marker_state':'unknown'},
               {'resources_closed':True,'resource_pending':True},
               {'resources_closed':False,'resource_pending':False}, {'complete':False})
        for changes in cases:
            self.setUp(); self.ready(); locks=self.lease.locks; finish=self.store.finish
            self.store.finish=lambda *args,**kw:changed_receipt(finish(*args),**changes)
            result=self.lease.restore()
            self.assertEqual('store_finish_unknown',result['reason']); self.assertIs(self.lease.locks,locks)
            self.assertTrue(result['resource_pending']); self.assertIsNone(result['pending_retained'])

    def test_full_record_task_state_changes_not_hidden_by_journal_key(self):
        for which in ('stock','controller','watchdog'):
            self.setUp(); self.ready(); finish=self.store.finish; locks=self.lease.locks
            def altered(*args):
                final=finish(*args); record=final.record
                if which=='stock':
                    old=record.baseline.stock_actors[0]
                    changed=actor(old.pid,old.exe,old.argv_sha,((old.pid,100,'D'),))
                    base=record.baseline
                    base=c.Snapshot(base.boot,base.stock_hashes,(changed,)+base.stock_actors[1:],
                        base.station,base.station_state_sha,base.station_frequency,base.interfaces,
                        base.ipv4,base.ipv6_addresses,base.ipv6_routes,True)
                    altered_record=record.replace(baseline=base)
                else:
                    old=getattr(record,which)
                    changed=actor(old.pid,old.exe,old.argv_sha,((old.pid,100,'T'),))
                    altered_record=record.replace(**{which:changed})
                self.assertEqual(altered_record.key(),record.key())
                return changed_receipt(final,record=altered_record)
            self.store.finish=altered
            self.assertEqual('store_finish_unknown',self.lease.restore()['reason'])
            self.assertIs(self.lease.locks,locks)

    def test_no_record_absent_marker_is_not_fabricated_retained(self):
        self.store.prior=False
        result=self.lease.start()
        self.assertEqual('pending_blocked',result['reason']); self.assertIsNone(self.lease.record)
        self.assertFalse(result['pending_retained']); self.assertEqual('not_attempted',result['clear_durability'])
        self.assertFalse(result['normal_restored']); self.assertFalse(result['terminal_durable'])
        self.assertFalse(result['resource_pending']); self.assertTrue(result['cleanup_unresolved'])
        self.assertFalse(result['cleanup_complete']); self.assertTrue(result['finish_sealed'])
        self.assertNotIn('create_client',self.provider.calls)

    def test_existing_go_record_is_not_adopted_or_cleared_in_finish(self):
        prior={'version':3,'kind':'go_ip_only'}; self.store.record=prior; self.store.pending=True
        result=self.lease.start()
        self.assertIs(self.store.record,prior); self.assertIsNone(self.lease.record)
        self.assertTrue(result['pending_retained']); self.assertTrue(self.store.pending)
        self.assertFalse(result['cleanup_complete']); self.assertEqual('current_blocked',result['reason'])

    def test_sealed_completed_owner_methods_never_reopen_finish_or_provider(self):
        self.ready(); self.assertTrue(self.lease.restore()['cleanup_complete'])
        self.provider.calls=[]; self.store.calls=[]
        for method in (self.lease.start,self.lease.restore,self.lease.recover_current):
            result=method()
            self.assertEqual('finish_sealed',result['reason']); self.assertTrue(result['cleanup_complete'])
            self.assertFalse(result['client_init_ready']); self.assertEqual([],self.store.calls)
            self.assertEqual([],self.provider.calls)
        self.error('finish_sealed',lambda:self.lease._save(self.lease.record))

    def test_finish_attempt_is_once_even_if_private_entry_called_again(self):
        self.ready(); self.store.final_close=False; self.lease.restore()
        self.store.calls=[]
        self.error('finish_sealed',lambda:self.lease._finish_receipt(self.lease.record,True,30))
        self.assertEqual([],self.store.calls); self.assertIs(self.lease.locks,self.store.lock)

    def test_provider_close_callback_baseline_change_cannot_clear_marker(self):
        self.ready(); close=self.provider.close_resources
        def changed(*args):
            proof=close(*args); self.provider.base_changed=True; return proof
        self.provider.close_resources=changed
        result=self.lease.restore()
        self.assertEqual('baseline_changed',result['reason']); self.assertFalse(result['normal_restored'])
        self.assertFalse(result['terminal_durable']); self.assertTrue(result['pending_retained'])
        self.assertFalse(result['cleanup_complete']); self.assertTrue(self.store.pending)

    def test_provider_baseexception_before_finish_cannot_publish_terminal(self):
        self.ready()
        def interrupted(*args): raise SystemExit('SECRET_REAP_INTERRUPT')
        self.provider.stop_and_reap=interrupted
        with self.assertRaises(SystemExit): self.lease.restore()
        result=self.lease.status()
        self.assertTrue(result['finish_sealed']); self.assertFalse(result['normal_restored'])
        self.assertFalse(result['terminal_durable']); self.assertTrue(result['pending_retained'])
        self.assertFalse(result['cleanup_complete']); self.assertFalse(result['client_init_ready'])
        self.assertEqual(1,self.store.calls.count('finish'))
        self.assertNotIn('SECRET_REAP_INTERRUPT',repr(result))

    def test_all_complete_facts_are_separate_fixed_nonsecret_status(self):
        self.ready(); result=self.lease.restore(); receipt=self.lease.finish_receipt
        self.assertIs(type(receipt),c.FinishReceipt); self.assertIs(receipt.store,self.store)
        self.assertTrue(receipt.normal_restored); self.assertTrue(receipt.terminal_durable)
        self.assertEqual('absent_observed',receipt.marker_state); self.assertEqual('verified',receipt.clear_durability)
        self.assertTrue(receipt.resources_closed); self.assertFalse(receipt.resource_pending); self.assertTrue(receipt.complete)
        self.assertFalse(result['cleanup_unresolved']); self.assertFalse(result['resource_pending'])
        for word in (BOOT,OWN.name,'a'*64,'/private/',repr(self.store.lock)):
            self.assertNotIn(word,repr(result))
        self.assertEqual('<CLIENT RF-init private record>',repr(receipt))
        with self.assertRaises(AttributeError): receipt.complete=False

    def test_finish_record_constructor_strict_fixed_types_and_enums(self):
        self.ready(); self.lease.restore(); receipt=self.lease.finish_receipt
        for changes in ({'marker_state':'SECRET'}, {'clear_durability':'SECRET'},
                {'complete':1},{'resources_closed':0},{'resource_pending':1},
                {'terminal_durable':1},{'normal_restored':1},{'record':{}},{'locks':None}):
            self.error('store_finish_unknown',lambda changes=changes:changed_receipt(receipt,**changes))

    def test_unimplemented_authentication_remains_unavailable(self):
        self.error('store_unavailable',lambda:c.ClientInitStore().authenticate_finish(object(),None,object(),30))

    def test_source_python35_no_io_or_forbidden_operations(self):
        path=os.path.join(ROOT,'runtime','mta_p2p_client_init.py')
        with open(path,encoding='utf-8') as handle: source=handle.read()
        tree=ast.parse(source,feature_version=(3,5))
        imports=[a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names]
        self.assertEqual(['mta_ip'],imports)
        calls=[n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertFalse(set(calls)&{'open','exec','eval','compile','__import__'})
        attributes=[n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
        self.assertFalse(set(attributes)&{'Popen','socket','sendto','group_add','scan','find','listen','address_ack'})


class ParserAndRecordsTests(unittest.TestCase):
    def reject(self,call):
        with self.assertRaises(c.ClientInitError): call()

    def test_status_valid_real_fields_no_private_return(self):
        value=c.parse_init_status(STATUS)
        self.assertEqual({'ctrl_inactive':True,'control_fields_only':True,'association_verified':False},value)
        self.assertEqual(value,c.parse_init_status(STATUS+b'ieee80211ac=1\nbss_max_idle_period=30\n'))

    def test_status_frame_duplicate_truncate_nul_and_cr_rejected(self):
        for value in ('str',STATUS[:-1],STATUS+b'\x00',STATUS.replace(b'\n',b'\r\n'),STATUS+b'wpa_state=INACTIVE\n',b'',STATUS*30):
            self.reject(lambda value=value:c.parse_init_status(value))

    def test_status_association_and_ip_fields_rejected(self):
        for field in (b'ssid=secret',b'id=0',b'freq=2412',b'bssid=02:11:22:33:44:55',b'ip_address=10.1.1.2',b'passphrase=secret',b'future_field=secret'):
            self.reject(lambda field=field:c.parse_init_status(STATUS+field+b'\n'))
        for state in (b'SCANNING',b'COMPLETED',b'DISCONNECTED'):
            self.reject(lambda state=state:c.parse_init_status(STATUS.replace(b'INACTIVE',state)))

    def test_status_missing_and_invalid_metadata_rejected(self):
        for value in (STATUS.replace(b'address=02:66:77:88:99:aa\n',b''),
            STATUS.replace(b'02:66:77:88:99:aa',b'00:00:00:00:00:00'),
            STATUS.replace(b'02:66:77:88:99:aa',b'03:66:77:88:99:aa'),
            STATUS.replace(b'uuid=12345678',b'uuid=secretxx'),STATUS+b'bss_max_idle_period=01\n'):
            self.reject(lambda value=value:c.parse_init_status(value))

    def test_full_client_combo_not_go_derived_bool(self):
        self.assertTrue(c.client_combo(caps(),snapshot()))
        value=caps(); value['station_plus_go_same_channel']=True
        self.reject(lambda:c.client_combo(value,snapshot()))

    def test_caps_missing_unknown_and_bool_constraints_rejected(self):
        mutations=(lambda p:p.pop('unknown_constraints'),lambda p:p.update(unknown_constraints=('unknown',)),
            lambda p:p.update(iftypes=(2,True,8)),lambda p:p['combinations'][0].update(max_interfaces=True),
            lambda p:p['combinations'][0].update(future_constraint=0))
        for change in mutations:
            value=caps(); change(value['phys'][0]); self.reject(lambda value=value:c.client_combo(value,snapshot()))

    def test_combo_overlap_coverage_limits_software_radar_failclosed(self):
        mutations=(lambda p:p['combinations'][0]['limits'][1].update(types=(2,8)),
            lambda p:p['combinations'][0]['limits'][1].update(types=(9,)),
            lambda p:p['combinations'][0].update(max_interfaces=1),lambda p:p.update(software_iftypes=(8,)),
            lambda p:p['combinations'][0].update(radar_widths=1),lambda p:p['combinations'][0].update(beacon_match=True))
        for change in mutations:
            value=caps(); change(value['phys'][0]); self.reject(lambda value=value:c.client_combo(value,snapshot()))

    def test_existing_client_count_not_ignored(self):
        existing=c.Origin(0,99,99,'p2p0',8)
        self.reject(lambda:c.client_combo(caps(),snapshot(existing)))

    def test_snapshot_mutable_bad_ipv4_and_partial_stock_rejected(self):
        self.reject(lambda:c.Snapshot(BOOT,(),STOCK,STA,'c'*64,2412,(STA,),IP,(),(),True))
        self.reject(lambda:c.Snapshot(BOOT,c.STOCK_PINS,STOCK,STA,'c'*64,2412,[STA],IP,(),(),True))
        self.reject(lambda:c.Snapshot(BOOT,c.STOCK_PINS,STOCK,STA,'c'*64,2412,(STA,),IP,(),(),1))
        invalid=ip.IpSnapshot((ip.AddressRecord(22,True,2,24,0x80,0,None,None,(0xffffffff,0xffffffff,1,1)),),(),RULES)
        self.reject(lambda:snapshot(ipv4=invalid))

    def test_owned_ipv6_profile_and_noncanonical_cases(self):
        address=('fe80'+'0'*28,'17','40','20','80',OWN.name)
        route=('ff'+'0'*30,'08','0'*32,'00','0'*32,'00000100','00000001','00000000','00000001',OWN.name)
        self.assertEqual(snapshot().key(),snapshot(OWN,ipv6_addresses=(address,),ipv6_routes=(route,)).key(OWN))
        for index,value in ((0,'ff01'+'0'*28),(1,'09'),(2,'1'+'0'*31),(3,'01'),(4,'1'+'0'*31),(8,'00000003')):
            bad=list(route); bad[index]=value
            self.reject(lambda bad=bad:snapshot(OWN,ipv6_routes=(tuple(bad),)).key(OWN))
        other=list(route); other[6]='00000002'
        self.reject(lambda:snapshot(OWN,ipv6_routes=(route,tuple(other))).key(OWN))

    def test_private_records_and_journal_strict_shape(self):
        self.reject(lambda:c.Origin(0,2,True,OWN.name,8))
        self.reject(lambda:c.InterfaceTicket(BOOT,0,'wlan0',1,1))
        self.reject(lambda:c.Actor(20,1,'/private/../bad','a'*64,((20,1,'S'),)))
        self.reject(lambda:c.Journal(IDENTITY,'go_ready',snapshot(),30))
        self.reject(lambda:c.Journal(IDENTITY,'client_init_ready',snapshot(),30,ready=True))
        self.reject(lambda:c.CloseProof(1,(1,),(True,)))
        value=c.Identity('a'*64)
        with self.assertRaises(AttributeError): value.candidate_sha='f'*64

    def test_executor_proof_private_strict_role_live_actor_and_bool(self):
        for role,value,ofd in (('future',actor(201),True),('owner',object(),True),
            ('owner',actor(201,tasks=((201,100,'Z'),)),True),('external_finalizer',actor(201),1)):
            self.reject(lambda role=role,value=value,ofd=ofd:c.ExecutorProof(role,value,ofd))
        proof=c.ExecutorProof('owner',actor(201),False)
        self.assertEqual('<CLIENT RF-init private record>',repr(proof))
        with self.assertRaises(AttributeError): proof.role='watchdog'

    def test_journal_phase_prerequisites_reject_missing_tickets(self):
        wd=c.Ticket('1'*32,'watchdog',BOOT,'/usr/bin/python3.5','b'*64)
        wd_actor=actor(101)
        it=c.InterfaceTicket(BOOT,0,OWN.name,1,99)
        self.reject(lambda:c.Journal(IDENTITY,'watchdog_intent',snapshot(),30))
        self.reject(lambda:c.Journal(IDENTITY,'prepared',snapshot(),30,watchdog_ticket=wd))
        self.reject(lambda:c.Journal(IDENTITY,'interface_intent',snapshot(),30,watchdog_ticket=wd,watchdog=wd_actor))
        self.reject(lambda:c.Journal(IDENTITY,'controller_intent',snapshot(),30,owned=OWN,
                                    interface_ticket=it,watchdog_ticket=wd,watchdog=wd_actor))


if __name__=='__main__': unittest.main()
