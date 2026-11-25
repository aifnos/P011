"""Same-worker GO + typed IP/DHCP live owner, SOURCE v72 only.

Based on current Bootstrap71 and the typed L3 slice, without replacing the
current Native62/Store56 fixes. prepare_live returns the SAME original owner
after one constructor-before-IO DHCP setup. poll_dhcp consumes the SAME once
20-second local service end; it neither reissues a TTL nor changes Native scope.
The original caller must retain this owner and restore in the SAME worker.
Default run serves only that bounded local slice, then attempts once recovery.

Recovery closes DHCP, restores the confirmed IP, then uses the original group,
child, interface, baseline and inventory reconciliation under one 60s period.
L3 failures prohibit group/netdev deletion; known original local inventory may
close stop-only and remains pending on uncertainty. No cached proof, Sender
provider, advertising, TLS or phone transfer is implemented by this definition.
Baseline15, active-stage min(original_until, now+seconds), current ownership,
unknown publication rules, resource ceilings and full native readbacks remain.
"""
import threading

import mta_go_deployment as sources
import mta_go_bootstrap_store as stores
import mta_go_process_owner as launch
import mta_go_native as native
import mta_go_dhcp as dhcp


def _fail(code): raise sources.GoSourceError(code) from None


class GoRestoreObservation(object):
    def __init__(self,owner,original_native):
        if type(owner) is not GoBootstrap or type(original_native) is not native.GoNativeRestoreObservation or \
                original_native is not owner.native.restored or original_native.owner is not owner:
            _fail('restore_source_invalid')
        self.owner,self.store,self.cleanup_until,self.native_observation=owner,owner.store,owner.cleanup_until,original_native
    def __repr__(self): return '<private original GO restoration observation>'


class _DhcpConstructor(object):
    """Strong inventory BEFORE the one real server constructor, no readiness."""
    def __init__(self,owner,binding):
        self.owner,self.binding,self.creator=owner,binding,dhcp.GoDhcpServer
        self.returned=None;self.unknown=True
    def __repr__(self): return '<private original GO DHCP constructor ticket>'


class GoBootstrap(object):
    """Fixed original same-F native owner, not an adapter with nine true flags."""
    def __init__(self,deployment,entry,clock=None,_store_io=None,_native_io=None,_launcher_os=None,_launcher_flags=None):
        if type(deployment) is not sources.LoadedGoDeployment: _fail('invalid_bootstrap_source')
        deployment.loader.authenticate(deployment)
        executor=deployment.modules['mta_go_executor']
        if type(entry) is not executor.GoEntrySource or entry.deployment is not deployment or entry.actor is None or \
                entry.mode!='--go-bootstrap' or entry.worker is not threading.current_thread() or \
                clock is not None and clock is not entry.clock: _fail('wrong_bootstrap_entry')
        entry._context()
        self.deployment,self.entry,self.clock,self.until=deployment,entry,entry.clock,entry.until
        self.worker,self.last=entry.worker,None
        self.started=self.restore_attempted=self.stop_requested=self.group_confirmed=False
        self.failure=self.restore_failure=self.restore_observation=self.cleanup_until=None
        self.watchdog=self.controller=self.native=self.launcher=None
        self.dhcp=self.dhcp_ticket=self._dhcp_ticket_original=None
        self.service_until=self._service_until_original=None
        self.ip_confirmed=self.dhcp_listening=False
        self.child_receipts,self.phase,self.cleanup_steps=[],'constructed',[]
        self._cleanup_original=self._cleanup_registered=None
        self.store=stores.GoBootstrapStore(deployment,self.until,_io=_store_io,_clock=self.clock)
        self.store.bind(self)
        deployment.loader.bind_runtime(deployment,self,self.until,entry.until_text)
        self.native=native.NativeGoResources(self,_io=_native_io);self.store.bind_native(self.native)
        # Exact fixed specs, actual original entry accounting and child launcher
        # are registered before the Store's first FS IO or any RF operation.
        self.launcher=launch.GoDirectChildOwner(deployment,_os=_launcher_os,_flags=_launcher_flags)
        self.store.bind_launcher(self.launcher)
        self._originals=(deployment,entry,self.clock,self.until,self.worker,self.store,self.native,self.launcher)
    def __repr__(self): return '<private same-F GO bootstrap owner; no transfer readiness>'
    def _owner(self):
        self.deployment.loader.authenticate(self.deployment);self.entry._context()
        if (self.deployment,self.entry,self.clock,self.until,self.worker,self.store,self.native,self.launcher)!=self._originals or \
                self.deployment.loader.runtime is not self or self.store.owner is not self or self.native.owner is not self or \
                self.store._native_original is not self.native or self.store._launcher_original is not self.launcher or \
                self.launcher.runtime is not self or threading.current_thread() is not self.worker:
            _fail('bootstrap_owner_changed')
    def _now(self):
        self._owner();now=sources._time(self.clock())
        if self.last is not None and now<self.last: _fail('clock_regressed')
        self.last=now;return now
    def _cleanup_period_current(self,original_native):
        """Pure exact once-owner cleanup source; no caller numeric grant/RF."""
        self._owner();original=self._cleanup_original
        resources=self.deployment.modules['mta_client_resource_budget']
        if type(original) is not tuple or original is not self._cleanup_registered or len(original)!=13 or \
                original_native is not self.native or not self.restore_attempted or not self.stop_requested or \
                self.cleanup_until!=original[1] or self.entry.cleanup_until!=original[1] or \
                (self,self.entry,self.store,self.native,self.launcher,self.clock,self.entry.accounting,
                    self.entry.budget,self.entry.reader,self.entry.accounting._epoch,self.entry.accounting._mutex)!=original[2:] or \
                self.entry.accounting._resource_lane_v23!=resources.CLEANUP or \
                self.entry.accounting._resource_budget_v23 is not self.entry.budget or \
                self.entry.reader._bound_budget_v24 is not self.entry.budget or \
                self.entry.reader._resource_budget_v24 is not self.entry.budget or \
                self.entry.budget._cancelled is not True or not 0<original[1]-original[0]<=60:
            _fail('original_cleanup_period_changed')
        # Entry._context above verifies the original budget RLock/epoch/reader
        # and unchanged formal profile. This source never reads a GO canonical.
        return original[1]
    def _stage(self,seconds):
        if type(seconds) not in (int,float) or not 0<seconds<=20 or self.restore_attempted: _fail('invalid_active_stage')
        end=min(self.until,self._now()+seconds)
        if self._cancelled(end): _fail('stop_requested')
        self.entry.accounting._io_deadline=end
        return end
    def _cancelled(self,stage_until):
        """Real original pipe/expiry observations, stop-only; never RF grant.

        Poll is passive/nonblocking, no per-packet _single/Proc generation. A
        full launcher/process/native stage still validates actual sources. The
        original watchdog until is never replaced with stage_until or a TTL.
        Cleanup is independent and never blocked by its earlier stop request.
        """
        if self.restore_attempted: return False
        now=self._now()
        if now>=self.until or now>=stage_until: self.stop_requested=True
        ticket=self.watchdog
        if ticket is not None and ticket.released and not ticket.waited and not self.stop_requested:
            end=min(self.until,stage_until,now+0.2)
            try:
                result=launch.GoDirectChildOwner.read_requests_passive_v30(self.launcher,ticket,end)
                if type(result) is not bool: _fail('watchdog_poll_invalid')
                if result: self.stop_requested=True
            except BaseException as error:
                self.failure=error;self.stop_requested=True
        return self.stop_requested
    def persist_preexec(self,ticket,original_actor):
        self._owner()
        if ticket is not self.watchdog and ticket is not self.controller: _fail('foreign_child')
        canonical=stores.GoBootstrapStore.persist_preexec(self.store,ticket,original_actor)
        if type(canonical) is not stores.GoCanonical or canonical is not self.store.current: _fail('child_publication_unknown')
        receipt=launch.PersistReceipt(ticket,original_actor);self.child_receipts.append((ticket,canonical,receipt))
        return receipt
    def _start_child(self,role):
        self._owner();end=self._stage(10)
        intent=self.store.prepare_child(role,self.native.baseline if role=='watchdog' else None)
        spec=self.deployment.watchdog_spec if role=='watchdog' else self.deployment.controller_spec
        if type(intent) is not stores.GoChildIntent or intent.spec is not spec or intent.until!=self.until:
            _fail('child_intent_not_original')
        ticket=self.launcher.register(spec,self.store.device.fd,self.until)
        if role=='watchdog': self.watchdog=ticket
        else: self.controller=ticket
        self.phase=role+'_launch'
        self.launcher.launch(ticket,_absolute_deadline=end)
        if ticket.preexec is None: _fail('child_preexec_unavailable')
        if self.launcher.release(ticket,self.persist_preexec,_absolute_deadline=end) is not True: _fail('child_release_failed')
        actual=None
        for unused in range(32):
            self._cancelled(end)
            if self.stop_requested: _fail('stop_requested')
            actual=self.launcher.resolve(ticket,_absolute_deadline=end)
            if actual is not None: break
            self.native.io.pause(min(0.01,end-self._now()))
        if actual is None or actual is not ticket.postexec: _fail('child_postexec_unavailable')
        self.store.confirm_actor(ticket,actual)
        if role=='controller':
            rows=self.launcher.read_diagnostics(ticket,_absolute_deadline=end)
            if any(code<0 for stage,code in rows): _fail('controller_native_init_failed')
        self.phase=role+'_live'
        return ticket
    def restore(self):
        with self.store.mutex:
            self._owner()
            if self.restore_attempted: _fail('restore_already_attempted')
            self.restore_attempted=True;self.stop_requested=True
            start=self._now();self.cleanup_until=start+60.0  # Once, before recovery IO.
            self.entry.cleanup_until=self.cleanup_until
            original=(start,self.cleanup_until,self,self.entry,self.store,self.native,self.launcher,self.clock,
                self.entry.accounting,self.entry.budget,self.entry.reader,self.entry.accounting._epoch,self.entry.accounting._mutex)
            self._cleanup_original=self._cleanup_registered=original
            # Use the EXISTING bound accounting lane and cancellation primitive,
            # not a fabricated GO grant/new quota or CLIENT lease/journal.
            resources=self.deployment.modules['mta_client_resource_budget']
            accounting=self.entry.accounting
            with accounting._mutex:
                self.entry._context()
                accounting._resource_lane_v23=resources.CLEANUP
                resources.ResourceBudget.cancel(self.entry.budget)
            self._cleanup_period_current(self.native)
            self.entry.accounting._io_deadline=self.cleanup_until
            self.phase='restore_intent'
            try:
                if self.store.current is None or self.store.publication_unknown:
                    # No typed original canonical: cannot claim RF restoration
                    # or clear an uncertain marker. Known local resources may
                    # close; unknown original inventory stays retained/pending.
                    for ticket in self.launcher._tickets:
                        try: self.native.stop_child_only(ticket)
                        except BaseException as error: self.cleanup_steps.append(('uncertain_child_stop',ticket,error))
                    try: self.native.close_known_inventory(self.cleanup_until)
                    except BaseException as error: self.cleanup_steps.append(('uncertain_native_close',error))
                    try: self.store.close_pending()
                    except BaseException as error: self.cleanup_steps.append(('uncertain_store_close',error))
                    _fail('reservation_or_publication_pending')
                self.store.begin_restore(self.cleanup_until)
                # L3 closes before GROUP_REMOVE or netdev DEL, even after an
                # early preparation failure with absent typed facts.
                closed=self.native.close_dhcp(self.cleanup_until)
                self.store.close_dhcp(closed)
                intent=self.native.prepare_ip_cleanup(self.cleanup_until)
                self.store.prepare_ip_delete(intent)
                restored_ip=self.native.restore_ip(self.cleanup_until)
                self.store.confirm_ip_restored(restored_ip)
                try: self.native.prepare_cleanup(self.cleanup_until)
                except BaseException as error:
                    self.cleanup_steps.append(('private_channels',error))
                    # Original channels already tried once; known child stop
                    # may proceed, but completion still checks full inventory.
                child_errors=[]
                for ticket in (self.controller,self.watchdog):
                    if ticket is None: continue
                    try: self.native.stop_child(ticket,self.cleanup_until)
                    except BaseException as error:
                        child_errors.append(error);self.cleanup_steps.append(('child_stop',ticket,error))
                        # A failed observation/reap does not skip the OTHER
                        # original child or its independently known local FDs.
                        # This does not retry TERM, grant a second period or
                        # turn physical local closure into process absence.
                        try:
                            if self.launcher.close_inventory(ticket,_absolute_deadline=self.cleanup_until) is not True:
                                _fail('child_inventory_pending')
                        except BaseException as close_error:
                            self.cleanup_steps.append(('child_close',ticket,close_error))
                try: self.native.close_known_inventory(self.cleanup_until)
                except BaseException as error:
                    child_errors.append(error);self.cleanup_steps.append(('native_close',error))
                if child_errors: raise child_errors[0]
                self.native.delete_interface(self.cleanup_until)
                observed=self.native.observe_restore(self.cleanup_until)
                self.restore_observation=GoRestoreObservation(self,observed)
                canonical=self.store.finish_restore(self.restore_observation)
                if canonical is not self.store.current or not self.store.logical_restored or \
                        any(not a or not c for a,c in self.store.closed_facts()) or any(not a or not c for a,c in self.native.closed_facts()):
                    _fail('restoration_pending')
                self.phase='restored';return canonical
            except BaseException as error:
                self.restore_failure=error;self.phase='restore_pending'
                # A failed L3 recovery cannot authorize RF removal. Stop-only
                # known original children still get their original once path.
                for ticket in self.launcher._tickets:
                    if ticket.waited or ticket.fork_negative: continue
                    try: self.native.stop_child_only(ticket)
                    except BaseException as child_error:
                        self.cleanup_steps.append(('pending_child_stop',ticket,child_error))
                # A failure never drops strong originals/marker, retries native
                # operations or grants a second recovery period. Best-effort
                # physical closure of known local objects is not restoration.
                try: self.native.close_known_inventory(self.cleanup_until)
                except BaseException as close_error: self.cleanup_steps.append(('native_close',close_error))
                try: self.store.close_pending()
                except BaseException as close_error: self.cleanup_steps.append(('store_close',close_error))
                raise
    def prepare_live(self):
        """Prepare one original same-worker GO owner; caller owns its finally."""
        self._owner()
        if self.started: _fail('already_started')
        self.started=True
        try:
            self.phase='baseline';baseline=self.native.observe_baseline(self._stage(15))
            self.store.reserve(baseline);self.phase='reserved'
            self._start_child('watchdog')
            self.native.validate_config(self._stage(5))
            channel=self.native.observe_channel(self._stage(10))
            create_until=self._stage(20)
            ticket=self.native.reserve_interface(create_until)
            self.store.prepare_interface(ticket,channel)
            owned=self.native.create_interface(create_until)
            self.store.confirm_interface(owned);self.phase='interface_owned'
            self._start_child('controller')
            group_until=self._stage(20)
            self.native.open_control(group_until)
            source=self.native.observe_group_source(group_until)
            self.store.prepare_group_add(source)
            self.native.submit_group_add(group_until)
            observed=self.native.wait_group(group_until)
            self.store.confirm_group(observed);self.phase='group_started';self.group_confirmed=True
            if self._cancelled(group_until): _fail('stop_requested')
            ip_until=self._stage(20)
            intent=self.native.prepare_ip(ip_until);self.store.prepare_ip(intent)
            receipt=self.native.create_ip(ip_until);self.store.persist_ip_receipt(receipt)
            self.store.confirm_ip(receipt);self.ip_confirmed=True;self.phase='ip_confirmed'
            with self.store.mutex:
                service_until=self._stage(20)  # Once local slice, not a rolling TTL.
                self.service_until=self._service_until_original=service_until
                binding=self.native.issue_dhcp_binding(service_until)
                ticket=_DhcpConstructor(self,binding)
                self.dhcp_ticket=self._dhcp_ticket_original=ticket  # BEFORE ctor.
                server=ticket.creator(binding);ticket.returned=server;self.dhcp=server
                if type(server) is not dhcp.GoDhcpServer or server.binding is not binding:
                    _fail('dhcp_constructor_unknown')
                ticket.unknown=False
                prepared=self.native.prepare_dhcp(binding,server,service_until)
                self.store.prepare_dhcp(prepared)
                # Publication narrowed the IO lane; restore only the SAME
                # already-issued service cap before native-owned socket open.
                native.NativeGoResources._begin(self.native,service_until)
                dhcp.GoDhcpServer.open(server)
                listening=self.native.observe_dhcp(server,service_until)
                self.store.confirm_dhcp(listening)
                self.dhcp_listening=True;self.phase='dhcp_listening'
                self.native.begin_dhcp_service(server,service_until)
                if self._cancelled(service_until): _fail('stop_requested')
            self._owner()
            return self
        except BaseException as error:
            self.failure=error;self.stop_requested=True
            raise
    def poll_dhcp(self):
        """Consume the existing service on its original worker; no scope renewal."""
        self._owner()
        with self.store.mutex:
            if (not self.started or not self.dhcp_listening or self.restore_attempted or
                    self.failure is not None or self.service_until is None or
                    self.service_until is not self._service_until_original or
                    self.native._scope != self.service_until or
                    self.dhcp_ticket is not self._dhcp_ticket_original or
                    type(self.dhcp_ticket) is not _DhcpConstructor or self.dhcp_ticket.unknown or
                    self.dhcp_ticket.returned is not self.dhcp or
                    self.dhcp_ticket.creator is not dhcp.GoDhcpServer or
                    type(self.dhcp) is not dhcp.GoDhcpServer or
                    self.dhcp.binding is not self.dhcp_ticket.binding):
                _fail('dhcp_live_owner_changed')
            # GoDhcpServer validates the same native-issued binding/canonical/
            # socket and treats original expiry as stop-only. Do not call
            # _stage, _begin or read_network here: any changed scope is a reject.
            try:
                return dhcp.GoDhcpServer.serve_once(self.dhcp)
            except BaseException as error:
                self.failure=error;self.stop_requested=True
                raise
    def run(self):
        self._owner()
        if self.started: _fail('already_started')
        try:
            self.prepare_live()
            while self._now()<self.service_until and not self._cancelled(self.service_until):
                result=self.poll_dhcp()
                if result.get('event')=='finished': break
        except BaseException as error: self.failure=error
        finally:
            try: self.restore()
            except BaseException: pass  # Retained restore_failure and pending, never a success substitute.
        return 0 if self.failure is None and self.restore_failure is None and self.phase=='restored' and \
            self.group_confirmed and self.ip_confirmed and self.dhcp_listening and self.store.logical_restored else 1
    def status(self):
        return {'phase':self.phase,'group_observed':self.group_confirmed,
            'restored':self.store.logical_restored,'original_until_unchanged':self.until==self.entry.until,
            'ip_observed':self.ip_confirmed,'dhcp_observed':self.dhcp_listening,
            'go_ready':False,'ip_ready':False,'dhcp_ready':False,'send_ready':False,
            'device_tested':False,'phone_tested':False}
