"""Versioned CLIENT two-phase composition; no default platform provider or RF gate.

Only explicit start/restore perform work. The existing core, B Store, C registry
and direct-child owner are composed unchanged. Private specs/actions are never
HTTP inputs; their shape is not an authenticated production manifest.
"""
import errno

import mta_p2p_client_init as core
import mta_client_store as stores
import mta_client_process_owner as processes
import mta_client_launch_registration as launches


class TwoPhaseClientInitProvider(core.ClientInitProvider):
    """Future fixed producer; default methods remain unavailable.

    request_child_stop is a trusted platform action, not an exit proof. Returning
    None only reports its return; the exact direct-child owner still waits/reaps
    and rereads absence. No default signal, socket or restore action is supplied.
    """
    def request_child_stop(self, child, deadline): core._fail('provider_unavailable')


class _Launch(object):
    def __init__(self, bridge, ticket, locks, intent):
        self.bridge, self.ticket, self.locks, self.intent = bridge, ticket, locks, intent
        self.child = self.registration = self.returned = self.handle = None
        self.prepare_requested = self.prepared = self.prepare_unknown = False
        self.launch_requested = self.release_requested = False
        self.stop_requested = self.stop_returned = self.stop_unknown = False
        self.gate = None
        self.gate_close_requested = self.gate_closed = False
        self.inventory_close_requested = self.inventory_closed = False
        self.exit_observations = []

    def __repr__(self): return '<CLIENT private two-phase launch>'


class DirectChildLaunchBridge(object):
    """Pure constructor over exact existing B/C/Owner, not a Linux Provider."""
    def __init__(self, store, owner, specs):
        if (type(store) is not stores.DurableClientInitStore or
                type(owner) is not processes.DirectChildOwner or type(specs) is not tuple or
                len(specs) != 2 or any(type(s) is not processes.LaunchSpec for s in specs) or
                set(s.role for s in specs) != set(('watchdog', 'controller'))):
            core._fail('invalid_provider')
        self.store, self.owner, self.specs = store, owner, dict((s.role, s) for s in specs)
        self.registry = launches.DurableLaunchRegistry(store, owner)
        self._mutex, self._epoch = store._mutex, store._epoch
        self._operations, self._pending, self._registry_close_requested = [], False, False

    def _exact(self, op):
        if (type(op) is not _Launch or op.bridge is not self or
                not any(item is op for item in self._operations)):
            core._fail('invalid_ticket')

    def reserve(self, ticket, locks, intent):
        # Save this exact operation in the caller BEFORE prepare/launch resources.
        with self._mutex:
            if self._pending or self._registry_close_requested: core._fail('resource_close_unknown')
            if (type(ticket) is not core.Ticket or type(intent) is not core.Journal or
                    self.store._epoch is not self._epoch or locks is not self.store._current_locks or
                    intent.stage != ticket.role + '_intent' or
                    getattr(intent, ticket.role + '_ticket').key() != ticket.key()):
                core._fail('invalid_ticket')
            spec = self.specs[ticket.role]
            if (ticket.exe, ticket.argv_sha) != (spec.exe, spec.argv_sha): core._fail('invalid_ticket')
            if len(self._operations) >= 2 or any(o.ticket.role == ticket.role for o in self._operations):
                core._fail('invalid_ticket')
            op = _Launch(self, ticket, locks, intent); self._operations.append(op)
            return op

    def prepare(self, op):
        with self._mutex:
            self._exact(op)
            if op.prepare_requested or self._pending: core._fail('invalid_ticket')
            op.prepare_requested = True
            try:
                actual = self.store.current(op.locks)
                if not core._same_journal(actual, op.intent): core._fail('stale_current')
                op.child = self.owner.register(self.specs[op.ticket.role], op.locks._device.fd, actual.deadline)
                op.registration = self.registry.register(op.ticket, op.child)
                op.prepared = True
                return op
            except BaseException:
                # Owner/C registries also retain a returned-before-raise resource.
                op.prepare_unknown = self._pending = True
                raise

    def launch(self, op):
        with self._mutex:
            self._exact(op)
            if not op.prepared or op.launch_requested or self._pending: core._fail('invalid_ticket')
            op.launch_requested = True
            op.returned = self.owner.launch(op.child)
            if op.returned is not op.child: self._pending = True; core._fail('actor_unknown')

    def release(self, op):
        with self._mutex:
            self._exact(op)
            if not op.launch_requested or op.release_requested: core._fail('exec_gate_failed')
            op.release_requested = True
            returned = self.registry.release(op.registration)
            if returned is not op.registration.persist_receipt: self._pending = True; core._fail('exec_gate_failed')

    def resolve(self, op):
        with self._mutex:
            self._exact(op)
            op.returned = self.registry.resolve(op.registration)
            if op.returned is not None:
                op.handle = op.returned  # Preserve even a malformed return before validation.
                if type(op.handle) is not core.Handle or op.handle.resource is not op.child:
                    self._pending = True; core._fail('actor_unknown')
            return op.returned

    def pause_resolution(self, op, deadline):
        self._exact(op); self.owner._now(deadline)
        self.owner._sleep(.01)  # Existing bounded owner adapter, not a new background actor.
        self.owner._now(deadline)

    def _close_child_inventory(self, op):
        if not op.inventory_close_requested:
            op.inventory_close_requested = True
            try: op.inventory_closed = self.owner.close_inventory(op.child) is True
            except BaseException: self._pending = True
        return op.inventory_closed

    def _close_pregate(self, op, deadline):
        child = op.child
        if (child.unknown or child.released or child.release_requested or self.owner._active or
                not child.fork_returned or child.fork_negative or type(child.pid) is not int or child.pid <= 0):
            return False
        rows = [row for row in child.fds if row.role == 'gate_write']
        if len(rows) != 1: return False
        if op.gate is None: op.gate = rows[0]
        if op.gate is not rows[0]: return False
        gate = op.gate
        if op.gate_close_requested:
            # A known timed-out wait can reobserve this original closed gate,
            # never close it again or trust closed=True without fresh EBADF.
            return op.gate_closed and self._closed_fd(gate, self.owner._os, 'unknown')
        if (gate.unknown or gate.attempted or gate.closed or gate.returned is not True or
                type(gate.fd) is not int or gate.metadata is None): return False
        self.owner._single(child, deadline=deadline)
        op.gate_close_requested = True
        op.gate_closed = self.owner._close_fd(child, gate) is True
        return op.gate_closed

    def _cleanup_child(self, op, provider, deadline):
        self._exact(op)
        child = op.child
        if op.prepare_unknown or type(child) is not processes.ChildTicket or child.unknown or self.owner._active:
            return False
        self.owner._exact(child)
        if not child.fork_requested or child.fork_negative:
            return self._close_child_inventory(op)
        if not child.fork_returned or child.preexec is None: return False
        if not child.released:
            # EOF only on the exact original gate. Keep executable, error,
            # notify and device-dupe inventory until actual reap + fresh exit.
            if not self._close_pregate(op, deadline): return False
        elif not child.waited and not op.stop_requested:
            op.stop_requested = True
            try:
                returned = provider.request_child_stop(child, deadline)
                if returned is not None: op.stop_unknown = True
                else: op.stop_returned = True
            except core.ClientInitError as error:
                # The default fixed negative supplied no stop action. Natural
                # exact wait/reap can still establish an already-exited child.
                if error.code != 'provider_unavailable': op.stop_unknown = True
            except BaseException: op.stop_unknown = True
        if op.stop_unknown: return False
        remaining = deadline - self.owner._now()
        if remaining <= 0: return False
        try:
            if self.owner.wait_reap(child, min(.1, remaining)) is not True: return False
            if self.owner.fresh_exit(child) is not True: return False
            op.exit_observations.append(child.exit_observation)
        except BaseException: return False
        return self._close_child_inventory(op)

    def cleanup(self, provider, deadline):
        """Explicit external cleanup; independent child attempts, no fake Handle."""
        with self._mutex:
            good = True
            for op in reversed(self._operations):
                try: good = self._cleanup_child(op, provider, deadline) and good
                except BaseException: good = False
            if not self._registry_close_requested:
                self._registry_close_requested = True
                try: self.registry.close()
                except BaseException: self._pending = True
            return good and self.verify_closed()

    @staticmethod
    def _closed_fd(ticket, io, unknown_field):
        if getattr(ticket, unknown_field, None) is not False or ticket.closed is not True: return False
        if ticket.fd is None: return ticket.attempted is False
        if type(ticket.fd) is not int or ticket.attempted is not True: return False
        try: io.fstat(ticket.fd)
        except OSError as error: return type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: pass
        return False

    def verify_closed(self):
        """Explicit readback (not public status): ALL Owner and C original FDs."""
        with self._mutex:
            children = [o.child for o in self._operations if o.child is not None]
            if (self._pending or self.owner._active or self.registry._pending or
                    len(children) != len(self._operations) or len(children) != len(self.owner._tickets) or
                    any(not any(t is child for child in children) for t in self.owner._tickets) or
                    not self._registry_close_requested): return False
            for op in self._operations:
                child = op.child
                if (op.prepare_unknown or op.stop_unknown or child.unknown or not op.inventory_closed or
                        child.fork_requested and not child.fork_negative and
                        (child.waited is not True or child.exit_verified is not True)): return False
                if any(not self._closed_fd(fd, self.owner._os, 'unknown') for fd in child.fds): return False
            return all(self._closed_fd(fd, fd.io, 'opening_unknown') for fd in self.registry._inventory)

    def status(self):
        # Passive: no clocks, file reads, callbacks, close or process inspection.
        with self._mutex:
            return {'launch_count': len(self._operations), 'prepare_unknown': any(o.prepare_unknown for o in self._operations),
                'resource_pending': self._pending or self.registry._pending or any(o.prepare_unknown or o.stop_unknown or
                    o.child is not None and o.child.unknown for o in self._operations),
                'registry_close_requested': self._registry_close_requested,
                'production_provider': False, 'send_available': False, 'receive_available': False}


class TwoPhaseClientInitLease(core.ClientInitLease):
    """Same immutable Journal v4, different honest launch and cleanup order."""
    def __init__(self, provider, store, identity, clock, bridge=None):
        core.ClientInitLease.__init__(self, provider, store, identity, clock)
        if type(store) is not stores.DurableClientInitStore or (bridge is not None and
                (type(bridge) is not DirectChildLaunchBridge or bridge.store is not store)):
            core._fail('invalid_store')
        self.bridge, self.launches, self.returned_handles = bridge, [], []
        self._start_attempted = self._restore_held = False
        self._provider_close_requested = self._provider_close_unknown = False
        self._provider_close = None

    def _role(self, role, deadline, cancelled):
        ticket = self._register(role, deadline)
        self._save(self.record.replace(stage=role + '_intent', **{role + '_ticket': ticket}))
        self._budget(deadline, cancelled); self._fresh()
        op = self.bridge.reserve(ticket, self.locks, self.record)
        self.launches.append(op)  # Before even pure child registration, let alone fork/FDs.
        self.bridge.prepare(op)
        self._budget(deadline, cancelled); self.bridge.launch(op)
        self._budget(deadline, cancelled); self._fresh(); self.bridge.release(op)
        for attempt in range(16):
            self._budget(deadline, cancelled)
            handle = self.bridge.resolve(op)
            if handle is not None:
                self.returned_handles.append(handle)
                handle = self._handle(ticket, handle)
                # Retain the genuine late child before deadline/cancellation checks.
                self._save(self.record.replace(stage=role + '_saved', **{role: handle.actor}))
                self._budget(deadline, cancelled)
                return handle
            if attempt != 15: self.bridge.pause_resolution(op, deadline)
        core._fail('actor_unknown')

    def start(self, ttl=20, cancelled=None):
        core._finite(ttl, 'invalid_budget')
        if not 0 < ttl <= 20: core._fail('invalid_budget')
        deadline = self._now() + ttl
        if self.sealed: return self._sealed_status(deadline)
        if self._start_attempted: self.reason = 'current_blocked'; return self.status()
        if self.bridge is None or not isinstance(self.provider, TwoPhaseClientInitProvider):
            self.reason = 'provider_unavailable'; return self.status()
        self._start_attempted = True
        deadline = self._now() + 20  # Bounded non-RF preparation; includes lock waiting.
        with self.store._mutex:
            try:
                self._budget(deadline, cancelled); prepared_executor = self._executor(deadline, starting=True)
                self.locks = self.store.acquire(self.identity, deadline)
                self._locked()
                if self.store.current(self.locks) is not None: core._fail('current_blocked')
                if self.store.pending_clear(self.locks) is not True: core._fail('pending_blocked')
                baseline = self.provider.snapshot(deadline)
                if type(baseline) is not core.Snapshot: core._fail('invalid_snapshot')
                if self.store.prior_clear(self.locks, baseline, deadline) is not True: core._fail('pending_blocked')
                core.client_combo(self.provider.caps(deadline), baseline)
                if self.provider.original_actors(baseline, deadline) is not True: core._fail('actor_unknown')
                # No external return/wait between preparation and the active
                # record. Recheck the same F and exact empty local admission.
                self._budget(deadline, cancelled)
                active_executor = self._executor(deadline, starting=True)
                if active_executor.actor.key() != prepared_executor.actor.key(): core._fail('actor_unknown')
                self._locked()
                if self.store.current(self.locks) is not None: core._fail('current_blocked')
                if self.store.pending_clear(self.locks) is not True: core._fail('pending_blocked')
                self._budget(deadline, cancelled)
                deadline = self._now() + ttl  # Set once BEFORE the first durable Journal.
                self._budget(deadline, cancelled); self._save(core.Journal(self.identity, 'prepared', baseline, deadline))
                self._role('watchdog', deadline, cancelled)
                baseline = self._baseline(deadline)
                core.client_combo(self.provider.caps(deadline), baseline)
                self._budget(deadline, cancelled)
                ticket = self.provider.register_interface(self.identity, self.record.baseline, deadline)
                if type(ticket) is not core.InterfaceTicket or ticket.boot != baseline.boot or ticket.phy != baseline.station.phy:
                    core._fail('invalid_origin')
                self._save(self.record.replace(stage='interface_intent', interface_ticket=ticket))
                self._budget(deadline, cancelled); self._fresh()
                owned = self.provider.create_client(ticket, deadline)
                if (type(owned) is not core.Origin or owned.iftype != 8 or owned.phy != baseline.station.phy or
                        owned.name != ticket.name or any(r.name == owned.name or r.ifindex == owned.ifindex or
                        r.wdev == owned.wdev for r in baseline.interfaces)): core._fail('invalid_origin')
                self._save(self.record.replace(stage='interface_owned', owned=owned))
                self._baseline(deadline, owned)
                handle = self._role('controller', deadline, cancelled)
                self._baseline(deadline, owned)
                if self.provider.origin_up(owned, deadline) is not True: core._fail('origin_changed')
                for actual in tuple(self.handles.values()):
                    proof = self.provider.live_actor(actual, deadline)
                    if type(proof) is not core.Actor or proof.key() != actual.actor.key() or not proof.live(): core._fail('actor_unknown')
                core.parse_init_status(self.provider.status(handle, owned, deadline))
                self._baseline(deadline, owned); self._budget(deadline, cancelled)
                self._save(self.record.replace(stage='client_init_ready', ready=True))
                self._active_return_lock(); self.reason = 'not_recorded'
            except BaseException as error:
                self.reason = error.code if type(error) is core.ClientInitError else 'unexpected_provider_error'
                self.pending = True
                try:
                    if self.locks is not None and self.record is not None and self.store._released is None:
                        self._active_return_lock()
                    elif self.locks is not None and self.record is None:
                        self._finish_receipt(None, False, deadline)
                except BaseException: self.locks_uncertain = self.locks is not None; self.resource_pending = True
                if not isinstance(error, Exception): raise
        return self.status()

    def restore(self, timeout=20, inherited=None):
        core._finite(timeout, 'invalid_budget')
        if not 0 < timeout <= 20: core._fail('invalid_budget')
        deadline = self._now() + timeout
        if self.sealed: return self._sealed_status(deadline)
        if self.bridge is None: self.reason = 'provider_unavailable'; return self.status()
        with self.store._mutex:
            try:
                self._known_locks_before_acquire(deadline)
                proof = self._executor(deadline, inherited=self.locks if inherited is None else inherited)
                # Direct child wait/reap belongs to the original live F only. No
                # shape-based external/orphan executor is admitted by this slice.
                if proof.role != 'owner': core._fail('executor_role_forbidden')
                for op in self.launches:
                    for actual in (op.child.preexec, op.child.postexec) if op.child is not None else ():
                        if actual is not None and (proof.actor.pid, proof.actor.start) == (actual.pid, actual.start):
                            core._fail('self_actor_recovery')
                if not self._restore_held:
                    self.locks = self.store.acquire(self.identity, deadline, self.locks if inherited is None else inherited)
                    self._restore_held = True
                self.record = self.store.current(self.locks)
                if type(self.record) is not core.Journal or not self._pending_admission(self.record): core._fail('current_blocked')
                if self.record.stage != 'cleanup_intent': self._save(self.record.replace(stage='cleanup_intent', ready=False))
                self._baseline(deadline, self.record.owned)
                if self.bridge.cleanup(self.provider, deadline) is not True: core._fail('resource_close_unknown')
                self._baseline(deadline, self.record.owned)
                owned = self.record.owned
                if owned is not None:
                    if self.provider.origin_up(owned, deadline) is not True or self.provider.delete_client(owned, deadline) is not True:
                        core._fail('origin_changed')
                    if self.provider.origin_absent(owned, deadline) is not True: core._fail('origin_changed')
                self._baseline(deadline)
                if not self._provider_close_requested:
                    self._provider_close_requested = True
                    try: self._provider_close = self.provider.close_resources(tuple(self.handles.values()), deadline)
                    except BaseException: self._provider_close_unknown = True; raise
                    if type(self._provider_close) is not core.CloseProof or not self._provider_close.complete():
                        self._provider_close_unknown = True
                if self._provider_close_unknown or type(self._provider_close) is not core.CloseProof or \
                        self._provider_close.expected < len(self.launches) or not self.bridge.verify_closed():
                    core._fail('resource_close_unknown')
                if self.store._restore_reader is None: core._fail('store_unavailable')
                self._baseline(deadline)
                self._save(self.record.replace(stage='cleanup_verified', ready=False))
                self._finish_receipt(self.record, True, deadline)  # Existing full B producer + semantic validation.
                if self.cleanup_complete: self.reason = 'not_recorded'
            except BaseException as error:
                self.pending = True; self.cleanup_complete = False
                self.reason = error.code if type(error) is core.ClientInitError else 'unexpected_provider_error'
                if not isinstance(error, Exception): raise
        return self.status()

    def status(self):
        value = core.ClientInitLease.status(self)
        value.update({'evidence': 'TWO_PHASE_HOST_COMPOSITION_ONLY', 'rf_init_possible': False,
            'production_provider': False, 'launch_count': len(self.launches), 'orphan_recovery': False,
            'send_available': False, 'receive_available': False})
        value['resource_pending'] = (value['resource_pending'] or self._provider_close_unknown or
            self.store.status()['resource_pending'])
        if self.bridge is not None:
            value['resource_pending'] = value['resource_pending'] or self.bridge.status()['resource_pending']
        return value
