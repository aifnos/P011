"""Private v21 CLIENT DORA coordinator over exact v19 producer originals.

No IP/route/DNS/ARP writes, endpoint proof or production admission. The caller
must retain this capsule, verify close, then use the original lease cleanup.
Original reader/receipt/FILES budgets are deliberately not increased. Python3.5.
"""
import hashlib
import math
import contextlib
import threading

import mta_client_connection as connection
import mta_client_linux_provider as linux
import mta_client_kernel_proof as kernel
import mta_client_control_frame as frame
import mta_p2p_client_init as core
import mta_ip as ip
import mta_dhcp_client as dhcp
import mta_dhcp_client_core as exchange
import mta_dhcp as wire

PROOF_SECONDS, LOCK_SECONDS = 5.0, 0.2
_CODES = frozenset(('wrong_owner', 'already_registered', 'receipt_unverified',
    'context_changed', 'proof_budget', 'deadline', 'cancelled', 'pending',
    'association_unverified', 'baseline_changed', 'ipv4_configured',
    'allocation_unverified', 'closed', 'concurrent_operation', 'io_unknown'))


class DoraError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in _CODES else 'io_unknown'
        RuntimeError.__init__(self, self.reason)


def _fail(reason): raise DoraError(reason) from None


class LiveAllocation(object):
    """Private issued live allocation, not installed IP or endpoint authority."""
    __slots__ = ('_issuer', '_client', '_socket', '_generation', '_context', '_configuration',
        '_ack', '_receipt', '_expires')
    def __init__(self, issuer, client, configuration, ack, receipt):
        for name, value in (('_issuer', issuer), ('_client', client), ('_socket', client._socket),
                ('_generation', client._generation), ('_context', client.context),
                ('_configuration', configuration), ('_ack', ack), ('_receipt', receipt),
                ('_expires', configuration.usable_until)):
            object.__setattr__(self, name, value)
    def __setattr__(self, name, value): raise AttributeError('private immutable live allocation')
    def __repr__(self): return '<private current CLIENT allocation; not an IP permission>'


class PrivateClientDora(object):
    """Only an actual v19 lease and its exact current issued receipt are inputs.

    HOST fixtures may inject the underlying DhcpSocketClient's existing socket
    and index seams after construction. Neither contexts nor proof booleans are
    constructor parameters. Synchronous v19 IO is not forcibly preempted: an
    over-budget result is retained and revoked after it actually returns.
    """
    def __init__(self, lease, receipt):
        if type(lease) is not linux.LinuxClientInitLease or type(receipt) is not connection.AssociationReceipt:
            _fail('wrong_owner')
        self.lease, self.provider, self.store = lease, lease.provider, lease.store
        if type(self.store) is not linux.stores.DurableClientInitStore: _fail('wrong_owner')
        self._owner, self._operation = self.store._mutex, self.provider._connection
        self._receipt, self._proof_calls, self._acks, self._issued = receipt, [], [], []
        self._actor_lock, self._proof_active = threading.RLock(), 0
        self._active_live, self._active, self._poll_token = None, None, None
        self._revoked, self._unknown, self._closed, self._reason = False, False, False, 'not_opened'
        self._client = None
        remaining = receipt._record.deadline - lease._now()
        if remaining <= 0: _fail('deadline')
        if not self._owner.acquire(timeout=min(LOCK_SECONDS, remaining)): _fail('pending')
        try:
            if getattr(self.provider, '_dora_v21_registration', None) is not None:
                _fail('already_registered')
            self.provider._association_receipt_current(receipt)
            op, record = self._operation, lease.record
            if (type(self.provider) is not linux.LinuxClientInitProvider or op is None or
                    type(op) is not connection._Connection or op.lease is not lease or
                    self.provider._lease is not lease or self.provider._store is not self.store or
                    receipt._operation is not op or receipt._record is not record): _fail('wrong_owner')
            self._registration = {'issuer': self, 'lease': lease, 'provider': self.provider,
                'operation': op, 'store': self.store, 'owner': self._owner,
                'binding': op.binding, 'wire': op.binding_wire, 'request': op.request,
                'record': record, 'baseline': record.baseline, 'canonical': receipt._canonical,
                'locks': lease.locks, 'device': lease.locks._device,
                'store_epoch': self.store._epoch, 'journal_epoch': self.store._journal_epoch,
                'marker': self.store._marker, 'marker_binding': self.store._binding,
                'handle': op.handle, 'deadline': op.deadline, 'client': None, 'unknown': True}
            self.provider._dora_v21_registration = self._registration
            op._dora_v21_registration = self._registration  # Retain before constructor/callbacks.
            fields = self._validate_receipt(receipt)
            meta, origin = op.binding.private_metadata(), fields['origin']
            self.context = dhcp.ClientAssociation(fields['boot'], meta['operation_epoch'],
                meta['native_epoch'], origin.phy, origin.wdev, origin.ifindex, origin.name,
                fields['local_mac'], op.deadline, hashlib.sha256(receipt._canonical.data).hexdigest())
            self._callback, self._cancel_callback = self.proof, self._cancelled
            client = dhcp.DhcpSocketClient(self.context, self._callback, self._cancel_callback,
                self._owner, clock=lease._now, proof_seconds=PROOF_SECONDS, lock_seconds=LOCK_SECONDS)
            self._client = client; self._registration['client'] = client
            self._core = client._core
            self._envelope_original = client._envelope
            self._envelope_callback = self._record_envelope
            client._envelope = self._envelope_callback
            self._registration['unknown'] = False
        except BaseException:
            if hasattr(self, '_registration'): self._revoke('io_unknown', True)
            raise
        finally: self._owner.release()

    def __repr__(self): return '<private v21 CLIENT DORA coordinator>'

    def _now(self):
        value = self.lease._now()
        if type(value) not in (int, float) or not math.isfinite(value): _fail('deadline')
        return value

    def _cancelled(self):
        return bool(self._closed or self._revoked or self.provider.cancelled.is_set())

    def _owner_current(self):
        r, op, store = self._registration, self._operation, self.store
        if self._closed or self._revoked: _fail('closed')
        if self.provider.cancelled.is_set(): _fail('cancelled')
        if self._now() >= r['deadline']: _fail('deadline')
        if (r is not getattr(self.provider, '_dora_v21_registration', None) or
                r is not getattr(op, '_dora_v21_registration', None) or r['issuer'] is not self or
                r['unknown'] is not False or r['lease'] is not self.lease or r['provider'] is not self.provider or
                r['store'] is not store or r['owner'] is not store._mutex or
                op is not self.provider._connection or op.lease is not self.lease or op.provider is not self.provider or
                self.lease.provider is not self.provider or self.lease.store is not store or
                self.provider._store is not store or self.provider._lease is not self.lease or
                self.lease.sealed or self.lease.cleanup_complete or self.lease._restore_held is not True or
                r['locks'] is not self.lease.locks or r['locks'] is not store._current_locks or
                r['device'] is not self.lease.locks._device or
                r['store_epoch'] is not store._epoch or r['journal_epoch'] is not store._journal_epoch or
                r['marker'] is not store._marker or r['marker_binding'] is not store._binding or
                r['canonical'] is not store._canonical or r['record'] is not self.lease.record or
                r['baseline'] is not self.lease.record.baseline or r['handle'] is not op.handle or
                r['handle'] is not self.lease.handles.get('controller') or
                r['binding'] is not op.binding or r['binding'] is not self.provider._connect_binding or
                type(op.binding) is not frame.ControlBinding or r['request'] is not op.request or
                op.request is not op.request._decoder._claimed_request or op.request.cancelled or
                op.request.binding is not op.binding or op.binding._wire != r['wire'] or
                op.binding.private_metadata() != self.lease.record.association.binding or
                op.deadline != r['deadline'] or self.lease.record.deadline != r['deadline'] or
                op.failed or op.disconnected or op.disconnect_requested or op.receipt_invalidated):
            _fail('context_changed')
        client = r['client']
        if client is not None and (client is not self._client or type(client) is not dhcp.DhcpSocketClient or
                client.context is not self.context or client._owner is not self._owner or client._core is not self._core or
                client._proof_callback is not self._callback or client._cancelled is not self._cancel_callback or
                client._envelope is not self._envelope_callback or client._closing): _fail('context_changed')

    def _validate_receipt(self, receipt, advance=False):
        self.provider._association_receipt_current(receipt)
        op, r = self._operation, self._registration
        canonical, original = receipt._canonical, r['canonical']
        if (receipt._record is not r['record'] or canonical is not self.store._canonical or
                not advance and canonical is not original or
                canonical._generation != original._generation or canonical.metadata != original.metadata or
                canonical.data != original.data or
                hashlib.sha256(canonical.data).hexdigest() != hashlib.sha256(original.data).hexdigest()):
            _fail('receipt_unverified')
        tickets = [t for t in self.provider._association_receipts if t['receipt'] is receipt]
        if len(tickets) != 1 or tickets[0]['unknown'] is not False: _fail('receipt_unverified')
        issued = tickets[0]['context']; executor, controller = issued['executor'], issued['controller']
        if (issued['consumed'] is not True or issued['operation'] is not op or issued['transaction'] is None or
                issued['locks'] is not r['locks'] or issued['device'] is not r['device'] or
                issued['canonical'] is not canonical or issued['store_epoch'] is not r['store_epoch'] or
                issued['journal_epoch'] is not r['journal_epoch'] or issued['marker'] is not r['marker'] or
                issued['marker_binding'] is not r['marker_binding'] or issued['binding'] is not r['binding'] or
                not any(x is issued['current'] for x in self.store._records) or
                not core._same_journal(issued['current'], self.lease.record) or
                type(executor) is not core.ExecutorProof or executor.role != 'owner' or
                not executor.actor.live() or
                executor.actor.key() != self.provider._self.key() or
                type(controller) is not core.Actor or not controller.live() or controller.key() != op.handle.actor.key()):
            _fail('receipt_unverified')
        obs, association = receipt._observation, self.lease.record.association
        if (type(obs) is not connection.ConnectionObservation or obs is not op.result or obs._operation is not op or
                not any(x is obs for x in op.observations) or len(obs._kernels) != 2 or len(obs._statuses) != 2 or
                len(obs._snapshots) != 2 or len(obs._caps) != 2 or
                type(association) is not core.ClientAssociationRecord or association.phase != 'confirmed'):
            _fail('association_unverified')
        previous = None
        for observation, status, snapshot, caps in zip(obs._kernels, obs._statuses, obs._snapshots, obs._caps):
            rows = [x for x in self.provider._kernel_readers if x['value'] is observation]
            if (type(observation) is not kernel.KernelObservation or len(rows) != 1 or
                    rows[0]['unknown'] is not False or rows[0]['reader'] is not observation._reader or
                    rows[0]['operation'] is not op): _fail('association_unverified')
            observation._reader.authenticate(op, op._operation_epoch, observation)
            fields, reported = observation.private_fields(), status.private_fields()
            op._kernel_fields(observation, reported, obs._event.private_fields())
            if (fields['origin'] is not op.owned or fields['origin'].iftype != 8 or
                    fields['boot'] != self.lease.record.baseline.boot or fields['boot'] != self.provider._boot or
                    not status.public_summary()['ctrl_completed'] or
                    (association.local_mac, association.bssid, association.frequency) !=
                    (fields['local_mac'], fields['stations'][0][0], fields['channel'][1])):
                _fail('association_unverified')
            cap_rows = [x for x in self.provider._caps_readers if x['value'] is caps]
            if len(cap_rows) != 1 or cap_rows[0]['unknown'] is not False: _fail('association_unverified')
            if type(snapshot) is not core.Snapshot or type(snapshot.ipv4) is not ip.IpSnapshot:
                _fail('baseline_changed')
            if (any(x.ifindex == op.owned.ifindex for x in snapshot.ipv4.addresses) or
                    any(x.oif == op.owned.ifindex for x in snapshot.ipv4.routes)): _fail('ipv4_configured')
            if snapshot.key(op.owned) != r['baseline'].key(): _fail('baseline_changed')
            facts = (op._kernel_fields(observation, reported, obs._event.private_fields()), reported, snapshot.key(op.owned), caps)
            if previous is not None and previous != facts: _fail('association_unverified')
            previous = facts
        self.store._canonical_valid(receipt._canonical, receipt._record)
        return fields

    def _revoke(self, reason, unknown=False):
        with self._actor_lock:
            self._revoked, self._active_live = True, None
            self._unknown = self._unknown or unknown
            if self._reason == 'not_opened' or self._reason == 'broadcast_dora': self._reason = reason
        if self._operation is not None: self._operation.invalidate_receipt()
        if unknown:
            self._registration['unknown'] = True
            self.lease.pending = self.lease.resource_pending = True
            self.lease.cleanup_complete = False
        if self._client is not None: self._client.close()

    def proof(self, context, budget):
        """A new original receipt on every call; no cached True or deadline renewal."""
        if context is not self.context or type(context) is not dhcp.ClientAssociation:
            _fail('wrong_owner')
        if type(budget) not in (int, float) or not math.isfinite(budget) or not 0 < budget <= PROOF_SECONDS:
            _fail('proof_budget')
        start = self._now(); until = min(context.deadline, start + budget)
        call = {'context': context, 'input': self._receipt, 'returned': None, 'proof': None,
            'previous_canonical': self._registration['canonical'], 'current_canonical': None,
            'started': start, 'until': until, 'unknown': True, 'active': True}
        # Separate from the DHCP adapter's guard: direct proof preflight also
        # has a producer that may still be returning after close is requested.
        with self._actor_lock:
            if self._closed or self._revoked: _fail('closed')
            self._proof_calls.append(call)
            self._proof_active += 1
        acquired = False
        try:
            acquired = self._owner.acquire(timeout=min(LOCK_SECONDS, max(0, until - start)))
            if not acquired: _fail('pending')
            self._owner_current()
            if self._now() >= until: _fail('proof_budget')
            returned = self.lease.read_association_receipt(self._receipt)
            call['returned'] = returned; self._receipt = returned  # Original return before any postcheck.
            call['current_canonical'] = returned._canonical
            fields = self._validate_receipt(returned, advance=True)
            meta, origin = self._operation.binding.private_metadata(), fields['origin']
            expected = dhcp.ClientAssociation(fields['boot'], meta['operation_epoch'], meta['native_epoch'],
                origin.phy, origin.wdev, origin.ifindex, origin.name, fields['local_mac'],
                self._operation.deadline, returned.receipt_id)
            if expected != context: _fail('context_changed')
            if self._now() > until: _fail('proof_budget')
            # Store.current replaces only its actual CanonicalRecord. The lease
            # retains its original Journal/baseline pointers across readback.
            self._registration['canonical'] = returned._canonical
            self._owner_current()
            # Each True follows the corresponding real fresh producer gates above.
            value = dhcp.AssociationProof(context, fields['boot'], meta['operation_epoch'], meta['native_epoch'],
                origin.phy, origin.wdev, origin.ifindex, origin.name, origin.iftype,
                True, True, True, True, True, True)
            call['proof'] = value; call['unknown'] = False
            return value
        except BaseException as error:
            call['failure'] = ('dora', error.reason) if type(error) is DoraError else linux._diagnostic_error(error)
            self._revoke('io_unknown', True)
            raise
        finally:
            try:
                if acquired: self._owner.release()
            except BaseException:
                call['owner_release_unknown'] = True
                self._revoke('io_unknown', True)
                raise
            finally:
                with self._actor_lock:
                    call['active'] = False
                    self._proof_active -= 1

    def _record_envelope(self, packet, ancillary, flags, source):
        reason = self._envelope_original(packet, ancillary, flags, source)
        if reason is None and wire.decode(packet)['type'] == wire.ACK:
            if len(self._acks) >= 64: _fail('allocation_unverified')
            row = {'packet': packet, 'source': source, 'ancillary': ancillary, 'flags': flags,
                'client': self._client, 'generation': self._client._generation,
                'token': self._poll_token, 'packets_before': self._core._packets,
                'configuration': None, 'accepted': False, 'unknown': True}
            self._acks.append(row)  # Original ingress bytes before core acceptance.
        return reason

    def _accept_ack(self, token):
        now = self._now(); configuration = self._core.configuration(now)
        if configuration is None: return
        rows = [r for r in self._acks if r['token'] is token]
        if len(rows) != 1: _fail('allocation_unverified')
        row = rows[0]; message = wire.decode(row['packet'])
        if (token is None or token is not self._poll_token or row['client'] is not self._client or row['generation'] != self._client._generation or
                self._core._packets != row['packets_before'] + 1 or message['chaddr'] != self.context.mac or
                message['xid'] != self._core._xid or
                wire.address(message['yiaddr']) != configuration.local_ip or
                wire.address(message['options'][54]) != configuration.server_ip or
                wire.address(message['options'][1]) != configuration.subnet_mask or
                configuration.usable_until > self.context.deadline): _fail('allocation_unverified')
        row['configuration'] = configuration; row['accepted'] = True; row['unknown'] = False

    @contextlib.contextmanager
    def _scope(self):
        remaining = self.context.deadline - self._now()
        if remaining <= 0: _fail('deadline')
        if not self._owner.acquire(timeout=min(LOCK_SECONDS, remaining)): _fail('pending')
        try:
            self._owner_current()
            yield
        finally: self._owner.release()

    def _enter(self, name):
        try:
            with self._scope():
                if self._active is not None: _fail('concurrent_operation')
                self._active = name
        except BaseException as error:
            reason = error.reason if type(error) is DoraError else 'io_unknown'
            self._revoke(reason, reason not in ('closed', 'cancelled', 'deadline'))
            raise

    def open(self):
        self._enter('open')
        try:
            self._client.open(); self._reason = 'broadcast_dora'
            return self
        except BaseException:
            self._revoke('io_unknown', True); raise
        finally: self._active = None

    def poll(self):
        self._enter('poll'); token = object(); self._poll_token = token
        try:
            returned = self._client.poll()
            if returned['event'] == 'candidate_received':
                with self._scope(): self._accept_ack(token)
            return returned
        except BaseException:
            self._revoke('io_unknown', True); raise
        finally: self._poll_token, self._active = None, None

    def candidate(self):
        self._enter('candidate')
        try:
            with self._scope():
                returned = self._client.candidate()
                if returned is None: return None
                if type(returned) is not dhcp.ConfigurationCandidate or returned.interface_configured or returned.endpoint_verified:
                    _fail('allocation_unverified')
                configuration = self._core.configuration(self._now())
                if configuration is not returned.allocation or type(configuration) is not exchange._Configuration:
                    _fail('allocation_unverified')
                rows = [r for r in self._acks if r['configuration'] is configuration and r['accepted'] is True and r['unknown'] is False]
                if len(rows) != 1 or len(self._issued) >= 8: _fail('allocation_unverified')
                ticket = {'client': self._client, 'configuration': configuration, 'ack': rows[0],
                    'receipt': self._receipt, 'value': None, 'unknown': True}
                self._issued.append(ticket)
                value = LiveAllocation(self, self._client, configuration, rows[0], self._receipt)
                ticket['value'] = value
                if not self._live_current(value): _fail('allocation_unverified')
                self._active_live = value; ticket['unknown'] = False
                return value
        except BaseException:
            self._revoke('io_unknown', True); raise
        finally: self._active = None

    def _live_current(self, value):
        self._owner_current()
        return (type(value) is LiveAllocation and value._issuer is self and value._client is self._client and
            value._socket is not None and value._socket is self._client._socket and self._client._stage == 'bound' and
            value._generation == self._client._generation and value._context is self.context and
            value._configuration is self._core.configuration(self._now()) and
            self._now() < value._expires <= self.context.deadline and value._ack['accepted'] is True and
            value._ack['unknown'] is False and value._ack['configuration'] is value._configuration and
            any(r is value._ack for r in self._acks) and not self._client._closing)

    def validate_live(self, value):
        """Exact registered original plus another fresh proof, under owner lock."""
        if type(value) is not LiveAllocation or value is not self._active_live: return False
        self._enter('validate_live')
        try:
            with self._scope():
                if not any(t['value'] is value and t['unknown'] is False for t in self._issued): return False
                self.proof(self.context, min(PROOF_SECONDS, self.context.deadline - self._now()))
                return self._live_current(value)
        except BaseException:
            self._revoke('io_unknown', True); raise
        finally: self._active = None

    def close(self):
        with self._actor_lock:
            self._closed, self._revoked, self._active_live = True, True, None
        complete = self._client.close() if self._client is not None else False
        with self._actor_lock:
            return complete and self._active is None and not self._unknown and self._proof_active == 0

    cancel = close

    def status(self):
        state = {} if self._client is None else self._client.status()
        with self._actor_lock:
            return {'closed': self._closed, 'resource_pending': bool(self._unknown or self._active is not None or
                self._proof_active or state.get('socket_actor_pending', True)), 'reason': self._reason,
                'proof_calls': len(self._proof_calls), 'live_allocation_issued': bool(self._issued),
                'interface_configured': False, 'endpoint_verified': False,
                'send_available': False, 'receive_available': False, 'production_available': False}
