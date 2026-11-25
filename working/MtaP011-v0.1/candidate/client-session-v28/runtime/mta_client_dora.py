"""Private v26 F CLIENT DORA coordinator over exact producer originals.

No IP/route/DNS/ARP writes, endpoint proof or production admission. The caller
must retain this capsule. Original Provider recovery consumes its exact factory,
UDP close tickets and all producers before terminal marker clearing. No source
quota/TTL expansion; payload subset is not a full heap or device proof. Python3.5.
"""
import hashlib
import errno
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


class _SocketTicket(object):
    """Original synchronous UDP factory/once-close evidence, never a public FD."""
    def __init__(self, owner, ordinal, creator):
        self.owner, self.issuer, self.ordinal, self.creator = owner, owner._socket_issuer_v26, ordinal, creator
        self.raw, self.descriptor, self.metadata = None, None, None
        self.cleanup_descriptor, self.cleanup_metadata = None, None
        self.before_fileno, self.final_fileno = None, None
        self.factory_returned, self.factory_active = False, True
        self.close_requested, self.close_called, self.close_active, self.close_returned = False, False, False, False
        self.close_result = self.close_error = self.ebadf_error = None
        self.ebadf_errno, self.fileno_closed, self.unknown = None, False, True

    def __repr__(self): return '<private original CLIENT UDP close ticket>'


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


class L3Handoff(object):
    """Once-issued original; journal IP facts or a copied ACK are not this grant."""
    def __init__(self, issuer, allocation):
        store, lease, op = issuer.store, issuer.lease, issuer._operation
        values = {'_issuer': issuer, '_allocation': allocation, '_lease': lease,
            '_store': store, '_mutex': store._mutex, '_store_epoch': store._epoch,
            '_journal_epoch': store._journal_epoch, '_locks': lease.locks,
            '_device': lease.locks._device, '_marker': store._marker,
            '_binding': store._binding, '_operation': op, '_controller': op.handle,
            '_record': lease.record, '_canonical': store._canonical,
            '_socket': allocation._socket, '_configuration': allocation._configuration,
            '_ack': allocation._ack, '_generation': allocation._generation,
            '_until': min(allocation._expires, lease.record.deadline)}
        for name, value in values.items(): object.__setattr__(self, name, value)
    def __setattr__(self, name, value): raise AttributeError('private original L3 handoff')
    def __repr__(self): return '<private original CLIENT L3 handoff>'


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
        self._socket_issuer_v26, self._socket_tickets_v26 = object(), []
        self._factory_active_v26, self._sync_active_v26, self._sync_ticket_v26 = 0, False, None
        self._active_live, self._active, self._poll_token = None, None, None
        self._l3_ticket_v28, self._l3_owner_v28 = None, None
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
            creation = self.provider._dora_v26_creation
            if (type(creation) is not dict or creation.get('receipt') is not receipt or
                    creation.get('creator') is not PrivateClientDora or creation.get('issued') is not None or
                    creation.get('returned') is not None or creation.get('unknown') is not True):
                _fail('wrong_owner')
            self._registration = {'issuer': self, 'lease': lease, 'provider': self.provider,
                'operation': op, 'store': self.store, 'owner': self._owner,
                'binding': op.binding, 'wire': op.binding_wire, 'request': op.request,
                'record': record, 'baseline': record.baseline, 'canonical': receipt._canonical,
                'locks': lease.locks, 'device': lease.locks._device,
                'store_epoch': self.store._epoch, 'journal_epoch': self.store._journal_epoch,
                'marker': self.store._marker, 'marker_binding': self.store._binding,
                'handle': op.handle, 'deadline': op.deadline, 'client': None, 'unknown': True}
            creation['issued'] = self  # The partial original survives a constructor exception.
            self.provider._dora_v21_registration = self._registration
            op._dora_v21_registration = self._registration  # After the original creation root, before callbacks.
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
            self._socket_creator_v26 = client._factory
            self._factory_callback_v26, self._dispose_callback_v26 = self._socket_factory_v26, self._dispose_socket_v26
            client._factory, client._dispose = self._factory_callback_v26, self._dispose_callback_v26
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
                client._envelope is not self._envelope_callback or
                client._factory is not self._factory_callback_v26 or client._dispose is not self._dispose_callback_v26 or
                client._closing): _fail('context_changed')

    def _socket_unknown_v26(self):
        # Physical close and source authorization are distinct. A no-return or
        # malformed producer never becomes known merely because a number closes.
        with self._actor_lock:
            self._unknown = True
            if hasattr(self, '_registration'): self._registration['unknown'] = True
            self.lease.pending = self.lease.resource_pending = True
            self.lease.cleanup_complete = False

    def _socket_factory_v26(self, family, kind, protocol):
        with self._actor_lock:
            if self._closed or self._revoked or self._socket_tickets_v26: _fail('closed')
            ticket = _SocketTicket(self, len(self._socket_tickets_v26), self._socket_creator_v26)
            self._socket_tickets_v26.append(ticket)  # Before the real factory.
            self._factory_active_v26 += 1
        try:
            raw = ticket.creator(family, kind, protocol)
            ticket.raw, ticket.factory_returned = raw, True  # Before fileno/fstat/postchecks.
            if self._closed or self._revoked: _fail('closed')
            if self._now() >= self.context.deadline: _fail('deadline')
            if raw is None or not callable(getattr(raw, 'fileno', None)) or not callable(getattr(raw, 'close', None)):
                _fail('io_unknown')
            descriptor = raw.fileno(); ticket.descriptor = descriptor
            if type(descriptor) is not int or not 0 <= descriptor <= 0x7fffffff: _fail('io_unknown')
            if self._now() >= self.context.deadline: _fail('deadline')
            ticket.metadata = linux.baseline._metadata(self.provider._io.fstat(descriptor))
            if not linux.stat.S_ISSOCK(ticket.metadata[2]): _fail('io_unknown')
            if self._now() >= self.context.deadline: _fail('deadline')
            ticket.unknown = False
            return raw
        except BaseException as error:
            ticket.factory_error = error
            self._socket_unknown_v26()
            raise
        finally:
            with self._actor_lock:
                ticket.factory_active = False
                self._factory_active_v26 -= 1

    def owns_socket_ticket_v26(self, ticket):
        return (type(ticket) is _SocketTicket and ticket.owner is self and ticket.issuer is self._socket_issuer_v26 and
            type(ticket.ordinal) is int and 0 <= ticket.ordinal < len(self._socket_tickets_v26) and
            self._socket_tickets_v26[ticket.ordinal] is ticket and ticket.creator is self._socket_creator_v26)

    def closed_socket_ticket_v26(self, ticket):
        # Consume the issuer's actual immediate EBADF, never manufacture it
        # from a later fstat of a descriptor that may have been reused.
        return (self.owns_socket_ticket_v26(ticket) and ticket.factory_returned and not ticket.factory_active and
            not ticket.unknown and ticket.raw is not None and type(ticket.descriptor) is int and
            0 <= ticket.descriptor <= 0x7fffffff and type(ticket.metadata) is tuple and
            ticket.close_called and not ticket.close_active and ticket.close_returned and ticket.close_result is None and
            ticket.close_error is None and ticket.fileno_closed and isinstance(ticket.ebadf_error, OSError) and
            type(ticket.ebadf_errno) is int and ticket.ebadf_errno == errno.EBADF)

    def _dispose_socket_v26(self, raw):
        client = self._client
        with self._actor_lock:
            rows = [r for r in self._socket_tickets_v26 if r.raw is raw and r.factory_returned]
            if len(rows) != 1:
                self._socket_unknown_v26(); return False
            ticket = rows[0]
            if ticket.close_requested: return self.closed_socket_ticket_v26(ticket)
            ticket.close_requested, ticket.close_active = True, True
        with client._lock:
            if any(value is raw for value in client._closers):
                ticket.close_active = False; ticket.unknown = True
                self._socket_unknown_v26(); return False
            client._closers.append(raw)
        verified = False
        try:
            owned, descriptor, metadata = False, ticket.descriptor, ticket.metadata
            try:
                # This is cleanup, permitted after association expiry. It
                # authenticates the exact original before its only close.
                actual_descriptor = raw.fileno(); ticket.before_fileno = actual_descriptor
                if type(actual_descriptor) is not int or not 0 <= actual_descriptor <= 0x7fffffff:
                    _fail('io_unknown')
                if descriptor is None and metadata is None:
                    # The exact returned raw may have missed its normal
                    # postcheck. Record cleanup-only identity, never erase the
                    # late/unknown factory fact or retrofit normal issuance.
                    if type(actual_descriptor) is int and 0 <= actual_descriptor <= 0x7fffffff:
                        descriptor = ticket.cleanup_descriptor = actual_descriptor
                        metadata = ticket.cleanup_metadata = linux.baseline._metadata(self.provider._io.fstat(descriptor))
                elif descriptor == actual_descriptor and metadata is None:
                    metadata = ticket.cleanup_metadata = linux.baseline._metadata(self.provider._io.fstat(descriptor))
                if (type(descriptor) is int and 0 <= descriptor <= 0x7fffffff and actual_descriptor == descriptor and
                        type(metadata) is tuple and linux.stat.S_ISSOCK(metadata[2]) and
                        linux.baseline._metadata(self.provider._io.fstat(descriptor)) == metadata):
                    final_descriptor = raw.fileno(); ticket.final_fileno = final_descriptor
                    owned = type(final_descriptor) is int and final_descriptor == descriptor
                if not owned: ticket.unknown = True
            except BaseException as error:
                ticket.before_close_error = error; ticket.unknown = True
            if not owned:
                # Retain the original/unknown strong reference; never close a
                # changed raw object or a descriptor now owned by somebody else.
                return False
            try:
                ticket.close_called = True
                ticket.close_result = raw.close(); ticket.close_returned = True
            except BaseException as error:
                ticket.close_error, ticket.unknown = error, True
            # This is the original immediate close evidence, not a late receipt.
            try:
                self.provider._io.fstat(descriptor)
            except OSError as error:
                ticket.ebadf_error, ticket.ebadf_errno = error, error.errno
            except BaseException as error:
                ticket.after_close_error, ticket.unknown = error, True
            try:
                value = raw.fileno(); ticket.fileno_closed = type(value) is int and value == -1
            except BaseException as error:
                ticket.fileno_error, ticket.unknown = error, True
        finally:
            with self._actor_lock:
                ticket.close_active = False
                verified = self.closed_socket_ticket_v26(ticket)
                if not verified: ticket.unknown = True
            with client._lock:
                client._pending_close = [value for value in client._pending_close if value is not raw]
                if not verified: client._pending_close.append(raw)
                client._closers = [value for value in client._closers if value is not raw]
            if not verified: self._socket_unknown_v26()
        return verified

    def closure_facts_v26(self, provider):
        """Exact local originals plus every UDP ticket; no caller status booleans."""
        with self._actor_lock:
            client, creation = self._client, provider._dora_v26_creation
            registered = (provider is self.provider and self.store is provider._store and self.lease is provider._lease and
                self._operation is provider._connection and self._registration is provider._dora_v21_registration and
                self._registration is getattr(self._operation, '_dora_v21_registration', None) and
                type(creation) is dict and creation.get('issued') is self and creation.get('returned') is self and
                creation.get('unknown') is False and creation.get('creator') is PrivateClientDora and
                self._registration.get('issuer') is self and self._registration.get('client') is client and
                type(client) is dhcp.DhcpSocketClient and client._owner is self._owner and client._core is self._core and
                client._factory is self._factory_callback_v26 and client._dispose is self._dispose_callback_v26)
            stopped = (registered and self._closed and self._revoked and not self._unknown and
                self._active is None and self._proof_active == 0 and not self._factory_active_v26 and not self._sync_active_v26 and
                (getattr(self, '_l3_ticket_v28', None) is None or
                 not self._l3_ticket_v28['unknown'] and not self._l3_ticket_v28['active']) and
                all(not call['active'] and not call['unknown'] for call in self._proof_calls) and
                client._closing and client._socket is None and client._candidate_socket is None and
                not (client._opening or client._active or client._proofs or client._closers or client._pending_close or
                     client._factory_unknown or client._runner_active or client._ticket is not None))
            facts = [(self._closed, bool(stopped))]
            for ticket in self._socket_tickets_v26:
                facts.append((ticket.close_called, bool(stopped and self.closed_socket_ticket_v26(ticket) and
                    provider._closed_fd(provider._io, ticket.descriptor, ticket))))
            return tuple(facts)

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
            if len(self._proof_calls) >= 26:
                self._revoke('proof_budget', False)
                _fail('proof_budget')  # Before owner wait, fresh readers or any new IO.
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

    def run_sync(self, _checkpoint):
        """Trusted F loop; returns the still-active exact allocation, never run()."""
        if not callable(_checkpoint): _fail('wrong_owner')
        with self._actor_lock:
            if self._sync_ticket_v26 is not None or self._closed or self._revoked: _fail('closed')
            row = {'checkpoint': _checkpoint, 'allocation': None, 'validated': False,
                'cancelled': False, 'returned': False, 'unknown': True}
            self._sync_ticket_v26, self._sync_active_v26 = row, True
        def stopped():
            value = _checkpoint()
            if type(value) is not bool: _fail('wrong_owner')
            return value
        try:
            if stopped():
                row['cancelled'] = True; self.close()
                row['returned'], row['unknown'] = True, False
                return None
            self.open()
            while True:
                if stopped():
                    row['cancelled'] = True; self.close()
                    row['returned'], row['unknown'] = True, False
                    return None
                event = self.poll()
                if event['event'] != 'candidate_received': continue
                value = self.candidate(); row['allocation'] = value  # Before the additional fresh validator.
                if value is None: _fail('allocation_unverified')
                if stopped():
                    row['cancelled'] = True; self.close()
                    row['returned'], row['unknown'] = True, False
                    return None
                if self.validate_live(value) is not True: _fail('allocation_unverified')
                if stopped():
                    row['cancelled'] = True; self.close()
                    row['returned'], row['unknown'] = True, False
                    return None
                with self._scope():
                    if not self._live_current(value): _fail('allocation_unverified')
                row['validated'], row['returned'], row['unknown'] = True, True, False
                return value
        except BaseException as error:
            row['failure'] = ('dora', error.reason) if type(error) is DoraError else linux._diagnostic_error(error)
            self._revoke('io_unknown', True)
            raise
        finally:
            with self._actor_lock: self._sync_active_v26 = False

    def issue_l3_handoff(self, allocation):
        """Actual fresh no-L3 proof precedes a single irreversible L3 handoff."""
        with self._actor_lock:
            if self._l3_ticket_v28 is not None: _fail('already_registered')
            row = {'allocation': allocation, 'token': None, 'unknown': True, 'active': True}
            self._l3_ticket_v28 = row  # Original before validator IO/exception.
        try:
            if type(allocation) is not LiveAllocation or allocation is not self._active_live:
                _fail('allocation_unverified')
            # Call the native implementation, never an instance callback True.
            if PrivateClientDora.validate_live(self, allocation) is not True:
                _fail('allocation_unverified')
            with self._scope():
                if not self._live_current(allocation) or not any(t['value'] is allocation and
                        t['unknown'] is False for t in self._issued): _fail('allocation_unverified')
                token = L3Handoff(self, allocation); row['token'] = token
                if self._now() >= token._until: _fail('deadline')
                row['unknown'] = False
                return token
        except BaseException:
            row['unknown'] = True
            raise
        finally: row['active'] = False

    def bind_l3_owner(self, token, owner):
        import mta_client_dynamic_ip as dynamic
        row = self._l3_ticket_v28
        if (type(token) is not L3Handoff or type(owner) is not dynamic.ClientDynamicIp or
                type(row) is not dict or row['token'] is not token or row['unknown'] or row['active'] or
                token._issuer is not self or self._l3_owner_v28 is not None or
                owner.dora is not self or owner.handoff is not token or
                self.provider._client_ip_owner_v28 is not owner): _fail('wrong_owner')
        self._l3_owner_v28 = owner

    def l3_handoff_current(self, token, owner, current, creating=True):
        """Continuity after L3 journal writes; deliberately no old no-L3 proof.

        Cleanup consumes the original grant and independent recovery scope even
        after cancellation/expiry/UDP closure. It never reissues network authority.
        The IP owner additionally performs real Store/current and nl80211 gates.
        """
        row = self._l3_ticket_v28
        if (type(token) is not L3Handoff or type(row) is not dict or row['token'] is not token or
                row['unknown'] or row['active'] or token._issuer is not self or
                self._l3_owner_v28 is not owner or self.provider._client_ip_owner_v28 is not owner or
                owner.handoff is not token or owner.dora is not self or type(current) is not core.Journal):
            return False
        store, lease, op, old = token._store, token._lease, token._operation, token._record
        if (self.store is not store or self.lease is not lease or self._operation is not op or
                self.provider._store is not store or self.provider._lease is not lease or
                self.provider._connection is not op or store._mutex is not token._mutex or
                store._epoch is not token._store_epoch or store._journal_epoch is not token._journal_epoch or
                lease.locks is not token._locks or store._current_locks is not token._locks or
                lease.locks._device is not token._device or store._marker is not token._marker or
                store._binding is not token._binding or op.handle is not token._controller or
                lease.handles.get('controller') is not token._controller or
                current.identity.key() != old.identity.key() or current.baseline.key() != old.baseline.key() or
                current.deadline != old.deadline or current.issued_at != old.issued_at or
                type(current.session_profile) is not str or current.session_profile != old.session_profile or current.owned is None or
                current.owned.key() != old.owned.key() or current.association is None): return False
        a, b = current.association, old.association
        if (a.binding != b.binding or a.executor.key() != b.executor.key() or a.executor.tasks != b.executor.tasks or
                (a.local_mac, a.bssid, a.frequency, a.observed_digest) !=
                (b.local_mac, b.bssid, b.frequency, b.observed_digest)): return False
        fact = current.client_ip
        if fact is not None and (fact.owned.key() != old.owned.key() or
                fact.local_ip != ip.ipv4_number(token._configuration.local_ip) or
                fact.prefix != token._configuration.prefix or fact.allocation_until != token._until): return False
        if creating:
            value = token._allocation
            return (not self._closed and not self._revoked and not self._unknown and
                not self.provider.cancelled.is_set() and not op.failed and not op.disconnected and
                not op.disconnect_requested and not op.receipt_invalidated and
                current.stage == 'client_init_ready' and current.ready and a.phase == 'confirmed' and
                self._now() < token._until and value is self._active_live and
                value._socket is token._socket and token._socket is self._client._socket and
                value._configuration is token._configuration and token._configuration is self._core.configuration(self._now()) and
                value._ack is token._ack and token._ack['accepted'] and not token._ack['unknown'] and
                token._ack['configuration'] is token._configuration and
                self._client._stage == 'bound' and not self._client._closing and
                self._client._generation == token._generation)
        return current.stage in ('cleanup_intent', 'cleanup_verified', 'reconciled') and a.phase == 'invalidated'

    def close(self):
        with self._actor_lock:
            self._closed, self._revoked, self._active_live = True, True, None
        complete = self._client.close() if self._client is not None else False
        # A wrapper may have received the exact raw socket and then failed its
        # postcheck before the adapter could save _candidate_socket. Keep and
        # close that original once too; an unknown factory remains unknown.
        for ticket in tuple(self._socket_tickets_v26):
            if ticket.factory_returned and ticket.raw is not None and not ticket.close_called:
                complete = self._dispose_socket_v26(ticket.raw) and complete
        with self._actor_lock:
            return (complete and self._active is None and not self._unknown and self._proof_active == 0 and
                not self._factory_active_v26 and not self._sync_active_v26 and
                all(self.closed_socket_ticket_v26(ticket) for ticket in self._socket_tickets_v26))

    cancel = close

    def status(self):
        state = {} if self._client is None else self._client.status()
        with self._actor_lock:
            return {'closed': self._closed, 'resource_pending': bool(self._unknown or self._active is not None or
                self._proof_active or self._factory_active_v26 or self._sync_active_v26 or
                (getattr(self, '_l3_ticket_v28', None) is not None and
                 (self._l3_ticket_v28['unknown'] or self._l3_ticket_v28['active'])) or
                any(not self.closed_socket_ticket_v26(ticket) for ticket in self._socket_tickets_v26) or
                state.get('socket_actor_pending', True)), 'reason': self._reason,
                'proof_calls': len(self._proof_calls), 'live_allocation_issued': bool(self._issued),
                'interface_configured': False, 'endpoint_verified': False,
                'send_available': False, 'receive_available': False, 'production_available': False}
