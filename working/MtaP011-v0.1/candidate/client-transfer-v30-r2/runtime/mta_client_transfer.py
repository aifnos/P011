"""Native CLIENT receive composition; no entry point or public availability.

Consumes the actual applied-IP owner and completed native neighbour reader.
The existing MTA ReceiverTransport performs WSS negotiation, HTTPS download,
SafeZipReceiver commit and the actual completion ACK. Everything runs on the
original F thread; this module never spawns a thread or restores the network.

Full native observations are performed before TCP creation and before raw
handoff. Nonblocking connect polls perform only current original/deadline/FD
checks, not a cached ScopeProof presented as a fresh kernel observation. The
reviewed ScopedDataSockets Linux option/source helpers are reused, without
changing its 0.2-second callback contract or creating detached permission facts.
Phone compatibility, F/Parent/Qt consent wiring and P011 performance are untested.
"""
import errno
import select
import socket
import sys
import threading

import mta_ip as ip
import mta_p2p_client_init as core
import mta_client_dora as dora
import mta_client_dynamic_ip as dynamic
import mta_client_peer as peer
import mta_scoped_sockets as scoped
import mta_storage as storage
import mta_transport as transport

MAX_CONNECTIONS = 2  # Actual WSS negotiation and separate HTTPS archive.
FULL_SECONDS = 5.0


class ClientTransferError(RuntimeError):
    def __init__(self, code):
        self.code = code
        RuntimeError.__init__(self, code)


def _fail(code): raise ClientTransferError(code) from None


class ClientTransferOwner(object):
    """Actual synchronous receiver owner; constructor registration precedes IO.

    confirm(request, original_until, cancelled) is trusted F/Parent coordination,
    not automatic consent. Its implementation must poll cancel/original_until;
    returning after the cap cannot authorize download. No UI path/IP/port input
    is accepted here. Only actual native producer objects provide those facts.
    """
    def __init__(self, native_peer, receiver, _executor=None):
        if type(native_peer) is not peer.ClientPeerReader or type(receiver) is not storage.SafeZipReceiver:
            _fail('native_receive_owners_required')
        self.peer, self.ip_owner = native_peer, native_peer.ip_owner
        self.provider, self.lease, self.store = native_peer.provider, native_peer.lease, native_peer.store
        self.operation, self.handoff, self.owned = native_peer.operation, native_peer.handoff, native_peer.owned
        # Deferred: F imports this composition only after its class/module graph
        # exists. No import-time F/MODULES cycle or detached poll callback.
        import mta_client_executor as executor
        if (type(_executor) is not executor.ClientExecutor or type(_executor.assembly) is not tuple or
                len(_executor.assembly) != 5 or _executor.assembly[0] is not self.provider or
                _executor.assembly[1] is not self.store or _executor.assembly[2] is not self.provider._owner or
                _executor.assembly[3] is not self.provider._bridge or _executor.assembly[4] is not self.lease or
                type(_executor.input) is not executor._StdinControl or
                _executor.input.binding is not self.operation.binding or
                getattr(self.operation._cancel_checkpoint, '__self__', None) is not _executor or
                getattr(self.operation._cancel_checkpoint, '__func__', None) is not executor.ClientExecutor._cancelled):
            _fail('native_executor_poll_required')
        self.executor, self.input = _executor, _executor.input
        self._input_decoder, self._input_binding, self._input_io = self.input.decoder, self.input.binding, self.input.io
        self._input_metadata = self.input.metadata
        self._input_codec, self._cancel_checkpoint = self.input.codec, self.operation._cancel_checkpoint
        mapping = native_peer._result
        if (self.provider._client_peer_owner_v29 is not native_peer or
                self.provider._client_ip_owner_v28 is not self.ip_owner or
                type(mapping) is not peer.NeighborRecord or native_peer.unknown or
                native_peer.reason != 'neighbor_mapping_observed' or native_peer._active or
                not all(a and c for a, c in native_peer.closed_facts()) or
                type(self.ip_owner.record) is not dynamic.DynamicIpRecord or self.ip_owner.record.phase != 'applied' or
                self.ip_owner.unknown or self.ip_owner.mutation_unknown or self.ip_owner.cleanup_called or
                self.provider._connection is not self.operation or self.provider._owned is not self.owned):
            _fail('native_peer_not_ready')
        if getattr(self.provider, '_client_transfer_owner_v30', None) is not None: _fail('already_registered')
        self.receiver, self.mapping = receiver, mapping
        self._mapping_key, self._ip_key = mapping.mapping_key(), self.ip_owner.record.key()
        self.host, self.port = ip.ipv4_text(mapping.destination), native_peer._peer_port
        self.local_ip = ip.ipv4_text(self.ip_owner.record.local_ip)
        self.deadline = min(self.operation.deadline, self.handoff._until)
        self._mutex, self._locks, self._worker = self.store._mutex, self.lease.locks, threading.current_thread()
        self._store_epoch, self._journal_epoch = self.store._epoch, self.store._journal_epoch
        self._marker, self._binding, self._device = self.store._marker, self.store._binding, self._locks._device
        self._io, self.clock = self.provider._io, self.lease._now
        self._factory = socket.socket
        self._raw_type = socket.socket
        association = self.ip_owner.dora.context
        # These are primitive-helper arguments derived from actual originals,
        # not public admission objects or a ScopeProof/cached boolean gate.
        self.context = scoped.OwnedContext(association.boot_id, association.task_epoch,
            association.native_epoch, self.owned.phy, self.owned.wdev, self.owned.ifindex,
            self.owned.name, 'client', self.local_ip, self.ip_owner.record.prefix,
            self.deadline, association.receipt_id)
        self._last = self._scope = self.transport = self.result = None
        self._running = self.started = self.close_called = self.observation_unknown = False
        self.reason = 'not_started'
        self.rows, self.full_rows, self.lock_rows, self.failures = [], [], [], []
        self.transport_ticket = {'creator': transport.ReceiverTransport, 'started': False,
            'returned': None, 'complete': False, 'close_called': False, 'close_result': None}
        self.provider._client_transfer_owner_v30 = self

    def _time(self, until=None):
        now = dynamic._number(self.clock())
        if self._last is not None and now < self._last: _fail('clock_regressed')
        self._last = now
        if until is not None and now >= dynamic._number(until): _fail('transfer_deadline')
        return now

    def _originals(self):
        if (threading.current_thread() is not self._worker or self.provider._client_transfer_owner_v30 is not self or
                self.provider._client_peer_owner_v29 is not self.peer or self.provider._client_ip_owner_v28 is not self.ip_owner or
                self.provider._store is not self.store or self.provider._lease is not self.lease or
                self.provider._connection is not self.operation or self.provider._owned is not self.owned or
                self.store._mutex is not self._mutex or self.lease.locks is not self._locks or
                self.store._current_locks is not self._locks or self._locks._device is not self._device or
                self.store._epoch is not self._store_epoch or self.store._journal_epoch is not self._journal_epoch or
                self.store._marker is not self._marker or self.store._binding is not self._binding or
                self.provider._io is not self._io or self.peer.ip_owner is not self.ip_owner or
                self.ip_owner.handoff is not self.handoff or self.handoff._operation is not self.operation or
                self.peer._result is not self.mapping or self.mapping.mapping_key() != self._mapping_key or
                type(self.executor.assembly) is not tuple or len(self.executor.assembly) != 5 or
                self.executor.assembly[0] is not self.provider or self.executor.assembly[1] is not self.store or
                self.executor.assembly[2] is not self.provider._owner or self.executor.assembly[3] is not self.provider._bridge or
                self.executor.assembly[4] is not self.lease or self.executor.input is not self.input or
                self.input.decoder is not self._input_decoder or self.input.binding is not self._input_binding or
                self.input.io is not self._input_io or self.input.metadata != self._input_metadata or
                self.input.codec is not self._input_codec or self.operation._cancel_checkpoint is not self._cancel_checkpoint or
                getattr(self._cancel_checkpoint, '__self__', None) is not self.executor or
                getattr(self._cancel_checkpoint, '__func__', None) is not type(self.executor)._cancelled or
                self.operation.peer_port != self.port or self.peer._peer_port != self.port or
                self.deadline != min(self.operation.deadline, self.handoff._until)):
            _fail('native_transfer_owner_changed')

    def _io_until_for_provider(self, provider, deadline):
        """Pure tightening of the current actual full/dial stage, no renewal."""
        dynamic._number(deadline)
        if provider is not self.provider: _fail('native_transfer_owner_changed')
        self._originals()
        if self._scope is None: return float(deadline)  # Includes close-only recovery.
        start, end, seconds = self._scope
        if (not self._running or type(self._scope) is not tuple or len(self._scope) != 3 or
                seconds not in (FULL_SECONDS, scoped.MAX_CONNECT_SECONDS) or
                end != min(self.deadline, start + seconds) or not start < end <= self.deadline):
            _fail('transfer_scope_changed')
        return min(float(deadline), end)

    def _stage(self, seconds):
        now = self._time(self.deadline)
        self._scope = (now, min(self.deadline, now + seconds), seconds)
        return self._scope[1]

    def _quick(self, until, row=None):
        """No baseline/Proc IO. Only current originals and the live original grant."""
        self._time(until); self._originals()
        current = self.lease.record
        if (type(current) is not core.Journal or current.stage != 'client_init_ready' or not current.ready or
                type(current.client_ip) is not dynamic.DynamicIpRecord or current.client_ip.key() != self._ip_key or
                self.store._canonical is None or self.store._canonical.journal.key() != current.key() or
                not dora.PrivateClientDora.l3_handoff_current(self.ip_owner.dora, self.handoff, self.ip_owner, current, True)):
            _fail('transfer_grant_changed')
        if self.provider.cancelled.is_set(): _fail('cancelled')
        if row is not None:
            raw, fd = row['raw'], row['fd']
            if (raw is None or type(fd) is not int or raw.fileno() != fd or
                    dynamic._metadata(self._io.fstat(fd)) != row['metadata']):
                _fail('tcp_identity_changed')
            scoped.ScopedDataSockets._socket_options(self, raw)
            if row['source'] is not None and scoped.ScopedDataSockets._source(self, raw) != row['source']:
                _fail('tcp_source_changed')
        self._time(until)

    def _neighbor(self, route, until, row):
        collector = peer.NeighborCollector(self.owned.ifindex, route._next(), route.port_id)
        original = {'collector': collector, 'wire': None, 'records': None}
        row['neighbors'].append(original)
        original['wire'] = route._send(collector.request, until)
        while not collector.complete:
            self._quick(until); collector.feed(route._recv(original['wire'], until))
        records = collector.records(); original['records'] = records
        found = tuple(r for r in records if r.destination == self.mapping.destination)
        if len(found) != 1 or found[0].state not in peer._RESOLVED: _fail('peer_neighbor_unavailable')
        return found[0]

    def _full(self):
        until = self._stage(FULL_SECONDS)
        row = {'constructor_started': False, 'transport': None, 'ticket': None, 'opened': False, 'close_called': False,
            'close_returned': False, 'cleanup_until': until + dynamic.IO_SECONDS,
            'current': None, 'association': None, 'snapshot': None, 'neighbors': [], 'success': False}
        self.full_rows.append(row)  # Inventory precedes the native constructor.
        try:
            self._quick(until)
            row['current'] = peer.ClientPeerReader._full_link_gate(self.peer, until)
            bssid = peer.ClientPeerReader._association(self.peer, until); row['association'] = bssid
            row['constructor_started'] = True
            route = dynamic.ClientRouteTransport(self.clock, _io=self._io); row['transport'] = route
            dynamic.ClientRouteTransport.open(route, until); row['ticket'], row['opened'] = route.ticket, True
            row['snapshot'] = route.stable_snapshot(until)
            if dynamic.snapshot_key(row['snapshot']) != dynamic.snapshot_key(row['current'].client_ip.observed):
                _fail('owned_l3_changed')
            a, b = self._neighbor(route, until, row), self._neighbor(route, until, row)
            if a.mapping_key() != b.mapping_key() or b.mapping_key() != self._mapping_key or b.link_layer != bssid:
                _fail('peer_mapping_changed')
            if peer.ClientPeerReader._association(self.peer, until) != bssid: _fail('peer_association_changed')
            after = route.stable_snapshot(until)
            if dynamic.snapshot_key(after) != dynamic.snapshot_key(row['snapshot']): _fail('owned_l3_changed')
            if peer.ClientPeerReader._full_link_gate(self.peer, until).key() != row['current'].key():
                _fail('native_journal_changed')
            self._quick(until); row['success'] = True
        finally:
            route = row['transport']
            if route is not None:
                row['close_called'] = True
                value = dynamic.ClientRouteTransport.close(route, row['cleanup_until'])
                row['close_returned'] = type(value) is bool
            # This independent cap permits only this original descriptor close.
            self._scope = None
        if not self._route_closed(row): _fail('neighbor_resource_pending')

    @staticmethod
    def _route_closed(row):
        route = row['transport']
        if route is None: return not row['constructor_started']  # No call differs from an unknown constructor outcome.
        ticket = route.ticket
        if ticket is None: return row['close_called'] and row['close_returned']
        error = ticket['ebadf']
        return (row['opened'] and ticket is row['ticket'] and not ticket['factory_active'] and
            ticket['factory_returned'] and row['close_called'] and row['close_returned'] and
            ticket['close_called'] and ticket['close_returned'] and ticket['close_result'] is None and
            ticket['close_error'] is None and ticket['fileno_closed'] and
            isinstance(error, OSError) and type(error.errno) is int and error.errno == errno.EBADF)

    def socket_factory(self, host, port, timeout):
        """Actual connected raw TCP for ReceiverTransport only, no fallback."""
        if (not self._running or type(self.transport) is not transport.ReceiverTransport or
                host != self.host or type(port) is not int or port != self.port or
                type(timeout) not in (int, float) or not 0 < timeout <= scoped.MAX_CONNECT_SECONDS or
                len(self.rows) >= MAX_CONNECTIONS): _fail('tcp_request_out_of_scope')
        if not sys.platform.startswith('linux'): _fail('native_linux_required')
        row = {'factory': self._factory, 'factory_started': False, 'factory_returned': False,
            'raw': None, 'fd': None, 'metadata': None, 'source': None, 'returned': False,
            'adopted': False, 'close_called': False, 'close_returned': False,
            'close_result': False, 'ebadf': None, 'fileno_closed': False,
            'close_until': None, 'unknown': False}
        self.rows.append(row)
        try:
            self._full()
            until = self._stage(scoped.MAX_CONNECT_SECONDS)
            # The caller's requested dial budget may only tighten the fixed stage.
            requested_until = min(until, self._scope[0] + float(timeout))
            # Reserve before the native factory: dial, the separate post-connect
            # full observation, then descriptor-only cleanup. Neither failure nor
            # close() may renew this fixed cap or the original network grant.
            row['close_until'] = until + FULL_SECONDS + dynamic.IO_SECONDS
            self._quick(requested_until)
            row['factory_started'] = True
            raw = row['factory'](socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            row['raw'], row['factory_returned'] = raw, True  # Retain a late raw before checking time/type.
            row['fd'] = raw.fileno(); row['metadata'] = dynamic._metadata(self._io.fstat(row['fd']))
            self._quick(requested_until)
            raw.set_inheritable(False)
            raw.setsockopt(socket.SOL_SOCKET, scoped.SO_BINDTODEVICE, self.owned.name.encode('ascii') + b'\0')
            scoped.ScopedDataSockets._socket_options(self, raw)
            scoped.ScopedDataSockets._unconnected(self, raw)
            raw.bind((self.local_ip, 0)); row['source'] = scoped.ScopedDataSockets._source(self, raw)
            if socket.if_nametoindex(self.owned.name) != self.owned.ifindex: _fail('tcp_interface_changed')
            raw.setblocking(False)
            if raw.gettimeout() != 0.0: _fail('tcp_nonblocking_failed')
            self._quick(requested_until, row)
            code = raw.connect_ex((self.host, self.port))
            pending = (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EAGAIN, errno.EINTR)
            if type(code) is not int or code not in (0,) + pending: _fail('tcp_connect_failed')
            while code != 0:
                self._quick(requested_until, row)
                ready = select.select([], [raw], [raw], min(scoped.POLL_SECONDS, requested_until - self._time()))
                self._quick(requested_until, row)
                if (type(ready) is not tuple or len(ready) != 3 or ready[0] or
                        any(v is not raw for group in ready[1:] for v in group)): _fail('tcp_poll_changed')
                if ready[1] or ready[2]:
                    code = raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if type(code) is not int or code != 0: _fail('tcp_connect_failed')
            if raw.getpeername() != (self.host, self.port): _fail('tcp_peer_changed')
            self._quick(requested_until, row)
            self._scope = None
            self._full()  # A separate fixed full stage; never renews the original allocation/session.
            self._quick(self.deadline, row)
            raw.settimeout(min(.5, self.deadline - self._time()))
            row['returned'] = True
            return raw
        except BaseException as failure:
            self.failures.append(failure); self.observation_unknown = row['unknown'] = True
            if not row['returned']: self._dispose(row)
            raise
        finally: self._scope = None

    def transport_handoff(self, actual_transport, raw):
        """Synchronous hook after actual life.adopt_returned, before TLS detach."""
        self._quick(self.deadline)
        rows = tuple(row for row in self.rows if row['raw'] is raw and row['returned'])
        if actual_transport is not self.transport or type(actual_transport) is not transport.ReceiverTransport or len(rows) != 1:
            _fail('foreign_transport_handoff')
        row = rows[0]
        if row['adopted']: _fail('duplicate_transport_handoff')
        life = actual_transport._life
        original = life._record(raw)
        if type(life) is not transport.SocketLifecycle or original is None or original['raw'] is not raw:
            _fail('transport_did_not_adopt_raw')
        row['adopted'] = True
        return raw

    def _cancelled(self):
        if self._time() >= self.deadline or self.provider.cancelled.is_set(): return True
        self._quick(self.deadline)
        import mta_client_executor as executor
        # Both are real nonblocking pipe reads. Neither rereads the Proc tree,
        # grants RF/restore permission or treats cached False as live authority.
        stop = executor._StdinControl.poll(self.input)
        if type(stop) is not bool: _fail('invalid_native_cancel_poll')
        if stop:
            self.executor.cancel_requested = True
            self.provider.cancelled.set()
            return True  # An actual cancellation needs no additional pipe read.
        watchdog = dora.linux.LinuxClientInitProvider.poll_transfer_requests_v30(self.provider, self)
        if type(watchdog) is not bool: _fail('invalid_native_cancel_poll')
        if watchdog:
            self.executor.cancel_requested = True
            if watchdog: self.executor._connect_stop_reason = 'watchdog'
            self.provider.cancelled.set()
            return True
        return self.provider.cancelled.is_set() or self._time() >= self.deadline

    def run(self, confirm, progress=None, file_progress=None):
        if self.started or self.close_called or not callable(confirm): _fail('receive_not_startable')
        self.started = True
        lock = {'returned': None, 'acquired': False, 'release_called': False, 'release_result': False}
        self.lock_rows.append(lock)
        try:
            lock['returned'] = self._mutex.acquire(timeout=min(FULL_SECONDS, self.deadline - self._time(self.deadline)))
            lock['acquired'] = lock['returned'] is True
            if type(lock['returned']) is not bool or not lock['acquired']: _fail('receive_owner_lock_pending')
            self._running = True
            self._quick(self.deadline)
            ticket = self.transport_ticket; ticket['started'] = True
            actual = ticket['creator'](self.host, self.port, self.receiver, self._cancelled,
                socket_factory=self.socket_factory, source_ip=self.local_ip,
                absolute_until=self.deadline, clock=self.clock, handoff=self.transport_handoff)
            ticket['returned'] = actual
            if type(actual) is not transport.ReceiverTransport: _fail('native_receiver_required')
            self.transport = actual; ticket['complete'] = True
            def bounded_confirm(request):
                self._quick(self.deadline)
                answer = confirm(request, self.deadline, self._cancelled)
                self._quick(self.deadline)
                if type(answer) is not bool: _fail('invalid_receive_consent')
                return answer
            self.result = transport.ReceiverTransport.run(actual, bounded_confirm, progress, file_progress)
            self.reason = 'receive_result_returned'
            return self.result
        except BaseException as failure:
            self.failures.append(failure); self.observation_unknown = True
            self.reason = failure.code if type(failure) is ClientTransferError else 'receive_failed'
            raise
        finally:
            self._scope = None
            try:
                if self.transport is not None:
                    self.transport_ticket['close_called'] = True
                    self.transport_ticket['close_result'] = transport.ReceiverTransport.close(self.transport, 0)
            finally:
                self._running = False
                if lock['acquired']:
                    lock['release_called'] = True; lock['release_result'] = self._mutex.release()

    def _dispose(self, row):
        if row['raw'] is None or row['close_called'] or row['returned']: return
        try:
            until = row['close_until']
            self._time(until)
            raw, fd = row['raw'], row['fd']
            if (type(fd) is not int or raw.fileno() != fd or row['metadata'] is None or
                    dynamic._metadata(self._io.fstat(fd)) != row['metadata']): _fail('tcp_close_identity_unknown')
            row['close_called'] = True
            row['close_result'] = raw.close(); row['close_returned'] = True
            try: self._io.fstat(fd)
            except OSError as error: row['ebadf'] = error
            row['fileno_closed'] = raw.fileno() == -1
        except BaseException as failure:
            self.failures.append(failure); row['unknown'] = True

    def _tcp_closed(self, row):
        if not row['factory_started']: return True
        if not row['factory_returned'] or row['raw'] is None: return False
        if row['returned']:
            if type(self.transport) is not transport.ReceiverTransport: return False
            state = transport.ReceiverTransport.closure_snapshot(self.transport, row['raw'])
            return (state.get('recognized_raw') is True and state.get('all_sockets_closed') is True and
                state.get('all_actors_exited') is True and state.get('close_verified') is True)
        error = row['ebadf']
        return (row['close_called'] and row['close_returned'] and row['close_result'] is None and
            row['fileno_closed'] and isinstance(error, OSError) and type(error.errno) is int and error.errno == errno.EBADF)

    def close(self, recovery_until):
        if self._running or self._scope is not None: return False
        if self.close_called: return all(a and c for a, c in self.closed_facts())
        self.close_called = True
        try:
            self._originals()
            now = self._time(); end = dynamic._number(recovery_until)
            if self.store._recovery_deadline != end or not 0 < end - now <= core.CLEANUP_SECONDS:
                _fail('native_restore_scope_required')
            if self.transport is not None:
                self.transport_ticket['close_called'] = True
                self.transport_ticket['close_result'] = transport.ReceiverTransport.close(self.transport, 0)
            for row in self.rows:
                if not row['returned']: self._dispose(row)
        except BaseException as failure: self.failures.append(failure)
        return all(a and c for a, c in self.closed_facts())

    def closed_facts(self):
        locks = all(type(r['returned']) is bool and
            ((r['returned'] is False and not r['acquired']) or
             (r['returned'] is True and r['acquired'] and r['release_called'] and r['release_result'] is None))
            for r in self.lock_rows)
        ticket = self.transport_ticket
        known_transport = (not ticket['started'] or ticket['complete'] and ticket['returned'] is self.transport and
            type(self.transport) is transport.ReceiverTransport and ticket['close_called'] and
            transport.ReceiverTransport.closed(self.transport))
        root_known = (self.provider._client_transfer_owner_v30 is self and self.close_called and
            not self._running and self._scope is None and locks and known_transport)
        return ((self.close_called, bool(root_known)),) + tuple((bool(not r['constructor_started'] or r['close_called']), bool(self._route_closed(r)))
            for r in self.full_rows) + tuple((bool(r['returned'] or r['close_called'] or not r['factory_started']),
                bool(self._tcp_closed(r))) for r in self.rows)

    def status(self):
        return {'started': self.started, 'running': self._running, 'result_available': self.result is not None,
            'resource_pending': not all(a and c for a, c in self.closed_facts()),
            'observation_unknown': self.observation_unknown, 'connections': len(self.rows),
            'native_full_reads': len(self.full_rows), 'reason': self.reason,
            'phone_tested': False, 'send_available': False, 'receive_available': False}
