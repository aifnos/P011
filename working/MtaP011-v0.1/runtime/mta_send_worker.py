# -*- coding: utf-8 -*-
"""Private actual send sequencer. No State wiring or platform availability.

The defaults are the real registry/crypto/sender. A missing trusted network
provider rejects before selection, GATT or network actions. HOST injection is
private dependency injection, never an HTTP/QML ready flag. This task runs on
the caller's saved worker; it does not spawn threads or restore inline.
"""
import base64
import math
import re
import threading
import time
from collections import namedtuple

from mta_crypto import OpenSslCrypto
from mta_dhcp_server import DhcpSocketServer
from mta_files import FileRegistry, FileSelection, MAX_FILES, MAX_TOTAL
from mta_protocol import DeviceInfo, P2pInfo, decode_json, validate_task_id
from mta_scoped_sockets import OwnedContext, ScopeProof, ScopedDataSockets, TransportClosedProof
from mta_sender import SenderTransport

ScanHandoff = namedtuple('ScanHandoff',
    'helper native_epoch operation_epoch peer seen_at task_id readback')
ScanObservation = namedtuple('ScanObservation',
    'helper native_epoch operation_epoch peer seen_at cached active')
NetworkReceipt = namedtuple('NetworkReceipt',
    'lease context scoped dhcp ssid psk go_mac')
AssociationReceipt = namedtuple('AssociationReceipt',
    'network handoff device_mac station_mac expires association_id binding_id')
ProviderClosed = namedtuple('ProviderClosed',
    'lease actors_pending resources_pending unknown_pending closed')
SendResult = namedtuple('SendResult',
    'file_count total_bytes archive_bytes_sent local_bytes_verified peer_completion_verified')

_PENDING = ('sockets_pending', 'actors_pending', 'threads_pending', 'wrappers_pending',
            'unknown_wrappers', 'unknown_resources', 'processes_pending')
_KINDS = frozenset(('helper', 'selection', 'crypto', 'key', 'lease', 'activation',
    'scope', 'dhcp', 'transport', 'listener', 'native_read', 'native_write',
    'association', 'network_readback', 'peer_readback', 'sender_start', 'sender_wait'))
_STAGES = frozenset(('new', 'unavailable', 'selecting', 'reading_peer', 'validating_peer',
    'preparing_network', 'preparing', 'waiting', 'publishing', 'awaiting_peer',
    'negotiating', 'accepted', 'awaiting_confirmation', 'transferring', 'awaiting_result', 'protocol_complete',
    'failed', 'cancelled', 'cleanup_pending', 'awaiting_network_restore'))
_CODES = frozenset(('backend_unavailable', 'invalid_private_input', 'owner_hooks_required',
    'already_started', 'scan_handoff_changed', 'scan_handoff_expired', 'cancelled',
    'deadline_expired', 'clock_failed', 'owner_registration_unknown', 'creation_unknown',
    'selection_unknown', 'peer_status_invalid', 'peer_busy_or_unencrypted',
    'native_failed', 'native_timeout', 'native_lease_expired', 'native_queue_overflow',
    'native_event_invalid', 'network_receipt_invalid', 'network_readback_invalid',
    'dhcp_not_listening', 'transport_contract_invalid', 'listener_handoff_unknown',
    'listener_port_invalid', 'credential_budget', 'association_invalid',
    'allocation_invalid', 'sender_result_invalid', 'progress_invalid', 'send_failed'))


class SendWorkerError(RuntimeError):
    def __init__(self, code):
        RuntimeError.__init__(self, code if code in _CODES else 'send_failed')


class CreationTicket(object):
    """Exact ticket retained before the call, including unknown/late returns."""
    def __init__(self, worker, kind):
        self.worker = worker
        self.kind = kind
        self.resource = None
        self.claimed = False
        self.resolved = False
        self.unknown = False
        self.unknown_closed = False

    def __repr__(self):
        return '<SendCreationTicket>'


def _number(value, maximum):
    if type(value) not in (int, float) or not 0 <= value <= maximum or not math.isfinite(value):
        raise SendWorkerError('invalid_private_input')
    return float(value)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _hash(value):
    return type(value) is str and re.match(r'^[0-9a-f]{64}\Z', value) is not None


def _ip(value):
    if type(value) is not str or not re.match(r'^\d{1,3}(\.\d{1,3}){3}\Z', value):
        raise SendWorkerError('allocation_invalid')
    parts = value.split('.')
    if any(str(int(part)) != part or not 0 <= int(part) <= 255 for part in parts):
        raise SendWorkerError('allocation_invalid')
    numbers = tuple(int(part) for part in parts)
    if not (numbers[0] == 10 or numbers[0] == 172 and 16 <= numbers[1] <= 31 or
            numbers[0] == 192 and numbers[1] == 168):
        raise SendWorkerError('allocation_invalid')
    return sum(part << (24 - 8 * index) for index, part in enumerate(numbers))


def _full_closed(transport, raw=None):
    try:
        value = transport.lifecycle_status() if raw is None else transport.closure_snapshot(raw)
        good = (type(value) is dict and value.get('closing') is True and
            value.get('close_verified') is True and value.get('cleanup_pending') is False and
            _integer(value.get('socket_records'), 0, 1000000) and
            all(type(value.get(key)) is int and value[key] == 0 for key in _PENDING))
        if raw is not None:
            good = good and value.get('socket_records', 0) >= 1 and all(value.get(key) is True
                for key in ('recognized_raw', 'all_sockets_closed', 'all_actors_exited'))
        return good and transport.closed() is True
    except BaseException:
        return False


class SendWorker(object):
    """run(hooks) is synchronous; native_event is the bounded reader-only input.

    hooks.claim/adopt/attach_transport/handoff must return the SAME ticket, not
    True. The enclosing exact Session retains them before start. Provider.reserve
    returns a pure lease; activate must retain all child actors/intents in that
    lease before acting. Provider methods and readback are private trusted APIs.
    """
    def __init__(self, handoff, registry, file_ids, provider=None,
                 openssl='/usr/bin/openssl', sender_name='P011', cancelled=None,
                 timeout=180, clock=None, crypto_factory=None, transport_factory=None):
        if (type(handoff) is not ScanHandoff or handoff.helper is None or
            not callable(getattr(handoff.helper, 'send', None)) or not callable(handoff.readback) or
            not _integer(handoff.native_epoch, 1, 2 ** 53) or
            not _integer(handoff.operation_epoch, 1, 2 ** 53) or
            not _integer(handoff.peer, 1, 65535) or not isinstance(registry, FileRegistry) or
            type(file_ids) is not list or not 1 <= len(file_ids) <= MAX_FILES or
            any(type(item) is not str or not 1 <= len(item) <= 128 for item in file_ids) or
            len(set(file_ids)) != len(file_ids) or type(sender_name) is not str or
            not sender_name or len(sender_name.encode('utf-8')) > 256):
            raise SendWorkerError('invalid_private_input')
        try:
            validate_task_id(handoff.task_id)
        except BaseException:
            raise SendWorkerError('invalid_private_input')
        _number(handoff.seen_at, 2 ** 53)
        self.timeout = _number(timeout, 300)
        if self.timeout < .2:
            raise SendWorkerError('invalid_private_input')
        if cancelled is not None and not isinstance(cancelled, threading.Event):
            raise SendWorkerError('invalid_private_input')
        self.handoff = handoff
        self.registry = registry
        self.file_ids = tuple(file_ids)
        self.provider = provider
        self.openssl = openssl
        self.sender_name = sender_name
        self.cancelled = cancelled if cancelled is not None else threading.Event()
        self._clock = clock or time.monotonic
        self._crypto_factory = crypto_factory or OpenSslCrypto
        self._transport_factory = transport_factory or SenderTransport
        if not all(callable(item) for item in (self._clock, self._crypto_factory, self._transport_factory)):
            raise SendWorkerError('invalid_private_input')
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._stage = 'new'
        self._reason = ''
        self._tickets = []
        self._unknown = []
        self._hooks = None
        self._started = False
        self._run_thread = None
        self._run_returned = False
        self._deadline = None
        self._last_time = None
        self._native_phase = None
        self._queue = []
        self._native_fault = None
        self._gatt_deadline = None
        self._authorized_until = None
        self._ignored_events = 0
        self._selection_handles = ()
        self.selection = None
        self.crypto = None
        self.key = None
        self._key_close_owner = None
        self._key_close_requested = False
        self._key_close_returned = False
        self._key_close_unknown = False
        self.lease = None
        self.network = None
        self.transport = None
        self._raws = []
        self._result = None
        self._bytes_verified = False
        self._progress = {'bytes': 0, 'archiveSize': 0, 'archiveBytesSent': 0,
                         'fileCount': 0, 'totalSize': 0}
        self._scope_released = False
        self._extra_closed = False
        self._cleanup_running = False

    def __repr__(self):
        return '<SendWorker>'

    def _now(self):
        with self._lock:
            try:
                now = _number(self._clock(), 2 ** 53)
            except BaseException:
                raise SendWorkerError('clock_failed')
            if self._last_time is not None and now < self._last_time:
                raise SendWorkerError('clock_failed')
            self._last_time = now
            return now

    def _check(self, gatt=False):
        if self.cancelled.is_set():
            raise SendWorkerError('cancelled')
        now = self._now()
        if self._deadline is not None and now >= self._deadline:
            raise SendWorkerError('deadline_expired')
        if self._native_fault is not None:
            raise SendWorkerError(self._native_fault)
        if gatt and self._gatt_deadline is not None and now >= self._gatt_deadline:
            raise SendWorkerError('native_lease_expired')
        return now

    def _phase(self, name):
        if name not in _STAGES:
            raise SendWorkerError('send_failed')
        with self._lock:
            self._stage = name

    def _claim(self, kind):
        if kind not in _KINDS:
            raise SendWorkerError('invalid_private_input')
        ticket = CreationTicket(self, kind)
        with self._lock:
            if len(self._tickets) >= 32:
                raise SendWorkerError('owner_registration_unknown')
            self._tickets.append(ticket)
        try:
            if self._hooks.claim(ticket) is not ticket:
                raise SendWorkerError('owner_registration_unknown')
            ticket.claimed = True
        except BaseException:
            ticket.unknown = True
            raise SendWorkerError('owner_registration_unknown')
        return ticket

    def _call(self, kind, function, *args):
        self._check()
        ticket = self._claim(kind)
        try:
            value = function(*args)
            ticket.resource = value             # BEFORE hooks or validation.
            if self._hooks.adopt(ticket) is not ticket:
                raise SendWorkerError('owner_registration_unknown')
            return value
        except BaseException:
            ticket.unknown = True
            raise
        finally:
            ticket.resolved = True

    def _retain(self, kind, resource):
        return self._call(kind, lambda: resource)

    def _fresh_scan(self):
        start = self._check()
        try:
            observed = self.handoff.readback(self.handoff, .2)
        except BaseException:
            raise SendWorkerError('scan_handoff_changed')
        end = self._check()
        handoff = self.handoff
        if (end - start > .2 or type(observed) is not ScanObservation or
            observed.helper is not handoff.helper or observed.native_epoch != handoff.native_epoch or
            type(observed.native_epoch) is not int or type(observed.operation_epoch) is not int or
            observed.operation_epoch != handoff.operation_epoch or type(observed.peer) is not int or
            observed.peer != handoff.peer or observed.cached is not False or observed.active is not True):
            raise SendWorkerError('scan_handoff_changed')
        seen = _number(observed.seen_at, 2 ** 53)
        if seen < handoff.seen_at or not 0 <= end - seen < 15:
            raise SendWorkerError('scan_handoff_expired')

    def native_event(self, event, helper, native_epoch, operation_epoch):
        """No IO, crypto, provider, close or observer calls on native reader."""
        with self._condition:
            if (helper is not self.handoff.helper or type(native_epoch) is not int or
                native_epoch != self.handoff.native_epoch or type(operation_epoch) is not int or
                operation_epoch != self.handoff.operation_epoch or self.cancelled.is_set() or
                self._run_returned):
                self._ignored_events += 1
                return False
            if type(event) is not dict:
                self._native_fault = 'native_event_invalid'
            else:
                name = event.get('event')
                if name in ('closed', 'error', 'stop', 'client'):
                    self._native_fault = 'native_failed'
                elif name == 'client_status' and self._native_phase == 'read':
                    if (set(event) != {'event', 'peer', 'payload_b64'} or
                        type(event.get('peer')) is not int or event['peer'] != self.handoff.peer or
                        type(event.get('payload_b64')) is not str or len(event['payload_b64']) > 684):
                        self._native_fault = 'native_event_invalid'
                    else:
                        self._queue.append(dict(event))
                elif name in ('client_read', 'client_write') and self._native_phase == ('read' if name == 'client_read' else 'write'):
                    if set(event) != {'event', 'code'} or type(event.get('code')) is not str or len(event['code']) > 96:
                        self._native_fault = 'native_event_invalid'
                    else:
                        self._queue.append(dict(event))
                else:
                    self._ignored_events += 1
                    return False
            if len(self._queue) > 8:
                # Never retain an unbounded private GATT payload collection.
                del self._queue[8:]
                self._native_fault = 'native_queue_overflow'
            self._condition.notify_all()
            return self._native_fault is None

    def _exchange(self, command, phase, seconds):
        with self._condition:
            if self._native_phase is not None or self._queue:
                raise SendWorkerError('native_failed')
            self._native_phase = phase
        try:
            self._call('native_' + phase, self.handoff.helper.send, command)
            stop = min(self._deadline, self._now() + seconds)
            while True:
                now = self._check(gatt=phase == 'write')
                with self._condition:
                    if self._queue:
                        event = self._queue.pop(0)
                        if self._queue:
                            raise SendWorkerError('native_event_invalid')
                        return event
                    if now >= stop:
                        raise SendWorkerError('native_timeout')
                    self._condition.wait(min(.05, stop - now))
        finally:
            with self._condition:
                self._native_phase = None

    def _peer_info(self, event):
        try:
            if event.get('event') != 'client_status':
                raise ValueError()
            text = event['payload_b64']
            wire = base64.b64decode(text.encode('ascii'), validate=True)
            if not 1 <= len(wire) <= 512 or base64.b64encode(wire).decode('ascii') != text:
                raise ValueError()
            value = decode_json(wire, 512)
            if (type(value) is not dict or not {'state', 'mac', 'key'} <= set(value) or
                not set(value) <= {'state', 'mac', 'key', 'catShare'}):
                raise ValueError()
            info = DeviceInfo.from_dict(value)
        except BaseException:
            raise SendWorkerError('peer_status_invalid')
        if info.state != 0 or info.key is None:
            raise SendWorkerError('peer_busy_or_unencrypted')
        return info

    def _network_valid(self, network):
        if (type(network) is not NetworkReceipt or network.lease is not self.lease or
            type(network.context) is not OwnedContext or network.context.mode != 'go' or
            network.context.task_epoch != self.handoff.operation_epoch or
            network.context.native_epoch != self.handoff.native_epoch or
            not isinstance(network.scoped, ScopedDataSockets) or
            network.scoped.context is not network.context or
            not isinstance(network.dhcp, DhcpSocketServer) or
            not self._check() < _number(network.context.deadline, 2 ** 53) <= self._deadline):
            raise SendWorkerError('network_receipt_invalid')
        try:
            P2pInfo(network.ssid, network.psk, network.go_mac, 1)
        except BaseException:
            raise SendWorkerError('network_receipt_invalid')
        start = self._check()
        proof = self._call('network_readback', self.provider.read_network, network, .2)
        if self._check() - start > .2:
            raise SendWorkerError('network_readback_invalid')
        if (type(proof) is not ScopeProof or proof.context is not network.context or
            proof.receipt_stage != 'confirmed' or any(flag is not True for flag in
                (proof.receipt_fsynced, proof.persistent_readback_verified,
                 proof.owner_verified, proof.address_verified, proof.route_baseline_verified)) or
            any(flag is not False for flag in
                (proof.client_association_verified, proof.dhcp_verified, proof.peer_verified)) or
            proof.endpoint is not None):
            raise SendWorkerError('network_readback_invalid')
        dhcp = network.dhcp.status()
        if (type(dhcp) is not dict or dhcp.get('stage') != 'listening' or
            type(dhcp.get('socket_actor_pending')) is not bool or dhcp.get('socket_close_verified') is not False or
            type(dhcp.get('client_limit')) is not int or dhcp['client_limit'] != 1 or
            dhcp.get('default_route_supplied') is not False or dhcp.get('dns_supplied') is not False):
            raise SendWorkerError('dhcp_not_listening')
        # Same exact configured DHCP object, not some other listener on a
        # coincidentally matching subnet. A live receive actor is normal here;
        # its thread/IO ownership must remain in the provider's saved lease.
        if (type(network.dhcp._ifindex) is not int or network.dhcp._ifindex != network.context.ifindex or
            network.dhcp._ifname_text != network.context.ifname or
            network.dhcp._server_ip != network.context.local_ip or
            not self._check() < _number(network.dhcp._deadline, 2 ** 53) <= network.context.deadline):
            raise SendWorkerError('dhcp_not_listening')
        network.scoped.check()

    def _listener(self, host, port):
        self._check(gatt=True)
        ticket = self._claim('listener')
        try:
            raw = self.network.scoped.listener_factory(host, port)
            ticket.resource = raw
            with self._lock:
                self._raws.append(raw)
            if self._hooks.handoff(ticket, self.transport, raw) is not ticket:
                raise SendWorkerError('listener_handoff_unknown')
            self._check(gatt=True)
            return raw
        except BaseException:
            ticket.unknown = True
            raise
        finally:
            ticket.resolved = True

    def _admit(self, info):
        association = self._call('association', self.provider.wait_association,
            self.network, self.handoff, info, self._deadline, self.cancelled.is_set)
        start = self._check()
        fresh = self._call('peer_readback', self.provider.read_association, association, .2)
        now = self._check()
        if (now - start > .2 or type(association) is not AssociationReceipt or
            type(fresh) is not AssociationReceipt or fresh != association or
            fresh.network is not self.network or fresh.handoff is not self.handoff or
            fresh.device_mac != info.mac or not _hash(fresh.association_id) or not _hash(fresh.binding_id) or
            type(fresh.station_mac) is not bytes or len(fresh.station_mac) != 6 or
            fresh.station_mac == b'\0' * 6 or fresh.station_mac[0] & 1 or
            not now < _number(fresh.expires, 2 ** 53) <= self.network.context.deadline):
            raise SendWorkerError('association_invalid')
        allocation = self.network.dhcp.allocation()
        if (type(allocation) is not dict or set(allocation) !=
            {'client_ip', 'mac', 'usable_until', 'ack_transmitted', 'phone_configured'} or
            allocation['ack_transmitted'] is not True or allocation['phone_configured'] is not False or
            type(allocation['mac']) is not bytes or allocation['mac'] != fresh.station_mac or
            not now < _number(allocation['usable_until'], 2 ** 53) <= self.network.context.deadline):
            raise SendWorkerError('allocation_invalid')
        peer = _ip(allocation['client_ip'])
        local = _ip(self.network.context.local_ip)
        mask = (0xffffffff << (32 - self.network.context.prefix)) & 0xffffffff
        if (peer == local or peer & mask != local & mask or
            peer in (local & mask, (local & mask) | (mask ^ 0xffffffff))):
            raise SendWorkerError('allocation_invalid')
        self._network_valid(self.network)
        self._check()
        self._authorized_until = min(fresh.expires, allocation['usable_until'])
        if self.transport.authorize_peer(allocation['client_ip']) is not True:
            raise SendWorkerError('association_invalid')

    def _sender_cancelled(self):
        # Called by the real sender's accept/write/wait checks, not a ready gate.
        # The trusted platform lease additionally revokes the shared Event on
        # actual scope/station loss; its watchdog actors remain lease-owned.
        if self.cancelled.is_set():
            return True
        try:
            now = self._now()
            end = min(self._deadline, self.network.context.deadline)
            if self._authorized_until is not None:
                end = min(end, self._authorized_until)
            if now >= end:
                self.cancelled.set()
                return True
            return False
        except BaseException:
            self.cancelled.set()
            return True

    def _sender_progress(self, stage, details):
        with self._lock:
            if self._run_returned or self._result is not None or self.cancelled.is_set():
                return
            allowed = {'preparing': set(), 'waiting': {'fileCount', 'totalSize'},
                'negotiating': set(), 'accepted': set(),
                'failed': set(), 'cancelled': set(),
                'awaiting_confirmation': set(), 'transferring': {'bytes', 'archiveSize'},
                'awaiting_result': {'archiveBytesSent'}, 'completed': {'fileCount', 'totalSize'}}
            if stage not in allowed or type(details) is not dict or set(details) != allowed[stage]:
                raise SendWorkerError('progress_invalid')
            if any(not _integer(value, 0, MAX_TOTAL) for value in details.values()):
                raise SendWorkerError('progress_invalid')
            if stage == 'transferring':
                if details['bytes'] > details['archiveSize'] or details['bytes'] < self._progress['bytes']:
                    raise SendWorkerError('progress_invalid')
                if self._progress['archiveSize'] and details['archiveSize'] != self._progress['archiveSize']:
                    raise SendWorkerError('progress_invalid')
            if stage == 'awaiting_result' and details['archiveBytesSent'] != self._progress['bytes']:
                raise SendWorkerError('progress_invalid')
            if stage in ('waiting', 'completed') and (details['fileCount'] != len(self._selection_handles) or
                    self.selection is None or details['totalSize'] != self.selection.total_bytes):
                raise SendWorkerError('progress_invalid')
            if stage == 'awaiting_result':
                if not self._progress['archiveSize'] or details['archiveBytesSent'] != self._progress['archiveSize']:
                    raise SendWorkerError('progress_invalid')
                self._bytes_verified = True
            self._progress.update(details)
            # A callback saying completed is not a matching task result/cleanup.
            self._stage = 'awaiting_result' if stage == 'completed' else stage

    def run(self, hooks):
        with self._lock:
            if self._started:
                raise SendWorkerError('already_started')
            self._started = True
            self._run_thread = threading.current_thread()
            self._hooks = hooks
        try:
            if self.provider is None:
                self._phase('unavailable')
                raise SendWorkerError('backend_unavailable')
            if not all(callable(getattr(hooks, name, None)) for name in
                       ('claim', 'adopt', 'attach_transport', 'handoff')):
                raise SendWorkerError('owner_hooks_required')
            if not all(callable(getattr(self.provider, name, None)) for name in
                       ('reserve', 'activate', 'read_network', 'wait_association',
                        'read_association', 'close_extra', 'extra_closed')):
                raise SendWorkerError('backend_unavailable')
            self._deadline = self._now() + self.timeout
            self._check()
            self._fresh_scan()
            self._retain('helper', self.handoff.helper)
            self._phase('selecting')
            self.selection = self._call('selection', self.registry.open_selection, list(self.file_ids))
            if not isinstance(self.selection, FileSelection) or self.selection.closed:
                raise SendWorkerError('selection_unknown')
            self._selection_handles = tuple(entry['handle'] for entry in self.selection.entries)
            if (not self._selection_handles or len(self._selection_handles) != len(self.file_ids) or
                any(not callable(getattr(handle, 'close', None)) for handle in self._selection_handles)):
                raise SendWorkerError('selection_unknown')
            self.crypto = self._call('crypto', self._crypto_factory, self.openssl)
            self.key = self._call('key', self.crypto.generate_keypair)
            self._phase('reading_peer')
            self._fresh_scan()
            event = self._exchange({'cmd': 'client_read', 'peer': self.handoff.peer}, 'read', 15)
            self._gatt_deadline = min(self._deadline, self._now() + 30)
            info = self._peer_info(event)
            self._phase('validating_peer')
            # Actual native P-256/SPKI/point/ECDH validation BEFORE mutation.
            shared = self.crypto.derive_shared(self.key, info.key)
            if type(shared) is not bytes or len(shared) != 32:
                raise SendWorkerError('peer_status_invalid')
            del shared
            self._check(gatt=True)
            self._phase('preparing_network')
            self.lease = self._call('lease', self.provider.reserve,
                                    self.handoff, self._deadline, self.cancelled)
            if self.lease is None:
                raise SendWorkerError('network_receipt_invalid')
            self.network = self._call('activation', self.provider.activate,
                self.lease, self.handoff, info, self._deadline, self.cancelled)
            self._check(gatt=True)
            self._network_valid(self.network)
            self._retain('scope', self.network.scoped)
            self._retain('dhcp', self.network.dhcp)
            remaining = min(self._deadline, self.network.context.deadline) - self._check(gatt=True)
            self.transport = self._call('transport', lambda: self._transport_factory(
                self.network.context.local_ip, 0, self.selection, self.openssl,
                sender_name=self.sender_name, task_id=self.handoff.task_id,
                cancelled=self._sender_cancelled, timeout=remaining,
                state_callback=self._sender_progress, allowed_peer_ip=None,
                listener_factory=self._listener))
            if not all(callable(getattr(self.transport, name, None)) for name in
                       ('start', 'authorize_peer', 'wait', 'cancel', 'close', 'closed',
                        'lifecycle_status', 'closure_snapshot')) or self.transport.allowed_peer_ip is not None:
                raise SendWorkerError('transport_contract_invalid')
            ticket = self._tickets[-1]
            if self._hooks.attach_transport(ticket, self.transport) is not ticket:
                ticket.unknown = True
                raise SendWorkerError('owner_registration_unknown')
            port = self._call('sender_start', self.transport.start)
            if not _integer(port, 1, 65535):
                raise SendWorkerError('listener_port_invalid')
            self._check(gatt=True)
            plain = P2pInfo(self.network.ssid, self.network.psk, self.network.go_mac,
                            port, sender_id=self.handoff.task_id)
            encrypted = self.crypto.encrypt_credentials(plain, self.key, info.key)
            if not isinstance(encrypted, P2pInfo) or encrypted.key != self.key.public_key:
                raise SendWorkerError('credential_budget')
            wire = encrypted.to_bytes()
            if not 1 <= len(wire) <= 2048:
                raise SendWorkerError('credential_budget')
            self._phase('publishing')
            reply = self._exchange({'cmd': 'client_write', 'peer': self.handoff.peer,
                'payload_b64': base64.b64encode(wire).decode('ascii')}, 'write', 10)
            if reply != {'event': 'client_write', 'code': 'accepted_by_bluez_not_file_transfer_complete'}:
                raise SendWorkerError('native_failed')
            self._phase('awaiting_peer')
            self._admit(info)
            self._check()
            result = self._call('sender_wait', self.transport.wait)
            with self._lock:
                if (type(result) is not dict or set(result) !=
                    {'fileCount', 'totalSize', 'archiveBytesSent', 'peer_completion_verified'} or
                    result['peer_completion_verified'] is not True or
                    not _integer(result['fileCount'], 1, MAX_FILES) or
                    result['fileCount'] != len(self._selection_handles) or
                    not _integer(result['totalSize'], 0, MAX_TOTAL) or
                    result['totalSize'] != self.selection.total_bytes or
                    not _integer(result['archiveBytesSent'], 1, MAX_TOTAL) or
                    result['archiveBytesSent'] != self._progress['bytes'] or
                    result['archiveBytesSent'] != self._progress['archiveSize']):
                    raise SendWorkerError('sender_result_invalid')
                # Real sender may finish before its awaiting_result callback.
                # Only the strict final matching result can fill this gap.
                self._bytes_verified = True
                self._progress['archiveBytesSent'] = result['archiveBytesSent']
                self._result = SendResult(result['fileCount'], result['totalSize'],
                    result['archiveBytesSent'], True, True)
                self._stage = 'protocol_complete'
                return self._result
        except BaseException as error:
            code = str(error) if type(error) is SendWorkerError else 'send_failed'
            with self._lock:
                self._reason = code
                if self._stage != 'unavailable':
                    self._stage = 'cancelled' if self.cancelled.is_set() else 'failed'
            raise SendWorkerError(code)
        finally:
            # Request only. No helper/key/lease disposal or network restore here.
            if self.transport is not None:
                try:
                    self.transport.close(timeout=0)
                except BaseException:
                    pass
            with self._condition:
                self._native_phase = None
                self._run_returned = True
                self._condition.notify_all()

    def cancel(self):
        self.cancelled.set()
        with self._condition:
            self._condition.notify_all()

    def private_owner_records(self):
        """Trusted coordinator only; raw resources NEVER go to HTTP/public logs."""
        with self._lock:
            return tuple(self._tickets)

    def _external_ready(self):
        try:
            return (self._run_returned and self._run_thread is not threading.current_thread() and
                    self._run_thread.is_alive() is False and
                    all(ticket.claimed and ticket.resolved for ticket in self._tickets) and
                    not any(ticket.unknown and ticket.kind in ('crypto', 'key', 'lease', 'transport', 'listener')
                            for ticket in self._tickets) and
                    not self._unknown and
                    (self.transport is None or _full_closed(self.transport)))
        except BaseException:
            return False

    def release_scoped(self):
        """External finalizer AFTER actual worker exit + exact transport proof."""
        with self._lock:
            if not self._external_ready() or self._cleanup_running:
                return False
            if self._scope_released:
                return True
            self._cleanup_running = True
        good = True
        try:
            if self.network is not None:
                if type(self.network) is not NetworkReceipt:
                    return False
                for raw in tuple(self._raws):
                    def proof(context, value, budget):
                        if context is not self.network.context or value is not raw or not _full_closed(self.transport, raw):
                            return None
                        return TransportClosedProof(context, raw, True, True)
                    try:
                        good = self.network.scoped.confirm_transport_closed(raw, proof) is True and good
                    except BaseException:
                        good = False
                if good:
                    good = self.network.scoped.close() is True
                status = self.network.scoped.status()
                good = (good and status.get('close_verified') is True and
                    status.get('actors_pending') is False and
                    type(status.get('handoffs_pending')) is int and status['handoffs_pending'] == 0 and
                    type(status.get('pre_handoff_close_pending')) is int and status['pre_handoff_close_pending'] == 0)
            with self._lock:
                self._scope_released = good
            return good
        finally:
            with self._lock:
                self._cleanup_running = False

    def close_extra(self):
        """External finalizer only; independent closes, NO restore method/call.

        False keeps owners/tickets. The enclosing Session must additionally call
        its exact provider/lease restore and read back the actual baseline.
        """
        with self._lock:
            if not self._external_ready() or not self._scope_released or self._cleanup_running:
                return False
            if self._extra_closed:
                return True
            self._cleanup_running = True
        good = True
        try:
            if self.network is not None:
                try:
                    self.network.dhcp.close()
                    status = self.network.dhcp.status()
                    good = status.get('socket_close_verified') is True and status.get('socket_actor_pending') is False
                except BaseException:
                    good = False
            try:
                helper = self.handoff.helper
                good = helper.close() is True and helper.closure_verified() is True and good
            except BaseException:
                good = False
            if self.key is not None:
                good = self._close_key_once() and good
            if self.selection is not None:
                try:
                    # FileSelection is the sole FD/wrapper closer. In particular
                    # selection.closed does NOT mean all original handles closed.
                    if self.selection.lifecycle_status().get('close_requested') is not True:
                        self.selection.close()
                    selection_status = self.selection.lifecycle_status()
                    good = (self._file_closed(selection_status, len(self._selection_handles)) and
                        all(handle.closed is True for handle in self._selection_handles) and good)
                except BaseException:
                    good = False
            provider_good = self.lease is None
            if self.lease is not None:
                try:
                    self.provider.close_extra(self.lease)
                    proof = self.provider.extra_closed(self.lease)
                    provider_good = (type(proof) is ProviderClosed and proof.lease is self.lease and
                        proof.closed is True and all(type(value) is int and value == 0 for value in
                        (proof.actors_pending, proof.resources_pending, proof.unknown_pending)))
                    good = provider_good and good
                except BaseException:
                    good = False
            # Keep failed-call history. Only actual exact owner closure can
            # reconcile a call whose children are owned by that known parent.
            for ticket in self._tickets:
                if not ticket.unknown:
                    continue
                verified = False
                try:
                    if ticket.kind == 'selection':
                        verified = self._file_closed(self.registry.lifecycle_status())
                    elif ticket.kind in ('native_read', 'native_write'):
                        verified = self.handoff.helper.closure_verified() is True
                    elif ticket.kind in ('sender_start', 'sender_wait'):
                        verified = self.transport is not None and _full_closed(self.transport)
                    elif ticket.kind in ('activation', 'network_readback', 'association', 'peer_readback'):
                        verified = provider_good and self.lease is not None
                except BaseException:
                    verified = False
                ticket.unknown_closed = verified
                good = verified and good
            with self._lock:
                self._extra_closed = good
                self._stage = 'awaiting_network_restore' if good and self.lease is not None else 'cleanup_pending'
            return good
        finally:
            with self._lock:
                self._cleanup_running = False

    def _close_key_once(self):
        # KeyPair sets closed before native free. Its flag cannot erase an
        # exception/unknown return from our one exact owned close attempt.
        key = self.key
        if not self._key_close_requested:
            self._key_close_owner = key
            self._key_close_requested = True
            try:
                if key.closed is not False:
                    self._key_close_unknown = True
                else:
                    result = key.close()
                    self._key_close_returned = result is None
                    if result is not None:
                        self._key_close_unknown = True
            except BaseException:
                self._key_close_unknown = True
        try:
            if self._key_close_owner is not key or key.closed is not True:
                self._key_close_unknown = True
        except BaseException:
            self._key_close_unknown = True
        return self._key_close_returned and not self._key_close_unknown

    @staticmethod
    def _file_closed(value, expected_count=None):
        keys = ('resource_count', 'open_attempt_count', 'close_attempted_count',
                'wrapper_closed_count', 'fd_closed_count', 'unknown_count')
        allowed = set(keys + ('resource_pending', 'closure_verified'))
        if expected_count is not None:
            allowed.update(('close_requested', 'selection_closed'))
        if (type(value) is not dict or set(value) != allowed or
            value.get('resource_pending') is not False or value.get('closure_verified') is not True or
            not all(type(value.get(key)) is int and 0 <= value[key] <= MAX_FILES for key in keys) or
            value['unknown_count'] != 0):
            return False
        count = value['resource_count']
        if any(value[key] != count for key in keys[1:5]):
            return False
        return (expected_count is None or (type(expected_count) is int and expected_count == count and
            value.get('close_requested') is True and value.get('selection_closed') is True))

    def status(self):
        """Passive fixed public fields; never call provider, socket or helper."""
        with self._lock:
            result = self._result
            return {'stage': self._stage, 'reason': self._reason,
                'cancel_requested': self.cancelled.is_set(), 'run_returned': self._run_returned,
                'creation_pending': sum(not row.resolved for row in self._tickets),
                'creation_unknown': sum(row.unknown for row in self._tickets),
                'unresolved_unknown': sum(row.unknown and not row.unknown_closed for row in self._tickets),
                'owner_records': len(self._tickets), 'handoff_count': len(self._raws),
                'ignored_native_events': self._ignored_events,
                'scope_released': self._scope_released, 'extra_resources_closed': self._extra_closed,
                'network_restore_required': self.lease is not None,
                'archiveBytesSent': self._progress['archiveBytesSent'],
                'bytes': self._progress['bytes'], 'archiveSize': self._progress['archiveSize'],
                'fileCount': self._progress['fileCount'], 'totalSize': self._progress['totalSize'],
                'localBytesVerified': self._bytes_verified,
                'peerCompletionVerified': bool(result and result.peer_completion_verified),
                'platform_available': False}
