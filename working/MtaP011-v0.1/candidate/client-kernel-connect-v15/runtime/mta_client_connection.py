"""Private association-only operation over the exact init owner; no L3 API.

The internal caller must bind decrypted P2pInfo to its BLE operation/epoch/task.
key=None is not that authentication. This module never issues DHCP or endpoint
proofs. Originals belong to the existing Provider ledger, not this operation.
"""
import binascii
import re
import socket

import mta_protocol as protocol
import mta_p2p_client_ctrl as ctrl
import mta_p2p_client_init as core
import mta_client_kernel_proof as kernel_proof

REASONS = frozenset(('invalid_info', 'wrong_owner', 'already_attempted', 'cancelled',
    'deadline', 'reacquire_unknown', 'current_changed', 'command_failed', 'event_missing',
    'event_stale', 'event_removed', 'event_unsupported', 'event_invalid', 'status_mismatch',
    'baseline_changed', 'not_connected', 'observation_expired', 'io_error',
    'kernel_unverified', 'kernel_mismatch', 'channel_unverified'))
MAX_EVENTS, MAX_PACKETS = 64, 128


class ConnectionError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in REASONS else 'io_error'
        RuntimeError.__init__(self, self.code)


def _fail(code): raise ConnectionError(code) from None


def _info(value):
    if type(value) is not protocol.P2pInfo or value.key is not None:
        _fail('invalid_info')
    # Revalidate mutable protocol objects; copying fields grants no BLE authority.
    try:
        checked = protocol.P2pInfo(value.ssid, value.psk, value.mac, value.port,
            sender_id=value.id, cat_share=value.cat_share)
        ssid, secret = checked.ssid.encode('utf-8'), checked.psk.encode('ascii')
        if len(secret) == 64:
            credentials = ctrl.ClientCredentials(ssid, raw_psk=binascii.unhexlify(secret))
        else:
            credentials = ctrl.ClientCredentials(ssid, passphrase=secret)
        mac = binascii.unhexlify(checked.mac.replace(':', ''))
        if len(mac) != 6 or not any(mac) or mac[0] & 1 or type(value.port) is not int:
            _fail('invalid_info')
    except (ValueError, TypeError, UnicodeError, AttributeError): _fail('invalid_info')
    return credentials, mac, checked.port


def _event(raw, name):
    if type(raw) is not bytes or not 1 <= len(raw) <= ctrl.MAX_EVENT:
        _fail('event_invalid')
    value = raw[:-1] if raw.endswith(b'\n') else raw
    if not value or any(n < 32 or n > 126 for n in value): _fail('event_invalid')
    if value.startswith(b'IFNAME='):
        field, separator, value = value.partition(b' ')
        if not separator or field[7:] != name: _fail('event_invalid')
    if value.startswith(b'<'):
        if len(value) < 3 or value[2:3] != b'>' or value[1] not in b'012345':
            _fail('event_invalid')
        value = value[3:]
    if value.startswith(b'P2P-GROUP-STARTED '): return 'started', value
    if value.startswith(b'P2P-GROUP-REMOVED '):
        fields = value.split(b' ')
        if len(fields) not in (3, 4) or fields[1:3] != [name, b'client'] or (
                len(fields) == 4 and re.fullmatch(br'reason=[A-Z_]+', fields[3]) is None):
            _fail('event_invalid')
        return 'removed', value
    # Bounded informational messages are retained, never taken as association.
    prefixes = (b'CTRL-EVENT-SCAN-STARTED', b'CTRL-EVENT-SCAN-RESULTS',
        b'CTRL-EVENT-BSS-ADDED ', b'CTRL-EVENT-BSS-REMOVED ',
        b'CTRL-EVENT-CONNECTED ', b'CTRL-EVENT-DISCONNECTED ',
        b'CTRL-EVENT-STATE-CHANGE ', b'CTRL-EVENT-SUBNET-STATUS-UPDATE ')
    if any(value == p or value.startswith(p) for p in prefixes): return 'information', value
    _fail('event_unsupported')


class ConnectionObservation(object):
    """Private current observations, NOT AssociationProof, address or endpoint."""
    __slots__ = ('_operation', '_event', '_statuses', '_snapshots', '_kernels', '_caps', '_observed', '_expires')
    def __init__(self, op, event, statuses, snapshots, kernels, caps, observed):
        self._operation, self._event, self._statuses = op, event, statuses
        self._kernels, self._caps = kernels, caps
        self._snapshots, self._observed, self._expires = snapshots, observed, op.deadline
    def __repr__(self): return '<private CLIENT connection observation>'
    def public_summary(self):
        return {'connection_observed': True, 'peer_mac_hint_matches':
            self._event.private_fields()['go_dev_addr'] == self._operation.peer_mac,
            'dhcp_proof_issued': False, 'ip_verified': False, 'endpoint_verified': False,
            'production_available': False}


class _Connection(object):
    """One operation, one journal handoff, same F/device and original TTL."""
    def __init__(self, provider, lease, info, checkpoint=None, operation_epoch=None):
        if type(operation_epoch) is not int or not 1 <= operation_epoch <= 2**53:
            _fail('wrong_owner')
        self.provider, self.lease, self.info = provider, lease, info
        self._operation_epoch = operation_epoch  # Actual validated private binding field.
        self._cancel_checkpoint = checkpoint  # Exact synchronous F callback, not authority.
        self.credentials, self.peer_mac, self.peer_port = _info(info)
        # Journal decoding intentionally makes value objects, not CREATE owners.
        self.deadline, self.owned, self.handle = lease.record.deadline, provider._owned, lease.handles.get('controller')
        if type(self.owned) is not core.Origin or type(lease.record.owned) is not core.Origin or self.owned.key() != lease.record.owned.key():
            _fail('wrong_owner')
        self.initial_record, self.initial_locks = lease.record, lease.locks
        self.reacquired = self.current = None
        self.reacquire_requested = self.started = self.group_requested = self.attached = False
        self.failed = self.disconnect_requested = self.disconnected = False
        self.reason, self.network_id = 'not_started', None
        self._command, self._command_event = None, False
        self._events, self._packets, self.observations = [], [], []
        self.group = self.result = None
    def __repr__(self): return '<private CLIENT connection operation>'
    def _checkpoint(self):
        # True means cancel; no reader thread and no renewal of the RF deadline.
        try:
            value = self._cancel_checkpoint() if callable(self._cancel_checkpoint) else None
        except BaseException:
            value = None
        if type(value) is not bool or value:
            self.failed, self.reason = True, 'cancelled'
            self.provider.cancelled.set()
            _fail('cancelled')
    def _fresh(self, full=False):
        self._checkpoint()
        self.provider._connection_context(self, self.deadline)
        if self.provider.cancelled.is_set(): _fail('cancelled')
        if full:
            value = self.lease._baseline(self.deadline, self.owned)
            self._checkpoint()
            return value
        self._checkpoint()
    def _exchange(self, wire, event=False):
        self._command, self._command_event = wire, event
        try: return self.provider._connection_exchange(self, wire, self.deadline, event)
        finally: self._command = None
    def _ok(self, wire, event=False):
        if ctrl.parse_ok_reply(self._exchange(wire, event)) is not True: _fail('command_failed')
    def _drain(self, before_group=False, disconnecting=False):
        for unused in range(8):
            raw = self.provider._connection_receive(self, self.deadline, poll=True)
            if raw is None: return
            kind, value = self._note_event(raw)
            if kind == 'started': _fail('event_stale')
            if kind == 'removed' and not disconnecting: _fail('event_removed')
            if self.group is not None and not disconnecting and value.startswith(b'CTRL-EVENT-DISCONNECTED '):
                _fail('event_removed')
        _fail('event_invalid')
    def _note_event(self, raw):
        if len(self._events) >= MAX_EVENTS: _fail('event_invalid')
        self._events.append(raw)  # Retain actual private bytes, never journal/log.
        return _event(raw, self.owned.name.encode('ascii'))
    def run(self):
        with self.lease.store._mutex:
            if self.started: _fail('already_attempted')
            self.started = True
            try:
                self._checkpoint()
                if self.provider.cancelled.is_set(): _fail('cancelled')
                self.lease._budget(self.deadline)
                if (self.lease.sealed or self.lease._restore_held or not self.initial_record.ready or
                        self.initial_record.stage != 'client_init_ready'):
                    _fail('wrong_owner')
                self.reacquire_requested = True
                self.reacquired = self.lease.store.acquire(self.lease.identity, self.deadline, self.initial_locks)
                # Save actual returned ownership before any later operation.
                self.lease.locks = self.reacquired
                if self.reacquired is not self.lease.store._current_locks or self.lease.store.lock_valid(self.reacquired) is not True:
                    _fail('reacquire_unknown')
                self.lease._restore_held = True  # restore must not acquire a second time.
                self._checkpoint()
                self.current = self.lease.store.current(self.reacquired)
                if type(self.current) is not core.Journal or not core._same_journal(self.current, self.initial_record):
                    _fail('current_changed')
                self.lease.record = self.current
                self._fresh(True)
                self.provider._connection_open(self, self.deadline, event=True)
                self._ok(b'ATTACH', True); self.attached = True
                self._drain(True)
                self.network_id = ctrl.parse_add_network_reply(self._exchange(ctrl.add_network_command().private_bytes()))
                for command in ctrl.network_commands(self.network_id, self.credentials):
                    self._ok(command.private_bytes())
                self._fresh(True)
                self.group_requested = True
                self._ok(ctrl.group_add_command(self.network_id).private_bytes())
                for unused in range(MAX_EVENTS):
                    self._fresh()
                    try: raw = self.provider._connection_receive(self, self.deadline)
                    except socket.timeout: continue
                    kind, value = self._note_event(raw)
                    if kind == 'removed': _fail('event_removed')
                    if kind == 'started':
                        self.group = ctrl.parse_group_started(raw, self.owned.name.encode('ascii'), self.credentials)
                        if self.group.public_summary()['optional_ip_reported']: _fail('status_mismatch')
                        break
                if self.group is None: _fail('event_missing')
                self.result = self._observe_connection()
                self.reason = 'connection_observed'; return self.result
            except BaseException as error:
                self.failed = True
                self.reason = error.code if type(error) is ConnectionError else 'io_error'
                raise
    def _status(self):
        report = ctrl.parse_status(self._exchange(ctrl.status_command().private_bytes()), self.credentials)
        fields = report.private_fields()
        if report.public_summary()['optional_ip_reported'] or fields.get('id') != self.network_id:
            _fail('status_mismatch')
        return report
    def _observe_connection(self):
        self._drain()
        first = self._status(); snap1 = self._fresh(True)
        kernel1 = self.provider._connection_kernel(self, self.deadline)
        caps1 = self.provider._connection_caps(self, snap1, kernel1, self.deadline)
        self._drain()
        second = self._status(); snap2 = self._fresh(True)
        kernel2 = self.provider._connection_kernel(self, self.deadline)
        caps2 = self.provider._connection_caps(self, snap2, kernel2, self.deadline)
        self._drain()
        event = self.group.private_fields()
        one, two = first.private_fields(), second.private_fields()
        if (not first.public_summary()['ctrl_completed'] or not second.public_summary()['ctrl_completed'] or
                one != two or one.get('freq') != event['frequency'] or
                snap1.key(self.owned) != snap2.key(self.owned)):
            _fail('status_mismatch')
        one_kernel = self._kernel_fields(kernel1, one, event)
        two_kernel = self._kernel_fields(kernel2, two, event)
        if one_kernel != two_kernel or caps1 != caps2: _fail('kernel_mismatch')
        self._fresh()
        observation = ConnectionObservation(self, self.group, (first, second), (snap1, snap2),
            (kernel1, kernel2), (caps1, caps2), self.lease._now())
        self.observations.append(observation); return observation
    def _kernel_fields(self, value, status, event):
        if type(value) is not kernel_proof.KernelObservation: _fail('kernel_unverified')
        fields = value.private_fields()
        origin, actor = fields['origin'], fields['executor']
        if (type(origin) is not core.Origin or origin.key() != self.owned.key() or
                type(actor) is not core.Actor or not actor.live() or actor.key() != self.provider._self.key() or
                fields['boot'] != self.provider._boot or fields['channel'] != (8, status.get('freq')) or
                fields['channel'][1] != event['frequency']): _fail('kernel_mismatch')
        rows = fields['stations']
        if (type(rows) is not tuple or len(rows) != 1 or rows[0][0] != status.get('bssid') or
                rows[0][4] != ('TRUE', 'TRUE', 'TRUE')): _fail('kernel_unverified')
        return origin.key(), actor.key(), fields['boot'], fields['channel'], rows
    def readback(self, observation):
        with self.lease.store._mutex:
            if observation is not self.result or not any(r is observation for r in self.observations) or self.failed or self.disconnected:
                _fail('not_connected')
            try:
                result = self._observe_connection(); self.result = result; return result
            except BaseException:
                self.failed = True; raise
    def disconnect(self):
        with self.lease.store._mutex:
            if self.failed or self.result is None or self.disconnect_requested: _fail('not_connected')
            self.disconnect_requested = True
            try:
                self._fresh(); self._ok(b'DISCONNECT')
                report = ctrl.parse_status(self._exchange(b'STATUS'), self.credentials)
                if report.private_fields()['state'] not in (b'DISCONNECTED', b'INACTIVE') or report.public_summary()['optional_ip_reported']:
                    _fail('status_mismatch')
                self._drain(disconnecting=True); self._fresh(True)
                self.disconnected = True
                return {'disconnect_observed': True, 'restored': False, 'production_available': False}
            except BaseException:
                self.failed = True; raise
    def status(self):
        return {'attempted': self.started, 'reacquire_requested': self.reacquire_requested,
            'restore_holds_journal': self.lease._restore_held, 'attached_observed': self.attached,
            'group_requested': self.group_requested, 'last_connection_observed': self.result is not None,
            'disconnect_requested': self.disconnect_requested, 'disconnect_observed': self.disconnected,
            'failed': self.failed, 'reason': self.reason, 'dhcp_proof_issued': False,
            'ip_verified': False, 'endpoint_verified': False, 'production_available': False}
