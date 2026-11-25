# -*- coding: utf-8 -*-
"""Private, bounded scan ownership; no helper commands or platform admission."""
import base64
import math
import re
import threading
import time
from collections import namedtuple
from mta_files import MAX_FILES
from mta_protocol import validate_task_id
from mta_send_worker import ScanHandoff, ScanObservation

_CODES = frozenset(('invalid_input', 'clock_failed', 'scan_not_ready', 'scan_expired',
    'native_event_invalid', 'native_failed', 'scan_stopped', 'peer_expired',
    'unknown_peer', 'intent_already_claimed', 'handoff_changed', 'read_already_noted',
    'readback_budget', 'cancelled'))
_Intent = namedtuple('_Intent', 'handoff file_ids cancelled')


class SendIntent(_Intent):
    __slots__ = ()
    def __repr__(self):
        return '<private scan send intent>'


class ScanHandoffError(RuntimeError):
    def __init__(self, code):
        RuntimeError.__init__(self, code if code in _CODES else 'invalid_input')


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _time(value):
    if type(value) not in (int, float) or not 0 <= value <= 2 ** 53 or not math.isfinite(value):
        raise ScanHandoffError('invalid_input')
    return float(value)


def _b64(value, maximum, text=False):
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ScanHandoffError('native_event_invalid')
    try:
        wire = base64.b64decode(value.encode('ascii'), validate=True)
        if len(wire) > maximum or base64.b64encode(wire).decode('ascii') != value:
            raise ValueError()
        if text:
            wire.decode('utf-8')
    except (ValueError, UnicodeError):
        raise ScanHandoffError('native_event_invalid')


def _discovered(event):
    if (set(event) != {'event', 'peer', 'cached', 'name_b64', 'service_data'} or
        not _integer(event.get('peer'), 1, 65535) or type(event.get('cached')) is not bool or
        type(event.get('service_data')) is not list or len(event['service_data']) > 8):
        raise ScanHandoffError('native_event_invalid')
    _b64(event.get('name_b64'), 128, True)
    for row in event['service_data']:
        if (type(row) is not dict or set(row) != {'uuid', 'payload_b64'} or
            type(row.get('uuid')) is not str or not re.match(
                r'^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z', row['uuid'])):
            raise ScanHandoffError('native_event_invalid')
        _b64(row.get('payload_b64'), 31)


class ScanSession(object):
    """started_at is saved BEFORE the exact helper's actual scan command.

    Only the trusted native reader supplies events. note_client_read records an
    intended command, not a sent command or successful GATT/association proof.
    """
    def __init__(self, helper, native_epoch, operation_epoch, started_at, ttl=30, clock=None, cancelled=None):
        start = _time(started_at)
        if (helper is None or not callable(getattr(helper, 'send', None)) or
            not _integer(native_epoch, 1, 2 ** 53) or not _integer(operation_epoch, 1, 2 ** 53) or
            not _integer(ttl, 1, 60) or start + ttl > 2 ** 53 or
            (clock is not None and not callable(clock)) or
            (cancelled is not None and not isinstance(cancelled, threading.Event))):
            raise ScanHandoffError('invalid_input')
        self._helper, self._native_epoch, self._operation_epoch = helper, native_epoch, operation_epoch
        self._started, self._deadline, self._last = start, start + ttl, start
        self._clock, self._lock = clock if clock is not None else time.monotonic, threading.RLock()
        self._cancelled = cancelled if cancelled is not None else threading.Event()
        self._ready, self._active, self._stopped, self._invalid = False, False, False, False
        self._reason, self._peers, self._intent, self._read_noted = '', {}, None, False
        self._ignored = 0

    def __repr__(self):
        return '<private scan session>'

    def _fail(self, code):
        if not self._invalid:
            self._invalid, self._reason, self._active = True, code, False
        self._cancelled.set()

    def _now(self):
        # Every caller holds this lock: sample and commit in the SAME order.
        if self._cancelled.is_set():
            self._fail('cancelled')
            raise ScanHandoffError(self._reason)
        try:
            now = _time(self._clock())
            if now < self._last:
                raise ValueError()
        except BaseException:
            self._fail('clock_failed')
            raise ScanHandoffError('clock_failed')
        self._last = now
        # A legitimate native handoff resets native scan_deadline to zero.
        # Do not synthesize a later scan expiry after own_session_stopped.
        if not self._stopped and now >= self._deadline:
            self._fail('scan_expired')
        return now

    def native_event(self, event, helper, native_epoch, operation_epoch):
        with self._lock:
            if (helper is not self._helper or type(native_epoch) is not int or
                native_epoch != self._native_epoch or type(operation_epoch) is not int or
                operation_epoch != self._operation_epoch):
                self._ignored += 1
                return False
            try:
                self._now()
            except ScanHandoffError:
                return False
            if self._invalid:
                return False
            try:
                if type(event) is not dict:
                    raise ScanHandoffError('native_event_invalid')
                name = event.get('event')
                if name == 'scan':
                    if set(event) != {'event', 'code'} or type(event.get('code')) is not str:
                        raise ScanHandoffError('native_event_invalid')
                    code = event['code']
                    if code == 'ready' and not self._ready:
                        self._ready, self._active = True, True
                        return True
                    if (code == 'own_session_stopped' and self._active and
                        self._intent is not None and self._read_noted):
                        self._active, self._stopped = False, True
                        return True
                    self._fail('scan_expired' if code == 'lease_expired' else
                               ('scan_stopped' if code == 'own_session_stopped' else 'native_failed'))
                elif name == 'discovered':
                    _discovered(event)
                    if self._ready and self._active and event['cached'] is False:
                        if event['peer'] not in self._peers and len(self._peers) >= 32:
                            raise ScanHandoffError('native_event_invalid')
                        self._peers[event['peer']] = self._last
                        return True
                    self._ignored += 1
                elif name in ('closed', 'error', 'stop', 'cleanup', 'client', 'client_read'):
                    self._fail('native_failed')
                else:
                    self._ignored += 1
            except ScanHandoffError:
                self._fail('native_event_invalid')
            return False

    def _fresh(self, peer, now):
        if self._invalid:
            raise ScanHandoffError(self._reason)
        if not self._ready or not self._active:
            raise ScanHandoffError('scan_not_ready')
        if peer not in self._peers:
            raise ScanHandoffError('unknown_peer')
        if not 0 <= now - self._peers[peer] < 15:
            raise ScanHandoffError('peer_expired')

    def claim_intent(self, device_id, file_ids, task_id):
        with self._lock:
            if self._intent is not None:
                raise ScanHandoffError('intent_already_claimed')
            if (type(device_id) is not str or not re.match(r'^[1-9][0-9]{0,4}\Z', device_id) or
                not _integer(int(device_id), 1, 65535) or type(file_ids) is not list or
                not 1 <= len(file_ids) <= MAX_FILES or
                any(type(value) is not str or not 1 <= len(value) <= 128 for value in file_ids) or
                len(set(file_ids)) != len(file_ids)):
                raise ScanHandoffError('invalid_input')
            try:
                if type(task_id) is not str:
                    raise ValueError()
                validate_task_id(task_id)
            except BaseException:
                raise ScanHandoffError('invalid_input')
            peer, now = int(device_id), self._now()
            self._fresh(peer, now)
            handoff = ScanHandoff(self._helper, self._native_epoch, self._operation_epoch,
                                 peer, self._peers[peer], task_id, self.readback)
            self._intent = SendIntent(handoff, tuple(file_ids), self._cancelled)
            return self._intent

    def note_client_read(self, handoff, command):
        with self._lock:
            if self._intent is None or handoff is not self._intent.handoff:
                raise ScanHandoffError('handoff_changed')
            if (type(command) is not dict or set(command) != {'cmd', 'peer'} or
                command.get('cmd') != 'client_read' or type(command.get('peer')) is not int or
                command['peer'] != handoff.peer):
                raise ScanHandoffError('invalid_input')
            self._fresh(handoff.peer, self._now())
            if self._read_noted:
                raise ScanHandoffError('read_already_noted')
            self._read_noted = True
            return self._intent

    def readback(self, handoff, budget):
        limit = _time(budget)
        if not 0 < limit <= .2 or not self._lock.acquire(timeout=limit):
            raise ScanHandoffError('readback_budget')
        try:
            start = self._now()
            if self._intent is None or handoff is not self._intent.handoff or self._invalid:
                raise ScanHandoffError('handoff_changed')
            seen = self._peers[handoff.peer]
            if not 0 <= start - seen < 15:
                raise ScanHandoffError('peer_expired')
            observed = ScanObservation(self._helper, self._native_epoch, self._operation_epoch,
                                       handoff.peer, seen, False, self._active)
            if self._now() - start > limit:
                raise ScanHandoffError('readback_budget')
            if self._invalid:
                raise ScanHandoffError('handoff_changed')
            return observed
        finally:
            self._lock.release()

    def cancel(self):
        with self._lock:
            self._fail('cancelled')

    def status(self):
        """Passive public projection, never clock/helper callbacks or secrets."""
        with self._lock:
            return {'ready_observed': self._ready, 'native_scan_active': self._active,
                'selectable': self._active and not self._invalid and self._intent is None and not self._cancelled.is_set(),
                'intent_claimed': self._intent is not None,
                'intent_valid': self._intent is not None and not self._invalid and not self._cancelled.is_set(),
                'client_read_noted': self._read_noted, 'scan_handoff_observed': self._stopped,
                'invalidated': self._invalid, 'reason': self._reason,
                'peer_records': len(self._peers), 'ignored_events': self._ignored,
                'cancel_requested': self._cancelled.is_set(),
                'platform_available': False}
