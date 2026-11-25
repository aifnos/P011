# -*- coding: utf-8 -*-
"""Bounded current GO station observations, not association authorization.

Borrow the owner's *unattached* private command control. Never open, attach,
close, unlink or mutate a network. The owner serializes ALL use of this command
socket and its restore with the same mutex. Its typed readback must additionally
check this exact control, current private WPA process and GO identity. No HTTP
or QML input can provide that callback. Python 3.5, no stdlib json dependency.
"""
import hashlib
import math
import os
import posixpath
import re
import socket
import stat
import threading
import time
from collections import namedtuple

from mta_scoped_sockets import OwnedContext, ScopeProof

MAX_REPLY = 8192
MAX_STATIONS = 32
MAX_LINES = 160
MAX_LINE = 1024
MAX_RAW_BYTES = 600000
MAX_BUDGET = 2.0
PROOF_BUDGET = 0.2
POLL_BUDGET = 0.1
REQUIRED_FLAGS = frozenset(('AUTH', 'ASSOC', 'AUTHORIZED'))
KNOWN_FLAGS = frozenset(('AUTH', 'ASSOC', 'AUTHORIZED', 'SHORT_PREAMBLE',
    'PREAUTH', 'WMM', 'MFP', 'WPS', 'MAYBE_WPS', 'WDS', 'NonERP', 'WPS2',
    'GAS', 'HT', 'VHT', 'HE', 'EHT', '6GHZ', 'VENDOR_VHT', 'SPP-A-MSDU',
    'WNM_SLEEP_MODE'))
_MAC = re.compile(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\Z')
_HASH = re.compile(r'^[0-9a-f]{64}\Z')
_META = frozenset(('aid', 'capability', 'listen_interval', 'supported_rates',
    'timeout_next', 'auth_alg', 'max_idle_period', 'rx_packets', 'tx_packets',
    'rx_bytes', 'tx_bytes', 'inactive_msec', 'signal', 'rx_rate_info', 'tx_rate_info',
    'connected_time', 'ht_caps_info', 'ht_mcs_bitmask', 'rx_vht_mcs_map',
    'tx_vht_mcs_map', 'vht_caps_info', 'last_ack_signal', 'supp_op_classes',
    'min_txpower', 'max_txpower', 'power_capab', 'wpa', 'AKMSuiteSelector',
    'hostapdWPAPTKState', 'hostapdWPAPTKGroupState', 'hostapdMFPR',
    'p2p_dev_capab', 'p2p_group_capab', 'p2p_primary_device_type',
    'p2p_device_name', 'p2p_config_methods'))
_REASONS = frozenset(('invalid_configuration', 'invalid_budget', 'invalid_clock',
    'clock_reversed', 'cancel_check_failed', 'cancelled', 'expired', 'reader_closed',
    'reader_busy', 'channel_tainted', 'owner_lock_failed', 'owner_lock_timeout',
    'owner_release_unknown', 'owner_readback_failed', 'owner_readback_unverified',
    'owner_readback_timeout', 'control_identity_failed', 'control_identity_changed',
    'control_io_failed', 'control_timeout', 'timeout_restore_unknown',
    'queued_or_event_reply', 'reply_truncated', 'reply_unsupported', 'reply_invalid',
    'reply_duplicate', 'station_limit', 'table_changed', 'association_absent',
    'association_ambiguous', 'association_changed', 'observation_not_owned',
    'raw_budget', 'unclassified_failure'))


class AssociationError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in _REASONS else 'unclassified_failure'
        RuntimeError.__init__(self, self.reason)


class StationRecord(namedtuple('StationRecord', 'station_mac device_mac flags')):
    __slots__ = ()
    def __repr__(self):
        return '<private StationRecord>'


class EventHint(namedtuple('EventHint', 'kind station_mac device_mac')):
    __slots__ = ()
    def __repr__(self):
        return '<private EventHint; not current association>'


class AssociationObservation(namedtuple('AssociationObservation',
        'reader context control station_mac device_mac flags started_at observed_at binding_id')):
    __slots__ = ()
    def __repr__(self):
        return '<private AssociationObservation; no future authorization>'


def _number(value, maximum=2 ** 53):
    # Bound integers BEFORE conversion/finite checks (huge ints must not overflow).
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not 0 <= value <= maximum or not math.isfinite(value)):
        raise AssociationError('invalid_budget')
    return float(value)


def _mac(value):
    if type(value) is not str or not _MAC.match(value):
        raise AssociationError('reply_invalid')
    result = bytes(bytearray(int(part, 16) for part in value.split(':')))
    if result == b'\0' * 6 or result[0] & 1:
        raise AssociationError('reply_invalid')
    return result


def _mac_text(value):
    return ':'.join('%02x' % part for part in value)


def parse_station(raw):
    """Parse a current 2.12 STA MIB row. Empty means enumeration end only.

    Standard non-binding MIB metadata is structurally checked/preserved by the
    reader's raw transcript, never used as identity. Unknown non-MIB extensions,
    multi-link/group-client formats and malformed PENDING_POLL flags fail closed.
    """
    if type(raw) is not bytes or len(raw) >= MAX_REPLY:
        raise AssociationError('reply_truncated')
    if not raw:
        return None
    if raw in (b'FAIL\n', b'UNKNOWN COMMAND\n'):
        raise AssociationError('reply_unsupported')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        raise AssociationError('reply_invalid')
    if not text.endswith('\n') or any(ord(c) < 32 and c != '\n' for c in text):
        raise AssociationError('reply_invalid')
    lines = text[:-1].split('\n')
    if not 2 <= len(lines) <= MAX_LINES or any(len(line.encode('utf-8')) > MAX_LINE for line in lines):
        raise AssociationError('reply_invalid')
    station = _mac(lines[0])
    fields = {}
    for line in lines[1:]:
        if '=' not in line:
            raise AssociationError('reply_invalid')
        key, value = line.split('=', 1)
        if not re.match(r'^[A-Za-z][A-Za-z0-9_]{0,79}\Z', key):
            raise AssociationError('reply_invalid')
        if key in fields:
            raise AssociationError('reply_duplicate')
        if key not in _META and key not in ('flags', 'p2p_device_addr') and not re.match(r'^dot(?:11|1x)[A-Za-z0-9_]+\Z', key):
            raise AssociationError('reply_unsupported')
        fields[key] = value
    required = {'flags', 'aid', 'capability', 'listen_interval', 'supported_rates', 'timeout_next'}
    if not required.issubset(fields):
        raise AssociationError('reply_invalid')
    flag_text = fields['flags']
    flags = re.findall(r'\[([A-Za-z0-9_-]+)\]', flag_text)
    if ''.join('[' + f + ']' for f in flags) != flag_text or len(set(flags)) != len(flags) or any(f not in KNOWN_FLAGS for f in flags):
        raise AssociationError('reply_invalid')
    for key, high in (('aid', 2007), ('listen_interval', 65535)):
        if not re.match(r'^(0|[1-9][0-9]{0,4})\Z', fields[key]) or int(fields[key]) > high:
            raise AssociationError('reply_invalid')
    if not re.match(r'^0x[0-9a-f]{1,4}\Z', fields['capability']):
        raise AssociationError('reply_invalid')
    if not re.match(r'^([0-9a-f]{2}( [0-9a-f]{2}){0,31})?\Z', fields['supported_rates']):
        raise AssociationError('reply_invalid')
    if fields['timeout_next'] not in ('NULLFUNC POLL', 'DISASSOC', 'DEAUTH', 'REMOVE', 'DISASSOC_FROM_CLI'):
        raise AssociationError('reply_unsupported')
    device = _mac(fields['p2p_device_addr']) if 'p2p_device_addr' in fields else None
    return StationRecord(station, device, tuple(sorted(flags)))


def parse_event_hint(raw):
    """Pure optional hint; event delivery never satisfies read()/readback()."""
    if type(raw) is not bytes or len(raw) > 256:
        raise AssociationError('reply_invalid')
    try:
        text = raw.decode('ascii', 'strict').rstrip('\n')
    except UnicodeError:
        raise AssociationError('reply_invalid')
    match = re.match(r'^(?:<[0-7]>)?AP-STA-(CONNECTED|DISCONNECTED) ([0-9a-fA-F:]{17})(?: p2p_dev_addr=([0-9a-fA-F:]{17}))?\Z', text)
    if not match:
        raise AssociationError('reply_unsupported')
    return EventHint(match.group(1).lower(), _mac(match.group(2)),
                     _mac(match.group(3)) if match.group(3) else None)


class AssociationReader:
    """Actual fixed queries through a retained borrowed PrivateControl.sock.

    owner_readback(control, context, budget) returns exact current ScopeProof
    for the owned GO, including this control/process binding; it is NOT a bool.
    The same owner mutex must serialize other command use, monitor revocation,
    process shutdown and lease restore. This component does not close the
    borrowed channel even if tainted. The provider must dispose it separately.
    """
    def __init__(self, control, context, ownership_lock, owner_readback,
                 cancelled, clock=None, lstat=None, socket_type=None,
                 owner_uid=None, sleeper=None):
        raw = getattr(control, 'sock', None)
        path = getattr(control, 'path', None)
        if (type(context) is not OwnedContext or context.mode != 'go' or
                type(context.ifname) is not str or
                not re.match(r'^mta[0-9a-f]{8}\Z', context.ifname) or
                not isinstance(path, str) or not path.startswith('/tmp/') or
                posixpath.normpath(path) != path or
                not re.match(r'^cli-[0-9a-f]{8}\Z', posixpath.basename(path)) or
                not callable(owner_readback) or not callable(cancelled) or
                not all(callable(getattr(ownership_lock, k, None)) for k in ('acquire', 'release'))):
            raise AssociationError('invalid_configuration')
        self.control, self.context, self.raw = control, context, raw
        self.path = path
        self.peer = posixpath.join(posixpath.dirname(path), context.ifname)
        self._owner_lock, self._proof, self._cancelled = ownership_lock, owner_readback, cancelled
        self._clock, self._lstat = clock or time.monotonic, lstat or os.lstat
        self._raw_type, self._uid, self._sleep = socket_type or socket.socket, owner_uid or getattr(os, 'geteuid', None), sleeper or time.sleep
        if (not isinstance(self._raw_type, type) or not isinstance(raw, self._raw_type) or
                not all(callable(fn) for fn in (self._uid, self._clock, self._lstat, self._sleep))):
            raise AssociationError('invalid_configuration')
        self._lock = threading.RLock()
        self._closed = self._active = self._tainted = False
        self._restore_ok = self._release_ok = True
        self._reason, self._last, self._identity, self._ready = 'none', None, None, False
        self._raw = []
        self._raw_bytes = 0

    def _now(self):
        try:
            value = _number(self._clock())
        except BaseException:
            raise AssociationError('invalid_clock')
        if self._last is not None and value < self._last:
            raise AssociationError('clock_reversed')
        self._last = value
        return value

    def _check(self, deadline):
        if self._closed:
            raise AssociationError('reader_closed')
        try:
            cancelled = self._cancelled()
        except BaseException:
            raise AssociationError('cancel_check_failed')
        if type(cancelled) is not bool:
            raise AssociationError('cancel_check_failed')
        if cancelled:
            raise AssociationError('cancelled')
        now = self._now()
        if now >= deadline or now >= _number(self.context.deadline):
            raise AssociationError('expired')
        return now

    def _control_identity(self):
        try:
            uid = self._uid()
            parent = self._lstat(posixpath.dirname(self.path))
            local, peer = self._lstat(self.path), self._lstat(self.peer)
            fd = self.raw.fileno()
            if (type(uid) is not int or uid != 0 or type(fd) is not int or fd < 0 or
                    self.control.sock is not self.raw or self.control.path != self.path or
                    self.raw.family != socket.AF_UNIX or self.raw.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM or
                    self.raw.getsockname() != self.path or self.raw.getpeername() != self.peer or
                    not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 or
                    not stat.S_ISSOCK(local.st_mode) or stat.S_IMODE(local.st_mode) != 0o600 or
                    not stat.S_ISSOCK(peer.st_mode) or
                    any(item.st_uid != uid for item in (parent, local, peer)) or
                    any(item.st_nlink != 1 for item in (local, peer))):
                raise AssociationError('control_identity_failed')
            identity = (fd,) + tuple((s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink) for s in (parent, local, peer))
        except AssociationError:
            raise
        except BaseException:
            raise AssociationError('control_identity_failed')
        if self._identity is not None and identity != self._identity:
            raise AssociationError('control_identity_changed')
        self._identity = identity

    def _owner(self, deadline):
        start = self._check(deadline)
        budget = min(PROOF_BUDGET, deadline - start)
        try:
            proof = self._proof(self.control, self.context, budget)
        except BaseException:
            raise AssociationError('owner_readback_failed')
        if self._now() - start > budget:
            raise AssociationError('owner_readback_timeout')
        if (type(proof) is not ScopeProof or proof.context is not self.context or
                proof.receipt_stage != 'confirmed' or
                any(v is not True for v in (proof.receipt_fsynced, proof.persistent_readback_verified,
                    proof.owner_verified, proof.address_verified, proof.route_baseline_verified)) or
                proof.endpoint is not None or
                any(v is not False for v in (proof.client_association_verified, proof.dhcp_verified, proof.peer_verified))):
            raise AssociationError('owner_readback_unverified')
        self._control_identity()
        self._check(deadline)

    def _query(self, command, deadline):
        if command not in ('PING', 'STA-FIRST') and not re.match(r'^STA(?:-NEXT)? [0-9a-f]{2}(:[0-9a-f]{2}){5}\Z', command):
            raise AssociationError('invalid_configuration')
        self._owner(deadline)
        timeout = min(POLL_BUDGET, deadline - self._check(deadline))
        original = None
        changed = False
        sent = False
        try:
            original = self.raw.gettimeout()
            if original is not None:
                _number(original)
            # Reject stale responses/events before sending an unsequenced ctrl request.
            changed = True
            self.raw.settimeout(0.0)
            try:
                self.raw.recvmsg(MAX_REPLY + 1, 0, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            except BlockingIOError:
                pass
            else:
                self._tainted = True
                raise AssociationError('queued_or_event_reply')
            self.raw.settimeout(timeout)
            actual = self.raw.gettimeout()
            if type(actual) not in (int, float) or not math.isfinite(actual) or abs(actual - timeout) > 1e-8:
                raise AssociationError('control_io_failed')
            wire = command.encode('ascii')
            # After invoking send, an exception/short send has an unknown reply outcome.
            sent = True
            if self.raw.send(wire) != len(wire):
                raise AssociationError('control_io_failed')
            raw, ancillary, flags, address = self.raw.recvmsg(MAX_REPLY + 1, 0)
            if type(raw) is not bytes:
                raise AssociationError('reply_invalid')
            if self._raw_bytes + len(raw) > MAX_RAW_BYTES:
                raise AssociationError('raw_budget')
            self._raw.append((command, raw))
            self._raw_bytes += len(raw)
            if ancillary or flags or len(raw) >= MAX_REPLY or address not in (None, '', self.peer):
                raise AssociationError('reply_truncated')
            if raw.startswith(b'<') or raw.startswith(b'IFNAME='):
                raise AssociationError('queued_or_event_reply')
            self._owner(deadline)
            sent = False
            return raw
        except socket.timeout:
            raise AssociationError('control_timeout')
        except AssociationError:
            raise
        except BaseException:
            raise AssociationError('control_io_failed')
        finally:
            if sent:
                self._tainted = True
            if changed:
                try:
                    self.raw.settimeout(original)
                    restored = self.raw.gettimeout()
                    if original is None:
                        ok = restored is None
                    else:
                        ok = type(restored) in (int, float) and math.isfinite(restored) and abs(restored - original) <= 1e-8
                    if not ok:
                        raise AssociationError('timeout_restore_unknown')
                except BaseException:
                    self._restore_ok = False
                    self._tainted = True
                    raise AssociationError('timeout_restore_unknown')

    def _table(self, deadline):
        result = {}
        command = 'STA-FIRST'
        for unused in range(MAX_STATIONS + 1):
            row = parse_station(self._query(command, deadline))
            if row is None:
                return result
            if len(result) == MAX_STATIONS:
                raise AssociationError('station_limit')
            if row.station_mac in result:
                raise AssociationError('reply_duplicate')
            if row.device_mac is not None and any(old.device_mac == row.device_mac for old in result.values()):
                raise AssociationError('association_ambiguous')
            result[row.station_mac] = row
            command = 'STA-NEXT ' + _mac_text(row.station_mac)
        raise AssociationError('station_limit')

    def read(self, device_mac, budget=PROOF_BUDGET):
        """Two whole current tables and final exact STA, no cached/event fallback."""
        target = _mac(device_mac)
        seconds = _number(budget, MAX_BUDGET)
        if seconds <= 0:
            raise AssociationError('invalid_budget')
        with self._lock:
            if self._active:
                raise AssociationError('reader_busy')
            if self._closed:
                raise AssociationError('reader_closed')
            if self._tainted:
                raise AssociationError('channel_tainted')
            self._active = True
            self._ready = False
        acquired = False
        try:
            start = self._now()
            deadline = min(start + seconds, _number(self.context.deadline))
            while not acquired:
                self._check(deadline)
                try:
                    acquired = self._owner_lock.acquire(False)
                except BaseException:
                    self._release_ok = False
                    self._tainted = True
                    raise AssociationError('owner_lock_failed')
                if type(acquired) is not bool:
                    self._release_ok = False
                    self._tainted = True
                    # No ownership was established for a blind unlock.
                    acquired = False
                    raise AssociationError('owner_lock_failed')
                if not acquired:
                    self._sleep(min(.01, deadline - self._check(deadline)))
            if self._query('PING', deadline) != b'PONG\n':
                raise AssociationError('reply_unsupported')
            first, second = self._table(deadline), self._table(deadline)
            if first != second:
                raise AssociationError('table_changed')
            matches = [row for row in second.values() if row.device_mac == target and REQUIRED_FLAGS.issubset(row.flags)]
            if not matches:
                raise AssociationError('association_absent')
            if len(matches) != 1:
                raise AssociationError('association_ambiguous')
            row = matches[0]
            current = parse_station(self._query('STA ' + _mac_text(row.station_mac), deadline))
            if current != row:
                raise AssociationError('association_changed')
            self._owner(deadline)
            end = self._check(deadline)
            binding = hashlib.sha256(repr((self.context, self._identity)).encode('ascii')).hexdigest()
            result = AssociationObservation(self, self.context, self.control, row.station_mac,
                                            target, row.flags, start, end, binding)
            with self._lock:
                self._check(deadline)
                self._ready = True
                self._reason = 'none'
            return result
        except AssociationError as error:
            self._reason = error.reason
            raise
        except BaseException:
            self._reason = 'unclassified_failure'
            raise AssociationError(self._reason)
        finally:
            try:
                if acquired:
                    try:
                        self._owner_lock.release()
                    except BaseException:
                        self._release_ok = False
                        self._tainted = True
                        self._ready = False
                        raise AssociationError('owner_release_unknown')
            finally:
                with self._lock:
                    self._active = False

    def readback(self, observation, budget=PROOF_BUDGET):
        if (type(observation) is not AssociationObservation or observation.reader is not self or
                observation.context is not self.context or observation.control is not self.control):
            raise AssociationError('observation_not_owned')
        fresh = self.read(_mac_text(observation.device_mac), budget)
        if (fresh.station_mac, fresh.device_mac, fresh.flags, fresh.binding_id) != (
                observation.station_mac, observation.device_mac, observation.flags, observation.binding_id):
            raise AssociationError('association_changed')
        return fresh

    def private_raw(self):
        return tuple(self._raw)

    def close(self):
        """Invalidate only. Borrowed socket ownership never transfers here."""
        with self._lock:
            self._closed = True
            self._ready = False
        return not self._active and self._restore_ok and self._release_ok and not self._tainted

    def status(self):
        with self._lock:
            return {'reader_closed': self._closed, 'query_active': self._active,
                    'channel_tainted': self._tainted, 'timeout_restore_verified': self._restore_ok,
                    'owner_release_verified': self._release_ok, 'observation_ready': self._ready,
                    'raw_frames': len(self._raw), 'last_reason': self._reason}
