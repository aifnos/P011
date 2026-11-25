# -*- coding: utf-8 -*-
"""Pure private F control codec; binding shape is NOT BLE/RF authorization.

Canonical ASCII CONNECT, one task-bound RECEIVE decision and CANCEL are understood. The
caller owns stdin and must poll it at connection checkpoints. No raw history,
socket, clock, thread, filesystem or cryptographic key operations occur here.
"""
import hashlib
import math
import re

import p011_json as json
import mta_protocol as protocol

MAX_FRAME = 4096
MAX_INFO = 2048
CANCEL = b'CANCEL\n'
PREFIX = b'CONNECT '
RECEIVE_PREFIX = b'RECEIVE '
RX_PREFIX = b'MTA_CLIENT_RX '
MAX_DECISION = 1024
# One original CONNECT, one decision and one CANCEL; no repeat task allowance.
MAX_TOTAL = MAX_FRAME + MAX_DECISION + len(CANCEL)
MAX_RX_FRAME, MAX_RX_EVENTS = 2048, 48
PRE_PROMPT_TERMINALS = frozenset(('failed', 'cancelled', 'unavailable'))
_HEX32 = re.compile(r'^[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'^[0-9a-f]{64}\Z')
_BINDING_KEYS = frozenset(('version', 'run_token', 'candidate_sha', 'operation_id',
    'native_epoch', 'operation_epoch', 'gatt_session', 'nonce', 'receive_consent'))
_INFO_REQUIRED = frozenset(('ssid', 'psk', 'mac', 'port'))
_INFO_KEYS = _INFO_REQUIRED | frozenset(('id', 'catShare'))
_CODES = frozenset(('invalid_binding', 'invalid_info', 'info_size', 'frame_size',
    'invalid_input', 'invalid_frame', 'noncanonical', 'binding_mismatch',
    'duplicate_nonce', 'connect_already_seen', 'already_claimed', 'stream_limit',
    'input_closed', 'cancelled', 'eof', 'not_recorded', 'receive_not_expected',
    'receive_already_seen', 'receive_already_claimed', 'receive_mismatch'))


class ControlFrameError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'invalid_input'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise ControlFrameError(code) from None


def _uint(value, low, high):
    return type(value) is int and low <= value <= high


def _canonical(value, code):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True).encode('ascii')
    except (ValueError, TypeError, UnicodeError, RuntimeError):
        _fail(code)


def _binding(value):
    if type(value) is not dict or set(value) != _BINDING_KEYS:
        _fail('invalid_binding')
    if (not _uint(value['version'], 1, 1) or
            type(value['run_token']) is not str or _HEX32.match(value['run_token']) is None or
            type(value['candidate_sha']) is not str or _HEX64.match(value['candidate_sha']) is None or
            type(value['nonce']) is not str or _HEX32.match(value['nonce']) is None or
            not _uint(value['native_epoch'], 1, 2 ** 53) or
            not _uint(value['operation_epoch'], 1, 2 ** 53) or
            not _uint(value['gatt_session'], 1, 4294967295) or
            value['receive_consent'] is not True or type(value['operation_id']) is not str):
        _fail('invalid_binding')
    try:
        protocol.validate_task_id(value['operation_id'])
    except (ValueError, TypeError, UnicodeError):
        _fail('invalid_binding')
    return dict(value)


class ControlBinding(object):
    """Exact private metadata, supplied by trusted internal operation handoff.

    operation_id is local and never inferred from P2pInfo.id. run_token, nonce,
    GATT session and other identifiers are private, even though not passwords.
    A canonical digest may be pinned in a future verified deployment manifest.
    """
    __slots__ = ('_values', '_wire', '_digest')

    def __init__(self, value):
        checked = _binding(value)
        object.__setattr__(self, '_values', tuple((key, checked[key]) for key in sorted(checked)))
        wire = _canonical(checked, 'invalid_binding')
        object.__setattr__(self, '_wire', wire)
        object.__setattr__(self, '_digest', hashlib.sha256(wire).hexdigest())

    def __setattr__(self, name, value):
        raise AttributeError('private immutable control binding')

    def __repr__(self):
        return '<private CLIENT control binding>'

    def private_metadata(self):
        return dict(self._values)

    def public_metadata(self):
        return {'version': 1, 'binding_sha256': self._digest}


def _info_dict(value):
    if (type(value) is not dict or not _INFO_REQUIRED.issubset(value) or
            not set(value).issubset(_INFO_KEYS)):
        _fail('invalid_info')
    if len(_canonical(value, 'invalid_info')) > MAX_INFO:
        _fail('info_size')
    if (any(type(value[key]) is not str for key in ('ssid', 'psk', 'mac')) or
            not _uint(value['port'], 1, 65535) or
            'id' in value and type(value['id']) is not str or
            'catShare' in value and not _uint(value['catShare'], 0, 65535)):
        _fail('invalid_info')
    try:
        info = protocol.P2pInfo(value['ssid'], value['psk'], value['mac'], value['port'],
            sender_id=value.get('id'), cat_share=value.get('catShare'))
    except (ValueError, TypeError, UnicodeError, AttributeError):
        _fail('invalid_info')
    result = {'ssid': info.ssid, 'psk': info.psk, 'mac': info.mac, 'port': info.port}
    if info.id is not None:
        result['id'] = info.id
    if info.cat_share is not None:
        result['catShare'] = info.cat_share
    return info, result


def _info_object(info):
    if type(info) is not protocol.P2pInfo or info.key is not None:
        _fail('invalid_info')
    value = {'ssid': info.ssid, 'psk': info.psk, 'mac': info.mac, 'port': info.port}
    if info.id is not None:
        value['id'] = info.id
    if info.cat_share is not None:
        value['catShare'] = info.cat_share
    return _info_dict(value)[1]


def encode_connect(binding, info):
    """Return secret stdin bytes; never log, persist, place in argv or stdout."""
    if type(binding) is not ControlBinding:
        _fail('invalid_binding')
    value = {'binding': binding.private_metadata(), 'p2p': _info_object(info)}
    wire = PREFIX + _canonical(value, 'invalid_frame') + b'\n'
    if len(wire) > MAX_FRAME:
        _fail('frame_size')
    return wire


def _task(value):
    if type(value) is not str: _fail('invalid_input')
    try: protocol.validate_task_id(value)
    except (ValueError, TypeError, UnicodeError): _fail('invalid_input')
    return value


def _display(value):
    # Display only. The original validated request stays in F/Transport.
    if type(value) is not str: _fail('invalid_input')
    return ''.join(c if ord(c) >= 32 and ord(c) != 127 else ' ' for c in value)[:80]


class ReceivePrompt(object):
    """Immutable task facts for local file consent, never RF/socket authority."""
    __slots__ = ('binding', 'prompt_id', 'task_id', 'file_count', 'total_size',
                 'sender_name', 'file_name', 'until', '_wire')

    def __init__(self, binding, value):
        if (type(binding) is not ControlBinding or type(value) is not dict or
                set(value) != {'prompt_id', 'task_id', 'file_count', 'total_size',
                    'sender_name', 'file_name', 'until'} or
                type(value['prompt_id']) is not str or _HEX32.match(value['prompt_id']) is None or
                not _uint(value['file_count'], 1, 256) or
                not _uint(value['total_size'], 0, 512 * 1024 * 1024) or
                any(type(value[k]) is not str or value[k] != _display(value[k])
                    for k in ('sender_name', 'file_name')) or
                type(value['until']) not in (int, float) or not math.isfinite(float(value['until'])) or
                not 0 < value['until'] < 1e12): _fail('invalid_input')
        _task(value['task_id'])
        object.__setattr__(self, 'binding', binding)
        for key in sorted(value): object.__setattr__(self, key, value[key])
        object.__setattr__(self, '_wire', _canonical(value, 'invalid_input'))

    def __setattr__(self, key, value): raise AttributeError('immutable receive prompt')
    def __repr__(self): return '<private CLIENT receive prompt>'
    def private_data(self): return json.loads(self._wire.decode('ascii'))


def encode_receive_decision(binding, prompt, accepted):
    if type(binding) is not ControlBinding or type(prompt) is not ReceivePrompt or \
            prompt.binding is not binding or type(accepted) is not bool: _fail('invalid_input')
    value = {'binding_sha256': binding._digest, 'prompt_id': prompt.prompt_id,
        'task_id': prompt.task_id, 'accepted': accepted}
    wire = RECEIVE_PREFIX + _canonical(value, 'invalid_frame') + b'\n'
    if len(wire) > MAX_DECISION: _fail('frame_size')
    return wire


class ReceiveDecision(object):
    __slots__ = ('_decoder', 'prompt', 'accepted')
    def __init__(self, decoder, accepted):
        object.__setattr__(self, '_decoder', decoder)
        object.__setattr__(self, 'prompt', decoder._receive_prompt)
        object.__setattr__(self, 'accepted', accepted)
    def __setattr__(self, key, value): raise AttributeError('immutable receive decision')
    def __repr__(self): return '<private CLIENT receive decision>'


def _rx_value(binding, sequence, kind, payload):
    if (type(binding) is not ControlBinding or not _uint(sequence, 0, MAX_RX_EVENTS - 1) or
            type(kind) is not str or type(payload) is not dict): _fail('invalid_frame')
    if kind == 'prompt':
        ReceivePrompt(binding, payload)
        if sequence != 0: _fail('invalid_frame')
    elif kind == 'progress':
        if (set(payload) != {'task_id', 'stage', 'count', 'total'} or
                payload['stage'] not in ('download', 'files') or
                not _uint(payload['count'], 0, 513 * 1024 * 1024) or
                not _uint(payload['total'], 0, 513 * 1024 * 1024) or
                payload['stage'] == 'files' and payload['count'] > payload['total']): _fail('invalid_frame')
        _task(payload['task_id'])
    elif kind == 'result':
        if (set(payload) != {'outcome', 'task_id', 'file_count', 'total_size', 'peer_ack_verified'} or
                type(payload['outcome']) is not str or type(payload['task_id']) is not str or
                payload['outcome'] not in ('committed', 'refused', 'confirmation_timeout',
                    'cancelled', 'unavailable', 'failed') or type(payload['peer_ack_verified']) is not bool or
                not _uint(payload['file_count'], 0, 256) or
                not _uint(payload['total_size'], 0, 512 * 1024 * 1024) or
                payload['task_id'] != '' and not _task(payload['task_id']) or
                payload['outcome'] != 'committed' and
                    (payload['file_count'] != 0 or payload['total_size'] != 0 or payload['peer_ack_verified'])):
            _fail('invalid_frame')
        # Empty task is only a first diagnostic terminal before file consent.
        # It cannot manufacture a commit, refusal or confirmation timeout.
        if payload['task_id'] == '' and (sequence != 0 or payload['outcome'] not in PRE_PROMPT_TERMINALS):
            _fail('invalid_frame')
    else: _fail('invalid_frame')
    return {'version': 1, 'binding_sha256': binding._digest, 'sequence': sequence,
        'kind': kind, 'payload': dict(payload)}


def encode_receive_event(binding, sequence, kind, payload):
    wire = RX_PREFIX + _canonical(_rx_value(binding, sequence, kind, payload), 'invalid_frame') + b'\n'
    if len(wire) > MAX_RX_FRAME: _fail('frame_size')
    return wire


def decode_receive_event(binding, wire):
    if type(wire) is not bytes or not wire.startswith(RX_PREFIX) or not wire.endswith(b'\n') or \
            len(wire) > MAX_RX_FRAME: _fail('invalid_frame')
    try: value = json.loads(wire[len(RX_PREFIX):-1].decode('ascii'))
    except (ValueError, TypeError, UnicodeError, RuntimeError): _fail('invalid_frame')
    if type(value) is not dict or set(value) != {'version', 'binding_sha256', 'sequence', 'kind', 'payload'} or \
            type(value['version']) is not int or value['version'] != 1 or value['binding_sha256'] != binding._digest:
        _fail('binding_mismatch')
    checked = _rx_value(binding, value['sequence'], value['kind'], value['payload'])
    if encode_receive_event(binding, value['sequence'], value['kind'], value['payload']) != wire:
        _fail('noncanonical')
    return checked


class ConnectRequest(object):
    """Private parsed request, not an association/IP/endpoint or consent proof."""
    __slots__ = ('_decoder', '_binding', '_info_wire')

    def __init__(self, decoder, info_wire):
        object.__setattr__(self, '_decoder', decoder)
        object.__setattr__(self, '_binding', decoder._binding)
        object.__setattr__(self, '_info_wire', info_wire)

    def __setattr__(self, name, value):
        raise AttributeError('private immutable connect request')

    def __repr__(self):
        return '<private CLIENT CONNECT request>'

    @property
    def binding(self):
        return self._binding

    @property
    def cancelled(self):
        return self._decoder._cancelled

    def private_info(self):
        if self is not self._decoder._claimed_request or self.cancelled:
            _fail('cancelled' if self.cancelled else 'invalid_input')
        # Reconstruct an exact protocol object; caller mutation cannot change
        # the canonical original. This does not authenticate its BLE origin.
        value = json.loads(self._info_wire.decode('ascii'))
        return _info_dict(value)[0]


class ControlFrameDecoder(object):
    """Single caller, bounded streaming parser. feed first, then take_connect.

    Process all currently readable stdin before claiming. CANCEL/EOF in the
    same feed wins over CONNECT; any trailing partial frame defers claiming.
    Caller must continue feeding at each connection cancellation checkpoint.
    """
    def __init__(self, binding):
        if type(binding) is not ControlBinding:
            _fail('invalid_binding')
        self._binding = binding
        self._buffer = b''
        self._total = 0
        self._seen = self._claimed = self._cancelled = self._eof = False
        self._reason = 'not_recorded'
        self._request = self._claimed_request = None
        self._seen_nonce = None
        self._receive_prompt = self._receive_decision = self._claimed_receive_decision = None
        self._receive_seen = self._receive_claimed = False

    def __repr__(self):
        return '<private CLIENT control decoder>'

    def _stop(self, reason):
        self._cancelled = True
        self._buffer = b''
        self._request = None
        self._receive_decision = None
        if self._reason == 'not_recorded':
            self._reason = reason

    def _reject(self, reason):
        self._stop(reason)
        _fail(reason)

    def cancel(self):
        self._stop('cancelled')
        return self.status()

    def _connect(self, line):
        if len(line) + 1 > MAX_FRAME:
            self._reject('frame_size')
        if not line.startswith(PREFIX):
            self._reject('invalid_frame')
        body = line[len(PREFIX):]
        try:
            value = json.loads(body.decode('ascii'))
        except (ValueError, TypeError, UnicodeError, RuntimeError):
            self._reject('invalid_frame')
        if type(value) is not dict or set(value) != {'binding', 'p2p'}:
            self._reject('invalid_frame')
        try:
            metadata = _binding(value['binding'])
            info, canonical_info = _info_dict(value['p2p'])
        except ControlFrameError as error:
            self._reject(error.code)
        if self._seen_nonce == metadata['nonce']:
            self._reject('duplicate_nonce')
        if metadata != self._binding.private_metadata():
            self._reject('binding_mismatch')
        canonical = _canonical({'binding': metadata, 'p2p': canonical_info}, 'invalid_frame')
        if body != canonical:
            self._reject('noncanonical')
        if self._seen:
            self._reject('connect_already_seen')
        info_wire = _canonical(canonical_info, 'invalid_info')
        self._seen, self._seen_nonce = True, metadata['nonce']
        self._request = ConnectRequest(self, info_wire)

    def expect_receive(self, request, until):
        if (self._cancelled or self._buffer or not self._claimed or
                self._claimed_request is None or self._receive_prompt is not None):
            _fail('receive_not_expected')
        try: checked = protocol.validate_send_request(request)
        except (ValueError, TypeError, UnicodeError): _fail('invalid_input')
        if type(request) is not dict or request != checked: _fail('invalid_input')
        prompt_id = hashlib.sha256(self._binding._wire + b'\0' +
            _canonical(checked, 'invalid_input')).hexdigest()[:32]
        self._receive_prompt = ReceivePrompt(self._binding, {'prompt_id': prompt_id,
            'task_id': checked['taskId'], 'file_count': checked['fileCount'],
            'total_size': checked['totalSize'], 'sender_name': _display(checked['senderName']),
            'file_name': _display(checked['fileName']), 'until': until})
        return self._receive_prompt

    def _receive(self, line):
        if len(line) + 1 > MAX_DECISION: self._reject('frame_size')
        if self._receive_prompt is None or not self._claimed: self._reject('receive_not_expected')
        if self._receive_seen: self._reject('receive_already_seen')
        try: value = json.loads(line[len(RECEIVE_PREFIX):].decode('ascii'))
        except (ValueError, TypeError, UnicodeError, RuntimeError): self._reject('invalid_frame')
        prompt = self._receive_prompt
        if (type(value) is not dict or set(value) != {'binding_sha256', 'prompt_id', 'task_id', 'accepted'} or
                type(value['accepted']) is not bool or value['binding_sha256'] != self._binding._digest or
                value['prompt_id'] != prompt.prompt_id or value['task_id'] != prompt.task_id):
            self._reject('receive_mismatch')
        if line + b'\n' != encode_receive_decision(self._binding, prompt, value['accepted']):
            self._reject('noncanonical')
        self._receive_seen = True
        self._receive_decision = ReceiveDecision(self, value['accepted'])

    def feed(self, data, eof=False):
        if type(data) is not bytes or type(eof) is not bool:
            self._reject('invalid_input')
        if len(data) > MAX_FRAME:
            self._reject('frame_size')
        if self._eof:
            if data:
                self._reject('input_closed')
            return self.status()
        if self._cancelled:
            return self.status()
        self._total += len(data)
        if self._total > MAX_TOTAL:
            self._reject('stream_limit')
        if eof:
            self._eof = True
            self._stop('eof')
            return self.status()
        combined = self._buffer + data
        # Recognize only complete line-boundary CANCEL, never a substring in
        # credentials (JSON control characters are escaped in canonical wire).
        lines = combined.split(b'\n')
        if any(line == b'CANCEL' for line in lines[:-1]):
            self._stop('cancelled')
            return self.status()
        self._buffer = lines[-1]
        try:
            for line in lines[:-1]:
                if line.startswith(RECEIVE_PREFIX): self._receive(line)
                else: self._connect(line)
            if len(self._buffer) >= MAX_FRAME:
                self._reject('frame_size')
            if self._buffer and not (CANCEL.startswith(self._buffer) or
                    PREFIX.startswith(self._buffer) or self._buffer.startswith(PREFIX) or
                    RECEIVE_PREFIX.startswith(self._buffer) or self._buffer.startswith(RECEIVE_PREFIX)):
                self._reject('invalid_frame')
        except ControlFrameError:
            self._buffer = b''
            raise
        return self.status()

    def take_connect(self):
        if self._cancelled or self._buffer or self._request is None:
            return None
        if self._claimed:
            _fail('already_claimed')
        self._claimed = True
        self._claimed_request, self._request = self._request, None
        return self._claimed_request

    def take_receive_decision(self):
        if self._cancelled or self._buffer or self._receive_decision is None: return None
        if self._receive_claimed: _fail('receive_already_claimed')
        self._receive_claimed = True
        self._claimed_receive_decision, self._receive_decision = self._receive_decision, None
        return self._claimed_receive_decision

    def status(self):
        return {'connect_seen': self._seen, 'connect_claimed': self._claimed,
            'connect_pending': self._request is not None and not self._cancelled,
            'cancel_requested': self._cancelled, 'eof_observed': self._eof,
            'buffered_bytes': len(self._buffer), 'input_bytes': self._total,
            'reason': self._reason, 'association_verified': False,
            'ip_verified': False, 'endpoint_verified': False, 'production_available': False}
