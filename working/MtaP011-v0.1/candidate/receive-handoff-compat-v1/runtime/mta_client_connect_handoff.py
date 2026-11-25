"""Internal receive GATT -> exact worker -> one CONNECT handoff.

No radio, process, pipe, file or restore operations. This is not an HTTP API.
The caller must be the existing State/native-helper/TransferSession path. Python
objects are not a security boundary against arbitrary code in this process.
MTA AES-CTR has no authentication tag; source binding must not be described as
cryptographic sender authentication or as an application endpoint proof.
The formal once-owned State grants only already claimed Handoff DATA checks.
The old public receive_available boolean is not authority. Constructor tickets
are retained by State before initialization; a partial object is never reusable.
"""
import base64
import math
import os
import threading
import time

import mta_crypto as crypto
import mta_protocol as protocol
import mta_transfer_session as sessions

MAX_ENCRYPTED_BYTES = 2048
_FIELDS = frozenset(('ssid', 'psk', 'mac', 'port', 'key', 'id', 'catShare'))
_CODES = frozenset(('invalid_owner', 'invalid_budget', 'wrong_thread', 'cancelled',
    'expired', 'invalid_event', 'already_received', 'not_received',
    'decrypt_failed', 'already_claimed', 'invalid_binding', 'frame_failed'))


class HandoffError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'invalid_owner'
        RuntimeError.__init__(self, self.code)


def _fail(code):
    raise HandoffError(code) from None


class ReceiveConnectHandoff(object):
    """A private owner retained on Operation before helper callbacks can act.

    Construct in the actual session worker after key/helper creation; capture
    only in the actual helper reader, decrypt and claim only in that worker.
    Both entry points recheck the original objects under State.lock. Cancellation
    and any failed decryption are terminal for this handoff, never retried.
    """
    def __init__(self, state, operation, deadline, _clock=None):
        self.state, self.operation = state, operation
        self.clock = time.monotonic if _clock is None else _clock
        self._clock_original = self.clock
        if (type(deadline) not in (int, float) or not 0 <= deadline <= 1e12 or
                not math.isfinite(deadline) or not callable(self.clock)):
            _fail('invalid_budget')
        self.deadline = self._deadline_original = float(deadline)
        self._data_ticket_original = getattr(operation, 'receive_handoff_ticket', None)
        self._data_authorizer_original = getattr(getattr(operation, 'receive_trial', None),
                                                '_state_handoff_data_authorizer', None)
        self.session, self.helper = operation.session, operation.helper
        self.crypto, self.key = operation.crypto, operation.key
        self.epoch = operation.epoch
        self.worker = threading.current_thread()
        self.reader = getattr(self.helper, 'thread', None)
        self.nonce = os.urandom(16).hex()
        self._wire = self._plain = None
        self._session_id = None
        self._received = self._decrypt_attempted = self._claimed = False
        self._failed = self._cancelled = False
        self.binding = None
        self._last = None
        with state.lock:
            if (type(self.session) is not sessions.TransferSession or
                    self.session._worker is not self.worker or
                    type(self.crypto) is not crypto.OpenSslCrypto or
                    type(self.key) is not crypto.KeyPair or
                    type(self.reader) is not threading.Thread):
                _fail('invalid_owner')
            self._check()
            remaining = self.deadline - self._last
            if not 0 < remaining <= 300:
                _fail('invalid_budget')

    def __repr__(self):
        return '<private receive CONNECT handoff>'

    def _forget(self):
        # Drop references, not a promise of erasing immutable Python copies.
        self._wire = self._plain = None

    def _check(self, role='worker'):
        op, state = self.operation, self.state
        if self._failed:
            _fail('invalid_owner')
        if (self._cancelled or op.cancelled.is_set() or self.session.cancelled.is_set()):
            self._cancelled = True
            self._forget()
            _fail('cancelled')
        if self.clock is not self._clock_original or self.deadline is not self._deadline_original:
            self._failed = True
            self._forget()
            _fail('invalid_owner')
        now = self._clock_original()
        if (type(now) not in (int, float) or not 0 <= now <= 1e12 or
                not math.isfinite(now) or now >= self.deadline or
                self._last is not None and now < self._last):
            self._failed = True
            self._forget()
            _fail('expired')
        self._last = now
        if (state.operation is not op or state.session is not self.session or
                state.worker is not self.worker or op.session is not self.session or
                state.helper is not self.helper or op.helper is not self.helper or
                state.key is not self.key or op.key is not self.key or
                state.crypto is not self.crypto or op.crypto is not self.crypto or
                op.kind != 'receive' or op.consent is not True or state.closing or
                type(self.epoch) is not int or
                not 1 <= self.epoch <= 9007199254740991 or
                type(state.native_epoch) is not int or type(op.epoch) is not int or
                self.epoch != op.epoch or self.epoch != state.native_epoch or
                self.session._worker is not self.worker or
                self.helper.thread is not self.reader or self.helper.closed or
                self.key.closed or self.key._owner is not self.crypto._lib):
            self._failed = True
            self._forget()
            _fail('invalid_owner')
        # Deferred import avoids the State/Handoff boot cycle. Only that actual
        # canonical State method can consume the original claimed Gate; no
        # caller-supplied bool/callback or fake available state substitutes it.
        import mta_service as service
        if (type(state) is not service.State or
                service.ReceiveConnectHandoff is not ReceiveConnectHandoff or
                service.State._receive_handoff_data_allowed is not self._data_authorizer_original or
                service.State._receive_handoff_data_allowed.__globals__ is not service.__dict__ or
                service.State._receive_handoff_data_allowed(state,op,self.session,self,role) is not True):
            self._failed = True
            self._forget()
            _fail('invalid_owner')

    def capture(self, event, helper, native_epoch, operation_epoch):
        """Called from the pinned helper reader, never from a browser or UI."""
        with self.state.lock:
            self._check('capture')
            if threading.current_thread() is not self.reader:
                _fail('wrong_thread')
            if (helper is not self.helper or type(native_epoch) is not int or
                    type(operation_epoch) is not int or
                    native_epoch != self.epoch or operation_epoch != self.epoch):
                _fail('invalid_owner')
            if self._received:
                _fail('already_received')
            if (self.operation.stage != 'advertising' or self.state.discoverable is not True or
                    type(event) is not dict or
                    set(event) != {'event', 'session', 'payload_b64'} or
                    event['event'] != 'p2p' or type(event['session']) is not int or
                    not 1 <= event['session'] <= 4294967295 or
                    type(event['payload_b64']) is not str or
                    not 1 <= len(event['payload_b64']) <= 2732):
                _fail('invalid_event')
            try:
                wire = base64.b64decode(event['payload_b64'].encode('ascii'), validate=True)
                if (not 1 <= len(wire) <= MAX_ENCRYPTED_BYTES or
                        base64.b64encode(wire).decode('ascii') != event['payload_b64']):
                    _fail('invalid_event')
                document = protocol.decode_json(wire, MAX_ENCRYPTED_BYTES)
                if type(document) is not dict:
                    _fail('invalid_event')
                # Unknown extension fields have no semantic or authority role.
                known = {field: document[field] for field in _FIELDS if field in document}
                info = protocol.P2pInfo.from_dict(known)
                if type(info) is not protocol.P2pInfo or not info.key:
                    _fail('invalid_event')
            except (ValueError, TypeError, UnicodeError, RuntimeError):
                _fail('invalid_event')
            self._wire = wire
            self._session_id = event['session']
            self._received = True
            self.state.discoverable = False
            self.operation.stage = 'connecting'
            return True

    def decrypt(self):
        """Return actual crypto output; never accept an externally supplied plain info."""
        with self.state.lock:
            self._check()
            if threading.current_thread() is not self.worker:
                _fail('wrong_thread')
            if not self._received:
                _fail('not_received')
            if self._decrypt_attempted:
                _fail('already_claimed')
            self._decrypt_attempted = True
            wire = self._wire
        try:
            encrypted = protocol.P2pInfo.from_bytes(wire)
            plain = self.crypto.decrypt_credentials(encrypted, self.key)
            if type(plain) is not protocol.P2pInfo or plain.key is not None:
                _fail('decrypt_failed')
            # Revalidate mutable fields and retain an exact private snapshot.
            plain = protocol.P2pInfo.from_bytes(plain.to_bytes())
        except BaseException:
            with self.state.lock:
                self._failed = True
                self._forget()
            _fail('decrypt_failed')
        with self.state.lock:
            self._check()
            self._plain = plain
            self._wire = None
            # No plaintext object leaves this owner before claim_frame.
            return True

    def claim_frame(self, codec, run_token, candidate_sha, operation_id):
        """Codec module is a pinned internal dependency, not a user parameter.

        The actual pipe owner must register binding and send returned bytes with
        a once-only private write; this class does not send or log the frame.
        """
        with self.state.lock:
            self._check()
            if threading.current_thread() is not self.worker:
                _fail('wrong_thread')
            if self._claimed:
                _fail('already_claimed')
            if self._plain is None:
                _fail('not_received')
            self._claimed = True
            try:
                binding = codec.ControlBinding({'version': 1, 'run_token': run_token,
                    'candidate_sha': candidate_sha, 'operation_id': operation_id,
                    'native_epoch': self.epoch, 'operation_epoch': self.epoch,
                    'gatt_session': self._session_id, 'nonce': self.nonce,
                    'receive_consent': True})
                self.binding = binding
                wire = codec.encode_connect(binding, self._plain)
                self._check()
            except BaseException:
                self._failed = True
                self._forget()
                _fail('frame_failed')
            self._forget()
            return wire

    def cancel(self):
        with self.state.lock:
            self._cancelled = True
            self._forget()

    def status(self):
        with self.state.lock:
            return {'received': self._received, 'decrypt_attempted': self._decrypt_attempted,
                'frame_claimed': self._claimed, 'failed': self._failed,
                'cancelled': self._cancelled or self.operation.cancelled.is_set(),
                'connected': False, 'ip_verified': False, 'endpoint_verified': False,
                'production_available': False}
