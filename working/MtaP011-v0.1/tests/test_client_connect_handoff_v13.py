"""New HOST handoff tests: real threads/libcrypto, synthetic State owners.

No native helper, Popen, radio, pipe, P011 or phone operation. No real State or
Session lifecycle is claimed by these manually assembled owner fixtures.
"""
import ast
import base64
import importlib.util
import os
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'candidate/client-connect-v13/runtime'))
import mta_crypto as crypto
import mta_protocol as protocol
import mta_service as service
import mta_transfer_session as sessions
import mta_client_connect_handoff as h


class HandoffTests(unittest.TestCase):
    def setUp(self):
        choices = [os.environ.get('MTA_TEST_OPENSSL'),
            r'C:\Program Files\Git\mingw64\bin\openssl.exe',
            r'C:\Program Files\Git\usr\bin\openssl.exe', '/usr/bin/openssl']
        executable = next((p for p in choices if p and os.path.isfile(p)), None)
        if executable is None:
            self.skipTest('HOST OpenSSL unavailable')
        self.crypto = crypto.OpenSslCrypto(executable)
        self.key = self.crypto.generate_keypair()
        self.sender = self.crypto.generate_keypair()
        self.plain = protocol.P2pInfo('DIRECT-public-fixture', 'fixture-only-psk',
            '02:11:22:33:44:55', 33331, sender_id='not-a-websocket-task')
        self.encrypted = self.crypto.encrypt_credentials(self.plain, self.sender, self.key.public_key)
        self.event = {'event': 'p2p', 'session': 7,
            'payload_b64': base64.b64encode(self.encrypted.to_bytes()).decode('ascii')}
        self.state = types.SimpleNamespace(lock=threading.RLock(), native_epoch=3,
            receive_available=True, closing=False, discoverable=True,
            key=self.key, crypto=self.crypto)
        self.op = service.Operation(object(), 3, 'receive')
        self.session = object.__new__(sessions.TransferSession)
        self.session.cancelled = self.op.cancelled
        self.op.session = self.session
        self.op.key, self.op.crypto = self.key, self.crypto
        self.helper = service.PrivateHelper('/HOST/never-executed', lambda e: None)
        self.op.helper, self.state.helper = self.helper, self.helper
        self.op.stage = 'advertising'
        self.state.operation, self.state.session = self.op, self.session
        self.errors, self.reader_errors, self.result = [], [], None
        self.clock = [10.0]

    def tearDown(self):
        self.key.close()
        self.sender.close()

    def run_owned(self, action, event=None):
        def reader():
            try:
                self.result.capture(self.event if event is None else event, self.helper, 3, 3)
            except BaseException as error:
                self.reader_errors.append(error)
        self.helper.thread = threading.Thread(target=reader)
        def worker():
            try:
                self.result = h.ReceiveConnectHandoff(self.state, self.op, 100,
                    _clock=lambda: self.clock[0])
                self.helper.thread.start()
                self.helper.thread.join(2)
                if self.helper.thread.is_alive():
                    raise AssertionError('HOST reader failed to exit')
                action(self.result)
            except BaseException as error:
                self.errors.append(error)
        thread = threading.Thread(target=worker)
        self.state.worker = self.session._worker = thread
        thread.start(); thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.helper.thread.is_alive())

    def test_exact_native_session_and_real_decryption(self):
        self.run_owned(lambda owner: self.assertTrue(owner.decrypt()))
        self.assertEqual(self.errors + self.reader_errors, [])
        self.assertEqual(self.result._session_id, 7)
        self.assertEqual(self.result._plain.to_dict(), self.plain.to_dict())
        self.assertIsNone(self.result._wire)
        self.assertFalse(self.result.status()['production_available'])

    def test_plaintext_and_extra_native_fields_never_decrypt(self):
        for event in (dict(self.event, payload_b64=base64.b64encode(self.plain.to_bytes()).decode('ascii')),
                dict(self.event, peer='unexpected'), dict(self.event, session=True)):
            with self.subTest(case=set(event)):
                self.state.discoverable = True; self.op.stage = 'advertising'
                self.errors, self.reader_errors = [], []
                self.run_owned(lambda owner: None, event)
                self.assertEqual(self.errors, [])
                self.assertEqual([e.code for e in self.reader_errors], ['invalid_event'])
                self.assertFalse(self.result._decrypt_attempted)

    def test_late_key_or_epoch_change_blocks_real_decrypt(self):
        for change in ('key', 'epoch', 'consent'):
            with self.subTest(change=change):
                self.state.discoverable = True; self.op.stage = 'advertising'
                self.state.native_epoch = self.op.epoch = 3
                self.op.consent = True; self.op.key = self.key
                self.errors, self.reader_errors = [], []
                def action(owner):
                    if change == 'key': self.op.key = self.sender
                    elif change == 'epoch': self.state.native_epoch = 4
                    else: self.op.consent = False
                    owner.decrypt()
                self.run_owned(action)
                self.assertEqual(self.reader_errors, [])
                self.assertEqual([e.code for e in self.errors], ['invalid_owner'])
                self.assertIsNone(self.result._plain)

    def test_cancel_during_actual_crypto_is_rechecked(self):
        decrypt = crypto.OpenSslCrypto.decrypt_credentials
        def cancelling(instance, info, key):
            plain = decrypt(instance, info, key)
            self.op.cancelled.set()
            return plain
        with mock.patch.object(crypto.OpenSslCrypto, 'decrypt_credentials', cancelling):
            self.run_owned(lambda owner: owner.decrypt())
        self.assertEqual([e.code for e in self.errors], ['cancelled'])
        self.assertEqual(self.reader_errors, [])
        self.assertIsNone(self.result._plain)
        self.assertIsNone(self.result._wire)

    def test_failure_is_terminal_and_never_accepts_external_plaintext(self):
        def action(owner):
            with mock.patch.object(crypto.OpenSslCrypto, 'decrypt_credentials',
                    side_effect=RuntimeError('HOST_FIXTURE_PRIVATE_ERROR')):
                with self.assertRaisesRegex(h.HandoffError, '^decrypt_failed$'): owner.decrypt()
            with self.assertRaisesRegex(h.HandoffError, '^invalid_owner$'): owner.decrypt()
        self.run_owned(action)
        self.assertEqual(self.errors + self.reader_errors, [])
        self.assertNotIn('HOST_FIXTURE_PRIVATE_ERROR', repr(self.result.status()))
        self.assertIsNone(self.result._plain)

    def test_wrong_thread_cannot_capture_or_decrypt(self):
        self.run_owned(lambda owner: None)
        self.assertEqual(self.errors + self.reader_errors, [])
        with self.assertRaisesRegex(h.HandoffError, '^wrong_thread$'):
            self.result.capture(self.event, self.helper, 3, 3)
        with self.assertRaisesRegex(h.HandoffError, '^wrong_thread$'):
            self.result.decrypt()

    def test_real_crypto_to_control_frame_once_and_cancel(self):
        import mta_client_control_frame as codec
        def action(owner):
            owner.decrypt()
            wire = owner.claim_frame(codec, 'a' * 32, 'b' * 64, 'local-operation-1')
            self.assertIsNone(owner._plain)
            self.assertEqual(owner.binding.private_metadata()['gatt_session'], 7)
            self.assertEqual(owner.binding.private_metadata()['operation_id'], 'local-operation-1')
            decoder = codec.ControlFrameDecoder(owner.binding)
            decoder.feed(wire[:11]); self.assertIsNone(decoder.take_connect())
            decoder.feed(wire[11:])
            request = decoder.take_connect()
            self.assertEqual(request.private_info().to_dict(), self.plain.to_dict())
            self.assertFalse(request.cancelled)
            decoder.feed(codec.CANCEL)
            self.assertTrue(request.cancelled)
            with self.assertRaises(codec.ControlFrameError): request.private_info()
            with self.assertRaisesRegex(h.HandoffError, '^already_claimed$'):
                owner.claim_frame(codec, 'a' * 32, 'b' * 64, 'local-operation-1')
            public = repr(owner.status()) + repr(owner.binding.public_metadata())
            for value in (owner.nonce, self.plain.psk, self.plain.ssid, self.plain.id):
                self.assertNotIn(value, public)
        self.run_owned(action)
        self.assertEqual(self.errors + self.reader_errors, [])

    def test_expiry_clock_rollback_and_public_privacy(self):
        def action(owner):
            self.clock[0] = 9
            with self.assertRaisesRegex(h.HandoffError, '^expired$'): owner.decrypt()
        self.run_owned(action)
        self.assertEqual(self.errors + self.reader_errors, [])
        public = repr(self.result) + repr(self.result.status())
        for private in (self.plain.ssid, self.plain.psk, self.plain.mac,
                self.sender.public_key, self.result.nonce, self.plain.id):
            self.assertNotIn(private, public)

    def test_source_py35_no_io_or_native_fallback(self):
        source = (BASE / 'candidate/client-connect-v13/runtime/mta_client_connect_handoff.py').read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        names = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertFalse(names & {'open', 'eval', 'exec', 'compile'})
        attrs = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse(attrs & {'Popen', 'write', 'connect', 'restore', 'start', 'fork'})

    def test_huge_clock_and_constructor_uses_one_validated_sample(self):
        def action(owner):
            # Existing instance stays terminal when a producer returns huge int.
            self.clock[0] = 10 ** 1000
            with self.assertRaisesRegex(h.HandoffError, '^expired$'): owner.decrypt()
            self.clock[0] = 10
            # Constructor checks bounded values before float conversion/finite.
            with self.assertRaisesRegex(h.HandoffError, '^invalid_budget$'):
                h.ReceiveConnectHandoff(self.state, self.op, 10 ** 1000)
            samples = [10, 'second-call-must-not-happen']
            calls = []
            def sample():
                calls.append(True)
                return samples.pop(0)
            fresh = h.ReceiveConnectHandoff(self.state, self.op, 100, _clock=sample)
            self.assertEqual(len(calls), 1)
            self.assertEqual(fresh._last, 10)
            self.assertEqual(samples, ['second-call-must-not-happen'])
        self.run_owned(action)
        self.assertEqual(self.errors + self.reader_errors, [])


if __name__ == '__main__':
    unittest.main()
