"""New v13 codec methods only: pure HOST, no F/Provider/device/OS execution."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
SOURCE = BASE / 'candidate/client-connect-v13/runtime/mta_client_control_frame.py'
spec = importlib.util.spec_from_file_location('client_control_frame_v13', str(SOURCE))
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
import mta_protocol as protocol
import p011_json as json


def metadata():
    return {'version': 1, 'run_token': '1' * 32, 'candidate_sha': '2' * 64,
        'operation_id': 'local-operation-1', 'native_epoch': 8, 'operation_epoch': 9,
        'gatt_session': 12, 'nonce': '3' * 32, 'receive_consent': True}


def info():
    return protocol.P2pInfo('Synthetic-\u6d4b\u8bd5', 'synthetic-secret',
        '02:11:22:33:44:55', 3345, sender_id='remote-p2p-id', cat_share=1)


def make():
    binding = codec.ControlBinding(metadata())
    return binding, codec.ControlFrameDecoder(binding)


def wire(value):
    return codec.PREFIX + json.dumps(value, sort_keys=True).encode('ascii') + b'\n'


def body(binding):
    return {'binding': binding.private_metadata(), 'p2p': info().to_dict()}


class ControlFrameTests(unittest.TestCase):
    def reject(self, decoder, data, code):
        with self.assertRaises(codec.ControlFrameError) as raised:
            decoder.feed(data)
        self.assertEqual(raised.exception.code, code)
        self.assertTrue(decoder.status()['cancel_requested'])
        self.assertIsNone(decoder.take_connect())

    def test_roundtrip_exact_protocol_preserves_remote_id_not_local_operation(self):
        binding, decoder = make()
        encoded = codec.encode_connect(binding, info())
        self.assertLessEqual(len(encoded), 4096)
        self.assertTrue(all(n < 128 for n in encoded))
        self.assertIn(b'\\u6d4b', encoded)
        decoder.feed(encoded)
        request = decoder.take_connect()
        self.assertIs(type(request), codec.ConnectRequest)
        self.assertIs(request.binding, binding)
        self.assertIs(type(request.private_info()), protocol.P2pInfo)
        self.assertEqual(request.private_info().to_dict(), info().to_dict())
        self.assertNotEqual(request.private_info().id, metadata()['operation_id'])

    def test_every_two_piece_split_and_bytewise(self):
        binding, _ = make()
        encoded = codec.encode_connect(binding, info())
        for offset in range(len(encoded)):
            with self.subTest(offset=offset):
                decoder = codec.ControlFrameDecoder(binding)
                decoder.feed(encoded[:offset])
                self.assertIsNone(decoder.take_connect())
                decoder.feed(encoded[offset:])
                self.assertEqual(decoder.take_connect().private_info().to_dict(), info().to_dict())
        decoder = codec.ControlFrameDecoder(binding)
        for byte in encoded:
            decoder.feed(bytes((byte,)))
        self.assertIsNotNone(decoder.take_connect())

    def test_binding_exact_fields_types_ranges_and_no_bool_int(self):
        cases = [('version', True), ('version', 2), ('run_token', 'a' * 31),
            ('run_token', 'A' * 32), ('candidate_sha', 'b' * 65),
            ('nonce', 'z' * 32), ('native_epoch', True), ('native_epoch', 0),
            ('operation_epoch', 2 ** 53 + 1), ('gatt_session', True),
            ('gatt_session', 0), ('gatt_session', 4294967296),
            ('gatt_session', 'fake-session-token'), ('receive_consent', False),
            ('receive_consent', 1), ('operation_id', 'bad/path')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = metadata(); data[key] = value
                with self.assertRaises(codec.ControlFrameError): codec.ControlBinding(data)
        for key in metadata():
            data = metadata(); del data[key]
            with self.assertRaises(codec.ControlFrameError): codec.ControlBinding(data)
        data = metadata(); data['extra'] = 1
        with self.assertRaises(codec.ControlFrameError): codec.ControlBinding(data)
        class DictSubclass(dict): pass
        with self.assertRaises(codec.ControlFrameError): codec.ControlBinding(DictSubclass(metadata()))

    def test_binding_private_immutable_copy_and_digest_only_public(self):
        data = metadata(); binding = codec.ControlBinding(data)
        original = binding.private_metadata(); data['nonce'] = '4' * 32
        copy = binding.private_metadata(); copy['run_token'] = '5' * 32
        self.assertEqual(binding.private_metadata(), original)
        with self.assertRaises(AttributeError): binding._wire = b'changed'
        canonical = json.dumps(original, sort_keys=True).encode('ascii')
        self.assertEqual(binding.public_metadata(), {'version': 1,
            'binding_sha256': hashlib.sha256(canonical).hexdigest()})
        for private in ('run_token', 'nonce', 'operation_id', 'gatt_session'):
            self.assertNotIn(private, binding.public_metadata())

    def test_encoder_rejects_wrong_exact_types_encrypted_and_mutated_info(self):
        binding, _ = make()
        class BindingSubclass(codec.ControlBinding): pass
        class InfoSubclass(protocol.P2pInfo): pass
        candidates = [InfoSubclass('x', 'abcdefgh', '02:11:22:33:44:55', 1), None]
        encrypted = info(); encrypted.key = 'not plaintext'; candidates.append(encrypted)
        for key, value in [('port', True), ('port', 0), ('cat_share', True),
                ('ssid', ''), ('psk', 'short'), ('mac', 'bad'), ('id', '../x')]:
            changed = info(); setattr(changed, key, value); candidates.append(changed)
        for candidate in candidates:
            with self.assertRaises(codec.ControlFrameError): codec.encode_connect(binding, candidate)
        with self.assertRaises(codec.ControlFrameError):
            codec.encode_connect(BindingSubclass(metadata()), info())

    def test_no_id_or_catshare_optional_fields_preserved(self):
        binding, decoder = make()
        value = protocol.P2pInfo('x', 'abcdefgh', '02:11:22:33:44:55', 1, cat_share=None)
        decoder.feed(codec.encode_connect(binding, value))
        self.assertEqual(decoder.take_connect().private_info().to_dict(), value.to_dict())

    def test_decoder_binding_mismatch_each_original_field(self):
        changes = {'run_token': '4' * 32, 'candidate_sha': '5' * 64,
            'operation_id': 'other-op', 'native_epoch': 10, 'operation_epoch': 11,
            'gatt_session': 13, 'nonce': '6' * 32}
        for key, value in changes.items():
            with self.subTest(key=key):
                binding, decoder = make(); data = body(binding); data['binding'][key] = value
                self.reject(decoder, wire(data), 'binding_mismatch')

    def test_extra_outer_binding_and_info_fields_rejected(self):
        for location in ('outer', 'binding', 'p2p'):
            binding, decoder = make(); data = body(binding)
            data['extra'] = 1 if location == 'outer' else None
            if location != 'outer':
                del data['extra']; data[location]['extra'] = 1
            self.reject(decoder, wire(data), 'invalid_frame' if location == 'outer' else
                'invalid_binding' if location == 'binding' else 'invalid_info')
        binding, decoder = make(); data = body(binding); data['p2p']['key'] = None
        self.reject(decoder, wire(data), 'invalid_info')

    def test_duplicate_json_keys_and_noncanonical_encodings(self):
        binding, _ = make(); encoded = codec.encode_connect(binding, info())
        for malformed in (encoded.replace(b'"version": 1', b'"version": 1, "version": 1'),
                encoded.replace(b'"port": 3345', b'"port": true')):
            self.assertNotEqual(malformed, encoded)
            decoder = codec.ControlFrameDecoder(binding)
            with self.assertRaises(codec.ControlFrameError): decoder.feed(malformed)
            self.assertTrue(decoder.status()['cancel_requested'])
        for changed in (encoded.replace(b'CONNECT {', b'CONNECT { '),
                encoded.replace(b'"mac": "02:11', b'"mac": "02:aa'),
                encoded[:-1] + b'\r\n'):
            decoder = codec.ControlFrameDecoder(binding)
            self.assertNotEqual(changed, encoded)
            with self.assertRaises(codec.ControlFrameError): decoder.feed(changed)

    def test_cancel_same_chunk_before_or_after_connect_and_malformed(self):
        binding, _ = make(); encoded = codec.encode_connect(binding, info())
        for data in (codec.CANCEL + encoded, encoded + codec.CANCEL,
                b'not-a-command\n' + codec.CANCEL):
            decoder = codec.ControlFrameDecoder(binding); decoder.feed(data)
            self.assertTrue(decoder.status()['cancel_requested'])
            self.assertEqual(decoder.status()['reason'], 'cancelled')
            self.assertIsNone(decoder.take_connect())
            self.assertFalse(decoder.status()['connect_seen'])

    def test_partial_cancel_after_connect_defers_then_cancels(self):
        binding, decoder = make()
        decoder.feed(codec.encode_connect(binding, info()) + b'CAN')
        self.assertTrue(decoder.status()['connect_pending'])
        self.assertIsNone(decoder.take_connect())
        decoder.feed(b'CEL\n'); self.assertIsNone(decoder.take_connect())
        self.assertTrue(decoder.status()['cancel_requested'])

    def test_eof_priority_with_connect_partial_and_claimed(self):
        binding, _ = make()
        for data in (b'', b'CONNECT {', codec.encode_connect(binding, info())):
            decoder = codec.ControlFrameDecoder(binding); decoder.feed(data, eof=True)
            self.assertIsNone(decoder.take_connect()); self.assertTrue(decoder.status()['eof_observed'])
            self.assertEqual(decoder.status()['reason'], 'eof')
        decoder = codec.ControlFrameDecoder(binding); decoder.feed(codec.encode_connect(binding, info()))
        request = decoder.take_connect(); decoder.feed(b'', eof=True)
        self.assertTrue(request.cancelled)
        with self.assertRaises(codec.ControlFrameError): request.private_info()

    def test_claim_once_and_mutated_info_cannot_change_original(self):
        binding, decoder = make(); decoder.feed(codec.encode_connect(binding, info()))
        request = decoder.take_connect(); copied = request.private_info(); copied.psk = 'changed-password'
        self.assertEqual(request.private_info().psk, info().psk)
        self.assertIsNone(decoder.take_connect())
        with self.assertRaises(AttributeError): request._info_wire = b'changed'

    def test_duplicate_nonce_and_other_connect_sticky_cancel(self):
        binding, decoder = make(); encoded = codec.encode_connect(binding, info())
        decoder.feed(encoded); request = decoder.take_connect()
        self.reject(decoder, encoded, 'duplicate_nonce')
        self.assertTrue(request.cancelled)
        binding, decoder = make(); decoder.feed(encoded)
        changed = body(binding); changed['binding']['nonce'] = '4' * 32
        self.reject(decoder, wire(changed), 'binding_mismatch')

    def test_piece_and_partial_frame_limits(self):
        _, decoder = make(); self.reject(decoder, b'x' * 4097, 'frame_size')
        _, decoder = make(); decoder.feed(codec.PREFIX + b'x' * (4095 - len(codec.PREFIX)))
        self.assertEqual(decoder.status()['buffered_bytes'], 4095)
        self.reject(decoder, b'x', 'frame_size')
        binding, decoder = make(); data = body(binding); data['p2p']['ssid'] = 'x' * 2049
        self.reject(decoder, wire(data), 'info_size')

    def test_stream_limit_and_invalid_segments(self):
        binding, decoder = make(); encoded = codec.encode_connect(binding, info())
        decoder.feed(encoded); request = decoder.take_connect()
        remaining = codec.MAX_TOTAL - len(encoded)
        decoder.feed(codec.PREFIX + b'x' * (remaining - len(codec.PREFIX)))
        self.assertEqual(decoder.status()['input_bytes'], codec.MAX_TOTAL)
        self.reject(decoder, b'x', 'stream_limit')
        self.assertTrue(request.cancelled)

    def test_invalid_ascii_commands_newline_and_types_fail_closed(self):
        for data in (b'CONNECT \xff\n', b'\x00', b'\n', b'CONNECT {}\n', b'STATUS\n',
                'CANCEL\n', bytearray(b'CANCEL\n'), None):
            with self.subTest(data=type(data).__name__):
                _, decoder = make()
                with self.assertRaises(codec.ControlFrameError): decoder.feed(data)
                self.assertTrue(decoder.status()['cancel_requested'])
        _, decoder = make()
        with self.assertRaises(codec.ControlFrameError): decoder.feed(b'', eof=1)

    def test_cancelled_request_and_public_no_secret_or_identifiers(self):
        binding, decoder = make(); decoder.feed(codec.encode_connect(binding, info()))
        request = decoder.take_connect(); decoder.cancel()
        with self.assertRaises(codec.ControlFrameError): request.private_info()
        text = repr(binding) + repr(decoder) + repr(request) + repr(decoder.status()) + repr(binding.public_metadata())
        for forbidden in (info().ssid, info().psk, info().mac, info().id,
                metadata()['operation_id'], metadata()['run_token'], metadata()['nonce']):
            self.assertNotIn(forbidden, text)
        self.assertFalse(decoder.status()['association_verified'])
        self.assertFalse(decoder.status()['ip_verified'])
        self.assertFalse(decoder.status()['endpoint_verified'])
        self.assertFalse(decoder.status()['production_available'])

    def test_cancel_token_inside_json_is_not_command(self):
        binding, decoder = make(); value = info(); value.psk = 'CANCEL\npassword'
        decoder.feed(codec.encode_connect(binding, value))
        self.assertFalse(decoder.status()['cancel_requested'])
        self.assertEqual(decoder.take_connect().private_info().psk, value.psk)

    def test_eof_afterwards_no_reopening_and_first_reason_preserved(self):
        _, decoder = make(); decoder.feed(b'', eof=True)
        with self.assertRaises(codec.ControlFrameError): decoder.feed(codec.CANCEL)
        self.assertTrue(decoder.status()['eof_observed'])
        self.assertEqual(decoder.status()['reason'], 'eof')
        _, decoder = make()
        self.reject(decoder, b'bad', 'invalid_frame')
        decoder.cancel(); decoder.feed(codec.CANCEL)
        self.assertEqual(decoder.status()['reason'], 'invalid_frame')

    def test_python35_ast_and_no_io_or_f_provider_import(self):
        source = SOURCE.read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        imports = [node.names[0].name for node in tree.body if isinstance(node, ast.Import)]
        self.assertEqual(imports, ['hashlib', 're', 'p011_json', 'mta_protocol'])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('open', 'print', 'input', 'eval', 'exec'))


if __name__ == '__main__':
    unittest.main()
