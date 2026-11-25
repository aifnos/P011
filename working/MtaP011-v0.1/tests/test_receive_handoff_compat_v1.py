"""HOST-only contract for the new capture parsing segment.

Executes the exact candidate's parsing try-block with real p011_json/protocol.
No Owner, worker, radio, device, crypto operation or restoration fixture runs.
"""
import ast
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest


BASE = Path(__file__).resolve().parents[1]
TARGET = BASE / 'candidate/formal-receive-compat-v1/runtime/mta_client_connect_handoff.py'


def load_definition(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture_parser():
    # The real bundled parser is temporarily supplied only for the pure protocol
    # import. The protocol keeps that exact module; the caller's namespace is
    # restored even if loading fails. No old receiver graph is imported.
    bundled = load_definition('host_compat_json', BASE / 'runtime/p011_json.py')
    absent = object()
    previous = sys.modules.get('p011_json', absent)
    try:
        sys.modules['p011_json'] = bundled
        protocol = load_definition('host_compat_protocol', BASE / 'runtime/mta_protocol.py')
    finally:
        if previous is absent:
            sys.modules.pop('p011_json', None)
        else:
            sys.modules['p011_json'] = previous
    source = ast.parse(TARGET.read_text(encoding='utf-8'), filename=str(TARGET))
    fields = []
    for node in source.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in
                ('MAX_ENCRYPTED_BYTES', '_FIELDS', '_CODES') for target in node.targets):
            fields.append(node)
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in ('HandoffError', '_fail'):
            fields.append(node)
    owner = next(node for node in source.body
                 if isinstance(node, ast.ClassDef) and node.name == 'ReceiveConnectHandoff')
    method = next(node for node in owner.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'capture')
    body = method.body[1].body
    fragment = next(node for node in body if isinstance(node, ast.Try))
    function = ast.FunctionDef(
        name='parse_capture_segment',
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg='event')],
                           vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=[fragment, ast.Return(value=ast.Tuple(elts=[
            ast.Name(id='wire', ctx=ast.Load()), ast.Name(id='info', ctx=ast.Load())], ctx=ast.Load()))],
        decorator_list=[])
    namespace = {'base64': base64, 'protocol': protocol}
    program = ast.fix_missing_locations(ast.Module(body=fields + [function], type_ignores=[]))
    exec(compile(program, str(TARGET), 'exec'), namespace)
    return namespace['parse_capture_segment'], namespace['HandoffError'], protocol


class CaptureCompatibilityTest(unittest.TestCase):
    def test_new_manifest_parser_rejects_old_root_and_unrelated_changes(self):
        definitions = load_definition('host_compat_definitions',
            BASE / 'host/formal_receive_compat_v1_definitions.py')
        raw = (BASE / definitions.MANIFEST[0]).read_bytes()
        rows = definitions.manifest_rows(raw)
        self.assertEqual(len(rows), 35)
        self.assertEqual(sum(row[1].startswith('candidate/formal-receive-compat-v1/')
                             for row in rows), 4)
        value = json.loads(raw)
        changed = next(row for row in value['sources']
                       if row['module'] == 'mta_client_connect_handoff')
        changed['path'] = 'candidate/formal-receive-v3/runtime/mta_client_connect_handoff.py'
        with self.assertRaises(ValueError):
            definitions.manifest_rows(json.dumps(value).encode('ascii'))
        value = json.loads(raw)
        untouched = next(row for row in value['sources'] if row['module'] == 'mta_protocol')
        untouched['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            definitions.manifest_rows(json.dumps(value).encode('ascii'))
        value = json.loads(raw)
        changed = next(row for row in value['sources']
                       if row['module'] == 'mta_client_connect_handoff')
        changed['bytes'] = True
        with self.assertRaises(ValueError):
            definitions.manifest_rows(json.dumps(value).encode('ascii'))
        with self.assertRaises(ValueError):
            definitions.make_source(None, {}, (), True)

    def test_actual_capture_segment_extensions_and_strict_rejections(self):
        parse, error, protocol = capture_parser()
        encrypted = base64.b64encode(b'host-fixture-encrypted-bytes').decode('ascii')
        known = dict(ssid=encrypted, psk=encrypted, mac=encrypted, port=8080,
                     key=encrypted, id='host_fixture_id', catShare=1)
        def event(raw):
            return {'payload_b64': base64.b64encode(raw).decode('ascii')}
        def reject(raw):
            with self.assertRaises(error) as caught:
                parse(event(raw))
            self.assertEqual(caught.exception.code, 'invalid_event')
        wire = protocol.encode_json(known)
        saved, info = parse(event(wire))
        self.assertEqual(saved, wire)
        self.assertEqual(info.to_dict(), known)
        extended = dict(known, host_fixture_extension={
            'port': False, 'key': None, 'ssid': 'not-an-authority'},
            host_fixture_array=[1, None, True])
        extended_wire = protocol.encode_json(extended)
        saved, info = parse(event(extended_wire))
        self.assertEqual(saved, extended_wire)  # Original encrypted wire, not re-encoded.
        self.assertEqual(info.to_dict(), known)
        self.assertEqual(info.to_bytes(), protocol.encode_json(known))
        self.assertNotIn('host_fixture_extension', info.to_dict())
        # The unchanged worker decode of that original wire also ignores extensions.
        self.assertEqual(protocol.P2pInfo.from_bytes(saved).to_dict(), known)
        for field in ('ssid', 'psk', 'mac', 'port', 'key'):
            with self.subTest(missing=field):
                value = dict(known)
                value.pop(field)
                reject(protocol.encode_json(value))
        # A fully valid plaintext P2pInfo still cannot pass the encrypted GATT
        # capture gate merely by omitting key or explicitly setting key=None.
        plaintext = dict(ssid='HOST_FIXTURE', psk='host_fixture_password',
                         mac='02:00:00:00:00:01', port=8080)
        reject(protocol.encode_json(plaintext))
        reject(protocol.encode_json(dict(plaintext, key=None)))
        for field, value in (('ssid', 7), ('psk', None), ('mac', False),
                             ('key', None), ('key', ''), ('key', 'not base64!'),
                             ('ssid', '%%%'), ('psk', '%%%'), ('mac', '%%%'),
                             ('port', True), ('port', '8080'), ('port', None),
                             ('port', 0), ('port', 65536), ('id', True),
                             ('catShare', True)):
            with self.subTest(field=field, invalid_type=type(value).__name__):
                invalid = dict(known)
                invalid[field] = value
                reject(protocol.encode_json(invalid))
        # Complete JSON tree/duplicate-key and original envelope restrictions
        # apply even to ignored extensions. No new unknown-key parser exists.
        reject(wire[:-1] + b',"port":8080}')
        reject(wire[:-1] + b',"host_fixture_extra":1,"host_fixture_extra":2}')
        reject(wire[:-1] + b',"host_fixture_float":0.5}')
        reject(b'[]')
        reject(b'"not-an-object"')
        reject(b'{"host_fixture_bad_utf8":"\xff"}')
        reject(b' ' * 2049)
        reject(wire[:-1] + b',"host_fixture_depth":' + b'[' * 18 +
               b'1' + b']' * 18 + b'}')
        with self.assertRaises(error) as caught:
            parse({'payload_b64': '%%%='})
        self.assertEqual(caught.exception.code, 'invalid_event')
        with self.assertRaises(error):
            parse({'payload_b64': event(wire)['payload_b64'] + ' '})
        # This test has parsed no plaintext credentials, started no native
        # operation and issued no owner/restore/phone success receipt.


if __name__ == '__main__':
    unittest.main(verbosity=2)
