"""Two HOST-only checks of the v2 fixed-root/manifest closure.

No receiver graph, Owner, radio, device, capture or crypto test is executed.
The frozen v1 capture contract is retained as evidence, not replayed here.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest


BASE = Path(__file__).resolve().parents[1]
EXECUTOR = BASE / 'candidate/formal-receive-compat-v2/runtime/mta_client_executor.py'
FROZEN_CAPTURE_TEST = ('tests/test_receive_handoff_compat_v1.py', 8437,
    '8dda7a8f4a475daee82b645ce1721c134528cea1b439971340b3b44312ef2086')
FROZEN_HANDOFF = ('candidate/formal-receive-compat-v1/runtime/mta_client_connect_handoff.py',
    12229, 'c86ccf734d9370ce86c3532cdc58a488382a056dd6b1e2d45ab24d06f27a683d')


def load_definition(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def directory_rejection():
    """Compile only actual constants, _token and the actual rejection expression.

    Nothing in _import_verified_sources is called. No stand-in path algorithm
    is introduced: its exact If.test and prefix/suffix assignments are used.
    """
    source = ast.parse(EXECUTOR.read_text(encoding='utf-8'), filename=str(EXECUTOR))
    constants = [node for node in source.body if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id in ('ROOT', 'PHYSICAL_ROOT')
        for target in node.targets)]
    token = next(node for node in source.body
                 if isinstance(node, ast.FunctionDef) and node.name == '_token')
    method = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                  and node.name == '_import_verified_sources')
    prefix = next(node for node in method.body if isinstance(node, ast.Assign) and
                  isinstance(node.targets[0], ast.Tuple) and
                  [item.id for item in node.targets[0].elts] == ['prefix', 'suffix'])
    checks = [node for node in method.body if isinstance(node, ast.If) and any(
        isinstance(item, ast.Constant) and
        item.value == '/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35'
        for item in ast.walk(node.test))]
    if len(constants) != 2 or len(checks) != 1:
        raise ValueError('actual_executor_fragment_changed')
    namespace = {'re': re}
    program = ast.fix_missing_locations(ast.Module(body=constants + [token, prefix], type_ignores=[]))
    exec(compile(program, str(EXECUTOR), 'exec'), namespace)
    condition = compile(ast.Expression(body=checks[0].test), str(EXECUTOR), 'eval')
    return lambda directory: eval(condition, namespace, {'directory': directory}), namespace


class StartupClosureTest(unittest.TestCase):
    def test_actual_executor_fixed_root_and_original_client_token_paths(self):
        reject, namespace = directory_rejection()
        self.assertEqual(namespace['ROOT'], '/tmp/p011-mta-client-rfinit')
        self.assertEqual(namespace['PHYSICAL_ROOT'], '/var/volatile/tmp/p011-mta-client-rfinit')
        self.assertFalse(reject('/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35'))
        original = '/tmp/p011-mta-client-rfinit/client-' + '0123456789abcdef' * 2 + '/runtime'
        self.assertFalse(reject(original))
        rejected = (
            '/var/volatile/tmp/p011-mta-formal-receive-v3/runtime35',
            '/var/volatile/tmp/p011-mta-formal-receive-compat-v1/runtime35',
            '/tmp/p011-mta-formal-receive-compat-v2/runtime35',
            '/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35/child',
            '/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35/../runtime35',
            '/var/volatile/tmp/other/runtime35',
            original + '/child', original.replace('/client-', '/other-'),
            original.replace('0123456789abcdef', '0123456789ABCDEF'),
            original.replace('0123456789abcdef' * 2, 'a' * 31),
            original.replace('0123456789abcdef' * 2, 'g' * 32),
            original.replace('/tmp/', '/var/volatile/tmp/'),
            original.replace('/runtime', '/runtime35'),
            original.replace('/runtime', '/../runtime'),
            original.replace('/client-', '/client-/'),
        )
        for directory in rejected:
            with self.subTest(case=directory):
                self.assertTrue(reject(directory))

    def test_new_ordinary_private_manifest_closure_and_frozen_capture_evidence(self):
        definitions = load_definition('host_compat_v2_definitions',
            BASE / 'host/formal_receive_compat_v2_definitions.py')
        raw = (BASE / definitions.MANIFEST[0]).read_bytes()
        private_raw = (BASE / definitions.PRIVATE_MANIFEST[0]).read_bytes()
        rows = definitions.manifest_rows(raw)
        private_rows = definitions.manifest_rows(private_raw, private=True)
        self.assertEqual(len(rows), 35)
        self.assertEqual(len(private_rows), 35)
        self.assertEqual(sum(row[1].startswith('candidate/formal-receive-compat-v2/')
                             for row in rows), 5)
        self.assertEqual(sum(row[1].startswith('candidate/formal-receive-compat-v2/')
                             for row in private_rows), 1)
        ordinary_executor = next(row[1:] for row in rows if row[0] == 'mta_client_executor')
        private_executor = next(row[1:] for row in private_rows
                                if row[0] == 'runtime35/mta_client_executor')
        self.assertEqual(ordinary_executor, private_executor)
        self.assertEqual(ordinary_executor, definitions.EXECUTOR_PIN)
        self.assertEqual(json.loads(private_raw)['previous_manifest_sha256'],
                         definitions.OLD_PRIVATE_MANIFEST[2])
        handoff = next(row[1:] for row in rows if row[0] == 'mta_client_connect_handoff')
        self.assertEqual(handoff, FROZEN_HANDOFF)
        for path, size, sha in (FROZEN_CAPTURE_TEST, FROZEN_HANDOFF):
            saved = (BASE / path).read_bytes()
            self.assertEqual(len(saved), size)
            self.assertEqual(hashlib.sha256(saved).hexdigest(), sha)
        def reject_mutation(before, private, mutate):
            value = json.loads(before)
            mutate(value)
            with self.assertRaises(ValueError):
                definitions.manifest_rows(json.dumps(value).encode('ascii'), private=private)
        def module(value, name):
            return next(row for row in value['sources'] if row['module'] == name)
        reject_mutation(raw, False, lambda value: module(value, 'mta_client_executor').update(
            path='candidate/formal-receive-v3/runtime/mta_client_executor.py'))
        reject_mutation(raw, False, lambda value: module(value, 'mta_client_executor').update(bytes=True))
        reject_mutation(raw, False, lambda value: module(value, 'mta_protocol').update(sha256='0' * 64))
        reject_mutation(raw, False, lambda value: module(value, 'mta_client_connect_handoff').update(
            path='candidate/formal-receive-compat-v2/runtime/mta_client_connect_handoff.py'))
        reject_mutation(private_raw, True, lambda value: module(value, 'mta_client_executor').update(
            path='candidate/formal-receive-v3/runtime/mta_client_executor.py'))
        reject_mutation(private_raw, True, lambda value: module(value, 'mta_client_executor').update(sha256='0' * 64))
        reject_mutation(private_raw, True, lambda value: value.update(previous_manifest_sha256='0' * 64))
        reject_mutation(private_raw, True, lambda value: module(value, 'mta_protocol').update(sha256='0' * 64))
        with self.assertRaises(ValueError):
            definitions.make_source(None, {}, (), True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
