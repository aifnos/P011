"""New wrapper/24-graph contracts only; temporary sources cannot execute."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v15_source_check',
    str(BASE / 'host/client_kernel_connect_v15_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class KernelSourceCheckV15Tests(unittest.TestCase):
    def fixture(self):
        shared = check.shared_checker()
        graph = check.expected(shared)
        temporary = tempfile.TemporaryDirectory(prefix='p011-v15-source-fixture-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        helper = root / 'host/client_connect_v14_source_check.py'
        helper.parent.mkdir(parents=True)
        helper.write_bytes((BASE / 'host/client_connect_v14_source_check.py').read_bytes())
        rows = []
        for name, relative in graph:
            text = 'raise RuntimeError("target code must not execute")\n'
            if name == 'mta_client_connection':
                text = 'import mta_client_kernel_proof\n' + text
            if name == 'mta_client_executor':
                text = 'MODULES = ' + repr(tuple(n for n, unused in graph)) + '\n' + text
            raw = text.encode('utf-8')
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            rows.append({'module': name, 'path': relative,
                'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        plan = root / 'manifest.json'
        plan.write_text(json.dumps({'version': 1, 'kind': check.KIND, 'sources': rows}), encoding='utf-8')
        return root, plan, rows

    def verify(self, root, plan):
        with mock.patch.object(check, 'BASE', root), mock.patch.object(check, 'PLAN', plan), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('process forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')):
            return check.verify()

    def test_wrapper_24_specific_kind_paths_kernel_slot_and_target_not_executed(self):
        root, plan, rows = self.fixture()
        self.assertEqual(24, len(rows))
        self.assertEqual(self.verify(root, plan), rows)
        value = json.loads(plan.read_text(encoding='utf-8'))
        value['kind'] = 'client-connect-v14-source-only'
        plan.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '^manifest_invalid$'):
            self.verify(root, plan)

    def test_shared_scope_checker_hash_gate_precedes_import(self):
        root, plan, unused = self.fixture()
        helper = root / 'host/client_connect_v14_source_check.py'
        helper.write_bytes(b'raise RuntimeError("changed helper must not execute")\n')
        with self.assertRaisesRegex(ValueError, '^shared_checker_changed$'):
            self.verify(root, plan)

    def test_shared_helper_executes_the_original_hashed_bytes_not_second_read(self):
        raw = (BASE / 'host/client_connect_v14_source_check.py').read_bytes()
        with mock.patch.object(Path, 'read_bytes', side_effect=[raw,
                b'raise RuntimeError("second read must not execute")\n']) as reads:
            shared = check.shared_checker()
        self.assertEqual(1, reads.call_count)
        self.assertEqual(23, len(shared.EXPECTED))
        self.assertIsNotNone(shared._Imports)

    def test_new_entry_has_no_argument_or_device_mode(self):
        with mock.patch.object(sys, 'argv', ['source_check', '--device']), \
                mock.patch.object(check, 'verify', side_effect=AssertionError('verify forbidden')), \
                mock.patch('builtins.print') as output:
            self.assertEqual(2, check.main())
            output.assert_called_once_with('SOURCE_ONLY: no arguments or device mode accepted')


if __name__ == '__main__':
    unittest.main()
