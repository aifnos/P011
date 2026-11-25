"""New PC-only checker cases. Temporary fixtures, never target execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_v14_source_check',
    str(ROOT / 'host/client_connect_v14_source_check.py'))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class SourceCheckV14Tests(unittest.TestCase):
    def fixture(self, change=None):
        temporary = tempfile.TemporaryDirectory(prefix='p011-v14-source-fixture-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        rows = []
        for name, relative in check.EXPECTED:
            text = 'CONST = 1\n'
            if name == 'mta_client_executor':
                text += 'MODULES = ' + repr(tuple(n for n, unused in check.EXPECTED)) + '\n'
            if change is not None:
                text = change(name, text)
            raw = text.encode('utf-8')
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            rows.append({'module': name, 'path': relative,
                'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        plan = root / 'manifest.json'
        plan.write_text(json.dumps({'version': 1, 'kind': 'client-connect-v14-source-only',
            'sources': rows}), encoding='utf-8')
        return root, plan, rows

    def verify(self, root, plan):
        with mock.patch.object(check, 'BASE', root), mock.patch.object(check, 'PLAN', plan), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('subprocess forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')):
            return check.verify()

    def test_fixed_23_sources_static_pass_without_executing_module_code(self):
        root, plan, rows = self.fixture(lambda name, text:
            text + 'raise RuntimeError("fixture must not execute")\n')
        self.assertEqual(self.verify(root, plan), rows)
        self.assertEqual(len(rows), 23)

    def test_changed_frozen_source_rejected_without_updating_manifest(self):
        root, plan, unused = self.fixture()
        (root / check.EXPECTED[0][1]).write_bytes(b'CONST = 2\n')
        with self.assertRaisesRegex(ValueError, '^source_mismatch$'):
            self.verify(root, plan)

    def test_forward_unknown_and_relative_dependencies_rejected(self):
        for text, code in (('import mta_client_executor\n', 'dependency_order'),
                ('import mta_unknown\n', 'dependency_order'),
                ('from . import x\n', 'relative_import')):
            with self.subTest(code=code, text=text):
                root, plan, unused = self.fixture(lambda name, original:
                    text if name == 'p011_json' else original)
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    self.verify(root, plan)

    def test_executor_literal_graph_and_manifest_shape_strict(self):
        root, plan, unused = self.fixture(lambda name, text:
            'MODULES = ()\n' if name == 'mta_client_executor' else text)
        with self.assertRaisesRegex(ValueError, '^executor_graph$'):
            self.verify(root, plan)
        root, plan, unused = self.fixture()
        value = json.loads(plan.read_text(encoding='utf-8'))
        value['version'] = True
        plan.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '^manifest_invalid$'):
            self.verify(root, plan)

    def test_deferred_exact_forward_dependencies_allowed_not_executed(self):
        root, plan, rows = self.fixture(lambda name, text: text + (
            'def deferred():\n    from mta_client_store import DurableClientInitStore\n'
            '    raise RuntimeError("deferred must not execute")\n'
            if name == 'mta_client_coordination' else ''))
        self.assertEqual(self.verify(root, plan), rows)

    def test_class_eager_and_deferred_unknown_or_relative_imports_rejected(self):
        for text, code in (
                ('class Eager:\n    import mta_client_executor\n', 'dependency_order'),
                ('def deferred():\n    import mta_unknown\n', 'dependency_order'),
                ('def deferred():\n    from . import x\n', 'relative_import')):
            with self.subTest(code=code, text=text):
                root, plan, unused = self.fixture(lambda name, original:
                    text if name == 'p011_json' else original)
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    self.verify(root, plan)

    def test_no_argument_or_device_mode_accepted(self):
        with mock.patch.object(sys, 'argv', ['source_check', '--execute-reviewed']), \
                mock.patch.object(check, 'verify', side_effect=AssertionError('verify forbidden')), \
                mock.patch('builtins.print') as output:
            self.assertEqual(check.main(), 2)
            output.assert_called_once_with('SOURCE_ONLY: no arguments or device mode accepted')


if __name__ == '__main__':
    unittest.main()
