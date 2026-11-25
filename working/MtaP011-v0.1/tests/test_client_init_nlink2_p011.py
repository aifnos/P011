"""Isolated r2 host entry only: Fake target and PC source reads, no ADB/RF."""
import ast
import base64
import builtins
import errno
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

import test_client_init_p011_host as old

BASE = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location('isolated_client_init_nlink2',
    str(BASE / 'host/client_init_nlink2_p011.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def fixture_source():
    raw = b'# HOST fixture only\n'
    rows = [(name, digest(raw), raw) for name, unused in driver.PINS]
    native = b'HOST_NOT_A_NATIVE_EXECUTABLE'
    source, sha = driver.build_source(rows, native, {}, 'a' * 32, 'b' * 64,
        _pins=tuple((name, pin) for name, pin, unused in rows), _native_pin=digest(native))
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            try: values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError, AttributeError): pass
    values['payloads'] = {name: data for name, unused, data in rows}
    return source, sha, values


class FakeExecutorError(ValueError):
    def __init__(self, code): self.code = code; ValueError.__init__(self, code)


def run_target(error=None, error_stage='python'):
    fixture = old.TargetFixture()
    original = fixture.modules['mta_client_executor']._ReadOwner
    class ReadOwner(original):
        def read_file(self, path, limit, *args, **kwargs):
            if path == '/python':
                metadata = list(fixture.modules['mta_client_executor']._meta(fixture.os.metadata(path)))
                metadata[5] = 2  # Synthetic profile, not a kernel receipt.
                row = {'path': path, 'fd': 77, 'metadata': tuple(metadata),
                    'unknown': False, 'attempted': False, 'closed': False}
                self.rows.append(row)
                if error is not None and error_stage == 'python': raise error
                return fixture.os.rows[path][1], row
            return super(ReadOwner, self).read_file(path, limit, *args, **kwargs)
        def close(self):
            for row in self.rows: row.update(attempted=True, closed=True)
            return True
    f = fixture.modules['mta_client_executor']
    f._ReadOwner, f.ExecutorError = ReadOwner, FakeExecutorError
    if error is not None and error_stage != 'python':
        original_assemble = fixture.modules['mta_client_linux_provider'].assemble
        def assemble(value):
            result = original_assemble(value)
            result[0].executor = lambda unused: (_ for _ in ()).throw(error)
            return result
        fixture.modules['mta_client_linux_provider'].assemble = assemble
    source, sha, values = fixture_source()
    values.update(modules=fixture.modules, base64=base64, hashlib=hashlib)
    imports = {'os': fixture.os,
        'sys': types.SimpleNamespace(flags=types.SimpleNamespace(optimize=0), version_info=(3, 5, 5)),
        'time': types.SimpleNamespace(monotonic=lambda: fixture.clock)}
    importer = builtins.__import__
    def fake_import(name, *args, **kwargs):
        return imports[name] if name in imports else importer(name, *args, **kwargs)
    output = []
    values['__builtins__'] = dict(vars(builtins), __import__=fake_import,
        print=lambda text: output.append(text))
    exec(driver.TARGET, values)
    return ast.literal_eval(output[-1][7:]), fixture


class ClientInitNlink2Tests(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'socket.socket', 'os.kill'):
            patcher = mock.patch(name, side_effect=AssertionError('no actual process/socket/RF'))
            patcher.start(); self.addCleanup(patcher.stop)
    def test_only_two_pins_and_source_locations_change(self):
        before, after = dict(old.driver.PINS), dict(driver.PINS)
        names = {'mta_client_executor', 'mta_client_process_owner'}
        self.assertEqual(set(driver.SOURCE_LOCATIONS), names)
        self.assertEqual(tuple(before), tuple(after))
        self.assertEqual({name for name in before if before[name] != after[name]}, names)
        for name in names:
            self.assertEqual(driver.SOURCE_LOCATIONS[name],
                BASE / 'candidate/client-init-nlink2/runtime' / (name + '.py'))
        self.assertEqual(driver.STATUS_DRIVER_SHA, old.driver.STATUS_DRIVER_SHA)
        self.assertEqual(driver.PROVIDER_SHA, old.driver.PROVIDER_SHA)
    def test_source_check_reads_original_status_and_seventeen_base_sources(self):
        seen, modules = [], []
        def read(path, pin, *args): seen.append((path, pin)); return b'# HOST\n'
        def module(path, pin, name):
            modules.append((path, pin)); return types.SimpleNamespace(
                source_check=lambda: (object(), 'MANIFEST={}\n', {}))
        with mock.patch.object(driver, '_read', side_effect=read), mock.patch.object(driver, '_module', side_effect=module):
            report, rows, native, manifest, unused = driver.source_check()
        self.assertEqual(len(rows), 19); self.assertTrue(report['source_check_pass'])
        self.assertEqual(modules, [(BASE / 'host/client_wpa_status_readonly.py', driver.STATUS_DRIVER_SHA)])
        observed = [path for path, pin in seen if path.suffix == '.py' and path.name != 'device_probe.py'
            and path.name != 'client_init_nlink2_p011.py']
        expected = [driver.SOURCE_LOCATIONS.get(name, BASE / 'runtime' / (name + '.py')) for name, unused in driver.PINS]
        self.assertEqual(observed, expected)
        self.assertEqual(sum(path.parent == BASE / 'runtime' for path in observed), 17)
    def test_default_cmd_and_main_do_not_execute(self):
        text = (BASE / 'HOST_CLIENT_INIT_NLINK2_SOURCE_CHECK.cmd').read_text(encoding='utf-8')
        self.assertIn('python -B host\\client_init_nlink2_p011.py', text)
        self.assertNotIn('--execute-reviewed', text)
        with mock.patch.object(driver, 'source_check', return_value=({'source_check_pass': True}, None, None, None, None)), \
                mock.patch.object(driver, 'execute', side_effect=AssertionError('no execute')), mock.patch('builtins.print'):
            self.assertEqual(driver.main([]), 0)
    def test_python_source_invalid_mapping_and_private_original_rows(self):
        value, fixture = run_target(FakeExecutorError('source_invalid'))
        self.assertEqual(value['public']['stage'], 'python')
        self.assertEqual(value['public']['reason'], 'python_invalid')
        self.assertFalse(value['public']['staging_attempted']); self.assertFalse(value['public']['rf_requested'])
        row = value['private']['python_files'][0]
        self.assertEqual(row['metadata'][5], 2); self.assertEqual(row['fd'], 77)
        self.assertTrue(row['attempted']); self.assertTrue(row['closed'])
        self.assertIn('FakeExecutorError: source_invalid', value['private']['errors'][0]['traceback'])
        self.assertNotIn('python_files', value['public'])
    def test_other_stage_source_invalid_not_mapped_to_python(self):
        value, fixture = run_target(FakeExecutorError('source_invalid'), 'baseline')
        self.assertEqual(value['public']['stage'], 'baseline_before')
        self.assertEqual(value['public']['reason'], 'unexpected')
        self.assertFalse(value['public']['rf_requested'])
    def test_python_os_error_remains_distinct(self):
        value, fixture = run_target(OSError(errno.EIO, 'synthetic private'))
        self.assertEqual(value['public']['reason'], 'os_error')
        self.assertEqual(value['private']['errors'][0]['class'], 'OSError')
        self.assertTrue(value['private']['python_files'][0]['closed'])
    def test_fake_target_public_shape_and_capabilities_unchanged(self):
        value, fixture = run_target()
        self.assertEqual(set(value['public']), set(driver._BOOLS) | {'stage', 'reason'})
        self.assertTrue(value['public']['pass'])  # HOST orchestration fixture only.
        for name in ('send_available', 'receive_available', 'phone_tested'):
            self.assertFalse(value['public'][name])
        self.assertEqual(value['private']['python_files'][0]['metadata'][5], 2)
    def test_actual_pc_new_nineteen_graph_and_bounded_python35_source(self):
        report, rows, native, manifest, unused = driver.source_check()
        self.assertTrue(report['source_check_pass']); self.assertEqual(report['source_count'], 19)
        for name, pin, raw in rows: self.assertEqual(digest(raw), pin)
        source, sha = driver.build_source(rows, native, manifest, 'c' * 32, report['driver_sha256'])
        ast.parse(source, feature_version=(3, 5))
        ast.parse((BASE / 'host/client_init_nlink2_p011.py').read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertLessEqual(len(source.encode('utf-8')), driver.MAX_SOURCE)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertEqual(len(sha), 64)
        self.assertFalse(report['send_available']); self.assertFalse(report['receive_available'])
    def test_original_source_and_reuse_functions_preserved(self):
        self.assertEqual(digest((BASE / 'host/client_init_p011.py').read_bytes()),
            'fda0e8b97122c7b29d3d6a2a6ab35e2e708d88c77eafc3f52b5e0e92eb36d49a')
        before, after = ast.parse((BASE / 'host/client_init_p011.py').read_text(encoding='utf-8')), \
            ast.parse((BASE / 'host/client_init_nlink2_p011.py').read_text(encoding='utf-8'))
        names = ('_read', '_module', 'build_source', '_validate_source', 'parse', 'main')
        for name in names:
            a = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == name)
            b = next(node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(ast.dump(a, include_attributes=False), ast.dump(b, include_attributes=False))


if __name__ == '__main__': unittest.main()
