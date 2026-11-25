"""One new HOST IO fault method; no SOURCE/build/binding main or device execution.

Actual shared evidence/sealing functions and the new checkers' input reader
definitions are used. Synthetic pin inputs and narrow read/write faults only;
no old suite, generated carrier, runtime role, RF or user data is exercised.
"""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

BASE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostArtifactSealV1Tests(unittest.TestCase):
    def test_partial_inputs_and_private_zip_fault_contract(self):
        helper = load('new_host_artifact_seal_fault_fixture', BASE / 'host/host_artifact_seal_v1.py')
        pc = load('new_pc_input_definition_fault_fixture', BASE / 'host/receive_durable_gui_v1_pc_check.py')
        # Parsing the three actual checkers is not executing their guarded main.
        for name in ('receive_durable_gui_v1_pc_check.py',
                     'receive_durable_gui_v1_binding_check.py',
                     'receive_durable_state_v1_source_check.py'):
            source = (BASE / 'host' / name).read_bytes()
            tree = ast.parse(source)
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
            self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                                node.func.attr == 'seal_result' for node in ast.walk(main)))
            self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                                 node.func.attr == 'ZipFile' for node in ast.walk(main)))
            # Each actual reader closes over the caller-owned collector.
            reader_name = {'receive_durable_gui_v1_binding_check.py': 'read',
                           'receive_durable_state_v1_source_check.py': 'retain'}.get(name)
            if reader_name:
                reader = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == reader_name)
                isolated = ast.fix_missing_locations(ast.Module(body=[reader], type_ignores=[]))
                with tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    raw = b'fully-read-but-rejected\x00\xff'
                    helper.fresh(root / 'rejected.bin', raw)
                    inputs = {}
                    evidence = helper.InputEvidence(inputs)
                    scope = dict(BASE=root, evidence=evidence)
                    exec(compile(isolated, '<actual-reader-definition-only>', 'exec'), scope)
                    with self.assertRaisesRegex(ValueError, 'input_pin'):
                        scope[reader_name](('rejected.bin', len(raw), '0' * 64))
                    evidence.snapshot(root / 'result', lambda key: key)
                    self.assertEqual(inputs['rejected.bin'], raw)
                    self.assertEqual((root / 'result/private-inputs/rejected.bin').read_bytes(), raw)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rejected = b'middle-source-pin-rejected\xff'
            donor = root / 'donor.py'
            helper.fresh(donor, rejected)
            builder = ("DONOR = %r\nDONOR_PIN = (%d, %r)\n"
                       "def bootstrap_source():\n    raise AssertionError('must-not-reach-bootstrap')\n" %
                       (str(donor), len(rejected), '0' * 64)).encode('utf-8')
            helper.fresh(root / 'builder.py', builder)
            inputs = {}
            evidence = helper.InputEvidence(inputs)
            with mock.patch.object(pc, 'BASE', root), mock.patch.object(pc, 'BUILDER', 'builder.py'), \
                    mock.patch.object(pc, 'BUILDER_PIN', (len(builder), helper.digest(builder))):
                with self.assertRaisesRegex(ValueError, 'input_pin'):
                    pc.inputs(inputs, evidence)
            self.assertEqual(inputs[root / 'builder.py'], builder)
            self.assertEqual(inputs[donor], rejected)
            evidence.snapshot(root / 'pin-fail', lambda key: key.relative_to(root).as_posix())
            self.assertEqual((root / 'pin-fail/private-inputs/builder.py').read_bytes(), builder)
            self.assertEqual((root / 'pin-fail/private-inputs/donor.py').read_bytes(), rejected)
            failure_report = dict(passed=False, host_exit=1, error='ValueError:input_pin', device=False, rf=False)
            sealed = helper.seal_result(root / 'pin-fail', failure_report, b'HOST fixture only.\n')
            self.assertFalse(sealed['report']['passed'])
            self.assertEqual(sealed['host_exit'], 1)
            self.assertEqual(sealed['report']['error'], failure_report['error'])

            # A real stream returns one chunk then faults: its prefix is private,
            # explicitly marked partial, and never described as a complete input.
            partial = root / 'partial.bin'
            class ReadFault:
                def __init__(self):
                    self.calls = 0
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
                def read(self, size):
                    self.calls += 1
                    if self.calls == 1:
                        return b'prefix-before-read-failure'
                    raise OSError('injected_read_failure')
            original_open = Path.open
            def faulty_open(path, *args, **kwargs):
                return ReadFault() if path == partial and args == ('rb',) else original_open(path, *args, **kwargs)
            partial_inputs = {}
            partial_evidence = helper.InputEvidence(partial_inputs)
            with mock.patch.object(Path, 'open', faulty_open):
                with self.assertRaisesRegex(OSError, 'injected_read_failure'):
                    partial_evidence.read(partial, key='partial.bin')
            partial_evidence.snapshot(root / 'partial-fail', lambda key: key)
            self.assertEqual((root / 'partial-fail/private-inputs/partial.bin').read_bytes(), b'prefix-before-read-failure')
            self.assertEqual(partial_evidence.partial, {'partial.bin'})
            self.assertEqual(json.loads((root / 'partial-fail/private-raw/input-read-status.json').read_bytes())['partial'],
                             ['partial.bin'])

            passed_report = dict(passed=True, host_exit=0, error=None, device=False, rf=False, phone=False)
            readme = b'HOST fixture only.\n'
            original_write = zipfile.ZipFile.writestr
            def write_fault(stream, *args, **kwargs):
                original_write(stream, *args, **kwargs)
                raise OSError('injected_zip_write_failure')
            faults = (('zip-write', mock.patch.object(zipfile.ZipFile, 'writestr', write_fault)),
                      ('zip-readback', mock.patch.object(helper, '_verify_zip',
                          side_effect=OSError('injected_zip_readback_failure'))))
            for label, fault in faults:
                out = root / label
                with fault:
                    result = helper.seal_result(out, passed_report, readme)
                self.assertFalse(result['report']['passed'])
                self.assertEqual(result['host_exit'], 1)
                self.assertIsNone(result['archive'])
                self.assertIsNone(result['archive_sha256'])
                self.assertFalse((out / 'public-result.zip').exists())
                public = json.loads((out / 'result.json').read_bytes())
                self.assertIs(public['passed'], False)
                self.assertEqual(public['host_exit'], 1)
                self.assertIn('injected_zip_', public['seal_error'])
                self.assertTrue((out / 'private-seal/candidate-result.zip').exists())
                self.assertIn(b'injected_zip_', (out / 'private-raw/seal-exception.txt').read_bytes())
                self.assertTrue(json.loads((out / 'private-seal/result.json').read_bytes())['passed'])
            self.assertTrue(passed_report['passed'])  # failure finalization never mutates caller facts

            # Normal sealing uses the real ZIP writer/CRC/member readback. No
            # public file exists while that readback is still in progress.
            out = root / 'normal'
            original_verify = helper._verify_zip
            verified = []
            def observe_verify(path, members):
                self.assertFalse((out / 'result.json').exists())
                self.assertFalse((out / 'public-result.zip').exists())
                digest = original_verify(path, members)
                verified.append(digest)
                return digest
            with mock.patch.object(helper, '_verify_zip', observe_verify):
                result = helper.seal_result(out, passed_report, readme)
            self.assertTrue(result['report']['passed'])
            self.assertEqual(result['host_exit'], 0)
            self.assertEqual(verified, [result['archive_sha256']])
            self.assertEqual(result['archive'], out / 'public-result.zip')
            with zipfile.ZipFile(result['archive']) as stream:
                self.assertEqual(stream.namelist(), ['result.json', 'README.txt'])
                self.assertIsNone(stream.testzip())
                self.assertEqual(stream.read('result.json'), (out / 'result.json').read_bytes())
                self.assertEqual(stream.read('README.txt'), readme)
            self.assertEqual((out / 'private-seal/candidate-result.zip').read_bytes(), result['archive'].read_bytes())
            self.assertFalse(json.loads((root / 'pin-fail/result.json').read_bytes())['passed'])
        print('HOST_ARTIFACT_SEAL_V1_FAULT_CONTRACT=1')


if __name__ == '__main__':
    unittest.main()
