"""New extracted SOURCE contracts with real HOST fixture child/pipe closure.

No production State/Owner, native helper, device, RF, phone or restore receipt
is constructed. Source-level probe methods run unchanged; the subprocesses are
the fixed HOST Python fixture. Mutation subcases touch only these HOST objects.
"""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/receive-probe-provenance-v1/runtime/mta_service.py'
CODEC = BASE / 'runtime/p011_json.py'
FIXTURE = str(BASE / 'tests/fixtures/receive_probe_fixture.py')
CODEC_PIN = (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')


def extracted_probe_scope():
    raw = SOURCE.read_bytes()
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    nodes = []
    methods = {'_probe_closed', '_probe_result', '_probe_cleanup_call', 'capability'}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in methods:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == '_CAPABILITY_CREATOR'
                for target in node.targets):
            nodes.append(node)
    if {node.name for node in nodes if isinstance(node, ast.FunctionDef)} != methods:
        raise AssertionError('Focused new probe methods missing')
    codec_raw = CODEC.read_bytes()
    if (len(codec_raw), hashlib.sha256(codec_raw).hexdigest()) != CODEC_PIN:
        raise AssertionError('Bundled JSON SOURCE changed')
    spec = importlib.util.spec_from_file_location('probe_test_p011_json', str(CODEC))
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    namespace = {'os': os, 'subprocess': subprocess, 'json': codec,
                 'threading': threading, 'types': types, '__name__': 'HOST_PROBE_EXTRACT'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), namespace)
    return namespace, len(raw), hashlib.sha256(raw).hexdigest()


class ReceiveProbeProvenanceContracts(unittest.TestCase):
    def test_original_actor_result_and_failure_inventory(self):
        namespace, size, pin = extracted_probe_scope()
        probe, result_owned = namespace['capability'], namespace['_probe_result']
        closed = namespace['_probe_closed']
        actors = []
        argv = [FIXTURE, 'valid']
        result = probe(sys.executable, argv, actors=actors)
        self.assertEqual(len(actors), 1)
        actor = actors[0]
        self.assertEqual(result, {'event': 'capabilities', 'powered': True})
        self.assertIs(actor['returned'], result)
        self.assertIs(actor['parsed'], result)
        self.assertIs(actor['out'], actor['_out_original'])
        self.assertIs(actor['err'], actor['_err_original'])
        self.assertEqual(actor['out'], b'{"event":"capabilities","powered":true}\n')
        self.assertEqual(actor['err'], b'')
        self.assertTrue(closed(actor))
        self.assertTrue(result_owned(actor, result, sys.executable, argv))
        self.assertEqual(actor['process'].returncode, 0)
        self.assertTrue(actor['process'].stdout.closed)
        self.assertTrue(actor['process'].stderr.closed)
        self.assertFalse(result_owned(actor, dict(result), sys.executable, argv))
        self.assertFalse(result_owned(actor, result, sys.executable, [FIXTURE, 'nonzero']))
        mutation_cases = 2
        original_value = result['powered']
        result['powered'] = False
        self.assertFalse(result_owned(actor, result, sys.executable, argv))
        result['powered'] = original_value
        self.assertTrue(result_owned(actor, result, sys.executable, argv))
        mutation_cases += 1
        changes = {'out': b'{}\n', 'err': b'changed', 'parsed': dict(result),
            'returned': dict(result), 'creator': object(), 'process': object(),
            'stdout': object(), 'stderr': object(), 'returncode': 3,
            'actors': list(actors), 'argv': list(actor['argv'])}
        for field, changed in changes.items():
            with self.subTest(mutation=field):
                original = actor[field]
                try:
                    actor[field] = changed
                    self.assertFalse(result_owned(actor, result, sys.executable, argv))
                finally:
                    actor[field] = original
                self.assertTrue(result_owned(actor, result, sys.executable, argv))
                mutation_cases += 1
        argv.append('not-original')
        self.assertFalse(result_owned(actor, result, sys.executable, argv))
        argv.pop()
        self.assertTrue(result_owned(actor, result, sys.executable, argv))
        mutation_cases += 1
        actors.remove(actor)
        self.assertFalse(result_owned(actor, result, sys.executable, argv))
        actors.append(actor)
        self.assertTrue(result_owned(actor, result, sys.executable, argv))
        mutation_cases += 1
        failure_modes = ('nonzero', 'stderr', 'invalid', 'multiline', 'oversize', 'list', 'wait')
        failure_cases = 0
        for mode in failure_modes:
            with self.subTest(child=mode):
                child_args = [FIXTURE, mode]
                prior = len(actors)
                returned = probe(sys.executable, child_args, actors=actors)
                self.assertEqual(len(actors), prior + 1)
                failed = actors[-1]
                self.assertIs(failed['returned'], returned)
                self.assertTrue(closed(failed))
                self.assertIsNotNone(failed['process'].returncode)
                self.assertTrue(failed['stdout'].closed)
                self.assertTrue(failed['stderr'].closed)
                self.assertFalse(result_owned(failed, returned, sys.executable, child_args))
                if mode == 'nonzero':
                    self.assertEqual(failed['returncode'], 7)
                    self.assertEqual(failed['out'], b'{"event":"capabilities","powered":true}\n')
                elif mode == 'stderr':
                    self.assertEqual(failed['err'], b'HOST fixture warning\n')
                elif mode == 'wait':
                    self.assertIsInstance(failed['failure'], subprocess.TimeoutExpired)
                    self.assertTrue(failed['cleanup_calls'])
                    self.assertFalse(failed['cleanup_failures'])
                failure_cases += 1
        self.assertEqual(len(actors), 1 + len(failure_modes))
        self.assertTrue(all(closed(row) for row in actors))
        print('RECEIVE_PROBE_PROVENANCE_CONTRACTS=' + repr(dict(
            valid_children=1, failure_children=failure_cases, mutation_subcases=mutation_cases,
            actual_extracted_functions=4, source_bytes=size, source_sha256=pin,
            original_child_pipes_closed=True, full_graph=False, device=False,
            native=False, rf=False, admission=False)), flush=True)
