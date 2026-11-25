"""One new private finish-parent DATA test; SOURCE until ROOT alone runs it.

Actual p011_json definitions and unchanged selected Bridge86 definitions run in
a private HOST definition domain. F84 is pinned and SOURCE-inspected only: its
test, lifecycle, restore and FD2 emission are not executed. The report below is
an explicit static F84-shape example, not a native Journal or finish receipt.

Every Popen object, wait return, FD metadata, stdout/stderr EOF and binding is
MODELED. No real process, pipe, worker, close, network observer, key free, State,
restoration or admission is established. Only the new pure decoder/reap capture/
original-tail checks/report accessor run; they are not replaced or made True.
Sixteen independent domains cover two accepted DATA reports, two missing-EOF
deferrals, ten strict refusals and two explicit unavailable lines. A report can
coexist with an original business failure/nonzero exit and never changes it.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
INPUTS = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_go_send_bridge', 'candidate/go-send-finish-parent-v86/runtime/mta_go_send_bridge.py', 75404,
     '964aaa1dff1f35bf780dd03c2ae094bbedf051028a3ca85f99cff660b5f99516'),
    ('f84_source_only', 'candidate/go-send-finish-v84/runtime/mta_go_executor.py', 53767,
     'cb9ef6d0ef97fbaca77c873245184d9dc5f0ee97c381790bb1102dc640a5623d'),
)
METHOD = 'test_original_child_tail_data_and_refusals'
MARKER = ('HOST86_FINISH_PARENT new_methods=1 old_methods=0 cases=16 '
          'child_tail_model=true device=false phone=false\n')
CASES = ('valid', 'business_error_nonzero', 'missing_stdout_eof', 'missing_stderr_eof',
         'missing_reap', 'foreign_process', 'large_first_line', 'large_stderr',
         'noncanonical', 'wrong_binding', 'wrong_child', 'bad_flags', 'bad_metadata',
         'default_unavailable', 'returned_unavailable', 'unknown_pipe')
REFUSALS = {
    'missing_reap': 'finish_original_child_tail',
    'foreign_process': 'finish_original_child_tail',
    'large_first_line': 'finish_data_first_line',
    'large_stderr': 'finish_original_child_tail',
    'noncanonical': 'finish_data_noncanonical',
    'wrong_binding': 'finish_data_binding',
    'wrong_child': 'finish_data_inventory',
    'bad_flags': 'finish_data_inventory',
    'bad_metadata': 'finish_data_binding',
    'unknown_pipe': 'finish_original_eof',
}


def _inputs():
    result = {}
    for name, path, size, digest in INPUTS:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('HOST fixed finish-parent source changed')
        result[name] = raw
    return result


def _domain(source):
    """Private definition execution, not a production Loader or old test."""
    bundled = types.ModuleType('p011_json')
    bundled.__dict__['__builtins__'] = dict(vars(builtins))
    exec(compile(source['p011_json'], 'HOST pinned p011_json', 'exec'), bundled.__dict__)
    bridge = types.ModuleType('mta_go_send_bridge')
    bridge.__dict__.update(__builtins__=dict(vars(builtins)), json=bundled,
                          os=os, re=re, stat=stat, math=math, types=types,
                          threading=threading)
    names = ('SendBridgeError', '_fail', '_number', '_uint', '_hex', '_binding',
             '_finish_number_v86', '_finish_metadata_v86', '_finish_wire_v86',
             '_finish_decode_v86', '_FinishReportV86', '_Fd', 'GoSendBridge')
    assignments = ('MAX_PRIVATE_ERROR', 'MAX_FINISH_DATA_V86', 'MAX_OUTPUT_BYTES',
                   '_BIND_KEYS', '_FINISH_KEYS_V86', '_FINISH_BIND_KEYS_V86',
                   '_FINISH_JOURNAL_KEYS_V86', '_INVENTORY')
    counts, nodes = {name: 0 for name in names + assignments}, []
    tree = ast.parse(source['mta_go_send_bridge'].decode('utf-8'), filename='HOST actual Bridge86')
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            nodes.append(node)
            counts[node.name] += 1
        elif isinstance(node, ast.Assign):
            matched = {part.id for target in node.targets for part in ast.walk(target)
                       if isinstance(part, ast.Name)}.intersection(assignments)
            if matched:
                nodes.append(node)
                for name in matched:
                    counts[name] += 1
    if any(count != 1 for count in counts.values()):
        raise ValueError('HOST selected Bridge86 definition changed')
    selected = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected), 'HOST actual Bridge86 definitions', 'exec'),
         bridge.__dict__)
    return bridge


class _ProcessModel(object):
    """No actual Popen/exit/absence/child identity claim is made here."""
    def __init__(self, pid):
        self.pid = pid
        self.wait = mock.Mock(side_effect=AssertionError('HOST modeled wait must not run'))


class _TailModel(object):
    def __init__(self, bridge):
        self.bridge = bridge
        self.value = object.__new__(bridge.GoSendBridge)
        value = self.value
        value.binding = {'run': '1' * 32, 'manifest': '2' * 64, 'task': 'V86_HOST_MODEL_TASK',
            'nonce': '3' * 32, 'native_epoch': 1, 'operation_epoch': 1,
            'until': '301.0', 'parent_pid': 101}
        value.nonce = value.binding['nonce']
        value.prepared = types.SimpleNamespace(task_id=value.binding['task'])
        stores = types.ModuleType('mta_go_bootstrap_store')
        stores.SCHEMA = 'p011-go-typed-live-v72'
        manifest = types.SimpleNamespace(run_token=value.binding['run'], candidate_sha='4' * 64)
        value.deployment = types.SimpleNamespace(manifest=manifest,
            manifest_sha=value.binding['manifest'], modules={'mta_go_bootstrap_store': stores},
            loader=types.SimpleNamespace(original_until_text='301.0'))
        value.process = _ProcessModel(201)
        value._process_original, value._process_pid = value.process, value.process.pid
        value.process_called, value.process_unknown, value.process_reaped = True, False, True
        value.returncode = 0
        value.clock = mock.Mock(side_effect=AssertionError('HOST no finish-parent clock'))
        value.rows = []
        for index, role in enumerate(('stdin', 'stdout', 'stderr')):
            row = bridge._Fd(role)  # Actual pure constructor; all following facts MODEL.
            row.fd, row.value = 30 + index, object()
            row.metadata = (1, 100 + index, stat.S_IFIFO | 0o600, 0, 0, 1, 0, 1, 1)
            row.returned, row.unknown = True, False
            value.rows.append(row)
            setattr(value, {'stdin': 'input', 'stdout': 'output', 'stderr': 'error_pipe'}[role], row)
        value._finish_source_originals_v86 = (value, value.binding, tuple(sorted(value.binding.items())),
            value.deployment, value.deployment.loader, value.process, value._process_pid,
            value.input, value.output, value.error_pipe)
        value.output_eof = value.error_eof = True
        value._finish_stdout_eof_v86 = (value.output, value.output.fd, value.output.value,
                                       value.output.metadata, b'')
        value._finish_stderr_eof_v86 = (value.error_pipe, value.error_pipe.fd, value.error_pipe.value,
                                       value.error_pipe.metadata, b'')
        value._finish_reap_v86 = None
        value._finish_attempted_v86 = False
        value._finish_raw_v86 = value._finish_report_v86 = value._finish_failure_v86 = None
        value._finish_unavailable_v86 = None
        value.stdout_raw, value._buffer = b'', b''
        value.failure = RuntimeError('HOST retained original primary')
        value.key, value.closed, value.result = object(), False, None
        value._key_release_original = {'unknown': True, 'error': RuntimeError('HOST original key close failure')}
        value._key_generation_original = {'called': True, 'unknown': True}
        # Static F84-shape DATA. There is no actual Journal/raw/fsync/native free.
        self.data = {'schema': 'p011-go-finish-data-v84', 'provenance': 'returned_restore',
            'binding': {name: value.binding[name] for name in bridge._FINISH_BIND_KEYS_V86},
            'journal': {'schema': stores.SCHEMA, 'phase': 'reconciled', 'generation': 5,
                'sha256': '7' * 64, 'bytes': 1200,
                'metadata': [1, 300, stat.S_IFREG | 0o600, 0, 0, 1, 1200, 1, 1],
                'facts_key': [stores.SCHEMA, value.binding['run'], manifest.candidate_sha,
                    value.binding['task'], '00000000-0000-0000-0000-000000000001', 1.0, 301.0]},
            'cleanup_until': 340.0, 'finished_at': 320.0,
            'device_lock_metadata': [1, 400, stat.S_IFREG | 0o600, 0, 0, 1, 0, 1, 1],
            'f_actor': [201, 20, '6' * 64], 'children': [], 'inventory_counts': [8, 1],
            'business_failed_at_capture': False, 'native_full_inventory_export': False,
            'independent_restore_verified': False, 'production_admitted': False}
        self.refresh()

    def refresh(self):
        self.value.private_stderr = self.bridge._finish_wire_v86(self.data)


class GoFinishParent86Test(unittest.TestCase):
    def test_original_child_tail_data_and_refusals(self):
        source = _inputs()
        # F84 is only SOURCE-read: default unavailable is not accepted DATA.
        f84_tree = ast.parse(source['f84_source_only'].decode('utf-8'))
        helpers = [node.name for node in f84_tree.body if isinstance(node, ast.FunctionDef)]
        self.assertIn('_finish_data_v84', helpers)
        self.assertIn('_capture_finish_data_v84', helpers)
        self.assertIn(b'GOFINISH84=unavailable provenance=default_run', source['f84_source_only'])
        complete, accepted, deferred, refused, unavailable = [], 0, 0, 0, 0
        for case in CASES:
            with self.subTest(case=case):
                bridge = _domain(source)
                model = _TailModel(bridge)
                value = model.value
                if case == 'business_error_nonzero':
                    value.returncode = 1
                    model.data['business_failed_at_capture'] = True
                    model.refresh()
                    value.private_stderr += b'PRIMARY\nHOST modeled business failure\n'
                elif case == 'missing_stdout_eof':
                    value.output_eof, value._finish_stdout_eof_v86 = False, None
                elif case == 'missing_stderr_eof':
                    value.error_eof, value._finish_stderr_eof_v86 = False, None
                elif case == 'large_first_line':
                    value.private_stderr = b'GOFINISH84=' + b'X' * 4096 + b'\n'
                elif case == 'large_stderr':
                    value.private_stderr += b'X' * 16384
                elif case == 'noncanonical':
                    value.private_stderr = value.private_stderr.replace(b'{', b'{ ', 1)
                elif case == 'wrong_binding':
                    model.data['binding']['nonce'] = 'a' * 32
                    model.refresh()
                elif case == 'wrong_child':
                    model.data['f_actor'][0] = 202
                    model.refresh()
                elif case == 'bad_flags':
                    model.data['independent_restore_verified'] = True
                    model.refresh()
                elif case == 'bad_metadata':
                    model.data['journal']['metadata'][1] = True
                    model.refresh()
                elif case == 'default_unavailable':
                    value.private_stderr = b'GOFINISH84=unavailable provenance=default_run\n'
                elif case == 'returned_unavailable':
                    value.private_stderr = b'GOFINISH84=unavailable provenance=returned_restore\n'
                elif case == 'unknown_pipe':
                    value.error_pipe.unknown = True
                original_process = value.process
                original_primary, original_key, original_closed, original_result = (
                    value.failure, value.key, value.closed, value.result)
                original_key_close, original_key_generation = (
                    value._key_release_original, value._key_generation_original)
                original_stderr = value.private_stderr
                with ExitStack() as stack:
                    targets = ('os.open', 'os.read', 'os.write', 'os.close', 'os.fstat', 'os.stat',
                               'os.getpid', 'os.urandom', 'os.kill', 'threading.current_thread',
                               'threading.Thread.start', 'subprocess.Popen', 'select.select')
                    probes = [stack.enter_context(mock.patch(target,
                        side_effect=AssertionError('HOST finish-parent side effect prohibited')))
                        for target in targets]
                    bridge.GoSendBridge._retain_finish_reap_v86(value)
                    self.assertIs(value._finish_reap_v86[0], original_process)
                    if case == 'missing_reap':
                        value._finish_reap_v86 = None
                    elif case == 'foreign_process':
                        value.process = _ProcessModel(201)
                    report = bridge.GoSendBridge._capture_finish_report_v86(value)
                    current = bridge.GoSendBridge.finish_report(value)
                    for probe in probes + [value.clock, original_process.wait]:
                        self.assertEqual(probe.call_count, 0)
                self.assertIs(value.failure, original_primary)
                self.assertIs(value.key, original_key)
                self.assertIs(value.closed, original_closed)
                self.assertIs(value.result, original_result)
                self.assertIs(value._key_release_original, original_key_close)
                self.assertIs(value._key_generation_original, original_key_generation)
                self.assertIs(original_key_close['unknown'], True)
                self.assertIs(original_key_generation['unknown'], True)
                self.assertIs(value.private_stderr, original_stderr)
                if case in ('valid', 'business_error_nonzero'):
                    self.assertIs(type(report), bridge._FinishReportV86)
                    self.assertIs(current, report)
                    self.assertIs(report.raw, value._finish_raw_v86)
                    self.assertIs(report.originals, value._finish_source_originals_v86)
                    self.assertIs(report.reap, value._finish_reap_v86)
                    self.assertIs(report.stdout_eof, value._finish_stdout_eof_v86)
                    self.assertIs(report.stderr_eof, value._finish_stderr_eof_v86)
                    self.assertEqual(report.data, model.data)
                    self.assertIsNone(value._finish_failure_v86)
                    self.assertIs(report.data['independent_restore_verified'], False)
                    self.assertIs(report.data['production_admitted'], False)
                    self.assertIs(report.data['business_failed_at_capture'], case == 'business_error_nonzero')
                    self.assertEqual(value.returncode, 1 if case == 'business_error_nonzero' else 0)
                    # Outer report is immutable; mutable decoded DATA cannot be
                    # silently consumed after it no longer encodes to original raw.
                    with self.assertRaises(AttributeError):
                        report.raw = b'foreign'
                    report.data['journal']['generation'] = 6
                    self.assertIsNone(bridge.GoSendBridge.finish_report(value))
                    self.assertIs(value._finish_report_v86, report)
                    accepted += 1
                elif case in ('missing_stdout_eof', 'missing_stderr_eof'):
                    self.assertIsNone(report)
                    self.assertIsNone(current)
                    self.assertIs(value._finish_attempted_v86, False)
                    self.assertIsNone(value._finish_failure_v86)
                    self.assertIsNone(value._finish_raw_v86)
                    deferred += 1
                elif case in ('default_unavailable', 'returned_unavailable'):
                    self.assertIsNone(report)
                    self.assertIsNone(current)
                    self.assertIs(value._finish_attempted_v86, True)
                    self.assertEqual(value._finish_unavailable_v86, original_stderr)
                    self.assertIsNone(value._finish_failure_v86)
                    self.assertIsNone(value._finish_report_v86)
                    unavailable += 1
                else:
                    self.assertIsNone(report)
                    self.assertIsNone(current)
                    self.assertIs(value._finish_attempted_v86, True)
                    failure = value._finish_failure_v86
                    self.assertIs(type(failure), bridge.SendBridgeError)
                    self.assertEqual(failure.args, (REFUSALS[case],))
                    self.assertIsNone(value._finish_report_v86)
                    # Sticky failed capture does not retry or clear failure.
                    value.private_stderr = bridge._finish_wire_v86(model.data)
                    self.assertIsNone(bridge.GoSendBridge._capture_finish_report_v86(value))
                    self.assertIs(value._finish_failure_v86, failure)
                    self.assertIsNone(value._finish_report_v86)
                    refused += 1
                complete.append(case)
        self.assertEqual(complete, list(CASES))
        self.assertEqual((accepted, deferred, refused, unavailable), (2, 2, 10, 2))


if __name__ == '__main__':
    suite = unittest.TestSuite([GoFinishParent86Test(METHOD)])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if result.wasSuccessful():
        sys.stdout.write(MARKER)
    raise SystemExit(0 if result.wasSuccessful() else 1)
