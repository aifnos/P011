"""One new v57-r3 method covers only the four unfinished v57 subcases.

The original v57 method remains overall FAIL; its 38 completed subcases are
not rerun or promoted to a whole-method pass. The r2 deadline precondition
failed before these four predicates ran. Fixed GO55 and GO56-r2 domains
use the same original Loader/F._entry/Bootstrap constructor and syscall model.
Only Store rows replacement and source change in actual model io.pid run.
The first refuses with the original GoStoreError; the second transparently
forwards actual pid and Loader.authenticate then original post-PID D refuses.
No Bootstrap.run, reserve, actors/pins, RF, child launch or restore runs.
Synthetic PID is denial-only, never reserved/canonical/grant/physical evidence.
Original sources, six helper definitions, quotas and all original caps remain.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket
import stat
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLANS = (
    ('v55', 'host/go_baseline_timing_v55_source_manifest.json',
        '32d1721de72d24a6c0f9759922a5b9dd461ee362fc22d588c3db2e7179a8ce69', 3951),
    ('v56r2', 'host/go_owner_coalesce_v56_r2_source_manifest.json',
        'a7d6e6704b04cd606b3a1da7c48ca7b5fe86eb118a934686cb96fd6beba862bf', 3954))
DELTA_MODULES = ('mta_go_executor', 'mta_go_bootstrap_store', 'mta_go_native')
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
STOCK = (
    ('/usr/bin/Z03', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
        'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('/usr/bin/control_engine', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/control_engine',
        '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('/usr/bin/zyb_z03_launch.sh', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/zyb_z03_launch.sh',
        '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913))
WPA = ('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
    'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 1351192)
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')


def _fixed(path, sha, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('HOST fixed input changed')
    return raw


def _definitions():
    """No old imports/module body/ClassDef/TestCase/method is executed."""
    tree = ast.parse(_fixed(HELPER, HELPER_SHA, HELPER_BYTES), filename=HELPER)
    chosen = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    if tuple(node.name for node in chosen) != FUNCTIONS:
        raise ValueError('HOST helper definition inventory')
    domain = dict(globals())
    exec(compile(ast.Module(body=chosen, type_ignores=[]), HELPER, 'exec'), domain)
    return domain


def _inputs():
    graphs, prior = [], None
    for label, path, sha, size in PLANS:
        tree = json.loads(_fixed(path, sha, size))
        if (type(tree) is not dict or set(tree) != {'schema', 'sources'} or
                tree['schema'] != 'go-frequency-v46-host' or len(tree['sources']) != 17 or
                len({r['module'] for r in tree['sources']}) != 17):
            raise ValueError('HOST fixed graph')
        rows = tree['sources']
        if prior is not None:
            changes = []
            for before, current in zip(prior, rows):
                if before['module'] != current['module']: raise ValueError('HOST graph order changed')
                if before != current: changes.append(current['module'])
            if tuple(changes) != DELTA_MODULES: raise ValueError('HOST unexpected lineage delta')
        source = {r['module']: _fixed(r['path'], r['sha256'], r['bytes']) for r in rows}
        source['HOST_WPA'] = _fixed(*WPA)
        graphs.append((label, rows, source))
        prior = rows
    stock = {path: _fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go_owner_coalesce_v57_r3_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return graphs, stock, model

def _runtime(definitions, rows, source, stock, model, stack):
    definitions['tripwires'](stack)
    io, modules, deployment, loader, executor, created = definitions['load_model'](
        rows, source, stock, model, None, stack)
    entry = executor._entry(deployment, model.UNTIL, repr(model.UNTIL),
        '--go-bootstrap', io.clock, io)
    runtime = modules['mta_go_bootstrap'].GoBootstrap(deployment, entry, clock=io.clock)
    if created != [runtime]: raise AssertionError('HOST original constructor inventory')
    return io, modules, deployment, loader, runtime



class GoOwnerCoalesceV57R3Tests(unittest.TestCase):
    def test_store_rows_and_post_pid_refusals_preserve_original_entry_slice(self):
        definitions = _definitions()
        graphs, stock, model = _inputs()
        cases = ('store_rows_changed', 'pid_changes_source')
        completed, refused, pid_measurements = [], 0, {}
        for label, rows, source in graphs:
            for case in cases:
                with self.subTest(graph=label, case=case), ExitStack() as stack:
                    io, modules, deployment, loader, runtime = _runtime(
                        definitions, rows, source, stock, model, stack)
                    native, store, entry = runtime.native, runtime.store, runtime.entry
                    original_accounting, original_budget, original_reader = entry.accounting, entry.budget, entry.reader
                    original_native_rows, original_store_rows = native.rows, store.rows
                    original_until, original_text = model.UNTIL, repr(model.UNTIL)
                    original_io_deadline = original_accounting._io_deadline
                    self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
                    self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
                    self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
                    self.assertIs(loader.runtime, runtime)
                    self.assertIs(store._native_original, native)
                    self.assertIs(original_accounting._proc_reader, original_reader)
                    self.assertIs(original_budget._store, original_accounting)
                    self.assertIs(original_budget._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
                    self.assertIs(original_budget._session_profile, modules['mta_p2p_client_init'].FORMAL_SESSION_PROFILE)
                    self.assertEqual(tuple(row['module'] for row in rows),
                        tuple(name for name, value in loader.original_modules))
                    self.assertEqual(original_until, loader.original_until)
                    self.assertEqual(original_text, loader.original_until_text)
                    self.assertEqual(min(original_until, io.clock() + 3.0), original_io_deadline)
                    self.assertTrue(original_reader.history_closed())
                    self.assertTrue(all(r['closed'] and not r['unknown'] for r in loader.owner.rows))
                    self.assertIsNone(loader.failure)
                    self.assertIsNone(store.current)
                    self.assertFalse(store.attempted)
                    self.assertFalse(store.restore_attempted)
                    self.assertFalse(store.publication_unknown)
                    self.assertEqual([], store.rows)
                    self.assertEqual([], native.rows)

                    # Counter records calls but always returns/raises from the actual
                    # original Loader method; it cannot turn authentication successful.
                    original_authenticate = type(loader).authenticate
                    auth_calls, mutation_calls, pid_calls = [], [], []
                    def authenticate_forward(actual_loader, value):
                        if actual_loader is loader:
                            auth_calls.append((value, actual_loader.failure))
                        return original_authenticate(actual_loader, value)
                    stack.enter_context(mock.patch.object(type(loader), 'authenticate', authenticate_forward))
                    io_before = list(io.calls)
                    poison = modules['mta_go_deployment'].GoSourceError('host_source_changed')

                    if case == 'pid_changes_source':
                        # Explicit synthetic denial fixture, not an actual reservation.
                        store.pid = io.pid()
                        original_pid = io.pid
                        def pid_forward():
                            pid_calls.append('pid')
                            value = original_pid()
                            mutation_calls.append('pid')
                            loader.failure = poison
                            return value
                        stack.enter_context(mock.patch.object(io, 'pid', pid_forward))
                        self.assertEqual(100, store.pid)
                        self.assertFalse(store.attempted)
                        self.assertIsNone(store.current)
                    if case == 'store_rows_changed':
                        store.rows = []
                        error_type = modules['mta_go_bootstrap_store'].GoStoreError
                        error_code = 'wrong_owner'
                    elif case == 'pid_changes_source':
                        pass  # Original model pid forward/poison hook already installed.
                        error_type = modules['mta_go_deployment'].GoSourceError
                        error_code = 'foreign_source_deployment'
                    else:
                        raise AssertionError('HOST unlisted affected case')
                    auth_calls[:] = []
                    with native.mutex, self.assertRaises(error_type) as caught:
                        native._owner()
                    self.assertIs(type(caught.exception), error_type)
                    self.assertEqual(error_code, caught.exception.code)
                    self.assertTrue(all(value is deployment for value, unused in auth_calls))
                    refused += 1
                    if case == 'pid_changes_source':
                        self.assertIs(loader.failure, poison)
                        self.assertEqual(['pid'], mutation_calls)
                        self.assertEqual(['pid'], pid_calls)
                        expected_auth = 4 if label == 'v55' else 2
                        self.assertEqual(expected_auth, len(auth_calls))
                        self.assertTrue(all(failed is None for unused, failed in auth_calls[:-1]))
                        self.assertIs(auth_calls[-1][1], poison)
                        self.assertIs(store.rows, original_store_rows)
                        pid_measurements[label] = len(auth_calls)
                    else:
                        self.assertIsNone(loader.failure)
                        self.assertEqual([], mutation_calls)
                        self.assertEqual([], pid_calls)
                        self.assertEqual(3 if label == 'v55' else 1, len(auth_calls))
                        self.assertTrue(all(failed is None for unused, failed in auth_calls))
                        self.assertIsNot(store.rows, original_store_rows)
                        self.assertEqual([], store.rows)
                        self.assertIsNone(store.pid)
                    self.assertEqual(io_before, io.calls)
                    self.assertEqual(1.0, io.clock())
                    self.assertEqual(original_until, native.until)
                    self.assertEqual(original_until, entry.until)
                    self.assertEqual(original_until, store.until)
                    self.assertEqual(original_until, loader.original_until)
                    self.assertEqual(original_text, loader.original_until_text)
                    self.assertEqual(original_io_deadline, original_accounting._io_deadline)
                    self.assertIsNone(native._scope)
                    self.assertIsNone(store.scope_until)
                    self.assertIs(native.rows, original_native_rows)
                    self.assertEqual([], original_native_rows)
                    self.assertEqual([], original_store_rows)
                    self.assertIsNone(store.current)
                    self.assertEqual((), store._canonical_history)
                    self.assertEqual((), store._fd_history)
                    self.assertFalse(store.attempted)
                    self.assertFalse(store.restore_attempted)
                    self.assertFalse(store.publication_unknown)
                    self.assertIs(entry.accounting, original_accounting)
                    self.assertIs(entry.budget, original_budget)
                    self.assertIs(entry.reader, original_reader)
                    self.assertFalse(original_accounting._attempted)
                    self.assertFalse(original_accounting._opened)
                    self.assertIsNone(original_accounting._canonical)
                    self.assertTrue(original_reader.history_closed())
                    self.assertTrue(all(r['closed'] and not r['unknown'] for r in loader.owner.rows))
                    self.assertEqual({}, io.live)
                    self.assertEqual({}, io.children)
                    self.assertEqual([], runtime.launcher._tickets)
                    self.assertEqual(0, io.create_count)
                    self.assertEqual(0, io.delete_count)
                    self.assertFalse(native._create_called)
                    self.assertFalse(native._group_submit_called)
                    self.assertFalse(native._delete_called)
                    self.assertFalse(runtime.started)
                    completed.append((label, case))
        self.assertEqual(4, len(completed))
        self.assertEqual(4, refused)
        self.assertEqual({'v55': 4, 'v56r2': 2}, pid_measurements)
        print('GO_OWNER_COALESCE_V57_R3_HOST_PASS domains=2 affected_cases=4 refused=4 '
            'pid_auth55=4 pid_auth56r2=2 rf_calls=0')


if __name__ == '__main__':
    unittest.main()
