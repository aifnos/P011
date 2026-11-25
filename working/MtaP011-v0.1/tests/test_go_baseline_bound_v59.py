"""One new v59 bounded-stage HOST method; no baseline/run/RF is executed.

Only the fixed GO58 actual Loader/F Entry/Bootstrap constructor domain runs
under the original syscall/FD/Proc/clock model. Nine fresh independent cases
call original _stage and Native._begin/_check: stage15 normal/clamp, expiry,
caller stop, invalid0/21/bool, issued-stage expiry and actual clock regression.
Original until301, all other stages/cleanup, quotas and gates remain. AST
source comparison checks only run's first baseline10 literal became15; it is
not proof that either real baseline snapshot or later reserve completes.
No _record/FD factory, actors/pins, reserve, run, fork, RF or restore runs.
The initial entry accounting deadline is the actual clock1+3 slice4, not11.
Existing scope+5 local close caps would numerically follow the changed scope;
this test does not claim those derived numbers are unchanged or grant closure.
Only the original six helper FunctionDefs execute, never old test methods.
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
PLAN = 'host/go_baseline_budget_v58_source_manifest.json'
PLAN_SHA = '0c987d6e667a0d4adce867b121493436f9bf2ba11380acc97e11efbf320a30a0'
PLAN_BYTES = 3957
PARENT_PLAN = 'host/go_owner_coalesce_v56_r2_source_manifest.json'
PARENT_PLAN_SHA = 'a7d6e6704b04cd606b3a1da7c48ca7b5fe86eb118a934686cb96fd6beba862bf'
PARENT_PLAN_BYTES = 3954
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


def _stage_source_bounds(old_raw, new_raw):
    """AST only: changed run baseline literal, all original class bodies remain."""
    old_tree, new_tree = ast.parse(old_raw), ast.parse(new_raw)
    classes = []
    for tree in (old_tree, new_tree):
        found = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GoBootstrap']
        if len(found) != 1: raise ValueError('HOST bootstrap class changed')
        classes.append(found[0])
    runs = []
    for cls in classes:
        found = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'run']
        if len(found) != 1: raise ValueError('HOST run changed')
        runs.append(found[0])
    calls = []
    for run in runs:
        rows = sorted((n for n in ast.walk(run) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
            and n.func.value.id == 'self' and n.func.attr == '_stage'),
            key=lambda n: (n.lineno, n.col_offset))
        if any(len(n.args) != 1 or n.keywords for n in rows): raise ValueError('HOST stage shape changed')
        calls.append(rows)
    if ([ast.literal_eval(n.args[0]) for n in calls[0]] != [10, 5, 10, 20, 20] or
            [ast.literal_eval(n.args[0]) for n in calls[1]] != [15, 5, 10, 20, 20]):
        raise ValueError('HOST stage constants changed')
    calls[0][0].args[0] = ast.Constant(value=15)
    if ast.dump(classes[0], include_attributes=False) != ast.dump(classes[1], include_attributes=False):
        raise ValueError('HOST other bootstrap body changed')


def _inputs():
    parent = json.loads(_fixed(PARENT_PLAN, PARENT_PLAN_SHA, PARENT_PLAN_BYTES))
    current = json.loads(_fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    for tree in (parent, current):
        if (type(tree) is not dict or set(tree) != {'schema', 'sources'} or
                tree['schema'] != 'go-frequency-v46-host' or len(tree['sources']) != 17 or
                len({r['module'] for r in tree['sources']}) != 17):
            raise ValueError('HOST fixed graph')
    if any(before['module'] != after['module'] for before, after in zip(parent['sources'], current['sources'])):
        raise ValueError('HOST graph order changed')
    changes = [after['module'] for before, after in zip(parent['sources'], current['sources']) if before != after]
    if changes != ['mta_go_bootstrap']: raise ValueError('HOST unexpected lineage delta')
    rows = current['sources']
    source = {r['module']: _fixed(r['path'], r['sha256'], r['bytes']) for r in rows}
    original = next(r for r in parent['sources'] if r['module'] == 'mta_go_bootstrap')
    _stage_source_bounds(_fixed(original['path'], original['sha256'], original['bytes']), source['mta_go_bootstrap'])
    source['HOST_WPA'] = _fixed(*WPA)
    stock = {path: _fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go_baseline_bound_v59_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model

def _runtime(definitions, rows, source, stock, model, stack):
    definitions['tripwires'](stack)
    io, modules, deployment, loader, executor, created = definitions['load_model'](
        rows, source, stock, model, None, stack)
    entry = executor._entry(deployment, model.UNTIL, repr(model.UNTIL),
        '--go-bootstrap', io.clock, io)
    runtime = modules['mta_go_bootstrap'].GoBootstrap(deployment, entry, clock=io.clock)
    if created != [runtime]: raise AssertionError('HOST original constructor inventory')
    return io, modules, deployment, loader, runtime




class GoBaselineBoundV59Tests(unittest.TestCase):
    def test_stage15_original_until_clamp_refusals_and_clock_without_radio(self):
        definitions = _definitions()
        rows, source, stock, model = _inputs()
        cases = ('normal15', 'clamp_original', 'expired_original', 'caller_stop',
            'invalid_zero', 'invalid_twentyone', 'invalid_bool', 'issued_stage_expired', 'clock_regressed')
        completed, refusals, issued = [], 0, []
        for case in cases:
            with self.subTest(case=case), ExitStack() as stack:
                io, modules, deployment, loader, runtime = _runtime(
                    definitions, rows, source, stock, model, stack)
                native, store, entry = runtime.native, runtime.store, runtime.entry
                accounting, budget, reader = entry.accounting, entry.budget, entry.reader
                original_until, original_text = model.UNTIL, repr(model.UNTIL)
                initial_deadline, expected_scope = accounting._io_deadline, None
                expected_deadline = initial_deadline
                original_native_rows, original_store_rows = native.rows, store.rows
                original_native_failure, original_runtime_failure = native.failure, runtime.failure
                original_last, original_native_last = runtime.last, native.last
                self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
                self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
                self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
                self.assertIs(loader.runtime, runtime)
                self.assertIs(store._native_original, native)
                self.assertIs(budget._store, accounting)
                self.assertIs(accounting._proc_reader, reader)
                self.assertIs(budget._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
                self.assertIs(budget._session_profile, modules['mta_p2p_client_init'].FORMAL_SESSION_PROFILE)
                self.assertEqual(301.0, original_until)
                self.assertEqual('301.0', original_text)
                self.assertEqual(min(original_until, io.clock() + 3.0), initial_deadline)
                self.assertEqual(4.0, initial_deadline)
                self.assertIsNone(loader.failure)
                self.assertIsNone(store.current)
                self.assertIsNone(native._scope)
                self.assertIsNone(store.scope_until)
                self.assertTrue(reader.history_closed())
                self.assertTrue(all(r['closed'] and not r['unknown'] for r in loader.owner.rows))
                io_before = list(io.calls)
                error_type = modules['mta_go_deployment'].GoSourceError
                if case in ('normal15', 'clamp_original', 'issued_stage_expired', 'clock_regressed'):
                    if case == 'clamp_original': io.clock.value = 299.0
                    with native.mutex:
                        end = runtime._stage(15)
                        issued.append(end)
                        expected_deadline = end
                        self.assertEqual(301.0 if case == 'clamp_original' else 16.0, end)
                        if case != 'clock_regressed':
                            self.assertEqual(end, native._begin(end))
                            expected_scope = end
                            self.assertEqual(io.clock(), native._check())
                    if case == 'issued_stage_expired':
                        io.clock.value = 16.0
                        with native.mutex, self.assertRaises(error_type) as caught:
                            native._check()
                        self.assertIs(type(caught.exception), error_type)
                        self.assertEqual('deadline', caught.exception.code)
                        refusals += 1
                    elif case == 'clock_regressed':
                        io.clock.value = 0.5
                        with native.mutex, self.assertRaises(error_type) as caught:
                            runtime._stage(15)
                        self.assertIs(type(caught.exception), error_type)
                        self.assertEqual('clock_regressed', caught.exception.code)
                        refusals += 1
                    self.assertFalse(runtime.stop_requested)
                elif case in ('expired_original', 'caller_stop'):
                    if case == 'expired_original': io.clock.value = original_until
                    else: runtime.stop_requested = True
                    with native.mutex, self.assertRaises(error_type) as caught:
                        runtime._stage(15)
                    self.assertIs(type(caught.exception), error_type)
                    self.assertEqual('stop_requested', caught.exception.code)
                    self.assertTrue(runtime.stop_requested)
                    refusals += 1
                elif case in ('invalid_zero', 'invalid_twentyone', 'invalid_bool'):
                    seconds = {'invalid_zero': 0, 'invalid_twentyone': 21, 'invalid_bool': True}[case]
                    with native.mutex, self.assertRaises(error_type) as caught:
                        runtime._stage(seconds)
                    self.assertIs(type(caught.exception), error_type)
                    self.assertEqual('invalid_active_stage', caught.exception.code)
                    self.assertIs(runtime.last, original_last)
                    self.assertIs(native.last, original_native_last)
                    self.assertFalse(runtime.stop_requested)
                    refusals += 1
                else:
                    raise AssertionError('HOST unlisted bounded-stage case')
                self.assertEqual(io_before, io.calls)
                self.assertEqual(expected_deadline, accounting._io_deadline)
                self.assertEqual(expected_scope, native._scope)
                self.assertEqual(original_until, runtime.until)
                self.assertEqual(original_until, native.until)
                self.assertEqual(original_until, entry.until)
                self.assertEqual(original_until, store.until)
                self.assertEqual(original_until, loader.original_until)
                self.assertEqual(original_text, loader.original_until_text)
                self.assertIsNone(loader.failure)
                self.assertIs(native.failure, original_native_failure)
                self.assertIs(runtime.failure, original_runtime_failure)
                self.assertIsNone(runtime.cleanup_until)
                self.assertIsNone(entry.cleanup_until)
                self.assertIsNone(store.restore_until)
                self.assertIsNone(store.scope_until)
                self.assertFalse(runtime.restore_attempted)
                self.assertFalse(store.attempted)
                self.assertFalse(store.restore_attempted)
                self.assertFalse(store.publication_unknown)
                self.assertIsNone(store.current)
                self.assertEqual((), store._canonical_history)
                self.assertEqual((), store._fd_history)
                self.assertIs(native.rows, original_native_rows)
                self.assertIs(store.rows, original_store_rows)
                self.assertEqual([], original_native_rows)
                self.assertEqual([], original_store_rows)
                self.assertEqual((), native._history)
                self.assertFalse(accounting._attempted)
                self.assertFalse(accounting._opened)
                self.assertIsNone(accounting._canonical)
                self.assertTrue(reader.history_closed())
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
                self.assertFalse(runtime.group_confirmed)
                completed.append(case)
        self.assertEqual(list(cases), completed)
        self.assertEqual([16.0, 301.0, 16.0, 16.0], issued)
        self.assertEqual(7, refusals)
        print('GO_BASELINE_BOUND_V59_HOST_PASS cases=9 issuances=4 refused=7 '
            'normal_end=16 clamped_end=301 original_until=301 rf_calls=0')


if __name__ == '__main__':
    unittest.main()
