"""One unique v57 guarded owner-authentication causal HOST component method.

Two fixed actual GO17 domains load through the original Loader/F._entry/
Bootstrap constructor under the pinned Linux/FD/Proc/clock model. Only Native
_owner/_check and original Entry/Store source predicates are exercised. No
Bootstrap.run, Store.reserve, actors/pins, RF, child launch or restore runs.
Twenty-one fresh cases per graph (42 isolated cases) compare v55 with v56-r2:
original authentication calls are transparently counted by forwarding the
actual Loader method, including the Store post-PID entry reauthentication.
Dynamic ticket/Budget/Reader/equality and Entry/Store wrapper callbacks must
fall back to old wrappers.
A synthetic PID is only a denial fixture; no reserved Store/canonical/grant or
physical closure follows from it. All original gates, quotas and caps remain.
The six old FunctionDefs load as definitions only, never old TestCases/methods.
PC archived bytes are actual; modeled Python/CLI/OS are not P011 evidence.
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
    model = types.ModuleType('HOST_go_owner_coalesce_v57_syscall_model')
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


class GoOwnerCoalesceV57Tests(unittest.TestCase):
    def test_original_owner_auth_coalescence_and_fallback_refusals_without_radio(self):
        definitions = _definitions()
        graphs, stock, model = _inputs()
        cases = ('normal_components', 'module_replaced', 'source_failed',
            'native_owner_changed', 'native_rows_changed', 'native_history_changed',
            'entry_reader_changed', 'entry_budget_changed', 'entry_accounting_changed',
            'store_owner_changed', 'store_rows_changed', 'ticket_changes_source', 'budget_context_changes_source',
            'reader_owns_changes_source', 'foreign_eq_changes_source', 'pid_changes_source',
            'entry_wrapper_changes_source', 'store_wrapper_changes_source',
            'clock_regressed', 'scope_expired', 'stop_requested')
        completed, refused, measurements = [], 0, {}
        callback_cases = ('ticket_changes_source', 'budget_context_changes_source', 'reader_owns_changes_source',
            'foreign_eq_changes_source', 'pid_changes_source', 'entry_wrapper_changes_source',
            'store_wrapper_changes_source')
        expected_codes = {
            'module_replaced': 'foreign_source_deployment', 'source_failed': 'foreign_source_deployment',
            'native_owner_changed': 'native_owner_changed', 'native_rows_changed': 'native_owner_changed',
            'native_history_changed': 'native_owner_changed', 'entry_reader_changed': 'accounting_source_changed',
            'entry_budget_changed': 'accounting_source_changed', 'entry_accounting_changed': 'accounting_source_changed',
            'store_owner_changed': 'native_owner_changed', 'store_rows_changed': 'wrong_owner',
            'ticket_changes_source': 'foreign_source_deployment',
            'budget_context_changes_source': 'foreign_source_deployment',
            'reader_owns_changes_source': 'foreign_source_deployment',
            'foreign_eq_changes_source': 'foreign_source_deployment',
            'pid_changes_source': 'foreign_source_deployment',
            'entry_wrapper_changes_source': 'foreign_source_deployment',
            'store_wrapper_changes_source': 'foreign_source_deployment',
            'clock_regressed': 'clock_regressed', 'scope_expired': 'deadline', 'stop_requested': 'stop_requested'}
        for label, rows, source in graphs:
            for case in cases:
                with self.subTest(graph=label, case=case), ExitStack() as stack:
                    io, modules, deployment, loader, runtime = _runtime(
                        definitions, rows, source, stock, model, stack)
                    native, store, entry = runtime.native, runtime.store, runtime.entry
                    original_accounting, original_budget, original_reader = entry.accounting, entry.budget, entry.reader
                    original_native_rows, original_store_rows = native.rows, store.rows
                    original_until, original_text = model.UNTIL, repr(model.UNTIL)
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
                    self.assertTrue(original_reader.history_closed())
                    self.assertTrue(all(r['closed'] and not r['unknown'] for r in loader.owner.rows))
                    self.assertIsNone(loader.failure)
                    self.assertIsNone(store.current)
                    self.assertFalse(store.attempted)
                    self.assertFalse(store.restore_attempted)
                    self.assertEqual([], store.rows)
                    self.assertEqual([], native.rows)

                    # This counting seam always calls the actual original method.
                    # It does not replace authentication results or any predicate.
                    original_authenticate = type(loader).authenticate
                    auth_calls = []
                    def authenticate_forward(actual_loader, value):
                        if actual_loader is loader:
                            auth_calls.append((value, actual_loader.failure))
                        return original_authenticate(actual_loader, value)
                    stack.enter_context(mock.patch.object(type(loader), 'authenticate', authenticate_forward))
                    counters, mutation_calls, pid_calls, wrapper_calls = {}, [], [], []
                    original_end = None
                    if case in ('normal_components', 'clock_regressed', 'scope_expired', 'stop_requested'):
                        with native.mutex:
                            original_end = runtime._stage(10)
                            native._begin(original_end)
                        self.assertEqual(11.0, original_end)
                        self.assertEqual(original_end, native._scope)
                        self.assertEqual(original_end, original_accounting._io_deadline)
                    auth_calls[:] = []
                    io_before = list(io.calls)
                    poison = modules['mta_go_deployment'].GoSourceError('host_source_changed')
                    def poison_source(tag):
                        mutation_calls.append(tag)
                        loader.failure = poison

                    if case == 'normal_components':
                        for name, actual_method in (
                                ('native_owner', native._owner), ('entry_context', entry._context),
                                ('store_owner', store._owner), ('active_check', native._check)):
                            auth_calls[:] = []
                            with native.mutex:
                                returned = actual_method()
                            counters[name] = len(auth_calls)
                            self.assertTrue(all(value is deployment and failed is None for value, failed in auth_calls))
                            if name == 'active_check': self.assertEqual(1.0, returned)
                            else: self.assertIsNone(returned)
                        wanted = dict(native_owner=4 if label == 'v55' else 2,
                            entry_context=1, store_owner=2, active_check=6 if label == 'v55' else 4)
                        self.assertEqual(wanted, counters)
                        measurements[label] = counters
                        self.assertIsNone(loader.failure)
                    else:
                        # The explicit synthetic PID activates only a denial boundary.
                        # It is not a reservation/current journal/child or grant fact.
                        if case in callback_cases:
                            store.pid = io.pid()
                            original_pid = io.pid
                            def pid_forward():
                                pid_calls.append('pid')
                                value = original_pid()
                                if case in ('pid_changes_source', 'store_wrapper_changes_source'):
                                    poison_source('pid')
                                return value
                            stack.enter_context(mock.patch.object(io, 'pid', pid_forward))
                            self.assertEqual(100, store.pid)
                            self.assertFalse(store.attempted)
                            self.assertIsNone(store.current)
                        if case == 'module_replaced':
                            modules['mta_client_pending'] = types.ModuleType('HOST_foreign_source')
                        elif case == 'source_failed': loader.failure = poison
                        elif case == 'native_owner_changed': native.owner = object()
                        elif case == 'native_rows_changed': native.rows = []
                        elif case == 'native_history_changed': native._history = (object(),)
                        elif case == 'entry_reader_changed': entry.reader = object()
                        elif case == 'entry_budget_changed': entry.budget = object()
                        elif case == 'entry_accounting_changed': entry.accounting = object()
                        elif case == 'store_owner_changed': store.owner = object()
                        elif case == 'store_rows_changed': store.rows = []
                        elif case == 'ticket_changes_source':
                            class DynamicTicket(dict):
                                def __getitem__(ticket, key):
                                    returned = dict.__getitem__(ticket, key)
                                    if key == 'unknown' and not mutation_calls:
                                        poison_source('ticket')
                                    return returned
                            entry.accounting_ticket = DynamicTicket(entry.accounting_ticket)
                        elif case == 'budget_context_changes_source':
                            original_context = original_budget._context
                            def context_forward(actual_budget):
                                self.assertIs(actual_budget, original_budget)
                                returned = original_context()
                                poison_source('budget')
                                return returned
                            stack.enter_context(mock.patch.object(original_budget, '_context',
                                types.MethodType(context_forward, original_budget)))
                        elif case == 'reader_owns_changes_source':
                            original_owns = original_reader.owns_generation
                            def owns_forward(actual_reader, generation):
                                self.assertIs(actual_reader, original_reader)
                                returned = original_owns(generation)
                                poison_source('reader')
                                return returned
                            stack.enter_context(mock.patch.object(original_reader, 'owns_generation',
                                types.MethodType(owns_forward, original_reader)))
                        elif case == 'foreign_eq_changes_source':
                            class ForeignEq(object):
                                def __eq__(foreign, other):
                                    poison_source('foreign_eq')
                                    return other is runtime
                                def __ne__(foreign, other):
                                    return not foreign.__eq__(other)
                            native._originals = (ForeignEq(),) + native._originals[1:]
                        elif case == 'entry_wrapper_changes_source':
                            original_entry_context = entry._context
                            def entry_context_forward(actual_entry):
                                self.assertIs(actual_entry, entry)
                                wrapper_calls.append('entry')
                                returned = original_entry_context()
                                poison_source('entry_wrapper')
                                return returned
                            stack.enter_context(mock.patch.object(entry, '_context',
                                types.MethodType(entry_context_forward, entry)))
                        elif case == 'store_wrapper_changes_source':
                            original_store_owner = store._owner
                            def store_owner_forward(actual_store):
                                self.assertIs(actual_store, store)
                                wrapper_calls.append('store')
                                return original_store_owner()
                            stack.enter_context(mock.patch.object(store, '_owner',
                                types.MethodType(store_owner_forward, store)))
                        elif case == 'clock_regressed': io.clock.value = 0.5
                        elif case == 'scope_expired': io.clock.value = original_end
                        elif case == 'stop_requested': runtime.stop_requested = True
                        else: raise AssertionError('HOST unlisted case')
                        auth_calls[:] = []
                        with native.mutex, self.assertRaises(modules['mta_go_deployment'].GoSourceError) as caught:
                            native._check() if original_end is not None else native._owner()
                        self.assertEqual(expected_codes[case], caught.exception.code)
                        refused += 1
                        if case in callback_cases:
                            self.assertIs(loader.failure, poison)
                            self.assertEqual(1, len(mutation_calls))
                            self.assertEqual(1 if case in ('pid_changes_source', 'store_wrapper_changes_source') else 0,
                                len(pid_calls))
                            self.assertEqual(1 if case in ('entry_wrapper_changes_source', 'store_wrapper_changes_source') else 0,
                                len(wrapper_calls))
                            expected_auth = (4 if label == 'v55' else 2) if case == 'pid_changes_source' else (
                                4 if case == 'store_wrapper_changes_source' else (
                                    2 if case == 'foreign_eq_changes_source' else 3))
                            self.assertEqual(expected_auth, len(auth_calls))
                            self.assertIs(auth_calls[-1][1], poison)
                        elif case == 'source_failed': self.assertIs(loader.failure, poison)
                        else: self.assertIsNone(loader.failure)
                        if case == 'stop_requested': self.assertTrue(runtime.stop_requested)
                    self.assertEqual(io_before, io.calls)  # No IO after the pure constructor.
                    self.assertEqual(original_until, native.until)
                    self.assertEqual(original_until, entry.until)
                    self.assertEqual(original_until, store.until)
                    self.assertEqual(original_until, loader.original_until)
                    self.assertEqual(original_text, loader.original_until_text)
                    self.assertEqual(original_end, native._scope)
                    self.assertEqual([], original_native_rows)
                    self.assertEqual([], original_store_rows)
                    self.assertIsNone(store.current)
                    self.assertEqual((), store._canonical_history)
                    self.assertFalse(store.attempted)
                    self.assertFalse(store.restore_attempted)
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
        self.assertEqual(42, len(completed))
        self.assertEqual(40, refused)
        self.assertEqual({'v55', 'v56r2'}, set(measurements))
        print('GO_OWNER_COALESCE_V57_HOST_PASS domains=2 isolated_cases=42 refused=40 '
            'native_auth55=4 native_auth56r2=2 entry_auth55=1 entry_auth56r2=1 '
            'store_auth55=2 store_auth56r2=2 check_auth55=6 check_auth56r2=4 rf_calls=0')


if __name__ == '__main__':
    unittest.main()
