"""One new v61 Proc diagnostic HOST method; ROOT alone executes after review.

Actual GO60 Loader/Entry/neutral Store/bound ProcReader/Bootstrap constructors
run in an explicit syscall/FD/Proc/clock model. Only actual Native._proc and
Reader observations reject: changed expected argv, missing mandatory stat,
local Reader deadline, uncertain close. No baseline/run/reserve/actors/pins,
fork, RF, canonical publication or restore executes. First original pair is
retained without replacing original native_actor_unknown. A later actual
neutral cleanup-lane generation is only latest data: match0 is not PRIMARY.

Pure actual F formatter has IO/clock/source/history-method tripwires, strict
typed error/errno/foreign-field and shape denials. Diagnostic-only error data
and AST-extracted actual F tail verify1024 head/16KiB/one FD2 write, not F.run.
The parent Native/F bytes are SOURCE-only equivalence, never old algorithms.
Only six fixed helper FunctionDefs load; no old TestCase/method/checker runs.
All physical device/RF/full restore/performance/phone layers remain false.
"""
import ast
import builtins
import copy
import errno
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
PLAN = 'host/go_proc_diagnostic_v60_source_manifest.json'
PLAN_SHA = 'c2be8155c68594d2baa863c5ff6a99b38f6e231c32eb79bb2f94aeac77a210cf'
PLAN_BYTES = 3956
PARENT_PLAN = 'host/go_baseline_budget_v58_source_manifest.json'
PARENT_PLAN_SHA = '0c987d6e667a0d4adce867b121493436f9bf2ba11380acc97e11efbf320a30a0'
PARENT_PLAN_BYTES = 3957
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


def _diagnostic_source_bounds(old_native, new_native, old_executor, new_executor):
    """SOURCE AST normalization only; no old graph algorithms execute."""
    native = [ast.parse(raw) for raw in (old_native, new_native)]
    executor = [ast.parse(raw) for raw in (old_executor, new_executor)]
    for tree in native + executor:
        if not tree.body or not isinstance(tree.body[0], ast.Expr) or not isinstance(tree.body[0].value, ast.Constant):
            raise ValueError('HOST source documentation shape')
        tree.body.pop(0)
    def method(tree, cls, name):
        owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls]
        rows = [n for n in owner[0].body if isinstance(n, ast.FunctionDef) and n.name == name] if len(owner) == 1 else []
        if len(rows) != 1: raise ValueError('HOST fixed method changed')
        return rows[0]
    ctor = method(native[1], 'NativeGoResources', '__init__')
    assignment = [n for n in ctor.body if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Attribute) and isinstance(n.targets[0].value, ast.Name)
        and n.targets[0].value.id == 'self' and n.targets[0].attr == 'last_proc_failure_v60'
        and isinstance(n.value, ast.Constant) and n.value.value is None]
    if len(assignment) != 1: raise ValueError('HOST original first pair constructor')
    ctor.body.remove(assignment[0])
    old_proc, new_proc = (method(tree, 'NativeGoResources', '_proc') for tree in native)
    old_if = [n for n in old_proc.body if isinstance(n, ast.If)]
    new_if = [n for n in new_proc.body if isinstance(n, ast.If)]
    if len(old_if) != 1 or len(new_if) != 1 or ast.dump(old_if[0].test) != ast.dump(new_if[0].test):
        raise ValueError('HOST original Proc refusal predicate changed')
    if len(new_if[0].body) != 2 or not isinstance(new_if[0].body[0], ast.Try):
        raise ValueError('HOST diagnostic capture shape')
    new_if[0].body.pop(0)
    if ast.dump(native[0], include_attributes=False) != ast.dump(native[1], include_attributes=False):
        raise ValueError('HOST other Native algorithm changed')
    added = [n for n in executor[1].body if isinstance(n, ast.FunctionDef) and n.name == '_proc_failure_text_v60']
    if len(added) != 1: raise ValueError('HOST formatter changed')
    executor[1].body.remove(added[0])
    functions = [[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'bootstrap'] for tree in executor]
    if any(len(rows) != 1 for rows in functions): raise ValueError('HOST original bootstrap function')
    heads = [[n for n in ast.walk(rows[0]) if isinstance(n, ast.Assign)
        and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'head']
        for rows in functions]
    if any(len(rows) != 2 for rows in heads): raise ValueError('HOST original private head changed')
    if len([n for n in ast.walk(heads[1][0]) if isinstance(n, ast.Call) and
            isinstance(n.func, ast.Name) and n.func.id == '_proc_failure_text_v60']) != 1:
        raise ValueError('HOST formatter head not used')
    if not any(isinstance(n, ast.Constant) and n.value == 1024 for n in ast.walk(heads[1][1])):
        raise ValueError('HOST head limit changed')
    for before, after in zip(heads[0], heads[1]): after.value = copy.deepcopy(before.value)
    if ast.dump(executor[0], include_attributes=False) != ast.dump(executor[1], include_attributes=False):
        raise ValueError('HOST other executor algorithm changed')


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
    if changes != ['mta_go_executor', 'mta_go_native']: raise ValueError('HOST unexpected lineage delta')
    rows = current['sources']
    source = {r['module']: _fixed(r['path'], r['sha256'], r['bytes']) for r in rows}
    originals = {r['module']: _fixed(r['path'], r['sha256'], r['bytes'])
        for r in parent['sources'] if r['module'] in changes}
    _diagnostic_source_bounds(originals['mta_go_native'], source['mta_go_native'],
        originals['mta_go_executor'], source['mta_go_executor'])
    source['HOST_WPA'] = _fixed(*WPA)
    stock = {path: _fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go_proc_diagnostic_v61_syscall_model')
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
    with runtime.native.mutex:
        end = runtime._stage(15)
        runtime.native._begin(end)
    return io, modules, deployment, loader, runtime, executor


def _diagnostic_block(raw, executor):
    """Compile only the actual F diagnostic tail, never bootstrap's business body."""
    tree = ast.parse(raw)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'bootstrap']
    if len(functions) != 1: raise ValueError('HOST original diagnostic tail')
    tail = functions[0].body[-2:]
    if len(tail) != 2 or not isinstance(tail[0], ast.If) or not isinstance(tail[1], ast.Return):
        raise ValueError('HOST diagnostic tail changed')
    shell = ast.parse('def _private_diag_v61(value, deployment, result):\n    pass\n').body[0]
    shell.body = tail
    namespace = dict(executor.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[shell], type_ignores=[])),
        'HOST_actual_F_v60_private_diagnostic_tail', 'exec'), namespace)
    return namespace['_private_diag_v61']


class ForeignTripwire:
    """Deny-only formatter input: no coercion or foreign property may run."""
    touched = 0
    def __repr__(self):
        type(self).touched += 1
        raise AssertionError('HOST foreign repr forbidden')
    def __str__(self):
        type(self).touched += 1
        raise AssertionError('HOST foreign str forbidden')
    def __bool__(self):
        type(self).touched += 1
        raise AssertionError('HOST foreign bool forbidden')
    def __getattribute__(self, name):
        if name in ('code', 'errno'):
            type(self).touched += 1
            raise AssertionError('HOST foreign field access forbidden')
        return object.__getattribute__(self, name)


class ForeignPair(list):
    touched = 0
    def __len__(self):
        type(self).touched += 1
        raise AssertionError('HOST foreign pair length forbidden')


class GoProcDiagnosticV61Tests(unittest.TestCase):
    def pure_text(self, io, loader, runtime, executor, deployment):
        before, now, history = list(io.calls), io.clock.value, runtime.entry.reader._history
        reader = runtime.entry.reader
        probes = []
        with ExitStack() as pure:
            for name in ('open', 'read', 'close', 'fstat', 'stat', 'listdir', 'readlink',
                    'socket', 'unix', 'realpath', 'getpid', 'pid', 'pause'):
                probes.append(pure.enter_context(mock.patch.object(io, name,
                    side_effect=AssertionError('HOST formatter syscall forbidden'))))
            probes.append(pure.enter_context(mock.patch.object(type(io.clock), '__call__',
                side_effect=AssertionError('HOST formatter clock forbidden'))))
            probes.append(pure.enter_context(mock.patch.object(reader, 'owns_generation',
                side_effect=AssertionError('HOST formatter owns method forbidden'))))
            probes.append(pure.enter_context(mock.patch.object(reader, 'history_closed',
                side_effect=AssertionError('HOST formatter history method forbidden'))))
            probes.append(pure.enter_context(mock.patch.object(loader, 'authenticate',
                side_effect=AssertionError('HOST formatter authentication forbidden'))))
            answer = executor._proc_failure_text_v60(runtime, deployment)
            for probe in probes: self.assertEqual(0, probe.call_count)
        self.assertIs(type(answer), str)
        self.assertLessEqual(len(answer.encode('ascii')), 512)
        self.assertEqual(before, io.calls)
        self.assertEqual(now, io.clock.value)
        self.assertIs(history, reader._history)
        return answer

    def reject(self, runtime, modules, pid, expected=None):
        with runtime.native.mutex, self.assertRaises(modules['mta_go_deployment'].GoSourceError) as caught:
            runtime.native._proc(pid, expected)
        self.assertIs(type(caught.exception), modules['mta_go_deployment'].GoSourceError)
        self.assertEqual('native_actor_unknown', caught.exception.code)
        self.assertIsNone(runtime.native.failure)
        return caught.exception

    def inventory(self, io, modules, loader, runtime, pending):
        entry, native, store = runtime.entry, runtime.native, runtime.store
        self.assertIs(entry.accounting._proc_reader, entry.reader)
        self.assertIs(entry.reader._bound_budget_v24, entry.budget)
        self.assertIs(entry.budget._store, entry.accounting)
        self.assertIs(loader.runtime, runtime)
        self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
        self.assertIs(type(entry.accounting), modules['mta_client_store'].DurableClientInitStore)
        for value in (runtime.until, entry.until, native.until, store.until, loader.original_until):
            self.assertEqual(301.0, value)
        self.assertEqual('301.0', loader.original_until_text)
        self.assertEqual(16.0, native._scope)
        self.assertEqual(16.0, entry.accounting._io_deadline)
        self.assertIs(entry.reader._pending, pending)
        self.assertIs(entry.reader.history_closed(), not pending)
        self.assertFalse(entry.accounting._attempted)
        self.assertFalse(entry.accounting._opened)
        self.assertIsNone(entry.accounting._canonical)
        self.assertFalse(store.attempted)
        self.assertFalse(store.restore_attempted)
        self.assertFalse(store.publication_unknown)
        self.assertIsNone(store.current)
        self.assertEqual((), store._canonical_history)
        self.assertEqual((), store._fd_history)
        self.assertEqual([], store.rows)
        self.assertEqual([], native.rows)
        self.assertEqual((), native._history)
        self.assertEqual({}, io.live)
        self.assertEqual({}, io.children)
        self.assertEqual([], runtime.launcher._tickets)
        self.assertTrue(all(r['closed'] and not r['unknown'] for r in loader.owner.rows))
        self.assertFalse(runtime.started)
        self.assertFalse(runtime.restore_attempted)
        self.assertFalse(runtime.group_confirmed)
        self.assertIsNone(runtime.cleanup_until)
        self.assertIsNone(entry.cleanup_until)
        self.assertEqual((0, 0), (io.create_count, io.delete_count))
        self.assertFalse(native._create_called)
        self.assertFalse(native._group_submit_called)
        self.assertFalse(native._delete_called)

    def actual_unknown_pair(self, io, modules, runtime, expected=None, pid=41):
        if expected is None:
            with runtime.native.mutex:
                expected = runtime.native._proc(pid).actor
        io.nodes['/proc/%d/cmdline' % pid].data = b'/usr/bin/HOST_CHANGED\0'
        error = self.reject(runtime, modules, pid, expected)
        observation = runtime.native.proc_observations[-1]
        reader, generation = runtime.entry.reader, runtime.entry.reader._history[-1]
        self.assertIs(type(observation), modules['mta_client_proc'].ProcObservation)
        self.assertEqual('unknown', observation.kind)
        self.assertEqual('expected_actor_changed', observation.reason)
        self.assertIsNone(observation.actor)
        self.assertIs(type(runtime.native.last_proc_failure_v60), tuple)
        self.assertIs(runtime.native.last_proc_failure_v60[0], observation)
        self.assertIs(runtime.native.last_proc_failure_v60[1], reader)
        self.assertIs(generation.observation, observation)
        self.assertTrue(reader.owns_generation(generation))
        self.assertFalse(generation.active)
        self.assertTrue(generation.ended)
        self.assertFalse(generation.unknown)
        self.assertFalse(generation.late)
        return observation, generation, error

    def test_actual_proc_unknown_first_pair_and_private_formatter_bounds_without_radio(self):
        definitions = _definitions()
        rows, source, stock, model = _inputs()
        cases = ('first_and_cleanup', 'record_disappeared', 'reader_deadline',
            'close_uncertainty', 'capture_best_effort', 'formatter_denials', 'private_fd2_bound')
        completed, refused, pairs, shape_denied, sanitized, writes = [], 0, 0, 0, 0, []
        ForeignTripwire.touched = 0
        ForeignPair.touched = 0
        for case in cases:
            with self.subTest(case=case), ExitStack() as stack:
                io, modules, deployment, loader, runtime, executor = _runtime(
                    definitions, rows, source, stock, model, stack)
                native, reader = runtime.native, runtime.entry.reader
                self.assertEqual(16.0, runtime.entry.accounting._io_deadline)
                self.assertEqual(301.0, runtime.until)
                self.assertIsNone(native.last_proc_failure_v60)
                pending = False
                if case in ('first_and_cleanup', 'formatter_denials', 'private_fd2_bound'):
                    observation, generation, original_error = self.actual_unknown_pair(io, modules, runtime)
                    refused += 1; pairs += 1
                    text = self.pure_text(io, loader, runtime, executor, deployment)
                    self.assertIn('reason=expected_actor_changed ', text)
                    self.assertIn('latest=0/1/0/0 match=1 latest_error=ProcReadError/expected_actor_changed', text)
                    self.assertIn('pending=0 reader=0/0/0 ', text)
                    pair = native.last_proc_failure_v60
                    if case == 'first_and_cleanup':
                        del io.nodes['/proc/42/stat']
                        self.reject(runtime, modules, 42); refused += 1
                        second = native.proc_observations[-1]
                        self.assertEqual('record_disappeared', second.reason)
                        self.assertIsNot(second, observation)
                        self.assertIs(native.last_proc_failure_v60, pair)
                        text = self.pure_text(io, loader, runtime, executor, deployment)
                        self.assertIn('reason=expected_actor_changed ', text)
                        self.assertIn('match=0 latest_error=OSError/2', text)
                        # Actual neutral accounting cleanup lane only: no GO cleanup/grant.
                        resources = modules['mta_client_resource_budget']
                        with native.mutex:
                            runtime.entry.accounting._resource_lane_v23 = resources.CLEANUP
                            runtime.entry.budget.cancel()
                            latest = reader.read_self(_absolute_deadline=native._scope)
                        latest_generation = reader._history[-1]
                        self.assertEqual('live_actor', latest.kind)
                        self.assertIs(latest_generation.observation, latest)
                        self.assertEqual(resources.CLEANUP, latest_generation.credit.lane)
                        self.assertIs(native.last_proc_failure_v60, pair)
                        text = self.pure_text(io, loader, runtime, executor, deployment)
                        self.assertIn('reason=expected_actor_changed ', text)
                        self.assertIn('latest=0/1/0/0 match=0 latest_error=none', text)
                        self.assertIn('resource_error=none', text)
                        self.assertTrue(runtime.entry.budget._cancelled)
                    elif case == 'formatter_denials':
                        resource = modules['mta_client_resource_budget']
                        errors = [
                            (modules['mta_client_proc'].ProcReadError('deadline'), 'ProcReadError/deadline'),
                            (modules['mta_client_proc'].ProcReadError('deadline'), 'invalid'),
                            (resource.ResourceBudgetError('safe_exhaustion'), 'ResourceBudgetError/safe_exhaustion'),
                            (resource.ResourceBudgetError('invalid_state'), 'invalid'),
                            (OSError(errno.ENOENT, 'HOST exact errno'), 'OSError/2'),
                            (OSError(errno.EIO, 'HOST invalid bool errno'), 'OSError/invalid'),
                            (OSError(errno.EIO, 'HOST foreign errno'), 'OSError/invalid'),
                            (ForeignTripwire(), 'other')]
                        errors[1][0].code = ForeignTripwire()
                        errors[3][0].code = ForeignTripwire()
                        errors[5][0].errno = True
                        errors[6][0].errno = ForeignTripwire()
                        actual_error, actual_resource = generation.error, reader._resource_error_v24
                        try:
                            for error, expected in errors:
                                generation.error = reader._resource_error_v24 = error
                                text = self.pure_text(io, loader, runtime, executor, deployment)
                                self.assertIn('latest_error=' + expected + ' resource_error=' + expected + '\n', text)
                                sanitized += 1
                        finally:
                            generation.error, reader._resource_error_v24 = actual_error, actual_resource
                        # Explicit malformed diagnostic-only fields; never positive ownership.
                        bad_fields = (
                            (observation, 'reason', ForeignTripwire()),
                            (observation, 'passes', True),
                            (observation, 'resource_pending', ForeignTripwire()),
                            (reader, '_history', tuple(reader._history)),
                            (generation, 'ordinal', True),
                            (generation, 'unknown', ForeignTripwire()),
                            (native, 'last_proc_failure_v60', ForeignPair(pair)))
                        for owner, name, bad in bad_fields:
                            original = getattr(owner, name)
                            try:
                                object.__setattr__(owner, name, bad)
                                self.assertEqual('PROC60=unavailable\n',
                                    self.pure_text(io, loader, runtime, executor, deployment))
                                shape_denied += 1
                            finally: object.__setattr__(owner, name, original)
                        self.assertEqual('PROC60=unavailable\n',
                            self.pure_text(io, loader, runtime, executor, ForeignTripwire()))
                        shape_denied += 1
                        self.assertEqual(0, ForeignTripwire.touched)
                        self.assertIs(native.last_proc_failure_v60, pair)
                    else:
                        emit = _diagnostic_block(source['mta_go_executor'], executor)
                        runtime.failure = original_error
                        initial_calls, initial_clock = list(io.calls), io.clock.value
                        def capture(fd, raw):
                            self.assertEqual(2, fd)
                            self.assertIs(type(raw), bytes)
                            writes.append(raw)
                            return len(raw)
                        with mock.patch.object(executor.os, 'write', capture):
                            self.assertEqual(1, emit(runtime, deployment, 1))
                        self.assertLessEqual(len(writes[-1]), 16384)
                        self.assertEqual(1, writes[-1].count(b'PROC60 role=first_native_proc_reject'))
                        self.assertEqual(1, writes[-1].count(b'PRIMARY\n'))
                        self.assertEqual(1, writes[-1].count(b'RESTORE\nunavailable\n'))
                        # Explicit long diagnostic data only, not an actual GO phase/failure.
                        runtime.phase = 'H' * 1500
                        runtime.failure, runtime.restore_failure = ValueError('X' * 20000), ValueError('Y' * 20000)
                        with mock.patch.object(executor.os, 'write', capture):
                            self.assertEqual(1, emit(runtime, deployment, 1))
                        self.assertEqual(16384, len(writes[-1]))
                        self.assertEqual(1024, writes[-1].find(b'PRIMARY\n'))
                        self.assertEqual(8704, writes[-1].find(b'RESTORE\n'))
                        def refused_write(fd, raw):
                            capture(fd, raw)
                            raise OSError(errno.EIO, 'HOST private writer failed')
                        with mock.patch.object(executor.os, 'write', refused_write):
                            self.assertEqual(1, emit(runtime, deployment, 1))
                        self.assertEqual(3, len(writes))
                        self.assertEqual(initial_calls, io.calls)
                        self.assertEqual(initial_clock, io.clock.value)
                        self.assertIs(native.last_proc_failure_v60, pair)
                elif case == 'record_disappeared':
                    del io.nodes['/proc/42/stat']
                    self.reject(runtime, modules, 42); refused += 1; pairs += 1
                    observation = native.proc_observations[-1]
                    self.assertEqual(('unknown', 'record_disappeared'), (observation.kind, observation.reason))
                    self.assertIs(native.last_proc_failure_v60[0], observation)
                    self.assertIs(native.last_proc_failure_v60[1], reader)
                    self.assertIs(reader._history[-1].observation, observation)
                    text = self.pure_text(io, loader, runtime, executor, deployment)
                    self.assertIn('match=1 latest_error=OSError/2', text)
                    self.assertIn('pending=0 reader=0/0/0 ', text)
                elif case == 'reader_deadline':
                    original_read, fired = io.read, []
                    def late_return(fd, count):
                        raw = original_read(fd, count)
                        if not fired:
                            fired.append(fd)
                            io.clock.value = 4.1  # Native16 is valid; actual Reader3s slice4 expires.
                        return raw
                    with mock.patch.object(io, 'read', late_return):
                        self.reject(runtime, modules, 41)
                    refused += 1; pairs += 1
                    observation, generation = native.proc_observations[-1], reader._history[-1]
                    self.assertEqual(1, len(fired))
                    self.assertEqual(('unknown', 'deadline'), (observation.kind, observation.reason))
                    self.assertIs(native.last_proc_failure_v60[0], observation)
                    self.assertIs(native.last_proc_failure_v60[1], reader)
                    self.assertIs(generation.observation, observation)
                    self.assertFalse(generation.unknown)
                    self.assertFalse(generation.late)
                    self.assertLess(io.clock.value, native._scope)
                    self.assertEqual(4.0, reader._deadline)
                    text = self.pure_text(io, loader, runtime, executor, deployment)
                    self.assertIn('latest=0/1/0/0 match=1 latest_error=ProcReadError/deadline', text)
                elif case == 'close_uncertainty':
                    original_close, closed_once = io.close, []
                    original_close_error = OSError(errno.EIO, 'HOST close returned unknown')
                    def physical_close_then_error(fd):
                        original_close(fd)
                        closed_once.append(fd)
                        raise original_close_error
                    with mock.patch.object(io, 'close', physical_close_then_error):
                        self.reject(runtime, modules, 41)
                    refused += 1; pairs += 1; pending = True
                    observation, generation = native.proc_observations[-1], reader._history[-1]
                    self.assertEqual(('unknown', 'file_close_unverified'), (observation.kind, observation.reason))
                    self.assertIs(native.last_proc_failure_v60[0], observation)
                    self.assertIs(native.last_proc_failure_v60[1], reader)
                    self.assertIs(generation.observation, observation)
                    self.assertTrue(generation.unknown)
                    self.assertTrue(generation.late)
                    self.assertTrue(observation.resource_pending)
                    self.assertEqual(1, len(closed_once))
                    ticket = generation.tickets[-1]
                    self.assertIs(ticket.close_error, original_close_error)
                    self.assertTrue(ticket.close_attempted)
                    self.assertFalse(ticket.close_returned)
                    self.assertTrue(ticket.ebadf_observed)
                    self.assertFalse(reader.closed_open_ticket(ticket))
                    self.assertTrue(runtime.entry.budget._cancelled)
                    text = self.pure_text(io, loader, runtime, executor, deployment)
                    self.assertIn('pending=1 reader=0/0/1 latest=0/1/1/1 match=1', text)
                    self.assertIn('latest_error=ProcReadError/file_close_unverified', text)
                    before = list(io.calls)
                    with self.assertRaises(modules['mta_client_proc'].ProcReadError) as caught:
                        reader.read_actor(42, _absolute_deadline=native._scope)
                    self.assertEqual('reader_pending_or_active', caught.exception.code)
                    self.assertEqual(before, io.calls)
                    self.assertEqual(1, len(closed_once))
                elif case == 'capture_best_effort':
                    del io.nodes['/proc/42/stat']
                    creator, original_setattr, failed_assign = type(native), type(native).__setattr__, []
                    def diagnostic_allocation_failure(value, name, actual):
                        if name == 'last_proc_failure_v60':
                            failed_assign.append(actual)
                            raise MemoryError('HOST diagnostic-only allocation refusal')
                        return original_setattr(value, name, actual)
                    with mock.patch.object(creator, '__setattr__', diagnostic_allocation_failure):
                        self.reject(runtime, modules, 42)
                    refused += 1
                    self.assertEqual(1, len(failed_assign))
                    self.assertIs(failed_assign[0][0], native.proc_observations[-1])
                    self.assertIs(failed_assign[0][1], reader)
                    self.assertIsNone(native.last_proc_failure_v60)
                    self.assertEqual('PROC60=unavailable\n',
                        self.pure_text(io, loader, runtime, executor, deployment))
                else:
                    raise AssertionError('HOST unlisted Proc diagnostic case')
                self.inventory(io, modules, loader, runtime, pending)
                completed.append(case)
        self.assertEqual(list(cases), completed)
        self.assertEqual((8, 6, 8, 8, 3), (refused, pairs, shape_denied, sanitized, len(writes)))
        self.assertEqual(0, ForeignTripwire.touched)
        self.assertEqual(0, ForeignPair.touched)
        print('GO_PROC_DIAGNOSTIC_V61_HOST_PASS cases=7 refused=8 pairs=6 first_unchanged=1 '
            'cleanup_match0=1 unknown_late=1 shape_denied=8 sanitized=8 capture_unavailable=1 '
            'fd2_writes=3 max_head=1024 max_write=16384 rf_calls=0')


if __name__ == '__main__':
    unittest.main()
