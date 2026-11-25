"""One new v66 pure private-diagnostic component method, SOURCE until ROOT runs.

ROOT alone may execute after fixed v65-r2 pins and full source review. The fixed
17 source modules are loaded for their actual class/function definitions only.
No Loader.load, Entry.prepare, accounting constructor, Bootstrap constructor,
Native business operation, baseline/reserve/fork/RF/restore or old test loads.
Exact classes allocated with object.__new__ contain explicitly synthetic
private diagnostic data. They are NOT original producers or permission.
RawRecord and parse_stat are actual definitions; stat bytes are HOST fixtures.
All Linux, actual process, business failure, restoration and phone claims are
false. Only new timing observers/selection, PROC65 diff and FD2 bounds run.
"""
import ast
import builtins
from contextlib import ExitStack
import copy
import errno
import hashlib
import json
from pathlib import Path
import re
import sys
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/go_private_diagnostic_v65_r2_source_manifest.json'
PLAN_SHA = '99a2329c18efeb26baf9bab3a6249e14168440a2ee87430720317be0caadba36'
PLAN_BYTES = 3968
PARENT_PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
PARENT_PLAN_SHA = 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842'
PARENT_PLAN_BYTES = 3955
MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_go_process_owner', 'mta_go_deployment', 'mta_go_executor', 'mta_go_bootstrap_store',
    'mta_go_native', 'mta_go_bootstrap')
DELTA_MODULES = ('mta_go_executor', 'mta_go_native')


def _fixed(path, sha, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('HOST fixed diagnostic input changed')
    return raw


def _inputs():
    current = json.loads(_fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    parent = json.loads(_fixed(PARENT_PLAN, PARENT_PLAN_SHA, PARENT_PLAN_BYTES))
    for graph in (parent, current):
        if (type(graph) is not dict or set(graph) != {'schema', 'sources'} or
                graph['schema'] != 'go-frequency-v46-host' or
                tuple(row['module'] for row in graph['sources']) != MODULES or
                any(set(row) != {'module', 'path', 'sha256', 'bytes'} for row in graph['sources'])):
            raise ValueError('HOST fixed diagnostic graph changed')
    delta = tuple(after['module'] for before, after in zip(parent['sources'], current['sources']) if before != after)
    if delta != DELTA_MODULES:
        raise ValueError('HOST unexpected diagnostic source delta')
    source = {row['module']: _fixed(row['path'], row['sha256'], row['bytes']) for row in current['sources']}
    originals = {row['module']: _fixed(row['path'], row['sha256'], row['bytes'])
        for row in parent['sources'] if row['module'] in DELTA_MODULES}
    return current['sources'], source, originals


def _source_delta(source, originals):
    """Inverse SOURCE comparison; this does not execute either old algorithm."""
    def parsed(raw):
        tree = ast.parse(raw.decode('utf-8'))
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) \
                and type(tree.body[0].value.value) is str:
            tree.body.pop(0)
        return tree
    def one(tree, name, owner=None):
        body = tree.body if owner is None else one(tree, owner).body
        values = [node for node in body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
        if len(values) != 1:
            raise ValueError('HOST SOURCE definition changed')
        return values[0]
    def dump(node):
        return ast.dump(node, include_attributes=False)
    old_n, new_n = (parsed(raw) for raw in (originals['mta_go_native'], source['mta_go_native']))
    captures = [node for node in new_n.body if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == '_PROC65_ORIGINALS' for t in node.targets)]
    wanted = ast.parse('_PROC65_ORIGINALS = (_proc_v56, _proc_v56.parse_stat)').body[0]
    if len(captures) != 1 or dump(captures[0]) != dump(wanted):
        raise ValueError('HOST SOURCE private Proc capture changed')
    new_n.body.remove(captures[0])
    cap = one(new_n, '_timing_begin_v55', 'NativeGoResources')
    values = [node for node in ast.walk(cap) if isinstance(node, ast.Constant) and type(node.value) is int and node.value == 32]
    if len(values) != 1:
        raise ValueError('HOST SOURCE timing capacity changed')
    values[0].value = 2
    if dump(new_n) != dump(old_n):
        raise ValueError('HOST SOURCE Native non-diagnostic delta')

    old_f, new_f = (parsed(raw) for raw in (originals['mta_go_executor'], source['mta_go_executor']))
    added = one(new_f, '_proc_stat_diff_text_v65')
    new_f.body.remove(added)
    timing = one(new_f, '_snapshot_timing_text_v55')
    new_f.body[new_f.body.index(timing)] = copy.deepcopy(one(old_f, '_snapshot_timing_text_v55'))
    old_run, new_run = one(old_f, 'bootstrap'), one(new_f, 'bootstrap')
    heads = lambda node: [n for n in ast.walk(node) if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'head' for t in n.targets)]
    before, after = heads(old_run), heads(new_run)
    if len(before) != 2 or len(after) != 2:
        raise ValueError('HOST SOURCE diagnostic head shape changed')
    if sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == '_proc_stat_diff_text_v65'
            for n in ast.walk(after[0])) != 1 or \
            sum(isinstance(n, ast.Constant) and type(n.value) is int and n.value == 2048 for n in ast.walk(after[1])) != 1:
        raise ValueError('HOST SOURCE diagnostic head delta changed')
    for original, changed in zip(before, after):
        changed.value = copy.deepcopy(original.value)
    if dump(new_f) != dump(old_f):
        raise ValueError('HOST SOURCE F non-diagnostic delta')
    # The fixed Loader's actual source shape supplies running F BEFORE its
    # private new Proc ModuleType. Only that shape, not load/authentication, is
    # simulated below; the actual Loader function is never called.
    loader = source['mta_go_deployment'].decode('utf-8')
    if "self.modules['mta_go_deployment'], self.modules['mta_go_executor'] = own, running" not in loader or \
            "if name in ('p011_json', 'mta_go_deployment', 'mta_go_executor'): continue" not in loader or \
            "module = types.ModuleType(name)" not in loader:
        raise ValueError('HOST SOURCE actual mixed definition shape changed')


def _definition_domain(rows, source, stack):
    """Running F precedes the Loader's private Proc definition domain.

    This is explicitly a definitions-only simulation of actual Loader.load's
    reuse-running-F/new-private-ModuleType shape, NOT Loader authentication.
    The ordinary sys.modules Proc and private deployment Proc stay distinct.
    No Loader/readback/manifest/Entry/Bootstrap algorithms execute.
    """
    modules, original_import = {}, builtins.__import__
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules or level:
                raise ImportError('HOST unlisted diagnostic definition')
            return modules[name]
        return original_import(name, globals, locals, fromlist, level)
    row_map = {row['module']: row for row in rows}
    def define(name, private=True):
        row = row_map[name]
        value = types.ModuleType(name)
        value.__file__ = str(BASE / row['path'])
        value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        if private:
            modules[name] = value
        else:
            stack.enter_context(mock.patch.dict(sys.modules, {name: value}))
        exec(compile(source[name], value.__file__, 'exec'), value.__dict__)
        return value
    # The source Loader reuses these already-running definitions and skips
    # their second exec. In r2 F must have no early ordinary Proc import.
    define('mta_go_deployment')
    define('mta_go_executor')
    for row in rows:
        if row['module'] not in ('mta_go_deployment', 'mta_go_executor'):
            define(row['module'])
    ordinary_proc = define('mta_client_proc', False)
    return modules, ordinary_proc


def _data_fixture(modules):
    """Synthetic exact-class data, not ctor/Loader/producer or ready evidence."""
    sources, executor, proc = (modules[name] for name in
        ('mta_go_deployment', 'mta_go_executor', 'mta_client_proc'))
    deployment = object.__new__(sources.LoadedGoDeployment)
    loader = object.__new__(sources.GoDeploymentLoader)
    object.__setattr__(deployment, 'modules', modules)
    object.__setattr__(deployment, 'loader', loader)
    runtime = object.__new__(modules['mta_go_bootstrap'].GoBootstrap)
    native = object.__new__(modules['mta_go_native'].NativeGoResources)
    entry = object.__new__(executor.GoEntrySource)
    reader = object.__new__(proc.ProcReader)
    runtime.deployment, runtime.native, runtime.entry = deployment, native, entry
    runtime.phase, runtime.failure, runtime.restore_failure = 'diagnostic_fixture', None, None
    native.entry, native.until, native._scope = entry, 301.0, 16.0
    native._snapshot_timing_v55, native.last_proc_failure_v60 = [], None
    native.last = 7.0
    entry.reader, entry.boot = reader, 'HOST_DIAGNOSTIC_BOOT'
    reader._issuer, reader._history = object(), []
    reader._active, reader._history_active, reader._pending = False, False, False
    reader._resource_error_v24 = None
    return runtime, native, entry, reader, deployment, loader, executor


def _stat_bytes(pid=41, start=100, comm=b'HOST_COMM', flags=0, ppid=1, threads=1, state=b'S'):
    fields = [b'0'] * 49
    fields[0], fields[5], fields[16], fields[18] = (
        str(ppid).encode('ascii'), str(flags).encode('ascii'),
        str(threads).encode('ascii'), str(start).encode('ascii'))
    return str(pid).encode('ascii') + b' (' + comm + b') ' + state + b' ' + b' '.join(fields) + b'\n'


def _raw_stat(proc, path, data, stage, pass_index):
    return proc.RawRecord(stage, pass_index, path, data, ())


def _pair(runtime, native, entry, reader, modules, raw, reason='pid_identity_changed'):
    proc = modules['mta_client_proc']
    observation = proc.ProcObservation('unknown', reason, 'pid_stat', entry.boot,
        None, False, (), False, 0, tuple(raw), 0, 0, False, 0)
    native.last_proc_failure_v60 = (observation, reader)
    generation = object.__new__(proc.ProcGeneration)
    generation.reader, generation._issuer, generation.ordinal = reader, reader._issuer, 0
    generation.active, generation.ended, generation.unknown, generation.late = False, True, False, False
    generation.observation, generation.error, generation.raw = observation, proc.ProcReadError(reason), []
    reader._history = [generation]
    return observation, generation


def _diagnostic_tail(raw, executor):
    """Only actual diagnostic tail, never F/bootstrap/run business dispatch."""
    tree = ast.parse(raw)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'bootstrap']
    if len(functions) != 1:
        raise ValueError('HOST actual diagnostic tail changed')
    tail = functions[0].body[-2:]
    if len(tail) != 2 or not isinstance(tail[0], ast.If) or not isinstance(tail[1], ast.Return):
        raise ValueError('HOST actual diagnostic tail shape')
    shell = ast.parse('def _private_tail_v66(value, deployment, result):\n    pass\n').body[0]
    shell.body = copy.deepcopy(tail)
    namespace = dict(executor.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[shell], type_ignores=[])),
        'HOST_v65_actual_diagnostic_tail_only', 'exec'), namespace)
    return namespace['_private_tail_v66']


class Foreign:
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
    def __len__(self):
        type(self).touched += 1
        raise AssertionError('HOST foreign length forbidden')


class GoPrivateDiagnosticV66Tests(unittest.TestCase):
    def pure(self, callback, runtime, native, reader, loader):
        before_history, before_rows, before_last = reader._history, native._snapshot_timing_v55, native.last
        probes = []
        with ExitStack() as stack:
            probes.append(stack.enter_context(mock.patch.object(loader, 'authenticate',
                side_effect=AssertionError('HOST pure formatter authentication forbidden'))))
            for method in ('read_self', 'read_actor', 'owns_generation', 'history_closed'):
                probes.append(stack.enter_context(mock.patch.object(reader, method,
                    side_effect=AssertionError('HOST pure formatter Reader call forbidden'))))
            for method in ('_owner', '_check', '_now', '_file', '_proc', '_record'):
                probes.append(stack.enter_context(mock.patch.object(native, method,
                    side_effect=AssertionError('HOST pure formatter Native call forbidden'))))
            probes.append(stack.enter_context(mock.patch.object(native, 'clock',
                side_effect=AssertionError('HOST pure formatter clock forbidden'), create=True)))
            for method in ('open', 'read', 'write', 'fstat', 'getpid'):
                probes.append(stack.enter_context(mock.patch.object(runtime.deployment.modules['mta_go_executor'].os,
                    method, side_effect=AssertionError('HOST pure formatter OS call forbidden'))))
            probes.append(stack.enter_context(mock.patch.object(runtime.deployment.modules['mta_go_executor'].time,
                'monotonic', side_effect=AssertionError('HOST pure formatter time forbidden'))))
            answer = callback()
            for probe in probes:
                self.assertEqual(0, probe.call_count)
        self.assertIs(reader._history, before_history)
        self.assertIs(native._snapshot_timing_v55, before_rows)
        self.assertEqual(before_last, native.last)
        self.assertEqual(0, Foreign.touched)
        return answer

    def timing_cases(self, runtime, native, reader, loader, executor):
        """Only timing observers, pure selected data and an early-fail finally."""
        completed = []
        ticks, callbacks = [1.0], []
        def clock():
            callbacks.append(ticks[0])
            return ticks[0]
        native._originals = (None, None, None, None, None, None, clock, None, None)
        for ordinal in range(32):
            native._scope = 16.0 + ordinal
            ticks[0] = 1.0 + ordinal
            row = native._timing_begin_v55()
            self.assertIs(row, native._snapshot_timing_v55[-1])
            self.assertEqual([native._scope, 301.0, 'boot', None], row[:4])
            for index, component in ((1, 'actors'), (2, 'pins'), (3, 'rest'), (4, None)):
                ticks[0] = 1.0 + ordinal + index / 10
                native._timing_mark_v55(row, index, component)
            self.assertEqual([1.0 + ordinal + index / 10 for index in range(5)], row[4])
            self.assertEqual(7.0, native.last)
        self.assertEqual(160, len(callbacks))
        before, count = list(native._snapshot_timing_v55), len(callbacks)
        self.assertIsNone(native._timing_begin_v55())
        self.assertEqual(before, native._snapshot_timing_v55)
        self.assertEqual(count, len(callbacks))
        completed.append('observer_capacity32')

        actual_rows = native._snapshot_timing_v55
        for length, selected in ((1, [1]), (2, [1, 2]), (3, [1, 2, 3]),
                (4, [1, 2, 3, 4]), (5, [1, 2, 4, 5]), (32, [1, 2, 31, 32])):
            native._snapshot_timing_v55 = actual_rows[:length]
            text = self.pure(lambda: executor._snapshot_timing_text_v55(runtime), runtime, native, reader, loader)
            self.assertEqual(selected, [int(value) for value in re.findall(r'^SNAP55#([0-9]+) ', text, re.M)])
            self.assertEqual(len(selected), text.count('\n'))
            self.assertLessEqual(len(text.encode('ascii')), 1024)
            completed.append('selected_' + str(length))
        native._snapshot_timing_v55 = actual_rows

        # Exact-list admission:33 and a foreign container never get traversed.
        for rows in ([], actual_rows + [copy.deepcopy(actual_rows[-1])], tuple(actual_rows), Foreign()):
            native._snapshot_timing_v55 = rows
            self.assertEqual('SNAP55=unavailable\n',
                self.pure(lambda: executor._snapshot_timing_text_v55(runtime), runtime, native, reader, loader))
        completed.append('selection_shape_denials')
        native._snapshot_timing_v55 = actual_rows
        original = actual_rows[-1]
        for row in (Foreign(), [True, 301.0, 'rest', None, [1.0] * 5],
                [16.0, 301.0, Foreign(), None, [1.0] * 5],
                [16.0, 301.0, 'rest', None, Foreign()],
                [16.0, 301.0, 'rest', None, [1.0, 0.5, None, None, 2.0]]):
            actual_rows[-1] = row
            self.assertEqual('SNAP55=invalid\n',
                self.pure(lambda: executor._snapshot_timing_text_v55(runtime), runtime, native, reader, loader))
        actual_rows[-1] = original
        # Only selected rows are rendered/validated. Foreign unselected data do
        # not become a success proof; this check merely excludes hidden reads.
        saved_middle = actual_rows[2]
        actual_rows[2] = Foreign()
        text = self.pure(lambda: executor._snapshot_timing_text_v55(runtime), runtime, native, reader, loader)
        self.assertEqual([1, 2, 31, 32], [int(x) for x in re.findall(r'^SNAP55#([0-9]+) ', text, re.M)])
        actual_rows[2] = saved_middle
        completed.append('selected_bad_fields')

        native._snapshot_timing_v55 = []
        failures = []
        def clock_raises():
            failures.append(1)
            raise RuntimeError('HOST observer callback failed')
        native._originals = (None, None, None, None, None, None, clock_raises, None, None)
        row = native._timing_begin_v55()
        self.assertIs(row, native._snapshot_timing_v55[0])
        self.assertEqual([None] * 5, row[4])
        native._timing_mark_v55(row, 1, 'actors')
        self.assertEqual([None] * 5, row[4])
        self.assertEqual(2, len(failures))
        self.assertEqual(7.0, native.last)
        completed.append('callback_failure_best_effort')

        # Actual observer regression handling leaves the business last/cap.
        ticks[0] = 2.0
        native._originals = (None, None, None, None, None, None, clock, None, None)
        native._snapshot_timing_v55 = []
        row = native._timing_begin_v55()
        ticks[0] = 1.0
        native._timing_mark_v55(row, 1, 'actors')
        self.assertEqual([2.0, None, None, None, None], row[4])
        self.assertEqual(7.0, native.last)
        completed.append('observer_regression')

        # Call actual unchanged _snapshot_once only until its first validation
        # fails. No file/Proc/snapshot or business success is made. Its actual
        # except/finally must preserve the same synthetic original exception.
        native._snapshot_timing_v55 = []
        ticks[0] = 3.0
        original_error = RuntimeError('HOST early validation error, no syscall')
        calls = []
        def reject_validate():
            calls.append('validate')
            ticks[0] = 4.0
            raise original_error
        native.io = types.SimpleNamespace(validate=reject_validate)
        with ExitStack() as no_business:
            probes = [no_business.enter_context(mock.patch.object(native, method,
                side_effect=AssertionError('HOST forbidden later snapshot work')))
                for method in ('_file', '_actors', '_pins', '_interfaces', '_stock_status', '_ipv4', '_ipv6')]
            with self.assertRaises(RuntimeError) as caught:
                native._snapshot_once()
            self.assertIs(caught.exception, original_error)
            for probe in probes:
                self.assertEqual(0, probe.call_count)
        self.assertEqual(['validate'], calls)
        row = native._snapshot_timing_v55[-1]
        self.assertEqual(('boot', 'boot'), tuple(row[2:4]))
        self.assertEqual([3.0, None, None, None, 4.0], row[4])
        self.assertEqual(7.0, native.last)
        self.assertEqual(301.0, native.until)
        completed.append('original_early_failure_finally')
        return completed

    def stat_cases(self, runtime, native, entry, reader, deployment, loader, executor, modules):
        """Actual RawRecord/parse_stat with synthetic bytes, never read_actor."""
        proc = modules['mta_client_proc']
        completed, vectors = [], []
        root, leader = '/proc/41/stat', '/proc/41/task/41/stat'
        baseline = _stat_bytes()
        def data(last=baseline, led=baseline, pass_index=1):
            return [_raw_stat(proc, root, baseline, 'pid_stat', pass_index),
                _raw_stat(proc, leader, led, 'task_stat', pass_index),
                _raw_stat(proc, root, last, 'pid_stat', pass_index)]
        def call(raw, passes=0):
            observation, generation = _pair(runtime, native, entry, reader, modules, raw)
            object.__setattr__(observation, 'passes', passes)
            text = self.pure(lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
                runtime, native, reader, loader)
            self.assertIs(native.last_proc_failure_v60[0], observation)
            self.assertIs(native.last_proc_failure_v60[1], reader)
            self.assertLessEqual(len(text.encode('ascii')), 512)
            return text
        for failed_pass in (1, 2):
            raw = data(pass_index=failed_pass)
            if failed_pass == 2:
                # Earlier pass differs; only the actual failed pass is compared.
                raw = data(_stat_bytes(flags=3), _stat_bytes(comm=b'EARLIER'), 1) + raw
            text = call(raw, failed_pass - 1)
            self.assertEqual('PROC65 failed_pass=%d fields=pid/start/comm/flags/ppid/threads '
                'first_last=000000 first_leader=000000 rootmeta=unavailable\n' % failed_pass, text)
            completed.append('failed_pass_' + str(failed_pass))
        changes = (('start', dict(start=101), '010000'), ('comm', dict(comm=b'HOST_DIFF'), '001000'),
            ('flags', dict(flags=2), '000100'), ('ppid', dict(ppid=2), '000010'),
            ('threads', dict(threads=2), '000001'))
        for name, changed, bits in changes:
            altered = _stat_bytes(**changed)
            actual = proc.parse_stat(altered, 41)
            original = proc.parse_stat(baseline, 41)
            fields = ('pid', 'start', 'comm', 'flags', 'ppid', 'threads')
            self.assertEqual(bits, ''.join('1' if getattr(actual, field) != getattr(original, field) else '0'
                for field in fields))
            for destination in ('last', 'leader'):
                text = call(data(last=altered) if destination == 'last' else data(led=altered))
                self.assertIn('first_last=' + (bits if destination == 'last' else '000000'), text)
                self.assertIn('first_leader=' + (bits if destination == 'leader' else '000000'), text)
                self.assertIn('rootmeta=unavailable', text)
                self.assertNotIn('HOST_', text)
                self.assertNotIn('/proc/', text)
                completed.append(name + '_' + destination)
                vectors.append(bits)
        # Same canonical path forces PID equality through original parse_stat.
        # A different raw PID is denied, never a fabricated positive pid bit.
        text = call(data(last=_stat_bytes(pid=42)))
        self.assertEqual('PROC65=unavailable\n', text)
        completed.append('raw_pid_path_mismatch')

        negatives = []
        negatives.append(('missing_last', data()[:2]))
        negatives.append(('multiple_last', data() + data()[-1:]))
        negatives.append(('missing_leader', data()[::2]))
        negatives.append(('multiple_leader', [data()[0], data()[1], data()[1], data()[2]]))
        negatives.append(('leader_after_last', [data()[0], data()[2], data()[1]]))
        negatives.append(('different_root_path', [data()[0], data()[1],
            _raw_stat(proc, '/proc/42/stat', _stat_bytes(pid=42), 'pid_stat', 1)]))
        negatives.append(('wrong_leader_path', [data()[0],
            _raw_stat(proc, '/proc/41/task/42/stat', _stat_bytes(pid=42), 'task_stat', 1), data()[2]]))
        negatives.append(('foreign_record', [data()[0], Foreign(), data()[2]]))
        negatives.append(('foreign_raw_data', [data()[0], data()[1],
            _raw_stat(proc, root, Foreign(), 'pid_stat', 1)]))
        negatives.append(('foreign_path', [data()[0], data()[1],
            _raw_stat(proc, Foreign(), baseline, 'pid_stat', 1)]))
        negatives.append(('bool_pass_index', [data()[0],
            _raw_stat(proc, leader, baseline, 'task_stat', True), data()[2]]))
        negatives.append(('malformed_stat', data(last=b'invalid_stat\n')))
        for name, raw in negatives:
            self.assertEqual('PROC65=unavailable\n', call(raw))
            completed.append(name)

        original_raw = data()
        observation, generation = _pair(runtime, native, entry, reader, modules, original_raw)
        for owner, field, bad in ((observation, 'raw', list(original_raw)),
                (observation, 'raw', Foreign()), (observation, 'passes', True),
                (observation, 'reason', Foreign()), (observation, 'stage', Foreign()),
                (native, 'last_proc_failure_v60', Foreign())):
            saved = getattr(owner, field)
            try:
                object.__setattr__(owner, field, bad)
                self.assertEqual('PROC65=unavailable\n', self.pure(
                    lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
                    runtime, native, reader, loader))
            finally:
                object.__setattr__(owner, field, saved)
            completed.append('bad_' + field)
        # Definition-time parser/module continuity is a pure deny-only gate.
        with mock.patch.object(proc, 'parse_stat', side_effect=AssertionError('HOST replaced parser forbidden')) as probe:
            self.assertEqual('PROC65=unavailable\n', self.pure(
                lambda: executor._proc_stat_diff_text_v65(runtime, deployment), runtime, native, reader, loader))
            self.assertEqual(0, probe.call_count)
        completed.append('parser_replaced')
        actual_proc = deployment.modules['mta_client_proc']
        deployment.modules['mta_client_proc'] = types.ModuleType('HOST_foreign_proc_domain')
        try:
            self.assertEqual('PROC65=unavailable\n', self.pure(
                lambda: executor._proc_stat_diff_text_v65(runtime, deployment), runtime, native, reader, loader))
        finally:
            deployment.modules['mta_client_proc'] = actual_proc
        completed.append('foreign_proc_module')
        return completed, vectors

    def domain_cases(self, runtime, native, entry, reader, deployment, loader, executor, modules, ordinary):
        """SOURCE-shaped mixed domains; no call to actual Loader.load."""
        proc, module = modules['mta_client_proc'], modules['mta_go_native']
        captured = module._PROC65_ORIGINALS
        self.assertIs(type(captured), tuple)
        self.assertEqual(2, len(captured))
        self.assertIs(captured[0], proc)
        self.assertIs(captured[1], proc.parse_stat)
        self.assertIsNot(proc, ordinary)
        self.assertIsNot(proc.ProcObservation, ordinary.ProcObservation)
        self.assertIsNot(proc.RawRecord, ordinary.RawRecord)
        self.assertIs(sys.modules['mta_client_proc'], ordinary)
        self.assertIs(executor.sources, modules['mta_go_deployment'])
        self.assertNotIn('_proc65_source', executor.__dict__)
        self.assertNotIn('_PROC65_ORIGINALS', executor.__dict__)
        raw = [_raw_stat(proc, '/proc/41/stat', _stat_bytes(), 'pid_stat', 1),
            _raw_stat(proc, '/proc/41/task/41/stat', _stat_bytes(), 'task_stat', 1),
            _raw_stat(proc, '/proc/41/stat', _stat_bytes(), 'pid_stat', 1)]
        observation, unused = _pair(runtime, native, entry, reader, modules, raw)
        answer = self.pure(lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
            runtime, native, reader, loader)
        self.assertIn('first_last=000000 first_leader=000000', answer)
        completed = ['actual_private_capture_with_distinct_ordinary_proc']
        # A different tuple of identical original members is not forbidden by
        # this data gate. Wrong shape/member/function domains ARE forbidden.
        for bad in ([proc, proc.parse_stat], (proc,), (ordinary, ordinary.parse_stat),
                (proc, ordinary.parse_stat), (Foreign(), proc.parse_stat), Foreign()):
            try:
                module._PROC65_ORIGINALS = bad
                self.assertEqual('PROC65=unavailable\n', self.pure(
                    lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
                    runtime, native, reader, loader))
            finally:
                module._PROC65_ORIGINALS = captured
            completed.append('capture_shape_or_domain_denial')
        ordinary_raw = list(raw)
        ordinary_raw[1] = ordinary.RawRecord('task_stat', 1, '/proc/41/task/41/stat', _stat_bytes(), ())
        saved_raw = observation.raw
        try:
            object.__setattr__(observation, 'raw', tuple(ordinary_raw))
            self.assertEqual('PROC65=unavailable\n', self.pure(
                lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
                runtime, native, reader, loader))
        finally:
            object.__setattr__(observation, 'raw', saved_raw)
        completed.append('ordinary_rawrecord_type_denial')
        old_pair = native.last_proc_failure_v60
        ordinary_observation = ordinary.ProcObservation('unknown', 'pid_identity_changed', 'pid_stat',
            entry.boot, None, False, (), False, 0, tuple(raw), 0, 0, False, 0)
        try:
            native.last_proc_failure_v60 = (ordinary_observation, reader)
            self.assertEqual('PROC65=unavailable\n', self.pure(
                lambda: executor._proc_stat_diff_text_v65(runtime, deployment),
                runtime, native, reader, loader))
        finally:
            native.last_proc_failure_v60 = old_pair
        completed.append('ordinary_observation_type_denial')
        self.assertIs(module._PROC65_ORIGINALS, captured)
        self.assertIs(native.last_proc_failure_v60[0], observation)
        self.assertEqual(0, Foreign.touched)
        return completed

    def fd2_cases(self, source, runtime, native, entry, reader, deployment, loader, executor, modules):
        """Actual unchanged diagnostic tail only; synthetic exception strings."""
        tail = _diagnostic_tail(source['mta_go_executor'], executor)
        proc = modules['mta_client_proc']
        _pair(runtime, native, entry, reader, modules,
            [_raw_stat(proc, '/proc/41/stat', _stat_bytes(), 'pid_stat', 1),
             _raw_stat(proc, '/proc/41/task/41/stat', _stat_bytes(), 'task_stat', 1),
             _raw_stat(proc, '/proc/41/stat', _stat_bytes(), 'pid_stat', 1)])
        native._snapshot_timing_v55 = [[16.0, 301.0, 'rest', None, [1.0, 1.1, 1.2, 1.3, 1.4]]]
        original_pair, original_last, original_until = native.last_proc_failure_v60, native.last, native.until
        completed = []
        def invoke(phase, primary, restore, failing_write=False):
            runtime.phase, runtime.failure, runtime.restore_failure = phase, primary, restore
            with ExitStack() as no_business:
                probes = [no_business.enter_context(mock.patch.object(loader, 'authenticate',
                    side_effect=AssertionError('HOST diagnostic tail authentication forbidden')))]
                for method in ('read_self', 'read_actor', 'owns_generation', 'history_closed'):
                    probes.append(no_business.enter_context(mock.patch.object(reader, method,
                        side_effect=AssertionError('HOST diagnostic tail Reader call forbidden'))))
                for method in ('_owner', '_check', '_now', '_file', '_proc', '_record'):
                    probes.append(no_business.enter_context(mock.patch.object(native, method,
                        side_effect=AssertionError('HOST diagnostic tail Native call forbidden'))))
                probes.append(no_business.enter_context(mock.patch.object(executor.time, 'monotonic',
                    side_effect=AssertionError('HOST diagnostic tail clock forbidden'))))
                output = no_business.enter_context(mock.patch.object(executor.os, 'write',
                    side_effect=OSError(errno.EIO, 'HOST private write failed') if failing_write else None))
                result = tail(runtime, deployment, 1)
                self.assertEqual(1, result)
                self.assertEqual(1, output.call_count)
                args = output.call_args.args
                self.assertEqual(2, args[0])
                self.assertIs(type(args[1]), bytes)
                raw = args[1]
                for probe in probes:
                    self.assertEqual(0, probe.call_count)
            self.assertLessEqual(len(raw), 16384)
            raw.decode('utf-8', 'strict')
            self.assertIs(native.last_proc_failure_v60, original_pair)
            self.assertEqual(original_last, native.last)
            self.assertEqual(original_until, native.until)
            return raw
        raw = invoke('diagnostic_fixture', RuntimeError('HOST_PRIMARY'), RuntimeError('HOST_RESTORE'))
        self.assertLess(raw.index(b'PROC60 '), raw.index(b'PROC65 '))
        self.assertLess(raw.index(b'PROC65 '), raw.index(b'SNAP55#1 '))
        self.assertLess(raw.index(b'SNAP55#1 '), raw.index(b'PRIMARY\n'))
        self.assertLessEqual(raw.index(b'PRIMARY\n'), 2048)
        self.assertLess(raw.index(b'PRIMARY\n'), raw.index(b'RESTORE\n'))
        completed.append('priority_and_single_fd2')
        raw = invoke('A' * 8192, RuntimeError('P' * 20000), RuntimeError('R' * 20000))
        self.assertEqual(16384, len(raw))
        self.assertEqual(2048, raw.index(b'PRIMARY\n'))
        self.assertEqual(9216, raw.index(b'RESTORE\n'))
        completed.append('head2048_and_aggregate16384')
        raw = invoke('\u4e2d' * 4096, RuntimeError('\u6587' * 10000), RuntimeError('\u672c' * 10000))
        self.assertLessEqual(raw.index(b'PRIMARY\n'), 2048)
        self.assertGreater(raw.index(b'PRIMARY\n'), 2044)
        self.assertLessEqual(raw.index(b'RESTORE\n') - raw.index(b'PRIMARY\n'),
            (16384 - raw.index(b'PRIMARY\n')) // 2)
        self.assertIn(b'RESTORE\n', raw)
        completed.append('utf8_boundary')
        invoke('diagnostic_fixture', None, None, True)
        completed.append('write_error_preserves_result')
        return completed

    def test_only_new_stat6diff_timing32_selection_and_private_utf8_bounds(self):
        rows, source, originals = _inputs()
        _source_delta(source, originals)
        with ExitStack() as definitions:
            modules, ordinary = _definition_domain(rows, source, definitions)
            runtime, native, entry, reader, deployment, loader, executor = _data_fixture(modules)
            Foreign.touched = 0
            timings = self.timing_cases(runtime, native, reader, loader, executor)
            stats, vectors = self.stat_cases(runtime, native, entry, reader, deployment, loader, executor, modules)
            domains = self.domain_cases(runtime, native, entry, reader, deployment, loader, executor, modules, ordinary)
            fd2 = self.fd2_cases(source, runtime, native, entry, reader, deployment, loader, executor, modules)
            self.assertEqual((12, 33, 9, 10, 4),
                (len(timings), len(stats), len(domains), len(vectors), len(fd2)))
            self.assertEqual(0, Foreign.touched)
            self.assertEqual(7.0, native.last)
            self.assertEqual(301.0, native.until)
            self.assertIs(modules['mta_go_native']._PROC65_ORIGINALS[0], modules['mta_client_proc'])
            print('HOST66_PRIVATE_DIAGNOSTIC timing=%d stat=%d domains=%d vectors=%d capacity_callbacks=160 fd2=%d '
                'private_sources=17 old_methods=0' %
                (len(timings), len(stats), len(domains), len(vectors), len(fd2)))


if __name__ == '__main__':
    unittest.main()
