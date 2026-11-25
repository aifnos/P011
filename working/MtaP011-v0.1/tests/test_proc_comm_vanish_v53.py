"""One new paired CLIENT51/GO52 comm-open race HOST method.

Actual source graphs, constructors, Proc producers, file pins and closure gates
run in two disjoint type domains. Only Linux syscalls/clock are modeled. This
does not execute collect(), Bootstrap.run(), reserve(), a radio or an old test.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import json
from pathlib import Path
import re
import socket
import stat
import sys
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
CLIENT_PLAN = 'host/client_readonly_proc_vanish_v51_source_manifest.json'
CLIENT_PLAN_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
CLIENT_PLAN_BYTES = 8096
CLIENT_PREVIOUS = 'host/client_readonly_diagnostic_v47_source_manifest.json'
CLIENT_PREVIOUS_SHA = '212caa6f86340d6fcfedee5714d8df5226e1eaf1e151b16c0742ab900c4ffbe0'
CLIENT_PREVIOUS_BYTES = 8095
GO_PLAN = 'host/go_proc_vanish_v52_source_manifest.json'
GO_PLAN_SHA = '1a4046f95ddcebfc6bbcac17df4518f0ba33759ce9f64484c569667ca5343311'
GO_PLAN_BYTES = 3952
GO_PREVIOUS = 'host/go_pin_digest_v49_source_manifest.json'
GO_PREVIOUS_SHA = '4b1f0322295f5612f70ddca4797d223b919e775a4b23a4218cbe48c66451a110'
GO_PREVIOUS_BYTES = 3951
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
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
CASES = ('open_enoent', 'open_eio', 'open_eacces', 'fd_fstat_enoent',
    'fd_read_enoent', 'close_enoent', 'tracked_proc_missing', 'tracked_image_missing',
    'mandatory_comm_missing', 'late_open_enoent')


def fixed(path, digest, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed source changed')
    return raw


def inputs():
    trees, graphs = {}, {}
    for kind, new, old in (
            ('client', (CLIENT_PLAN, CLIENT_PLAN_SHA, CLIENT_PLAN_BYTES),
                (CLIENT_PREVIOUS, CLIENT_PREVIOUS_SHA, CLIENT_PREVIOUS_BYTES)),
            ('go', (GO_PLAN, GO_PLAN_SHA, GO_PLAN_BYTES),
                (GO_PREVIOUS, GO_PREVIOUS_SHA, GO_PREVIOUS_BYTES))):
        current, previous = json.loads(fixed(*new)), json.loads(fixed(*old))
        changed = 'mta_client_baseline' if kind == 'client' else 'mta_go_native'
        if set(current) != set(previous) or any(current[k] != previous[k] for k in current if k != 'sources'):
            raise ValueError('HOST graph metadata changed')
        rows, former = current['sources'], previous['sources']
        if len(rows) != (35 if kind == 'client' else 17) or [r['module'] for r in rows] != [r['module'] for r in former]:
            raise ValueError('HOST graph inventory changed')
        if [r['module'] for r, p in zip(rows, former) if r != p] != [changed]:
            raise ValueError('HOST graph is not one-source delta')
        trees[kind] = rows
        graphs[kind] = {r['module']: fixed(r['path'], r['sha256'], r['bytes']) for r in rows}
        graphs[kind]['HOST_WPA'] = fixed(*WPA)
    stock = {path: fixed(relative, digest, size) for path, relative, digest, size in STOCK}
    model = types.ModuleType('HOST_proc_comm_vanish_v53_linux_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    raw = fixed(HELPER, HELPER_SHA, HELPER_BYTES)
    selected = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
    if tuple(n.name for n in selected) != FUNCTIONS: raise ValueError('HOST helper inventory')
    helper = dict(globals())
    exec(compile(ast.Module(body=selected, type_ignores=[]), HELPER, 'exec'), helper)
    return trees, graphs, stock, model, helper


def client_domain(rows, source):
    """All 35 actual definitions; no old test import and no shared GO classes."""
    modules, original = {}, builtins.__import__
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(('mta_', 'p011_')):
            if level or name not in modules: raise ImportError('HOST unlisted CLIENT source')
            return modules[name]
        return original(name, globals, locals, fromlist, level)
    for row in rows:
        name = row['module']
        value = types.ModuleType(name)
        value.__file__ = 'HOST-proc-comm-client-v53/' + name + '.py'
        value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = value
        exec(compile(source[name], value.__file__, 'exec'), value.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST actual CLIENT graph changed')
    return modules


def make_client(rows, source, stock, model, helper, stack):
    helper['tripwires'](stack)
    modules = client_domain(rows, source)
    io = model.LinuxModel(rows, source, stock)
    io.install_actor(100, 100, model.PYTHON, b'/usr/bin/python3.5\0HOST_only\0')
    core, proc, stores = (modules[n] for n in ('mta_p2p_client_init', 'mta_client_proc', 'mta_client_store'))
    reader = proc.ProcReader(timeout=5.0, _fs=io, _clock=io.clock)
    store = stores.DurableClientInitStore('7' * 32, core.Identity(CLIENT_PLAN_SHA),
        timeout=5.0, _proc_reader=reader, _clock=io.clock)
    manifest = tuple((p, digest) for p, relative, digest, size in STOCK) + (
        ('/usr/sbin/wpa_cli', hashlib.sha256(model.CLI).hexdigest()),)
    collector = modules['mta_client_baseline'].BaselineCollector(manifest, timeout=5.0,
        _io=io, _reader=reader, _clock=io.clock)
    # Explicit HOST private-method stage: the same once-only collect issuance
    # expression, not a collect result, Journal, publication or network grant.
    collector._deadline = min(11.0, collector._now() + collector._timeout)
    for path, expected in manifest:
        raw, ticket, metadata = collector._read_file(path, modules['mta_client_baseline'].MAX_FILE, binary=True)
        if hashlib.sha256(raw).hexdigest() != expected: raise AssertionError('HOST actual pin prep failed')
        collector._binaries[path] = (ticket, metadata, collector._binary_parents(path))
    return io, modules, collector, store, reader, None


def make_go(rows, source, stock, model, helper, stack):
    helper['tripwires'](stack)
    io, modules, deployment, loader, executor, created = helper['load_model'](
        rows, source, stock, model, None, stack)
    entry = executor._entry(deployment, model.UNTIL, repr(model.UNTIL),
        '--go-bootstrap', io.clock, io)
    runtime = modules['mta_go_bootstrap'].GoBootstrap(deployment, entry, clock=io.clock)
    if created != [runtime]: raise AssertionError('HOST constructor inventory')
    native = runtime.native
    with native.mutex: native._begin(runtime._stage(10))
    return io, modules, native, runtime.store, entry.reader, runtime


class Fault(object):
    """Only existing syscall seams; retains one original returned/raised fact."""
    def __init__(self, io, subject, graph, case):
        self.io, self.subject, self.graph, self.case = io, subject, graph, case
        self.target = '/proc/41/comm' if case == 'mandatory_comm_missing' else '/proc/12/comm'
        self.path = '/proc/41/stat' if case == 'tracked_proc_missing' else (
            '/proc/41/exe' if case == 'tracked_image_missing' else self.target)
        self.error = OSError(errno.EIO if case == 'open_eio' else
            errno.EACCES if case == 'open_eacces' else errno.ENOENT, 'HOST original syscall fault')
        self.used, self.fd, self.fstats, self.close_calls = False, None, 0, 0
        self.ticket_before = self.ticket_after = None
        self.original_open, self.original_fstat = io.open, io.fstat
        self.original_read, self.original_close = io.read, io.close
    def tickets(self): return self.subject._tickets if self.graph == 'client' else self.subject.rows
    def open(self, path, flags=None):
        if path == self.path and not self.used and self.case in (
                'open_enoent', 'open_eio', 'open_eacces', 'mandatory_comm_missing',
                'late_open_enoent', 'tracked_proc_missing', 'tracked_image_missing'):
            self.used = True; self.ticket_before = len(self.tickets()) - 1
            self.ticket_after = len(self.tickets())
            self.io.event('open', path, flags)
            if self.case == 'late_open_enoent':
                self.io.clock.value = self.subject._deadline if self.graph == 'client' else self.subject._scope
            raise self.error
        result = self.original_open(path, flags)
        if path == self.target: self.fd = result
        return result
    def fstat(self, fd):
        if fd == self.fd:
            self.fstats += 1
            # GO adoption performs its own first fstat. Inject the next actual
            # read gate, never a fabricated no-FD open failure.
            if self.case == 'fd_fstat_enoent' and not self.used and self.fstats == (1 if self.graph == 'client' else 2):
                self.used = True; raise self.error
        return self.original_fstat(fd)
    def read(self, fd, count):
        if fd == self.fd and self.case == 'fd_read_enoent' and not self.used:
            self.used = True; raise self.error
        return self.original_read(fd, count)
    def close(self, fd):
        if fd == self.fd: self.close_calls += 1
        result = self.original_close(fd)
        if fd == self.fd and self.case == 'close_enoent' and not self.used:
            self.used = True; raise self.error
        return result
    def install(self, stack):
        for name in ('open', 'fstat', 'read', 'close'):
            stack.enter_context(mock.patch.object(self.io, name, getattr(self, name)))


class ProcCommVanishV53Tests(unittest.TestCase):
    def test_paired_original_comm_open_absence_and_non_absence_refusals(self):
        trees, graphs, stock, model, helper = inputs()
        completed, skips, refusals, uncertain = [], 0, 0, 0
        class_origins = {}
        for graph in ('client', 'go'):
            for case in CASES:
                with self.subTest(graph=graph, case=case), ExitStack() as stack:
                    factory = make_client if graph == 'client' else make_go
                    io, modules, subject, store, reader, runtime = factory(
                        trees[graph], graphs[graph], stock, model, helper, stack)
                    class_origins[graph] = modules['mta_p2p_client_init'].Actor
                    self.assertIs(reader._bound_budget_v24, store._resource_budget_v23 if graph == 'client' else runtime.entry.budget)
                    self.assertTrue(reader.history_closed())
                    self.assertFalse(store._attempted if graph == 'client' else store.attempted)
                    self.assertFalse(store._opened if graph == 'client' else store.restore_attempted)
                    cap = subject._deadline if graph == 'client' else subject._scope
                    self.assertEqual(6.0 if graph == 'client' else 11.0, cap)
                    io.install_actor(12, 12, '/usr/bin/untracked', b'/usr/bin/untracked\0')
                    fault = Fault(io, subject, graph, case)
                    fault.install(stack)
                    result, error = None, None
                    try:
                        if graph == 'go':
                            with subject.mutex:
                                result = subject._actors()
                                if case == 'tracked_image_missing': subject._pins(result)
                        else: result = subject._actors()
                    except BaseException as caught:
                        error = caught
                    self.assertTrue(fault.used, helper['diagnostic'](runtime) if runtime is not None else case)
                    if case == 'open_enoent':
                        self.assertIsNone(error)
                        self.assertIs(type(result), tuple)
                        required = ('Z03', 'control_engine', 'weston') + (('wpa_supplicant',) if graph == 'go' else ())
                        for name in required:
                            self.assertEqual(1, sum(a.exe.rsplit('/', 1)[-1] == name for a in result))
                        self.assertTrue(all(type(a) is modules['mta_p2p_client_init'].Actor and a.live() for a in result))
                        self.assertTrue(all(v.kind == 'live_actor' and v.passes == 2 and v.resource_pending is False
                            for v in (subject._observations if graph == 'client' else subject.proc_observations)))
                        self.assertTrue(reader.history_closed())
                        self.assertEqual(fault.ticket_before + 1, fault.ticket_after)
                        row = (subject._tickets if graph == 'client' else subject.rows)[fault.ticket_before]
                        if graph == 'client':
                            self.assertIs(row['open_error_original_v47'], fault.error)
                            self.assertEqual(fault.target, row['open_requested_path_v47'])
                            self.assertEqual(modules['mta_client_baseline']._READ_FLAGS, row['open_requested_flags_v47'])
                            self.assertIsNone(row['fd']); self.assertIsNone(row['value'])
                            self.assertFalse(row['unknown']); self.assertTrue(row['closed']); self.assertFalse(row['attempted'])
                            images = [r for r in subject._raw if r[0] == 'actor_image']
                            self.assertEqual(2, len(images))
                            self.assertEqual({dict(subject._manifest)['/usr/bin/Z03'], dict(subject._manifest)['/usr/bin/control_engine']},
                                {r[2] for r in images})
                        else:
                            self.assertIs(row._open_error_original_v52, fault.error)
                            self.assertEqual(fault.target, row._open_requested_path_v52)
                            self.assertEqual(modules['mta_go_native']._CLOEXEC | modules['mta_go_native']._NOFOLLOW, row._open_requested_flags_v52)
                            self.assertFalse(row.returned); self.assertIsNone(row.fd); self.assertIsNone(row.value); self.assertIsNone(row.metadata)
                            self.assertFalse(row.unknown); self.assertTrue(row.closed); self.assertTrue(row.attempted)
                        self.assertEqual(0, fault.close_calls)
                        skips += 1
                    elif case == 'close_enoent':
                        self.assertIsNotNone(fault.fd)
                        self.assertEqual(1, fault.close_calls)
                        self.assertEqual(1, io.closed.count(fault.fd))
                        if graph == 'client':
                            self.assertIsNone(error)  # Native Baseline close records pending instead of rethrowing.
                            self.assertIs(type(result), tuple)
                            row = next(r for r in subject._tickets if r['fd'] == fault.fd)
                            self.assertTrue(row['attempted']); self.assertFalse(row['closed']); self.assertTrue(subject._pending)
                            self.assertFalse(subject.close())
                        else:
                            self.assertIs(error, fault.error)
                            row = next(r for r in subject.rows if r.fd == fault.fd)
                            self.assertTrue(row.returned); self.assertTrue(row.attempted); self.assertFalse(row.closed)
                            self.assertIs(row.close_failure, fault.error)
                            with self.assertRaises(modules['mta_go_deployment'].GoSourceError) as retry:
                                subject._close(row)
                            self.assertEqual('native_close_pending', retry.exception.code)
                            self.assertFalse(all(a and b for a, b in subject.closed_facts()))
                        self.assertEqual(1, fault.close_calls)
                        uncertain += 1; refusals += 1
                    else:
                        self.assertIsNotNone(error)
                        if case in ('open_eio', 'open_eacces', 'fd_fstat_enoent', 'fd_read_enoent', 'tracked_image_missing'):
                            self.assertIs(error, fault.error)
                        if case == 'mandatory_comm_missing':
                            self.assertEqual('actor_unknown' if graph == 'client' else 'native_actor_unknown', error.code)
                        if case == 'late_open_enoent': self.assertEqual('deadline', error.code)
                        if case == 'tracked_proc_missing':
                            self.assertEqual('actor_unknown' if graph == 'client' else 'native_actor_unknown', error.code)
                            observations = subject._observations if graph == 'client' else subject.proc_observations
                            self.assertTrue(observations)
                            self.assertEqual('unknown', observations[-1].kind)
                        if case in ('fd_fstat_enoent', 'fd_read_enoent'):
                            self.assertIsNotNone(fault.fd)
                            self.assertEqual(1, fault.close_calls)
                        refusals += 1
                    self.assertEqual(cap, subject._deadline if graph == 'client' else subject._scope)
                    if graph == 'client':
                        closed = subject.close()
                        self.assertEqual(case != 'close_enoent', closed)
                        self.assertFalse(subject._success)
                        self.assertEqual([], subject._rounds)
                        self.assertEqual(0, subject._packets)
                        self.assertIsNone(store._canonical); self.assertIsNone(store._marker)
                        self.assertFalse(store._attempted); self.assertFalse(store._opened)
                    else:
                        self.assertEqual(model.UNTIL, runtime.until)
                        self.assertEqual(model.UNTIL, subject.until)
                        self.assertIsNone(store.current); self.assertEqual((), store._canonical_history)
                        self.assertFalse(store.attempted); self.assertFalse(store.restore_attempted)
                        self.assertFalse(store.logical_restored); self.assertFalse(runtime.restore_attempted)
                        self.assertEqual([], runtime.launcher._tickets)
                        self.assertEqual(0, store._fd_attempts)
                        self.assertEqual(0, subject._packets)
                        if case != 'close_enoent': self.assertTrue(all(a and b for a, b in subject.closed_facts()))
                    self.assertEqual(0, io.create_count); self.assertEqual(0, io.delete_count)
                    self.assertEqual([], io.sockets)
                    self.assertFalse(io.live)
                    self.assertEqual(len(io.closed), len(set(io.closed)))
                    completed.append(graph + ':' + case)
        self.assertIsNot(class_origins['client'], class_origins['go'])
        self.assertEqual([g + ':' + c for g in ('client', 'go') for c in CASES], completed)
        self.assertEqual((2, 18, 2), (skips, refusals, uncertain))
        print('PROC_COMM_VANISH_V53_HOST_PASS paired_cases=10 graph_cases=20 known_open_skips=%d refusals=%d uncertain_close_attempts=%d rf_calls=0' %
            (skips, refusals, uncertain))


if __name__ == '__main__': unittest.main()
