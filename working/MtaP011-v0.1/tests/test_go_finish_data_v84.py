"""One new F84 private finish-DATA method; SOURCE until ROOT alone runs it.

The eleven pinned production files supply exact class/function definitions.
JSON/IP/core/facts are defined in a private module domain; the other files
supply explicitly selected, unchanged AST ClassDefs/functions/constants.
No old test, Loader.load/authentication, Entry preparation, Bootstrap ctor or
restore, native producer, syscall, child wait/reap, RF or phone flow executes.

Actual classes allocated with __new__ below contain SYNTHETIC Journal, FS,
deadline, issuer/history and returned_restore facts. They are not actual native
issuance or physical closure. Actual GoRecord/Snapshot constructors and their
pure encode/key algorithms validate this DATA. The new F84 helpers are never
replaced. Seven independent typed DATA domains cover two positive and five
refusal cases; an eighth SOURCE assertion checks default-run unavailable.
That eighth case does not call default bootstrap/run or claim restoration.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import math
from pathlib import Path
import re
import stat
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
INPUTS = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'candidate/client-session-v28/runtime/mta_p2p_client_init.py', 69966,
     '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    ('mta_client_journal_codec', 'candidate/client-session-v28/runtime/mta_client_journal_codec.py', 17450,
     '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_go_deployment', 'candidate/go-send-transport-v76/runtime/mta_go_deployment.py', 26113,
     '3abac40ec1fc0a6d223a7238cd10eb86fd2942407ec26156484826021eb161e8'),
    ('mta_client_proc', 'candidate/client-proc-deadline-v25/runtime/mta_client_proc.py', 39384,
     'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_go_process_owner', 'candidate/go-bootstrap-v33-r3/runtime/mta_go_process_owner.py', 42612,
     '78a480728a348e98e578acf4e7c778be50bfae3411ba5d34bb563493e1ba6583'),
    ('mta_go_bootstrap_store', 'candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap_store.py', 78430,
     '24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae'),
    ('mta_go_native', 'candidate/go-send-transport-v76/runtime/mta_go_native.py', 200317,
     'ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f'),
    ('mta_go_bootstrap', 'candidate/go-send-transport-v76/runtime/mta_go_bootstrap.py', 30951,
     '25247dcb905b53cab1e1df1d0949e8c9296b91caf36d94d4c1171763cbc46568'),
    ('mta_go_executor', 'candidate/go-send-finish-v84/runtime/mta_go_executor.py', 53767,
     'cb9ef6d0ef97fbaca77c873245184d9dc5f0ee97c381790bb1102dc640a5623d'),
)
MARKER = ('HOST84_FINISH_DATA new_methods=1 old_methods=0 cases=8 '
          'returned_restore_model=true device=false phone=false\n')


def _inputs():
    source = {}
    for name, path, size, digest in INPUTS:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('HOST fixed finish input changed')
        source[name] = raw
    return source


def _selected(source, filename, namespace, definitions=(), assignments=()):
    """Execute unchanged selected definition AST only, never source main/calls.

    The selection is exact and must find each requested name once. This is a
    HOST fixture definition mechanism, not the production Loader or RF graph.
    """
    tree = ast.parse(source.decode('utf-8'), filename=filename)
    nodes, counts = [], {name: 0 for name in definitions + assignments}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in definitions:
            counts[node.name] += 1
            nodes.append(node)
        elif isinstance(node, ast.Assign):
            names = {item.id for target in node.targets for item in ast.walk(target)
                     if isinstance(item, ast.Name)}
            matched = names.intersection(assignments)
            if matched:
                for name in matched:
                    counts[name] += 1
                nodes.append(node)
    if any(count != 1 for count in counts.values()):
        raise ValueError('HOST selected finish definition changed')
    selected = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected), filename, 'exec'), namespace)
    return tree


def _domain(source):
    modules, original_import = {}, builtins.__import__
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(('mta_', 'p011_')):
            if level or name not in modules:
                raise ImportError('HOST unlisted finish definition')
            return modules[name]
        return original_import(name, globals, locals, fromlist, level)
    def module(name):
        value = types.ModuleType(name)
        value.__file__ = str(BASE / next(row[1] for row in INPUTS if row[0] == name))
        value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = value
        return value
    for name in ('p011_json', 'mta_ip', 'mta_p2p_client_init', 'mta_client_journal_codec'):
        value = module(name)
        exec(compile(source[name], value.__file__, 'exec'), value.__dict__)
    common = {'math': math, 're': re, 'stat': stat, 'threading': threading,
              'time': time, 'types': types, 'hashlib': hashlib}
    value = module('mta_go_deployment')
    value.__dict__.update(common)
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('GoManifest', 'LoadedGoDeployment'), ('_MANIFEST_KEYS',))
    value = module('mta_client_proc')
    value.__dict__.update(common, owner=modules['mta_p2p_client_init'])
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('_Private', 'ProcObservation', 'ProcGeneration', 'ProcReader'))
    value = module('mta_go_process_owner')
    value.__dict__.update(common)
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('LaunchSpec', '_FD', 'ChildTicket', 'GoDirectChildOwner'))
    value = module('mta_go_bootstrap_store')
    value.__dict__.update(common, json=modules['p011_json'], core=modules['mta_p2p_client_init'],
                          facts=modules['mta_client_journal_codec'], ip=modules['mta_ip'])
    _selected(source[value.__name__], value.__file__, value.__dict__,
        ('GoStoreError', '_fail', '_uint', '_number', '_hex', '_boot', 'GoChildFacts',
         '_group', '_group_data', 'GoIpFacts', 'GoDhcpFacts', 'GoRecord', 'encode',
         'GoCanonical', '_Fd', 'GoBootstrapStore'),
        ('DEVICE_LOCK', 'JOURNAL_LOCK', 'SCHEMA', 'MAX_FDS', 'MAX_RECORD',
         'MAX_PUBLICATIONS', 'MAX_ACTIVE_SECONDS', '_ACTIVE_PHASES', '_CLEANUP_PHASES', '_PHASES', '_KEYS'))
    value = module('mta_go_native')
    value.__dict__.update(common)
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('_Resource', '_Observation', 'GoBaselineObservation', 'GoNativeRestoreObservation',
               'NativeGoResources'), ('_MAX_FDS',))
    value = module('mta_go_bootstrap')
    value.__dict__.update(common, native=modules['mta_go_native'], sources=modules['mta_go_deployment'])
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('GoRestoreObservation', 'GoBootstrap'))
    value = module('mta_go_executor')
    value.__dict__.update(common, sources=modules['mta_go_deployment'])
    tree = _selected(source[value.__name__], value.__file__, value.__dict__,
              ('GoEntrySource', 'GoSendLaunch', '_finish_refs_v84', '_finish_data_v84',
               '_capture_finish_data_v84'),
              ('_ENTRY_INVENTORY', '_SEND_LAUNCH_TOKEN', '_FINISH_TOKEN_V84', '_FINISH_MAX_V84'))
    return modules, tree


def _set(value, **fields):
    # Only fixture field population in explicitly synthetic exact class data.
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


class _FactsModel(object):
    """No production constructor/return/FD close is claimed by these models."""
    def __init__(self, modules):
        self.modules = modules
        f, stores, native, boot, proc, process, sources, core, ip = (modules[n] for n in (
            'mta_go_executor', 'mta_go_bootstrap_store', 'mta_go_native', 'mta_go_bootstrap',
            'mta_client_proc', 'mta_go_process_owner', 'mta_go_deployment', 'mta_p2p_client_init', 'mta_ip'))
        worker, until, cleanup = threading.current_thread(), 301.0, 340.0
        self.clock = mock.Mock(side_effect=AssertionError('HOST unexpected finish clock'))
        self.authenticate = mock.Mock(side_effect=AssertionError('HOST unexpected source authentication'))
        self.loader = types.SimpleNamespace(authenticate=self.authenticate, launcher=None)
        manifest = _set(object.__new__(sources.GoManifest), run_token='1' * 32,
                        candidate_sha='2' * 64, task_id='F84_HOST_MODEL_TASK')
        specs = tuple(_set(object.__new__(process.LaunchSpec), role=role)
                      for role in ('controller', 'watchdog'))
        self.deployment = sources.LoadedGoDeployment(self.loader, manifest, modules, (), '3' * 64, specs, 'f_entry')
        entry_actor = core.Actor(201, 20, '/usr/bin/python3.5', '4' * 64, ((201, 20, 'S'),))
        actors = tuple(core.Actor(pid, start, exe, '5' * 64, ((pid, start, 'S'),))
            for pid, start, exe in ((101, 10, '/usr/bin/Z03'), (102, 11, '/usr/bin/control_engine'),
                                     (103, 12, '/usr/bin/weston')))
        origin = core.Origin(1, 7, 3, 'wlan0', 2)
        snapshot = core.Snapshot('00000000-0000-0000-0000-000000000001', core.STOCK_PINS,
            actors, origin, '6' * 64, 2412, (origin,),
            ip.IpSnapshot((), (), tuple(ip.RuleRecord(*r) for r in ((0, 255), (32766, 254), (32767, 253)))),
            (), (), True)
        reader = _set(object.__new__(proc.ProcReader), _history=[], _issuer=object())
        self.entry = _set(object.__new__(f.GoEntrySource), deployment=self.deployment,
            until=until, until_text='301.0', worker=worker, clock=self.clock,
            actor=entry_actor, boot=snapshot.boot, reader=reader)
        self.value = _set(object.__new__(boot.GoBootstrap), deployment=self.deployment,
            entry=self.entry, until=until, worker=worker, clock=self.clock,
            restore_attempted=True, phase='restored', restore_failure=None, failure=None,
            cleanup_until=cleanup, controller=None)
        self.launch = _set(object.__new__(f.GoSendLaunch), entry=self.entry,
            deployment=self.deployment, original_until=until, worker=worker,
            task_id=manifest.task_id, nonce='7' * 32, native_epoch=1, operation_epoch=1)
        _set(self.entry, send_launch=self.launch, _send_launch_original=self.launch)
        _set(self.value, send_launch=self.launch, _send_launch_original=self.launch)
        issuer, mutex = object(), threading.RLock()
        self.store = _set(object.__new__(stores.GoBootstrapStore), owner=self.value,
            _original_owner=self.value, deployment=self.deployment, _deployment=self.deployment,
            worker=worker, issuer=issuer, _issuer=issuer, until=until, clock=self.clock,
            mutex=mutex, _mutex=mutex, restore_failure=None, logical_restored=True,
            marker_cleared=True, publication_unknown=False, _close_called=True,
            boot_id=snapshot.boot, restore_until=cleanup, _restore_until_original=cleanup, last=320.0)
        self.native = _set(object.__new__(native.NativeGoResources), owner=self.value,
            store=self.store, deployment=self.deployment, worker=worker, clock=self.clock,
            mutex=mutex, until=until, _ancillary_unknown=False, _server_absent=True)
        _set(self.value, store=self.store, native=self.native)
        _set(self.store, _native_original=self.native)
        rows = []
        for index in range(8):
            row = stores._Fd('directory' if index < 6 else 'lock')
            mode = stat.S_IFDIR | 0o700 if index < 6 else stat.S_IFREG | 0o600
            row.fd, row.metadata = 30 + index, (1, 100 + index, mode, 0, 0, 1, 0, 1, 1)
            row.returned = row.attempted = row.closed = True
            row.unknown = False
            rows.append(row)
        self.store.rows = self.store._original_rows = rows
        self.store._fd_history, self.store._fd_attempts = tuple(rows), len(rows)
        self.store.anchors = [(row, None, None, row.metadata, 0o700) for row in rows[:6]]
        self.store.tmp, self.store.run = rows[3], rows[5]
        self.store.device, self.store.journal_lock = rows[6:]
        rows[6].parent, rows[6].name = self.store.tmp, stores.DEVICE_LOCK
        rows[7].parent, rows[7].name = self.store.run, stores.JOURNAL_LOCK
        self.native_row = native._Resource(self.native, 'file', cleanup)
        self.native_row.returned = self.native_row.attempted = self.native_row.closed = True
        self.native_row.unknown = False
        self.native.rows = self.native._rows_original = [self.native_row]
        self.native._history = (self.native_row,)
        self.native.baseline = native.GoBaselineObservation(self.native, snapshot)
        self.native.restored = native.GoNativeRestoreObservation(self.native, snapshot)
        self.native.observations = [self.native.baseline, self.native.restored]
        self.value.restore_observation = boot.GoRestoreObservation(self.value, self.native.restored)
        launcher = _set(object.__new__(process.GoDirectChildOwner), runtime=self.value,
                       entry=self.entry, _reader=reader, _tickets=[])
        self.value.launcher = self.store._launcher_original = self.loader.launcher = launcher
        values = dict(schema=stores.SCHEMA, run_token=manifest.run_token,
            candidate_sha=manifest.candidate_sha, task_id=manifest.task_id, boot_id=snapshot.boot,
            issued_at=1.0, until=until, baseline=snapshot, watchdog=None, controller=None,
            interface_intent=None, owned=None, group_add=None, group_observed=None, ip=None, dhcp=None)
        canonical = []
        for generation, phase in enumerate(('reserved', 'restore_intent', 'dhcp_closed',
                                            'ip_delete_intent', 'ip_restored', 'reconciled')):
            record = stores.GoRecord(dict(values, generation=generation, phase=phase,
                cleanup_until=None if phase == 'reserved' else cleanup,
                restored=snapshot if phase == 'reconciled' else None))
            raw = stores.encode(record)
            metadata = (1, 200 + generation, stat.S_IFREG | 0o600, 0, 0, 1, len(raw), 1, 1)
            canonical.append(stores.GoCanonical(issuer, record, raw, metadata))
        # Synthetic before/after of ONE once restore return; no restore called.
        self.store.current, self.store._canonical_history = canonical[0], (canonical[0],)
        before = f._finish_refs_v84(self.value)
        self.store.current, self.store._canonical_history = canonical[-1], tuple(canonical)
        after = f._finish_refs_v84(self.value)
        self.ticket = {'creator': f._FINISH_TOKEN_V84, 'owner': self.value, 'launch': self.launch,
            'called': True, 'returned': canonical[-1], 'before': before, 'after': after,
            'restore_error': None, 'export_error': None, 'data': None, 'raw': None, 'unknown': True}
        f._ENTRY_INVENTORY.append(self.ticket)

    def replace_finish(self, finish):
        self.store.current = finish
        self.store._canonical_history = self.store._canonical_history[:-1] + (finish,)
        self.ticket['returned'] = finish
        self.ticket['after'] = self.modules['mta_go_executor']._finish_refs_v84(self.value)


class GoFinishData84Test(unittest.TestCase):
    def test_returned_restore_data_and_refusals(self):
        source = _inputs()
        completed, positives, refusals = [], 0, 0
        for case in ('returned_restore', 'business_failed', 'no_return', 'history_changed',
                     'native_fd_unknown', 'bad_metadata_type', 'foreign_canonical'):
            with self.subTest(case=case):
                modules, tree = _domain(source)
                model = _FactsModel(modules)
                f, stores = modules['mta_go_executor'], modules['mta_go_bootstrap_store']
                primary = None
                if case == 'business_failed':
                    primary = RuntimeError('HOST original business failure')
                    model.value.failure = primary
                elif case == 'no_return':
                    model.ticket['returned'] = None
                elif case == 'history_changed':
                    model.store._canonical_history = tuple(list(model.store._canonical_history))
                elif case == 'native_fd_unknown':
                    model.native_row.unknown = True
                elif case in ('bad_metadata_type', 'foreign_canonical'):
                    old = model.store.current
                    if case == 'bad_metadata_type':
                        finish = stores.GoCanonical(old.issuer, old.record, old.raw,
                                                   old.metadata[:1] + (True,) + old.metadata[2:])
                    else:
                        foreign = {'__builtins__': dict(vars(builtins))}
                        _selected(source['mta_go_bootstrap_store'], 'HOST foreign exact canonical domain',
                                  foreign, ('GoCanonical',))
                        finish = foreign['GoCanonical'](old.issuer, old.record, old.raw, old.metadata)
                        self.assertIsNot(type(finish), stores.GoCanonical)
                    model.replace_finish(finish)
                original_current = model.store.current
                original_native_history = model.native._history
                original_store_history = model.store._fd_history
                with ExitStack() as stack:
                    tripwires = [stack.enter_context(mock.patch(target,
                        side_effect=AssertionError('HOST forbidden finish side effect')))
                        for target in ('os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
                                       'os.stat', 'os.fork', 'os.kill', 'threading.Thread.start') if
                        target != 'os.fork' or hasattr(__import__('os'), 'fork')]
                    restore_probe = stack.enter_context(mock.patch.object(modules['mta_go_bootstrap'].GoBootstrap,
                        'restore', side_effect=AssertionError('HOST actual restore prohibited')))
                    raw = f._capture_finish_data_v84(model.ticket)
                    for probe in tripwires + [restore_probe, model.clock, model.authenticate]:
                        self.assertEqual(probe.call_count, 0)
                if case in ('returned_restore', 'business_failed'):
                    self.assertIs(type(raw), bytes)
                    self.assertLessEqual(len(raw), 4096)
                    self.assertTrue(raw.startswith(b'GOFINISH84='))
                    self.assertTrue(raw.endswith(b'\n'))
                    data = modules['p011_json'].loads(raw[len(b'GOFINISH84='):-1].decode('ascii'))
                    self.assertEqual(data, model.ticket['data'])
                    self.assertEqual(data['provenance'], 'returned_restore')
                    self.assertEqual(data['journal']['phase'], 'reconciled')
                    self.assertEqual(data['journal']['generation'], 5)
                    self.assertEqual(data['journal']['sha256'], hashlib.sha256(original_current.raw).hexdigest())
                    self.assertEqual(data['journal']['metadata'], list(original_current.metadata))
                    self.assertEqual(data['journal']['facts_key'], list(stores.GoRecord.facts_key(original_current.record)))
                    self.assertEqual(data['inventory_counts'], [8, 1])
                    self.assertEqual(data['children'], [])
                    self.assertIs(data['business_failed_at_capture'], case == 'business_failed')
                    self.assertIs(data['native_full_inventory_export'], False)
                    self.assertIs(data['independent_restore_verified'], False)
                    self.assertIs(data['production_admitted'], False)
                    self.assertIs(model.ticket['unknown'], False)
                    self.assertIsNone(model.ticket['export_error'])
                    self.assertIs(model.value.failure, primary)
                    positives += 1
                else:
                    self.assertIsNone(raw)
                    self.assertIsNone(model.ticket['raw'])
                    self.assertIsNone(model.ticket['data'])
                    self.assertIs(model.ticket['unknown'], True)
                    self.assertIs(type(model.ticket['export_error']), ValueError)
                    self.assertEqual(model.ticket['export_error'].args, ('finish_data_unavailable',))
                    if case == 'native_fd_unknown':
                        self.assertIs(model.native_row.unknown, True)
                    refusals += 1
                self.assertIs(model.store.current, original_current)
                self.assertIs(model.store._fd_history, original_store_history)
                self.assertIs(model.native._history, original_native_history)
                self.assertIsNone(model.ticket['restore_error'])
                completed.append(case)
        # The default path is SOURCE evidence only, not a called runtime.
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'bootstrap']
        self.assertEqual(len(functions), 1)
        defaults = [node for node in functions[0].body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'finish_raw' for target in node.targets)]
        self.assertEqual(len(defaults), 1)
        self.assertIs(type(defaults[0].value), ast.Constant)
        self.assertEqual(defaults[0].value.value, b'GOFINISH84=unavailable provenance=default_run\n')
        self.assertEqual(len(completed), 7)
        self.assertEqual((positives, refusals), (2, 5))
        completed.append('default_unavailable_SOURCE_only')
        self.assertEqual(len(completed), 8)


if __name__ == '__main__':
    suite = unittest.TestSuite([GoFinishData84Test('test_returned_restore_data_and_refusals')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if result.wasSuccessful():
        sys.stdout.write(MARKER)
    raise SystemExit(0 if result.wasSuccessful() else 1)
