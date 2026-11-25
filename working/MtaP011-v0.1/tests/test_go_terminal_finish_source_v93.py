"""One new V93 method / two changed domains; SOURCE until ROOT alone runs it.

F93 complete Actor DATA and original ChildTicket outcomes are exercised using
the actual selected F helpers, classes and fixed private pure JSON/IP/core/
facts definitions. Bridge93's changed strict decoder consumes the resulting
canonical wire. No old TestCase is imported and no old method is dispatched.
Twelve current files are read once with explicit byte/hash pins; selected AST
definitions retain their unchanged bodies but are NOT a loaded private GO
graph. The actual F90 preflight/bootstrap/default flow is not called.

Restore returns, canonical issuance/history, launcher/registration flags,
inventory closure, locks, timestamps, FD metadata and reap are SYNTHETIC DATA.
Actual pure ChildTicket/LaunchSpec constructors populate no-fork/negative-fork
fixtures; no fork or process action occurs. Actual Snapshot/Actor/GoRecord and
encode/key functions validate fixture DATA. Six F and twelve Bridge fixtures
cover only the V93 changes. Platform IO, clock, authentication and restore
tripwires must remain zero in every fixture. No RF, native recovery, admission,
CLIENT FinishReceipt, phone, independent observer or physical closure is proved.
The Bridge P-state fixture validates primitive DATA only: the pinned older
Core Actor constructor is not claimed to issue P-state observations.
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
    ('mta_go_deployment', 'candidate/go-send-preflight-key-v90/runtime/mta_go_deployment.py', 26543,
     'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe'),
    ('mta_client_proc', 'candidate/client-proc-deadline-v25/runtime/mta_client_proc.py', 39384,
     'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_go_process_owner', 'candidate/go-bootstrap-v33-r3/runtime/mta_go_process_owner.py', 42612,
     '78a480728a348e98e578acf4e7c778be50bfae3411ba5d34bb563493e1ba6583'),
    ('mta_go_bootstrap_store', 'candidate/go-dhcp-setup-v74/runtime/mta_go_bootstrap_store.py', 78430,
     '24620844c7d24f4777114ba9bfb4ea292ded2020a281681dd8e71fe07c7a4eae'),
    ('mta_go_native', 'candidate/go-send-transport-v76/runtime/mta_go_native.py', 200317,
     'ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f'),
    ('mta_go_bootstrap', 'candidate/go-send-preflight-key-v90/runtime/mta_go_bootstrap.py', 31964,
     '93bc97ccb9d83d5727c2f528f0a2934f09d8cae093591821a9bf5ad60f425697'),
    ('mta_go_executor', 'candidate/go-send-terminal-source-v93/runtime/mta_go_executor.py', 62728,
     'f33ad96651e8aed38adab1ca931da6de7455130b8dbcedd774e1038ee39c8ed0'),
    ('mta_go_send_bridge', 'candidate/go-send-terminal-source-v93/runtime/mta_go_send_bridge.py', 87625,
     '027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02'),
)
MARKER = ('HOST93_TERMINAL_FINISH_SOURCE new_methods=1 old_methods=0 domains=2 '
          'issuer_model=true pure_codec=true device=false phone=false\n')


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
              ('GoManifest', 'LoadedGoDeployment'), ('_MANIFEST_KEYS', 'PYTHON'))
    value = module('mta_client_proc')
    value.__dict__.update(common, owner=modules['mta_p2p_client_init'])
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('_Private', 'ProcObservation', 'ProcGeneration', 'ProcReader'))
    value = module('mta_go_process_owner')
    value.__dict__.update(common)
    _selected(source[value.__name__], value.__file__, value.__dict__,
              ('ProcessOwnerError', '_fail', '_int', '_time', 'LaunchSpec', '_FD',
               'ChildTicket', 'GoDirectChildOwner'), ('_CODES',))
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
    value = module('mta_go_send_bridge')
    value.__dict__.update(common, json=modules['p011_json'])
    _selected(source[value.__name__], value.__file__, value.__dict__,
        ('SendBridgeError', '_fail', '_uint', '_hex', '_finish_number_v86',
         '_finish_metadata_v86', '_finish_wire_v86', '_finish_actor_data_v93',
         '_finish_decode_v86'),
        ('MAX_FINISH_DATA_V86', '_FINISH_KEYS_V86', '_FINISH_BIND_KEYS_V86',
         '_FINISH_JOURNAL_KEYS_V86', '_FINISH_ACTOR_KEYS_V93',
         '_FINISH_OUTCOME_KEYS_V93', '_FINISH_PYTHON_V93'))
    return modules


def _set(value, **fields):
    # Only fixture field population in explicitly synthetic exact class data.
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return value


class _FactsModel(object):
    """No production constructor/return/FD close is claimed by these models."""
    def __init__(self, modules, tasks=None, branches=()):
        self.modules = modules
        f, stores, native, boot, proc, process, sources, core, ip = (modules[n] for n in (
            'mta_go_executor', 'mta_go_bootstrap_store', 'mta_go_native', 'mta_go_bootstrap',
            'mta_client_proc', 'mta_go_process_owner', 'mta_go_deployment', 'mta_p2p_client_init', 'mta_ip'))
        worker, until, cleanup = threading.current_thread(), 301.0, 340.0
        self.clock = mock.Mock(side_effect=AssertionError('HOST unexpected finish clock'))
        self.authenticate = mock.Mock(side_effect=AssertionError('HOST unexpected source authentication'))
        self.loader = types.SimpleNamespace(authenticate=self.authenticate, launcher=None)
        manifest = _set(object.__new__(sources.GoManifest), run_token='1' * 32,
                        candidate_sha='2' * 64, task_id='F93_HOST_MODEL_TASK')
        specs = tuple(process.LaunchSpec(role, '/usr/bin/python3.5',
            ('/usr/bin/python3.5', '--HOST93-inert-' + role), (), '8' * 64)
            for role in ('controller', 'watchdog'))
        self.deployment = sources.LoadedGoDeployment(self.loader, manifest, modules, (), '3' * 64, specs, 'f_entry')
        entry_actor = core.Actor(201, 20, '/usr/bin/python3.5', '4' * 64,
            tasks if tasks is not None else ((201, 20, 'S'), (202, 21, 'R'), (203, 22, 'D')))
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
            cleanup_until=cleanup, controller=None, watchdog=None)
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
                       entry=self.entry, _reader=reader, _tickets=[],
                       _registered_v33=[], _pid_v30=entry_actor.pid)
        self.value.launcher = self.store._launcher_original = self.loader.launcher = launcher
        self.children = []
        for role, branch in branches:
            spec = (self.deployment.controller_spec if role == 'controller'
                    else self.deployment.watchdog_spec)
            child = process.ChildTicket(launcher, spec, self.store.device.fd, until)
            # Only modeled fork outcomes; the unchanged pure constructor holds
            # original flags/fields. No source FD or fork producer is invoked.
            if branch == 'negative':
                child.fork_requested, child.fork_negative = True, True
            elif branch == 'positive_missing_actor':
                child.fork_requested, child.fork_returned, child.pid = True, True, 211
            elif branch != 'never':
                raise ValueError('HOST unknown fixture child branch')
            launcher._tickets.append(child)
            launcher._registered_v33.append((child, spec, child.original_device_fd, child.deadline))
            setattr(self.value, role, child)
            self.children.append(child)
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


    def unbounded_expected_data(self):
        """Fixture expected DATA, never substituted into the production helper."""
        value, store, actor = self.value, self.store, self.entry.actor
        stores = self.modules['mta_go_bootstrap_store']
        finish, record = self.ticket['returned'], self.ticket['returned'].record
        children, outcomes = [], []
        for child in self.children:
            children.append([child.spec.role, None if child.preexec is None else child.preexec.pid,
                             None if child.preexec is None else child.preexec.start])
            outcomes.append({'role': child.spec.role, 'fork_requested': child.fork_requested,
                'fork_negative': child.fork_negative, 'waited': child.waited,
                'exit_verified': child.exit_verified, 'actor_present': child.preexec is not None})
        return {'schema': 'p011-go-finish-data-v93', 'provenance': 'returned_restore',
            'binding': {'run': record.run_token, 'manifest': self.deployment.manifest_sha,
                'task': self.launch.task_id, 'nonce': self.launch.nonce,
                'native_epoch': self.launch.native_epoch,
                'operation_epoch': self.launch.operation_epoch, 'until': self.entry.until_text},
            'journal': {'schema': record.schema, 'phase': record.phase, 'generation': record.generation,
                'sha256': hashlib.sha256(finish.raw).hexdigest(), 'bytes': len(finish.raw),
                'metadata': list(finish.metadata), 'facts_key': list(stores.GoRecord.facts_key(record))},
            'cleanup_until': value.cleanup_until, 'finished_at': store.last,
            'device_lock_metadata': list(store.device.metadata),
            'f_actor': [actor.pid, actor.start, actor.argv_sha],
            'f_actor_data': self.modules['mta_client_journal_codec']._actor_tree(actor),
            'children': children, 'children_outcomes': outcomes,
            'inventory_counts': [len(store._fd_history), len(self.native._history)],
            'business_failed_at_capture': value.failure is not None,
            'native_full_inventory_export': False, 'independent_restore_verified': False,
            'production_admitted': False}


class GoTerminalFinishSource93Test(unittest.TestCase):
    def _guard(self, stack, modules, model):
        # These probes are denial-only and never replace a new tested helper.
        probes = [stack.enter_context(mock.patch(target,
            side_effect=AssertionError('HOST93 forbidden platform/restore side effect')))
            for target in ('os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
                           'os.stat', 'os.kill', 'threading.Thread.start')]
        if hasattr(__import__('os'), 'fork'):
            probes.append(stack.enter_context(mock.patch('os.fork',
                side_effect=AssertionError('HOST93 forbidden fork'))))
        probes.append(stack.enter_context(mock.patch.object(modules['mta_go_bootstrap'].GoBootstrap,
            'restore', side_effect=AssertionError('HOST93 actual restore prohibited'))))
        return probes + [model.clock, model.authenticate]

    def _zero(self, probes):
        for probe in probes:
            self.assertEqual(probe.call_count, 0)

    def test_full_actor_outcomes_and_strict_consumer(self):
        source = _inputs()
        self.assertEqual(len(source), 12)
        completed, positives, refusals = [], 0, 0
        f_cases = ('full_actor_business_first_error', 'actual_never_and_negative',
                   'codec_function_changed', 'registration_missing',
                   'positive_without_actor', 'whole_128_tasks_over_limit')
        for case in f_cases:
            with self.subTest(domain='F93_full_actor_outcomes', fixture=case):
                modules = _domain(source)
                f, core, bridge = (modules[name] for name in
                    ('mta_go_executor', 'mta_p2p_client_init', 'mta_go_send_bridge'))
                tasks, branches = None, ()
                if case == 'whole_128_tasks_over_limit':
                    tasks = ((201, 20, 'S'),) + tuple(
                        (2147483500 + i, (1 << 64) - 1 - i, 'R') for i in range(127))
                elif case in ('actual_never_and_negative', 'registration_missing'):
                    branches = (('controller', 'never'), ('watchdog', 'negative'))
                elif case == 'positive_without_actor':
                    branches = (('controller', 'positive_missing_actor'),)
                model = _FactsModel(modules, tasks=tasks, branches=branches)
                actor, original_tasks = model.entry.actor, model.entry.actor.tasks
                current, fd_history, native_history = (
                    model.store.current, model.store._fd_history, model.native._history)
                primary = None
                codec_probe = None
                if case == 'full_actor_business_first_error':
                    primary = RuntimeError('HOST93 retained original business error')
                    model.value.failure = primary
                elif case == 'codec_function_changed':
                    # Actual namespace function identity changes AFTER before/
                    # after were retained. Its body must never be invoked.
                    codec_probe = mock.Mock(side_effect=AssertionError('HOST93 foreign encoder invoked'))
                    def foreign_encoder(value):
                        return codec_probe(value)
                    modules['mta_client_journal_codec']._actor_tree = foreign_encoder
                elif case == 'registration_missing':
                    model.value.launcher._registered_v33.pop()
                with ExitStack() as stack:
                    probes = self._guard(stack, modules, model)
                    raw = f._capture_finish_data_v84(model.ticket)
                    self._zero(probes)
                    if codec_probe is not None:
                        self.assertEqual(codec_probe.call_count, 0)
                if case in ('full_actor_business_first_error', 'actual_never_and_negative'):
                    self.assertIs(type(raw), bytes)
                    self.assertLessEqual(len(raw), 4096)
                    data = modules['p011_json'].loads(raw[len(b'GOFINISH84='):-1].decode('ascii'))
                    self.assertEqual(data, model.unbounded_expected_data())
                    self.assertEqual(data['schema'], 'p011-go-finish-data-v93')
                    self.assertEqual(data['f_actor_data'], {
                        'pid': actor.pid, 'start': actor.start, 'exe': actor.exe,
                        'argv_sha': actor.argv_sha, 'tasks': [list(t) for t in original_tasks]})
                    self.assertEqual(data['f_actor'], [actor.pid, actor.start, actor.argv_sha])
                    self.assertEqual(data['f_actor_data']['tasks'],
                                     [[201, 20, 'S'], [202, 21, 'R'], [203, 22, 'D']])
                    self.assertIs(model.ticket['unknown'], False)
                    self.assertIsNone(model.ticket['export_error'])
                    self.assertIs(data['business_failed_at_capture'], primary is not None)
                    if case == 'actual_never_and_negative':
                        self.assertEqual(data['children'], [['controller', None, None], ['watchdog', None, None]])
                        self.assertEqual(data['children_outcomes'], [
                            {'role': 'controller', 'fork_requested': False, 'fork_negative': False,
                             'waited': False, 'exit_verified': False, 'actor_present': False},
                            {'role': 'watchdog', 'fork_requested': True, 'fork_negative': True,
                             'waited': False, 'exit_verified': False, 'actor_present': False}])
                        for index, child in enumerate(model.children):
                            self.assertIs(type(child), modules['mta_go_process_owner'].ChildTicket)
                            registration = model.value.launcher._registered_v33[index]
                            self.assertIs(registration[0], child)
                            self.assertIs(registration[1], child.spec)
                            self.assertEqual(registration[2], model.store.device.fd)
                            self.assertIs(registration[3], child.deadline)
                            self.assertEqual(child.fds, [])
                            self.assertIs(child.unknown, False)
                    else:
                        self.assertEqual((data['children'], data['children_outcomes']), ([], []))
                    for name in ('native_full_inventory_export', 'independent_restore_verified', 'production_admitted'):
                        self.assertIs(data[name], False)
                    positives += 1
                else:
                    self.assertIsNone(raw)
                    self.assertIsNone(model.ticket['raw'])
                    self.assertIsNone(model.ticket['data'])
                    self.assertIs(model.ticket['unknown'], True)
                    self.assertIs(type(model.ticket['export_error']), ValueError)
                    self.assertEqual(model.ticket['export_error'].args, ('finish_data_unavailable',))
                    if case == 'whole_128_tasks_over_limit':
                        # Actual full Actor encoder plus pure JSON proves whole
                        # wire exceeds the unchanged cap; no truncated tree.
                        expected = model.unbounded_expected_data()
                        self.assertEqual(len(expected['f_actor_data']['tasks']), 128)
                        self.assertGreater(len(bridge._finish_wire_v86(expected)), 4096)
                    refusals += 1
                self.assertIs(type(actor), core.Actor)
                self.assertIs(model.entry.actor, actor)
                self.assertIs(actor.tasks, original_tasks)
                self.assertIs(model.value.failure, primary)
                self.assertIsNone(model.ticket['restore_error'])
                self.assertIs(model.store.current, current)
                self.assertIs(model.store._fd_history, fd_history)
                self.assertIs(model.native._history, native_history)
                self.assertEqual(len(model.ticket['before']), 16)
                self.assertEqual(len(model.ticket['after']), 16)
                completed.append(('F93', case))

        bridge_cases = ('valid_new_wire', 'valid_P_primitive_DATA', 'missing_full_actor',
            'missing_outcomes', 'full_actor_mismatch', 'fixed_python_changed', 'leader_missing',
            'duplicate_tid', 'outcome_fake_bool', 'positive_fork_without_actor',
            'outcome_role_mismatch', 'outcome_count_mismatch')
        expected_codes = {
            'missing_full_actor': 'finish_data_noncanonical',
            'missing_outcomes': 'finish_data_noncanonical',
            'full_actor_mismatch': 'finish_data_actor',
            'fixed_python_changed': 'finish_data_actor',
            'leader_missing': 'finish_data_actor_tasks',
            'duplicate_tid': 'finish_data_actor_tasks',
            'outcome_fake_bool': 'finish_data_outcomes',
            'positive_fork_without_actor': 'finish_data_outcomes',
            'outcome_role_mismatch': 'finish_data_outcomes',
            'outcome_count_mismatch': 'finish_data_outcomes',
        }
        for case in bridge_cases:
            with self.subTest(domain='Bridge93_strict_consumer', fixture=case):
                modules = _domain(source)
                f, bridge = modules['mta_go_executor'], modules['mta_go_send_bridge']
                model = _FactsModel(modules, branches=(('controller', 'never'), ('watchdog', 'negative')))
                with ExitStack() as stack:
                    probes = self._guard(stack, modules, model)
                    original_raw = f._capture_finish_data_v84(model.ticket)
                    self.assertIs(type(original_raw), bytes)
                    data = modules['p011_json'].loads(original_raw[len(b'GOFINISH84='):-1].decode('ascii'))
                    original_data = model.ticket['data']
                    binding = dict(data['binding'])
                    actor = data['f_actor_data']
                    if case == 'valid_P_primitive_DATA':
                        actor['tasks'][-1][2] = 'P'
                    elif case == 'missing_full_actor':
                        del data['f_actor_data']
                    elif case == 'missing_outcomes':
                        del data['children_outcomes']
                    elif case == 'full_actor_mismatch':
                        actor['argv_sha'] = '9' * 64
                    elif case == 'fixed_python_changed':
                        actor['exe'] = '/usr/bin/python3'
                    elif case == 'leader_missing':
                        actor['tasks'] = actor['tasks'][1:]
                    elif case == 'duplicate_tid':
                        actor['tasks'][1][0] = actor['tasks'][0][0]
                    elif case == 'outcome_fake_bool':
                        data['children_outcomes'][0]['fork_requested'] = 0
                    elif case == 'positive_fork_without_actor':
                        data['children_outcomes'][0].update(fork_requested=True, fork_negative=False,
                            waited=True, exit_verified=True)
                    elif case == 'outcome_role_mismatch':
                        data['children_outcomes'][0]['role'] = 'watchdog'
                    elif case == 'outcome_count_mismatch':
                        data['children_outcomes'].pop()
                    raw = bridge._finish_wire_v86(data)
                    self.assertLessEqual(len(raw), 4096)
                    if case in ('valid_new_wire', 'valid_P_primitive_DATA'):
                        actual = bridge._finish_decode_v86(raw, binding,
                            model.deployment.manifest.candidate_sha, model.entry.actor.pid,
                            modules['mta_go_bootstrap_store'].SCHEMA)
                        self.assertEqual(actual, data)
                        self.assertEqual(actual['f_actor_data']['exe'], '/usr/bin/python3.5')
                        self.assertEqual(actual['children'], [['controller', None, None], ['watchdog', None, None]])
                        if case == 'valid_P_primitive_DATA':
                            self.assertEqual(actual['f_actor_data']['tasks'][-1][2], 'P')
                            self.assertEqual(model.entry.actor.tasks[-1][2], 'D')
                        for name in ('native_full_inventory_export', 'independent_restore_verified', 'production_admitted'):
                            self.assertIs(actual[name], False)
                        positives += 1
                    else:
                        with self.assertRaises(bridge.SendBridgeError) as caught:
                            bridge._finish_decode_v86(raw, binding,
                                model.deployment.manifest.candidate_sha, model.entry.actor.pid,
                                modules['mta_go_bootstrap_store'].SCHEMA)
                        self.assertEqual(caught.exception.args, (expected_codes[case],))
                        refusals += 1
                    self._zero(probes)
                # New pure decoding cannot mutate retained producer facts or
                # turn its original report into a grant/physical close proof.
                self.assertIs(model.ticket['data'], original_data)
                self.assertEqual(model.ticket['raw'], original_raw)
                self.assertEqual(model.entry.actor.tasks,
                    ((201, 20, 'S'), (202, 21, 'R'), (203, 22, 'D')))
                self.assertIsNone(model.value.failure)
                self.assertIsNone(model.ticket['restore_error'])
                completed.append(('Bridge93', case))
        self.assertEqual(len(f_cases), 6)
        self.assertEqual(len(bridge_cases), 12)
        self.assertEqual(len(completed), 18)
        self.assertEqual((positives, refusals), (4, 14))
        self.assertEqual({domain for domain, case in completed}, {'F93', 'Bridge93'})


if __name__ == '__main__':
    suite = unittest.TestSuite([GoTerminalFinishSource93Test('test_full_actor_outcomes_and_strict_consumer')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if result.wasSuccessful():
        sys.stdout.write(MARKER)
    raise SystemExit(0 if result.wasSuccessful() else 1)
