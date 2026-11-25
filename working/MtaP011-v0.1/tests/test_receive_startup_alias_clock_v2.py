"""One affected HOST contract, definitions-only AST; no graph/device/RF run.

Actual Scope guards, alias algorithm, Files boundaries and Owner._now bodies
are executed only by an explicit unittest run. Owner._context, empty State,
DirectoryBinding and metadata IO are limited fixtures, not full Owner proof.
"""
import ast
import copy
import errno
import hashlib
import math
from pathlib import Path
import stat
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
FACTORY = ('candidate/receive-startup-alias-clock-v2/runtime/mta_client_receive_factory.py',
           89375, 'c018edb57aa5824b87d4fc731aa12710cb113c18ca064afecff23f8dd597bb1a')
EXECUTOR = ('candidate/formal-receive-filecenter-v1/runtime/mta_client_executor.py',
            117754, '2a6b596004f9f34ef46359f3cb82e4742b82025ff537d70296bb5c5dd8b083b5')
OWNER = ('candidate/formal-receive-filecenter-v1/runtime/mta_client_service_owner.py',
         107054, 'f6a1f670899129a26da2e6c66e6d4166b1787ee52a940c945b992dfd7319828d')


def pinned_tree(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('contract_source_pin')
    return ast.parse(raw, filename=pin[0])


def subset(tree, functions=(), classes=None, assignments=()):
    """Keep exact requested bodies only; never execute module imports/main."""
    nodes, found = [], set()
    for row in tree.body:
        if isinstance(row, ast.FunctionDef) and row.name in functions:
            nodes.append(copy.deepcopy(row)); found.add(row.name)
        elif isinstance(row, ast.ClassDef) and row.name in (classes or {}):
            cls = copy.deepcopy(row)
            wanted = classes[row.name]
            cls.body = [n for n in cls.body if
                        isinstance(n, ast.FunctionDef) and n.name in wanted or
                        isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and
                        t.id in wanted for t in n.targets)]
            names = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
            names.update(t.id for n in cls.body if isinstance(n, ast.Assign)
                         for t in n.targets if isinstance(t, ast.Name))
            if names != set(wanted): raise ValueError('contract_method_selection')
            nodes.append(cls); found.add(row.name)
        elif isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id in assignments for target in row.targets for t in ast.walk(target)):
            nodes.append(copy.deepcopy(row))
            found.update(t.id for target in row.targets for t in ast.walk(target)
                         if isinstance(t, ast.Name))
    if found != set(functions) | set(classes or {}) | set(assignments):
        raise ValueError('contract_definition_selection')
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   '<actual-startup-alias-v2-selected-bodies>', 'exec')


class ReceiveStartupAliasClockV2Contract(unittest.TestCase):
    def test_actual_alias_density_full_io_and_original_code_refusal(self):
        ft, et, ot = (pinned_tree(pin) for pin in (FACTORY, EXECUTOR, OWNER))
        class Rejected(ValueError): pass
        def fail(code): raise Rejected(code)
        calls = dict(clock=0, context=0, directory=0, injected=0, open=0)
        tick = [10.0]
        def clock():
            calls['clock'] += 1
            return tick[0]
        class Node: pass
        links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}
        events, inodes = [], {}
        root = '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1'
        class MetadataIo:
            def stat(self, path):
                events.append(('stat', path))
                mode = (stat.S_IFLNK | 0o777 if path in links else stat.S_IFDIR |
                        (0o1777 if path in ('/var/volatile', '/var/volatile/tmp') else 0o755))
                if path == root or path.startswith(root + '/'): mode = stat.S_IFDIR | 0o700
                row = Node()
                row.st_dev, row.st_ino = 1, inodes.setdefault(path, len(inodes) + 1)
                row.st_mode, row.st_uid, row.st_gid, row.st_nlink = mode, 0, 0, 1
                row.st_size = len(links.get(path, ''))
                row.st_mtime_ns = row.st_ctime_ns = 1
                return row
            def readlink(self, path):
                events.append(('readlink', path))
                return links[path]
        def denied_open(path, flags):
            calls['open'] += 1
            events.append(('open', calls['directory']))
            raise OSError(errno.EACCES, 'HOST pre-open refusal')
        def forbidden(*unused, **kwargs):
            raise AssertionError('no actual FD/content operation is authorized')
        fake_os = types.SimpleNamespace(getpid=lambda: 123,
            stat=lambda path, follow_symlinks=False: MetadataIo().stat(path),
            open=denied_open, read=forbidden, close=forbidden, fstat=forbidden,
            O_RDONLY=0, O_CLOEXEC=0, O_NOFOLLOW=0)
        executor = types.ModuleType('mta_client_executor')
        executor.__dict__.update(_fail=fail, math=math, stat=stat)
        exec(subset(et, functions=('_uint', '_finite', '_meta', '_path'),
            classes={'_ReadOwner': ('__init__', 'check', '_fixed_tmp_alias')}), executor.__dict__)
        executor._LinuxIo = MetadataIo
        executor.DeploymentLoader = type('DeploymentLoader', (), {})
        executor.LoadedDeployment = type('LoadedDeployment', (), {})
        executor.ClientExecutor = type('ClientExecutor', (), {})
        executor.RECEIVE_ROOT = '/mnt/data/p011-toolbox/user/Received'
        class Directory:
            def check(self):
                calls['directory'] += 1
                if self.reject: fail('directory_rejected')
                return self
        class State:
            @staticmethod
            def _probes_closed(value): return value.probe_actors == []
        service = types.ModuleType('fixture_service'); service.State = State
        startup = types.ModuleType('mta_client_startup_readonly')
        startup.StartupCollection = type('StartupCollection', (), {})
        exec('def collect(scope): return None', startup.__dict__)
        ons = dict(__name__='fixture_original_owner', _fail=fail, math=math, calls=calls,
                   STARTUP_READONLY_SCHEMA='receive-startup-readonly-v1')
        exec('def _context(self): calls["context"] += 1\ndef start(self): pass\n'
             'def _startup_readonly(self): pass\ndef close(self): pass', ons)
        owner_class = next(n for n in ot.body if isinstance(n, ast.ClassDef) and
                           n.name == 'FixedStateServiceOwner')
        now_node = next(n for n in owner_class.body if isinstance(n, ast.FunctionDef) and n.name == '_now')
        finite_node = next(n for n in ot.body if isinstance(n, ast.FunctionDef) and n.name == '_finite')
        exec(compile(ast.Module(body=[copy.deepcopy(finite_node), copy.deepcopy(now_node)],
                               type_ignores=[]), '<actual-original-owner-now>', 'exec'), ons)
        Owner = type('FixedStateServiceOwner', (), dict(__module__=ons['__name__'],
            _context=ons['_context'], _now=ons['_now'], start=ons['start'],
            _startup_readonly=ons['_startup_readonly'], close=ons['close']))
        ons['FixedStateServiceOwner'] = Owner
        ns = dict(__name__='fixture_actual_factory', _fail=fail, executor=executor,
            math=math, stat=stat, errno=errno, hashlib=hashlib, os=fake_os,
            types=types, threading=threading, sys=sys, time=types.SimpleNamespace(monotonic=clock),
            storage=types.SimpleNamespace(DirectoryBinding=Directory), _DIRECTORY_TYPE=Directory,
            FixedReceiveDeploymentFactory=type('FixedReceiveDeploymentFactory', (), {}),
            _PublicationAttempt=type('_PublicationAttempt', (), {}),
            _F_ORIGINALS=(executor, executor.DeploymentLoader, executor.LoadedDeployment,
                          executor.ClientExecutor, executor._ReadOwner))
        exec(subset(ft, functions=('_number', '_path', '_close_identity', '_startup_owner_type'),
            classes={'_StartupReadScope': ('__init__', '_originals', 'check_active', 'now',
                        'alias_now', 'close_originals_allowed', 'close_parent_originals'),
                     '_Files': ('__init__', '_alias', 'anchors', 'read', 'close_row')},
            assignments=('SOURCE_PINS', 'SOURCE_MANIFEST_SHA', 'F_SHA', 'BASELINE_MANIFEST',
                         'STARTUP_READ_SECONDS', 'STARTUP_READONLY_SCHEMA',
                         'MAX_PROFILE_FILES', 'MAX_ENTRIES', 'MAX_IMAGE',
                         '_STARTUP_ALIAS_ORIGINALS', '_STARTUP_ALIAS_CODES')),
             ns)
        ns['ASSET_PHYSICAL_ROOT'], ns['PYTHON'] = root, '/usr/bin/python3.5'
        Scope, Files = ns['_StartupReadScope'], ns['_Files']
        owner, state, loader, directory = Owner(), State(), Node(), Directory()
        factory = ns['FixedReceiveDeploymentFactory']()
        owner.lock = threading.RLock(); owner.last = None
        owner.until = owner.original_until = parent_until = 600.0
        owner.clock = clock; owner.worker = threading.current_thread(); owner.pid = 123
        owner._startup_owner_type_original, owner._startup_namespace_original = Owner, ons
        owner.loader = loader; loader._original_until = parent_until; loader.clock = clock
        loader.modules = {'mta_client_startup_readonly': startup}
        owner.factory = owner._startup_factory_original = factory
        owner.state = owner._state_original = state; owner.service = service
        owner.received_directory = owner._received_directory_original = directory
        directory.root, directory.absolute_until, directory.clock = executor.RECEIVE_ROOT, parent_until, clock
        directory.reject = False
        owner._startup_module_original = startup; owner._startup_collect_original = startup.collect
        owner._startup_collection_type_original = startup.StartupCollection
        owner.started = owner.state_complete = owner.startup_called = True
        owner.close_called = owner.server_called = owner.start_complete = False
        owner.server = owner.thread = None; owner.probe_rows = []
        state._trusted_receive_deployment_factory = factory
        state._original_service_until = state._service_until_original = parent_until
        state._original_received_binding = state._received_binding_original = directory
        state.closing = state.receive_available = state.send_available = False
        state.wifi_restore_pending = state.radio_restore_pending = False
        state.probe_actors = owner.probe_rows
        scope = Scope.__new__(Scope)
        owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope
        saved = {n: sys.modules.get(n) for n in ('mta_client_executor', 'mta_client_startup_readonly')}
        sys.modules.update(mta_client_executor=executor, mta_client_startup_readonly=startup)
        try:
            Scope.__init__(scope, factory, owner)
            scope.files = scope._files_original = Files.__new__(Files)
            Files.__init__(scope.files, scope)
            callback = scope._alias_clock
            def reset():
                for key in calls: calls[key] = 0
                events[:] = []
            reset()
            scope.files.alias_owner._fixed_tmp_alias()
            self.assertEqual((calls['clock'], calls['directory']), (23, 0))
            self.assertEqual((owner.last, scope.last), (10.0, 10.0))
            self.assertEqual(len(events), 17)  # 13 stats + four readlinks, not FD/content IO.
            reset(); path = root + '/runtime35/unused.py'
            scope.files.anchors(path)
            self.assertEqual((calls['clock'], calls['directory']), (30, 7))
            reset()
            with self.assertRaises(OSError): scope.files.read(path, 100, '0' * 64, True)
            self.assertEqual(events[-1], ('open', 9))
            self.assertEqual(calls['open'], 1)
            self.assertTrue(scope.files.rows[-1]['closed'])
            directory.reject = True; reset()
            with self.assertRaises(Rejected): scope.files.read(path, 100, '0' * 64, True)
            self.assertEqual((calls['open'], len(events)), (0, 0)); directory.reject = False
            scope.phase = 'importing'; tick[0] = 11.0
            self.assertEqual(callback(), 11.0)
            self.assertEqual((owner.last, scope.last), (11.0, 11.0))
            tick[0] = 10.0
            with self.assertRaises(Rejected): callback()
            tick[0] = 11.0
            negatives = ((owner, 'close_called', True), (state, 'closing', True),
                (scope, 'phase', 'read_closed'), (scope, 'prepare_until', None),
                (scope, 'prepare_until', 20.5), (scope, 'clock', lambda: 11.0),
                (scope, '_alias_clock', lambda: 11.0), (scope, '_alias_owner_codes', ()),
                (scope, '_alias_owner_methods', ()),
                (scope, '_alias_codes', ()), (scope.files.alias_owner, 'clock', lambda: 11.0))
            for obj, name, value in negatives:
                original = getattr(obj, name); setattr(obj, name, value); reset()
                try:
                    with self.subTest(refusal=name):
                        with self.assertRaises(Rejected): callback()
                        self.assertEqual((calls['clock'], calls['open'], calls['directory']), (0, 0, 0))
                finally: setattr(obj, name, original)
            exec('def injected(self, cleanup=False): calls["injected"] += 1; return 11.0', ons)
            original_now = Owner._now; original_code = original_now.__code__
            try:
                original_now.__code__ = ons['injected'].__code__
                for codes in (scope._alias_owner_codes, ()):
                    old_codes, old_origin = scope._alias_owner_codes, scope._alias_owner_codes_original
                    scope._alias_owner_codes = scope._alias_owner_codes_original = codes
                    reset()
                    try:
                        with self.assertRaises(Rejected): callback()
                        self.assertEqual((calls['injected'], calls['clock']), (0, 0))
                    finally: scope._alias_owner_codes, scope._alias_owner_codes_original = old_codes, old_origin
            finally: original_now.__code__ = original_code
            Owner._now = ons['injected']; reset()
            try:
                with self.assertRaises(Rejected): callback()
                self.assertEqual(calls['injected'], 0)
            finally: Owner._now = original_now
            prepare = scope.original_prepare_until; tick[0] = prepare
            with self.assertRaises(Rejected): callback()
            self.assertIs(scope.original_prepare_until, prepare)
            self.assertEqual(prepare, 20.0)
        finally:
            for name, module in saved.items():
                if module is None: sys.modules.pop(name, None)
                else: sys.modules[name] = module


if __name__ == '__main__':
    unittest.main(verbosity=2)
