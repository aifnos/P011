"""One selected HOST contract; authored only, not complete Owner/device proof.

Execute actual Scope/alias/Files/Owner._now bodies only when ROOT runs this
selector. Context, State, Received directory and FD/content IO are explicit
fixtures. No old test method, production module imports, graph or RF run.
"""
import ast
import copy
from contextlib import contextmanager
import errno
import hashlib
import json
import math
from pathlib import Path
import stat
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
OLD = ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_receive_factory.py',
       89982, 'd1637a6ba8f1d694cf240d09c62afa583dc02c07dc4dd79b4216f2643d7d5824')
FACTORY = ('candidate/receive-startup-anchor-clock-v1/runtime/mta_client_receive_factory.py',
           91907, 'bd6e8f65ad03bf1e18594979af21699dd97813502c4f5b6211eb6b05f026fcf5')
SPEC = ('candidate/receive-startup-anchor-clock-v1/exactsource-delta.json',
        5343, '23187b91b1aa63f851ac6b1e31517accaf197bc55b15d19350d6e896ef6eaaf5')
EXECUTOR = ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_executor.py',
            117760, 'ff13becc37e9dd2d616733dd4b2381f4c968913a1d913183b9f3ae9845d95496')
OWNER = ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_service_owner.py',
         107066, 'a73e9646a3f407c2b36a22b67bdcd127945f53e6345b616fe8c646fbbf7837ba')


def pinned_bytes(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('anchor_contract_source_pin')
    return raw


def subset(tree, functions=(), classes=None, assignments=()):
    """Exact requested function bodies; do not execute imports/main/old tests."""
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
            if names != set(wanted): raise ValueError('anchor_contract_method_selection')
            nodes.append(cls); found.add(row.name)
        elif isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id in assignments for target in row.targets for t in ast.walk(target)):
            nodes.append(copy.deepcopy(row))
            found.update(t.id for target in row.targets for t in ast.walk(target)
                         if isinstance(t, ast.Name))
    if found != set(functions) | set(classes or {}) | set(assignments):
        raise ValueError('anchor_contract_definition_selection')
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   '<actual-startup-anchor-selected-bodies>', 'exec')


class Rejected(ValueError):
    pass


def fail(code):
    raise Rejected(code)


@contextmanager
def environment(ft, et, ot):
    """Actual selected guards plus narrow context/metadata/fake FD dependencies."""
    calls = dict(clock=0, context=0, directory=0, injected=0,
                 open=0, read=0, close=0, fstat=0, sha=0)
    tick, hook = [10.0], [None]
    events, inodes, opened, offsets = [], {}, {}, {}
    links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}
    class Node: pass

    def clock():
        calls['clock'] += 1
        return tick[0]

    # _Files contents are fixture bytes, not production private pins or files.
    # Their SHA is still computed by actual hashlib through the observed wrapper.
    contents = {}
    root_row = next(n for n in ft.body if isinstance(n, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == 'ASSET_PHYSICAL_ROOT' for t in n.targets))
    root = ast.literal_eval(root_row.value)

    class MetadataIo:
        def stat(self, path):
            events.append(('stat', path, calls['directory']))
            if path in contents:
                mode, size = stat.S_IFREG | (0o400 if path.startswith(root + '/') else 0o644), len(contents[path])
            else:
                mode = stat.S_IFLNK | 0o777 if path in links else stat.S_IFDIR | (
                    0o1777 if path in ('/var/volatile', '/var/volatile/tmp') else 0o755)
                if path == root or path.startswith(root + '/'): mode = stat.S_IFDIR | 0o700
                size = len(links.get(path, ''))
            row = Node()
            row.st_dev, row.st_ino = 1, inodes.setdefault(path, len(inodes) + 1)
            row.st_mode, row.st_uid, row.st_gid, row.st_nlink = mode, 0, 0, 1
            row.st_size, row.st_mtime_ns, row.st_ctime_ns = size, 1, 1
            if hook[0] is not None: hook[0](path)
            return row

        def readlink(self, path):
            events.append(('readlink', path, calls['directory']))
            return links[path]

    def op(kind):
        calls[kind] += 1
        events.append((kind, calls['directory']))

    def fake_open(path, flags):
        op('open')
        if path not in contents: raise OSError(errno.ENOENT, 'HOST fixture missing content')
        fd = 100 + calls['open']
        if fd in opened: raise AssertionError('fixture fd collision')
        opened[fd], offsets[fd] = path, 0
        return fd

    def fake_fstat(fd):
        op('fstat')
        if fd not in opened: raise OSError(errno.EBADF, 'HOST fixture closed FD')
        # Metadata matches, but fstat itself never invokes the path mutation hook.
        saved = hook[0]; hook[0] = None
        try: return MetadataIo().stat(opened[fd])
        finally: hook[0] = saved

    def fake_read(fd, count):
        op('read')
        data = contents[opened[fd]]
        value = data[offsets[fd]:offsets[fd] + count]
        offsets[fd] += len(value)
        return value

    def fake_close(fd):
        op('close')
        if fd not in opened: raise OSError(errno.EBADF, 'HOST fixture duplicate close')
        del opened[fd]; del offsets[fd]
        return None

    def observed_sha(data):
        op('sha')
        return hashlib.sha256(data)

    fake_os = types.SimpleNamespace(getpid=lambda: 123,
        stat=lambda path, follow_symlinks=False: MetadataIo().stat(path),
        open=fake_open, read=fake_read, close=fake_close, fstat=fake_fstat,
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
            events.append(('directory', calls['directory']))
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

    # Only the Publication branch comparison uses this context fixture.
    # It does not claim an actual handoff/Publication grant.
    class Publication:
        def now(self):
            directory.check()
            return clock()

    ns = dict(__name__='fixture_actual_factory', _fail=fail, executor=executor, calls=calls,
        math=math, stat=stat, errno=errno, hashlib=types.SimpleNamespace(sha256=observed_sha), os=fake_os,
        types=types, threading=threading, sys=sys, time=types.SimpleNamespace(monotonic=clock),
        storage=types.SimpleNamespace(DirectoryBinding=Directory), _DIRECTORY_TYPE=Directory,
        FixedReceiveDeploymentFactory=type('FixedReceiveDeploymentFactory', (), {}),
        _PublicationAttempt=Publication,
        _F_ORIGINALS=(executor, executor.DeploymentLoader, executor.LoadedDeployment,
                      executor.ClientExecutor, executor._ReadOwner))
    exec(subset(ft, functions=('_number', '_path', '_close_identity', '_startup_owner_type'),
        classes={'_StartupReadScope': ('__init__', '_originals', 'check_active', 'now',
                    'alias_now', 'close_originals_allowed', 'close_parent_originals'),
                 '_Files': ('__init__', '_alias', 'anchors', 'read', 'close_row', 'close', 'closed')},
        assignments=('SOURCE_PINS', 'SOURCE_MANIFEST_SHA', 'F_SHA', 'BASELINE_MANIFEST',
                     'ASSET_PHYSICAL_ROOT', 'PYTHON', 'STARTUP_READ_SECONDS', 'STARTUP_READONLY_SCHEMA',
                     'MAX_PROFILE_FILES', 'MAX_ENTRIES', 'MAX_IMAGE',
                     '_STARTUP_ALIAS_ORIGINALS', '_STARTUP_ALIAS_CODES')), ns)
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
        def reset():
            for key in calls: calls[key] = 0
            events[:] = []
        reset()
        yield types.SimpleNamespace(ns=ns, Scope=Scope, Files=Files, Owner=Owner, owner=owner,
            scope=scope, files=scope.files, directory=directory, calls=calls, tick=tick,
            events=events, hook=hook, reset=reset, root=root, contents=contents, opened=opened,
            Publication=Publication, ons=ons, clock=clock)
    finally:
        for name, module in saved.items():
            if module is None: sys.modules.pop(name, None)
            else: sys.modules[name] = module


class ReceiveStartupAnchorClockV1Contract(unittest.TestCase):
    def test_actual_startup_anchor_density_io_and_refusals(self):
        old, current, spec_raw, executor, owner = (pinned_bytes(pin) for pin in
                                                  (OLD, FACTORY, SPEC, EXECUTOR, OWNER))
        spec = json.loads(spec_raw.decode('ascii'))
        self.assertEqual(set(spec), {'schema', 'evidence', 'source', 'candidate', 'replacements'})
        self.assertEqual(spec['source'], list(OLD)); self.assertEqual(spec['candidate'], list(FACTORY))
        self.assertEqual(spec['schema'], 'p011-startup-anchor-clock-source-delta-v1')
        self.assertEqual(len(spec['replacements']), 1)
        row = spec['replacements'][0]
        self.assertEqual(set(row), {'name', 'before', 'after', 'count'})
        self.assertEqual(row['name'], 'startup_fixed_anchor_metadata_clock')
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        self.assertEqual((row['count'], old.count(before), current.count(after)), (1, 1, 1))
        self.assertEqual(old.replace(before, after, 1), current)
        self.assertEqual(current.replace(after, before, 1), old)
        ft_old, ft_new, et, ot = (ast.parse(raw) for raw in (old, current, executor, owner))

        # Actual anchor stat/readlink order and returned metadata must match.
        paths = ('/proc/123/comm', '/usr/bin/python3.5', 'PRIVATE',
                 '/proc/config.gz', '/usr/bin', '/opt/fixture/deep/leaf')
        for path_name in paths:
            snapshots = []
            for ft in (ft_old, ft_new):
                with environment(ft, et, ot) as e:
                    path = e.root + '/runtime35/unused.py' if path_name == 'PRIVATE' else path_name
                    d = len(path.split('/')) - 1
                    value = e.files.anchors(path)
                    io = [event[:2] for event in e.events if event[0] in ('stat', 'readlink')]
                    snapshots.append((value, io, e.calls['clock'], e.calls['directory']))
            a, b = snapshots
            self.assertEqual(a[:2], b[:2])
            eligible = path_name in ('/proc/123/comm', '/usr/bin/python3.5', 'PRIVATE')
            with self.subTest(anchor=path_name):
                if eligible:
                    self.assertEqual((b[2] - a[2], a[3] - b[3]), (1, d - 2))
                else:
                    self.assertEqual(a[2:], b[2:])
        for ft in (ft_old, ft_new):
            with environment(ft, et, ot) as e:
                e.files.alias_owner._fixed_tmp_alias()
                self.assertEqual((e.calls['clock'], e.calls['directory']), (23, 0))

        # Publication takes the original branch; only its surrounding context
        # is a fixture. No actual Publication/Handoff permission is claimed.
        snapshots = []
        for ft in (ft_old, ft_new):
            with environment(ft, et, ot) as e:
                pub = e.Publication(); pub._alias_clock = pub.now; pub.prepare_until = 20.0
                pf = e.Files(pub); pub.files = pf
                e.reset(); value = pf.anchors('/usr/bin/python3.5')
                snapshots.append((value, e.calls.copy(), e.events.copy()))
        self.assertEqual(snapshots[0], snapshots[1])

        # Full Directory gates at selected anchors entry and successful exit.
        for boundary in ('entry', 'exit'):
            with environment(ft_new, et, ot) as e:
                if boundary == 'entry': e.directory.reject = True
                else:
                    def reject_exit(path):
                        if path == '/proc/123': e.directory.reject = True
                    e.hook[0] = reject_exit
                with self.subTest(directory_boundary=boundary):
                    with self.assertRaises(Rejected): e.files.anchors('/proc/123/comm')
                    self.assertEqual(e.calls['open'], 0)
                    self.assertEqual(e.calls['directory'], 1 if boundary == 'entry' else 2)
                    self.assertEqual(len([v for v in e.events if v[0] == 'stat']),
                                     0 if boundary == 'entry' else 3)

        # Actual _Files.read/SHA/chunk/close bodies: fake FD IO is explicitly
        # not native descriptor proof. Original call ordering is preserved.
        read_snapshots = []
        for ft in (ft_old, ft_new):
            with environment(ft, et, ot) as e:
                path, raw = '/proc/123/comm', b'wpa_supplicant\n'
                e.contents[path] = raw
                value, meta = e.files.read(path, 128, hashlib.sha256(raw).hexdigest(), proc=True)
                self.assertEqual(value, raw)
                expected_directories = 15 if ft is ft_old else 13
                self.assertEqual(e.calls['directory'], expected_directories)
                self.assertEqual((e.calls['open'], e.calls['read'], e.calls['sha'], e.calls['close']), (1, 2, 1, 1))
                positions = {kind: [v[1] for v in e.events if v[0] == kind]
                             for kind in ('open', 'read', 'sha', 'close')}
                self.assertEqual(positions, dict(open=[5 if ft is ft_old else 4],
                    read=[7, 9] if ft is ft_old else [6, 8],
                    sha=[14 if ft is ft_old else 12], close=[expected_directories]))
                self.assertFalse(e.opened)
                self.assertIs(e.files.rows[-1]['closed'], True)
                self.assertIs(e.files.rows[-1]['unknown'], False)
                self.assertIs(e.files.close(), True)
                self.assertIs(e.files.close(), True)
                self.assertEqual(e.calls['close'], 1)
                # Filter directory-count annotations, not original IO order.
                read_snapshots.append((value, meta,
                    [v[:2] if v[0] in ('stat', 'readlink') else (v[0],)
                     for v in e.events if v[0] not in ('directory',)]))
        self.assertEqual(read_snapshots[0], read_snapshots[1])
        with environment(ft_new, et, ot) as e:
            e.contents['/proc/123/comm'] = b'wpa_supplicant\n'
            e.directory.reject = True
            with self.assertRaises(Rejected): e.files.read('/proc/123/comm', 128, proc=True)
            self.assertEqual((e.calls['open'], e.calls['read'], e.calls['close']), (0, 0, 0))

        # Mutate after the first actual metadata stat, not before entry. The
        # next callback must reject before injected method/code can execute.
        mutations = ('callback', 'alias_owner_clock', 'alias_function', 'alias_code',
                     'owner_function', 'owner_code', 'owner_clock', 'phase', 'cap',
                     'functions_empty', 'codes_empty', 'attempt', 'expired')
        for mutation in mutations:
            with environment(ft_new, et, ot) as e:
                injection_ns = dict(calls=e.calls)
                exec('def injected(self): calls["injected"] += 1; return 10.0', injection_ns)
                injected = injection_ns['injected']
                # exec globals carry only fixture counters, no target credentials.
                original_alias, original_alias_code = e.Scope.alias_now, e.Scope.alias_now.__code__
                original_now, original_now_code = e.Owner._now, e.Owner._now.__code__
                acted = [False]
                def mutate(path):
                    if path != '/' or acted[0]: return
                    acted[0] = True
                    if mutation == 'callback': e.scope._alias_clock = types.MethodType(injected, e.scope)
                    elif mutation == 'alias_owner_clock': e.files.alias_owner.clock = types.MethodType(injected, e.scope)
                    elif mutation == 'alias_function': e.Scope.alias_now = injected
                    elif mutation == 'alias_code': original_alias.__code__ = injected.__code__
                    elif mutation == 'owner_function': e.Owner._now = injected
                    elif mutation == 'owner_code': original_now.__code__ = injected.__code__
                    elif mutation == 'owner_clock': e.owner.clock = types.MethodType(injected, e.owner)
                    elif mutation == 'phase': e.scope.phase = 'read_closed'
                    elif mutation == 'cap': e.scope.prepare_until = None
                    elif mutation == 'functions_empty': e.scope._alias_functions = ()
                    elif mutation == 'codes_empty': e.scope._alias_codes = ()
                    elif mutation == 'attempt': e.files.attempt = types.SimpleNamespace(now=lambda: injected(e.scope))
                    elif mutation == 'expired': e.tick[0] = e.scope.original_prepare_until
                e.hook[0] = mutate
                try:
                    with self.subTest(refusal=mutation):
                        with self.assertRaises(Rejected): e.files.anchors('/proc/123/comm')
                        self.assertTrue(acted[0])
                        self.assertEqual((e.calls['injected'], e.calls['open']), (0, 0))
                        self.assertEqual(len([v for v in e.events if v[0] == 'stat']), 1)
                        self.assertEqual(e.scope.original_prepare_until, 20.0)
                finally:
                    original_alias.__code__ = original_alias_code; e.Scope.alias_now = original_alias
                    original_now.__code__ = original_now_code; e.Owner._now = original_now


if __name__ == '__main__':
    unittest.main(verbosity=2)
