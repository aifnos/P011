"""One affected HOST contract; no complete profile, Owner, Trial or device proof.

Select the actual _live_profile prefix through its complete classification For,
plus actual Files IO/close and Startup/Publication clock guards. Stop before
daemon continuity/profile completion. Parent Owner._context, Handoff._check,
Trial/Bridge/Directory objects and stat/FD/content IO are narrow HOST fixtures.
Only Owner._now is selected from the actual Owner; no module main/old suite runs.
"""
import ast
import copy
from contextlib import contextmanager
import errno
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
OLD = ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py',
       94393, '887942d83faf27f781981f426cce5890fa4894219365545901df9310887cd8d3')
FACTORY = ('candidate/receive-profile-classification-clock-v1/runtime/mta_client_receive_factory.py',
           97801, '8cf46d17fda24cc2199e8900a0dfdd9d980b2247808c87801c00426db6158c37')
SPEC = ('candidate/receive-profile-classification-clock-v1/exactsource-delta.json',
        4360, '676ff4a410e882dc75c7750d7b5e02d110919ca41b5e14895141b1c3d1a6d7ae')
EXECUTOR = ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_executor.py',
            117761, '34eddfee126c771776808e64a746f2186f61065cfce9a0c2e59e23e85d67ae23')
OWNER = ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_service_owner.py',
         107068, '745c9569d43711d2dd3f1cf3b29b415020d7163fc7a956bf3b64347a0bda4bcb')


def pinned(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('classification_contract_source_pin')
    return raw


def selected(tree, functions=(), classes=None, assignments=()):
    nodes, found = [], set()
    for row in tree.body:
        if isinstance(row, ast.FunctionDef) and row.name in functions:
            nodes.append(copy.deepcopy(row)); found.add(row.name)
        elif isinstance(row, ast.ClassDef) and row.name in (classes or {}):
            cls = copy.deepcopy(row); wanted = set(classes[row.name])
            cls.body = [n for n in cls.body if
                isinstance(n, ast.FunctionDef) and n.name in wanted or
                isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets)]
            names = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
            names.update(t.id for n in cls.body if isinstance(n, ast.Assign)
                         for t in n.targets if isinstance(t, ast.Name))
            if names != wanted: raise ValueError('classification_contract_method_selection')
            nodes.append(cls); found.add(row.name)
        elif isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id in assignments for target in row.targets for t in ast.walk(target)):
            nodes.append(copy.deepcopy(row))
            found.update(t.id for target in row.targets for t in ast.walk(target) if isinstance(t, ast.Name))
    if found != set(functions) | set(classes or {}) | set(assignments):
        raise ValueError('classification_contract_definition_selection')
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   '<actual-classification-selected-bodies>', 'exec')


def prefix(tree):
    """Exact original prefix through the selected For; only a fixture return added."""
    fn = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_live_profile'))
    indexes = [i for i, n in enumerate(fn.body) if isinstance(n, ast.For)]
    if not indexes: raise ValueError('classification_prefix_missing')
    # No renaming/replacing business calls or loop statements.
    fn.body = fn.body[:indexes[0] + 1] + [ast.Return(value=ast.Tuple(
        elts=[ast.Name(id='found', ctx=ast.Load()), ast.Name(id='discovery', ctx=ast.Load())],
        ctx=ast.Load()))]
    return compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                   '<actual-live-profile-classification-prefix>', 'exec')


class Rejected(ValueError): pass


def fail(code):
    raise Rejected(code)


@contextmanager
def environment(ft, et, ot, mode, names):
    """Only exact selected bodies under limited parent/IO fixtures; no authorities."""
    calls = dict(clock=0, directory=0, handoff=0, injected=0, open=0, read=0, close=0)
    tick, rejected, hook = [10.0], [False], [None]
    events, inodes, opened, offsets = [], {}, {}, {}
    contents = {'/usr/bin/python3.5': b'\x7fELFHOST-fixture'}
    for name in names:
        if re.fullmatch('[1-9][0-9]{0,9}', name):
            contents['/proc/' + name + '/comm'] = b'wpa_supplicant\n' if name == '2' else b'other\n'

    def clock():
        calls['clock'] += 1
        return tick[0]

    def meta(path):
        leaf = path in contents
        return types.SimpleNamespace(st_dev=1, st_ino=inodes.setdefault(path, len(inodes) + 1),
            st_mode=(stat.S_IFREG | (0o755 if path == '/usr/bin/python3.5' else 0o444)) if leaf
                    else stat.S_IFDIR | 0o755,
            st_uid=0, st_gid=0, st_nlink=1, st_size=len(contents[path]) if leaf else 0,
            st_mtime_ns=1, st_ctime_ns=1)

    class MetadataIo:
        def validate(self): events.append(('validate',)); return None
        def stat(self, path):
            events.append(('stat', path, calls['directory'], calls['handoff']))
            return meta(path)
        def readlink(self, path): raise AssertionError('no alias readlink in this prefix fixture')

    def observed_stat(path, follow_symlinks=False):
        events.append(('stat', path, calls['directory'], calls['handoff']))
        return meta(path)

    def opened_fd(path, flags):
        calls['open'] += 1
        events.append(('open', path, calls['directory'], calls['handoff']))
        fd = 100 + calls['open']; opened[fd] = path; offsets[fd] = 0
        return fd

    def fstat_fd(fd):
        if fd not in opened: raise OSError(errno.EBADF, 'HOST closed fixture')
        return meta(opened[fd])

    def read_fd(fd, count):
        calls['read'] += 1
        events.append(('read', opened[fd], calls['directory'], calls['handoff']))
        raw = contents[opened[fd]]; value = raw[offsets[fd]:offsets[fd] + count]
        offsets[fd] += len(value)
        return value

    def close_fd(fd):
        calls['close'] += 1
        events.append(('close', opened[fd]))
        del opened[fd]; del offsets[fd]
        return None

    def listdir(path):
        if path != '/proc': raise AssertionError('prefix directory')
        events.append(('listdir', path, calls['directory'], calls['handoff']))
        return list(names)

    def classified(pattern, value):
        matched = re.fullmatch(pattern, value)
        events.append(('classify', value, calls['directory'], calls['handoff']))
        if hook[0] is not None: hook[0](value)
        return matched

    executor = types.ModuleType('mta_client_executor')
    executor.__dict__.update(_fail=fail, math=math, stat=stat)
    exec(selected(et, functions=('_uint', '_finite', '_meta', '_path'),
        classes={'_ReadOwner': ('__init__', 'check', '_fixed_tmp_alias')}), executor.__dict__)
    executor._LinuxIo = MetadataIo
    for name in ('DeploymentLoader', 'LoadedDeployment', 'ClientExecutor'):
        setattr(executor, name, type(name, (), {}))
    executor.RECEIVE_ROOT = '/mnt/data/p011-toolbox/user/Received'

    class Directory:
        def check(self):
            calls['directory'] += 1
            events.append(('directory', calls['directory']))
            if rejected[0]: fail('fixture_received_full')
            return self

    class Node: pass
    class Factory: pass
    service = types.ModuleType('mta_service')
    class State:
        @staticmethod
        def _probes_closed(value): return value.probe_actors == []
    service.State, service.Operation = State, type('Operation', (), {})
    exec('def _receive_handoff_data_allowed(self, *args): return True', service.__dict__)
    State._receive_handoff_data_allowed = service._receive_handoff_data_allowed
    startup = types.ModuleType('mta_client_startup_readonly')
    startup.StartupCollection = type('StartupCollection', (), {})
    exec('def collect(scope): return None', startup.__dict__)
    ons = dict(__name__='fixture_classification_owner', _fail=fail, math=math,
               STARTUP_READONLY_SCHEMA='receive-startup-readonly-v1')
    exec('def _context(self): pass\ndef start(self): pass\n'
         'def _startup_readonly(self): pass\ndef close(self): pass', ons)
    owner_cls = next(n for n in ot.body if isinstance(n, ast.ClassDef) and n.name == 'FixedStateServiceOwner')
    now = next(n for n in owner_cls.body if isinstance(n, ast.FunctionDef) and n.name == '_now')
    finite = next(n for n in ot.body if isinstance(n, ast.FunctionDef) and n.name == '_finite')
    exec(compile(ast.Module(body=[copy.deepcopy(finite), copy.deepcopy(now)], type_ignores=[]),
                 '<actual-original-owner-now>', 'exec'), ons)
    Owner = type('FixedStateServiceOwner', (), dict(__module__=ons['__name__'],
        _context=ons['_context'], _now=ons['_now'], start=ons['start'],
        _startup_readonly=ons['_startup_readonly'], close=ons['close']))
    ons['FixedStateServiceOwner'] = Owner

    class Handoff:
        def _check(self):
            calls['handoff'] += 1
            events.append(('handoff', calls['handoff']))
            if rejected[0]: fail('fixture_handoff_full')
            return None
    bridge_module = types.ModuleType('mta_client_state_bridge')
    bridge_module.StateClientBridge = type('StateClientBridge', (), {})
    trials = types.ModuleType('mta_receive_trial')
    trials.FixedReceiveTrial = type('FixedReceiveTrial', (), {})
    handoffs = types.SimpleNamespace(ReceiveConnectHandoff=Handoff,
        sessions=types.SimpleNamespace(TransferSession=type('TransferSession', (), {})),
        crypto=types.SimpleNamespace(OpenSslCrypto=type('OpenSslCrypto', (), {}),
                                     KeyPair=type('KeyPair', (), {})))
    service.ReceiveConnectHandoff = Handoff
    ns = dict(__name__='fixture_actual_classification_factory', _fail=fail, executor=executor,
        math=math, stat=stat, errno=errno, hashlib=hashlib,
        os=types.SimpleNamespace(getpid=lambda: 123, stat=observed_stat,
            listdir=listdir, open=opened_fd, fstat=fstat_fd, read=read_fd, close=close_fd,
            O_RDONLY=0, O_CLOEXEC=0, O_NOFOLLOW=0),
        re=types.SimpleNamespace(fullmatch=classified),
        types=types, threading=threading,
        sys=types.SimpleNamespace(modules=sys.modules, version_info=(3, 5, 5)),
        time=types.SimpleNamespace(monotonic=clock),
        storage=types.SimpleNamespace(DirectoryBinding=Directory), _DIRECTORY_TYPE=Directory,
        handoffs=handoffs, _HANDOFF_TYPE=Handoff, _HANDOFF_CHECK=Handoff._check,
        FixedReceiveDeploymentFactory=Factory, calls=calls)
    exec(selected(ft, functions=('_number', '_path', '_close_identity', '_startup_owner_type'),
        classes={'_StartupReadScope': ('__init__', '_originals', 'check_active', 'now',
                    'alias_now', 'close_originals_allowed', 'close_parent_originals'),
                 '_PublicationAttempt': ('__init__', 'originals', 'now', 'alias_now', 'close_parent_originals'),
                 '_Files': ('__init__', '_alias', 'anchors', 'read', 'close_row', 'close', 'closed')},
        assignments=('ASSET_PHYSICAL_ROOT', 'PYTHON', 'SOURCE_PINS', 'SOURCE_MANIFEST_SHA', 'F_SHA',
            'CODEC_SHA', 'BASELINE_MANIFEST', 'STARTUP_READ_SECONDS', 'STARTUP_READONLY_SCHEMA',
            'MAX_PROFILE_FILES', 'MAX_ENTRIES', 'MAX_IMAGE', '_F_ORIGINALS',
            '_STARTUP_ALIAS_ORIGINALS', '_STARTUP_ALIAS_CODES',
            '_PUBLICATION_ALIAS_ORIGINALS', '_PUBLICATION_ALIAS_CODES')), ns)
    exec(prefix(ft), ns)
    executor.MODULES = tuple(n for n, size, sha in ns['SOURCE_PINS'])
    executor.CONNECT_CODEC_SHA = ns['CODEC_SHA']
    factory, owner, state, directory, loader = Factory(), Owner(), State(), Directory(), Node()
    parent = 600.0
    directory.root, directory.absolute_until, directory.clock = executor.RECEIVE_ROOT, parent, clock
    owner.lock = state.lock = threading.RLock()
    owner.clock, owner.last, owner.until, owner.original_until = clock, None, parent, parent
    owner.worker, owner.pid = threading.current_thread(), 123
    owner._startup_owner_type_original, owner._startup_namespace_original = Owner, ons
    owner.factory = owner._startup_factory_original = factory
    owner.state = owner._state_original = state
    owner.service, owner.loader = service, loader
    owner.received_directory = owner._received_directory_original = directory
    owner._startup_module_original, owner._startup_collect_original = startup, startup.collect
    owner._startup_collection_type_original = startup.StartupCollection
    loader._original_until, loader.clock = parent, clock
    loader.modules = {'mta_client_startup_readonly': startup}
    owner.started = owner.state_complete = owner.startup_called = True
    owner.close_called = owner.server_called = owner.start_complete = owner.stop_called = False
    owner.server = owner.thread = None; owner.probe_rows = []
    state._trusted_receive_deployment_factory = factory
    state._original_service_until = state._service_until_original = parent
    state._original_received_binding = state._received_binding_original = directory
    state.closing = state.receive_available = state.send_available = False
    state.wifi_restore_pending = state.radio_restore_pending = False
    state.probe_actors = owner.probe_rows

    if mode == 'startup':
        Scope = ns['_StartupReadScope']; scope = Scope.__new__(Scope)
        owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope
    elif mode == 'publication':
        Scope = ns['_PublicationAttempt']; scope = Scope.__new__(Scope)
        handoff, op, session = Handoff(), service.Operation(), handoffs.sessions.TransferSession()
        bridge = bridge_module.StateClientBridge(); trial = trials.FixedReceiveTrial()
        helper, crypto, key = Node(), handoffs.crypto.OpenSslCrypto(), handoffs.crypto.KeyPair()
        op.client_bridge, op.receive_trial = bridge, trial
        op.cancelled = threading.Event(); session.cancelled = threading.Event()
        op.session, op.kind, op.consent, op.epoch = session, 'receive', True, 1
        session._worker, session._task_deadline = owner.worker, parent
        handoff.state, handoff.operation, handoff.session = state, op, session
        handoff.worker, handoff.clock, handoff._clock_original = owner.worker, clock, clock
        handoff.deadline = handoff._deadline_original = parent
        handoff.epoch, handoff._session_id, handoff.nonce = 1, 'fixture-session', 'fixture-nonce'
        handoff._decrypt_attempted, handoff._claimed, handoff.binding = True, False, None
        handoff._failed = handoff._cancelled = False; handoff._last = None
        handoff._data_authorizer_original = State._receive_handoff_data_allowed
        reader = Node(); helper.thread, helper.closed = reader, False
        crypto._lib = Node(); key._owner, key.closed = crypto._lib, False
        handoff.helper, handoff.key, handoff.crypto, handoff.reader = helper, key, crypto, reader
        state.operation, state.session, state.worker, state.native_epoch = op, session, owner.worker, 1
        state.helper = op.helper = helper; state.key = op.key = key; state.crypto = op.crypto = crypto
        state._receive_trial = state._receive_trial_original = trial
        trial.owner = trial._owner_original = owner
        trial._owner_type, trial._owner_namespace = Owner, ons
        trial.state, trial.factory, trial.clock = state, factory, clock
        trial.until = trial._until_original = parent
        trial.revoked = trial.expired = False; trial._last = None
        owner.receive_trial = owner._receive_trial_original = trial
        bridge._factory, bridge.handoff, bridge.state = factory, handoff, state
        bridge.operation, bridge.session, bridge.worker, bridge.clock = op, session, owner.worker, clock
        bridge._executor, bridge.started, bridge.running, bridge.parent = executor, True, True, None
        bridge.parent_ticket = {'started': False}
        bridge.factory_ticket = {'started': True, 'returned': None, 'authenticated': False}
        factory._active, factory._attempts = scope, [scope]
        factory._alias_functions = ns['_PUBLICATION_ALIAS_ORIGINALS']
        factory._alias_codes = ns['_PUBLICATION_ALIAS_CODES']
    else: raise ValueError('fixture_mode')

    modules = dict(mta_client_executor=executor, mta_client_startup_readonly=startup,
        mta_client_state_bridge=bridge_module, mta_service=service, mta_receive_trial=trials)
    saved = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    functions = ns['_STARTUP_ALIAS_ORIGINALS'] if mode == 'startup' else ns['_PUBLICATION_ALIAS_ORIGINALS']
    codes = tuple(fn.__code__ for fn in functions)
    owner_now_code = Owner._now.__code__
    try:
        if mode == 'startup': Scope.__init__(scope, factory, owner)
        else:
            Scope.__init__(scope, factory, handoff)
            scope.until = scope.original_until = parent
            scope.prepare_until = scope.original_prepare_until = 130.0
            scope.phase = 'reading'
        Files = ns['_Files']; scope.files = Files(scope)
        if mode == 'startup': scope._files_original = scope.files
        for k in calls: calls[k] = 0
        events[:] = []
        yield types.SimpleNamespace(scope=scope, files=scope.files, Scope=Scope, Files=Files,
            owner=owner, Owner=Owner, factory=factory, directory=directory, calls=calls, tick=tick,
            rejected=rejected, hook=hook, events=events, opened=opened, contents=contents,
            functions=functions, codes=codes, ns=ns, executor=executor,
            run=ns['_live_profile'], handoff=handoff if mode == 'publication' else None)
    finally:
        for fn, code in zip(functions, codes): fn.__code__ = code
        Owner._now.__code__ = owner_now_code
        for name, module in saved.items():
            if module is None: sys.modules.pop(name, None)
            else: sys.modules[name] = module


class ReceiveProfileClassificationClockV1Contract(unittest.TestCase):
    def test_actual_profile_classification_io_and_refusals(self):
        old, current, spec_raw, eraw, oraw = (pinned(pin) for pin in (OLD, FACTORY, SPEC, EXECUTOR, OWNER))
        spec = json.loads(spec_raw.decode('ascii'))
        self.assertEqual(set(spec), {'schema', 'evidence', 'source', 'candidate', 'replacements'})
        self.assertEqual(spec['schema'], 'p011-profile-classification-clock-source-delta-v1')
        self.assertEqual(spec['evidence'], 'READBACK_BYTE_INVERSE_ONLY')
        self.assertEqual(spec['source'], list(OLD)); self.assertEqual(spec['candidate'], list(FACTORY))
        self.assertEqual(len(spec['replacements']), 1)
        row = spec['replacements'][0]
        self.assertEqual(set(row), {'name', 'before', 'after', 'count'})
        self.assertEqual(row['name'], 'live_profile_classification_metadata_clock')
        self.assertIs(type(row['count']), int); self.assertEqual(row['count'], 1)
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        self.assertEqual((old.count(before), current.count(after)), (1, 1))
        self.assertEqual(old.replace(before, after, 1), current)
        self.assertEqual(current.replace(after, before, 1), old)
        marker, end = b'    def read(self, path, limit,', b'\n    def close_row(self, row):'
        def read_bytes(raw):
            start = raw.index(marker); return raw[start:raw.index(end, start)]
        self.assertEqual(read_bytes(old), read_bytes(current))
        ft_old, ft_new, et, ot = (ast.parse(raw) for raw in (old, current, eraw, oraw))

        for mode in ('startup', 'publication'):
            for names in ([], ['2'], ['000', '2'], ['000', '2', 'aaa']):
                snapshots = []
                for ft in (ft_old, ft_new):
                    with environment(ft, et, ot, mode, names) as e:
                        cap = e.scope.original_prepare_until
                        found, discovery = e.run(e.scope)
                        self.assertEqual(found, [2] if '2' in names else [])
                        self.assertEqual(len(discovery), 1 if '2' in names else 0)
                        self.assertFalse(e.opened)
                        self.assertIs(e.files.close(), True)
                        self.assertEqual(e.calls['open'], 2 if '2' in names else 1)
                        self.assertEqual(e.calls['close'], e.calls['open'])
                        self.assertIs(e.scope.original_prepare_until, cap)
                        snapshots.append((e.calls.copy(), [v[:2] for v in e.events if
                            v[0] in ('validate', 'stat', 'open', 'read', 'close', 'listdir', 'classify')]))
                with self.subTest(mode=mode, names=names):
                    a, b = snapshots
                    self.assertEqual(a[1], b[1])
                    self.assertEqual(a[0]['clock'], b[0]['clock'])
                    self.assertEqual(a[0]['directory'] - b[0]['directory'], max(len(names) - 1, 0))
                    self.assertEqual(a[0]['handoff'] - b[0]['handoff'],
                                     max(len(names) - 1, 0) if mode == 'publication' else 0)

            # Reject full directory or Handoff immediately before PID stat:
            # the second classification metadata callback itself intentionally
            # does not call these full fixtures. No PID stat/comm open is issued.
            with environment(ft_new, et, ot, mode, ['000', '2']) as e:
                first = [False]
                def reject_after_first(name):
                    if name == '000':
                        first[0] = True; e.rejected[0] = True
                e.hook[0] = reject_after_first
                with self.assertRaisesRegex(Rejected, 'fixture_received_full|fixture_handoff_full'):
                    e.run(e.scope)
                self.assertTrue(first[0])
                self.assertEqual(e.calls['open'], 1)  # original Python read completed
                self.assertFalse(any(v[0] == 'stat' and v[1] == '/proc/2' for v in e.events))
                self.assertFalse(e.opened)

            # Every actual PID stat is preceded/followed by original full guard;
            # successful comm content uses actual unchanged Files read/close.
            with environment(ft_new, et, ot, mode, ['000', '2']) as e:
                e.run(e.scope)
                rows = [(i, v) for i, v in enumerate(e.events) if v[0] == 'stat' and v[1] == '/proc/2']
                self.assertGreaterEqual(len(rows), 1)
                i, v = rows[0]
                guards = 'directory' if mode == 'startup' else 'handoff'
                self.assertEqual(e.events[i - 1][0], guards if mode == 'startup' else 'directory')
                self.assertEqual(e.events[i + 1][0], guards)
                self.assertTrue(any(v[0] == 'open' and v[1] == '/proc/2/comm' for v in e.events))

            mutations = ('callback', 'alias_function', 'alias_code', 'full_function', 'full_code',
                'functions_empty', 'codes_empty', 'scope_files', 'files_attempt',
                'alias_owner_type', 'alias_owner_clock', 'alias_owner_io', 'alias_owner_deadline',
                'phase_or_cancel', 'owner_clock', 'prepare_identity', 'expired', 'monotonic',
                'factory_active', 'owner_code_empty')
            for mutation in mutations:
                with environment(ft_new, et, ot, mode, ['000', '2']) as e:
                    exec('def injected(self, *args): calls["injected"] += 1; return 10.0', e.ns)
                    injected = e.ns['injected']; acted = [False]
                    def mutate(name):
                        if name != '000' or acted[0]: return
                        acted[0] = True
                        if mutation == 'callback': e.scope._alias_clock = types.MethodType(injected, e.scope)
                        elif mutation == 'alias_function': e.Scope.alias_now = injected
                        elif mutation == 'alias_code': e.functions[3].__code__ = injected.__code__
                        elif mutation == 'full_function':
                            if mode == 'startup': e.Scope.check_active = injected
                            else: e.Scope.now = injected
                        elif mutation == 'full_code': e.functions[2].__code__ = injected.__code__
                        elif mutation == 'functions_empty': e.scope._alias_functions = ()
                        elif mutation == 'codes_empty': e.scope._alias_codes = ()
                        elif mutation == 'scope_files': e.scope.files = object()
                        elif mutation == 'files_attempt': e.files.attempt = object()
                        elif mutation == 'alias_owner_type': e.files.alias_owner = object()
                        elif mutation == 'alias_owner_clock': e.files.alias_owner.clock = types.MethodType(injected, e.scope)
                        elif mutation == 'alias_owner_io': e.files.alias_owner.io = object()
                        elif mutation == 'alias_owner_deadline': e.files.alias_owner.deadline = 999.0
                        elif mutation == 'phase_or_cancel':
                            if mode == 'startup': e.scope.phase = 'read_closed'
                            else: e.handoff._cancelled = True
                        elif mutation == 'owner_clock': e.owner.clock = lambda: injected(e.owner)
                        elif mutation == 'prepare_identity': e.scope.prepare_until = float(str(e.scope.prepare_until))
                        elif mutation == 'expired': e.tick[0] = e.scope.original_prepare_until
                        elif mutation == 'monotonic': e.tick[0] = 9.0
                        elif mutation == 'factory_active':
                            if mode == 'startup': e.factory._startup_scope = object()
                            else: e.factory._active = object()
                        elif mutation == 'owner_code_empty':
                            if mode == 'startup':
                                e.scope._alias_owner_codes = e.scope._alias_owner_codes_original = ()
                            else: e.scope._alias_trial._owner_original = object()
                    e.hook[0] = mutate
                    with self.subTest(mode=mode, mutation=mutation):
                        with self.assertRaises(Rejected): e.run(e.scope)
                        self.assertTrue(acted[0])
                        self.assertEqual(e.calls['injected'], 0)
                        self.assertEqual(e.calls['open'], 1)
                        self.assertFalse(any(v[0] == 'stat' and v[1] == '/proc/2' for v in e.events))
                        self.assertFalse(e.opened)
                        self.assertEqual(e.scope.original_prepare_until, 20.0 if mode == 'startup' else 130.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
